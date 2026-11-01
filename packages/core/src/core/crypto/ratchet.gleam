//// The Double Ratchet (Signal's specification, with X25519, HKDF-SHA-256 and
//// HMAC-SHA-256 chains), written as a pure function from one state value to
//// the next.
////
//// ## Value semantics is the point
////
//// `docs/spec.md` §5.3 requires that a crypto operation never advance hidden
//// state before the application commits its database transaction. Here the
//// ratchet state is an ordinary immutable value, so that holds by
//// construction:
////
//// - `encrypt(suite, state, plaintext)` and `decrypt(suite, state, message)`
////   return `#(new_state, output)` and never touch `state`.
//// - A failed `decrypt` returns an error and the caller still holds the old
////   state, so a forged or corrupted message cannot burn a message key,
////   advance a chain, or fill the skipped-key store.
//// - A message key is consumed exactly when the caller keeps the returned
////   state. If the caller's transaction fails and it discards the new state,
////   the same message decrypts again from the old one; if it commits, a
////   replay fails because the key is gone.
////
//// ## Encryption is deterministic in the state
////
//// `encrypt` is a function of the state and the plaintext: the same state
//// and the same plaintext give the same message, and two different
//// plaintexts encrypted from one state use the same message key and nonce,
//// which breaks ChaCha20-Poly1305. A ciphertext must therefore not leave
//// the process unless the state that produced it has been committed. That
//// is the commit-then-send order of `docs/spec.md` §8.2: persist the
//// returned state first, then send, and on a crash resume from the
//// committed state and resend the same bytes rather than encrypting afresh.
////
//// ## What the mailbox sees
////
//// Headers are not encrypted in v1. Each message is the 40-byte header (the
//// sender's current ratchet public key, the previous chain's length PN and
//// this message's number N) followed by the AEAD ciphertext, and the
//// mailbox, or anyone who can read it, sees the header. That reveals when a
//// DH ratchet step happened and how many messages each chain carried, not
//// who the parties are or what they said. The header is authenticated: it
//// is part of the AEAD's associated data.
////
//// ## Keys and chains
////
//// ```text
//// KDF_RK(rk, dh_out) = HKDF(salt = rk, ikm = dh_out, info = RootInfo, L = 64)
////                      -> (rk', chain key)
//// KDF_CK(ck)         = (HMAC(ck, 0x02), HMAC(ck, 0x01))  -> (ck', mk)
//// message keys       = HKDF(salt = 0^32, ikm = mk, info = MessageInfo, L = 44)
////                      -> 32-byte ChaCha20-Poly1305 key, 12-byte nonce
//// ```
////
//// The associated data of every message is the session's AD (set by the
//// handshake) followed by the header bytes.
////
//// ## Bounds
////
//// Skipped message keys are stored so that late messages still decrypt. A
//// header that claims a gap over `limits.max_skip_per_message` is refused,
//// since the gap is chosen by whoever can reach the mailbox, and a receiver
//// also refuses a message number at `limits.max_message_number`, the number
//// the sender never uses. The store itself holds at most
//// `limits.max_skipped_message_keys`; storing more evicts the oldest keys,
//// so a message older than the eviction is undecryptable, as any lost
//// message is, and the session keeps working. No path is an unbounded loop,
//// and `decode_state` refuses a stored count over the bound.
////
//// ## Not in v1
////
//// There is no post-quantum ratchet. The root key is seeded from PQXDH, so
//// the initial secret is protected against a quantum adversary, but every
//// later DH step is classical X25519. The state's version byte reserves room
//// for Signal's sparse post-quantum ratchet.

import core/crypto/error.{
  type Error, AuthenticationFailed, CounterExhausted, Malformed,
  MessageKeyUnavailable, NoSendingChain, PrimitiveFailed, SkipLimitExceeded,
  SkippedKeyStoreFull,
}
import core/crypto/hkdf
import core/crypto/keys.{type X25519Public, type X25519Secret}
import core/crypto/suite.{type Suite}
import core/crypto/wire
import core/limits
import core/secret.{type Secret}
import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

/// The version byte at the head of a serialized state. A state with any
/// other version is refused, which is how a future ratchet with new fields
/// (the post-quantum steps) will be told apart.
pub const state_version = 1

/// The size of a message header: ratchet public key, PN and N.
pub const header_bytes = 40

/// The HKDF `info` of the root-key step.
pub const root_info = <<"Reedwire_Ratchet_v1":utf8>>

/// The HKDF `info` that expands a message key into an AEAD key and nonce.
pub const message_info = <<"Reedwire_MessageKeys_v1":utf8>>

/// One side's ratchet state. Opaque: it is built by `init_sender`,
/// `init_receiver` or `decode_state`, and changes only by returning a new
/// value from `encrypt` or `decrypt`.
///
/// The invariants are carried by the shape. A receiving chain is one value
/// holding the peer's ratchet key, the chain key and the next expected
/// number, so a chain key can never be present without the key it belongs
/// to. `skipped` is newest first and never longer than
/// `limits.max_skipped_message_keys`.
pub opaque type State {
  State(
    ad: BitArray,
    sending_secret: X25519Secret,
    sending_public: X25519Public,
    root: Secret,
    sending_chain: Option(Secret),
    receiving: Option(ReceivingChain),
    sent: Int,
    previous: Int,
    skipped: List(Skipped),
  )
}

/// The chain that decrypts the peer's current ratchet key's messages.
type ReceivingChain {
  ReceivingChain(remote: X25519Public, chain: Secret, next: Int)
}

/// A message key derived for a message that has not arrived yet, kept under
/// the ratchet key and number that identify it.
type Skipped {
  Skipped(remote: X25519Public, number: Int, message_key: Secret)
}

/// A parsed message header.
type Header {
  Header(remote: X25519Public, previous: Int, number: Int)
}

/// The initiator's state after the handshake: it has the responder's first
/// ratchet public key, so it takes the first DH step at once and can send
/// immediately.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(state) = ratchet.init_sender(suite, shared, ad, bundle_spk)
/// ```
pub fn init_sender(
  suite: Suite,
  shared: Secret,
  ad: BitArray,
  remote: X25519Public,
) -> Result(State, Error) {
  use #(secret, public) <- result.try(keys.generate_x25519(suite))
  use dh_out <- result.try(keys.dh(suite, secret, remote))
  use #(root, chain) <- result.try(kdf_rk(suite, shared, dh_out))

  Ok(
    State(
      ad: ad,
      sending_secret: secret,
      sending_public: public,
      root: root,
      sending_chain: Some(chain),
      receiving: None,
      sent: 0,
      previous: 0,
      skipped: [],
    ),
  )
}

/// The responder's state after the handshake. Its first ratchet key pair is
/// the signed prekey the initiator agreed against. It has no sending chain
/// until it receives a message, because it does not yet know the
/// initiator's ratchet key.
///
/// ## Examples
///
/// ```gleam
/// let state = ratchet.init_receiver(shared, ad, spk_secret, spk_public)
/// ```
pub fn init_receiver(
  shared: Secret,
  ad: BitArray,
  secret: X25519Secret,
  public: X25519Public,
) -> State {
  State(
    ad: ad,
    sending_secret: secret,
    sending_public: public,
    root: shared,
    sending_chain: None,
    receiving: None,
    sent: 0,
    previous: 0,
    skipped: [],
  )
}

/// Encrypts `plaintext` and returns the next state with the wire message:
/// the 40-byte header followed by the sealed body. The input state is
/// unchanged; the caller keeps the returned one if and only if it commits
/// the message.
///
/// Encryption is deterministic in the state. A ciphertext must not leave the
/// process unless the state that produced it is committed, and the caller
/// must never encrypt two different plaintexts from one state, because that
/// reuses a message key and nonce. Persist the returned state first, then
/// send (`docs/spec.md` §8.2).
///
/// A responder that has not yet received anything has no sending chain and
/// gets `NoSendingChain`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(next, wire)) = ratchet.encrypt(suite, state, <<"hi">>)
/// ```
pub fn encrypt(
  suite: Suite,
  state: State,
  plaintext: BitArray,
) -> Result(#(State, BitArray), Error) {
  use chain <- result.try(option.to_result(state.sending_chain, NoSendingChain))
  use Nil <- result.try(check_counter(state.sent))

  let #(next_chain, message_key) = kdf_ck(suite, chain)
  let header = encode_header(state.sending_public, state.previous, state.sent)
  use sealed <- result.try(seal(suite, state.ad, header, message_key, plaintext))

  Ok(
    #(State(..state, sending_chain: Some(next_chain), sent: state.sent + 1), <<
      header:bits,
      sealed:bits,
    >>),
  )
}

fn check_counter(sent: Int) -> Result(Nil, Error) {
  case sent >= limits.max_message_number {
    True -> Error(CounterExhausted)
    False -> Ok(Nil)
  }
}

/// Decrypts a wire message and returns the next state with the plaintext.
/// The input state is unchanged. On any error, whether a malformed header,
/// a replay, a gap past the bounds or a failed authentication, the caller
/// still holds the old state and nothing was consumed.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(next, plaintext)) = ratchet.decrypt(suite, state, wire)
/// ```
pub fn decrypt(
  suite: Suite,
  state: State,
  message: BitArray,
) -> Result(#(State, BitArray), Error) {
  use #(header, raw_header, sealed) <- result.try(parse_message(message))

  // A key kept from an earlier gap serves this message directly. Opening
  // with it removes it, so the second delivery of the message finds nothing.
  case take_skipped(state.skipped, header) {
    Ok(#(entry, rest)) ->
      open(
        suite,
        State(..state, skipped: rest),
        raw_header,
        entry.message_key,
        sealed,
      )

    Error(Nil) -> {
      use #(state, chain) <- result.try(advance(suite, state, header))
      use #(state, message_key) <- result.try(take_key(
        suite,
        state,
        chain,
        header.number,
      ))

      open(suite, state, raw_header, message_key, sealed)
    }
  }
}

/// Removes the stored key for the header's ratchet key and number, keeping
/// the rest in order.
fn take_skipped(
  skipped: List(Skipped),
  header: Header,
) -> Result(#(Skipped, List(Skipped)), Nil) {
  let #(before, after) =
    list.split_while(skipped, fn(entry) {
      entry.remote != header.remote || entry.number != header.number
    })

  // The first entry the split leaves in `after` is the match; none means the key is not stored.
  case after {
    [found, ..rest] -> Ok(#(found, list.append(before, rest)))
    [] -> Error(Nil)
  }
}

/// Brings the state to the chain the header names. Under the peer's current
/// ratchet key that is the chain already held; under a new one it first
/// stores the keys the old chain still owes (the header's PN says how many
/// it sent) and then takes the DH ratchet step.
fn advance(
  suite: Suite,
  state: State,
  header: Header,
) -> Result(#(State, ReceivingChain), Error) {
  // The same ratchet key means the same chain, a new key after a chain means a DH step, and a first message needs only the step.
  case state.receiving {
    Some(chain) if chain.remote == header.remote -> Ok(#(state, chain))

    Some(old) -> {
      use #(skipped, _) <- result.try(skip_chain(
        suite,
        state.skipped,
        old,
        header.previous,
      ))

      dh_ratchet(suite, State(..state, skipped: skipped), header.remote)
    }

    None -> dh_ratchet(suite, state, header.remote)
  }
}

/// The DH ratchet step: derive the receiving chain from the peer's new key,
/// then pick a fresh key pair of our own and derive the sending chain from it.
fn dh_ratchet(
  suite: Suite,
  state: State,
  remote: X25519Public,
) -> Result(#(State, ReceivingChain), Error) {
  use received <- result.try(keys.dh(suite, state.sending_secret, remote))
  use #(root, receiving_chain) <- result.try(kdf_rk(suite, state.root, received))
  use #(secret, public) <- result.try(keys.generate_x25519(suite))
  use sent <- result.try(keys.dh(suite, secret, remote))
  use #(root, sending_chain) <- result.try(kdf_rk(suite, root, sent))

  let chain = ReceivingChain(remote: remote, chain: receiving_chain, next: 0)

  Ok(#(
    State(
      ..state,
      sending_secret: secret,
      sending_public: public,
      root: root,
      sending_chain: Some(sending_chain),
      receiving: Some(chain),
      sent: 0,
      previous: state.sent,
    ),
    chain,
  ))
}

/// Stores the keys of messages `chain.next` up to but not including `until`
/// and returns the chain advanced past them. The per-message bound is
/// checked before any key is derived, so a hostile gap costs a comparison.
/// The store bound is enforced by eviction: the list is newest first, so
/// keeping its first `limits.max_skipped_message_keys` entries drops the
/// oldest. A message whose key was evicted is undecryptable, exactly as a
/// lost message is, and a session never wedges on a full store.
fn skip_chain(
  suite: Suite,
  skipped: List(Skipped),
  chain: ReceivingChain,
  until: Int,
) -> Result(#(List(Skipped), ReceivingChain), Error) {
  let gap = until - chain.next

  // The gap is attacker-controlled, so an oversized one is refused outright.
  case gap > limits.max_skip_per_message {
    True -> Error(SkipLimitExceeded)

    False -> {
      let #(stored, advanced) = store_skipped(suite, skipped, chain, until)

      Ok(#(list.take(stored, limits.max_skipped_message_keys), advanced))
    }
  }
}

/// Derives and stores the keys from the chain's next number up to `until`, returning the advanced chain.
fn store_skipped(
  suite: Suite,
  skipped: List(Skipped),
  chain: ReceivingChain,
  until: Int,
) -> #(List(Skipped), ReceivingChain) {
  // Stop once the chain has reached `until`.
  case chain.next < until {
    True -> {
      let #(next_chain, message_key) = kdf_ck(suite, chain.chain)
      let entry =
        Skipped(
          remote: chain.remote,
          number: chain.next,
          message_key: message_key,
        )
      let advanced =
        ReceivingChain(..chain, chain: next_chain, next: chain.next + 1)

      store_skipped(suite, [entry, ..skipped], advanced, until)
    }

    False -> #(skipped, chain)
  }
}

/// The key of message `number` in `chain`: any earlier numbers are stored as
/// skipped keys, and the chain moves past `number`. A number below the
/// chain's next one that is not in the store is a replay of a spent key.
fn take_key(
  suite: Suite,
  state: State,
  chain: ReceivingChain,
  number: Int,
) -> Result(#(State, Secret), Error) {
  // A number below the chain's next one was already consumed or skipped
  // past. A number at the sender's limit is one no honest sender emits, and
  // refusing it keeps `next` below 2^32 so `encode_state` never truncates.
  case number < chain.next {
    True -> Error(MessageKeyUnavailable)

    False if number >= limits.max_message_number -> Error(CounterExhausted)

    False -> {
      use #(skipped, chain) <- result.try(skip_chain(
        suite,
        state.skipped,
        chain,
        number,
      ))
      let #(next_chain, message_key) = kdf_ck(suite, chain.chain)
      let advanced =
        ReceivingChain(..chain, chain: next_chain, next: chain.next + 1)

      Ok(#(
        State(..state, skipped: skipped, receiving: Some(advanced)),
        message_key,
      ))
    }
  }
}

/// Authenticates and decrypts one message with its message key. The state returned is the one the caller passed, already stripped of any consumed skipped key.
fn open(
  suite: Suite,
  state: State,
  raw_header: BitArray,
  message_key: Secret,
  sealed: BitArray,
) -> Result(#(State, BitArray), Error) {
  use #(key, nonce) <- result.try(message_keys(suite, message_key))

  // Authentication failure maps to a single error that carries nothing.
  case suite.aead_open(key, nonce, <<state.ad:bits, raw_header:bits>>, sealed) {
    Ok(plaintext) -> Ok(#(state, plaintext))
    Error(Nil) -> Error(AuthenticationFailed)
  }
}

/// Encrypts one message under its message key, with the session AD and the header as associated data.
fn seal(
  suite: Suite,
  ad: BitArray,
  raw_header: BitArray,
  message_key: Secret,
  plaintext: BitArray,
) -> Result(BitArray, Error) {
  use #(key, nonce) <- result.try(message_keys(suite, message_key))

  suite.aead_seal(key, nonce, <<ad:bits, raw_header:bits>>, plaintext)
  |> result.replace_error(PrimitiveFailed)
}

/// KDF_RK: the root key and the DH output give the next root key and a chain
/// key, 32 bytes each.
fn kdf_rk(
  suite: Suite,
  root: Secret,
  dh_out: BitArray,
) -> Result(#(Secret, Secret), Error) {
  // The root key is the HKDF salt of this step, which is its whole use.
  use okm <- result.try(hkdf.extract_expand(
    suite,
    secret.expose(root),
    dh_out,
    root_info,
    64,
  ))
  use #(next_root, chain) <- result.try(wire.take(okm, 32, "root step"))

  Ok(#(secret.new(next_root), secret.new(chain)))
}

/// KDF_CK: one HMAC with each constant byte, the message key first. The
/// chain key advances with 0x02 so that it is unrelated to the message key.
fn kdf_ck(suite: Suite, chain: Secret) -> #(Secret, Secret) {
  // The chain key is the HMAC key of this step, which is its whole use.
  let key = secret.expose(chain)

  #(
    secret.new(suite.hmac_sha256(key, <<2>>)),
    secret.new(suite.hmac_sha256(key, <<1>>)),
  )
}

/// A message key expands to the AEAD key and nonce for that one message.
fn message_keys(
  suite: Suite,
  message_key: Secret,
) -> Result(#(BitArray, BitArray), Error) {
  // The message key is the HKDF input of this step, which is its whole use.
  use okm <- result.try(hkdf.extract_expand(
    suite,
    <<0:256>>,
    secret.expose(message_key),
    message_info,
    44,
  ))
  use #(key, nonce) <- result.try(wire.take(okm, 32, "message keys"))

  Ok(#(key, nonce))
}

fn encode_header(public: X25519Public, previous: Int, number: Int) -> BitArray {
  <<keys.x25519_public_bytes(public):bits, previous:size(32), number:size(32)>>
}

/// Splits a wire message into its parsed header, the raw header bytes (which are authenticated as AD) and the sealed body.
fn parse_message(
  message: BitArray,
) -> Result(#(Header, BitArray, BitArray), Error) {
  use #(raw_header, sealed) <- result.try(wire.take(
    message,
    header_bytes,
    "message header",
  ))
  use #(remote, rest) <- result.try(wire.take(
    raw_header,
    keys.x25519_bytes,
    "message header",
  ))
  use remote <- result.try(keys.x25519_public(remote))
  use #(previous, rest) <- result.try(wire.read_u32(rest, "message header"))
  use #(number, _) <- result.try(wire.read_u32(rest, "message header"))

  Ok(#(Header(remote, previous, number), raw_header, sealed))
}

/// Serializes a state into a versioned, fixed binary layout, held as a
/// `Secret` because it contains every key the session has.
///
/// The layout is the version byte; the session AD with a 32-bit length; the
/// sending key pair, 32 bytes each; the root key; the sending chain as a tag
/// byte (0 or 1) and, if 1, its key; the receiving chain as a tag byte and,
/// if 1, the peer's ratchet key, the chain key and the next number (32
/// bits); the sent count and PN (32 bits each); and the skipped keys as a
/// 32-bit count followed by, for each, the ratchet key, the number (32 bits)
/// and the message key. Integers are big-endian.
///
/// ## Examples
///
/// ```gleam
/// ratchet.decode_state(secret.expose(ratchet.encode_state(state)))
/// // -> Ok(state)
/// ```
pub fn encode_state(state: State) -> Secret {
  // Serialization is the one place every key leaves its wrapper, and the
  // result goes straight back into a `Secret`.
  secret.new(<<
    state_version:size(8),
    bit_array.byte_size(state.ad):size(32),
    state.ad:bits,
    keys.expose_x25519_secret(state.sending_secret):bits,
    keys.x25519_public_bytes(state.sending_public):bits,
    secret.expose(state.root):bits,
    encode_sending(state.sending_chain):bits,
    encode_receiving(state.receiving):bits,
    state.sent:size(32),
    state.previous:size(32),
    list.length(state.skipped):size(32),
    encode_skipped(state.skipped):bits,
  >>)
}

fn encode_sending(chain: Option(Secret)) -> BitArray {
  case chain {
    Some(key) -> <<1, secret.expose(key):bits>>
    None -> <<0>>
  }
}

/// The receiving chain as a tag byte and, when present, its fields.
fn encode_receiving(receiving: Option(ReceivingChain)) -> BitArray {
  case receiving {
    Some(chain) -> <<
      1,
      keys.x25519_public_bytes(chain.remote):bits,
      secret.expose(chain.chain):bits,
      chain.next:size(32),
    >>
    None -> <<0>>
  }
}

/// The skipped keys in list order, each as ratchet key, number and message key.
fn encode_skipped(skipped: List(Skipped)) -> BitArray {
  list.fold(skipped, <<>>, fn(acc, entry) {
    <<
      acc:bits,
      keys.x25519_public_bytes(entry.remote):bits,
      entry.number:size(32),
      secret.expose(entry.message_key):bits,
    >>
  })
}

/// Parses a serialized state. Decoding is total: any byte string is either
/// a state or an error, a wrong version or length is `Malformed`, and a
/// stored count over `limits.max_skipped_message_keys` is refused before any
/// entry is read, so a corrupt or hostile blob cannot make this allocate
/// without bound. It checks structure, not that the stored public key
/// matches the stored secret.
///
/// ## Examples
///
/// ```gleam
/// ratchet.decode_state(<<>>)
/// // -> Error(Malformed("state"))
/// ```
pub fn decode_state(bytes: BitArray) -> Result(State, Error) {
  use #(version, rest) <- result.try(wire.read_u8(bytes, "state"))
  use Nil <- result.try(check_version(version))
  use #(ad_size, rest) <- result.try(wire.read_u32(rest, "state"))
  use #(ad, rest) <- result.try(wire.take(rest, ad_size, "state"))
  use #(sending_secret, rest) <- result.try(read_x25519_secret(rest))
  use #(sending_public, rest) <- result.try(read_x25519_public(rest))
  use #(root, rest) <- result.try(read_secret(rest))
  use #(sending_chain, rest) <- result.try(decode_sending(rest))
  use #(receiving, rest) <- result.try(decode_receiving(rest))
  use #(sent, rest) <- result.try(wire.read_u32(rest, "state"))
  use #(previous, rest) <- result.try(wire.read_u32(rest, "state"))
  use #(count, rest) <- result.try(wire.read_u32(rest, "state"))
  use #(skipped, rest) <- result.try(decode_skipped(rest, count, []))
  use Nil <- result.try(wire.end(rest, "state"))

  Ok(State(
    ad: ad,
    sending_secret: sending_secret,
    sending_public: sending_public,
    root: root,
    sending_chain: sending_chain,
    receiving: receiving,
    sent: sent,
    previous: previous,
    skipped: skipped,
  ))
}

fn check_version(version: Int) -> Result(Nil, Error) {
  case version == state_version {
    True -> Ok(Nil)
    False -> Error(Malformed("state version"))
  }
}

/// Reads a 32-byte X25519 secret key off the front of a serialized state.
fn read_x25519_secret(
  bytes: BitArray,
) -> Result(#(X25519Secret, BitArray), Error) {
  use #(raw, rest) <- result.try(wire.take(bytes, keys.x25519_bytes, "state"))
  use key <- result.try(keys.x25519_secret(raw))

  Ok(#(key, rest))
}

/// Reads a 32-byte X25519 public key off the front of a serialized state.
fn read_x25519_public(
  bytes: BitArray,
) -> Result(#(X25519Public, BitArray), Error) {
  use #(raw, rest) <- result.try(wire.take(bytes, keys.x25519_bytes, "state"))
  use key <- result.try(keys.x25519_public(raw))

  Ok(#(key, rest))
}

fn read_secret(bytes: BitArray) -> Result(#(Secret, BitArray), Error) {
  use #(raw, rest) <- result.try(wire.take(bytes, 32, "state"))

  Ok(#(secret.new(raw), rest))
}

/// Reads the sending chain: a tag byte, then a chain key when the tag is 1.
fn decode_sending(
  bytes: BitArray,
) -> Result(#(Option(Secret), BitArray), Error) {
  use #(tag, rest) <- result.try(wire.read_u8(bytes, "state"))

  // The tag byte is 0 or 1; anything else is corruption.
  case tag {
    0 -> Ok(#(None, rest))

    1 -> {
      use #(key, rest) <- result.try(read_secret(rest))

      Ok(#(Some(key), rest))
    }

    _ -> Error(Malformed("state"))
  }
}

/// Reads the receiving chain: a tag byte, then its fields when the tag is 1.
fn decode_receiving(
  bytes: BitArray,
) -> Result(#(Option(ReceivingChain), BitArray), Error) {
  use #(tag, rest) <- result.try(wire.read_u8(bytes, "state"))

  // The tag byte is 0 or 1; anything else is corruption.
  case tag {
    0 -> Ok(#(None, rest))

    1 -> {
      use #(remote, rest) <- result.try(read_x25519_public(rest))
      use #(chain, rest) <- result.try(read_secret(rest))
      use #(next, rest) <- result.try(wire.read_u32(rest, "state"))

      Ok(#(Some(ReceivingChain(remote: remote, chain: chain, next: next)), rest))
    }

    _ -> Error(Malformed("state"))
  }
}

/// Reads `count` skipped entries. The count is bounded before the first read,
/// and each read consumes input, so the loop is bounded by both the limit and
/// the length of the blob.
fn decode_skipped(
  bytes: BitArray,
  count: Int,
  acc: List(Skipped),
) -> Result(#(List(Skipped), BitArray), Error) {
  case count > limits.max_skipped_message_keys {
    True -> Error(SkippedKeyStoreFull)
    False -> read_skipped(bytes, count, acc)
  }
}

/// Reads `count` skipped entries, newest first, consuming input as it goes.
fn read_skipped(
  bytes: BitArray,
  count: Int,
  acc: List(Skipped),
) -> Result(#(List(Skipped), BitArray), Error) {
  // Zero remaining ends the list; otherwise one entry is read and the rest follows.
  case count {
    0 -> Ok(#(list.reverse(acc), bytes))

    _ -> {
      use #(remote, rest) <- result.try(read_x25519_public(bytes))
      use #(number, rest) <- result.try(wire.read_u32(rest, "state"))
      use #(message_key, rest) <- result.try(read_secret(rest))
      let entry =
        Skipped(remote: remote, number: number, message_key: message_key)

      read_skipped(rest, count - 1, [entry, ..acc])
    }
  }
}
