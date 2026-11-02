//// The invitation ticket: a short string that stands in for a 14.6 KB
//// invitation file (ADR-009).
////
//// An invitation embeds the inviter's post-quantum prekey bundle, so it is
//// too large to read aloud or paste into a chat. A ticket carries only two
//// things: where the inviter's mailbox is, and a fresh 32-byte secret `K`.
//// The invitation itself waits at that mailbox, sealed under keys derived
//// from `K`, and the joiner fetches and opens it. Anything the ticket cannot
//// carry stays inside the sealed invitation.
////
//// ## Text form
////
//// `pl1` followed by the data and a fifteen-character checksum, all in the
//// bech32 alphabet (`core/codex32`). The first data symbol is the format:
//// 0 for an onion mailbox, 1 for a loopback one (tests and the demo). The
//// rest is the payload regrouped as 5-bit symbols, its padding bits zero:
////
//// | Format | Payload | Ticket length |
//// |---|---|---|
//// | 0, onion | decoded onion label (35) or port (2) or `K` (32) | 130 |
//// | 1, loopback | port (2) or `K` (32) | 74 |
////
//// (Read "or" as concatenation; the table cannot hold a bar.) The port is
//// big-endian. A future format is a new first symbol, refused here as
//// `UnknownFormat`. The decoder is total and strict: lowercase only, no
//// whitespace, the checksum first, exact lengths and zero padding, so a
//// string it accepts is the only spelling of its ticket.
////
//// ## Derivations
////
//// ```text
//// PRK        = HKDF-Extract(salt = "Pondline_Ticket_v1", ikm = K)
//// locator    = HKDF-Expand(PRK, "Pondline_TicketLocator_v1", 16)
//// retrieve   = HKDF-Expand(PRK, "Pondline_TicketCapability_v1", 32)
//// key, nonce = HKDF-Expand(PRK, "Pondline_TicketKey_v1", 44)   32 then 12
//// commit_key = HKDF-Expand(PRK, "Pondline_TicketCommitment_v1", 32)
//// ```
////
//// The mailbox sees the locator (the blob's name), the hash of the retrieve
//// capability and the sealed bytes; it learns nothing it does not already
//// see for a queue. The AEAD key and the commitment key never leave the two
//// daemons.
////
//// ## Sealed blob
////
//// ```text
//// blob       = 0x01 || commitment (32) || ChaCha20-Poly1305(key, nonce,
////                aad = "Pondline_TicketBlob_v1" || locator, invitation)
//// commitment = HMAC-SHA-256(commit_key, invitation)
//// ```
////
//// ChaCha20-Poly1305 is not key-committing: someone who chooses two keys can
//// build one ciphertext that opens under both. A mailbox without `K` cannot
//// forge a blob that opens at all, but the inviter, or anyone a ticket
//// leaked to, knows `K`. The commitment closes that: `open` recomputes it
//// from the plaintext and refuses a blob whose commitment differs, so one
//// stored blob opens to at most one invitation for every ticket, and an
//// invitation is never used until it has passed both the AEAD and the
//// commitment. Each key encrypts exactly one plaintext, so the derived
//// nonce is never reused, and sealing the same invitation twice under one
//// ticket gives the same bytes, which is what makes a retried store
//// idempotent.

import core/capability.{type Capability, type Retrieve}
import core/codex32
import core/crypto/hkdf
import core/crypto/suite.{type Suite}
import core/endpoint.{type Endpoint, Loopback, Onion}
import core/id.{type Blob, type Id}
import core/limits
import core/secret.{type Secret}
import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/result
import gleam/string

/// The human-readable part of every ticket.
pub const prefix = "pl"

/// The size of a ticket's secret `K`, in bytes.
pub const secret_bytes = 32

/// The version byte a sealed blob starts with.
pub const blob_version = 1

/// The bytes a sealed blob adds to the invitation: the version, the
/// commitment and the AEAD tag.
pub const blob_overhead_bytes = 49

/// A ticket: the inviter's mailbox and the secret every key is derived from.
/// The secret is a `Secret`, so a ticket prints as a closure.
pub opaque type Ticket {
  Ticket(endpoint: Endpoint, secret: Secret)
}

/// The values derived from a ticket's secret.
pub type Keys {
  Keys(
    /// The blob's name at the mailbox. Not secret from the mailbox.
    locator: Id(Blob),
    /// The capability that fetches the blob; the mailbox stores its hash.
    retrieve: Capability(Retrieve),
    /// The AEAD key that seals the invitation. Never leaves a daemon.
    key: Secret,
    /// The AEAD nonce, used with `key` exactly once.
    nonce: BitArray,
    /// The key of the commitment to the plaintext. Never leaves a daemon.
    commit_key: Secret,
  )
}

/// Why text is not a ticket. No variant carries any of the text.
pub type TicketError {
  /// Not `pl1` and bech32 characters, or longer than
  /// `limits.max_ticket_bytes`.
  NotATicket

  /// The checksum does not match: a character was mistyped.
  BadChecksum

  /// The format symbol names no format this build reads.
  UnknownFormat

  /// The payload has the wrong length, non-zero padding, or names a
  /// mailbox that is not a valid endpoint.
  BadPayload
}

/// Why a sealed blob did not yield an invitation. None carries bytes.
pub type OpenError {
  /// The blob is shorter than its fixed fields or has another version.
  MalformedBlob

  /// The AEAD refused it: it was not sealed under this ticket's key.
  NotSealedForTicket

  /// It opened, but its commitment does not match the plaintext, so it
  /// cannot be the invitation the ticket was issued for.
  CommitmentMismatch
}

/// A fresh ticket for a mailbox, its secret drawn from the suite's
/// randomness.
///
/// ## Examples
///
/// ```gleam
/// ticket.generate(suite, mailbox)
/// // -> Ok(ticket)
/// ```
pub fn generate(suite: Suite, mailbox: Endpoint) -> Result(Ticket, Nil) {
  from_parts(mailbox, suite.random(secret_bytes))
}

/// A ticket from its mailbox and secret bytes, which must be
/// `secret_bytes` long.
///
/// ## Examples
///
/// ```gleam
/// ticket.from_parts(mailbox, <<0:256>>)
/// // -> Ok(ticket)
/// ```
pub fn from_parts(mailbox: Endpoint, secret: BitArray) -> Result(Ticket, Nil) {
  case bit_array.byte_size(secret) == secret_bytes {
    True -> Ok(Ticket(endpoint: mailbox, secret: secret.new(secret)))
    False -> Error(Nil)
  }
}

/// The mailbox that holds the ticket's sealed invitation.
///
/// ## Examples
///
/// ```gleam
/// ticket.endpoint(ticket)
/// // -> Loopback(port)
/// ```
pub fn endpoint(ticket: Ticket) -> Endpoint {
  ticket.endpoint
}

/// The ticket's text, as a `Secret` because it is the authority to fetch
/// and open the invitation.
///
/// ## Examples
///
/// ```gleam
/// secret.expose(ticket.encode(ticket))
/// // -> <<"pl1qq...":utf8>>
/// ```
pub fn encode(ticket: Ticket) -> Secret {
  // The secret is exposed only to be spelled into the ticket's own text,
  // which is itself returned as a secret.
  let key = secret.expose(ticket.secret)

  // The endpoint decides the format symbol and what the payload holds.
  let #(format, payload) = case ticket.endpoint {
    Onion(address:, port:) -> #(onion_format, <<
      endpoint.onion_bytes(address):bits,
      endpoint.port_number(port):size(16),
      key:bits,
    >>)

    Loopback(port:) -> #(loopback_format, <<
      endpoint.port_number(port):size(16),
      key:bits,
    >>)
  }

  let data = [format, ..codex32.bytes_to_symbols(payload)]
  let symbols = codex32.from_symbols(data)
  let checksum = codex32.from_symbols(codex32.checksum(prefix, data))

  secret.new(<<prefix:utf8, "1":utf8, symbols:utf8, checksum:utf8>>)
}

/// Reads a ticket's text. The checksum is checked before the payload is
/// read, so a mistyped ticket is `BadChecksum` whatever it would decode to.
///
/// ## Examples
///
/// ```gleam
/// ticket.decode("pl1qq")
/// // -> Error(BadChecksum)
/// ```
pub fn decode(text: String) -> Result(Ticket, TicketError) {
  use <- bool.guard(
    string.byte_size(text) > limits.max_ticket_bytes,
    Error(NotATicket),
  )
  use body <- result.try(after_prefix(text))
  use symbols <- result.try(
    codex32.to_symbols(body) |> result.replace_error(NotATicket),
  )
  use <- bool.guard(!codex32.verify(prefix, symbols), Error(BadChecksum))

  // The checksum is the last `checksum_symbols`; the rest is the data,
  // whose first symbol is the format.
  let data = list.take(symbols, list.length(symbols) - codex32.checksum_symbols)

  // The format symbol selects the payload's layout; a symbol no format
  // claims is refused before the payload is read.
  case data {
    [format, ..payload] if format == onion_format -> read_onion(payload)

    [format, ..payload] if format == loopback_format -> read_loopback(payload)

    [_, ..] -> Error(UnknownFormat)

    [] -> Error(BadPayload)
  }
}

/// The values derived from a ticket's secret, each under its own label.
///
/// ## Examples
///
/// ```gleam
/// ticket.keys(suite, ticket)
/// // -> Ok(Keys(locator:, retrieve:, ..))
/// ```
pub fn keys(suite: Suite, ticket: Ticket) -> Result(Keys, Nil) {
  // The secret is exposed only as HKDF's input keying material.
  let prk =
    hkdf.extract(suite, <<extract_salt:utf8>>, secret.expose(ticket.secret))
  let expand = fn(label: String, length: Int) {
    hkdf.expand(suite, prk, <<label:utf8>>, length)
    |> result.replace_error(Nil)
  }

  use locator_bytes <- result.try(expand(locator_label, id.id_bytes))
  use locator <- result.try(id.from_bytes(locator_bytes))
  use retrieve_bytes <- result.try(expand(
    capability_label,
    capability.capability_bytes,
  ))
  use retrieve <- result.try(capability.from_bytes(retrieve_bytes))
  use sealing <- result.try(expand(key_label, aead_key_bytes + nonce_bytes))
  use commit_bytes <- result.try(expand(commitment_label, commit_key_bytes))

  // HKDF returned exactly the 44 bytes asked for, so the split always
  // matches; the other arm is the type's, not a reachable state.
  case sealing {
    <<key:bytes-size(aead_key_bytes), nonce:bytes-size(nonce_bytes)>> ->
      Ok(Keys(
        locator:,
        retrieve:,
        key: secret.new(key),
        nonce:,
        commit_key: secret.new(commit_bytes),
      ))

    _ -> Error(Nil)
  }
}

/// Seals an invitation file for the mailbox. Deterministic in the keys and
/// the invitation, so sealing twice gives the same blob.
///
/// ## Examples
///
/// ```gleam
/// ticket.seal(suite, keys, invitation_bytes)
/// // -> Ok(<<1, ...>>)
/// ```
pub fn seal(
  suite: Suite,
  keys: Keys,
  invitation: BitArray,
) -> Result(BitArray, Nil) {
  // The keys are exposed only to the primitives that use them.
  let commitment = suite.hmac_sha256(secret.expose(keys.commit_key), invitation)

  use sealed <- result.try(suite.aead_seal(
    secret.expose(keys.key),
    keys.nonce,
    associated_data(keys),
    invitation,
  ))

  Ok(<<blob_version, commitment:bits, sealed:bits>>)
}

/// Opens a sealed blob and returns the invitation file inside. The AEAD is
/// checked first, then the commitment, and nothing is returned unless both
/// pass. The bytes returned are still an unverified invitation file;
/// `core/invitation.decode` verifies its bundle.
///
/// ## Examples
///
/// ```gleam
/// ticket.open(suite, keys, blob)
/// // -> Ok(invitation_bytes)
/// ```
pub fn open(
  suite: Suite,
  keys: Keys,
  blob: BitArray,
) -> Result(BitArray, OpenError) {
  use #(commitment, sealed) <- result.try(blob_fields(blob))

  use invitation <- result.try(
    suite.aead_open(
      secret.expose(keys.key),
      keys.nonce,
      associated_data(keys),
      sealed,
    )
    |> result.replace_error(NotSealedForTicket),
  )

  // The AEAD alone is not a commitment to one plaintext; the HMAC is.
  let expected = suite.hmac_sha256(secret.expose(keys.commit_key), invitation)

  // Only an invitation whose commitment matches leaves this function.
  case suite.constant_time_equal(expected, commitment) {
    True -> Ok(invitation)
    False -> Error(CommitmentMismatch)
  }
}

// ------------------------------------------------------------------ format

const onion_format = 0

const loopback_format = 1

/// Payload bytes of each format: the onion label, the port, the secret.
const onion_payload_bytes = 69

const loopback_payload_bytes = 34

/// Reads an onion payload: the decoded label, the port, the secret.
fn read_onion(payload: List(Int)) -> Result(Ticket, TicketError) {
  use bytes <- result.try(payload_bytes(payload, onion_payload_bytes))
  let label_size = endpoint.onion_address_bytes

  // The payload's length was checked, so only the fields' values can fail.
  case bytes {
    <<
      label:bytes-size(label_size),
      number:size(16),
      key:bytes-size(secret_bytes),
    >> -> {
      use address <- result.try(
        endpoint.onion_from_bytes(label) |> result.replace_error(BadPayload),
      )
      use port <- result.try(
        endpoint.port(number) |> result.replace_error(BadPayload),
      )

      Ok(Ticket(endpoint: Onion(address:, port:), secret: secret.new(key)))
    }

    _ -> Error(BadPayload)
  }
}

/// Reads a loopback payload: the port, the secret.
fn read_loopback(payload: List(Int)) -> Result(Ticket, TicketError) {
  use bytes <- result.try(payload_bytes(payload, loopback_payload_bytes))

  // The payload's length was checked, so only the port can fail.
  case bytes {
    <<number:size(16), key:bytes-size(secret_bytes)>> -> {
      use port <- result.try(
        endpoint.port(number) |> result.replace_error(BadPayload),
      )

      Ok(Ticket(endpoint: Loopback(port:), secret: secret.new(key)))
    }

    _ -> Error(BadPayload)
  }
}

/// The payload's bytes, which must be exactly `size` long with zero
/// padding. Checking the length here, rather than in the pattern, also
/// refuses a payload one symbol too long whose extra bits happen to be
/// zero.
fn payload_bytes(
  payload: List(Int),
  size: Int,
) -> Result(BitArray, TicketError) {
  use bytes <- result.try(
    codex32.symbols_to_bytes(payload) |> result.replace_error(BadPayload),
  )

  // Exactly the format's size, or the text is not this format's.
  case bit_array.byte_size(bytes) == size {
    True -> Ok(bytes)
    False -> Error(BadPayload)
  }
}

/// The text after the `pl1` prefix.
fn after_prefix(text: String) -> Result(String, TicketError) {
  // Any other prefix, a codex32 seed's included, is not a ticket.
  case text {
    "pl1" <> body -> Ok(body)
    _ -> Error(NotATicket)
  }
}

/// A blob's commitment and sealed invitation, after its version byte.
fn blob_fields(blob: BitArray) -> Result(#(BitArray, BitArray), OpenError) {
  // Another version, or too few bytes for the commitment, never reaches
  // the AEAD.
  case blob {
    <<version, commitment:bytes-size(32), sealed:bytes>>
      if version == blob_version
    -> Ok(#(commitment, sealed))

    _ -> Error(MalformedBlob)
  }
}

// ------------------------------------------------------------- derivation

const extract_salt = "Pondline_Ticket_v1"

const locator_label = "Pondline_TicketLocator_v1"

const capability_label = "Pondline_TicketCapability_v1"

const key_label = "Pondline_TicketKey_v1"

const commitment_label = "Pondline_TicketCommitment_v1"

const blob_label = "Pondline_TicketBlob_v1"

const aead_key_bytes = 32

const nonce_bytes = 12

const commit_key_bytes = 32

/// The AEAD's associated data: a domain label and the locator, so the
/// ciphertext is bound to the name it is stored under.
fn associated_data(keys: Keys) -> BitArray {
  <<blob_label:utf8, id.to_bytes(keys.locator):bits>>
}
