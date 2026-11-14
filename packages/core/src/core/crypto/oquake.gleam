//// OQUAKE: the post-quantum symmetric PAKE of `draft-vos-cfrg-pqpake-03`
//// §6, over ML-BUA-sKEM-1024 and HKDF-SHA-256.
////
//// Two parties who share a low-entropy password-related string (PRS) want
//// a key that an eavesdropper, or an active attacker who gets one guess
//// per run, cannot learn. OQUAKE is two messages. The initiator makes a
//// fresh ML-BUA-sKEM key pair and encrypts the secret-key-dependent part of
//// the public key, `ut`, under the password with a two-round Feistel
//// network; the responder decrypts it with its own copy of the password,
//// encapsulates to the result, and answers with the ciphertext and a
//// confirmation tag `h`. Both derive the session key from everything sent.
//// A wrong password at the responder decrypts to a different but equally
//// well-formed key (`core/crypto/kemeleon` explains why every string is
//// one), so the initiator's tag check fails and it, too, ends with a key
//// unrelated to the responder's.
////
//// In Pondline OQUAKE is Stage 2 of CPaceOQUAKE (§7): the PRS is the code's
//// words, the secret context is CPace's session key and the public context
//// CPace's transcript hash. The DST is that of the outermost configuration
//// (§9), so it is an argument here and not a constant: the
//// `oquake-mlbuaskem1024` vectors of Appendix E.2 and the CPaceOQUAKE
//// vectors of E.4 use different ones, and `packages/primitives/test` runs
//// both.
////
//// ## Derivations
////
//// `Extract(salt, ikm)` and `Expand(prk, info, L)` are HKDF-SHA-256
//// (`core/crypto/hkdf`), `lv` a two-byte big-endian length prefix, and
//// `||` concatenation. Fixed-length fields are not prefixed. `lv` and `TH`
//// are the draft's shared definitions in `core/crypto/pake_common`, which
//// CPace and the combiner use too, and `EncodePublicContext` lives there
//// alone.
////
//// ```text
//// effective_PRS = Expand(Extract(PRS, DST || "OQUAKE-context" ||
////                   lv(public_context) || lv(secret_context)),
////                 DST || "effective_PRS", 32)
//// (ut, rho)     = Split(upk)                     upk from BUA-sKEM.KeyGen
//// T             = ut XOR Expand(Extract(effective_PRS, DST || "OQUAKE" ||
////                   rho || r), DST || "T_pad", 1564)
//// s             = r XOR Expand(Extract(effective_PRS, DST || "OQUAKE" ||
////                   rho || T), DST || "s_pad", 64)
//// prk_sk        = Extract(effective_PRS, DST || "OQUAKE" ||
////                   s || T || rho || upk || ct || k)
//// h             = Expand(prk_sk, DST || "confirm", 32)
//// key           = Expand(prk_sk, DST || "key", 32)
//// th            = Extract(DST || "TH-OQUAKE",
////                   lv(public_context) || lv(s) || lv(T) || lv(rho) ||
////                   lv(ct) || lv(h))
//// ```
////
//// `r` is 64 fresh random bytes. The responder runs the Feistel network
//// backwards: the `s_pad` round first to recover `r`, then the `T_pad`
//// round to recover `ut`.
////
//// ## Messages (Appendix C.2)
////
//// ```text
//// init message      = s (64) || T (1564) || rho (32)        1660 bytes
//// response message  = ct (1568) || h (32)                   1600 bytes
//// ```
////
//// A message of any other length is refused with a typed `Refusal`, as the
//// draft requires (it says the party MUST abort). Nothing else about a
//// message is checked, because every string of the right length is a
//// possible message.
////
//// ## Randomness and secrets
////
//// `init` and `finish` draw from the suite; `init_with` and `finish_with`
//// take the key pair, `r` and the fallback key as arguments, so a test can
//// pin every random value the draft's vectors list. The responder's only
//// randomness is ML-KEM's own, inside `suite.kem_encapsulate`. The PRS, the
//// secret context, the effective PRS, the decapsulation key and the
//// session keys are `Secret`s, and `InitiatorState` is opaque, so none of
//// them prints. The `s`, `T` and `rho` values held in the state are on the
//// wire anyway.
////
//// What is not constant time: Kemeleon's arithmetic (its module doc), and
//// the XOR of the Feistel rounds, done here over the BEAM's integers. The
//// tag comparison goes through `suite.constant_time_equal`, and `finish`
//// draws its fallback key whether or not it will use it, so both outcomes
//// make the same calls on the suite.

import core/crypto/bua_skem.{type KeyPair, Encapsulation, SplitKey}
import core/crypto/hkdf
import core/crypto/pake_common
import core/crypto/suite.{type Suite}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/result

/// The bytes of `r`, the initiator's randomness: Nr in pqpake §9.1.
pub const r_bytes = 64

/// The bytes of the confirmation tag `h`: Nkc in pqpake §9.1.
pub const tag_bytes = 32

/// The bytes of the session key: Nkey in pqpake §9.1.
pub const key_bytes = 32

/// The bytes of the transcript hash, HKDF-SHA-256's extract output.
pub const transcript_hash_bytes = 32

/// The bytes of an initiator message: Nr + Nt + N-rho.
pub const init_message_bytes = 1660

/// The bytes of a responder message: Nct + Nkc.
pub const response_message_bytes = 1600

/// The label of OQUAKE's transcript hash, `TH("OQUAKE", ...)` (§6).
const transcript_label = <<"OQUAKE":utf8>>

/// The inputs both parties bring to a run: pqpake §5's common interface,
/// with the configuration's DST.
pub type Inputs {
  Inputs(
    /// The domain separation tag of the outermost configuration: §9.2.1's
    /// for OQUAKE alone, §9.4.1's for OQUAKE inside CPaceOQUAKE.
    dst: BitArray,
    /// The password-related string. A spoken code's words, in Pondline.
    prs: Secret,
    /// Public session information both sides agree on, at most 65 535
    /// bytes. CPaceOQUAKE passes CPace's transcript hash.
    public_context: BitArray,
    /// Confidential information both sides share, never sent, at most
    /// 65 535 bytes, and empty when there is none. CPaceOQUAKE passes
    /// CPace's session key.
    secret_context: Secret,
  )
}

/// What the initiator keeps between `init` and `finish`: the effective
/// password, its key pair and what it sent. Opaque, and its secrets are
/// `Secret`s, so it cannot be printed or forged.
pub opaque type InitiatorState {
  InitiatorState(
    dst: BitArray,
    effective_prs: Secret,
    key_pair: KeyPair,
    sent: Sent,
    public_context: BitArray,
  )
}

/// The responder's output: the message to send back, its session key and
/// the transcript hash.
pub type Response {
  Response(
    /// The `response_message_bytes` message `ct || h` for the initiator.
    message: BitArray,
    /// The session key. It equals the initiator's only if the two used the
    /// same PRS, public context and secret context.
    key: Secret,
    /// The transcript hash over the public context and both messages.
    transcript_hash: BitArray,
  )
}

/// The initiator's output from `finish`.
pub type Established {
  Established(
    /// The session key, or a fresh random key if the responder's tag did
    /// not verify; the two cannot be told apart from here.
    key: Secret,
    /// The transcript hash over the public context and both messages.
    transcript_hash: BitArray,
  )
}

/// Why a run could not go on. No variant carries a key, a password or a
/// message: only lengths, which are public.
pub type Refusal {
  /// The initiator message was not `init_message_bytes` long.
  InitMessageLength(found: Int)

  /// The responder message was not `response_message_bytes` long.
  ResponseMessageLength(found: Int)

  /// The public or secret context is longer than its two-byte length
  /// prefix can say (`pake_common.max_field_bytes`).
  ContextTooLong

  /// `init_with` was given a key pair or an `r` of the wrong size.
  MalformedKeyMaterial

  /// The suite failed on input whose sizes were already checked, which a
  /// correct suite never does.
  PrimitiveFailed
}

/// The fields of the initiator message, which both sides hash into the
/// session key and the transcript.
type Sent {
  Sent(s: BitArray, t: BitArray, rho: BitArray)
}

/// One side's view of a run: the suite, the DST and the derived password,
/// which every derivation after the first needs.
type Run {
  Run(
    suite: Suite,
    dst: BitArray,
    effective_prs: Secret,
    public_context: BitArray,
  )
}

/// `OQUAKE.Init`: a fresh key pair and `r` from the suite, then
/// `init_with`. Returns the state to keep and the `init_message_bytes`
/// message to send.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(state, message)) = oquake.init(suite, inputs)
/// bit_array.byte_size(message)
/// // -> 1660
/// ```
pub fn init(
  suite: Suite,
  inputs: Inputs,
) -> Result(#(InitiatorState, BitArray), Refusal) {
  use key_pair <- result.try(
    bua_skem.keygen(suite) |> result.replace_error(PrimitiveFailed),
  )

  init_with(suite, inputs, key_pair, secret.new(suite.random(r_bytes)))
}

/// `OQUAKE.Init` with its randomness given: the key pair (whose public key
/// already carries Kemeleon's randomness) and `r`, which must be `r_bytes`
/// long. The public key's `ut` is masked by the `T_pad` round keyed by
/// `r`, and `r` by the `s_pad` round keyed by the masked `T`, so the
/// message is `s || T || rho`.
///
/// ## Examples
///
/// ```gleam
/// oquake.init_with(suite, inputs, key_pair, secret.new(r))
/// // -> Ok(#(state, init_message))
/// ```
pub fn init_with(
  suite: Suite,
  inputs: Inputs,
  key_pair: KeyPair,
  r: Secret,
) -> Result(#(InitiatorState, BitArray), Refusal) {
  use SplitKey(ut:, rho:) <- result.try(
    bua_skem.split(key_pair.public_key)
    |> result.replace_error(MalformedKeyMaterial),
  )
  use <- bool.guard(
    when: secret.byte_size(r) != r_bytes,
    return: Error(MalformedKeyMaterial),
  )
  use run <- result.try(begin(suite, inputs))

  // The first Feistel round hides `ut` under a pad keyed by `r`; `r` is
  // exposed only to key that pad and to be masked in the next round.
  let r = secret.expose(r)
  use t_pad <- result.try(pad(run, rho, r, "T_pad", bua_skem.dependent_bytes))
  use t <- result.try(xor(ut, t_pad))

  // The second round hides `r` under a pad keyed by `T`, so the responder
  // can strip it with nothing but the password and what it received.
  use s_pad <- result.try(pad(run, rho, t, "s_pad", r_bytes))
  use s <- result.try(xor(r, s_pad))

  let sent = Sent(s:, t:, rho:)
  let state =
    InitiatorState(
      dst: inputs.dst,
      effective_prs: run.effective_prs,
      key_pair:,
      sent:,
      public_context: inputs.public_context,
    )

  Ok(#(state, <<s:bits, t:bits, rho:bits>>))
}

/// `OQUAKE.Respond`: unmask the initiator's public key with this side's
/// password, encapsulate to it, and derive the tag, the session key and
/// the transcript hash. A wrong password does not fail here: it unmasks to
/// another valid key, and the mismatch surfaces as unequal session keys.
/// Only a message of the wrong length is refused.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(Response(message:, key:, transcript_hash:)) =
///   oquake.respond(suite, inputs, init_message)
/// bit_array.byte_size(message)
/// // -> 1600
/// ```
pub fn respond(
  suite: Suite,
  inputs: Inputs,
  init_message: BitArray,
) -> Result(Response, Refusal) {
  use sent <- result.try(read_init_message(init_message))
  use run <- result.try(begin(suite, inputs))
  let Sent(s:, t:, rho:) = sent

  // The Feistel network backwards: the `s_pad` round first gives back `r`,
  // and `r` keys the `T_pad` round that gives back `ut`.
  use s_pad <- result.try(pad(run, rho, t, "s_pad", r_bytes))
  use r <- result.try(xor(s, s_pad))
  use t_pad <- result.try(pad(run, rho, r, "T_pad", bua_skem.dependent_bytes))
  use ut <- result.try(xor(t, t_pad))

  // Every `ut` combines into a key Kemeleon can decode, so encapsulation
  // succeeds whatever password produced it.
  use public_key <- result.try(
    bua_skem.combine(ut, rho) |> result.replace_error(PrimitiveFailed),
  )
  use Encapsulation(shared_secret:, ciphertext:) <- result.try(
    bua_skem.encapsulate(suite, public_key)
    |> result.replace_error(PrimitiveFailed),
  )

  use #(tag, key) <- result.try(session_keys(
    run,
    sent,
    public_key,
    ciphertext,
    shared_secret,
  ))
  use transcript_hash <- result.map(transcript(run, sent, ciphertext, tag))

  Response(message: <<ciphertext:bits, tag:bits>>, key:, transcript_hash:)
}

/// `OQUAKE.Finish`: draws a fallback key from the suite, then
/// `finish_with`. The draw happens on every call, so a run that verifies
/// and one that does not make the same calls on the suite.
///
/// Completion is not evidence that the peer knows the password. The draft
/// (§6.3) says callers MUST NOT treat the output of Finish as such
/// evidence: a bad tag or a failed decapsulation returns a fresh random
/// key, indistinguishable from here from the real one, so that no failure
/// signal tells an attacker its guess was wrong. A caller that needs to
/// know must confirm explicitly with a key derived from this one, as
/// ADR-016's `confirm_J` and the hand-off AEAD do.
///
/// ## Examples
///
/// ```gleam
/// oquake.finish(suite, state, response_message)
/// // -> Ok(Established(key:, transcript_hash:))
/// ```
pub fn finish(
  suite: Suite,
  state: InitiatorState,
  response_message: BitArray,
) -> Result(Established, Refusal) {
  finish_with(
    suite,
    state,
    response_message,
    secret.new(suite.random(key_bytes)),
  )
}

/// `OQUAKE.Finish` with its fallback key given: the key returned, in place
/// of the session key, when decapsulation fails or the tag `h` does not
/// match the one recomputed from the decapsulated secret. The transcript
/// hash is computed from the message as received either way. Only a
/// message of the wrong length is refused, and that is a public fact.
///
/// The same warning as `finish`: an `Ok` here proves nothing about the
/// peer's password.
///
/// ## Examples
///
/// ```gleam
/// oquake.finish_with(suite, state, response_message, secret.new(fallback))
/// // -> Ok(Established(key:, transcript_hash:))
/// ```
pub fn finish_with(
  suite: Suite,
  state: InitiatorState,
  response_message: BitArray,
  fallback: Secret,
) -> Result(Established, Refusal) {
  use #(ciphertext, tag) <- result.try(read_response_message(response_message))
  let run =
    Run(
      suite:,
      dst: state.dst,
      effective_prs: state.effective_prs,
      public_context: state.public_context,
    )
  use transcript_hash <- result.try(transcript(run, state.sent, ciphertext, tag))

  // A decapsulation failure is the draft's DecapsError, which Finish turns
  // into the fallback key rather than an error (§6.3, §10): surfacing it
  // would tell the peer something about its guess.
  case
    bua_skem.decapsulate(suite, state.key_pair.decapsulation_key, ciphertext)
  {
    Ok(shared_secret) -> {
      use #(expected, key) <- result.map(session_keys(
        run,
        state.sent,
        state.key_pair.public_key,
        ciphertext,
        shared_secret,
      ))

      // The tag is compared in constant time, and a mismatch yields the
      // fallback, never an error: a wrong password must look like success.
      let key = case suite.constant_time_equal(tag, expected) {
        True -> key
        False -> fallback
      }

      Established(key:, transcript_hash:)
    }

    Error(_) -> Ok(Established(key: fallback, transcript_hash:))
  }
}

/// Both sides' first step: the effective password, from the PRS keyed over
/// the DST and both length-prefixed contexts, so that a run whose public
/// or secret context differs is, to OQUAKE, a run with another password.
fn begin(suite: Suite, inputs: Inputs) -> Result(Run, Refusal) {
  use public_context <- result.try(prefixed(inputs.public_context))

  // The secret context leaves its closure only to be hashed with the PRS.
  use secret_context <- result.try(
    prefixed(secret.expose(inputs.secret_context)),
  )
  let info = <<
    inputs.dst:bits,
    "OQUAKE-context":utf8,
    public_context:bits,
    secret_context:bits,
  >>

  // The PRS is the extract salt, as the draft writes it, so it is exposed
  // only to key that one HMAC.
  let prk = hkdf.extract(suite, secret.expose(inputs.prs), info)
  use effective <- result.map(expand(
    suite,
    prk,
    <<inputs.dst:bits, "effective_PRS":utf8>>,
    key_bytes,
  ))

  Run(
    suite:,
    dst: inputs.dst,
    effective_prs: secret.new(effective),
    public_context: inputs.public_context,
  )
}

/// One Feistel pad: `Expand(Extract(effective_PRS, DST || "OQUAKE" || rho
/// || input), DST || label, length)`. `T_pad` is keyed by `r` and `s_pad`
/// by `T`; rho binds both to the key's public seed.
fn pad(
  run: Run,
  rho: BitArray,
  input: BitArray,
  label: String,
  length: Int,
) -> Result(BitArray, Refusal) {
  let prk =
    hkdf.extract(run.suite, secret.expose(run.effective_prs), <<
      run.dst:bits,
      "OQUAKE":utf8,
      rho:bits,
      input:bits,
    >>)

  expand(run.suite, prk, <<run.dst:bits, label:utf8>>, length)
}

/// The tag `h` and the session key, both expanded from one key extracted
/// over the whole run: the message fields, the unmasked public key, the
/// ciphertext and the shared secret. The two sides agree on it only if
/// they agree on all of those and on the effective password.
fn session_keys(
  run: Run,
  sent: Sent,
  public_key: BitArray,
  ciphertext: BitArray,
  shared_secret: Secret,
) -> Result(#(BitArray, Secret), Refusal) {
  // The shared secret is exposed only into the extract that consumes it.
  let ikm = <<
    run.dst:bits,
    "OQUAKE":utf8,
    sent.s:bits,
    sent.t:bits,
    sent.rho:bits,
    public_key:bits,
    ciphertext:bits,
    secret.expose(shared_secret):bits,
  >>
  let prk = hkdf.extract(run.suite, secret.expose(run.effective_prs), ikm)

  use tag <- result.try(expand(
    run.suite,
    prk,
    <<run.dst:bits, "confirm":utf8>>,
    tag_bytes,
  ))
  use key <- result.map(expand(
    run.suite,
    prk,
    <<run.dst:bits, "key":utf8>>,
    key_bytes,
  ))

  #(tag, secret.new(key))
}

/// `TH("OQUAKE", public_context, s, T, rho, ct, h)` of pqpake §5, through
/// the shared `pake_common.transcript_hash` under this run's DST. It covers
/// only public values, so both sides compute it whatever happened to the
/// keys.
fn transcript(
  run: Run,
  sent: Sent,
  ciphertext: BitArray,
  tag: BitArray,
) -> Result(BitArray, Refusal) {
  pake_common.transcript_hash(run.suite, run.dst, transcript_label, [
    run.public_context,
    sent.s,
    sent.t,
    sent.rho,
    ciphertext,
    tag,
  ])
  |> result.replace_error(ContextTooLong)
}

/// Appendix C.2's initiator message: `s`, `T` and `rho` at fixed offsets,
/// refused unless it is exactly `init_message_bytes` long.
fn read_init_message(message: BitArray) -> Result(Sent, Refusal) {
  let t_bytes = bua_skem.dependent_bytes
  let rho_bytes = bua_skem.seed_bytes

  // Exactly the three fields, or the length is wrong: any bytes of the
  // right length are a message someone could have sent.
  case message {
    <<s:bytes-size(r_bytes), t:bytes-size(t_bytes), rho:bytes-size(rho_bytes)>> ->
      Ok(Sent(s:, t:, rho:))

    _ -> Error(InitMessageLength(found: bit_array.byte_size(message)))
  }
}

/// Appendix C.2's responder message: `ct` then `h`, refused unless it is
/// exactly `response_message_bytes` long.
fn read_response_message(
  message: BitArray,
) -> Result(#(BitArray, BitArray), Refusal) {
  let ciphertext_bytes = bua_skem.ciphertext_bytes

  // Exactly the ciphertext and the tag, or the length is wrong.
  case message {
    <<ciphertext:bytes-size(ciphertext_bytes), tag:bytes-size(tag_bytes)>> ->
      Ok(#(ciphertext, tag))

    _ -> Error(ResponseMessageLength(found: bit_array.byte_size(message)))
  }
}

/// `lv_encode` of pqpake §3.1 with its refusal named: a field past
/// `pake_common.max_field_bytes` is a context too long, never wrapped.
fn prefixed(bytes: BitArray) -> Result(BitArray, Refusal) {
  pake_common.lv_encode(bytes)
  |> result.replace_error(ContextTooLong)
}

/// HKDF-Expand with the crypto layer's error mapped. Every length here is
/// a constant far below HKDF's limit, so the error arm is unreachable.
fn expand(
  suite: Suite,
  prk: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Refusal) {
  hkdf.expand(suite, prk, info, length)
  |> result.replace_error(PrimitiveFailed)
}

/// XOR of two byte strings of the same length, as two big integers. A
/// length mismatch cannot happen for the pads above, whose lengths are the
/// fields', and is refused rather than truncated if it ever does.
fn xor(left: BitArray, right: BitArray) -> Result(BitArray, Refusal) {
  let size = bit_array.bit_size(left)

  // Equal lengths XOR as integers of that many bits; anything else is a bug.
  case left, right {
    <<left:size(size)>>, <<right:size(size)>> ->
      Ok(<<int.bitwise_exclusive_or(left, right):size(size)>>)

    _, _ -> Error(PrimitiveFailed)
  }
}
