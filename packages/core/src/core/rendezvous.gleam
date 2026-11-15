//// The spoken-code pairing run of ADR-016, as a pure step function for
//// each side.
////
//// Two operators read a code such as `482719-cradle-noble-velvet` to each
//// other. The words are 33 bits, far too few to key anything, so they are
//// the password of CPaceOQUAKE (`core/crypto/cpace_oquake`), and what the
//// run delivers, once each side has proved it holds the words, is the
//// inviter's `pl1` ticket text (ADR-009). From there the joiner's flow is a
//// ticket's, unchanged. This module owns the run's framing and its key
//// schedule; it does no I/O, holds no clock and keeps no count. The
//// mailbox slot, the timeouts and the durable count of failed
//// confirmations are the daemon's.
////
//// ## The run
////
//// The joiner is the draft's client and the inviter its server, so the
//// inviter sees proof of the words before it releases anything.
////
//// ```text
//// Joiner                                                   Inviter
//// join             m1 = lv(Ya)                      -->    inviter_answer
////                  m2 = lv(Yb) || oquake_init       <--
//// joiner_confirm   m3 = ct || h || confirm_J        -->    inviter_release
////                  m4 = AEAD(handoff, ticket text)  <--    (only if confirm_J
//// joiner_receive                                            matched)
//// ```
////
//// | Message | Bytes |
//// | --- | --- |
//// | `m1` | 34, `join_message_bytes` |
//// | `m2` | 1694, `answer_message_bytes` |
//// | `m3` | 1632, `confirm_message_bytes` |
//// | `m4` | the ticket text and a 16-byte tag; at most `max_release_message_bytes()` |
////
//// Every message's length is checked before anything else is done with it,
//// so a message of the wrong shape is `MalformedMessage` and is never
//// counted as a guess.
////
//// ## The context
////
//// ```text
//// public_context = lv("Pondline_Rendezvous_v1") || lv(nameplate, ASCII) ||
////                  EncodePublicContext(sid = rendezvous id,
////                                      U = "joiner", S = "inviter")
//// secret_context = empty
//// password       = word1 "-" word2 "-" word3
//// ```
////
//// Both sides build it from what they hold: the inviter from its own code
//// and the identifier it opened the slot under, the joiner from the code it
//// was read and the identifier the mailbox answered its claim with. A
//// difference anywhere is, to the PAKE, a different password.
////
//// ## Confirmation and hand-off
////
//// CPaceOQUAKE's completion proves nothing (pqpake §6.3), so the run
//// confirms explicitly, in both directions, from the session key and the
//// transcript hash `th`:
////
//// ```text
//// PRK         = HKDF-Extract(salt = "Pondline_Rendezvous_v1", ikm = session_key)
//// confirm_key = HKDF-Expand(PRK, "Pondline_RendezvousConfirm_v1", 32)
//// confirm_J   = HMAC-SHA-256(confirm_key, th)
//// key, nonce  = HKDF-Expand(PRK, "Pondline_RendezvousHandoff_v1", 44)   32 then 12
//// m4          = ChaCha20-Poly1305(key, nonce,
////                 aad = "Pondline_RendezvousHandoff_v1" || th, ticket text)
//// ```
////
//// The inviter compares `confirm_J` in constant time and seals `m4` only on
//// a match; the joiner's proof that the inviter held the words is `m4`'s
//// tag. Either failure is `ConfirmationFailed`, the one outcome that may be
//// a spent guess. Any error ends the run: there is no retry within a run,
//// and the operator makes a new code.
////
//// ## Type-state
////
//// Each step takes the state the previous step returned and returns the
//// next, so the steps can only be taken in order. Gleam values can be
//// reused, so taking a step twice from one state is the caller's to avoid;
//// `inviter_release` says why it matters there. It matters at every step
//// for a second reason (ADR-016, second addendum): each answer a side
//// computes from a message the peer chose is something the peer can test
//// a candidate code against, so a step run on a second message at the same
//// index gives the peer, or the mailbox that serves the messages, a second
//// guess in one run. The caller acts on the first message at each index
//// and ends the run on any error. The states are opaque and
//// keep every key, the password and the ticket as `Secret`s, and no
//// `RunError` carries bytes, so nothing here prints a secret.
////
//// ## Flow
////
//// `join` → `inviter_answer` → `joiner_confirm` → `inviter_release`
//// → `joiner_receive`
////
//// 1. `invite` and `join` frame the context with `public_context`, and
////    `join` makes the joiner's CPace share, the first message.
//// 2. `inviter_answer` runs CPaceOQUAKE's respond on it.
//// 3. `joiner_confirm` finishes both stages, derives the `schedule` and
////    sends OQUAKE's response with the joiner's confirmation tag.
//// 4. `inviter_release` finishes OQUAKE, checks that tag, and only then
////    seals the ticket with `seal`.
//// 5. `joiner_receive` opens the hand-off and returns the ticket text.

import core/crypto/cpace_oquake.{type ClientState, type ServerState}
import core/crypto/hkdf
import core/crypto/pake_common
import core/crypto/suite.{type Suite}
import core/id.{type Id, type Rendezvous}
import core/limits
import core/nameplate.{type Nameplate}
import core/pairing_code.{type PairingCode}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/bool
import gleam/result

/// The run's label: the public context's first field and the salt of the
/// key schedule's extract.
pub const label = <<"Pondline_Rendezvous_v1":utf8>>

/// The label `confirm_key` is expanded under.
pub const confirm_label = <<"Pondline_RendezvousConfirm_v1":utf8>>

/// The label the hand-off key and nonce are expanded under, and the prefix
/// of `m4`'s associated data.
pub const handoff_label = <<"Pondline_RendezvousHandoff_v1":utf8>>

/// The joiner's identity in the public context, `U`.
pub const joiner_identity = <<"joiner":utf8>>

/// The inviter's identity in the public context, `S`.
pub const inviter_identity = <<"inviter":utf8>>

/// The bytes of `confirm_key` and of `confirm_J`, HMAC-SHA-256's output.
pub const confirm_bytes = 32

/// The bytes of the hand-off AEAD key, ChaCha20-Poly1305's.
pub const handoff_key_bytes = 32

/// The bytes of the hand-off nonce, ChaCha20-Poly1305's.
pub const handoff_nonce_bytes = 12

/// The bytes of ChaCha20-Poly1305's tag, which `m4` carries after the
/// ticket text.
pub const handoff_tag_bytes = 16

/// The bytes of `m1`: CPaceOQUAKE's `msg1`.
pub const join_message_bytes = cpace_oquake.init_message_bytes

/// The bytes of `m2`: CPaceOQUAKE's `msg2`.
pub const answer_message_bytes = cpace_oquake.response_message_bytes

/// The bytes of `m3`: CPaceOQUAKE's `msg3` (1600) and `confirm_J` (32).
pub const confirm_message_bytes = 1632

/// What the inviter holds before `m1` arrives: the PAKE's inputs and the
/// ticket text to release. Opaque; the password and the ticket are
/// `Secret`s.
pub opaque type InviterWaiting {
  InviterWaiting(inputs: cpace_oquake.Inputs, ticket: Secret)
}

/// What the inviter holds after answering `m1`: CPaceOQUAKE's server state
/// and the ticket text. Opaque.
pub opaque type InviterAnswered {
  InviterAnswered(server: ServerState, ticket: Secret)
}

/// What the joiner holds after sending `m1`: CPaceOQUAKE's client state.
/// Opaque.
pub opaque type JoinerSent {
  JoinerSent(client: ClientState)
}

/// What the joiner holds after sending `m3`: the hand-off key, nonce and
/// transcript hash, which open `m4`. Opaque.
pub opaque type JoinerConfirmed {
  JoinerConfirmed(schedule: Schedule)
}

/// The inviter's last step: `m4` for the joiner, and the run's transcript
/// hash.
pub type Released {
  Released(
    /// `m4`, sealed once for this run. Keep these bytes and resend them;
    /// never seal again.
    message: BitArray,
    /// CPaceOQUAKE's `th`, public, 32 bytes; equal to the joiner's
    /// `transcript_hash` on an honest run.
    transcript_hash: BitArray,
  )
}

/// Why a run ended. The variants are what ADR-016's failure report must
/// tell apart, and none carries message bytes, the code or a key.
pub type RunError {
  /// A message of the wrong length or framing. This is interference or a
  /// broken peer, never a guess at the words, and is not counted as one.
  MalformedMessage

  /// The peer's CPace share was a low-order point or zero, which the draft
  /// says MUST abort the run. Also interference rather than a guess.
  LowOrderShare

  /// The inviter's check of `confirm_J` failed, or the joiner's `m4` did
  /// not open. Either may be a spent guess, and it is what the daemon
  /// counts per rendezvous endpoint.
  ConfirmationFailed

  /// The ticket text given to `invite` is empty or longer than
  /// `limits.max_ticket_bytes`. A caller error, raised before any message.
  TicketLength

  /// The suite broke its contract, or an encoding of fixed-size fields
  /// failed. A correct suite never produces this.
  PrimitiveFailed
}

/// The key schedule of one run, derived from its session key and
/// transcript hash. Private: a caller sees only the messages it yields.
type Schedule {
  Schedule(
    confirm_key: Secret,
    key: Secret,
    nonce: Secret,
    transcript_hash: BitArray,
  )
}

/// The run's public context, `lv(label) || lv(nameplate) ||
/// EncodePublicContext(rendezvous, "joiner", "inviter")`. The nameplate is
/// its six ASCII digits; the rendezvous identifier is its sixteen bytes and
/// is the PAKE's session identifier.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(plate) = nameplate.from_int(482_719)
/// rendezvous.public_context(plate, slot)
/// // -> Ok(<<0, 22, "Pondline_Rendezvous_v1", 0, 6, "482719", 0, 0, 0, 16,
/// //        slot_bytes:bits, 0, 0, 0, 6, "joiner", 0, 0, 0, 7, "inviter">>)
/// ```
pub fn public_context(
  nameplate: Nameplate,
  rendezvous: Id(Rendezvous),
) -> Result(BitArray, RunError) {
  let plate = <<nameplate.to_string(nameplate):utf8>>

  // Every field has a fixed size far below its prefix's bound, so the
  // framing cannot fail; the error arm is the encoders' type, not a state.
  use framed_label <- result.try(lv(label))
  use framed_plate <- result.try(lv(plate))
  use identities <- result.map(
    pake_common.encode_public_context(
      id.to_bytes(rendezvous),
      joiner_identity,
      inviter_identity,
    )
    |> result.replace_error(PrimitiveFailed),
  )

  <<framed_label:bits, framed_plate:bits, identities:bits>>
}

/// The inviter's start: its code, the rendezvous identifier it opened the
/// slot under, and the ticket text it minted and stored before any message
/// arrives (ADR-016: the ticket is `BlobStored` before `m1` is read). The
/// ticket text must be between one byte and `limits.max_ticket_bytes`.
///
/// ## Examples
///
/// ```gleam
/// rendezvous.invite(code, slot, secret.new(<<ticket_text:utf8>>))
/// // -> Ok(waiting)
/// ```
pub fn invite(
  code: PairingCode,
  rendezvous: Id(Rendezvous),
  ticket: Secret,
) -> Result(InviterWaiting, RunError) {
  let size = secret.byte_size(ticket)

  use <- bool.guard(
    when: size < 1 || size > limits.max_ticket_bytes,
    return: Error(TicketLength),
  )
  use inputs <- result.map(inputs(code, rendezvous))

  InviterWaiting(inputs:, ticket:)
}

/// The joiner's start: its code and the rendezvous identifier the mailbox
/// answered its claim with. Returns the state to keep and `m1`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(sent, m1)) = rendezvous.join(suite, code, slot)
/// bit_array.byte_size(m1)
/// // -> 34
/// ```
pub fn join(
  suite: Suite,
  code: PairingCode,
  rendezvous: Id(Rendezvous),
) -> Result(#(JoinerSent, BitArray), RunError) {
  use inputs <- result.try(inputs(code, rendezvous))
  use #(client, message) <- result.map(
    cpace_oquake.init(suite, inputs) |> result.map_error(from_combiner),
  )

  #(JoinerSent(client:), message)
}

/// The inviter answers `m1` with `m2`: CPace's response and OQUAKE's first
/// message. `m1` must be exactly `join_message_bytes`. A wrong password is
/// not detectable here; it surfaces at `inviter_release`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(answered, m2)) =
///   rendezvous.inviter_answer(suite, waiting, m1)
/// bit_array.byte_size(m2)
/// // -> 1694
/// ```
pub fn inviter_answer(
  suite: Suite,
  state: InviterWaiting,
  m1: BitArray,
) -> Result(#(InviterAnswered, BitArray), RunError) {
  use Nil <- result.try(expect_length(m1, join_message_bytes))
  use #(server, message) <- result.map(
    cpace_oquake.respond(suite, state.inputs, m1)
    |> result.map_error(from_combiner),
  )

  #(InviterAnswered(server:, ticket: state.ticket), message)
}

/// The joiner finishes both stages on `m2` and answers with `m3`, OQUAKE's
/// response followed by `confirm_J`. `m2` must be exactly
/// `answer_message_bytes`. The joiner learns nothing about the inviter's
/// words here; that is `m4`'s job.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(confirmed, m3)) =
///   rendezvous.joiner_confirm(suite, sent, m2)
/// bit_array.byte_size(m3)
/// // -> 1632
/// ```
pub fn joiner_confirm(
  suite: Suite,
  state: JoinerSent,
  m2: BitArray,
) -> Result(#(JoinerConfirmed, BitArray), RunError) {
  use Nil <- result.try(expect_length(m2, answer_message_bytes))
  use cpace_oquake.ClientFinished(key:, message:, transcript_hash:) <- result.try(
    cpace_oquake.initiator_finish(suite, state.client, m2)
    |> result.map_error(from_combiner),
  )

  // The joiner's proof of the words is a MAC over the transcript under a
  // key only the session key yields; it goes out beside OQUAKE's own tag.
  use schedule <- result.map(schedule(suite, key, transcript_hash))
  let confirm = confirmation_of(suite, schedule)

  #(JoinerConfirmed(schedule:), <<message:bits, confirm:bits>>)
}

/// The joiner's transcript hash, CPaceOQUAKE's `th`: public, 32 bytes, and
/// equal to the inviter's on an honest run.
///
/// ## Examples
///
/// ```gleam
/// rendezvous.transcript_hash(confirmed) == released.transcript_hash
/// // -> True
/// ```
pub fn transcript_hash(state: JoinerConfirmed) -> BitArray {
  state.schedule.transcript_hash
}

/// The inviter's last step: finish OQUAKE on `m3`, check `confirm_J` in
/// constant time, and only on a match seal the ticket text into `m4`. `m3`
/// must be exactly `confirm_message_bytes`. A mismatch is
/// `ConfirmationFailed`, and then no `m4` exists for this run.
///
/// `m4` is sealed once per run. The caller keeps the returned bytes and
/// resends exactly them, and must never call this twice for one run: the
/// hand-off key and nonce are fixed by the session key, so two different
/// plaintexts sealed under them would break ChaCha20-Poly1305's
/// confidentiality and integrity. (The state carries one ticket, so a
/// second call would reproduce the same bytes; the rule is what keeps that
/// true when the caller's code changes.)
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(Released(message: m4, transcript_hash:)) =
///   rendezvous.inviter_release(suite, answered, m3)
/// ```
pub fn inviter_release(
  suite: Suite,
  state: InviterAnswered,
  m3: BitArray,
) -> Result(Released, RunError) {
  use #(response, confirm) <- result.try(read_confirm_message(m3))
  use cpace_oquake.ServerFinished(key:, transcript_hash:) <- result.try(
    cpace_oquake.responder_finish(suite, state.server, response)
    |> result.map_error(from_combiner),
  )
  use schedule <- result.try(schedule(suite, key, transcript_hash))

  // The gate of the whole run. A wrong word at either end, a changed
  // message or another context all arrive here as a session key the
  // joiner does not hold, so `confirm_J` differs and nothing is sealed.
  let expected = confirmation_of(suite, schedule)
  use <- bool.guard(
    when: !suite.constant_time_equal(expected, confirm),
    return: Error(ConfirmationFailed),
  )
  use message <- result.map(seal(suite, schedule, state.ticket))

  Released(message:, transcript_hash:)
}

/// The joiner opens `m4` and returns the ticket text, a `Secret` to hand to
/// `core/ticket.decode`. A tag that does not verify, which is what an
/// inviter without the words produces, is `ConfirmationFailed`. `m4` must
/// carry at least one byte of ticket text and at most
/// `limits.max_ticket_bytes`.
///
/// ## Examples
///
/// ```gleam
/// rendezvous.joiner_receive(suite, confirmed, m4)
/// // -> Ok(ticket_text)
/// ```
pub fn joiner_receive(
  suite: Suite,
  state: JoinerConfirmed,
  m4: BitArray,
) -> Result(Secret, RunError) {
  let size = bit_array.byte_size(m4)

  use <- bool.guard(
    when: size <= handoff_tag_bytes || size > max_release_message_bytes(),
    return: Error(MalformedMessage),
  )
  let schedule = state.schedule

  // The key and nonce leave their closures only to enter the AEAD.
  suite.aead_open(
    secret.expose(schedule.key),
    secret.expose(schedule.nonce),
    associated_data(schedule),
    m4,
  )
  |> result.map(secret.new)
  |> result.replace_error(ConfirmationFailed)
}

/// The largest `m4`: the longest ticket text and the AEAD tag.
///
/// ## Examples
///
/// ```gleam
/// assert rendezvous.max_release_message_bytes() == 208
/// ```
pub fn max_release_message_bytes() -> Int {
  limits.max_ticket_bytes + handoff_tag_bytes
}

/// `confirm_J` for a session key and transcript hash. Exposed only so a
/// test can pin the key schedule against an independent implementation;
/// the run computes it inside `joiner_confirm` and `inviter_release`.
///
/// ## Examples
///
/// ```gleam
/// rendezvous.confirmation(suite, session_key, transcript_hash)
/// // -> Ok(<<_:256>>)
/// ```
@internal
pub fn confirmation(
  suite: Suite,
  session_key: Secret,
  transcript_hash: BitArray,
) -> Result(BitArray, RunError) {
  use schedule <- result.map(schedule(suite, session_key, transcript_hash))

  confirmation_of(suite, schedule)
}

/// `m4` for a session key, transcript hash and ticket text, with no
/// confirmation check. Exposed only so a test can pin the key schedule and
/// play an inviter that skips its check; the run seals inside
/// `inviter_release`, after the check.
///
/// ## Examples
///
/// ```gleam
/// rendezvous.seal_release(suite, session_key, transcript_hash, ticket)
/// // -> Ok(m4)
/// ```
@internal
pub fn seal_release(
  suite: Suite,
  session_key: Secret,
  transcript_hash: BitArray,
  ticket: Secret,
) -> Result(BitArray, RunError) {
  use schedule <- result.try(schedule(suite, session_key, transcript_hash))

  seal(suite, schedule, ticket)
}

/// Both sides' PAKE inputs from a code and a rendezvous identifier: the
/// words as password, the run's public context, and no secret context.
fn inputs(
  code: PairingCode,
  rendezvous: Id(Rendezvous),
) -> Result(cpace_oquake.Inputs, RunError) {
  use context <- result.map(public_context(
    pairing_code.nameplate(code),
    rendezvous,
  ))

  cpace_oquake.Inputs(
    prs: pairing_code.password(code),
    public_context: context,
    secret_context: secret.new(<<>>),
  )
}

/// ADR-016's key schedule from the session key: one extract salted with the
/// run's label, then the confirmation key and the hand-off key and nonce,
/// each under its own label so no derived value can stand in for another.
fn schedule(
  suite: Suite,
  session_key: Secret,
  transcript_hash: BitArray,
) -> Result(Schedule, RunError) {
  // The session key is exposed only into the extract that consumes it.
  let prk = hkdf.extract(suite, label, secret.expose(session_key))
  let sealing_bytes = handoff_key_bytes + handoff_nonce_bytes

  use confirm_key <- result.try(expand(suite, prk, confirm_label, confirm_bytes))
  use sealing <- result.try(expand(suite, prk, handoff_label, sealing_bytes))
  use #(key, nonce) <- result.map(split_sealing(sealing))

  Schedule(
    confirm_key: secret.new(confirm_key),
    key: secret.new(key),
    nonce: secret.new(nonce),
    transcript_hash:,
  )
}

/// HKDF-Expand with the crypto layer's error mapped. Every length here is a
/// constant far below HKDF's limit.
fn expand(
  suite: Suite,
  prk: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, RunError) {
  hkdf.expand(suite, prk, info, length)
  |> result.replace_error(PrimitiveFailed)
}

/// The 44 hand-off bytes as the AEAD key, then the nonce.
fn split_sealing(sealing: BitArray) -> Result(#(BitArray, BitArray), RunError) {
  let key_size = handoff_key_bytes
  let nonce_size = handoff_nonce_bytes

  // HKDF returned exactly the bytes asked for, so the split matches; the
  // other arm is the pattern's, not a reachable state.
  case sealing {
    <<key:bytes-size(key_size), nonce:bytes-size(nonce_size)>> ->
      Ok(#(key, nonce))
    _ -> Error(PrimitiveFailed)
  }
}

/// `confirm_J = HMAC-SHA-256(confirm_key, th)`.
fn confirmation_of(suite: Suite, schedule: Schedule) -> BitArray {
  // The confirmation key is exposed only to the MAC.
  suite.hmac_sha256(
    secret.expose(schedule.confirm_key),
    schedule.transcript_hash,
  )
}

/// `m4`: the ticket text under the hand-off key and nonce, with the label
/// and the transcript hash as associated data.
fn seal(
  suite: Suite,
  schedule: Schedule,
  ticket: Secret,
) -> Result(BitArray, RunError) {
  // The key, the nonce and the ticket leave their closures only to enter
  // the AEAD.
  suite.aead_seal(
    secret.expose(schedule.key),
    secret.expose(schedule.nonce),
    associated_data(schedule),
    secret.expose(ticket),
  )
  |> result.replace_error(PrimitiveFailed)
}

/// `m4`'s associated data: the hand-off label and the transcript hash, so
/// `m4` opens only in the run whose transcript both sides hashed.
fn associated_data(schedule: Schedule) -> BitArray {
  <<handoff_label:bits, schedule.transcript_hash:bits>>
}

/// `m3` cut into CPaceOQUAKE's `msg3` and `confirm_J`, or
/// `MalformedMessage` unless it is exactly `confirm_message_bytes`.
fn read_confirm_message(
  m3: BitArray,
) -> Result(#(BitArray, BitArray), RunError) {
  let response_size = cpace_oquake.finish_message_bytes
  let confirm_size = confirm_bytes

  // Exactly the response and the tag, or the shape is wrong.
  case m3 {
    <<response:bytes-size(response_size), confirm:bytes-size(confirm_size)>> ->
      Ok(#(response, confirm))
    _ -> Error(MalformedMessage)
  }
}

/// `Nil` when a message is exactly `expected` bytes, else
/// `MalformedMessage`.
fn expect_length(message: BitArray, expected: Int) -> Result(Nil, RunError) {
  case bit_array.byte_size(message) == expected {
    True -> Ok(Nil)
    False -> Error(MalformedMessage)
  }
}

/// `lv_encode` with its refusal mapped: every field framed here is a fixed
/// label or a six-digit nameplate.
fn lv(field: BitArray) -> Result(BitArray, RunError) {
  pake_common.lv_encode(field)
  |> result.replace_error(PrimitiveFailed)
}

/// The combiner's errors in the run's terms: framing is interference, a
/// low-order share is the draft's abort, and the rest is a broken suite.
fn from_combiner(error: cpace_oquake.CombinerError) -> RunError {
  case error {
    cpace_oquake.MalformedInitMessage -> MalformedMessage
    cpace_oquake.MalformedResponseMessage -> MalformedMessage
    cpace_oquake.MalformedFinishMessage -> MalformedMessage
    cpace_oquake.LowOrderShare -> LowOrderShare
    cpace_oquake.ContextTooLong -> PrimitiveFailed
    cpace_oquake.PrimitiveFailed -> PrimitiveFailed
  }
}
