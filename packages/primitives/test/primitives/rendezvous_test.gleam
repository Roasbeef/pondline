//// The spoken-code run (`core/rendezvous`) over the real primitives.
////
//// The key schedule is pinned by `test/vectors/cpace_oquake_rendezvous_schedule.json`,
//// which an independent script (Python's `hmac`, `hashlib` and
//// `cryptography`'s ChaCha20-Poly1305, kept outside the repository)
//// computed from Appendix E.4's session key and transcript hash, together
//// with the public context for a fixed nameplate and identifier. Everything
//// else runs the whole exchange with fresh randomness: an honest run, a
//// wrong word at either end, another context at one end, a changed bit in
//// each message, and messages of the wrong length.

import core/crypto/cpace_oquake
import core/id.{type Id, type Rendezvous}
import core/limits
import core/nameplate
import core/pairing_code.{type PairingCode}
import core/rendezvous.{
  type InviterAnswered, type InviterWaiting, type JoinerConfirmed,
  type JoinerSent, type RunError, ConfirmationFailed, LowOrderShare,
  MalformedMessage, Released, TicketLength,
}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import primitives/suite
import primitives/vectors

/// A loopback-length ticket text: what `m4` carries.
const ticket_text =
  "pl1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8"

fn ticket() -> Secret {
  secret.new(<<ticket_text:utf8>>)
}

fn code(text: String) -> PairingCode {
  let assert Ok(code) = pairing_code.decode(text) as "a well-formed test code"
  code
}

fn slot(byte: Int) -> Id(Rendezvous) {
  let assert Ok(slot) = id.from_bytes(<<byte:size(128)>>) as "16 bytes"
  slot
}

const words = "482719-cradle-noble-velvet"

/// One honest exchange, every state and message kept so a test can replay
/// any step with a changed input.
type Exchange {
  Exchange(
    sent: JoinerSent,
    m1: BitArray,
    waiting: InviterWaiting,
    answered: InviterAnswered,
    m2: BitArray,
    confirmed: JoinerConfirmed,
    m3: BitArray,
    m4: BitArray,
    transcript_hash: BitArray,
  )
}

/// Runs the joiner on `joiner` and the inviter on `inviter` as far as `m3`
/// and returns the inviter's verdict on it.
fn attempt(
  joiner: #(PairingCode, Id(Rendezvous)),
  inviter: #(PairingCode, Id(Rendezvous)),
) -> Result(rendezvous.Released, RunError) {
  let suite = suite.suite()
  let assert Ok(#(sent, m1)) = rendezvous.join(suite, joiner.0, joiner.1)
  let assert Ok(waiting) = rendezvous.invite(inviter.0, inviter.1, ticket())
  let assert Ok(#(answered, m2)) = rendezvous.inviter_answer(suite, waiting, m1)
  let assert Ok(#(_confirmed, m3)) = rendezvous.joiner_confirm(suite, sent, m2)

  rendezvous.inviter_release(suite, answered, m3)
}

fn honest() -> Exchange {
  let suite = suite.suite()
  let assert Ok(#(sent, m1)) = rendezvous.join(suite, code(words), slot(7))
  let assert Ok(waiting) = rendezvous.invite(code(words), slot(7), ticket())
  let assert Ok(#(answered, m2)) = rendezvous.inviter_answer(suite, waiting, m1)
  let assert Ok(#(confirmed, m3)) = rendezvous.joiner_confirm(suite, sent, m2)
  let assert Ok(Released(message: m4, transcript_hash:)) =
    rendezvous.inviter_release(suite, answered, m3)

  Exchange(
    sent:,
    m1:,
    waiting:,
    answered:,
    m2:,
    confirmed:,
    m3:,
    m4:,
    transcript_hash:,
  )
}

// ------------------------------------------------------------- the schedule

fn schedule_vector() -> vectors.Vector {
  let assert [vector] = vectors.load("cpace_oquake_rendezvous_schedule")
    as "the fixture has one case"
  vector
}

/// `confirm_J` and `m4` from E.4's session key and transcript hash match an
/// independent implementation of ADR-016's schedule: the extract's salt,
/// both labels, the 32/12 split, and the associated data with `th`.
pub fn schedule_matches_the_independent_vector_test() {
  let v = schedule_vector()
  let suite = suite.suite()
  let key = secret.new(vectors.hex(v, "session_key"))
  let th = vectors.hex(v, "th")

  assert rendezvous.confirmation(suite, key, th)
    == Ok(vectors.hex(v, "confirm_J"))
  assert rendezvous.seal_release(
      suite,
      key,
      th,
      secret.new(vectors.hex(v, "ticket")),
    )
    == Ok(vectors.hex(v, "m4"))
}

/// The public context for nameplate 482719 and identifier 00..0f matches the
/// independent script byte for byte: the label and nameplate framed with two
/// bytes, then `EncodePublicContext` with the joiner as `U`.
pub fn public_context_matches_the_independent_vector_test() {
  let v = schedule_vector()
  let assert Ok(plate) = nameplate.parse(vectors.text(v, "nameplate"))
  let assert Ok(slot) = id.from_bytes(vectors.hex(v, "rendezvous"))

  assert rendezvous.public_context(plate, slot)
    == Ok(vectors.hex(v, "public_context"))
}

// ---------------------------------------------------------------- honest

/// An honest run delivers exactly the ticket text, the two transcript
/// hashes agree, every message has its stated length, and `m2` and `m3`
/// fit a rendezvous body.
pub fn an_honest_run_delivers_the_ticket_test() {
  let exchange = honest()
  let suite = suite.suite()

  assert rendezvous.joiner_receive(suite, exchange.confirmed, exchange.m4)
    == Ok(ticket())
  assert rendezvous.transcript_hash(exchange.confirmed)
    == exchange.transcript_hash
  assert bit_array.byte_size(exchange.m1) == rendezvous.join_message_bytes
  assert bit_array.byte_size(exchange.m2) == rendezvous.answer_message_bytes
  assert bit_array.byte_size(exchange.m3) == rendezvous.confirm_message_bytes
  assert bit_array.byte_size(exchange.m4)
    == string.byte_size(ticket_text) + rendezvous.handoff_tag_bytes
  assert list.all([exchange.m1, exchange.m2, exchange.m3, exchange.m4], fn(m) {
    bit_array.byte_size(m) <= limits.max_rendezvous_body_bytes
  })
}

/// Releasing from one state twice reproduces the same `m4`: the run's
/// hand-off key and nonce never seal a second, different plaintext.
pub fn a_release_is_the_same_bytes_every_time_test() {
  let exchange = honest()
  let suite = suite.suite()
  let assert Ok(Released(message:, ..)) =
    rendezvous.inviter_release(suite, exchange.answered, exchange.m3)

  assert message == exchange.m4
}

// --------------------------------------------------------- wrong inputs

/// A joiner with one wrong word is caught at the inviter, and no `m4` is
/// produced for the run.
pub fn a_joiner_with_a_wrong_word_fails_confirmation_test() {
  assert attempt(#(code("482719-cradle-noble-vendor"), slot(7)), #(
      code(words),
      slot(7),
    ))
    == Error(ConfirmationFailed)
}

/// An inviter with one wrong word fails its own confirmation check; and an
/// inviter that held a wrong word and skipped that check, sealing the
/// ticket under the session key it derived, is refused by the joiner.
pub fn an_inviter_with_a_wrong_word_fails_confirmation_test() {
  let suite = suite.suite()

  assert attempt(#(code(words), slot(7)), #(
      code("482719-cradle-noble-vendor"),
      slot(7),
    ))
    == Error(ConfirmationFailed)

  // The forging inviter runs CPaceOQUAKE directly with the wrong word and
  // the right context, then seals without checking `confirm_J`.
  let assert Ok(#(sent, m1)) = rendezvous.join(suite, code(words), slot(7))
  let assert Ok(context) =
    rendezvous.public_context(pairing_code.nameplate(code(words)), slot(7))
  let wrong =
    cpace_oquake.Inputs(
      prs: secret.new(<<"cradle-noble-vendor":utf8>>),
      public_context: context,
      secret_context: secret.new(<<>>),
    )
  let assert Ok(#(server, m2)) = cpace_oquake.respond(suite, wrong, m1)
  let assert Ok(#(confirmed, m3)) = rendezvous.joiner_confirm(suite, sent, m2)
  let assert Ok(response) = bit_array.slice(m3, 0, 1600)
  let assert Ok(cpace_oquake.ServerFinished(key:, transcript_hash:)) =
    cpace_oquake.responder_finish(suite, server, response)
  let assert Ok(forged) =
    rendezvous.seal_release(suite, key, transcript_hash, ticket())

  assert rendezvous.joiner_receive(suite, confirmed, forged)
    == Error(ConfirmationFailed)
}

/// `m4` from another honest run does not open in this one.
pub fn another_runs_release_does_not_open_test() {
  let one = honest()
  let other = honest()

  assert rendezvous.joiner_receive(suite.suite(), one.confirmed, other.m4)
    == Error(ConfirmationFailed)
}

/// A different nameplate, or a different rendezvous identifier, at one end
/// is a different password to the PAKE, and fails the same way.
pub fn a_different_context_fails_confirmation_test() {
  assert attempt(#(code("482718-cradle-noble-velvet"), slot(7)), #(
      code(words),
      slot(7),
    ))
    == Error(ConfirmationFailed)
  assert attempt(#(code(words), slot(8)), #(code(words), slot(7)))
    == Error(ConfirmationFailed)
}

// --------------------------------------------------------- changed bits

/// `bits` positions spread over a message of `size` bytes: the first and
/// last bit and `count` evenly spaced between.
fn positions(size: Int, count: Int) -> List(Int) {
  let total = size * 8
  let step = int.max(1, total / count)

  span(0, total - 1)
  |> list.filter(fn(bit) { bit % step == 0 || bit == total - 1 })
}

/// The integers from `from` to `to`, both included.
fn span(from: Int, to: Int) -> List(Int) {
  case from > to {
    True -> []
    False -> [from, ..span(from + 1, to)]
  }
}

/// The message with bit `position` inverted, counted from the first byte's
/// most significant bit.
fn flip(message: BitArray, position: Int) -> BitArray {
  let assert <<before:bits-size(position), bit:size(1), after:bits>> = message
    as "the position is inside the message"
  <<before:bits, { 1 - bit }:size(1), after:bits>>
}

/// Whatever follows a changed `m1`, the inviter never releases; every bit
/// of `m1` is tried.
pub fn a_changed_m1_never_releases_test() {
  let exchange = honest()
  let suite = suite.suite()

  assert list.all(positions(rendezvous.join_message_bytes, 272), fn(position) {
    let released = {
      use #(answered, m2) <- result.try(rendezvous.inviter_answer(
        suite,
        exchange.waiting,
        flip(exchange.m1, position),
      ))
      use #(_, m3) <- result.try(rendezvous.joiner_confirm(
        suite,
        exchange.sent,
        m2,
      ))
      rendezvous.inviter_release(suite, answered, m3)
    }
    result.is_error(released)
  })
}

/// Whatever the joiner sends after a changed `m2`, the inviter never
/// releases; about 400 bits spread over the message are tried, the length
/// prefix and `Yb` among them.
pub fn a_changed_m2_never_releases_test() {
  let exchange = honest()
  let suite = suite.suite()

  assert list.all(positions(rendezvous.answer_message_bytes, 400), fn(position) {
    let released = {
      use #(_, m3) <- result.try(rendezvous.joiner_confirm(
        suite,
        exchange.sent,
        flip(exchange.m2, position),
      ))
      rendezvous.inviter_release(suite, exchange.answered, m3)
    }
    result.is_error(released)
  })
}

/// A changed `m3`, in OQUAKE's ciphertext, its tag or `confirm_J`, never
/// releases; every bit of `confirm_J` is tried.
pub fn a_changed_m3_never_releases_test() {
  let exchange = honest()
  let suite = suite.suite()
  let confirm_bits = span(1600 * 8, 1632 * 8 - 1)
  let spread = positions(1600, 400)

  assert list.all(list.append(spread, confirm_bits), fn(position) {
    rendezvous.inviter_release(
      suite,
      exchange.answered,
      flip(exchange.m3, position),
    )
    == Error(ConfirmationFailed)
  })
}

/// Every single-bit change to `m4` is refused by the joiner.
pub fn a_changed_m4_never_opens_test() {
  let exchange = honest()
  let suite = suite.suite()
  let size = bit_array.byte_size(exchange.m4)

  assert list.all(span(0, size * 8 - 1), fn(position) {
    rendezvous.joiner_receive(
      suite,
      exchange.confirmed,
      flip(exchange.m4, position),
    )
    == Error(ConfirmationFailed)
  })
}

// --------------------------------------------------------- wrong shapes

/// A truncated or extended message is `MalformedMessage` at every step,
/// never `ConfirmationFailed`, so the daemon does not count it as a guess.
pub fn a_message_of_the_wrong_length_is_malformed_test() {
  let exchange = honest()
  let suite = suite.suite()
  let shorter = fn(message: BitArray) {
    let assert Ok(cut) =
      bit_array.slice(message, 0, bit_array.byte_size(message) - 1)
    cut
  }

  assert list.all([shorter(exchange.m1), <<exchange.m1:bits, 0>>], fn(m1) {
    rendezvous.inviter_answer(suite, exchange.waiting, m1)
    |> result.map(fn(_) { Nil })
    == Error(MalformedMessage)
  })
  assert list.all([shorter(exchange.m2), <<exchange.m2:bits, 0>>], fn(m2) {
    rendezvous.joiner_confirm(suite, exchange.sent, m2)
    |> result.map(fn(_) { Nil })
    == Error(MalformedMessage)
  })
  assert list.all([shorter(exchange.m3), <<exchange.m3:bits, 0>>], fn(m3) {
    rendezvous.inviter_release(suite, exchange.answered, m3)
    == Error(MalformedMessage)
  })
  assert list.all(
    [
      <<>>,
      <<0:size(128)>>,
      <<0:size(rendezvous.max_release_message_bytes() * 8 + 8)>>,
    ],
    fn(m4) {
      rendezvous.joiner_receive(suite, exchange.confirmed, m4)
      == Error(MalformedMessage)
    },
  )
}

/// A length prefix other than 32 inside a message of the right length is
/// malformed framing, too.
pub fn a_wrong_length_prefix_is_malformed_test() {
  let exchange = honest()
  let suite = suite.suite()
  let assert <<_:size(16), share:bytes>> = exchange.m1 as "lv(Ya)"
  let assert <<_:size(16), rest:bytes>> = exchange.m2 as "lv(Yb) || init"

  assert rendezvous.inviter_answer(suite, exchange.waiting, <<
      31:size(16),
      share:bits,
    >>)
    |> result.map(fn(_) { Nil })
    == Error(MalformedMessage)
  assert rendezvous.joiner_confirm(suite, exchange.sent, <<
      33:size(16),
      rest:bits,
    >>)
    |> result.map(fn(_) { Nil })
    == Error(MalformedMessage)
}

/// A CPace share of zero is the draft's abort, reported as such.
pub fn a_zero_share_aborts_test() {
  let exchange = honest()

  assert rendezvous.inviter_answer(suite.suite(), exchange.waiting, <<
      32:size(16),
      0:size(256),
    >>)
    |> result.map(fn(_) { Nil })
    == Error(LowOrderShare)
}

/// A ticket text that is empty or past `limits.max_ticket_bytes` is
/// refused before the run starts.
pub fn a_ticket_out_of_bounds_is_refused_test() {
  let too_long = <<0:size({ limits.max_ticket_bytes + 1 } * 8)>>
  let longest = <<0:size(limits.max_ticket_bytes * 8)>>

  assert rendezvous.invite(code(words), slot(7), secret.new(<<>>))
    |> result.map(fn(_) { Nil })
    == Error(TicketLength)
  assert rendezvous.invite(code(words), slot(7), secret.new(too_long))
    |> result.map(fn(_) { Nil })
    == Error(TicketLength)
  assert rendezvous.invite(code(words), slot(7), secret.new(longest))
    |> result.is_ok
}

// --------------------------------------------------------------- printing

/// No state, result or error prints the words, the ticket text or a key.
pub fn nothing_prints_a_secret_test() {
  let exchange = honest()
  let errors = [
    attempt(#(code("482719-cradle-noble-vendor"), slot(7)), #(
      code(words),
      slot(7),
    ))
    |> result.map(fn(_) { Nil }),
  ]
  let printed =
    string.concat([
      string.inspect(exchange),
      string.inspect(errors),
      string.inspect(code(words)),
    ])

  assert !string.contains(printed, "cradle")
  assert !string.contains(printed, "velvet")
  assert !string.contains(printed, "pl1")
  assert !string.contains(printed, inner(<<"cradle":utf8>>))
  assert !string.contains(printed, inner(<<"pl1qpzry":utf8>>))
}

/// How a byte string appears inside a printed bit array, without the
/// brackets, so it is found wherever it sits in a longer one.
fn inner(bytes: BitArray) -> String {
  string.inspect(bytes)
  |> string.drop_start(2)
  |> string.drop_end(2)
}
