//// Properties of the spoken-code run (`core/rendezvous`) as pure Gleam,
//// over the fake suite with `cpace_oquake_test`'s stand-in ML-KEM.
////
//// Each side draws from its own seeded suite, as two daemons would, so a
//// run is a function of its two seeds, its codes, its identifiers and its
//// ticket. That is what lets the determinism of `m4` be stated at all. The
//// real primitives, the bit-level tampering and the schedule's independent
//// vector are in `packages/primitives/test/primitives/rendezvous_test.gleam`.

import core/crypto/cpace_oquake
import core/crypto/cpace_oquake_test
import core/id.{type Id, type Rendezvous}
import core/limits
import core/nameplate
import core/pairing_code.{type PairingCode}
import core/rendezvous.{type RunError, ConfirmationFailed, Released}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/list
import gleam/result
import qcheck

/// How many runs each property is checked over, and the seed they are drawn
/// from. A run costs three Kemeleon operations; the seed is fixed so the
/// gate is deterministic.
const run_count = 100

const run_seed = 16_016

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(run_count)
  |> qcheck.with_seed(qcheck.seed(run_seed))
  |> qcheck.run(generator, check)
}

/// One side of a run: its code and the rendezvous identifier it holds.
type Side {
  Side(code: PairingCode, rendezvous: Id(Rendezvous))
}

/// Everything a run is a function of.
type Case {
  Case(seed: Int, joiner: Side, inviter: Side, ticket: Secret)
}

/// A code drawn from a seeded suite for a drawn nameplate.
fn side(seed: Int, plate: Int, slot: Int) -> Side {
  let assert Ok(plate) = nameplate.from_int(plate) as "plate is in range"
  let assert Ok(rendezvous) = id.from_bytes(<<slot:size(128)>>)
    as "sixteen bytes"
  let code = pairing_code.generate(cpace_oquake_test.kem_suite(seed), plate)

  Side(code:, rendezvous:)
}

/// A seed for the words and the suites, a nameplate, an identifier and a
/// ticket text between one byte and the limit.
fn honest_cases() -> qcheck.Generator(Case) {
  qcheck.map4(
    qcheck.bounded_int(0, 1_000_000),
    qcheck.bounded_int(0, 999_999),
    qcheck.bounded_int(0, 1_000_000),
    qcheck.fixed_size_byte_aligned_bit_array(limits.max_ticket_bytes)
      |> qcheck.map2(qcheck.bounded_int(1, limits.max_ticket_bytes), cut),
    fn(seed, plate, slot, ticket) {
      let both = side(seed, plate, slot)
      Case(seed:, joiner: both, inviter: both, ticket: secret.new(ticket))
    },
  )
}

/// The first `length` bytes of `bytes`.
fn cut(bytes: BitArray, length: Int) -> BitArray {
  let assert <<head:bytes-size(length), _:bytes>> = bytes
    as "length is within the drawn bytes"
  head
}

/// One run as far as the inviter's release: the joiner's state and the
/// inviter's verdict on `m3`, or the first error.
fn release(
  case_: Case,
) -> Result(#(rendezvous.JoinerConfirmed, rendezvous.Released), RunError) {
  let joiner_suite = cpace_oquake_test.kem_suite(case_.seed)
  let inviter_suite = cpace_oquake_test.kem_suite(case_.seed + 1)

  use waiting <- result.try(rendezvous.invite(
    case_.inviter.code,
    case_.inviter.rendezvous,
    case_.ticket,
  ))
  use #(sent, m1) <- result.try(rendezvous.join(
    joiner_suite,
    case_.joiner.code,
    case_.joiner.rendezvous,
  ))
  use #(answered, m2) <- result.try(rendezvous.inviter_answer(
    inviter_suite,
    waiting,
    m1,
  ))
  use #(confirmed, m3) <- result.try(rendezvous.joiner_confirm(
    joiner_suite,
    sent,
    m2,
  ))
  use released <- result.map(rendezvous.inviter_release(
    inviter_suite,
    answered,
    m3,
  ))

  #(confirmed, released)
}

/// The whole run: `m4`, and the ticket the joiner opened from it.
fn run(case_: Case) -> Result(#(BitArray, Secret), RunError) {
  use #(confirmed, Released(message: m4, transcript_hash:)) <- result.try(
    release(case_),
  )
  use ticket <- result.map(rendezvous.joiner_receive(
    cpace_oquake_test.kem_suite(case_.seed + 2),
    confirmed,
    m4,
  ))

  assert rendezvous.transcript_hash(confirmed) == transcript_hash
  #(m4, ticket)
}

/// An honest run delivers exactly the ticket the inviter was given.
pub fn honest_runs_deliver_the_ticket_test() {
  use case_ <- property(honest_cases())

  let assert Ok(#(_m4, ticket)) = run(case_)
  assert ticket == case_.ticket
}

/// `m4` is a function of the run: the same codes, identifiers, ticket and
/// randomness give the same bytes.
pub fn the_release_is_deterministic_in_the_run_test() {
  use case_ <- property(honest_cases())

  let assert Ok(#(first, _)) = run(case_)
  let assert Ok(#(second, _)) = run(case_)
  assert first == second
}

/// What to change at the inviter's end: its words, its nameplate, or its
/// rendezvous identifier. Drawn as an index, so a failure shrinks toward
/// the words.
type Change {
  Words
  Plate
  Slot
}

fn change_of(index: Int) -> Change {
  case index {
    0 -> Words
    1 -> Plate
    _ -> Slot
  }
}

/// An honest case whose inviter differs from its joiner in one way.
fn unequal_cases() -> qcheck.Generator(#(Change, Case)) {
  qcheck.map2(
    honest_cases(),
    qcheck.map(qcheck.bounded_int(0, 2), change_of),
    fn(case_, change) {
      let Side(code:, rendezvous:) = case_.joiner
      let plate = nameplate.to_int(pairing_code.nameplate(code))
      let other_plate = { plate + 1 } % 1_000_000
      let next = as_integer(id.to_bytes(rendezvous)) + 1
      let assert Ok(other_slot) = id.from_bytes(<<next:size(128)>>)
        as "sixteen bytes"
      let inviter = case change {
        Words -> Side(..case_.joiner, code: other_words(case_.seed, plate))
        Plate -> Side(..case_.joiner, code: same_words(code, other_plate))
        Slot -> Side(..case_.joiner, rendezvous: other_slot)
      }
      #(change, Case(..case_, inviter:))
    },
  )
}

/// A code with fresh words for the same nameplate, which differ from the
/// joiner's (a seed apart, so a different draw).
fn other_words(seed: Int, plate: Int) -> PairingCode {
  let assert Ok(plate) = nameplate.from_int(plate) as "plate is in range"
  pairing_code.generate(cpace_oquake_test.kem_suite(seed + 7), plate)
}

/// The same words at another nameplate.
fn same_words(code: PairingCode, plate: Int) -> PairingCode {
  let assert Ok(plate) = nameplate.from_int(plate) as "plate is in range"
  let words = secret.expose(pairing_code.password(code))
  let assert Ok(text) = bit_array.to_string(words) as "words are ASCII"
  let assert Ok(moved) =
    pairing_code.decode(nameplate.to_string(plate) <> "-" <> text)
    as "a well-formed code"
  moved
}

/// An identifier's sixteen bytes as one integer.
fn as_integer(bytes: BitArray) -> Int {
  let assert <<value:size(128)>> = bytes as "sixteen bytes"
  value
}

/// A run whose two ends disagree on the words, the nameplate or the
/// identifier never delivers a ticket: it ends at the inviter's check, in
/// `ConfirmationFailed`, so no `m4` exists to be opened at all.
/// Two draws of three words collide once in 2^33; a seed that did would
/// fail here and be a finding about the generator, not the run.
pub fn unequal_runs_never_deliver_test() {
  use #(_change, case_) <- property(unequal_cases())

  let words_differ =
    pairing_code.password(case_.joiner.code)
    != pairing_code.password(case_.inviter.code)
  let plates_differ =
    pairing_code.nameplate(case_.joiner.code)
    != pairing_code.nameplate(case_.inviter.code)
  let slots_differ = case_.joiner.rendezvous != case_.inviter.rendezvous
  assert words_differ || plates_differ || slots_differ

  assert result.map(release(case_), fn(_) { Nil }) == Error(ConfirmationFailed)
}

/// The unequal generator reaches every kind of change on the seed the
/// property uses, so none of the three is tested only by name.
pub fn the_unequal_generator_reaches_every_change_test() {
  let #(drawn, _) =
    qcheck.generate(unequal_cases(), run_count, qcheck.seed(run_seed))
  let changes = list.map(drawn, fn(pair) { pair.0 })

  assert list.contains(changes, Words)
  assert list.contains(changes, Plate)
  assert list.contains(changes, Slot)
}

/// `m2` and `m3` fit a rendezvous body, and so does the largest `m4`; `m3`
/// is CPaceOQUAKE's third message and `confirm_J`.
pub fn messages_fit_a_rendezvous_body_test() {
  assert rendezvous.join_message_bytes <= limits.max_rendezvous_body_bytes
  assert rendezvous.answer_message_bytes <= limits.max_rendezvous_body_bytes
  assert rendezvous.confirm_message_bytes <= limits.max_rendezvous_body_bytes
  assert rendezvous.max_release_message_bytes()
    <= limits.max_rendezvous_body_bytes
  assert rendezvous.confirm_message_bytes
    == cpace_oquake.finish_message_bytes + rendezvous.confirm_bytes
  assert rendezvous.answer_message_bytes == 1694
  assert rendezvous.confirm_message_bytes == 1632
}
