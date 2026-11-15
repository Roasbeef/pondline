//// The rendezvous nameplate: its range, its one spelling, and a parser that
//// accepts nothing but that spelling (ADR-016).
////
//// Mutation notes, each run once and restored:
////
//// - `from_int` bound `value >= bound()` changed to `value > bound()`:
////   `the_range_ends_are_exact_test` fails on 1 000 000.
//// - `from_int` lower bound `value < 0` changed to `value < -1`:
////   `the_range_ends_are_exact_test` fails on -1.
//// - `read_digits` lower guard `byte < 0x30` changed to `byte < 0x2b`
////   (admits `+`, `,`, `-`, `.`, `/`): `parse_refuses_anything_but_digits_test`
////   fails on `48+719`; a leading sign alone is masked by the range check,
////   which is why the test puts the stray byte in the middle.

import core/limits
import core/nameplate
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import qcheck

/// How many values each property is checked over, and its fixed seed. The
/// seed is a constant so the gate is deterministic; change it in a commit to
/// see another sample.
const property_count = 300

const property_seed = 1601

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

/// The largest nameplate, written from the limit rather than as a literal.
fn largest() -> Int {
  limits_bound() - 1
}

fn limits_bound() -> Int {
  list.repeat(10, limits.nameplate_digits) |> int.product
}

/// Every in-range number is a nameplate that prints at the full width and
/// parses back to itself.
pub fn a_nameplate_round_trips_property_test() {
  use value <- property(qcheck.bounded_int(0, largest()))

  let assert Ok(plate) = nameplate.from_int(value)
  let text = nameplate.to_string(plate)

  assert nameplate.to_int(plate) == value
  assert string.length(text) == limits.nameplate_digits
  assert nameplate.parse(text) == Ok(plate)
}

/// Anything `parse` accepts prints back as the same text, so a nameplate has
/// one spelling. The generator draws strings made of digits and a few
/// near-misses so that acceptance is actually reached.
pub fn what_parse_accepts_prints_back_property_test() {
  let alphabet = qcheck.string_from(qcheck.uniform_codepoint())
  let digits = qcheck.bounded_int(0, largest()) |> qcheck.map(int.to_string)
  use text <- property(qcheck.from_generators(digits, [alphabet]))

  case nameplate.parse(text) {
    Ok(plate) -> {
      assert nameplate.to_string(plate) == text
    }
    Error(Nil) -> Nil
  }
}

/// `parse` never crashes, whatever string arrives.
pub fn parse_is_total_property_test() {
  use text <- property(qcheck.string())

  let _ = nameplate.parse(text)
  Nil
}

/// The ends of the range: zero is a nameplate, one past the widest is not,
/// and nor is anything negative.
pub fn the_range_ends_are_exact_test() {
  assert result.map(nameplate.from_int(0), nameplate.to_string) == Ok("000000")
  assert result.map(nameplate.from_int(largest()), nameplate.to_string)
    == Ok("999999")
  assert nameplate.from_int(largest() + 1) == Error(Nil)
  assert nameplate.from_int(-1) == Error(Nil)
}

/// A known nameplate has its documented spelling.
pub fn known_spellings_test() {
  let assert Ok(plate) = nameplate.parse("482719")
  assert nameplate.to_int(plate) == 482_719

  let assert Ok(padded) = nameplate.from_int(42)
  assert nameplate.to_string(padded) == "000042"
  assert nameplate.parse("000042") == Ok(padded)
}

/// A sign is not a digit, so neither `int.parse`'s `+` nor `-` gets in.
pub fn parse_refuses_a_sign_test() {
  assert nameplate.parse("+12345") == Error(Nil)
  assert nameplate.parse("-12345") == Error(Nil)
}

/// Too short, too long and empty are refused, and a shorter spelling of the
/// same number is not the nameplate.
pub fn parse_refuses_the_wrong_width_test() {
  assert nameplate.parse("") == Error(Nil)
  assert nameplate.parse("42") == Error(Nil)
  assert nameplate.parse("12345") == Error(Nil)
  assert nameplate.parse("1234567") == Error(Nil)
  assert nameplate.parse("0000000") == Error(Nil)
}

/// Whitespace and letters are not digits.
pub fn parse_refuses_anything_but_digits_test() {
  assert nameplate.parse(" 48271") == Error(Nil)
  assert nameplate.parse("48271 ") == Error(Nil)
  assert nameplate.parse("48271\n") == Error(Nil)
  assert nameplate.parse("48a719") == Error(Nil)
  assert nameplate.parse("48_719") == Error(Nil)
  assert nameplate.parse("0x1234") == Error(Nil)
  assert nameplate.parse("48+719") == Error(Nil)
  assert nameplate.parse("48-719") == Error(Nil)
  assert nameplate.parse("48/719") == Error(Nil)
  assert nameplate.parse("48:719") == Error(Nil)
}

/// Six bytes that are not six digits: an Arabic-Indic digit is two bytes, so
/// five digits and one of them is six bytes long, and a fullwidth digit
/// string is longer.
pub fn parse_refuses_non_ascii_digits_test() {
  assert nameplate.parse("1234٣") == Error(Nil)
  assert nameplate.parse("１２３４５６") == Error(Nil)
}
