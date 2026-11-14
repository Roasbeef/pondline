//// The public half of a pairing code: a rendezvous nameplate (ADR-016).
////
//// A nameplate is `limits.nameplate_digits` decimal digits. The rendezvous
//// mailbox draws it at random and the claimant presents it to find the slot,
//// so it names a rendezvous and carries no secret. What it must not do is
//// have two spellings: `000042` and `42` would be one slot reached two ways,
//// and a decoder that accepted both would let a re-encoded code differ from
//// the text it came from. So the type holds an integer in
//// `0..10^nameplate_digits - 1`, `parse` accepts exactly the zero-padded
//// spelling of it, and `to_string` produces that spelling.
////
//// `parse` reads the ASCII digits one byte at a time rather than calling
//// `int.parse`, which accepts a leading sign.

import core/limits
import gleam/bool
import gleam/int
import gleam/list
import gleam/result
import gleam/string

/// A rendezvous nameplate: an integer from zero to one less than ten to the
/// `limits.nameplate_digits`. Opaque, so every value is in range.
pub opaque type Nameplate {
  Nameplate(value: Int)
}

/// A nameplate from its number, or `Error(Nil)` when the number is negative
/// or has more than `limits.nameplate_digits` digits.
///
/// ## Examples
///
/// ```gleam
/// assert nameplate.from_int(482_719) |> result.map(nameplate.to_int)
///   == Ok(482_719)
/// ```
///
/// ```gleam
/// assert nameplate.from_int(1_000_000) == Error(Nil)
/// ```
pub fn from_int(value: Int) -> Result(Nameplate, Nil) {
  // Ten to the number of digits is the first number that is too wide.
  let bound = list.repeat(10, limits.nameplate_digits) |> int.product
  use <- bool.guard(value < 0 || value >= bound, Error(Nil))
  Ok(Nameplate(value:))
}

/// A nameplate from its text, which is exactly `limits.nameplate_digits`
/// ASCII digits and nothing else: no sign, no space, no shorter spelling.
///
/// ## Examples
///
/// ```gleam
/// assert nameplate.parse("000042") |> result.map(nameplate.to_int) == Ok(42)
/// ```
///
/// ```gleam
/// assert nameplate.parse("42") == Error(Nil)
/// ```
pub fn parse(text: String) -> Result(Nameplate, Nil) {
  // The byte count is checked first, so the digit walk below is bounded by
  // `limits.nameplate_digits` whatever text arrives.
  use <- bool.guard(
    string.byte_size(text) != limits.nameplate_digits,
    Error(Nil),
  )
  use value <- result.try(read_digits(<<text:utf8>>, 0))
  from_int(value)
}

/// The nameplate's text, zero-padded to `limits.nameplate_digits`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(plate) = nameplate.from_int(42)
/// assert nameplate.to_string(plate) == "000042"
/// ```
pub fn to_string(nameplate: Nameplate) -> String {
  nameplate.value
  |> int.to_string
  |> string.pad_start(to: limits.nameplate_digits, with: "0")
}

/// The nameplate's number.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(plate) = nameplate.from_int(42)
/// assert nameplate.to_int(plate) == 42
/// ```
pub fn to_int(nameplate: Nameplate) -> Int {
  nameplate.value
}

/// Reads ASCII digits, most significant first, into a number.
fn read_digits(bytes: BitArray, accumulator: Int) -> Result(Int, Nil) {
  case bytes {
    <<>> -> Ok(accumulator)

    // One byte is one digit, or the end of the text's validity.
    <<byte, rest:bits>> -> {
      use <- bool.guard(byte < 0x30 || byte > 0x39, Error(Nil))
      read_digits(rest, accumulator * 10 + byte - 0x30)
    }

    // Input from a `String` is whole bytes, so this arm is only the
    // pattern's own remainder case and is not reachable from `parse`.
    _ -> Error(Nil)
  }
}
