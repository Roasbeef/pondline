//// The checksummed base32 text form a ticket is written in: the bech32
//// alphabet and layout of BIP-173, with the long codex32 checksum of
//// BIP-93 in place of bech32's.
////
//// A ticket is typed or pasted by a person, so a mistyped character must be
//// caught before anything is dialled. Bech32m's six-character checksum
//// guarantees to catch any four substitutions only up to 89 characters of
//// data, and a ticket's data part runs to about 127, past the length its
//// guarantee covers. The long codex32 code is a published BCH code over the
//// same alphabet with a fifteen-character checksum, and BIP-93 states it
//// detects any error changing at most eight characters in an expanded
//// codeword of up to 1023 characters (the human-readable part's expansion,
//// the data and the checksum). Nothing about the code is designed here: the
//// generator, the target residue and the expansion are BIP-93's, checked
//// against its fifth test vector in `test/core/codex32_test.gleam`. Only the
//// human-readable part differs, which is enough to keep a codex32 seed and
//// a Pondline ticket from ever being mistaken for each other.
////
//// The functions work on lists of 5-bit symbols and do no parsing of their
//// own; `core/ticket` owns the format, and this module owns the arithmetic.
//// The residue is a 75-bit integer, which the BEAM's integers hold exactly.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string

/// The bech32 alphabet: symbol `n` is the `n`th character.
pub const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

/// The number of checksum symbols the long code appends.
pub const checksum_symbols = 15

/// The longest expanded codeword the code's guarantee covers: the
/// human-readable part's expansion, the data and the checksum together.
pub const max_codeword_symbols = 1023

/// BIP-93's `MS32_LONG_CONST`: the residue a valid codeword leaves.
const target = 0x43381e570bf4798ab26

/// BIP-93's `ms32_long_polymod` generator, one entry per bit of the
/// symbol shifted out of the residue.
const generator = [
  0x3d59d273535ea62d897, 0x7a9becb6361c6c51507, 0x543f9b7e6c38d8a2a0e,
  0xc577eaeccf1990d13c, 0x1887f74f8dc71b10651,
]

/// The 70 low bits of the residue, the part that survives a shift by one
/// symbol.
const low_mask = 0x3fffffffffffffffff

/// The fifteen checksum symbols for `data` under `hrp`.
///
/// ## Examples
///
/// ```gleam
/// list.length(codex32.checksum("pl", [0, 1, 2]))
/// // -> 15
/// ```
pub fn checksum(hrp: String, data: List(Int)) -> List(Int) {
  let values =
    list.flatten([expand(hrp), data, list.repeat(0, checksum_symbols)])
  let residue = int.bitwise_exclusive_or(polymod(values), target)

  // Symbol `i` is the residue's 5-bit group counted from the top.
  list.repeat(Nil, checksum_symbols)
  |> list.index_map(fn(_, index) {
    let shift = 5 * { checksum_symbols - 1 - index }
    int.bitwise_and(int.bitwise_shift_right(residue, shift), 31)
  })
}

/// Whether `data` (checksum included) is a valid codeword under `hrp`.
/// A codeword longer than the code's guaranteed length is invalid
/// whatever its residue.
///
/// ## Examples
///
/// ```gleam
/// codex32.verify("pl", list.append(data, codex32.checksum("pl", data)))
/// // -> True
/// ```
pub fn verify(hrp: String, data: List(Int)) -> Bool {
  let values = list.append(expand(hrp), data)

  // The length test stops at the bound instead of counting a long input.
  case list.drop(values, max_codeword_symbols) {
    [] -> polymod(values) == target
    [_, ..] -> False
  }
}

/// The symbols of `text`, each a character of `alphabet`. Any other
/// character, uppercase included, is refused: a ticket has one spelling.
///
/// ## Examples
///
/// ```gleam
/// codex32.to_symbols("qpz")
/// // -> Ok([0, 1, 2])
/// ```
pub fn to_symbols(text: String) -> Result(List(Int), Nil) {
  list.try_map(string.to_graphemes(text), symbol_of)
}

/// The text of a list of symbols. Every symbol must be 0 to 31.
///
/// ## Examples
///
/// ```gleam
/// codex32.from_symbols([0, 1, 2])
/// // -> "qpz"
/// ```
pub fn from_symbols(symbols: List(Int)) -> String {
  symbols
  |> list.map(fn(symbol) { string.slice(alphabet, symbol, 1) })
  |> string.concat
}

/// Regroups bytes as 5-bit symbols, most significant bit first, padding
/// the last symbol with zero bits.
///
/// ## Examples
///
/// ```gleam
/// codex32.bytes_to_symbols(<<255>>)
/// // -> [31, 28]
/// ```
pub fn bytes_to_symbols(bytes: BitArray) -> List(Int) {
  // Zero bits are appended until the length is a whole number of symbols,
  // which is the padding `symbols_to_bytes` insists on.
  let padding = { 5 - bit_array.byte_size(bytes) * 8 % 5 } % 5
  symbols_loop(<<bytes:bits, 0:size(padding)>>, [])
}

/// Regroups 5-bit symbols as bytes. The bits left over after the last
/// whole byte are padding: fewer than eight, and all zero, or the input is
/// refused, so every byte string has exactly one symbol spelling.
///
/// ## Examples
///
/// ```gleam
/// codex32.symbols_to_bytes([31, 28])
/// // -> Ok(<<255>>)
/// codex32.symbols_to_bytes([31, 29])
/// // -> Error(Nil)
/// ```
pub fn symbols_to_bytes(symbols: List(Int)) -> Result(BitArray, Nil) {
  let bits =
    list.fold(symbols, <<>>, fn(acc, symbol) { <<acc:bits, symbol:size(5)>> })
  let whole = int.bitwise_shift_left(list.length(symbols) * 5 / 8, 3)
  let padding = list.length(symbols) * 5 - whole

  // The padding must be shorter than a symbol and zero; anything else
  // is a second spelling of the same bytes, or bytes that were never there.
  case bits {
    <<bytes:bits-size(whole), 0:size(padding)>> if padding < 5 -> Ok(bytes)
    _ -> Error(Nil)
  }
}

/// The 5-bit groups of `bits`, whose length is a multiple of five.
fn symbols_loop(bits: BitArray, acc: List(Int)) -> List(Int) {
  case bits {
    <<symbol:size(5), rest:bits>> -> symbols_loop(rest, [symbol, ..acc])
    _ -> list.reverse(acc)
  }
}

/// BIP-173's expansion of the human-readable part: each character's high
/// bits, a zero, then each character's low five bits.
fn expand(hrp: String) -> List(Int) {
  let codes =
    string.to_utf_codepoints(hrp)
    |> list.map(string.utf_codepoint_to_int)

  list.flatten([
    list.map(codes, int.bitwise_shift_right(_, 5)),
    [0],
    list.map(codes, int.bitwise_and(_, 31)),
  ])
}

/// BIP-93's long polymod, starting from 1 as BIP-173's does. Starting from
/// 1 and feeding the expansion of `ms` reaches BIP-93's initial residue
/// `0x23181b3`, which is how one function serves both prefixes.
fn polymod(values: List(Int)) -> Int {
  list.fold(values, 1, fn(residue, value) {
    let top = int.bitwise_shift_right(residue, 70)
    let shifted =
      int.bitwise_and(residue, low_mask)
      |> int.bitwise_shift_left(5)
      |> int.bitwise_exclusive_or(value)

    list.index_fold(generator, shifted, fn(acc, term, bit) {
      case int.bitwise_and(int.bitwise_shift_right(top, bit), 1) {
        1 -> int.bitwise_exclusive_or(acc, term)
        _ -> acc
      }
    })
  })
}

/// The symbol a character stands for: its position in `alphabet`.
fn symbol_of(character: String) -> Result(Int, Nil) {
  string.to_graphemes(alphabet)
  |> list.index_map(fn(letter, index) { #(letter, index) })
  |> list.key_find(character)
}
