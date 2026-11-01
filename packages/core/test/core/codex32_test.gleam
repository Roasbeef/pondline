//// The long codex32 checksum against BIP-93's published vector, and the
//// symbol regrouping the ticket format relies on.

import core/codex32
import gleam/list
import gleam/string
import qcheck

/// BIP-93 test vector 5, a long codex32 string: everything after `ms1`
/// except the fifteen checksum characters, and the checksum.
const vector_data =
  "00c8vsm32zxfguhpchtlupzry9x8gf2tvdw0s3jn54khce6mua7lqpzygsfjd6an074rxvcemlh8wu3tk925acdefghjklmnpqrstuvwxy06f"

const vector_checksum = "hpv80undvarhrak"

/// How many values each property is checked over, and its fixed seed.
const property_count = 200

const property_seed = 93

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

fn symbols(text: String) -> List(Int) {
  let assert Ok(values) = codex32.to_symbols(text)
  values
}

/// The checksum is BIP-93's: it reproduces the vector's checksum under the
/// `ms` prefix, and the whole string verifies.
pub fn the_long_checksum_matches_bip93_vector_5_test() {
  let data = symbols(vector_data)

  assert codex32.from_symbols(codex32.checksum("ms", data)) == vector_checksum
  assert codex32.verify("ms", list.append(data, symbols(vector_checksum)))
}

/// The prefix is part of the codeword: the same data and checksum do not
/// verify under another prefix.
pub fn the_prefix_is_covered_by_the_checksum_test() {
  let data = symbols(vector_data)
  let whole = list.append(data, codex32.checksum("ms", data))

  assert !codex32.verify("rw", whole)
}

/// Uppercase, characters outside the alphabet and separators are not
/// symbols.
pub fn only_the_lowercase_alphabet_is_read_test() {
  assert codex32.to_symbols("QPZ") == Error(Nil)
  assert codex32.to_symbols("qpb") == Error(Nil)
  assert codex32.to_symbols("qp z") == Error(Nil)
  assert codex32.to_symbols("") == Ok([])
  assert codex32.from_symbols(symbols(codex32.alphabet)) == codex32.alphabet
}

/// Bytes regroup as symbols and back, and any symbol list with non-zero
/// padding, or padding of a whole symbol, is refused.
pub fn regrouping_round_trips_and_padding_is_strict_test() {
  property(qcheck.byte_aligned_bit_array(), fn(bytes) {
    let regrouped = codex32.bytes_to_symbols(bytes)

    assert codex32.symbols_to_bytes(regrouped) == Ok(bytes)
  })

  assert codex32.symbols_to_bytes([31, 28]) == Ok(<<255>>)
  assert codex32.symbols_to_bytes([31, 29]) == Error(Nil)
  assert codex32.symbols_to_bytes([31, 28, 0]) == Error(Nil)
  assert codex32.symbols_to_bytes([]) == Ok(<<>>)
}

/// A string longer than the code's guaranteed length never verifies.
pub fn an_overlong_codeword_never_verifies_test() {
  let data = list.repeat(0, codex32.max_codeword_symbols)
  let whole = list.append(data, codex32.checksum("rw", data))

  assert !codex32.verify("rw", whole)
  assert string.length(codex32.alphabet) == 32
}
