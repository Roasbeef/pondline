//// The spoken pairing code and its word list (ADR-016): the strict text
//// decoder, the draw of three eleven-bit indices, and the BIP-39 table the
//// indices select from.
////
//// Mutation notes, each run once against the intended test and restored:
////
//// - `is_code_point` also admitting `A`..`Z`: `decode_refuses_uppercase_test`.
//// - `decode` calling `has_word_count` with the limit plus one (a fourth
////   word accepted): `decode_refuses_the_wrong_number_of_words_test`.
//// - `nameplate.from_int` bound `>` for `>=`: `the_range_ends_are_exact_test`
////   in `nameplate_test`.
//// - `read_indices` reading `size(10)`:
////   `generate_slices_the_bits_it_is_given_test` and
////   `generate_matches_independent_arithmetic_property_test`.
//// - `bytes_drawn` asking for four bytes: `generate_asks_for_enough_bytes_test`.
//// - `word_at` slicing at `index * 8`: `every_word_round_trips_test` and
////   `the_list_has_its_published_positions_test`.
//// - `read_indices` skipping the first bit of the draw: the same tests.
//// - `search` was not mutated; `every_word_round_trips_test` is what would
////   catch a wrong bound, as a failure or a hang.

import core/crypto/fake_suite
import core/crypto/suite.{type Suite, Suite}
import core/limits
import core/nameplate
import core/pairing_code.{BadNameplate, BadShape, TooLong, UnknownWord}
import core/pairing_code/words
import core/secret
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/order
import gleam/set
import gleam/string
import qcheck

/// How many values each property is checked over, and its fixed seed. The
/// seed is a constant so the gate is deterministic; change it in a commit to
/// see another sample.
const property_count = 300

const property_seed = 1602

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

/// The text of the code used throughout the refusal tests.
const valid = "482719-cradle-noble-velvet"

// ------------------------------------------------------------- helpers

/// A suite whose `random` returns `bytes` whatever is asked.
fn suite_returning(bytes: BitArray) -> Suite {
  Suite(..fake_suite.suite(), random: fn(_) { bytes })
}

/// A suite whose `random` returns every byte it is asked for as `0xFF`.
fn suite_of_ones() -> Suite {
  Suite(..fake_suite.suite(), random: fn(count) {
    let bits = count * 8
    <<-1:size(bits)>>
  })
}

fn plate(value: Int) -> nameplate.Nameplate {
  let assert Ok(made) = nameplate.from_int(value)
  made
}

fn as_text(code: pairing_code.PairingCode) -> String {
  let assert Ok(text) =
    bit_array.to_string(secret.expose(pairing_code.encode(code)))
  text
}

/// A code with exactly these three word indices, drawn through `generate`
/// from the bytes that spell them.
fn code_of(first: Int, second: Int, third: Int) -> pairing_code.PairingCode {
  let bytes = <<first:size(11), second:size(11), third:size(11), 0:size(7)>>
  pairing_code.generate(suite_returning(bytes), plate(482_719))
}

/// The indices of the words in a code's password, read back through the list.
fn indices_of(code: pairing_code.PairingCode) -> List(Int) {
  let assert Ok(spoken) =
    bit_array.to_string(secret.expose(pairing_code.password(code)))
  spoken
  |> string.split("-")
  |> list.map(fn(word) {
    let assert Ok(index) = words.index_of(word)
    index
  })
}

/// Every index of the list, in order.
fn all_indices() -> List(Int) {
  list.repeat(Nil, words.word_count) |> list.index_map(fn(_, index) { index })
}

fn indices() -> qcheck.Generator(Int) {
  qcheck.bounded_int(0, words.word_count - 1)
}

/// A code, drawn as three indices and a nameplate so a failure shrinks
/// toward `000000-abandon-abandon-abandon`.
fn codes() -> qcheck.Generator(pairing_code.PairingCode) {
  qcheck.map4(
    indices(),
    indices(),
    indices(),
    qcheck.bounded_int(0, 999_999),
    fn(first, second, third, number) {
      let bytes = <<first:size(11), second:size(11), third:size(11), 0:size(7)>>
      pairing_code.generate(suite_returning(bytes), plate(number))
    },
  )
}

// ------------------------------------------------------------- the list

/// The ends and a few interior positions of the list are the published ones.
pub fn the_list_has_its_published_positions_test() {
  assert words.word_at(0) == Ok("abandon")
  assert words.word_at(1) == Ok("ability")
  assert words.word_at(399) == Ok("cradle")
  assert words.word_at(1019) == Ok("legal")
  assert words.word_at(1197) == Ok("noble")
  assert words.word_at(1936) == Ok("velvet")
  assert words.word_at(2046) == Ok("zone")
  assert words.word_at(2047) == Ok("zoo")
}

/// The list holds 2048 words and eleven bits select one of them exactly.
pub fn the_list_is_eleven_bits_wide_test() {
  assert words.word_count == 2048
  assert int.bitwise_shift_left(1, words.index_bits) == words.word_count
  assert words.word_at(words.word_count) == Error(Nil)
  assert words.word_at(-1) == Error(Nil)
}

/// Every index reads back as itself through the word it names.
pub fn every_word_round_trips_test() {
  all_indices()
  |> list.each(fn(index) {
    let assert Ok(word) = words.word_at(index)
    assert words.index_of(word) == Ok(index)
  })
}

/// What the search and the decoder rely on: the words are strictly
/// increasing, lowercase, three to eight letters, and the first four letters
/// already tell one from another (the property BIP-39 chose them for).
pub fn words_are_sorted_and_distinct_test() {
  let all =
    all_indices()
    |> list.map(fn(index) {
      let assert Ok(word) = words.word_at(index)
      word
    })

  assert list.window_by_2(all)
    |> list.all(fn(pair) { string.compare(pair.0, pair.1) == order.Lt })

  assert list.all(all, fn(word) {
    string.lowercase(word) == word
    && string.length(word) >= 3
    && string.length(word) <= 8
    && !string.contains(word, " ")
  })

  let prefixes = list.map(all, fn(word) { string.slice(word, 0, 4) })
  assert set.size(set.from_list(prefixes)) == words.word_count
}

/// Only an exact word is on the list: case, padding, prefixes, extensions
/// and the empty string are all refused.
pub fn index_of_refuses_non_words_test() {
  assert words.index_of("Abandon") == Error(Nil)
  assert words.index_of("abandon ") == Error(Nil)
  assert words.index_of(" abandon") == Error(Nil)
  assert words.index_of("aband") == Error(Nil)
  assert words.index_of("abandons") == Error(Nil)
  assert words.index_of("") == Error(Nil)
  assert words.index_of("zzz") == Error(Nil)
  assert words.index_of("abandon-ability") == Error(Nil)
  assert words.index_of("café") == Error(Nil)
}

// ----------------------------------------------------------- generating

/// Fixed random bytes give the indices the bits spell, at the field
/// boundaries: all ones, a field of ones in each position, and the trailing
/// seven bits ignored.
pub fn generate_slices_the_bits_it_is_given_test() {
  let draw = fn(bytes: BitArray) {
    indices_of(pairing_code.generate(suite_returning(bytes), plate(0)))
  }

  assert draw(<<0, 0, 0, 0, 0>>) == [0, 0, 0]
  assert draw(<<0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>) == [2047, 2047, 2047]
  assert draw(<<0xFF, 0xE0, 0x00, 0x00, 0x00>>) == [2047, 0, 0]
  assert draw(<<0x00, 0x1F, 0xFC, 0x00, 0x00>>) == [0, 2047, 0]
  assert draw(<<0x00, 0x00, 0x03, 0xFF, 0x80>>) == [0, 0, 2047]
  assert draw(<<0x00, 0x00, 0x00, 0x00, 0x80>>) == [0, 0, 1]
  assert draw(<<0x00, 0x00, 0x00, 0x00, 0x7F>>) == [0, 0, 0]
  assert draw(<<0x00, 0x20, 0x00, 0x00, 0x00>>) == [1, 0, 0]
  assert draw(<<0x00, 0x10, 0x00, 0x00, 0x00>>) == [0, 1024, 0]
  assert draw(<<0x00, 0x04, 0x00, 0x00, 0x00>>) == [0, 256, 0]
  assert draw(<<0x00, 0x00, 0x00, 0x00, 0x00, 0xFF>>) == [0, 0, 0]
}

/// The suite is asked for enough bytes: a suite that gives back exactly what
/// was asked, all ones, yields three full fields only if five were asked.
pub fn generate_asks_for_enough_bytes_test() {
  let code = pairing_code.generate(suite_of_ones(), plate(0))

  assert indices_of(code) == [2047, 2047, 2047]
}

/// The three indices are the bit fields of the draw by independent
/// arithmetic, not by the slicing `generate` uses.
pub fn generate_matches_independent_arithmetic_property_test() {
  use bytes <- property(qcheck.fixed_size_byte_aligned_bit_array(5))

  let assert <<value:size(40)>> = bytes
  let first = value / int.bitwise_shift_left(1, 29)
  let second = value / int.bitwise_shift_left(1, 18) % 2048
  let third = value / int.bitwise_shift_left(1, 7) % 2048

  let code = pairing_code.generate(suite_returning(bytes), plate(7))

  assert indices_of(code) == [first, second, third]
}

/// A draw for known indices is the text it is documented to be.
pub fn generate_spells_a_known_code_test() {
  assert as_text(code_of(399, 1197, 1936)) == valid
  assert as_text(code_of(0, 0, 0)) == "482719-abandon-abandon-abandon"
  assert as_text(code_of(2047, 2047, 2047)) == "482719-zoo-zoo-zoo"
}

/// The nameplate is the one given, and the password is the words alone.
pub fn the_parts_are_the_nameplate_and_the_words_test() {
  let code = code_of(399, 1197, 1936)

  assert nameplate.to_string(pairing_code.nameplate(code)) == "482719"
  assert secret.expose(pairing_code.password(code))
    == <<"cradle-noble-velvet":utf8>>
}

// ------------------------------------------------------------- decoding

/// Every code decodes to itself, with its nameplate and password.
pub fn a_code_round_trips_property_test() {
  use code <- property(codes())

  let assert Ok(back) = pairing_code.decode(as_text(code))

  assert back == code
  assert pairing_code.nameplate(back) == pairing_code.nameplate(code)
  assert secret.expose(pairing_code.password(back))
    == secret.expose(pairing_code.password(code))
}

/// The documented code decodes and spells back as the text it came from.
pub fn the_documented_code_decodes_test() {
  let assert Ok(code) = pairing_code.decode(valid)

  assert as_text(code) == valid
  assert code == code_of(399, 1197, 1936)
}

/// `decode` never crashes, whatever string arrives, and anything it does
/// accept re-encodes to the same text.
pub fn decode_is_total_property_test() {
  use text <- property(qcheck.string())

  case pairing_code.decode(text) {
    Ok(code) -> {
      assert as_text(code) == text
    }
    Error(_) -> Nil
  }
}

/// How a valid text is damaged: a character replaced, removed or added at a
/// position, or one word swapped for another listed word (which stays a code,
/// so acceptance is reached as well as refusal).
fn damaged() -> qcheck.Generator(String) {
  qcheck.map4(
    codes(),
    qcheck.bounded_int(0, 3),
    qcheck.bounded_int(0, 40),
    qcheck.bounded_int(0, 37),
    fn(code, kind, position, pick) {
      let characters = string.to_graphemes(as_text(code))
      let alphabet =
        string.to_graphemes("abcdefghijklmnopqrstuvwxyz0123456789- A")
      let assert Ok(character) = list.drop(alphabet, pick) |> list.first
      let before = list.take(characters, position)
      let after = list.drop(characters, position)

      case kind {
        0 ->
          string.concat(list.append(before, [character, ..list.drop(after, 1)]))
        1 -> string.concat(list.append(before, list.drop(after, 1)))
        2 -> string.concat(list.append(before, [character, ..after]))
        _ -> {
          let assert Ok(word) = words.word_at(pick * 50)
          let assert [plate, _, ..rest] =
            string.split(string.concat(characters), "-")
          string.join([plate, word, ..rest], "-")
        }
      }
    },
  )
}

/// Near-misses of valid codes are either refused or are themselves codes
/// that re-encode to exactly their text.
pub fn what_decode_accepts_re_encodes_property_test() {
  use text <- property(damaged())

  case pairing_code.decode(text) {
    Ok(code) -> {
      assert as_text(code) == text
    }
    Error(_) -> Nil
  }
}

/// Past the limit is `TooLong`, and the limit itself is not.
pub fn decode_refuses_too_long_test() {
  let limit = limits.max_pairing_code_bytes

  assert pairing_code.decode(string.repeat("a", limit + 1)) == Error(TooLong)
  assert pairing_code.decode(valid <> string.repeat("a", limit))
    == Error(TooLong)
  assert pairing_code.decode(string.repeat("a", limit)) == Error(BadShape)
}

/// Uppercase anywhere is not a code: the decoder does not fold case.
pub fn decode_refuses_uppercase_test() {
  assert pairing_code.decode("482719-Cradle-noble-velvet") == Error(BadShape)
  assert pairing_code.decode("482719-cradle-noble-velveT") == Error(BadShape)
  assert pairing_code.decode("482719-CRADLE-NOBLE-VELVET") == Error(BadShape)
}

/// Whitespace is not trimmed, inside or around the code, and nothing but a
/// single hyphen separates parts.
pub fn decode_refuses_whitespace_and_other_separators_test() {
  assert pairing_code.decode(" " <> valid) == Error(BadShape)
  assert pairing_code.decode(valid <> " ") == Error(BadShape)
  assert pairing_code.decode(valid <> "\n") == Error(BadShape)
  assert pairing_code.decode(valid <> "\r\n") == Error(BadShape)
  assert pairing_code.decode("\t" <> valid) == Error(BadShape)
  assert pairing_code.decode("482719 cradle noble velvet") == Error(BadShape)
  assert pairing_code.decode("482719-cradle noble-velvet") == Error(BadShape)
  assert pairing_code.decode("482719_cradle_noble_velvet") == Error(BadShape)
  assert pairing_code.decode("482719.cradle.noble.velvet") == Error(BadShape)
}

/// A doubled, leading or trailing hyphen leaves an empty part, and empty
/// text is not a code.
pub fn decode_refuses_empty_parts_test() {
  assert pairing_code.decode("482719--cradle-noble-velvet") == Error(BadShape)
  assert pairing_code.decode("482719-cradle--noble-velvet") == Error(BadShape)
  assert pairing_code.decode("-482719-cradle-noble-velvet") == Error(BadShape)
  assert pairing_code.decode(valid <> "-") == Error(BadShape)
  assert pairing_code.decode("") == Error(BadShape)
  assert pairing_code.decode("-") == Error(BadShape)
}

/// Exactly three words: none, one, two, four and more are all refused, with
/// every word on the list.
pub fn decode_refuses_the_wrong_number_of_words_test() {
  assert pairing_code.decode("482719") == Error(BadShape)
  assert pairing_code.decode("482719-cradle") == Error(BadShape)
  assert pairing_code.decode("482719-cradle-noble") == Error(BadShape)
  assert pairing_code.decode("482719-cradle-noble-velvet-legal")
    == Error(BadShape)
  assert pairing_code.decode("482719-cradle-noble-velvet-legal-zoo")
    == Error(BadShape)
  assert pairing_code.decode("cradle-noble-velvet") == Error(BadShape)
}

/// The nameplate is exactly six digits: shorter, longer and non-digits are
/// refused as a nameplate.
pub fn decode_refuses_a_bad_nameplate_test() {
  assert pairing_code.decode("48271-cradle-noble-velvet") == Error(BadNameplate)
  assert pairing_code.decode("4827190-cradle-noble-velvet")
    == Error(BadNameplate)
  assert pairing_code.decode("48271a-cradle-noble-velvet")
    == Error(BadNameplate)
  assert pairing_code.decode("abcdef-cradle-noble-velvet")
    == Error(BadNameplate)
  assert pairing_code.decode("cradle-cradle-noble-velvet")
    == Error(BadNameplate)
}

/// A word not on the list is refused at its position, whichever position it
/// is in; the first such word is the one named.
pub fn decode_refuses_an_unknown_word_test() {
  assert pairing_code.decode("482719-cradel-noble-velvet")
    == Error(UnknownWord(1))
  assert pairing_code.decode("482719-cradle-nobel-velvet")
    == Error(UnknownWord(2))
  assert pairing_code.decode("482719-cradle-noble-velvett")
    == Error(UnknownWord(3))
  assert pairing_code.decode("482719-cradle-noble-velve")
    == Error(UnknownWord(3))
  assert pairing_code.decode("482719-crad-noble-velvet")
    == Error(UnknownWord(1))
  assert pairing_code.decode("482719-cradle1-noble-velvet")
    == Error(UnknownWord(1))
  assert pairing_code.decode("482719-xxx-yyy-velvet") == Error(UnknownWord(1))
}

/// Characters outside ASCII are refused as a shape, never as a word.
pub fn decode_refuses_non_ascii_test() {
  assert pairing_code.decode("482719-cradlé-noble-velvet") == Error(BadShape)
  assert pairing_code.decode("４８２７１９-cradle-noble-velvet") == Error(BadShape)
  assert pairing_code.decode("482719-cradle-noble-velvet🙂") == Error(BadShape)
}

/// No refusal carries the text, a word or the nameplate: a code is a secret
/// and an error is logged.
pub fn errors_never_carry_the_text_test() {
  let refused = [
    "482719-secretly-noble-velvet",
    "482719-cradle-noble",
    "000000-Cradle-noble-velvet",
    "12345-cradle-noble-velvet",
    string.repeat("hunter", 20),
  ]

  list.each(refused, fn(text) {
    let assert Error(error) = pairing_code.decode(text)
    let rendered = string.inspect(error)

    assert !string.contains(rendered, "secretly")
    assert !string.contains(rendered, "cradle")
    assert !string.contains(rendered, "hunter")
    assert !string.contains(rendered, "12345")
  })
}

/// A code prints as a closure for its words: the secret is not in any
/// rendering of the value.
pub fn a_code_does_not_print_its_words_test() {
  let assert Ok(code) = pairing_code.decode(valid)
  let rendered = string.inspect(code)

  assert !string.contains(rendered, "cradle")
  assert !string.contains(rendered, "noble")
  assert !string.contains(rendered, "velvet")
  assert !string.contains(string.inspect(pairing_code.password(code)), "cradle")
}
