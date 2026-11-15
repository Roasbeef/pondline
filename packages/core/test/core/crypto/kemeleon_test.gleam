//// Round trips, totality and refusals for `core/crypto/kemeleon`.
////
//// The property OQUAKE rests on is that `decode` turns every string of the
//// encoded length into a well-formed ML-KEM-1024 encapsulation key, so a
//// password guess can never unmask to something that is visibly not a key.
//// It is checked here over arbitrary bytes with the coefficients read back
//// by this file's own FIPS 203 decoder, independent of the module's. The
//// draft's vectors, which need the fixtures in `packages/primitives`, are
//// checked in `primitives/bua_skem_test`.

import core/crypto/error.{Malformed}
import core/crypto/kemeleon
import core/secret
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import qcheck

/// How many keys each round-trip property is checked over, and the seed
/// they are drawn from. Each case encodes a whole key, so the count is
/// modest; the seed is fixed so the gate is deterministic.
const round_trip_count = 40

const round_trip_seed = 132

/// How many arbitrary strings the totality property decodes, and its seed.
const totality_count = 60

const totality_seed = 1596

fn property(
  count: Int,
  seed: Int,
  generator: qcheck.Generator(a),
  check: fn(a) -> Nil,
) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(count)
  |> qcheck.with_seed(qcheck.seed(seed))
  |> qcheck.run(generator, check)
}

/// FIPS 203's ByteEncode_12 of a list of coefficients, written here rather
/// than taken from the module so that the round trip is checked against an
/// independent reading of the standard.
fn byte_encode(coefficients: List(Int)) -> BitArray {
  case coefficients {
    [first, second, ..rest] -> <<
      { first % 256 },
      { first / 256 + 16 * { second % 16 } },
      { second / 16 },
      byte_encode(rest):bits,
    >>
    _ -> <<>>
  }
}

/// FIPS 203's ByteDecode_12, the inverse of `byte_encode`.
fn byte_decode(bytes: BitArray) -> List(Int) {
  case bytes {
    <<low, middle, high, rest:bytes>> -> [
      low + 256 * { middle % 16 },
      middle / 16 + 16 * high,
      ..byte_decode(rest)
    ]
    _ -> []
  }
}

/// A valid encapsulation key: 1024 coefficients below the modulus and a
/// seed. Coefficients shrink toward zero, the least eventful key.
fn encapsulation_keys() -> qcheck.Generator(BitArray) {
  qcheck.map2(
    qcheck.fixed_length_list_from(
      qcheck.bounded_int(0, kemeleon.modulus - 1),
      kemeleon.polynomial_count * kemeleon.coefficients_per_polynomial,
    ),
    qcheck.fixed_size_byte_aligned_bit_array(kemeleon.seed_bytes),
    fn(coefficients, seed) { <<byte_encode(coefficients):bits, seed:bits>> },
  )
}

fn randomness_from(bytes: BitArray) -> kemeleon.Randomness {
  let assert Ok(randomness) = kemeleon.randomness(secret.new(bytes))
    as "the draw is randomness_bytes long"
  randomness
}

fn randomnesses() -> qcheck.Generator(kemeleon.Randomness) {
  qcheck.fixed_size_byte_aligned_bit_array(kemeleon.randomness_bytes)
  |> qcheck.map(randomness_from)
}

/// Any valid key decodes back from its encoding, under any randomness. An
/// off-by-one in the base-3329 accumulation or the digit read-back breaks
/// this.
pub fn decode_inverts_encode_test() {
  use #(key, randomness) <- property(
    round_trip_count,
    round_trip_seed,
    qcheck.tuple2(encapsulation_keys(), randomnesses()),
  )

  let assert Ok(encoded) = kemeleon.encode(key, randomness)

  assert bit_array.byte_size(encoded) == kemeleon.encoded_key_bytes
  assert kemeleon.decode(encoded) == Ok(key)
}

/// The extreme keys round-trip too: every coefficient zero and every one
/// 3328, under the smallest and the largest draws.
pub fn extreme_keys_round_trip_test() {
  let seed = <<7:size(256)>>
  let low = <<byte_encode(list.repeat(0, 1024)):bits, seed:bits>>
  let high = <<byte_encode(list.repeat(3328, 1024)):bits, seed:bits>>
  let smallest = randomness_from(<<0:size(1536)>>)
  let largest = randomness_from(<<-1:size(1536)>>)

  assert list.all([low, high], fn(key) {
    list.all([smallest, largest], fn(randomness) {
      let assert Ok(encoded) = kemeleon.encode(key, randomness)
      kemeleon.decode(encoded) == Ok(key)
    })
  })
}

/// The seed rho passes through untouched at the end, which is what lets
/// ML-BUA-sKEM split an encoded key where it splits a FIPS 203 one.
pub fn encoding_ends_with_the_seed_test() {
  use #(key, randomness) <- property(
    round_trip_count,
    round_trip_seed + 1,
    qcheck.tuple2(encapsulation_keys(), randomnesses()),
  )

  let assert Ok(encoded) = kemeleon.encode(key, randomness)
  let assert Ok(seed) = bit_array.slice(key, 1536, 32)
  let assert Ok(tail) = bit_array.slice(encoded, 1564, 32)

  assert tail == seed
}

/// `decode` is total: every string of the encoded length decodes to a key
/// of FIPS 203's length whose every coefficient is below the modulus, with
/// the seed passed through, and which `encode` accepts again.
pub fn decode_is_total_and_yields_valid_keys_test() {
  use bytes <- property(
    totality_count,
    totality_seed,
    qcheck.fixed_size_byte_aligned_bit_array(kemeleon.encoded_key_bytes),
  )

  let assert Ok(key) = kemeleon.decode(bytes)
  let assert Ok(polynomials) = bit_array.slice(key, 0, 1536)
  let assert Ok(seed) = bit_array.slice(key, 1536, 32)
  let assert Ok(tail) = bit_array.slice(bytes, 1564, 32)
  let coefficients = byte_decode(polynomials)

  assert bit_array.byte_size(key) == kemeleon.encapsulation_key_bytes
  assert list.length(coefficients) == 1024
  assert list.all(coefficients, fn(c) { c >= 0 && c < kemeleon.modulus })
  assert seed == tail
  assert kemeleon.encode(key, randomness_from(<<0:size(1536)>>)) |> is_ok
}

fn is_ok(result: Result(a, b)) -> Bool {
  case result {
    Ok(_) -> True
    Error(_) -> False
  }
}

/// The string of all ones, the largest integer every chunk can hold, still
/// decodes to a valid key, though no encoding ever reaches it: decoding
/// reads remainders modulo 3329 and does not rely on the encoder's range.
pub fn all_ones_decodes_to_a_valid_key_test() {
  let assert Ok(key) = kemeleon.decode(<<-1:size(12_768)>>)
  let assert Ok(polynomials) = bit_array.slice(key, 0, 1536)

  assert list.all(byte_decode(polynomials), fn(c) { c < kemeleon.modulus })
}

/// Encoding is randomised: two draws give two different encodings of one
/// key, both of which decode to it.
pub fn encoding_depends_on_the_randomness_test() {
  let key = <<byte_encode(list.repeat(1234, 1024)):bits, 9:size(256)>>
  let assert Ok(first) = kemeleon.encode(key, randomness_from(<<1:size(1536)>>))
  let assert Ok(second) =
    kemeleon.encode(key, randomness_from(<<2:size(1536)>>))

  assert first != second
  assert kemeleon.decode(first) == kemeleon.decode(second)
}

/// A multiple inside its range is used exactly as given: encoding with
/// multiple m adds m * 3329^256 to the polynomial's integer, so the
/// encodings under multiples 0 and 1 differ by exactly 3329^256 in each
/// chunk.
pub fn a_multiple_in_range_is_used_as_given_test() {
  let key = <<byte_encode(list.repeat(5, 1024)):bits, 0:size(256)>>
  let assert Ok(zero) = kemeleon.randomness_from_multiples([0, 0, 0, 0])
  let assert Ok(one) = kemeleon.randomness_from_multiples([1, 1, 1, 1])
  let assert Ok(<<low:little-size(3128), _:bits>>) = kemeleon.encode(key, zero)
  let assert Ok(<<high:little-size(3128), _:bits>>) = kemeleon.encode(key, one)

  assert high - low == span()
}

fn span() -> Int {
  list.fold(list.repeat(kemeleon.modulus, 256), 1, fn(acc, q) { acc * q })
}

/// The lowest `count` base-3329 digits of `value`, lowest first: the
/// coefficients of the polynomial whose integer is `value`.
fn digits(value: Int, count: Int) -> List(Int) {
  case count {
    0 -> []
    _ -> [
      value % kemeleon.modulus,
      ..digits(value / kemeleon.modulus, count - 1)
    ]
  }
}

/// The Kemeleon draft draws a multiple from `[0, floor((2^3128 - r) /
/// 3329^256)]`, and for the one polynomial value `2^3128 mod 3329^256` its
/// top multiple makes the sum exactly `2^3128`, which 391 bytes would write
/// as zeros. Here that multiple is out of range and reduces, so a key made
/// of that polynomial round-trips under the draft's top multiple, the
/// largest multiple still in range, and the largest 48-byte draw.
pub fn the_drafts_overflow_point_round_trips_test() {
  let ceiling = int.bitwise_shift_left(1, 3128)
  let star = ceiling % span()
  let draft_top = { ceiling - star } / span()
  let polynomial = byte_encode(digits(star, 256))
  let key = <<
    polynomial:bits,
    polynomial:bits,
    polynomial:bits,
    polynomial:bits,
    3:size(256),
  >>
  let assert Ok(multiples) =
    kemeleon.randomness_from_multiples([
      draft_top,
      draft_top - 1,
      draft_top + 1,
      0,
    ])
    as "four non-negative multiples"

  // The draft's top multiple is the one whose sum would not fit.
  assert star + draft_top * span() == ceiling

  // Each draw encodes to a first chunk that is not the zero string the
  // overflow would write, and decodes back to the key.
  assert list.all([multiples, randomness_from(<<-1:size(1536)>>)], fn(draw) {
    let assert Ok(encoded) = kemeleon.encode(key, draw)
    let assert <<first:little-size(3128), _:bits>> = encoded
      as "an encoding starts with a whole chunk"

    first != 0 && kemeleon.decode(encoded) == Ok(key)
  })
}

/// A coefficient of 3329 fails FIPS 203's modulus check and has no
/// encoding; neither does a key of the wrong length.
pub fn encode_refuses_what_is_not_a_key_test() {
  let randomness = randomness_from(<<0:size(1536)>>)
  let bad = <<byte_encode([3329, ..list.repeat(0, 1023)]):bits, 0:size(256)>>
  let good = <<byte_encode(list.repeat(0, 1024)):bits, 0:size(256)>>

  assert kemeleon.encode(bad, randomness)
    == Error(Malformed("ml-kem encapsulation key"))
  assert kemeleon.encode(<<good:bits, 0>>, randomness)
    == Error(Malformed("ml-kem encapsulation key"))
  assert kemeleon.encode(<<>>, randomness)
    == Error(Malformed("ml-kem encapsulation key"))
}

/// Only the encoded length is refused by `decode`.
pub fn decode_refuses_wrong_lengths_test() {
  assert kemeleon.decode(<<0:size(12_760)>>)
    == Error(Malformed("kemeleon encoded key"))
  assert kemeleon.decode(<<0:size(12_776)>>)
    == Error(Malformed("kemeleon encoded key"))
}

/// Randomness comes in exactly four draws or four non-negative multiples.
pub fn randomness_has_one_draw_per_polynomial_test() {
  assert kemeleon.randomness(secret.new(<<0:size(1528)>>))
    == Error(Malformed("kemeleon randomness"))
  assert kemeleon.randomness_from_multiples([1, 2, 3])
    == Error(Malformed("kemeleon multiples"))
  assert kemeleon.randomness_from_multiples([1, 2, 3, -4])
    == Error(Malformed("kemeleon multiples"))
}

/// The randomness is secret, so it does not print.
pub fn randomness_does_not_print_test() {
  let assert Ok(randomness) =
    kemeleon.randomness_from_multiples([
      123_456_789_123,
      223_456_789_123,
      323_456_789_123,
      423_456_789_123,
    ])

  assert !string.contains(string.inspect(randomness), "123456789123")
}
