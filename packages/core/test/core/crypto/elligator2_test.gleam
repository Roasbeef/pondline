//// The Elligator 2 map onto Curve25519 (`core/crypto/elligator2`).
////
//// Three kinds of evidence. The draft's own vector: cpace-21 Appendix
//// B.1.1 prints the hash of a generator string, the field element it
//// decodes to and the generator it maps to, and those hex strings were
//// copied here by script from the fixture
//// `packages/primitives/test/vectors/cpace_x25519_sha512.json`. Values
//// from an independent implementation: cpace-21 Appendix A.5's reference
//// `elligator2`, which reaches the point by a different formula, run in
//// Python over inputs chosen to take both branches of the map. And
//// properties: every input lands on the curve, `r` and `-r` agree, and
//// the input is read modulo p.

import core/crypto/elligator2
import gleam/bit_array
import gleam/list
import qcheck

/// How many inputs each property draws, and its fixed seed.
const property_count = 300

const property_seed = 2_550_519

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

fn hex(text: String) -> BitArray {
  let assert Ok(bytes) = bit_array.base16_decode(text)
    as "test vectors are well-formed hex"
  bytes
}

fn decoded(text: String) -> Int {
  let assert Ok(value) = elligator2.decode_u_coordinate(hex(text))
    as "a vector coordinate is 32 bytes"
  value
}

fn map_bytes(text: String) -> BitArray {
  elligator2.map_to_curve(decoded(text))
  |> elligator2.encode_u_coordinate
}

/// cpace-21 B.1.1, `hash generator string`.
const b1_generator_hash =
  "03998087BDB1A2617BBE25EF5A7C18CD4F84F902328701790958755EE4AED1D3"

/// cpace-21 B.1.1, `decoded field element of 255 bits`.
const b1_field_element =
  "03998087BDB1A2617BBE25EF5A7C18CD4F84F902328701790958755EE4AED153"

/// cpace-21 B.1.1, `generator g`.
const b1_generator =
  "D04BF6D41F6A289632A2E929FA29BEBD51092512A7829FDDE7D314B62F05A73F"

/// Decoding clears bit 255 and nothing else: the B.1.1 digest ends in
/// `d3`, its field element in `53`.
pub fn decode_clears_bit_255_as_b1_1_does_test() {
  assert elligator2.encode_u_coordinate(decoded(b1_generator_hash))
    == hex(b1_field_element)
}

/// B.1.1: the field element maps to the generator.
pub fn b1_1_field_element_maps_to_the_generator_test() {
  assert map_bytes(b1_field_element) == hex(b1_generator)
  assert map_bytes(b1_generator_hash) == hex(b1_generator)
}

/// Inputs and outputs of cpace-21 Appendix A.5's reference `elligator2`,
/// computed in Python. The last column says which branch the reference
/// took (its `epsilon`): `x1` where the first candidate is on the curve,
/// `x2` where the map falls through to `-x1 - A`. 2^255 - 1 is above p, so
/// it also checks that an unreduced input is reduced.
pub fn reference_implementation_agrees_on_both_branches_test() {
  let cases = [
    #(1, "9CDB525555555555555555555555555555555555555555555555555555555555"),
    #(2, "B349328EE3388EE3388EE3388EE3388EE3388EE3388EE3388EE3388EE3388E63"),
    #(3, "55C4AEA1BC86F21ACA6B28AFA1BC86F21ACA6B28AFA1BC86F21ACA6B28AFA13C"),
    #(
      elligator2.field_prime - 1,
      "9CDB525555555555555555555555555555555555555555555555555555555555",
    ),
    #(
      elligator2.field_prime + 18,
      "1E5942DD97C756040D27755F1E5B11349CD47D796C45D07052F7E5B11541C349",
    ),
    #(
      0x1234567890ABCDEF * 1_267_650_600_228_229_401_496_703_205_376,
      "5256E42F7A470428DA9DB55D18F4E0E7D36CB28A67DB2ACC97AB0E2958BC303C",
    ),
  ]

  // Branches, in order: x1, x2, x1, x1, x2, x2.
  assert list.all(cases, fn(case_) {
    let #(input, expected) = case_
    elligator2.encode_u_coordinate(elligator2.map_to_curve(input))
    == hex(expected)
  })
}

/// Zero maps to the point of order two, `u = 0`, because `-A` is not a
/// square: the one degenerate output, which CPace refuses when it
/// multiplies the generator.
pub fn zero_maps_to_the_point_of_order_two_test() {
  assert !elligator2.is_square(0 - elligator2.curve_a)
  assert elligator2.map_to_curve(0) == 0
  assert elligator2.map_to_curve(elligator2.field_prime) == 0
}

/// Z = 2 is a non-square, which is what makes the second candidate a curve
/// point whenever the first is not. And -1/2 is a non-square, which is what
/// keeps the map's denominator `1 + 2 r^2` from vanishing: -1/2 is -2 times
/// the square (1/2)^2, so it is a square exactly when -2 is, and -2 is not.
pub fn the_constants_have_the_properties_the_map_needs_test() {
  assert !elligator2.is_square(elligator2.non_square)
  assert elligator2.is_square(elligator2.field_prime - 1)
  assert !elligator2.is_square(elligator2.field_prime - 2)
}

/// Decoding refuses anything but 32 bytes.
pub fn decode_refuses_other_lengths_test() {
  assert elligator2.decode_u_coordinate(<<0:248>>) == Error(Nil)
  assert elligator2.decode_u_coordinate(<<0:264>>) == Error(Nil)
  assert elligator2.decode_u_coordinate(<<>>) == Error(Nil)
}

/// Every 32 bytes decode, and map to a reduced coordinate of a point on
/// the curve, not the twist.
pub fn every_input_maps_onto_the_curve_property_test() {
  use bytes <- property(qcheck.fixed_size_byte_aligned_bit_array(32))

  let assert Ok(field_element) = elligator2.decode_u_coordinate(bytes)
    as "32 bytes always decode"
  let u = elligator2.map_to_curve(field_element)

  assert u >= 0 && u < elligator2.field_prime
  assert elligator2.is_square(elligator2.curve_right_side(u))
}

/// The map reads `r^2`, so `r` and `-r` give one point; and it reads its
/// input modulo p, so `r` and `r + p` do too.
pub fn the_map_is_even_and_reads_modulo_p_property_test() {
  use bytes <- property(qcheck.fixed_size_byte_aligned_bit_array(32))

  let assert Ok(r) = elligator2.decode_u_coordinate(bytes)
    as "32 bytes always decode"
  let u = elligator2.map_to_curve(r)

  assert elligator2.map_to_curve(elligator2.field_prime - r) == u
  assert elligator2.map_to_curve(r + elligator2.field_prime) == u
}
