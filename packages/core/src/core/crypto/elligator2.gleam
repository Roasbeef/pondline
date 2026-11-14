//// The Elligator 2 map onto Curve25519, the step that turns a hash into
//// CPace's generator (`core/crypto/cpace`).
////
//// CPace needs a generator nobody knows the discrete logarithm of, and it
//// derives one from the password: hash the password-bearing generator
//// string, read the digest as a field element, and map that onto the curve.
//// The map must be deterministic, must hit a curve point for every input,
//// and must not reveal a relation between the points of two passwords; the
//// Elligator 2 map of RFC 9380 §6.7.1 is all three, and cpace-21 §8.2 names
//// it. This module is that map for Curve25519 in Montgomery form
//// (`A = 486662`, `B = 1`, the non-square `Z = 2`), returning only the
//// u-coordinate, which is all X25519 reads.
////
//// The arithmetic is the field GF(2^255 - 19) written over Gleam's
//// arbitrary-precision `Int`: reduction, multiplication, exponentiation by
//// square-and-multiply, `inverse` as `x^(p-2)` (RFC 9380's `inv0`) and the
//// square test as Euler's criterion `x^((p-1)/2)`. It is total. Every
//// integer maps, and
//// `decode_u_coordinate` and `encode_u_coordinate` are the RFC 7748
//// conversions cpace-21 Appendix A.4 repeats.
////
//// ## Timing
////
//// **This implementation is not constant time.** Its input derives from
//// the password, and cpace-21 §10.10 asks that the map run in constant
//// time so that a timing observer learns nothing about the generator. Here
//// the exponentiations branch on the bits of public exponents only, but
//// BEAM bignum arithmetic takes time that depends on the size of its
//// operands, and the final choice between the two candidate points is an
//// ordinary branch. ADR-016 accepts that, for now, on a stated argument: the
//// observer would have to share the host, across Tor the jitter is orders
//// of magnitude above the signal, and a code is used once. A native helper
//// is the remedy if review rejects that argument, and it would need its own
//// ADR. On the JavaScript target Gleam's `Int` is a float, so this module
//// computes nonsense there; it is correct on the BEAM only.
////
//// ## The exceptional inputs
////
//// RFC 9380's map divides by `1 + Z r^2`, which is zero only when `-1/Z`
//// is a square. For Curve25519 it is not, so that division never fails; the
//// RFC's fallback for it is kept anyway, because it costs one comparison
//// and makes the map total by construction rather than by argument. One
//// input class does produce a degenerate point: `r = 0` (a field element
//// equal to 0 or to p) maps to `u = 0`, the point of order two, because
//// `-A` is not a square. CPace meets that as an X25519 refusal when it
//// multiplies the generator, and reports it; a SHA-512 output landing there
//// has probability 2^-254.
////
//// Checked against cpace-21 Appendix B.1.1, through the generator, in
//// `packages/core/test/core/crypto/elligator2_test.gleam`, with properties
//// that every output is on the curve and that `r` and `-r` agree.

import gleam/int

/// The field prime `p = 2^255 - 19`.
pub const field_prime =
  57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_949

/// The Montgomery coefficient `A` of Curve25519, `v^2 = u^3 + A u^2 + u`.
pub const curve_a = 486_662

/// The non-square `Z` RFC 9380 fixes for Curve25519, and which cpace-21
/// Appendix A.5's `find_z_ell2` finds.
pub const non_square = 2

/// The size of a u-coordinate on the wire, in bytes.
pub const coordinate_bytes = 32

/// `2^255 - 1`: the mask that clears bit 255, which RFC 7748's
/// `decodeUCoordinate` ignores for Curve25519.
const low_255_bits =
  57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_967

/// `(p - 1) / 2`, the exponent of Euler's criterion.
const legendre_exponent =
  28_948_022_309_329_048_855_892_746_252_171_976_963_317_496_166_410_141_009_864_396_001_978_282_409_974

/// `p - 2`, the exponent that inverts by Fermat's little theorem.
const inverse_exponent =
  57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_947

/// RFC 7748's `decodeUCoordinate` for Curve25519: 32 bytes read
/// little-endian with bit 255 cleared. The result is below 2^255 but not
/// necessarily below p, exactly as the RFC leaves it; `map_to_curve`
/// reduces. Any other length is refused.
///
/// ## Examples
///
/// ```gleam
/// assert elligator2.decode_u_coordinate(<<9, 0:248>>) == Ok(9)
/// ```
///
/// ```gleam
/// assert elligator2.decode_u_coordinate(<<0:248, 0x80>>) == Ok(0)
/// ```
pub fn decode_u_coordinate(bytes: BitArray) -> Result(Int, Nil) {
  case bytes {
    <<value:little-size(256)>> -> Ok(int.bitwise_and(value, low_255_bits))
    _ -> Error(Nil)
  }
}

/// RFC 7748's `encodeUCoordinate` for Curve25519: the field element,
/// reduced modulo p, as 32 little-endian bytes. Reducing first makes the
/// encoding canonical, so equal field elements encode equally.
///
/// ## Examples
///
/// ```gleam
/// assert elligator2.encode_u_coordinate(9) == <<9, 0:248>>
/// ```
pub fn encode_u_coordinate(u: Int) -> BitArray {
  <<reduce(u):little-size(256)>>
}

/// RFC 9380 §6.7.1's `map_to_curve_elligator2` for Curve25519, returning
/// the u-coordinate of the point in `[0, p)`. The input is any integer and
/// is reduced modulo p first; cpace-21 Appendix A.5's `elligator2` computes
/// the same value by another route.
///
/// The map tries `x1 = -A / (1 + Z r^2)`. If `x1^3 + A x1^2 + x1` is a
/// square, `x1` is the u-coordinate of a curve point; if not, then because
/// `Z` is a non-square, `x2 = -x1 - A` is, and the map returns that. Which
/// one it takes depends on the input, and so on the password: see the
/// module doc's timing section.
///
/// ## Examples
///
/// ```gleam
/// assert elligator2.map_to_curve(0) == 0
/// ```
pub fn map_to_curve(field_element: Int) -> Int {
  let r = reduce(field_element)
  let denominator = reduce(1 + non_square * multiply(r, r))
  let x1 = multiply(reduce(0 - curve_a), inverse(denominator))

  // The RFC's exceptional case: a zero denominator inverts to zero, and
  // the map then starts from `-A`. Unreachable for Curve25519, kept so the
  // map is total without an argument about which inputs reach it.
  let x1 = case x1 == 0 {
    True -> reduce(0 - curve_a)
    False -> x1
  }

  let gx1 = curve_right_side(x1)
  let x2 = reduce(0 - x1 - curve_a)

  // The choice between the two candidates: exactly one of them lies on
  // the curve rather than its twist, and Euler's criterion says which.
  case is_square(gx1) {
    True -> x1
    False -> x2
  }
}

/// `u^3 + A u^2 + u`, the right-hand side of the curve equation with
/// `B = 1`: a square exactly when `u` is the coordinate of a curve point
/// rather than of a point on the twist.
///
/// ## Examples
///
/// ```gleam
/// assert elligator2.curve_right_side(0) == 0
/// ```
pub fn curve_right_side(u: Int) -> Int {
  let square = multiply(u, u)

  reduce(multiply(square, u) + multiply(curve_a, square) + u)
}

/// Whether `value` is a square in the field, zero included, by Euler's
/// criterion: `value^((p-1)/2)` is 1 for a non-zero square, `p - 1` for a
/// non-square and 0 for zero.
///
/// ## Examples
///
/// ```gleam
/// assert elligator2.is_square(4)
/// ```
///
/// ```gleam
/// assert !elligator2.is_square(elligator2.non_square)
/// ```
pub fn is_square(value: Int) -> Bool {
  power(reduce(value), legendre_exponent) != field_prime - 1
}

/// The representative of `value` in `[0, p)`. Gleam's `%` keeps the sign
/// of the dividend, so a negative value is lifted by one more p.
fn reduce(value: Int) -> Int {
  { value % field_prime + field_prime } % field_prime
}

/// The product of two field elements, reduced.
fn multiply(left: Int, right: Int) -> Int {
  reduce(left * right)
}

/// The inverse by Fermat, `x^(p-2)`, which sends zero to zero: RFC 9380's
/// `inv0`, which the exceptional case of `map_to_curve` relies on.
fn inverse(value: Int) -> Int {
  power(value, inverse_exponent)
}

/// `base^exponent` in the field, by square-and-multiply over the bits of
/// the exponent. The exponents here are the public constants above, so
/// the branch on each bit reveals nothing about the base.
fn power(base: Int, exponent: Int) -> Int {
  power_loop(reduce(base), exponent, 1)
}

/// The square-and-multiply loop: `accumulator * base^exponent` is
/// invariant, and the exponent halves on every step until it is zero.
fn power_loop(base: Int, exponent: Int, accumulator: Int) -> Int {
  // The exponent is spent once it reaches zero, and the accumulator holds
  // the power.
  case exponent > 0 {
    False -> accumulator

    True -> {
      // The exponent's lowest bit decides whether this power of the base
      // joins the product.
      let accumulator = case int.is_odd(exponent) {
        True -> multiply(accumulator, base)
        False -> accumulator
      }

      power_loop(multiply(base, base), exponent / 2, accumulator)
    }
  }
}
