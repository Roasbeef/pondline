import Pondline.Kemeleon

/-
A transcription of RFC 9380's Elligator 2 map onto Curve25519 as
`packages/core/src/core/crypto/elligator2.gleam` implements it:
`map_to_curve`, `curve_right_side`, `is_square`, the private `reduce`,
`multiply`, `inverse`, `power` and `power_loop`, and the RFC 7748
conversions `decode_u_coordinate` and `encode_u_coordinate`.

The arithmetic is over `Int`, as the Gleam's is, and Gleam's `%` is the
remainder that keeps the dividend's sign, which is `Int.tmod`; `reduce` uses
it exactly as the Gleam writes it. Exponents are the module's positive
constants, so they are `Nat` here.

What is proved is only what elementary algebra gives: every output is a
reduced field element, and the map reads its input through `r^2` modulo p,
so `r`, `p - r` and `r + p` map alike. That the output is the u-coordinate
of a point on the curve rather than its twist is a theorem about quadratic
residues in GF(2^255 - 19) (Euler's criterion, and that Z = 2 is a
non-square), which core Lean cannot reach without a library of field
theory. It is tested, not proved: by the Gleam property test
`every_input_maps_onto_the_curve_property_test`, by cpace-21's B.1.1 vector
and the reference values in `elligator2_test.gleam`, and, through the
conformance vectors, by the agreement of this transcription with the
Gleam on those same inputs.
-/

namespace Pondline.Elligator2

open Pondline

/-- `elligator2.field_prime`, p = 2^255 - 19. -/
def p : Int := 57896044618658097711785492504343953926634992332820282019728792003956564819949

/-- `elligator2.curve_a`. -/
def curveA : Int := 486662

/-- `elligator2.non_square`, Z. -/
def nonSquare : Int := 2

/-- `low_255_bits`, 2^255 - 1. -/
def low255Bits : Nat := 57896044618658097711785492504343953926634992332820282019728792003956564819967

/-- `legendre_exponent`, (p - 1) / 2. -/
def legendreExponent : Nat := 28948022309329048855892746252171976963317496166410141009864396001978282409974

/-- `inverse_exponent`, p - 2. -/
def inverseExponent : Nat := 57896044618658097711785492504343953926634992332820282019728792003956564819947

/-- `reduce`: `{ value % field_prime + field_prime } % field_prime`, with
Gleam's truncated remainder. -/
def reduce (value : Int) : Int := Int.tmod (Int.tmod value p + p) p

/-- `multiply`. -/
def multiply (left right : Int) : Int := reduce (left * right)

/-- `power_loop`: square-and-multiply over the bits of the exponent. -/
def powerLoop (base : Int) (exponent : Nat) (accumulator : Int) : Int :=
  if exponent > 0 then
    let accumulator := if exponent % 2 = 1 then multiply accumulator base else accumulator
    powerLoop (multiply base base) (exponent / 2) accumulator
  else accumulator
termination_by exponent
decreasing_by omega

/-- `power`. -/
def power (base : Int) (exponent : Nat) : Int := powerLoop (reduce base) exponent 1

/-- `inverse`, Fermat's `x^(p-2)`. -/
def inverse (value : Int) : Int := power value inverseExponent

/-- `is_square`, Euler's criterion. -/
def isSquare (value : Int) : Bool := power (reduce value) legendreExponent != p - 1

/-- `curve_right_side`, `u^3 + A u^2 + u`. -/
def curveRightSide (u : Int) : Int :=
  let square := multiply u u
  reduce (multiply square u + multiply curveA square + u)

/-- `map_to_curve`. -/
def mapToCurve (fieldElement : Int) : Int :=
  let r := reduce fieldElement
  let denominator := reduce (1 + nonSquare * multiply r r)
  let x1 := multiply (reduce (0 - curveA)) (inverse denominator)
  let x1 := if x1 = 0 then reduce (0 - curveA) else x1
  let gx1 := curveRightSide x1
  let x2 := reduce (0 - x1 - curveA)
  if isSquare gx1 then x1 else x2

/-- `decode_u_coordinate`: 32 bytes little-endian, bit 255 cleared. -/
def decodeU (bytes : Bytes) : Option Nat :=
  if bytes.length = 32 then some (Kemeleon.valLE bytes &&& low255Bits) else none

/-- `encode_u_coordinate`: the reduced element as 32 little-endian bytes. -/
def encodeU (u : Int) : Bytes := Kemeleon.writeLE 32 (reduce u).toNat

/-! ## The constants are what their names say -/

theorem constants :
    p = 2 ^ 255 - 19 ∧ (low255Bits : Int) = 2 ^ 255 - 1 ∧
      (legendreExponent : Int) = (p - 1) / 2 ∧ (inverseExponent : Int) = p - 2 := by
  decide +kernel

theorem p_pos : 0 < p := by decide

/-! ## Reduction -/

/-- `reduce` with Gleam's truncated remainder is the Euclidean residue. -/
theorem reduce_eq (v : Int) : reduce v = v % p := by
  have hp := p_pos
  have h0 := Int.emod_nonneg v (Int.ne_of_gt hp)
  have h1 := Int.emod_lt_of_pos v hp
  have hk : Int.tmod v p = v % p ∨ Int.tmod v p = v % p - p := by
    rw [Int.tmod_eq_emod]
    split
    · left; simp
    · right; rw [Int.natAbs_of_nonneg (Int.le_of_lt hp)]
  have ha : 0 ≤ Int.tmod v p + p := by rcases hk with h | h <;> omega
  unfold reduce
  rw [Int.tmod_eq_emod, ifT (Or.inl ha)]
  rcases hk with h | h <;> rw [h] <;> simp

theorem reduce_range (v : Int) : 0 ≤ reduce v ∧ reduce v < p := by
  rw [reduce_eq]
  exact ⟨Int.emod_nonneg v (Int.ne_of_gt p_pos), Int.emod_lt_of_pos v p_pos⟩

/-- **Every output is a reduced field element**, in `[0, p)`. -/
theorem mapToCurve_range (r : Int) : 0 ≤ mapToCurve r ∧ mapToCurve r < p := by
  unfold mapToCurve multiply
  simp only []
  repeat' split
  all_goals exact reduce_range _

/-- The map sees its input only through the reduced square. -/
theorem square_eq (r : Int) : multiply (reduce r) (reduce r) = r * r % p := by
  unfold multiply
  rw [reduce_eq, reduce_eq, ← Int.mul_emod]

theorem mapToCurve_square {r s : Int} (h : r * r % p = s * s % p) : mapToCurve r = mapToCurve s := by
  unfold mapToCurve
  simp only []
  rw [square_eq, square_eq, h]

/-- **`r` and `p - r` map to one point.** -/
theorem mapToCurve_neg (r : Int) : mapToCurve (p - r) = mapToCurve r := by
  apply mapToCurve_square
  have : (p - r) * (p - r) = r * r + p * (p - 2 * r) := by grind
  rw [this, Int.add_mul_emod_self_left]

/-- **The input is read modulo p**: `r` and `r + p` map to one point. -/
theorem mapToCurve_periodic (r : Int) : mapToCurve (r + p) = mapToCurve r := by
  apply mapToCurve_square
  have : (r + p) * (r + p) = r * r + p * (2 * r + p) := by grind
  rw [this, Int.add_mul_emod_self_left]

end Pondline.Elligator2
