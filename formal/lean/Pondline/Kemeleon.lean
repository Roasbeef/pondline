import Pondline.Bytes

/-
A transcription of `Kemeleon.EncodeEk` and `DecodeEk` as
`packages/core/src/core/crypto/kemeleon.gleam` implements them at t = 132
for ML-KEM-1024, with the theorems OQUAKE's use of it rests on.

An encapsulation key is four 384-byte polynomials in FIPS 203's ByteEncode_12
form and a 32-byte seed. Each polynomial's 256 coefficients are read as the
digits of one integer in base 3329 (`accumulate`), a multiple of 3329^256 is
added (`vectorEncode`), and the sum is written as 391 little-endian bytes.
Decoding reads those bytes back, reduces modulo 3329^256 and peels the 256
digits off again (`vectorDecode`).

The randomness is modelled as the list of non-negative draws
`randomness.draws()` returns: `randomness` and `randomness_from_multiples`
both produce four of them, and `vector_encode` reduces each modulo the size of
its polynomial's range. The theorems quantify over every draw, so they cover
both constructors.

The range of multiples is one smaller than the Kemeleon draft's at a single
polynomial value. The draft's inclusive bound, `draftRange`, admits for the
value `2^3128 mod 3329^256` a multiple whose sum is exactly `2^3128`, which
391 bytes cannot hold (`draft_bound_overflows`); the Gleam, and so `range`,
excludes it, and every other value has the draft's range
(`range_eq_draftRange`). With that, every key round-trips (`round_trip`) and
the encoding is a bijection onto 391-byte strings (`encoding_bijective`).

The proofs keep `span` (3329^256) and `ceiling` (2^3128) symbolic and appeal to
the kernel's big-number arithmetic only for the few facts about the constants
themselves (`span_lt_ceiling`, `vector_bits_tight`, `ceiling_eq`).
-/

namespace Pondline.Kemeleon

open Pondline

/-! ## The constants (`kemeleon.gleam`) -/

/-- `kemeleon.modulus`, ML-KEM's q. -/
def q : Nat := 3329

/-- `kemeleon.coefficients_per_polynomial`, n. -/
def coefficients : Nat := 256

/-- `kemeleon.vector_bits`, b. -/
def vectorBits : Nat := 2996

/-- `kemeleon.statistical_distance`, t. -/
def statisticalDistance : Nat := 132

/-- `kemeleon.encoded_polynomial_bytes`. -/
def encodedPolynomialBytes : Nat := 391

/-- `kemeleon`'s private `polynomial_bytes`, ByteEncode_12 of 256 coefficients. -/
def polynomialBytes : Nat := 384

/-- `kemeleon.seed_bytes`. -/
def seedBytes : Nat := 32

/-- `kemeleon.encapsulation_key_bytes`. -/
def encapsulationKeyBytes : Nat := 1568

/-- `kemeleon.encoded_key_bytes`. -/
def encodedKeyBytes : Nat := 1596

/-- `polynomial_span()`: 3329^256. -/
def span : Nat := q ^ coefficients

/-- `ceiling` in `vector_encode`: `1 << (vector_bits + statistical_distance)`. -/
def ceiling : Nat := 2 ^ (vectorBits + statisticalDistance)

/-! ## Little-endian bytes -/

/-- The number a little-endian byte string spells: `<<v:little-size(8n)>>`
read as a pattern. -/
def valLE (l : Bytes) : Nat := valBE l.reverse

/-- `<<v:little-size(8 * n)>>`: the low `8 * n` bits of `v`, little-endian. -/
def writeLE (n v : Nat) : Bytes := (writeBE n v).reverse

/-! ## Encoding (`kemeleon.encode`) -/

/-- `read_coefficients`: ByteDecode_12 with the modulus check, three bytes to
two coefficients, collected in reverse (highest index first). -/
def readCoefficients : Bytes → List Nat → Option (List Nat)
  | low :: middle :: high :: rest, reversed =>
    let first := low + 256 * (middle % 16)
    let second := middle / 16 + 16 * high
    if first < q ∧ second < q then readCoefficients rest (second :: first :: reversed)
    else none
  | [], reversed => some reversed
  | _, _ => none

/-- `accumulate`: the coefficients as `sum a[j] * 3329^j`, by Horner's rule
over the reversed list. -/
def accumulate (polynomial : Bytes) : Option Nat :=
  (readCoefficients polynomial []).map (List.foldl (fun value c => value * q + c) 0)

/-- The size of the range of multiples `vector_encode` reduces a draw into:
`(ceiling - 1 - value) / span + 1`. (`value < span < ceiling` for every value
`accumulate` returns, so the natural subtraction does not truncate.) -/
def range (value : Nat) : Nat := (ceiling - 1 - value) / span + 1

/-- The integer `vector_encode` writes, before it is cut to 3128 bits. -/
def encodedValue (value draw : Nat) : Nat := value + draw % range value * span

/-- `vector_encode`: `<<encoded:little-size(3128)>>`. -/
def vectorEncode (value draw : Nat) : Bytes := writeLE encodedPolynomialBytes (encodedValue value draw)

/-- `encode_polynomials`: one draw per 384-byte polynomial, then exactly the
seed. -/
def encodePolynomials : Bytes → List Nat → Bytes → Option Bytes
  | key, draw :: draws, encoded =>
    if polynomialBytes ≤ key.length then
      (accumulate (key.take polynomialBytes)).bind fun value =>
        encodePolynomials (key.drop polynomialBytes) draws (encoded ++ vectorEncode value draw)
    else none
  | key, [], encoded => if key.length = seedBytes then some (encoded ++ key) else none

/-- `kemeleon.encode`, with the randomness as its draws. -/
def encode (key : Bytes) (draws : List Nat) : Option Bytes :=
  if key.length ≠ encapsulationKeyBytes then none else encodePolynomials key draws []

/-! ## Decoding (`kemeleon.decode`) -/

/-- `write_coefficients`: two base-3329 digits at a time, three bytes per
pair. -/
def writeCoefficients : Nat → Nat → Bytes → Bytes
  | _, 0, bytes => bytes
  | value, pairs + 1, bytes =>
    let first := value % q
    let second := value / q % q
    let low := first % 256
    let middle := first / 256 + 16 * (second % 16)
    let high := second / 16
    writeCoefficients (value / q / q) pairs (bytes ++ [low, middle, high])

/-- `vector_decode`. -/
def vectorDecode (value : Nat) : Bytes :=
  writeCoefficients (value % span) (coefficients / 2) []

/-- `decode_polynomials`. -/
def decodePolynomials : Bytes → Nat → Bytes → Option Bytes
  | encoded, remaining + 1, key =>
    if encodedPolynomialBytes ≤ encoded.length then
      decodePolynomials (encoded.drop encodedPolynomialBytes) remaining
        (key ++ vectorDecode (valLE (encoded.take encodedPolynomialBytes)))
    else none
  | encoded, 0, key => if encoded.length = seedBytes then some (key ++ encoded) else none

/-- `kemeleon.decode`. -/
def decode (encoded : Bytes) : Option Bytes :=
  if encoded.length ≠ encodedKeyBytes then none else decodePolynomials encoded 4 []

/-! ## Proof vocabulary

`coefficientsOf` is `read_coefficients` read front to back, and `horner` is
the integer a coefficient list spells, lowest digit first. Neither is in the
Gleam; they name what `accumulate` computes so the theorems can say it.
-/

/-- The coefficients ByteDecode_12 reads, in index order, or `none` when one
is not below q or the length is not a multiple of three. -/
def coefficientsOf : Bytes → Option (List Nat)
  | low :: middle :: high :: rest =>
    if low + 256 * (middle % 16) < q ∧ middle / 16 + 16 * high < q then
      (coefficientsOf rest).map fun cs => (low + 256 * (middle % 16)) :: (middle / 16 + 16 * high) :: cs
    else none
  | [] => some []
  | _ => none

/-- `sum cs[j] * q^j`. -/
def horner : List Nat → Nat
  | [] => 0
  | c :: cs => c + q * horner cs

/-- A polynomial in ByteEncode_12 form with every coefficient below q: what
`encode` accepts for each of the four. -/
def PolyValid (p : Bytes) : Prop :=
  p.length = polynomialBytes ∧ Bytes.Valid p ∧ (coefficientsOf p).isSome

/-- Not the Gleam: the range `draft-irtf-cfrg-kemeleon-02`'s `VectorEncode`
gives, `[0, floor((2^(b+t) - r) / q^n)]`, as a count. Stated only to record
how it differs from `range`. -/
def draftRange (value : Nat) : Nat := (ceiling - value) / span + 1

/-! ## Facts about the constants, decided by the kernel's big numbers -/

theorem span_pos : 0 < span := Nat.pow_pos (by decide)

theorem span_lt_ceiling : span < ceiling := by decide +kernel

theorem ceiling_eq : ceiling = 256 ^ encodedPolynomialBytes := by decide +kernel

/-- **`vector_bits` is ⌈256 · log₂ 3329⌉**: 3329^256 needs exactly 2996 bits. -/
theorem vector_bits_tight : 2 ^ (vectorBits - 1) ≤ span ∧ span < 2 ^ vectorBits := by
  decide +kernel

/-- **391 bytes are exactly `b + t` bits.** -/
theorem encoded_width : 8 * encodedPolynomialBytes = vectorBits + statisticalDistance ∧
    4 * encodedPolynomialBytes + seedBytes = encodedKeyBytes ∧
    4 * polynomialBytes + seedBytes = encapsulationKeyBytes := ⟨rfl, rfl, rfl⟩

theorem span_eq : span = q ^ coefficients := rfl

/- The proofs below treat the two big constants as opaque numbers; only the
facts above look inside them, and the kernel checks those. -/
attribute [irreducible] span ceiling

/-! ## Bytes, little-endian -/

@[simp] theorem length_writeLE (n v : Nat) : (writeLE n v).length = n := by
  simp [writeLE]

theorem valLE_writeLE (n v : Nat) : valLE (writeLE n v) = v % 256 ^ n := by
  simp [valLE, writeLE, valBE_writeBE]

theorem writeBE_zero (n : Nat) : writeBE n 0 = List.replicate n 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simp [writeBE, ih, List.replicate_succ]

theorem valBE_replicate_zero (n : Nat) : valBE (List.replicate n 0) = 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simp [List.replicate_succ, valBE, ih]

/-! ## Reading coefficients -/

/-- `read_coefficients` is `coefficientsOf` reversed onto its accumulator. -/
theorem readCoefficients_eq (p acc : Bytes) :
    readCoefficients p acc = (coefficientsOf p).map (fun cs => cs.reverse ++ acc) := by
  induction p, acc using readCoefficients.induct with
  | case1 low middle high rest reversed first second h ih =>
    simp only [readCoefficients, coefficientsOf]
    simp only [first, second] at h ih
    rw [ifT h, ifT h, ih, Option.map_map]
    cases coefficientsOf rest <;> simp
  | case2 low middle high rest reversed first second h =>
    simp only [readCoefficients, coefficientsOf]
    simp only [first, second] at h
    rw [ifF h, ifF h]; rfl
  | case3 reversed => simp [readCoefficients, coefficientsOf]
  | case4 l reversed h1 h2 =>
    match l, h1, h2 with
    | [_], _, _ => simp [readCoefficients, coefficientsOf]
    | [_, _], _, _ => simp [readCoefficients, coefficientsOf]
    | [], _, h => exact (h rfl).elim
    | _ :: _ :: _ :: _, h, _ => exact (h _ _ _ _ rfl).elim

theorem foldl_reverse_horner (a : Nat) (cs : List Nat) :
    List.foldl (fun value c => value * q + c) a cs.reverse = a * q ^ cs.length + horner cs := by
  rw [List.foldl_reverse]
  induction cs with
  | nil => simp [horner]
  | cons c cs ih =>
    simp only [List.foldr_cons, ih, horner, List.length_cons, Nat.pow_succ]
    grind

/-- **`accumulate` is the base-q integer of the coefficients.** -/
theorem accumulate_eq (p : Bytes) : accumulate p = (coefficientsOf p).map horner := by
  unfold accumulate
  rw [readCoefficients_eq, Option.map_map]
  congr 1
  funext cs
  simp only [Function.comp, List.append_nil]
  rw [foldl_reverse_horner]
  simp

theorem coefficientsOf_spec {p : Bytes} {cs : List Nat} (h : coefficientsOf p = some cs) :
    (∀ c ∈ cs, c < q) ∧ cs.length = 2 * (p.length / 3) ∧ p.length % 3 = 0 := by
  induction p using coefficientsOf.induct generalizing cs with
  | case1 low middle high rest hc ih =>
    simp only [coefficientsOf, ifT hc] at h
    cases hr : coefficientsOf rest with
    | none => simp [hr] at h
    | some cs' =>
      simp only [hr, Option.map_some, Option.some.injEq] at h
      subst h
      obtain ⟨h1, h2, h3⟩ := ih hr
      refine ⟨?_, ?_, ?_⟩
      · intro c hc'
        simp only [List.mem_cons] at hc'
        rcases hc' with rfl | rfl | hc'
        · exact hc.1
        · exact hc.2
        · exact h1 c hc'
      · simp only [List.length_cons]; omega
      · simp only [List.length_cons]; omega
  | case2 low middle high rest hc =>
    simp [coefficientsOf, ifF hc] at h
  | case3 => simp [coefficientsOf] at h; subst h; simp
  | case4 l h1 h2 =>
    match l, h1, h2 with
    | [_], _, _ => simp [coefficientsOf] at h
    | [_, _], _, _ => simp [coefficientsOf] at h
    | [], _, h => exact (h rfl).elim
    | _ :: _ :: _ :: _, h, _ => exact (h _ _ _ _ rfl).elim

theorem horner_lt {cs : List Nat} (h : ∀ c ∈ cs, c < q) : horner cs < q ^ cs.length := by
  induction cs with
  | nil => simp [horner]
  | cons c cs ih =>
    have hc := h c (by simp)
    have ht := ih (fun d hd => h d (by simp [hd]))
    simp only [horner, List.length_cons, Nat.pow_succ]
    have : q * horner cs + q ≤ q * q ^ cs.length := by
      rw [← Nat.mul_succ]; exact Nat.mul_le_mul_left _ ht
    rw [Nat.mul_comm (q ^ cs.length)]
    omega

/-! ## Writing coefficients -/

theorem writeCoefficients_append (v k : Nat) (pre : Bytes) :
    writeCoefficients v k pre = pre ++ writeCoefficients v k [] := by
  induction k generalizing v pre with
  | zero => simp [writeCoefficients]
  | succ k ih =>
    simp only [writeCoefficients]
    rw [ih _ (pre ++ _), ih _ ([] ++ _)]
    simp

theorem writeCoefficients_succ (v k : Nat) :
    writeCoefficients v (k + 1) [] =
      [v % q % 256, v % q / 256 + 16 * (v / q % q % 16), v / q % q / 16] ++
        writeCoefficients (v / q / q) k [] := by
  simp only [writeCoefficients]
  rw [writeCoefficients_append]
  rfl

/-- Writing back what was read: ByteEncode_12 inverts ByteDecode_12 on bytes. -/
theorem writeCoefficients_horner {p : Bytes} {cs : List Nat} (hv : Bytes.Valid p)
    (h : coefficientsOf p = some cs) : writeCoefficients (horner cs) (p.length / 3) [] = p := by
  induction p using coefficientsOf.induct generalizing cs with
  | case1 low middle high rest hc ih =>
    simp only [coefficientsOf, ifT hc] at h
    cases hr : coefficientsOf rest with
    | none => simp [hr] at h
    | some cs' =>
      simp only [hr, Option.map_some, Option.some.injEq] at h
      subst h
      simp only [Bytes.valid_cons] at hv
      obtain ⟨hl, hm, hh, hv⟩ := hv
      have hlen : (low :: middle :: high :: rest).length / 3 = rest.length / 3 + 1 := by
        simp only [List.length_cons]; omega
      rw [hlen, writeCoefficients_succ]
      have hq : q = 3329 := rfl
      simp only [horner]
      rw [hq] at hc ⊢
      have e1 : (low + 256 * (middle % 16) + 3329 * (middle / 16 + 16 * high + 3329 * horner cs')) % 3329 =
          low + 256 * (middle % 16) := by omega
      have e2 : (low + 256 * (middle % 16) + 3329 * (middle / 16 + 16 * high + 3329 * horner cs')) / 3329 =
          middle / 16 + 16 * high + 3329 * horner cs' := by omega
      rw [e1, e2]
      have e3 : (middle / 16 + 16 * high + 3329 * horner cs') % 3329 = middle / 16 + 16 * high := by omega
      have e4 : (middle / 16 + 16 * high + 3329 * horner cs') / 3329 = horner cs' := by omega
      rw [e3, e4, ih hv hr]
      simp only [List.cons_append, List.nil_append, List.cons.injEq]
      exact ⟨by omega, by omega, by omega, trivial⟩
  | case2 low middle high rest hc =>
    simp [coefficientsOf, ifF hc] at h
  | case3 => simp [coefficientsOf] at h; subst h; rfl
  | case4 l h1 h2 =>
    match l, h1, h2 with
    | [_], _, _ => simp [coefficientsOf] at h
    | [_, _], _, _ => simp [coefficientsOf] at h
    | [], _, h => exact (h rfl).elim
    | _ :: _ :: _ :: _, h, _ => exact (h _ _ _ _ rfl).elim

/-- Whatever number is written, the bytes are a valid polynomial whose
coefficients are its lowest `2k` base-q digits. -/
theorem writeCoefficients_spec (v k : Nat) :
    (writeCoefficients v k []).length = 3 * k ∧ Bytes.Valid (writeCoefficients v k []) ∧
      ∃ cs, coefficientsOf (writeCoefficients v k []) = some cs ∧ horner cs = v % q ^ (2 * k) := by
  induction k generalizing v with
  | zero => simp [writeCoefficients, Bytes.valid_nil, coefficientsOf, horner, Nat.mod_one]
  | succ k ih =>
    obtain ⟨ih1, ih2, cs, ih3, ih4⟩ := ih (v / q / q)
    rw [writeCoefficients_succ]
    have hf : v % q < q := Nat.mod_lt _ (by decide)
    have hs : v / q % q < q := Nat.mod_lt _ (by decide)
    have hpow : q ^ (2 * (k + 1)) = q * (q * q ^ (2 * k)) := by
      rw [show 2 * (k + 1) = 2 * k + 1 + 1 by omega, Nat.pow_succ, Nat.pow_succ]; grind
    have hmod : v % q ^ (2 * (k + 1)) = v % q + q * (v / q % q + q * (v / q / q % q ^ (2 * k))) := by
      rw [hpow, Nat.mod_mul, Nat.mod_mul]
    rw [hmod, ← ih4]
    generalize v % q = f at hf ⊢
    generalize v / q % q = s at hs ⊢
    have hf' : f < 3329 := hf
    have hs' : s < 3329 := hs
    refine ⟨?_, ?_, ?_⟩
    · simp [ih1]; omega
    · simp only [List.cons_append, List.nil_append, Bytes.valid_cons]
      exact ⟨by omega, by omega, by omega, ih2⟩
    · refine ⟨f :: s :: cs, ?_, ?_⟩
      · simp only [List.cons_append, List.nil_append, coefficientsOf]
        have c1 : f % 256 + 256 * ((f / 256 + 16 * (s % 16)) % 16) = f := by omega
        have c2 : (f / 256 + 16 * (s % 16)) / 16 + 16 * (s / 16) = s := by omega
        rw [c1, c2, ifT ⟨hf, hs⟩]
        rw [ih3]; rfl
      · rfl

/-! ## The range of multiples (`vector_encode`) -/

theorem multiple_le (x d : Nat) : d % range x ≤ (ceiling - 1 - x) / span :=
  Nat.lt_succ_iff.mp (Nat.mod_lt _ (Nat.succ_pos _))

/-- `C - C % S` is a whole number of spans, `C / S` of them. -/
theorem ceiling_sub_mod : ceiling - ceiling % span = span * (ceiling / span) := by
  have := Nat.div_add_mod ceiling span
  omega

/-- **The sum always fits 391 bytes**: for every value below `3329^256` and
every draw, it is below `2^3128`. -/
theorem encodedValue_lt {x : Nat} (hx : x < span) (d : Nat) : encodedValue x d < ceiling := by
  have hC := span_lt_ceiling
  have h1 := Nat.mul_le_mul_right span (multiple_le x d)
  have h2 := Nat.div_mul_le_self (ceiling - 1 - x) span
  unfold encodedValue
  omega

/-- **The draft's bound overflows at one value** (a statement about the
draft's formula, not the code): for `x* = 2^3128 mod 3329^256` its largest
multiple makes the sum exactly `2^3128`, and `x*` is not zero, so the
391-byte truncation would decode to a different polynomial. -/
theorem draft_bound_overflows :
    ceiling % span < span ∧ ceiling % span ≠ 0 ∧
      ceiling % span + (draftRange (ceiling % span) - 1) * span = ceiling := by
  have hS := span_pos
  refine ⟨Nat.mod_lt _ hS, by decide +kernel, ?_⟩
  unfold draftRange
  rw [Nat.add_sub_cancel, ceiling_sub_mod, Nat.mul_div_cancel_left _ hS, Nat.mul_comm]
  have := Nat.div_add_mod ceiling span
  omega

/-- **Everywhere else the code's range is the draft's**, so any multiple in
the draft's range for another value, as every draft vector's is, encodes
identically. At `x*` the code's range is one smaller. -/
theorem range_eq_draftRange {x : Nat} (hx : x < span) :
    (x ≠ ceiling % span → range x = draftRange x) ∧
      range (ceiling % span) + 1 = draftRange (ceiling % span) := by
  have hS := span_pos
  have hC := span_lt_ceiling
  constructor
  · intro hne
    unfold range draftRange
    congr 1
    have hdm := Nat.div_add_mod (ceiling - x) span
    have hr := Nat.mod_lt (ceiling - x) hS
    have hr0 : (ceiling - x) % span ≠ 0 := by
      intro h0
      apply hne
      have hc : ceiling = x + span * ((ceiling - x) / span) := by omega
      rw [hc, Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hx]
    apply Nat.div_eq_of_lt_le
    · rw [Nat.mul_comm]; omega
    · rw [Nat.succ_mul, Nat.mul_comm]; omega
  · unfold range draftRange
    have hA := ceiling_sub_mod
    rw [hA, Nat.mul_div_cancel_left _ hS]
    have hpos : 0 < ceiling / span := Nat.div_pos (Nat.le_of_lt hC) hS
    have hK : (ceiling - 1 - ceiling % span) / span = ceiling / span - 1 := by
      have e : ceiling - 1 - ceiling % span = span * (ceiling / span) - 1 := by omega
      rw [e]
      apply Nat.div_eq_of_lt_le
      · rw [Nat.sub_one_mul]
        have := Nat.le_mul_of_pos_right span hpos
        have hc : ceiling / span * span = span * (ceiling / span) := Nat.mul_comm _ _
        omega
      · rw [Nat.sub_add_cancel hpos]
        have := Nat.le_mul_of_pos_right span hpos
        have hc : ceiling / span * span = span * (ceiling / span) := Nat.mul_comm _ _
        omega
    rw [hK]
    omega

/-! ## One polynomial -/

theorem accumulate_some {p : Bytes} (hp : PolyValid p) :
    ∃ cs, coefficientsOf p = some cs ∧ accumulate p = some (horner cs) := by
  obtain ⟨_, _, hs⟩ := hp
  obtain ⟨cs, hcs⟩ := Option.isSome_iff_exists.mp hs
  exact ⟨cs, hcs, by rw [accumulate_eq, hcs]; rfl⟩

/-- A valid polynomial's value is below `3329^256`. -/
theorem accumulate_lt {p : Bytes} {x : Nat} (hp : PolyValid p) (hx : accumulate p = some x) :
    x < span := by
  obtain ⟨cs, hcs, hacc⟩ := accumulate_some hp
  rw [hacc, Option.some.injEq] at hx
  subst hx
  obtain ⟨hlt, hlen, _⟩ := coefficientsOf_spec hcs
  have : cs.length = coefficients := by rw [hlen, hp.1]; rfl
  have := horner_lt hlt
  rwa [‹cs.length = coefficients›, ← span_eq] at this

/-- **One polynomial round-trips**, under every draw. -/
theorem vector_round_trip {p : Bytes} {x d : Nat} (hp : PolyValid p) (hx : accumulate p = some x) :
    vectorDecode (valLE (vectorEncode x d)) = p := by
  have hxs := accumulate_lt hp hx
  have hlt : encodedValue x d < ceiling := encodedValue_lt hxs d
  obtain ⟨cs, hcs, hacc⟩ := accumulate_some hp
  rw [hacc, Option.some.injEq] at hx
  subst hx
  unfold vectorDecode vectorEncode
  rw [valLE_writeLE, ← ceiling_eq, Nat.mod_eq_of_lt hlt]
  unfold encodedValue
  rw [Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hxs]
  have h384 : p.length / 3 = coefficients / 2 := by rw [hp.1]; rfl
  rw [← h384]
  exact writeCoefficients_horner hp.2.1 hcs

/-- Whatever 391 bytes hold, they decode to a valid polynomial. -/
theorem vectorDecode_valid (v : Nat) : PolyValid (vectorDecode v) := by
  obtain ⟨h1, h2, cs, h3, _⟩ := writeCoefficients_spec (v % span) (coefficients / 2)
  exact ⟨h1, h2, by unfold vectorDecode; rw [h3]; rfl⟩

/-- The value `accumulate` reads from a decoded polynomial is the input
reduced modulo `3329^256`. -/
theorem accumulate_vectorDecode (v : Nat) : accumulate (vectorDecode v) = some (v % span) := by
  obtain ⟨_, _, cs, h3, h4⟩ := writeCoefficients_spec (v % span) (coefficients / 2)
  unfold vectorDecode
  rw [accumulate_eq, h3]
  simp only [Option.map_some, Option.some.injEq]
  rw [h4, congrArg (q ^ ·) (by decide : 2 * (coefficients / 2) = coefficients), ← span_eq]
  exact Nat.mod_mod _ _

/-! ## The whole key -/

theorem encodePolynomials_step {p rest acc : Bytes} {d x : Nat} {ds : List Nat}
    (hl : p.length = polynomialBytes) (hx : accumulate p = some x) :
    encodePolynomials (p ++ rest) (d :: ds) acc =
      encodePolynomials rest ds (acc ++ vectorEncode x d) := by
  conv => lhs; unfold encodePolynomials
  rw [ifT (by simp [hl]), List.take_left' hl, List.drop_left' hl, hx]
  rfl

theorem encodePolynomials_seed {rho acc : Bytes} (h : rho.length = seedBytes) :
    encodePolynomials rho [] acc = some (acc ++ rho) := by
  unfold encodePolynomials
  rw [ifT h]

theorem decodePolynomials_step (e key : Bytes) (n : Nat) (hl : encodedPolynomialBytes ≤ e.length) :
    decodePolynomials e (n + 1) key =
      decodePolynomials (e.drop encodedPolynomialBytes) n
        (key ++ vectorDecode (valLE (e.take encodedPolynomialBytes))) := by
  conv => lhs; unfold decodePolynomials
  rw [ifT hl]

theorem decodePolynomials_seed {rho key : Bytes} (h : rho.length = seedBytes) :
    decodePolynomials rho 0 key = some (key ++ rho) := by
  unfold decodePolynomials
  rw [ifT h]

theorem length_vectorEncode (x d : Nat) : (vectorEncode x d).length = encodedPolynomialBytes := by
  simp [vectorEncode]

theorem decodePolynomials_append {c : Bytes} (rest key : Bytes) (n : Nat)
    (hl : c.length = encodedPolynomialBytes) :
    decodePolynomials (c ++ rest) (n + 1) key = decodePolynomials rest n (key ++ vectorDecode (valLE c)) := by
  rw [decodePolynomials_step _ _ _ (by simp [hl]), List.drop_left' hl, List.take_left' hl]

/-- `encode` on four valid polynomials and a seed, spelled out. -/
theorem encode_eq {p₁ p₂ p₃ p₄ rho : Bytes} {x₁ x₂ x₃ x₄ : Nat} (d₁ d₂ d₃ d₄ : Nat)
    (h₁ : p₁.length = polynomialBytes) (h₂ : p₂.length = polynomialBytes)
    (h₃ : p₃.length = polynomialBytes) (h₄ : p₄.length = polynomialBytes)
    (hr : rho.length = seedBytes)
    (a₁ : accumulate p₁ = some x₁) (a₂ : accumulate p₂ = some x₂)
    (a₃ : accumulate p₃ = some x₃) (a₄ : accumulate p₄ = some x₄) :
    encode (p₁ ++ p₂ ++ p₃ ++ p₄ ++ rho) [d₁, d₂, d₃, d₄] =
      some (vectorEncode x₁ d₁ ++ vectorEncode x₂ d₂ ++ vectorEncode x₃ d₃ ++
        vectorEncode x₄ d₄ ++ rho) := by
  unfold encode
  rw [ifF (by simp [h₁, h₂, h₃, h₄, hr, polynomialBytes, seedBytes, encapsulationKeyBytes])]
  simp only [List.append_assoc]
  rw [encodePolynomials_step h₁ a₁, encodePolynomials_step h₂ a₂, encodePolynomials_step h₃ a₃,
    encodePolynomials_step h₄ a₄, encodePolynomials_seed hr]
  simp

/-- **Round trip.** Four polynomials with every coefficient below 3329 and
any seed encode under any four draws, the result is `encoded_key_bytes`
long, and it decodes to the key. -/
theorem round_trip {p₁ p₂ p₃ p₄ rho : Bytes} {d₁ d₂ d₃ d₄ : Nat}
    (h₁ : PolyValid p₁) (h₂ : PolyValid p₂) (h₃ : PolyValid p₃) (h₄ : PolyValid p₄)
    (hr : rho.length = seedBytes) :
    ∃ e, encode (p₁ ++ p₂ ++ p₃ ++ p₄ ++ rho) [d₁, d₂, d₃, d₄] = some e ∧
      e.length = encodedKeyBytes ∧ decode e = some (p₁ ++ p₂ ++ p₃ ++ p₄ ++ rho) := by
  obtain ⟨_, _, a₁⟩ := accumulate_some h₁
  obtain ⟨_, _, a₂⟩ := accumulate_some h₂
  obtain ⟨_, _, a₃⟩ := accumulate_some h₃
  obtain ⟨_, _, a₄⟩ := accumulate_some h₄
  refine ⟨_, encode_eq d₁ d₂ d₃ d₄ h₁.1 h₂.1 h₃.1 h₄.1 hr a₁ a₂ a₃ a₄, ?_, ?_⟩
  · simp [hr, length_vectorEncode, encodedPolynomialBytes, seedBytes, encodedKeyBytes]
  · unfold decode
    rw [ifF (by simp [hr, length_vectorEncode, encodedPolynomialBytes, seedBytes, encodedKeyBytes])]
    simp only [List.append_assoc]
    rw [decodePolynomials_append _ _ _ (length_vectorEncode _ _), decodePolynomials_append _ _ _ (length_vectorEncode _ _),
      decodePolynomials_append _ _ _ (length_vectorEncode _ _), decodePolynomials_append _ _ _ (length_vectorEncode _ _),
      decodePolynomials_seed hr, vector_round_trip h₁ a₁, vector_round_trip h₂ a₂,
      vector_round_trip h₃ a₃, vector_round_trip h₄ a₄]
    simp

/-- **`decode` is total and always yields a key.** Every `encoded_key_bytes`
input decodes, to four polynomials whose every coefficient is below 3329
followed by the input's last 32 bytes unchanged. This is what makes a wrong
password's unmasking indistinguishable by its shape. -/
theorem decode_total {e : Bytes} (h : e.length = encodedKeyBytes) :
    ∃ p₁ p₂ p₃ p₄, PolyValid p₁ ∧ PolyValid p₂ ∧ PolyValid p₃ ∧ PolyValid p₄ ∧
      decode e = some (p₁ ++ p₂ ++ p₃ ++ p₄ ++ e.drop (4 * encodedPolynomialBytes)) := by
  unfold decode
  rw [ifF (by rw [h]; exact fun h => h rfl)]
  have hl : e.length = 1596 := h
  rw [decodePolynomials_step _ _ _ (by unfold encodedPolynomialBytes; omega)]
  rw [decodePolynomials_step _ _ _ (by simp [encodedPolynomialBytes]; omega)]
  rw [decodePolynomials_step _ _ _ (by simp [encodedPolynomialBytes]; omega)]
  rw [decodePolynomials_step _ _ _ (by simp [encodedPolynomialBytes]; omega)]
  rw [decodePolynomials_seed (by simp [encodedPolynomialBytes, seedBytes]; omega)]
  refine ⟨vectorDecode (valLE (e.take encodedPolynomialBytes)),
    vectorDecode (valLE ((e.drop encodedPolynomialBytes).take encodedPolynomialBytes)),
    vectorDecode (valLE (((e.drop encodedPolynomialBytes).drop encodedPolynomialBytes).take
      encodedPolynomialBytes)),
    vectorDecode (valLE ((((e.drop encodedPolynomialBytes).drop encodedPolynomialBytes).drop
      encodedPolynomialBytes).take encodedPolynomialBytes)),
    vectorDecode_valid _, vectorDecode_valid _, vectorDecode_valid _, vectorDecode_valid _, ?_⟩
  simp [List.drop_drop, encodedPolynomialBytes]

/-- **A decoded key passes `encode`'s modulus check**: whatever was decoded
is accepted by `encode`, under any four draws. -/
theorem decode_then_encode {e k : Bytes} (h : decode e = some k) (d₁ d₂ d₃ d₄ : Nat) :
    (encode k [d₁, d₂, d₃, d₄]).isSome := by
  have hl : e.length = encodedKeyBytes := by
    unfold decode at h
    by_cases hc : e.length = encodedKeyBytes
    · exact hc
    · rw [ifT hc] at h; cases h
  obtain ⟨p₁, p₂, p₃, p₄, h₁, h₂, h₃, h₄, hd⟩ := decode_total hl
  rw [h, Option.some.injEq] at hd
  subst hd
  obtain ⟨_, _, a₁⟩ := accumulate_some h₁
  obtain ⟨_, _, a₂⟩ := accumulate_some h₂
  obtain ⟨_, _, a₃⟩ := accumulate_some h₃
  obtain ⟨_, _, a₄⟩ := accumulate_some h₄
  rw [encode_eq d₁ d₂ d₃ d₄ h₁.1 h₂.1 h₃.1 h₄.1 (by simp [hl]; rfl) a₁ a₂ a₃ a₄]
  rfl

/-! ## Counting: what the statistical-distance claim reduces to -/

/-- **The encoding is injective** on values below `3329^256` and any
multiples. -/
theorem encoding_injective {x x' m m' : Nat} (hx : x < span) (hx' : x' < span)
    (h : x + m * span = x' + m' * span) : x = x' ∧ m = m' := by
  have e : x = x' := by
    have := congrArg (· % span) h
    simp only [Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hx, Nat.mod_eq_of_lt hx'] at this
    exact this
  subst e
  exact ⟨rfl, Nat.eq_of_mul_eq_mul_right span_pos (by omega)⟩

/-- **Its image is exactly `[0, 2^3128)`**: every integer below `2^3128` is
`x + m * 3329^256` for one value `x` and one multiple `m` in `x`'s range, and
no larger integer is. -/
theorem encoding_image (y : Nat) :
    (∃ x m, x < span ∧ m < range x ∧ y = x + m * span) ↔ y < ceiling := by
  have hS := span_pos
  constructor
  · intro ⟨x, m, hx, hm, hy⟩
    subst hy
    have h1 := Nat.mul_le_mul_right span (Nat.lt_succ_iff.mp hm)
    have h2 := Nat.div_mul_le_self (ceiling - 1 - x) span
    have := span_lt_ceiling
    omega
  · intro hy
    refine ⟨y % span, y / span, Nat.mod_lt _ hS, ?_, ?_⟩
    · unfold range
      apply Nat.lt_succ_of_le
      apply (Nat.le_div_iff_mul_le hS).mpr
      have := Nat.div_add_mod y span
      rw [Nat.mul_comm] at this
      omega
    · have := Nat.div_add_mod y span
      rw [Nat.mul_comm] at this
      omega

theorem writeLE_valLE {l : Bytes} (h : Bytes.Valid l) : writeLE l.length (valLE l) = l := by
  have hr : Bytes.Valid l.reverse := fun b hb => h b (List.mem_reverse.mp hb)
  have := writeBE_valBE hr
  rw [List.length_reverse] at this
  simp [writeLE, valLE, this]

/-- **The encoding is a bijection** between pairs of a value below
`3329^256` and a multiple in its range, and 391-byte strings: distinct
pairs write distinct strings, and every string is written by some pair. -/
theorem encoding_bijective :
    (∀ {x x' m m' : Nat}, x < span → x' < span → m < range x → m' < range x' →
        writeLE encodedPolynomialBytes (x + m * span) =
          writeLE encodedPolynomialBytes (x' + m' * span) → x = x' ∧ m = m') ∧
      (∀ b : Bytes, Bytes.Valid b → b.length = encodedPolynomialBytes →
        ∃ x m, x < span ∧ m < range x ∧ writeLE encodedPolynomialBytes (x + m * span) = b) := by
  constructor
  · intro x x' m m' hx hx' hm hm' h
    have hy := (encoding_image _).mp ⟨x, m, hx, hm, rfl⟩
    have hy' := (encoding_image _).mp ⟨x', m', hx', hm', rfl⟩
    have := congrArg valLE h
    rw [valLE_writeLE, valLE_writeLE, ← ceiling_eq, Nat.mod_eq_of_lt hy, Nat.mod_eq_of_lt hy'] at this
    exact encoding_injective hx hx' this
  · intro b hv hl
    have hlt : valLE b < ceiling := by
      rw [ceiling_eq, ← hl]
      have hr : Bytes.Valid b.reverse := fun c hc => hv c (List.mem_reverse.mp hc)
      have := valBE_lt hr
      rwa [List.length_reverse] at this
    obtain ⟨x, m, hx, hm, he⟩ := (encoding_image _).mpr hlt
    refine ⟨x, m, hx, hm, ?_⟩
    rw [← he, ← hl, writeLE_valLE hv]

/-- **Every value's range has `⌊2^3128 / 3329^256⌋` or one more multiples**,
and that count is at least `2^132`, so the number of encodings of two
values differs by at most one part in `2^132`. -/
theorem range_bounds {x : Nat} (hx : x < span) :
    ceiling / span ≤ range x ∧ range x ≤ ceiling / span + 1 := by
  have hS := span_pos
  unfold range
  constructor
  · have : ceiling / span - 1 ≤ (ceiling - 1 - x) / span := by
      apply (Nat.le_div_iff_mul_le hS).mpr
      rw [Nat.sub_one_mul]
      have := Nat.div_mul_le_self ceiling span
      omega
    omega
  · have := Nat.div_le_div_right (c := span) (Nat.le_trans (Nat.sub_le (ceiling - 1) x) (Nat.sub_le ceiling 1))
    omega

theorem range_large : 2 ^ statisticalDistance ≤ ceiling / span := by decide +kernel

end Pondline.Kemeleon
