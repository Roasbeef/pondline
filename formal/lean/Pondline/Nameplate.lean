import Pondline.Bytes

/-
A transcription of `nameplate.from_int`, `parse` and `to_string`
(`packages/core/src/core/nameplate.gleam`), with the theorem ADR-016 asks of a
nameplate: one spelling per nameplate.

Text is modelled as its UTF-8 bytes, which is what `parse` reads
(`string.byte_size` and `<<text:utf8>>`). `to_string` is `int.to_string`
followed by `string.pad_start` with `"0"`; `decimal` transcribes the first
for a non-negative integer, and `padStart` the second for ASCII text, where a
grapheme is a byte.
-/

namespace Pondline.Nameplate

open Pondline

/-- `limits.nameplate_digits`. -/
def nameplateDigits : Nat := 6

/-- The bound `from_int` computes, `10^nameplate_digits`. -/
def bound : Nat := 10 ^ nameplateDigits

/-- `nameplate.from_int`: a value in `[0, 10^6)`. -/
def fromInt (value : Int) : Option Nat :=
  if value < 0 ∨ value ≥ bound then none else some value.toNat

/-- `read_digits`: ASCII digits, most significant first. -/
def readDigits : Bytes → Nat → Option Nat
  | [], accumulator => some accumulator
  | byte :: rest, accumulator =>
    if byte < 0x30 ∨ byte > 0x39 then none
    else readDigits rest (accumulator * 10 + byte - 0x30)

/-- `nameplate.parse`. -/
def parse (text : Bytes) : Option Nat :=
  if text.length ≠ nameplateDigits then none
  else (readDigits text 0).bind fun value => fromInt value

/-- `int.to_string` of a non-negative integer: its decimal digits in ASCII,
with no leading zero (zero itself is `"0"`). -/
def decimal (n : Nat) : Bytes :=
  if n < 10 then [0x30 + n] else decimal (n / 10) ++ [0x30 + n % 10]
termination_by n
decreasing_by omega

/-- `string.pad_start(text, to: width, with: "0")` on ASCII text. -/
def padStart (width : Nat) (text : Bytes) : Bytes :=
  List.replicate (width - text.length) 0x30 ++ text

/-- `nameplate.to_string`. -/
def toString (value : Nat) : Bytes := padStart nameplateDigits (decimal value)

/-! ## Proof vocabulary -/

/-- The `k` least significant decimal digits of `v`, in ASCII, most
significant first. -/
def writeDec : Nat → Nat → Bytes
  | 0, _ => []
  | k + 1, v => writeDec k (v / 10) ++ [0x30 + v % 10]

/-- Every byte is an ASCII digit. -/
def Digits (text : Bytes) : Prop := ∀ b ∈ text, 0x30 ≤ b ∧ b ≤ 0x39

/-- The number a digit string spells. -/
def valDec (text : Bytes) : Nat := text.foldl (fun acc b => acc * 10 + b - 0x30) 0

theorem writeDec_zero (k : Nat) : writeDec k 0 = List.replicate k 0x30 := by
  induction k with
  | zero => rfl
  | succ k ih =>
    simp only [writeDec, Nat.zero_div, Nat.zero_mod, ih]
    rw [List.replicate_succ']

@[simp] theorem length_writeDec (k v : Nat) : (writeDec k v).length = k := by
  induction k generalizing v with
  | zero => rfl
  | succ k ih => simp [writeDec, ih]

theorem digits_writeDec (k v : Nat) : Digits (writeDec k v) := by
  induction k generalizing v with
  | zero => intro b hb; simp [writeDec] at hb
  | succ k ih =>
    intro b hb
    simp only [writeDec, List.mem_append, List.mem_singleton] at hb
    rcases hb with hb | hb
    · exact ih _ b hb
    · have := Nat.mod_lt v (by decide : 10 > 0); omega

/-- `int.to_string` padded to `k` digits is the `k`-digit spelling, for a
number that has at most `k` digits. -/
theorem padStart_decimal (n k : Nat) (hk : 0 < k) (h : n < 10 ^ k) :
    padStart k (decimal n) = writeDec k n ∧ (decimal n).length ≤ k := by
  induction n using Nat.strongRecOn generalizing k with
  | ind n ih =>
    rw [decimal]
    by_cases hn : n < 10
    · rw [ifT hn]
      cases k with
      | zero => omega
      | succ k =>
        simp only [padStart, writeDec, List.length_singleton, Nat.div_eq_of_lt hn, writeDec_zero,
          Nat.mod_eq_of_lt hn]
        exact ⟨by simp, by omega⟩
    · rw [ifF hn]
      cases k with
      | zero => omega
      | succ k =>
        have hk' : n / 10 < 10 ^ k := by
          rw [Nat.pow_succ] at h
          exact (Nat.div_lt_iff_lt_mul (by decide)).mpr h
        have hk0 : 0 < k := by
          cases k with
          | zero => simp at hk'; omega
          | succ k => omega
        obtain ⟨ih1, ih2⟩ := ih (n / 10) (by omega) k hk0 hk'
        unfold padStart at ih1 ⊢
        simp only [writeDec, ← ih1, List.length_append, List.length_singleton, ← List.append_assoc]
        refine ⟨?_, by omega⟩
        rw [show k + 1 - ((decimal (n / 10)).length + 1) = k - (decimal (n / 10)).length by omega]

theorem readDigits_append (l₁ l₂ : Bytes) (acc : Nat) :
    readDigits (l₁ ++ l₂) acc = (readDigits l₁ acc).bind (readDigits l₂) := by
  induction l₁ generalizing acc with
  | nil => rfl
  | cons b l ih =>
    simp only [List.cons_append, readDigits]
    split
    · rfl
    · exact ih _

theorem readDigits_one {d : Nat} (acc : Nat) (h : 0x30 ≤ d ∧ d ≤ 0x39) :
    readDigits [d] acc = some (acc * 10 + d - 0x30) := by
  simp only [readDigits]
  rw [ifF (by omega)]

/-- Reading `k` written digits gives the number modulo `10^k`. -/
theorem readDigits_writeDec (k v acc : Nat) :
    readDigits (writeDec k v) acc = some (acc * 10 ^ k + v % 10 ^ k) := by
  induction k generalizing v acc with
  | zero => simp [writeDec, readDigits, Nat.mod_one]
  | succ k ih =>
    have hd := Nat.mod_lt v (by decide : 10 > 0)
    rw [writeDec, readDigits_append, ih, Option.bind_some, readDigits_one _ (by omega)]
    congr 1
    rw [Nat.pow_succ, Nat.mul_comm (10 ^ k) 10, Nat.mod_mul]
    have : (acc * 10 ^ k + v / 10 % 10 ^ k) * 10 = acc * (10 * 10 ^ k) + 10 * (v / 10 % 10 ^ k) := by
      grind
    omega

/-- A digit string is the `k`-digit spelling of the number it reads as. -/
theorem readDigits_digits (s : Bytes) (h : Digits s) :
    ∃ v, v < 10 ^ s.length ∧ writeDec s.length v = s ∧
      ∀ acc, readDigits s acc = some (acc * 10 ^ s.length + v) := by
  rw [← List.reverse_reverse s] at h ⊢
  generalize s.reverse = r at h ⊢
  induction r with
  | nil => exact ⟨0, by decide, rfl, fun acc => by simp [readDigits]⟩
  | cons d r ih =>
    rw [List.reverse_cons] at h ⊢
    generalize r.reverse = t at h ih ⊢
    have ht : Digits t := fun b hb => h b (by simp [hb])
    have hd : 0x30 ≤ d ∧ d ≤ 0x39 := h d (by simp)
    obtain ⟨v, hv, hw, hr⟩ := ih ht
    refine ⟨v * 10 + (d - 0x30), ?_, ?_, ?_⟩
    · simp only [List.length_append, List.length_singleton, Nat.pow_succ]; omega
    · simp only [List.length_append, List.length_singleton, writeDec]
      rw [show (v * 10 + (d - 0x30)) / 10 = v by omega, hw,
        show 0x30 + (v * 10 + (d - 0x30)) % 10 = d by omega]
    · intro acc
      rw [readDigits_append, hr, Option.bind_some, readDigits_one _ hd]
      simp only [List.length_append, List.length_singleton, Nat.pow_succ]
      congr 1
      have : (acc * 10 ^ t.length + v) * 10 = acc * (10 ^ t.length * 10) + v * 10 := by grind
      omega

/-- A byte that is not an ASCII digit is refused wherever it is. -/
theorem readDigits_none (s : Bytes) (h : ¬Digits s) (acc : Nat) : readDigits s acc = none := by
  induction s generalizing acc with
  | nil => exact absurd (fun b hb => by simp at hb) h
  | cons b l ih =>
    simp only [readDigits]
    by_cases hb : b < 0x30 ∨ b > 0x39
    · rw [ifT hb]
    · rw [ifF hb]
      apply ih
      intro hl
      apply h
      intro c hc
      simp only [List.mem_cons] at hc
      rcases hc with rfl | hc
      · omega
      · exact hl c hc

/-! ## The theorems -/

theorem toString_eq {n : Nat} (h : n < bound) : toString n = writeDec nameplateDigits n :=
  (padStart_decimal n nameplateDigits (by decide) h).1

/-- **`from_int` accepts exactly `[0, 10^nameplate_digits)`**, so every
nameplate has a value `to_string` can spell in `nameplate_digits` digits. -/
theorem fromInt_some_iff (v : Int) (n : Nat) : fromInt v = some n ↔ v = n ∧ n < bound := by
  unfold fromInt
  split
  · simp only [reduceCtorEq, false_iff, not_and]
    omega
  · simp only [Option.some.injEq]
    omega

/-- **`to_string` spells exactly `nameplate_digits` ASCII digits.** -/
theorem toString_digits {n : Nat} (h : n < bound) :
    (toString n).length = nameplateDigits ∧ Digits (toString n) := by
  rw [toString_eq h]
  exact ⟨length_writeDec _ _, digits_writeDec _ _⟩

/-- **`parse` reads back what `to_string` wrote.** -/
theorem parse_toString {n : Nat} (h : n < bound) : parse (toString n) = some n := by
  have hl := (toString_digits h).1
  unfold parse
  rw [ifF (by rw [hl]; exact fun h => h rfl), toString_eq h, readDigits_writeDec, Option.bind_some]
  unfold fromInt
  rw [ifF (by unfold bound at h ⊢; omega)]
  simp only [Nat.zero_mul, Nat.zero_add, Int.toNat_natCast]
  rw [Nat.mod_eq_of_lt (by exact h)]

/-- **`parse` accepts exactly the strings of `nameplate_digits` ASCII
digits**: no sign, no space, no shorter or longer spelling, and no
multi-byte character, whatever its byte count. -/
theorem parse_isSome_iff (s : Bytes) :
    (parse s).isSome ↔ s.length = nameplateDigits ∧ Digits s := by
  unfold parse
  by_cases hl : s.length = nameplateDigits
  · rw [ifF (fun h => h hl)]
    by_cases hd : Digits s
    · obtain ⟨v, hv, _, hr⟩ := readDigits_digits s hd
      rw [hr, Option.bind_some]
      unfold fromInt
      rw [hl] at hv
      rw [ifF (by unfold bound; omega)]
      simp [hl, hd]
    · rw [readDigits_none s hd]
      simp [hd]
  · rw [ifT hl]
    simp [hl]

/-- **One spelling per nameplate**: whatever `parse` accepts is the text
`to_string` writes for the value it returns. -/
theorem parse_canonical {s : Bytes} {n : Nat} (h : parse s = some n) :
    toString n = s ∧ n < bound := by
  have ⟨hl, hd⟩ := (parse_isSome_iff s).mp (by rw [h]; rfl)
  obtain ⟨v, hv, hw, hr⟩ := readDigits_digits s hd
  unfold parse at h
  rw [ifF (fun h => h hl), hr, Option.bind_some] at h
  unfold fromInt at h
  rw [hl] at hv hw
  rw [ifF (by unfold bound; omega)] at h
  simp only [Nat.zero_mul, Nat.zero_add, Int.toNat_natCast, Option.some.injEq] at h
  subst h
  exact ⟨by rw [toString_eq hv]; exact hw, hv⟩

end Pondline.Nameplate
