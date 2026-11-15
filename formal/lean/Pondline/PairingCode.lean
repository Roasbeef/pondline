import Pondline.Bytes

/-
A transcription of how `pairing_code.generate` turns random bytes into word
indices: `bytes_drawn` and `read_indices`
(`packages/core/src/core/pairing_code.gleam`), with the theorem ADR-016's
"no modulo bias" rests on.

A Gleam bit string is modelled as its value and its width in bits; the
pattern `<<index:size(11), rest:bits>>` takes the top eleven bits as the
index and leaves the low `width - 11` bits as the rest. A draw shorter than
eleven bits reads as index zero and ends the string, as the Gleam does for a
suite that broke `random`'s contract.
-/

namespace Pondline.PairingCode

open Pondline

/-- `words.index_bits`. -/
def indexBits : Nat := 11

/-- `words.word_count`. -/
def wordCount : Nat := 2048

/-- `limits.pairing_code_words`. -/
def pairingCodeWords : Nat := 3

/-- `bytes_drawn`: enough whole bytes for every word's bits. -/
def bytesDrawn : Nat := (pairingCodeWords * indexBits + 7) / 8

/-- `read_indices` over a bit string of `width` bits holding `value`. -/
def readIndices : Nat → Nat → Nat → List Nat → List Nat
  | _, _, 0, collected => collected.reverse
  | value, width, remaining + 1, collected =>
    if indexBits ≤ width then
      readIndices (value % 2 ^ (width - indexBits)) (width - indexBits) remaining
        (value / 2 ^ (width - indexBits) :: collected)
    else readIndices 0 0 remaining (0 :: collected)

/-- The indices `generate` looks words up by, for the bytes the suite
returned. -/
def indices (bytes : Bytes) : List Nat :=
  readIndices (valBE bytes) (8 * bytes.length) pairingCodeWords []

/-! ## Three eleven-bit fields -/

/-- A 33-bit number as three eleven-bit fields, most significant first. -/
def split (v : Nat) : List Nat := [v / 2 ^ 22, v / 2 ^ 11 % 2 ^ 11, v % 2 ^ 11]

/-- Three fields back into one number. -/
def join (a b c : Nat) : Nat := a * 2 ^ 22 + b * 2 ^ 11 + c

theorem bytesDrawn_eq : bytesDrawn = 5 := rfl

/-- **`generate` reads the top 33 of the 40 bits it draws**, as three
eleven-bit fields. -/
theorem indices_eq {bytes : Bytes} (hv : Bytes.Valid bytes) (hl : bytes.length = bytesDrawn) :
    indices bytes = split (valBE bytes / 2 ^ 7) := by
  have hlt := valBE_lt hv
  rw [hl] at hlt
  unfold indices
  rw [hl]
  generalize valBE bytes = V at hlt ⊢
  rw [bytesDrawn_eq] at hlt ⊢
  simp [readIndices, indexBits, pairingCodeWords, split] at hlt ⊢
  refine ⟨by omega, by omega, by omega⟩

/-- **Every field is a word index**: below `word_count`, so `word_at` never
refuses one and `filter_map` drops nothing. -/
theorem split_lt {v : Nat} (h : v < 2 ^ (pairingCodeWords * indexBits)) :
    ∀ i ∈ split v, i < wordCount := by
  simp only [pairingCodeWords, indexBits] at h
  simp only [split, wordCount, List.mem_cons, List.not_mem_nil, or_false]
  omega

/-- **The fields are a bijection** between 33-bit numbers and triples of
indices: `split` lands in `[0, 2048)^3` (`split_lt`), `join` undoes
`split` ... -/
theorem join_split (v : Nat) : join (v / 2 ^ 22) (v / 2 ^ 11 % 2 ^ 11) (v % 2 ^ 11) = v := by
  simp only [join]
  omega

/-- ... and `split` undoes `join` on every triple of indices, so no triple is
reached twice and none is missed. -/
theorem split_join {a b c : Nat} (ha : a < wordCount) (hb : b < wordCount) (hc : c < wordCount) :
    split (join a b c) = [a, b, c] ∧ join a b c < 2 ^ (pairingCodeWords * indexBits) := by
  simp only [wordCount] at ha hb hc
  simp only [split, join, pairingCodeWords, indexBits, List.cons.injEq, Nat.reducePow, Nat.reduceMul]
  exact ⟨⟨by omega, by omega, by omega, trivial⟩, by omega⟩

/-- **No modulo bias.** For five drawn bytes and any triple of indices, the
draw yields that triple exactly when its top 33 bits spell it: exactly the
128 byte strings `join a b c * 128 + j`, `j < 128`, written big-endian. Every
triple has the same number of draws behind it. -/
theorem indices_preimage {bytes : Bytes} (hv : Bytes.Valid bytes) (hl : bytes.length = bytesDrawn)
    {a b c : Nat} (ha : a < wordCount) (hb : b < wordCount) (hc : c < wordCount) :
    indices bytes = [a, b, c] ↔
      ∃ j < 2 ^ 7, bytes = writeBE bytesDrawn (join a b c * 2 ^ 7 + j) := by
  rw [indices_eq hv hl]
  have hlt := valBE_lt hv
  have hw := writeBE_valBE hv
  rw [hl] at hlt hw
  rw [bytesDrawn_eq] at hlt hw ⊢
  generalize valBE bytes = V at hlt hw ⊢
  subst hw
  simp only [wordCount] at ha hb hc
  simp only [split, join, List.cons.injEq, Nat.reducePow] at hlt ⊢
  constructor
  · intro h
    refine ⟨V % 128, by omega, ?_⟩
    congr 1
    omega
  · intro ⟨j, hj, he⟩
    have hval : V = (a * 4194304 + b * 2048 + c) * 128 + j := by
      have := congrArg valBE he
      simp only [valBE_writeBE, Nat.reducePow] at this
      omega
    subst hval
    exact ⟨by omega, by omega, by omega, trivial⟩

end Pondline.PairingCode
