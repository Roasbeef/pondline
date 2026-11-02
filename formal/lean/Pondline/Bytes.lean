/-
Byte strings as the Gleam code holds them.

A Gleam `BitArray` that is a whole number of bytes is modelled as a list of
natural numbers, each below 256 (`Bytes.Valid`). The decoders are defined on
any list, as the Gleam decoders accept any bit array; the theorems that
reconstruct an input from what was decoded assume `Valid`, which every real
byte string satisfies.

`writeBE n v` is Gleam's `<<v:size(8 * n)>>`: the low `8 * n` bits of `v`,
big-endian. `valBE` reads a byte string back as a big-endian number, which is
what a pattern `<<value:size(8 * n), rest:bits>>` binds.
-/

namespace Pondline

/-- `if_pos`, under a name this toolchain does not deprecate. -/
theorem ifT {α : Sort _} {c : Prop} [Decidable c] (h : c) {a b : α} :
    (if c then a else b) = a := by simp [h]

/-- `if_neg`, likewise. -/
theorem ifF {α : Sort _} {c : Prop} [Decidable c] (h : ¬c) {a b : α} :
    (if c then a else b) = b := by simp [h]

/-- A whole-byte `BitArray`. -/
abbrev Bytes := List Nat

/-- Every element is a byte. -/
def Bytes.Valid (l : Bytes) : Prop := ∀ b ∈ l, b < 256

/-- The big-endian number a byte string spells. -/
def valBE : Bytes → Nat
  | [] => 0
  | b :: l => b * 256 ^ l.length + valBE l

/-- The low `8 * n` bits of `v`, as `n` big-endian bytes. -/
def writeBE : Nat → Nat → Bytes
  | 0, _ => []
  | n + 1, v => (v / 256 ^ n % 256) :: writeBE n v

theorem Bytes.valid_nil : Bytes.Valid [] := by simp [Bytes.Valid]

theorem Bytes.valid_cons {b : Nat} {l : Bytes} :
    Bytes.Valid (b :: l) ↔ b < 256 ∧ Bytes.Valid l := by
  simp [Bytes.Valid]

theorem Bytes.valid_append {l₁ l₂ : Bytes} :
    Bytes.Valid (l₁ ++ l₂) ↔ Bytes.Valid l₁ ∧ Bytes.Valid l₂ := by
  simp only [Bytes.Valid, List.mem_append]
  constructor
  · intro h; exact ⟨fun b hb => h b (Or.inl hb), fun b hb => h b (Or.inr hb)⟩
  · intro ⟨h₁, h₂⟩ b hb; rcases hb with hb | hb
    · exact h₁ b hb
    · exact h₂ b hb

theorem Bytes.valid_take {l : Bytes} (n : Nat) (h : Bytes.Valid l) :
    Bytes.Valid (l.take n) := fun b hb => h b (List.mem_of_mem_take hb)

theorem Bytes.valid_drop {l : Bytes} (n : Nat) (h : Bytes.Valid l) :
    Bytes.Valid (l.drop n) := fun b hb => h b (List.mem_of_mem_drop hb)

theorem Bytes.valid_replicate (n : Nat) : Bytes.Valid (List.replicate n 0) := by
  intro b hb; rw [List.eq_of_mem_replicate hb]; omega

@[simp] theorem length_writeBE (n v : Nat) : (writeBE n v).length = n := by
  induction n with
  | zero => rfl
  | succ n ih => simp [writeBE, ih]

theorem valid_writeBE (n v : Nat) : Bytes.Valid (writeBE n v) := by
  induction n with
  | zero => exact Bytes.valid_nil
  | succ n ih =>
    rw [writeBE, Bytes.valid_cons]
    exact ⟨Nat.mod_lt _ (by decide), ih⟩

/-- Reading back what was written gives the value modulo the width. -/
theorem valBE_writeBE (n v : Nat) : valBE (writeBE n v) = v % 256 ^ n := by
  induction n with
  | zero => simp [writeBE, valBE, Nat.mod_one]
  | succ n ih =>
    simp only [writeBE, valBE, length_writeBE, ih]
    rw [Nat.mod_pow_succ, Nat.mul_comm]
    omega

/-- A byte string's value is below the base raised to its length. -/
theorem valBE_lt {l : Bytes} (h : Bytes.Valid l) : valBE l < 256 ^ l.length := by
  induction l with
  | nil => simp [valBE]
  | cons b t ih =>
    rw [Bytes.valid_cons] at h
    have ht := ih h.2
    have hb : b + 1 ≤ 256 := h.1
    simp only [valBE, List.length_cons]
    calc b * 256 ^ t.length + valBE t
        < b * 256 ^ t.length + 256 ^ t.length := by omega
      _ = (b + 1) * 256 ^ t.length := by rw [Nat.succ_mul]
      _ ≤ 256 * 256 ^ t.length := Nat.mul_le_mul_right _ hb
      _ = 256 ^ (t.length + 1) := by rw [Nat.pow_succ, Nat.mul_comm]

/-- Only the low `8 * n` bits reach the output. -/
theorem writeBE_add_mul (n k x : Nat) : writeBE n (k * 256 ^ n + x) = writeBE n x := by
  induction n generalizing k with
  | zero => rfl
  | succ n ih =>
    have hpos : 0 < 256 ^ n := Nat.pow_pos (by decide)
    have hrw : k * 256 ^ (n + 1) + x = (k * 256) * 256 ^ n + x := by
      rw [Nat.pow_succ, Nat.mul_comm (256 ^ n) 256, Nat.mul_assoc]
    simp only [writeBE]
    rw [hrw, ih (k * 256)]
    congr 1
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hpos, Nat.add_mul_mod_self_right]

/-- Writing a byte string's own value at its own width gives it back. -/
theorem writeBE_valBE {l : Bytes} (h : Bytes.Valid l) : writeBE l.length (valBE l) = l := by
  induction l with
  | nil => rfl
  | cons b t ih =>
    rw [Bytes.valid_cons] at h
    have ht := valBE_lt h.2
    have hpos : 0 < 256 ^ t.length := Nat.pow_pos (by decide)
    simp only [List.length_cons, writeBE, valBE]
    rw [writeBE_add_mul, ih h.2]
    congr 1
    rw [Nat.add_comm, Nat.add_mul_div_right _ _ hpos, Nat.div_eq_of_lt ht, Nat.zero_add,
      Nat.mod_eq_of_lt h.1]

/-- The value of the first `n` bytes of a written number is the number,
when it fits. -/
theorem valBE_take_writeBE (n v : Nat) (rest : Bytes) (hv : v < 256 ^ n) :
    valBE ((writeBE n v ++ rest).take n) = v := by
  rw [List.take_left' (length_writeBE n v), valBE_writeBE, Nat.mod_eq_of_lt hv]

theorem drop_writeBE (n v : Nat) (rest : Bytes) : (writeBE n v ++ rest).drop n = rest :=
  List.drop_left' (length_writeBE n v)

end Pondline
