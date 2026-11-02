import Pondline.Retention

/-
A transcription of `retransmit.due_at` (`packages/core/src/core/retransmit.gleam`)
and the claims ADR-006 and `limits.max_retransmits` make about the schedule.

`due_at` is called by `daemon/store.record_send` with `stored_at` the time the
mailbox stored *that* copy, so the schedule is a chain: copy `k + 1` is
stored no earlier than copy `k` came due. `chain` models that chain with no
latency between a copy coming due and being stored.
-/

namespace Pondline

/-- `plan.OutboundKind`, without its payloads. -/
inductive Kind where
  | application
  | control
  | receipt
  | handshake
  deriving DecidableEq, Repr

/-- `is_retransmitted`. -/
def Kind.retransmitted : Kind → Bool
  | .application => true
  | .control => true
  | .receipt => false
  | .handshake => false

/-- `limits.max_retransmits`. -/
def maxRetransmits : Int := 5

/-- `int.bitwise_shift_left(1, k)` on the BEAM: `2^k`, and `1 bsr -k = 0` for
a negative `k`. -/
def shiftOne (k : Int) : Int := if 0 ≤ k then 2 ^ k.toNat else 0

/-- `retransmit.due_at`. -/
def dueAt (window : Int) (kind : Kind) (storedAt retransmits deadline : Int) : Option Int :=
  let due := storedAt + window * shiftOne retransmits
  if kind.retransmitted && decide (retransmits < maxRetransmits) && !decide (due > deadline)
  then some due else none

/-- **What `due_at` returns.** A copy is scheduled only for a retransmitted
kind, below the bound, at the doubled window, and never past the deadline. -/
theorem dueAt_spec {w : Int} {kind : Kind} {t k d u : Int} (h : dueAt w kind t k d = some u) :
    u ≤ d ∧ k < maxRetransmits ∧ kind.retransmitted = true ∧ u = t + w * shiftOne k := by
  unfold dueAt at h
  dsimp only at h
  split at h
  · rename_i hc
    cases h
    simp only [Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq, decide_eq_false_iff_not] at hc
    exact ⟨by omega, hc.1.2, hc.1.1, rfl⟩
  · cases h

/-- **At most `max_retransmits` copies**: none is scheduled once `k` reaches it. -/
theorem dueAt_exhausted (w : Int) (kind : Kind) (t k d : Int) (hk : maxRetransmits ≤ k) :
    dueAt w kind t k d = none := by
  unfold dueAt
  dsimp only
  rw [ifF]
  simp only [Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq, decide_eq_false_iff_not]
  omega

/-- Receipts and the handshake are never scheduled. -/
theorem dueAt_not_retransmitted (w : Int) (t k d : Int) :
    dueAt w .receipt t k d = none ∧ dueAt w .handshake t k d = none := by
  constructor <;> rfl

theorem shiftOne_pos {k : Int} (hk : 0 ≤ k) : 1 ≤ shiftOne k := by
  unfold shiftOne
  rw [ifT hk]
  have : (0 : Int) < 2 ^ k.toNat := Int.pow_pos (by decide)
  omega

/-- **Every copy waits at least the window** after the copy before it was
stored (ADR-006's addendum relies on this). -/
theorem retransmit_after_window {w : Int} {kind : Kind} {t k d u : Int}
    (h : dueAt w kind t k d = some u) (hk : 0 ≤ k) (hw : 0 ≤ w) : t + w ≤ u := by
  obtain ⟨_, _, _, hu⟩ := dueAt_spec h
  have := Int.mul_le_mul_of_nonneg_left (shiftOne_pos hk) hw
  rw [Int.mul_one] at this
  omega

/-- The schedule with no latency: copy `k + 1` is stored the moment copy `k`
comes due. `fuel` only makes the recursion structural; any `fuel ≥ 5`
gives the whole schedule. -/
def chain (window : Int) (kind : Kind) (deadline : Int) : Nat → Int → Int → List Int
  | 0, _, _ => []
  | fuel + 1, t, k =>
    match dueAt window kind t k deadline with
    | some u => u :: chain window kind deadline fuel u (k + 1)
    | none => []

/-- **At most five retransmits**, from the first copy (`k = 0`). -/
theorem chain_length (w : Int) (kind : Kind) (d : Int) :
    ∀ (fuel : Nat) (t k : Int), 0 ≤ k → (chain w kind d fuel t k).length ≤ (maxRetransmits - k).toNat := by
  intro fuel
  induction fuel with
  | zero => intros; simp [chain]
  | succ n ih =>
    intro t k hk
    simp only [chain]
    split
    · rename_i u hu
      have := (dueAt_spec hu).2.1
      have := ih u (k + 1) (by omega)
      simp only [List.length_cons]
      unfold maxRetransmits at *
      omega
    · simp

/-- **No copy past the deadline.** -/
theorem chain_le_deadline (w : Int) (kind : Kind) (d : Int) :
    ∀ (fuel : Nat) (t k : Int), ∀ u ∈ chain w kind d fuel t k, u ≤ d := by
  intro fuel
  induction fuel with
  | zero => intros; simp [chain] at *
  | succ n ih =>
    intro t k u hu
    simp only [chain] at hu
    split at hu
    · rename_i u' hu'
      simp only [List.mem_cons] at hu
      rcases hu with hu | hu
      · subst hu; exact (dueAt_spec hu').1
      · exact ih _ _ u hu
    · simp at hu

/-- **ADR-006's "31 hours".** With no latency and a deadline far enough out,
the five retransmits of a message stored at `t` go out at `t` plus 1, 3, 7,
15 and 31 windows: the last `31 * window` after the first copy was stored. -/
theorem chain_zero_latency (w : Int) (kind : Kind) (t d : Int)
    (hw : 0 ≤ w) (hkind : kind.retransmitted = true) (hd : t + 31 * w ≤ d) :
    chain w kind d 6 t 0 = [t + w, t + 3 * w, t + 7 * w, t + 15 * w, t + 31 * w] := by
  have step : ∀ (f : Nat) (t' k : Int) (u : Int), dueAt w kind t' k d = some u →
      chain w kind d (f + 1) t' k = u :: chain w kind d f u (k + 1) := by
    intro f t' k u h; simp only [chain, h]
  have due : ∀ (t' k : Int) (n : Nat), k = n → k < 5 → t' + w * 2 ^ n ≤ d →
      dueAt w kind t' k d = some (t' + w * 2 ^ n) := by
    intro t' k n hk hk5 hle
    unfold dueAt shiftOne maxRetransmits
    subst hk
    simp only [Int.natCast_nonneg, ifT, Int.toNat_natCast]
    rw [ifT (by simp [hkind]; omega)]
  have p1 : w * 2 ^ 1 = 2 * w := by simp [Int.mul_comm]
  have p2 : w * 2 ^ 2 = 4 * w := by simp [Int.mul_comm]
  have p3 : w * 2 ^ 3 = 8 * w := by simp [Int.mul_comm]
  have p4 : w * 2 ^ 4 = 16 * w := by simp [Int.mul_comm]
  rw [step 5 t 0 _ (due t 0 0 rfl (by decide) (by simp; omega))]
  rw [step 4 _ _ _ (due _ (0 + 1) 1 rfl (by decide) (by rw [p1]; simp; omega))]
  rw [step 3 _ _ _ (due _ (0 + 1 + 1) 2 rfl (by decide) (by rw [p1, p2]; simp; omega))]
  rw [step 2 _ _ _ (due _ (0 + 1 + 1 + 1) 3 rfl (by decide) (by rw [p1, p2, p3]; simp; omega))]
  rw [step 1 _ _ _ (due _ (0 + 1 + 1 + 1 + 1) 4 rfl (by decide)
    (by rw [p1, p2, p3, p4]; simp; omega))]
  have h5 : chain w kind d 1 (t + w * 2 ^ 0 + w * 2 ^ 1 + w * 2 ^ 2 + w * 2 ^ 3 + w * 2 ^ 4)
      (0 + 1 + 1 + 1 + 1 + 1) = [] := by
    simp only [chain]
    rw [dueAt_exhausted _ _ _ _ _ (by unfold maxRetransmits; omega)]
  rw [h5, p1, p2, p3, p4]
  simp only [Int.pow_zero, Int.mul_one, List.cons.injEq, and_true, true_and]
  and_intros <;> omega

/-- The same with the production window: 1, 3, 7, 15 and 31 hours. -/
theorem chain_hours (kind : Kind) (t d : Int) (hkind : kind.retransmitted = true)
    (hd : t + 111600 ≤ d) :
    chain receiptWindowSeconds kind d 6 t 0 =
      [t + 3600, t + 10800, t + 25200, t + 54000, t + 111600] := by
  rw [show receiptWindowSeconds = 3600 from rfl,
    chain_zero_latency 3600 kind t d (by decide) hkind (by omega)]
  simp only [List.cons.injEq, and_true, true_and]
  and_intros <;> omega

/-- **The span is a lower bound under any latency.** Whatever delay separates
a copy coming due from the next copy being stored, the fifth retransmit is
stored at least `31 * window` after the first copy. -/
theorem span_lower_bound {w : Int} {kind : Kind} {d : Int} {t0 t1 t2 t3 t4 t5 u0 u1 u2 u3 u4 : Int}
    (h0 : dueAt w kind t0 0 d = some u0) (l0 : u0 ≤ t1)
    (h1 : dueAt w kind t1 1 d = some u1) (l1 : u1 ≤ t2)
    (h2 : dueAt w kind t2 2 d = some u2) (l2 : u2 ≤ t3)
    (h3 : dueAt w kind t3 3 d = some u3) (l3 : u3 ≤ t4)
    (h4 : dueAt w kind t4 4 d = some u4) (l4 : u4 ≤ t5) :
    t0 + 31 * w ≤ t5 := by
  have e0 := (dueAt_spec h0).2.2.2
  have e1 := (dueAt_spec h1).2.2.2
  have e2 := (dueAt_spec h2).2.2.2
  have e3 := (dueAt_spec h3).2.2.2
  have e4 := (dueAt_spec h4).2.2.2
  simp only [shiftOne] at e0 e1 e2 e3 e4
  simp at e0 e1 e2 e3 e4
  omega

/-- **"Doubling from one hour keeps a day-long outage to five copies"**
(ADR-006): the original and four retransmits fall within 24 hours of the
first store, the fifth after it. -/
theorem day_outage_five_copies (kind : Kind) (t d : Int) (hkind : kind.retransmitted = true)
    (hd : t + 111600 ≤ d) :
    ((chain receiptWindowSeconds kind d 6 t 0).filter (fun u => decide (u ≤ t + 86400))).length = 4 := by
  rw [chain_hours kind t d hkind hd]
  simp [List.filter]

/-- **"31 hours ... well inside `message_retention_seconds`"** (`limits`). -/
theorem span_inside_retention : 31 * receiptWindowSeconds < messageRetentionSeconds := by
  decide

end Pondline
