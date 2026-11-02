import Pondline.Bytes

/-
A transcription of `retention.offers` (`packages/core/src/core/retention.gleam`)
and the claims ADR-008 and ADR-006's addendum make about it.

Instants are Gleam `Int` seconds, so they are `Int` here. The mailbox's rule
(`mailbox/service.insert_new`) is `accepted`: a deadline after the mailbox's
`now` and no later than its `now + message_retention_seconds`.
-/

namespace Pondline

/-- `limits.message_retention_seconds`. -/
def messageRetentionSeconds : Int := 604800

/-- `limits.retention_slack_seconds`. -/
def retentionSlackSeconds : Int := 3600

/-- `limits.max_deadline_offers`. -/
def maxDeadlineOffers : Nat := 4

/-- `limits.receipt_window_seconds`. -/
def receiptWindowSeconds : Int := 3600

/-- Gleam's `lifetime / 2`, which truncates toward zero (Erlang `div`). -/
def tdiv2 (x : Int) : Int := if 0 ≤ x then x / 2 else -((-x) / 2)

/-- `halved`: up to `left` deadlines after `now`, each halving the lifetime
before it, stopping at a half of zero. The Gleam `left` is an `Int` and only
ever `max_deadline_offers - 1 = 3`; it is a `Nat` here. -/
def halved (now lifetime : Int) : Nat → List Int
  | 0 => []
  | left + 1 =>
    let half := tdiv2 lifetime
    if half > 0 then (now + half) :: halved now half left else []

/-- `offers`, with the three limits as parameters so that ADR-006's addendum
can be stated for other values of the slack. -/
def offersWith (retention slack : Int) (maxOffers : Nat) (expiresAt now : Int) :
    Int × List Int :=
  let ceiling := now + (retention - slack)
  let first := min expiresAt ceiling
  (first, halved now (first - now) (maxOffers - 1))

/-- `retention.offers` with the production limits. -/
def offers (expiresAt now : Int) : Int × List Int :=
  offersWith messageRetentionSeconds retentionSlackSeconds maxDeadlineOffers expiresAt now

/-- The offers in the order they are made. -/
def allOffers (o : Int × List Int) : List Int := o.1 :: o.2

/-- Whether a mailbox whose clock reads `mailboxNow` accepts `deadline`. -/
def accepted (deadline mailboxNow : Int) : Prop :=
  mailboxNow < deadline ∧ deadline ≤ mailboxNow + messageRetentionSeconds

/-! ## `halved` -/

theorem tdiv2_nonneg {x : Int} (h : 0 ≤ x) : tdiv2 x = x / 2 := by
  simp [tdiv2, h]

theorem halved_length (now L : Int) (left : Nat) : (halved now L left).length ≤ left := by
  induction left generalizing L with
  | zero => simp [halved]
  | succ n ih =>
    simp only [halved]
    split
    · simp only [List.length_cons]; have := ih (tdiv2 L); omega
    · simp

/-- Every halved deadline is after `now` and no later than `now` plus half the
lifetime it halves. -/
theorem halved_bounds (now L : Int) (left : Nat) :
    ∀ x ∈ halved now L left, now < x ∧ x ≤ now + tdiv2 L := by
  induction left generalizing L with
  | zero => simp [halved]
  | succ n ih =>
    simp only [halved]
    split
    · rename_i hpos
      intro x hx
      simp only [List.mem_cons] at hx
      rcases hx with hx | hx
      · omega
      · obtain ⟨h1, h2⟩ := ih (tdiv2 L) x hx
        have : tdiv2 (tdiv2 L) ≤ tdiv2 L := by
          rw [tdiv2_nonneg (by omega)]; omega
        omega
    · simp

/-- The halved deadlines strictly decrease. -/
theorem halved_decreasing (now L : Int) (left : Nat) :
    (halved now L left).Pairwise (· > ·) := by
  induction left generalizing L with
  | zero => simp [halved]
  | succ n ih =>
    simp only [halved]
    split
    · rename_i hpos
      rw [List.pairwise_cons]
      refine ⟨?_, ih _⟩
      intro x hx
      have := halved_bounds now (tdiv2 L) n x hx
      have : tdiv2 (tdiv2 L) < tdiv2 L := by
        rw [tdiv2_nonneg (by omega)]; omega
      omega
    · simp

/-! ## `offers` -/

/-- **At most `max_deadline_offers` offers.** -/
theorem offers_length (e n : Int) : (allOffers (offers e n)).length ≤ maxDeadlineOffers := by
  simp only [allOffers, offers, offersWith, List.length_cons]
  have := halved_length n (min e (n + (messageRetentionSeconds - retentionSlackSeconds)) - n)
    (maxDeadlineOffers - 1)
  unfold maxDeadlineOffers at *
  omega

/-- The first offer is the slack below the mailbox's maximum by the sender's
clock, and never past `expires_at`. -/
theorem offers_first (e n : Int) :
    (offers e n).1 = min e (n + (messageRetentionSeconds - retentionSlackSeconds)) := rfl

/-- The shorter offers are always after `now` and before the first offer. -/
theorem shorter_bounds (e n : Int) : ∀ d ∈ (offers e n).2, n < d ∧ d < (offers e n).1 := by
  intro d hd
  simp only [offers, offersWith] at hd ⊢
  have := halved_bounds _ _ _ d hd
  unfold tdiv2 at this
  split at this <;> omega

/-- **Every offer is in `(now, expires_at]`**, for a row whose deadline is
still ahead. -/
theorem offers_window {e n : Int} (h : n < e) :
    ∀ d ∈ allOffers (offers e n), n < d ∧ d ≤ e := by
  intro d hd
  simp only [allOffers, List.mem_cons] at hd
  have hfirst : (offers e n).1 = min e (n + 601200) := by
    rw [offers_first]; rfl
  rcases hd with hd | hd
  · rw [hd, hfirst]; omega
  · have := shorter_bounds e n d hd
    rw [hfirst] at this; omega

/-- **The boundary the module tests and ADR-008 does not state.** A row at its
deadline is still sent (the scheduler fails a row only once `now` is past its
deadline), and its one offer is `now` itself, which the mailbox refuses. -/
theorem offers_at_deadline (n : Int) : offers n n = (n, []) := by
  simp only [offers, offersWith, messageRetentionSeconds, retentionSlackSeconds]
  have : min n (n + (604800 - 3600)) = n := by omega
  rw [this, Int.sub_self]
  rfl

theorem offers_at_deadline_refused (n : Int) :
    ∀ d ∈ allOffers (offers n n), ¬ accepted d n := by
  rw [offers_at_deadline]
  intro d hd
  simp only [allOffers, List.mem_cons, List.not_mem_nil, or_false] at hd
  subst hd
  unfold accepted; omega

/-- **The offers strictly decrease.** -/
theorem offers_decreasing (e n : Int) : (allOffers (offers e n)).Pairwise (· > ·) := by
  simp only [allOffers]
  rw [List.pairwise_cons]
  refine ⟨fun d hd => (shorter_bounds e n d hd).2, ?_⟩
  exact halved_decreasing _ _ _

/-- The full ladder: a row with at least the default lifetime is offered
167 h, then 83.5 h, 41.75 h and 20.875 h. -/
theorem offers_full (e n : Int) (h : n + 601200 ≤ e) :
    offers e n = (n + 601200, [n + 300600, n + 150300, n + 75150]) := by
  simp only [offers, offersWith, messageRetentionSeconds, retentionSlackSeconds,
    maxDeadlineOffers]
  have h1 : min e (n + (604800 - 3600)) = n + 601200 := by omega
  rw [h1]
  have h2 : n + 601200 - n = 601200 := by omega
  rw [h2]
  simp [halved, tdiv2]

/-- **A sender up to the slack ahead is accepted on the first offer.** -/
theorem slack_accepted_first {e n s : Int} (h : n < e) (hs0 : 0 ≤ s)
    (hs : s ≤ retentionSlackSeconds) : accepted (offers e n).1 (n - s) := by
  rw [offers_first]
  unfold accepted messageRetentionSeconds retentionSlackSeconds at *
  omega

/-- One second past the slack, a full-lifetime first offer is refused. -/
theorem slack_tight (n : Int) :
    ¬ accepted (offers (n + messageRetentionSeconds) n).1 (n - (retentionSlackSeconds + 1)) := by
  rw [offers_first]
  unfold accepted messageRetentionSeconds retentionSlackSeconds
  omega

/-- The furthest the sender's clock can lead and still meet an accepted
offer: the retention less the last rung, `604800 - 75150` seconds, about
6.13 days. -/
def reach : Int := messageRetentionSeconds - 75150

/-- **ADR-008's reach.** For any row whose deadline is ahead, a mailbox whose
clock trails the sender's by up to `reach` accepts one of the offers. -/
theorem reach_accepted {e n s : Int} (h : n < e) (hs0 : 0 ≤ s) (hs : s ≤ reach) :
    ∃ d ∈ allOffers (offers e n), accepted d (n - s) := by
  have hfirst : (offers e n).1 = min e (n + 601200) := by rw [offers_first]; rfl
  unfold reach messageRetentionSeconds at hs
  by_cases hL : (offers e n).1 - n ≤ 75150
  · refine ⟨(offers e n).1, by simp [allOffers], ?_⟩
    unfold accepted messageRetentionSeconds
    omega
  · -- A lifetime over 75150 seconds survives three halvings, and the third
    -- is at most 75150 seconds.
    have hL' : 75150 < min e (n + 601200) - n := by omega
    simp only [offers, offersWith, messageRetentionSeconds, retentionSlackSeconds,
      maxDeadlineOffers] at *
    have hm : min e (n + (604800 - 3600)) = min e (n + 601200) := rfl
    rw [hm] at *
    generalize hL0 : min e (n + 601200) - n = L at *
    have hle : L ≤ 601200 := by omega
    have h2 : tdiv2 L = L / 2 := tdiv2_nonneg (by omega)
    have h4 : tdiv2 (L / 2) = L / 2 / 2 := tdiv2_nonneg (by omega)
    have h8 : tdiv2 (L / 2 / 2) = L / 2 / 2 / 2 := tdiv2_nonneg (by omega)
    refine ⟨n + L / 2 / 2 / 2, ?_, ?_⟩
    · simp only [allOffers, halved, h2, h4, h8]
      rw [ifT (by omega), ifT (by omega), ifT (by omega)]
      simp
    · unfold accepted messageRetentionSeconds
      omega

/-- **"A sender up to about six days ahead is accepted"** (ADR-008, and the
`max_deadline_offers` doc). -/
theorem six_days_accepted {e n s : Int} (h : n < e) (hs0 : 0 ≤ s) (hs : s ≤ 6 * 86400) :
    ∃ d ∈ allOffers (offers e n), accepted d (n - s) :=
  reach_accepted h hs0 (by unfold reach messageRetentionSeconds; omega)

/-- The reach is exact: one second further, a full-lifetime row meets no
accepted offer. -/
theorem reach_tight (e n : Int) (h : n + 601200 ≤ e) :
    ∀ d ∈ allOffers (offers e n), ¬ accepted d (n - (reach + 1)) := by
  rw [offers_full e n h]
  intro d hd
  simp only [allOffers, List.mem_cons, List.not_mem_nil, or_false] at hd
  unfold accepted reach messageRetentionSeconds
  omega

/-! ## ADR-006's addendum -/

/-- The premise the addendum rests on holds for the production limits. -/
theorem slack_le_window : retentionSlackSeconds ≤ receiptWindowSeconds := by decide

/-- **ADR-006 addendum.** A message sealed at `sealedAt` with a lifetime of at
most the retention (`relationship.lifetime_seconds`), first stored at
`stored`, has every copy sent at `copy`, at least one receipt window after
`stored` (`retransmit_after_window`). While the slack is no wider than the
window, each copy's first offer is the message's own expiry. -/
theorem copy_first_offer_is_expiry (retention slack window : Int) (maxOffers : Nat)
    (sealedAt life stored copy : Int)
    (hsw : slack ≤ window) (hlife : life ≤ retention) (hseal : sealedAt ≤ stored)
    (hcopy : stored + window ≤ copy) :
    (offersWith retention slack maxOffers (sealedAt + life) copy).1 = sealedAt + life := by
  simp only [offersWith]
  omega

/-- The addendum's last sentence: with a slack wider than the window, the
first copy can be held short of the expiry. -/
theorem copy_short_if_slack_exceeds_window (retention slack window : Int) (maxOffers : Nat)
    (stored : Int) (hsw : window < slack) :
    (offersWith retention slack maxOffers (stored + retention) (stored + window)).1 <
      stored + retention := by
  simp only [offersWith]
  omega

/-- The addendum with the production limits. -/
theorem copy_first_offer_is_expiry_prod (sealedAt life stored copy : Int)
    (hlife : life ≤ messageRetentionSeconds) (hseal : sealedAt ≤ stored)
    (hcopy : stored + receiptWindowSeconds ≤ copy) :
    (offers (sealedAt + life) copy).1 = sealedAt + life :=
  copy_first_offer_is_expiry _ _ _ _ sealedAt life stored copy slack_le_window hlife hseal hcopy

end Pondline
