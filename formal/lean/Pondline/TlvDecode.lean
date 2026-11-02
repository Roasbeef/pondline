import Pondline.TlvProofs

/-
Theorems about reading a parsed stream (`required`, `optional`, `run`) and
about building one (`put`, `encode`).
-/

namespace Pondline

/-! ## Unknown even types fail closed -/

/-- Every record the decoder was given is either still unread or has a type
the decoder names. -/
theorem runSpec_cover :
    ∀ (spec : List Entry) (recs : Records) (vs : List (Nat × Option Value)) (rem : Records),
      runSpec spec recs = .ok (vs, rem) →
        ∀ r ∈ recs, r ∈ rem ∨ r.1 ∈ spec.map Entry.tag := by
  intro spec
  induction spec with
  | nil =>
    intro recs vs rem h r hr
    simp only [runSpec] at h; cases h; exact Or.inl hr
  | cons e es ih =>
    intro recs vs rem h r hr
    simp only [runSpec] at h
    split at h
    · split at h
      · cases h
      · split at h
        · cases h
        · rename_i vs' rem' hrest
          cases h
          by_cases ht : r.1 = e.tag
          · exact Or.inr (by simp [ht])
          · have hmem : r ∈ erase e.tag recs := by
              simp only [erase, List.mem_filter]; exact ⟨hr, by simp [ht]⟩
            rcases ih _ _ _ hrest r hmem with h' | h'
            · exact Or.inl h'
            · exact Or.inr (by simp at h' ⊢; exact Or.inr h')
    · split at h
      · cases h
      · split at h
        · cases h
        · rename_i vs' rem' hrest
          cases h
          rcases ih _ _ _ hrest r hr with h' | h'
          · exact Or.inl h'
          · exact Or.inr (by simp at h' ⊢; exact Or.inr h')

/-- **Unknown even types fail closed.** If `decode` succeeds, every even type
in the stream is one the decoder reads. -/
theorem decode_fail_closed {spec : List Entry} {bytes : Bytes} {maxBytes : Int}
    {vs : List (Nat × Option Value)} (h : decode spec bytes maxBytes = .ok vs) :
    ∃ recs, parse bytes maxBytes = .ok recs ∧
      ∀ r ∈ recs, r.1 % 2 = 0 → r.1 ∈ spec.map Entry.tag := by
  unfold decode at h
  split at h
  · cases h
  · rename_i recs hp
    refine ⟨recs, hp, ?_⟩
    intro r hr heven
    unfold runStream at h
    split at h
    · cases h
    · rename_i vs' rem hrun
      split at h
      · cases h
      · rename_i hnone
        rcases runSpec_cover spec recs vs' rem hrun r hr with hin | hin
        · rw [List.find?_eq_none] at hnone
          exact absurd (by simp [isEven, heven]) (hnone r hin)
        · exact hin

/-! ## Unknown odd types are ignored -/

theorem lookup_filter (tag : Nat) (p : Nat × Bytes → Bool)
    (hp : ∀ r : Nat × Bytes, r.1 = tag → p r = true) :
    ∀ l : Records, lookup tag (l.filter p) = lookup tag l := by
  intro l
  induction l with
  | nil => rfl
  | cons r rs ih =>
    obtain ⟨t, v⟩ := r
    by_cases ht : t = tag
    · have := hp (t, v) ht
      subst ht
      simp [List.filter, this, lookup]
    · by_cases hpr : p (t, v) = true
      · simp [List.filter, hpr, lookup, ht, ih]
      · simp [List.filter, hpr, lookup, ht, ih]

theorem erase_filter (tag : Nat) (p : Nat × Bytes → Bool) (l : Records) :
    erase tag (l.filter p) = (erase tag l).filter p := by
  simp only [erase, List.filter_filter, Bool.and_comm]

theorem find?_filter (q p : Nat × Bytes → Bool) (hqp : ∀ r, q r = true → p r = true) :
    ∀ l : Records, (l.filter p).find? q = l.find? q := by
  intro l
  induction l with
  | nil => rfl
  | cons r rs ih =>
    by_cases hq : q r = true
    · simp [List.filter, hqp r hq, List.find?, hq]
    · by_cases hpr : p r = true
      · simp [List.filter, hpr, List.find?, hq, ih]
      · simp [List.filter, hpr, List.find?, hq, ih]

/-- Filtering out records the decoder never names and that are odd commutes
with running the decoder. -/
theorem runSpec_filter (p : Nat × Bytes → Bool) :
    ∀ (spec : List Entry), (∀ e ∈ spec, ∀ r : Nat × Bytes, r.1 = e.tag → p r = true) →
      ∀ recs : Records,
        runSpec spec (recs.filter p) =
          (runSpec spec recs).map (fun x => (x.1, x.2.filter p)) := by
  intro spec
  induction spec with
  | nil => intro _ recs; rfl
  | cons e es ih =>
    intro hp recs
    have hpe := hp e (by simp)
    have hes : ∀ e' ∈ es, ∀ r : Nat × Bytes, r.1 = e'.tag → p r = true :=
      fun e' he' => hp e' (by simp [he'])
    simp only [runSpec]
    rw [lookup_filter e.tag p hpe recs]
    cases lookup e.tag recs with
    | some raw =>
      simp only
      cases e.codec.read raw with
      | error err => rfl
      | ok v =>
        simp only
        rw [erase_filter, ih hes]
        cases runSpec es (erase e.tag recs) with
        | error err => rfl
        | ok x => rfl
    | none =>
      simp only
      cases e.want with
      | required => rfl
      | optional =>
        simp only
        rw [ih hes]
        cases runSpec es recs with
        | error err => rfl
        | ok x => rfl

/-- **Unknown odd types are ignored.** Removing every record whose type is
odd and not named by the decoder changes nothing about the result. -/
theorem runStream_odd_ignored (spec : List Entry) (recs : Records) :
    runStream spec (recs.filter (fun r => (spec.map Entry.tag).contains r.1 || isEven r)) =
      runStream spec recs := by
  let p : Nat × Bytes → Bool := fun r => (spec.map Entry.tag).contains r.1 || isEven r
  have hp : ∀ e ∈ spec, ∀ r : Nat × Bytes, r.1 = e.tag → p r = true := by
    intro e he r hr
    simp only [p, Bool.or_eq_true, List.contains_iff_mem]
    exact Or.inl (by rw [hr]; exact List.mem_map_of_mem he)
  have hq : ∀ r, isEven r = true → p r = true := by
    intro r hr; simp [p, hr]
  show runStream spec (recs.filter p) = runStream spec recs
  unfold runStream
  rw [runSpec_filter p spec hp recs]
  cases runSpec spec recs with
  | error e => rfl
  | ok x =>
    obtain ⟨vs, rem⟩ := x
    show (match (rem.filter p).find? isEven with
      | some r => Except.error (TlvError.unknownRequired r.1)
      | none => Except.ok vs) = _
    rw [find?_filter isEven p hq rem]
    rfl

/-! ## The builder -/

theorem mem_put {b : Records} {t : Int} {v : Bytes} {r : Nat × Bytes}
    (h : r ∈ put b t v) : r = (t.toNat, v) ∨ r ∈ b := by
  simp only [put, List.mem_cons, List.mem_filter] at h
  rcases h with h | h
  · exact Or.inl h
  · exact Or.inr h.1

theorem nodup_put (b : Records) (t : Int) (v : Bytes) (h : (b.map Prod.fst).Nodup) :
    ((put b t v).map Prod.fst).Nodup := by
  simp only [put, List.map_cons]
  rw [List.nodup_cons]
  constructor
  · simp
  · exact List.Nodup.sublist (List.Sublist.map _ (List.filter_sublist)) h

theorem build_spec (Q : Nat × Bytes → Prop) :
    ∀ (puts : List (Int × Bytes)) (b : Records),
      (∀ p ∈ puts, Q (p.1.toNat, p.2)) → (∀ r ∈ b, Q r) → (b.map Prod.fst).Nodup →
        (∀ r ∈ puts.foldl (fun b p => put b p.1 p.2) b, Q r) ∧
          ((puts.foldl (fun b p => put b p.1 p.2) b).map Prod.fst).Nodup := by
  intro puts
  induction puts with
  | nil => intro b _ hb hn; exact ⟨hb, hn⟩
  | cons p ps ih =>
    intro b hps hb hn
    simp only [List.foldl_cons]
    apply ih
    · intro p' hp'; exact hps p' (by simp [hp'])
    · intro r hr
      rcases mem_put hr with h | h
      · rw [h]; exact hps p (by simp)
      · exact hb r h
    · exact nodup_put b p.1 p.2 hn

theorem recsOk_of_pairwise (previous : Int) :
    ∀ l : Records, l.Pairwise (fun a b => a.1 < b.1) →
      (∀ r ∈ l, previous < (r.1 : Int) ∧ r.1 ≤ maxU64 ∧ r.2.length ≤ maxU64 ∧ Bytes.Valid r.2) →
        RecsOk previous l := by
  intro l
  induction l generalizing previous with
  | nil => intros; trivial
  | cons r rs ih =>
    intro hpw hall
    obtain ⟨t, v⟩ := r
    rw [List.pairwise_cons] at hpw
    obtain ⟨h1, h2, h3, h4⟩ := hall (t, v) (by simp)
    refine ⟨h1, h2, h3, h4, ih t hpw.2 ?_⟩
    intro r' hr'
    obtain ⟨_, h2', h3', h4'⟩ := hall r' (by simp [hr'])
    have := hpw.1 r' hr'
    exact ⟨by simp at this ⊢; omega, h2', h3', h4'⟩

/-- **The builder's output is canonical.** A builder whose types fit a u64
and whose values are byte strings no longer than the u64 range encodes to a
stream `parse` accepts, and the records it yields are the builder's, sorted.
The hypothesis on types is needed: `put(2^64, a)` and `put(2^64 + 1, b)`
both encode as type `2^64 - 1` (`builder_overflow_rejected`). -/
theorem builder_accepted (puts : List (Int × Bytes)) (maxBytes : Int)
    (hputs : ∀ p ∈ puts, p.1 ≤ (maxU64 : Int) ∧ p.2.length ≤ maxU64 ∧ Bytes.Valid p.2)
    (hbound : ((encodeBuilder (build puts)).length : Int) ≤ maxBytes) :
    parse (encodeBuilder (build puts)) maxBytes =
      .ok ((build puts).mergeSort (fun x y => decide (x.1 ≤ y.1))) := by
  let Q : Nat × Bytes → Prop := fun r => r.1 ≤ maxU64 ∧ r.2.length ≤ maxU64 ∧ Bytes.Valid r.2
  obtain ⟨hq, hn⟩ := build_spec Q puts []
    (fun p hp => by
      obtain ⟨a, b, c⟩ := hputs p hp
      exact ⟨by unfold maxU64 at a ⊢; omega, b, c⟩)
    (by simp) (by simp)
  let le : Nat × Bytes → Nat × Bytes → Bool := fun x y => decide (x.1 ≤ y.1)
  have hperm := List.mergeSort_perm (build puts) le
  have hsorted : ((build puts).mergeSort le).Pairwise (fun a b => le a b) :=
    List.pairwise_mergeSort
      (fun a b c hab hbc => by simp only [le, decide_eq_true_eq] at *; omega)
      (fun a b => by simp only [le, Bool.or_eq_true, decide_eq_true_eq]; omega)
      (build puts)
  have hnd : (((build puts).mergeSort le).map Prod.fst).Nodup :=
    (hperm.map Prod.fst).nodup_iff.mpr hn
  rw [List.Nodup, List.pairwise_map] at hnd
  have hlt : ((build puts).mergeSort le).Pairwise (fun a b => a.1 < b.1) :=
    (hsorted.and hnd).imp (fun ⟨h1, h2⟩ => by simp only [le, decide_eq_true_eq] at h1; omega)
  apply parse_encode _ maxBytes _ hbound
  apply recsOk_of_pairwise (-1) _ hlt
  intro r hr
  obtain ⟨a, b, c⟩ := hq r (hperm.mem_iff.mp hr)
  exact ⟨by omega, a, b, c⟩

/-- A record repeated is refused as out of order at its second copy. -/
theorem parseRecords_repeat (t : Nat) (v rest : Bytes) (previous : Int)
    (ht : t ≤ maxU64) (hlen : v.length ≤ maxU64) (hprev : previous < (t : Int)) :
    parseRecords (encodeRecord (t, v) ++ (encodeRecord (t, v) ++ rest)) previous =
      .error (.outOfOrder t) := by
  have step : ∀ (prev : Int) (tail : Bytes),
      parseRecords (encodeRecord (t, v) ++ tail) prev =
        if (t : Int) > prev then
          (match parseRecords tail t with
            | .error e => .error e
            | .ok recs => .ok ((t, v) :: recs))
        else .error (.outOfOrder t) := by
    intro prev tail
    rw [parseRecords]
    have hne : encodeRecord (t, v) ++ tail ≠ [] := by
      simp [encodeRecord, encodeBigSize_ne_nil]
    rw [ifF hne]
    have e1 : decodeBigSize (encodeRecord (t, v) ++ tail) =
        .ok (t, encodeBigSize v.length ++ (v ++ tail)) := by
      simp only [encodeRecord, List.append_assoc]
      exact decodeBigSize_encode t _ ht
    have e2 : decodeBigSize (encodeBigSize v.length ++ (v ++ tail)) =
        .ok (v.length, v ++ tail) := decodeBigSize_encode _ _ hlen
    split
    · rename_i e h1; rw [e1] at h1; cases h1
    · rename_i tag rest1 h1
      rw [e1] at h1; cases h1
      split
      · rename_i e h2; rw [e2] at h2; cases h2
      · rename_i length rest2 h2
        rw [e2] at h2; cases h2
        by_cases hgt : (t : Int) > prev
        · rw [ifT hgt, ifT hgt, ifF (by simp), List.drop_left' rfl, List.take_left' rfl]
          try rfl
        · rw [ifF hgt, ifF hgt]
  rw [step, ifT hprev, step, ifF (by omega)]

/-- **The builder's type bound is needed.** Two types past the u64 range
clamp to the same BigSize, so the builder emits a repeated type and `parse`
refuses its output. Unreachable today (every codec's types are small
constants), but it bounds the module doc's claim that the encoder "cannot
emit a duplicate". -/
theorem builder_overflow_rejected (maxBytes : Int) :
    parse (encodeBuilder (build [(2 ^ 64, []), (2 ^ 64 + 1, [])])) maxBytes =
      if (20 : Int) > maxBytes then .error .inputTooLarge
      else .error (.outOfOrder maxU64) := by
  let x : Nat × Bytes := (2 ^ 64 + 1, [])
  let y : Nat × Bytes := (2 ^ 64, [])
  have hb : build [(2 ^ 64, []), (2 ^ 64 + 1, [])] = [x, y] := by
    simp [build, put, x, y]
  let le : Nat × Bytes → Nat × Bytes → Bool := fun a b => decide (a.1 ≤ b.1)
  have hperm := List.mergeSort_perm [x, y] le
  have hrec : ∀ r ∈ [x, y].mergeSort le, encodeRecord r = encodeRecord (maxU64, []) := by
    intro r hr
    have := hperm.mem_iff.mp hr
    simp only [List.mem_cons, List.not_mem_nil, or_false] at this
    rcases this with h | h <;> subst h <;> rfl
  have hlen : ([x, y].mergeSort le).length = 2 := by simp
  have henc : encodeBuilder (build [(2 ^ 64, []), (2 ^ 64 + 1, [])]) =
      encodeRecord (maxU64, []) ++ (encodeRecord (maxU64, []) ++ []) := by
    rw [hb]
    unfold encodeBuilder
    match h : [x, y].mergeSort le, hrec, hlen with
    | [a, b], hr, _ =>
      simp only [encodeRecords, hr a (by simp), hr b (by simp), List.append_nil]
  rw [henc]
  unfold parse
  have hl : ((encodeRecord (maxU64, []) ++ (encodeRecord (maxU64, []) ++ [])).length : Int) = 20 := by
    rfl
  rw [hl]
  split
  · rfl
  · rw [parseRecords_repeat maxU64 [] [] (-1) (Nat.le_refl _) (by simp [maxU64]) (by simp [maxU64])]

end Pondline
