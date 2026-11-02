import Pondline.Bytes

/-
A transcription of `limits.padded_size` and of `envelope.pad`, `unpad` and
`from_wire` (`packages/core/src/core/limits.gleam`,
`packages/core/src/core/envelope.gleam`), with the theorems the padding
scheme rests on.
-/

namespace Pondline

/-- `limits.max_ciphertext_bytes`. -/
def maxCiphertextBytes : Nat := 262144

/-- `limits.padding_buckets`, smallest first. -/
def paddingBuckets : List Nat := [4096, 16384, 65536, 262144]

/-- `limits.padded_size`: the first bucket that holds `size`. -/
def paddedSize (size : Int) : Option Nat :=
  paddingBuckets.find? (fun bucket => decide (size ≤ (bucket : Int)))

/-- The padded bytes for a chosen bucket: a four-byte length, the ciphertext,
zeros to the bucket. -/
def fill (sealed : Bytes) (bucket : Nat) : Bytes :=
  writeBE 4 sealed.length ++ sealed ++ List.replicate (bucket - sealed.length - 4) 0

/-- `envelope.pad`. (Written with `Option.map` rather than a `match`: the
kernel's check of the `match` form's equation lemma recurses on the bucket
literals.) -/
def pad (sealed : Bytes) : Option Bytes :=
  (paddedSize ((sealed.length : Int) + 4)).map (fill sealed)

/-- `envelope.unpad`: the length prefix, then that many bytes of what follows. -/
def unpad (padded : Bytes) : Option Bytes :=
  if padded.length < 4 then none
  else
    let length := valBE (padded.take 4)
    let rest := padded.drop 4
    if length ≤ rest.length then some (rest.take length) else none

/-- `envelope.from_wire`: accepted exactly when the size is a bucket. -/
def fromWire (bytes : Bytes) : Option Bytes :=
  if bytes.length ∈ paddingBuckets then some bytes else none

/-! ## `padded_size` -/

/-- **The largest bucket is the mailbox's limit.** -/
theorem largest_bucket : paddingBuckets.getLast? = some maxCiphertextBytes ∧
    ∀ b ∈ paddingBuckets, b ≤ maxCiphertextBytes := by
  refine ⟨rfl, ?_⟩
  intro b hb
  simp only [paddingBuckets, List.mem_cons, List.not_mem_nil, or_false] at hb
  unfold maxCiphertextBytes
  omega

/-- `padded_size` spelled out as the four cases it is. -/
theorem paddedSize_eq (size : Int) :
    paddedSize size =
      if size ≤ 4096 then some 4096
      else if size ≤ 16384 then some 16384
      else if size ≤ 65536 then some 65536
      else if size ≤ 262144 then some 262144
      else none := by
  unfold paddedSize paddingBuckets
  simp only [List.find?]
  by_cases h1 : size ≤ 4096
  · simp [h1]
  · by_cases h2 : size ≤ 16384
    · simp [h1, h2]
    · by_cases h3 : size ≤ 65536
      · simp [h1, h2, h3]
      · by_cases h4 : size ≤ 262144
        · simp [h1, h2, h3, h4]
        · simp [h1, h2, h3, h4]

/-- **Defined exactly up to the limit.** -/
theorem paddedSize_isSome (size : Int) :
    (paddedSize size).isSome ↔ size ≤ (maxCiphertextBytes : Int) := by
  rw [paddedSize_eq]; unfold maxCiphertextBytes
  split <;> (try split) <;> (try split) <;> (try split) <;> simp <;> omega

/-- **A bucket, at least the input, and the smallest such bucket.** -/
theorem paddedSize_spec {size : Int} {b : Nat} (h : paddedSize size = some b) :
    b ∈ paddingBuckets ∧ size ≤ b ∧ ∀ b' ∈ paddingBuckets, size ≤ (b' : Int) → b ≤ b' := by
  rw [paddedSize_eq] at h
  simp only [paddingBuckets, List.mem_cons, List.not_mem_nil, or_false]
  split at h
  · cases h; refine ⟨by simp, by omega, ?_⟩; intro b' hb' _; omega
  · split at h
    · cases h; refine ⟨by simp, by omega, ?_⟩; intro b' hb' hs; omega
    · split at h
      · cases h; refine ⟨by simp, by omega, ?_⟩; intro b' hb' hs; omega
      · split at h
        · cases h; refine ⟨by simp, by omega, ?_⟩; intro b' hb' hs; omega
        · cases h

/-- **Monotone.** A smaller ciphertext never pads to a larger bucket. -/
theorem paddedSize_mono {s t : Int} {bt : Nat} (hst : s ≤ t) (ht : paddedSize t = some bt) :
    ∃ bs, paddedSize s = some bs ∧ bs ≤ bt := by
  obtain ⟨hmem, hle, _⟩ := paddedSize_spec ht
  have hsome : (paddedSize s).isSome := by
    rw [paddedSize_isSome]
    have := (largest_bucket.2 bt hmem)
    omega
  obtain ⟨bs, hbs⟩ := Option.isSome_iff_exists.mp hsome
  obtain ⟨_, _, hmin⟩ := paddedSize_spec hbs
  exact ⟨bs, hbs, hmin bt hmem (by omega)⟩

/-! ## `pad`, `unpad`, `from_wire` -/

/-- **Pad then unpad is the identity**, and the padded size is a bucket the
mailbox accepts from the wire. -/
theorem pad_spec {sealed p : Bytes} (h : pad sealed = some p) :
    p.length ∈ paddingBuckets ∧ paddedSize ((sealed.length : Int) + 4) = some p.length ∧
      unpad p = some sealed ∧ fromWire p = some p := by
  unfold pad at h
  cases hb : paddedSize ((sealed.length : Int) + 4) with
  | none => rw [hb] at h; cases h
  | some bucket =>
    rw [hb] at h
    simp only [Option.map_some, Option.some.injEq] at h
    subst h
    obtain ⟨hmem, hle, _⟩ := paddedSize_spec hb
    have hmax := largest_bucket.2 bucket hmem
    unfold maxCiphertextBytes at hmax
    have hlen : (fill sealed bucket).length = bucket := by
      simp [fill]; omega
    rw [hlen]
    refine ⟨?_, ?_, ?_, ?_⟩
    · exact hmem
    · rfl
    · unfold unpad
      rw [hlen, ifF (by omega)]
      simp only [fill, List.append_assoc]
      rw [valBE_take_writeBE 4 _ _ (by simp; omega), drop_writeBE]
      rw [ifT (by simp)]
      simp
    · unfold fromWire; rw [hlen, ifT hmem]

/-- **Pad fails only for a ciphertext too large for every bucket.** -/
theorem pad_none_iff (sealed : Bytes) :
    pad sealed = none ↔ sealed.length + 4 > maxCiphertextBytes := by
  have := paddedSize_isSome ((sealed.length : Int) + 4)
  unfold pad
  cases hb : paddedSize ((sealed.length : Int) + 4) with
  | none => rw [hb] at this; simp at this ⊢; omega
  | some b => rw [hb] at this; simp at this ⊢; omega

/-- **`from_wire` accepts exactly the bucket sizes.** -/
theorem fromWire_spec (bytes : Bytes) :
    (fromWire bytes = some bytes ↔ bytes.length ∈ paddingBuckets) ∧
      (fromWire bytes = none ↔ bytes.length ∉ paddingBuckets) := by
  unfold fromWire
  split <;> simp_all

end Pondline
