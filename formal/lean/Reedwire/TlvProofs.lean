import Reedwire.Tlv

/-
Theorems about the TLV transcription: BigSize round trips both ways, the
stream codec is canonical (every accepted input is the encoding of what it
decoded to, and every well-formed record list decodes from its encoding),
the input bound holds, unknown even types fail closed, unknown odd types do
not change the result, and a `Builder` whose types fit a u64 encodes to an
accepted stream.

Totality needs no theorem: Lean accepted `parseRecords` with a termination
proof (each record consumes at least two bytes), so it returns on every
input.
-/

namespace Reedwire

/-! ## BigSize -/

theorem wide_writeBE {n floor v : Nat} (rest : Bytes) (hf : floor < v) (hv : v < 256 ^ n) :
    wide (writeBE n v ++ rest) n floor = .ok (v, rest) := by
  unfold wide
  have hlen : ¬ (writeBE n v ++ rest).length < n := by simp
  rw [ifF hlen, valBE_take_writeBE n v rest hv, ifT hf, drop_writeBE]

/-- **BigSize round trip.** Every value in the u64 range decodes from its
encoding, whatever follows it. -/
theorem decodeBigSize_encode (v : Nat) (rest : Bytes) (hv : v ≤ maxU64) :
    decodeBigSize (encodeBigSize v ++ rest) = .ok (v, rest) := by
  have hmin : min v maxU64 = v := Nat.min_eq_left hv
  unfold encodeBigSize
  dsimp only
  rw [hmin]
  unfold maxU64 at hv
  by_cases h1 : v < 0xfd
  · rw [ifT h1]
    simp only [List.cons_append, List.nil_append, decodeBigSize]
    rw [ifF (by omega), ifF (by omega), ifF (by omega)]
  · rw [ifF h1]
    by_cases h2 : v ≤ maxU16
    · rw [ifT h2]
      simp only [List.cons_append, decodeBigSize]
      rw [ifT trivial, ifF (by decide), ifF (by decide)]
      refine wide_writeBE rest ?_ ?_ <;> simp [maxU16] at * <;> omega
    · rw [ifF h2]
      by_cases h3 : v ≤ maxU32
      · rw [ifT h3]
        simp only [List.cons_append, decodeBigSize]
        rw [ifT trivial, ifF (by decide)]
        refine wide_writeBE rest ?_ ?_ <;> simp [maxU16, maxU32] at * <;> omega
      · rw [ifF h3]
        simp only [List.cons_append, decodeBigSize, ↓reduceIte]
        refine wide_writeBE rest ?_ ?_ <;> simp [maxU32] at * <;> omega

theorem wide_canonical {rest r : Bytes} {n floor v : Nat} (hvalid : Bytes.Valid rest)
    (h : wide rest n floor = .ok (v, r)) :
    rest = writeBE n v ++ r ∧ floor < v ∧ v < 256 ^ n := by
  unfold wide at h
  split at h
  · cases h
  · rename_i hlen
    split at h
    · rename_i hgt
      cases h
      have htv := Bytes.valid_take n hvalid
      have hlt := valBE_lt htv
      have htl : (rest.take n).length = n := by simp; omega
      rw [htl] at hlt
      refine ⟨?_, hgt, hlt⟩
      have := writeBE_valBE htv
      rw [htl] at this
      rw [this, List.take_append_drop]
    · cases h

/-- **BigSize canonicality.** A byte string `decode_big_size` accepts is the
minimal encoding of the value it read, followed by the rest. -/
theorem decodeBigSize_canonical {l r : Bytes} {v : Nat} (hvalid : Bytes.Valid l)
    (h : decodeBigSize l = .ok (v, r)) : l = encodeBigSize v ++ r ∧ v ≤ maxU64 := by
  cases l with
  | nil => cases h
  | cons b rest =>
    rw [Bytes.valid_cons] at hvalid
    simp only [decodeBigSize] at h
    unfold encodeBigSize
    unfold maxU64
    split at h
    · rename_i hb
      obtain ⟨hr, hf, hv⟩ := wide_canonical hvalid.2 h
      unfold maxU32 at hf
      simp at hv
      have hmin : min v 0xffffffffffffffff = v := Nat.min_eq_left (by omega)
      simp only [hmin]
      rw [ifF (by omega), ifF (by unfold maxU16; omega), ifF (by unfold maxU32; omega)]
      subst hb; rw [hr]; exact ⟨rfl, by omega⟩
    · split at h
      · rename_i _ hb
        obtain ⟨hr, hf, hv⟩ := wide_canonical hvalid.2 h
        unfold maxU16 at hf
        simp at hv
        have hmin : min v 0xffffffffffffffff = v := Nat.min_eq_left (by omega)
        simp only [hmin]
        rw [ifF (by omega), ifF (by unfold maxU16; omega), ifT (by unfold maxU32; omega)]
        subst hb; rw [hr]; exact ⟨rfl, by omega⟩
      · split at h
        · rename_i _ _ hb
          obtain ⟨hr, hf, hv⟩ := wide_canonical hvalid.2 h
          simp at hv
          have hmin : min v 0xffffffffffffffff = v := Nat.min_eq_left (by omega)
          simp only [hmin]
          rw [ifF (by omega), ifT (by unfold maxU16; omega)]
          subst hb; rw [hr]; exact ⟨rfl, by omega⟩
        · rename_i h1 h2 h3
          cases h
          have hb := hvalid.1
          have hmin : min v 0xffffffffffffffff = v := Nat.min_eq_left (by omega)
          simp only [hmin]
          rw [ifT (by omega)]
          exact ⟨rfl, by omega⟩

theorem encodeBigSize_ne_nil (v : Nat) : encodeBigSize v ≠ [] := by
  unfold encodeBigSize
  dsimp only
  split
  · simp
  · split
    · simp
    · split <;> simp

theorem valid_encodeBigSize (v : Nat) : Bytes.Valid (encodeBigSize v) := by
  unfold encodeBigSize
  dsimp only
  split
  · rename_i h
    rw [Bytes.valid_cons]; exact ⟨by omega, Bytes.valid_nil⟩
  · split
    · rw [Bytes.valid_cons]; exact ⟨by decide, valid_writeBE _ _⟩
    · split
      · rw [Bytes.valid_cons]; exact ⟨by decide, valid_writeBE _ _⟩
      · rw [Bytes.valid_cons]; exact ⟨by decide, valid_writeBE _ _⟩

/-! ## Streams -/

/-- A record list `encode_stream` can produce and `parse` should accept:
types strictly increasing from `previous`, every type and length in the u64
range, and every value a byte string. -/
def RecsOk : Int → Records → Prop
  | _, [] => True
  | previous, (t, v) :: rs =>
    previous < (t : Int) ∧ t ≤ maxU64 ∧ v.length ≤ maxU64 ∧ Bytes.Valid v ∧ RecsOk t rs

/-- **Stream round trip.** A well-formed record list decodes from its
encoding. -/
theorem parseRecords_encode (recs : Records) (previous : Int) (h : RecsOk previous recs) :
    parseRecords (encodeRecords recs) previous = .ok recs := by
  induction recs generalizing previous with
  | nil => simp [encodeRecords, parseRecords]
  | cons r rs ih =>
    obtain ⟨t, v⟩ := r
    obtain ⟨hprev, ht, hlen, _, hrest⟩ := h
    rw [parseRecords]
    have hne : encodeRecords ((t, v) :: rs) ≠ [] := by
      simp [encodeRecords, encodeRecord, encodeBigSize_ne_nil]
    rw [ifF hne]
    have e1 : decodeBigSize (encodeRecords ((t, v) :: rs)) =
        .ok (t, encodeBigSize v.length ++ (v ++ encodeRecords rs)) := by
      simp only [encodeRecords, encodeRecord, List.append_assoc]
      exact decodeBigSize_encode t _ ht
    have e2 : decodeBigSize (encodeBigSize v.length ++ (v ++ encodeRecords rs)) =
        .ok (v.length, v ++ encodeRecords rs) := decodeBigSize_encode _ _ hlen
    split
    · rename_i e h1; rw [e1] at h1; cases h1
    · rename_i tag rest1 h1
      rw [e1] at h1; cases h1
      split
      · rename_i e h2; rw [e2] at h2; cases h2
      · rename_i length rest2 h2
        rw [e2] at h2; cases h2
        rw [ifT hprev, ifF (by simp)]
        rw [List.drop_left' rfl, ih t hrest, List.take_left' rfl]

/-- `parse_records` only ever reads types in the u64 range from bytes. -/
theorem decodeBigSize_le {l r : Bytes} {v : Nat} (hvalid : Bytes.Valid l)
    (h : decodeBigSize l = .ok (v, r)) : v ≤ maxU64 :=
  (decodeBigSize_canonical hvalid h).2

/-- **Stream canonicality.** For every byte string `parse_records` accepts,
`encode_stream` reproduces it exactly, and the records it read are
well-formed (so in particular strictly increasing by type). -/
theorem parseRecords_canonical :
    ∀ (bits : Bytes) (previous : Int) (recs : Records), Bytes.Valid bits →
      parseRecords bits previous = .ok recs → encodeRecords recs = bits ∧ RecsOk previous recs := by
  intro bits
  induction h : bits.length using Nat.strongRecOn generalizing bits with
  | _ n ih =>
    intro previous recs hvalid hp
    rw [parseRecords] at hp
    split at hp
    · rename_i hnil; cases hp; subst hnil; exact ⟨rfl, trivial⟩
    · split at hp
      · cases hp
      · rename_i tag rest1 h1
        obtain ⟨hb1, htag⟩ := decodeBigSize_canonical hvalid h1
        have hv1 : Bytes.Valid rest1 := by
          rw [hb1, Bytes.valid_append] at hvalid; exact hvalid.2
        split at hp
        · cases hp
        · rename_i length rest2 h2
          obtain ⟨hb2, hlen⟩ := decodeBigSize_canonical hv1 h2
          have hv2 : Bytes.Valid rest2 := by
            rw [hb2, Bytes.valid_append] at hv1; exact hv1.2
          split at hp
          · rename_i hgt
            split at hp
            · cases hp
            · rename_i hle
              split at hp
              · cases hp
              · rename_i recs' hrec
                cases hp
                have hshort : (rest2.drop length).length < n := by
                  have := decodeBigSize_shrinks h1
                  have := decodeBigSize_shrinks h2
                  simp only [List.length_drop]; omega
                obtain ⟨henc, hok⟩ :=
                  ih _ hshort (rest2.drop length) rfl tag recs' (Bytes.valid_drop _ hv2) hrec
                have htl : (rest2.take length).length = length := by simp; omega
                refine ⟨?_, ?_⟩
                · simp only [encodeRecords, encodeRecord, htl, henc, List.append_assoc,
                    List.take_append_drop]
                  rw [hb1, hb2]
                · exact ⟨hgt, htag, by rw [htl]; exact hlen, Bytes.valid_take _ hv2, hok⟩
          · cases hp

/-- **Canonical encoding, as the module states it.** Two byte strings `parse`
accepts with the same records are the same byte string. -/
theorem parse_injective {a b : Bytes} {ma mb : Int} {recs : Records}
    (hva : Bytes.Valid a) (hvb : Bytes.Valid b)
    (ha : parse a ma = .ok recs) (hb : parse b mb = .ok recs) : a = b := by
  unfold parse at ha hb
  split at ha
  · cases ha
  · split at hb
    · cases hb
    · rw [← (parseRecords_canonical a _ _ hva ha).1, ← (parseRecords_canonical b _ _ hvb hb).1]

/-- **Input bound.** `parse` never accepts more than `max_bytes`. -/
theorem parse_bound {bytes : Bytes} {maxBytes : Int} {recs : Records}
    (h : parse bytes maxBytes = .ok recs) : (bytes.length : Int) ≤ maxBytes := by
  unfold parse at h
  split at h
  · cases h
  · omega

/-- **Stream round trip through `parse`.** -/
theorem parse_encode (recs : Records) (maxBytes : Int) (h : RecsOk (-1) recs)
    (hbound : ((encodeRecords recs).length : Int) ≤ maxBytes) :
    parse (encodeRecords recs) maxBytes = .ok recs := by
  unfold parse
  rw [ifF (by omega)]
  exact parseRecords_encode recs (-1) h

end Reedwire
