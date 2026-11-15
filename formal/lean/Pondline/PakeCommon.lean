import Pondline.Nameplate

/-
A transcription of `pake_common.lv_encode` and `encode_public_context`
(`packages/core/src/core/crypto/pake_common.gleam`) and of the public context
`rendezvous.public_context` builds from them
(`packages/core/src/core/rendezvous.gleam`), with the theorem ADR-016's
framing rests on: every framed context has exactly one parse.
-/

namespace Pondline.PakeCommon

open Pondline

/-- `pake_common.max_field_bytes`. -/
def maxFieldBytes : Nat := 65535

/-- `pake_common.max_context_part_bytes`. -/
def maxContextPartBytes : Nat := 4294967295

/-- `lv_encode`: the field behind its length as two big-endian bytes, refused
past `max_field_bytes`. -/
def lvEncode (field : Bytes) : Option Bytes :=
  if field.length ≤ maxFieldBytes then some (writeBE 2 field.length ++ field) else none

/-- `frame_context_part`: the part behind its length as four big-endian
bytes, refused past `max_context_part_bytes`. -/
def framePart (part : Bytes) : Option Bytes :=
  if part.length ≤ maxContextPartBytes then some (writeBE 4 part.length ++ part) else none

/-- `encode_public_context`: `list.try_map` over the three parts, then
`bit_array.concat`. -/
def encodePublicContext (sid client server : Bytes) : Option Bytes :=
  ([sid, client, server].mapM framePart).map List.flatten

/-- The ADR-016 public context, `lv(label) || lv(nameplate) ||
EncodePublicContext(sid, U, S)`, as `rendezvous.public_context` assembles it
with `use ... <- result.try`. -/
def publicContext (label plate sid client server : Bytes) : Option Bytes :=
  (lvEncode label).bind fun framedLabel =>
    (lvEncode plate).bind fun framedPlate =>
      (encodePublicContext sid client server).map fun identities =>
        framedLabel ++ framedPlate ++ identities

/-- `rendezvous.label`, `"Pondline_Rendezvous_v1"` in ASCII. -/
def rendezvousLabel : Bytes := "Pondline_Rendezvous_v1".toUTF8.toList.map (·.toNat)

/-- `rendezvous.joiner_identity`, `"joiner"`. -/
def joinerIdentity : Bytes := "joiner".toUTF8.toList.map (·.toNat)

/-- `rendezvous.inviter_identity`, `"inviter"`. -/
def inviterIdentity : Bytes := "inviter".toUTF8.toList.map (·.toNat)

/-- `rendezvous.public_context(nameplate, rendezvous)`: the nameplate as its
six ASCII digits, the rendezvous identifier's bytes as the session
identifier. -/
def rendezvousContext (nameplate : Nat) (rendezvous : Bytes) : Option Bytes :=
  publicContext rendezvousLabel (Nameplate.toString nameplate) rendezvous joinerIdentity
    inviterIdentity

/-! ## One length-prefixed field -/

/-- A length-prefixed field is a prefix code: the width-`n` length that
leads it says where it ends, so whatever follows cannot change how it is
read. -/
theorem prefixed_inj {n : Nat} {a b r r' : Bytes} (ha : a.length < 256 ^ n) (hb : b.length < 256 ^ n)
    (h : writeBE n a.length ++ a ++ r = writeBE n b.length ++ b ++ r') : a = b ∧ r = r' := by
  simp only [List.append_assoc] at h
  obtain ⟨h1, h2⟩ := List.append_inj h (by simp)
  have hl : a.length = b.length := by
    have := congrArg valBE h1
    rwa [valBE_writeBE, valBE_writeBE, Nat.mod_eq_of_lt ha, Nat.mod_eq_of_lt hb] at this
  exact List.append_inj h2 hl

theorem lvEncode_some {a x : Bytes} (h : lvEncode a = some x) :
    a.length < 256 ^ 2 ∧ x = writeBE 2 a.length ++ a := by
  unfold lvEncode at h
  split at h
  · cases h; exact ⟨by unfold maxFieldBytes at *; omega, rfl⟩
  · cases h

theorem framePart_some {a x : Bytes} (h : framePart a = some x) :
    a.length < 256 ^ 4 ∧ x = writeBE 4 a.length ++ a := by
  unfold framePart at h
  split at h
  · cases h; exact ⟨by unfold maxContextPartBytes at *; omega, rfl⟩
  · cases h

/-- **`lv_encode` frames with one parse**: two framed fields followed by
anything are equal only if the fields and what follows are. -/
theorem lvEncode_prefix {a b x y r r' : Bytes} (hx : lvEncode a = some x) (hy : lvEncode b = some y)
    (h : x ++ r = y ++ r') : a = b ∧ r = r' := by
  obtain ⟨ha, rfl⟩ := lvEncode_some hx
  obtain ⟨hb, rfl⟩ := lvEncode_some hy
  exact prefixed_inj ha hb h

/-- **`lv_encode` refuses exactly the fields its prefix cannot hold.** -/
theorem lvEncode_none_iff (a : Bytes) : lvEncode a = none ↔ maxFieldBytes < a.length := by
  unfold lvEncode
  split <;> simp <;> omega

theorem framePart_prefix {a b x y r r' : Bytes} (hx : framePart a = some x) (hy : framePart b = some y)
    (h : x ++ r = y ++ r') : a = b ∧ r = r' := by
  obtain ⟨ha, rfl⟩ := framePart_some hx
  obtain ⟨hb, rfl⟩ := framePart_some hy
  exact prefixed_inj ha hb h

theorem encodePublicContext_some {s u v x : Bytes} (h : encodePublicContext s u v = some x) :
    ∃ fs fu fv, framePart s = some fs ∧ framePart u = some fu ∧ framePart v = some fv ∧
      x = fs ++ (fu ++ fv) := by
  unfold encodePublicContext at h
  cases hs : framePart s <;> cases hu : framePart u <;> cases hv : framePart v <;>
    simp [List.mapM_cons, hs, hu, hv] at h
  subst h
  exact ⟨_, _, _, rfl, rfl, rfl, by simp⟩

/-- **`EncodePublicContext` has one parse**, whatever follows it. -/
theorem encodePublicContext_prefix {s u v s' u' v' x x' r r' : Bytes}
    (h : encodePublicContext s u v = some x) (h' : encodePublicContext s' u' v' = some x')
    (he : x ++ r = x' ++ r') : s = s' ∧ u = u' ∧ v = v' ∧ r = r' := by
  obtain ⟨fs, fu, fv, hs, hu, hv, rfl⟩ := encodePublicContext_some h
  obtain ⟨fs', fu', fv', hs', hu', hv', rfl⟩ := encodePublicContext_some h'
  simp only [List.append_assoc] at he
  obtain ⟨e1, he⟩ := framePart_prefix hs hs' he
  obtain ⟨e2, he⟩ := framePart_prefix hu hu' he
  obtain ⟨e3, he⟩ := framePart_prefix hv hv' he
  exact ⟨e1, e2, e3, he⟩

/-- **The ADR-016 public context has one parse**: equal framed contexts come
from equal labels, nameplates, session identifiers and identities. -/
theorem publicContext_injective {l n s u v l' n' s' u' v' x : Bytes}
    (h : publicContext l n s u v = some x) (h' : publicContext l' n' s' u' v' = some x) :
    l = l' ∧ n = n' ∧ s = s' ∧ u = u' ∧ v = v' := by
  unfold publicContext at h h'
  cases hl : lvEncode l <;> cases hn : lvEncode n <;> cases he : encodePublicContext s u v <;>
    simp [hl, hn, he] at h
  cases hl' : lvEncode l' <;> cases hn' : lvEncode n' <;> cases he' : encodePublicContext s' u' v' <;>
    simp [hl', hn', he'] at h'
  rw [← h'] at h
  obtain ⟨e1, h⟩ := lvEncode_prefix hl hl' h
  obtain ⟨e2, h⟩ := lvEncode_prefix hn hn' h
  obtain ⟨e3, e4, e5, _⟩ := encodePublicContext_prefix (r := []) (r' := []) he he' (by simpa using h)
  exact ⟨e1, e2, e3, e4, e5⟩

/-- **Two rendezvous contexts are equal only for the same nameplate and the
same rendezvous**: the framing and `to_string`'s one spelling together. -/
theorem rendezvousContext_injective {n n' : Nat} {sid sid' x : Bytes}
    (hn : n < Nameplate.bound) (hn' : n' < Nameplate.bound)
    (h : rendezvousContext n sid = some x) (h' : rendezvousContext n' sid' = some x) :
    n = n' ∧ sid = sid' := by
  obtain ⟨_, e, e', _, _⟩ := publicContext_injective h h'
  refine ⟨?_, e'⟩
  have := congrArg Nameplate.parse e
  rwa [Nameplate.parse_toString hn, Nameplate.parse_toString hn', Option.some.injEq] at this

end Pondline.PakeCommon
