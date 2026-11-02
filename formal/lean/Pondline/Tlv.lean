import Pondline.Bytes

/-
A transcription of `packages/core/src/core/tlv.gleam`.

Every definition below mirrors one Gleam function, with the same branch order,
so that an input reaching a given error in Gleam reaches the same error here.
Where the Gleam code holds a `Dict(Int, BitArray)`, the model holds the
association list `parse` builds, in the order the records were read, which is
strictly increasing by type; `encode`'s sort is the identity on such a list.

The decoder side models `required` and `optional` reads with two field codecs,
`bytes` (accepts anything) and `u8` (exactly one byte), which is enough to
reach every error `locate` and `run` produce. `items`, `sequence`, `nested`
and `text` are not transcribed.
-/

namespace Pondline

/-- `tlv.TlvError`, without `TooManyItems` (only `sequence` raises it). -/
inductive TlvError where
  | truncated
  | nonMinimalBigSize
  | outOfOrder (tag : Nat)
  | inputTooLarge
  | unknownRequired (tag : Nat)
  | missingRequired (tag : Nat)
  | invalidField (tag : Nat)
  | invalidValue
  deriving DecidableEq, Repr

def maxU16 : Nat := 0xffff
def maxU32 : Nat := 0xffffffff
def maxU64 : Nat := 0xffffffffffffffff

/-! ## BigSize -/

/-- `encode_big_size`: the value clamped to the u64 range, in the narrowest
form. A negative Gleam `Int` clamps to zero, which is `Int.toNat`. -/
def encodeBigSize (value : Nat) : Bytes :=
  let v := min value maxU64
  if v < 0xfd then [v]
  else if v ≤ maxU16 then 0xfd :: writeBE 2 v
  else if v ≤ maxU32 then 0xfe :: writeBE 4 v
  else 0xff :: writeBE 8 v

/-- `encode_big_size` on a Gleam `Int`. -/
def encodeBigSizeInt (value : Int) : Bytes := encodeBigSize value.toNat

/-- One wide form: `n` payload bytes after the marker, accepted by `minimal`
only when the value exceeds `floor`, the largest the next-narrower form can
hold. -/
def wide (rest : Bytes) (n floor : Nat) : Except TlvError (Nat × Bytes) :=
  if rest.length < n then .error .truncated
  else if valBE (rest.take n) > floor then .ok (valBE (rest.take n), rest.drop n)
  else .error .nonMinimalBigSize

/-- `decode_big_size`. -/
def decodeBigSize : Bytes → Except TlvError (Nat × Bytes)
  | [] => .error .truncated
  | b :: rest =>
    if b = 0xff then wide rest 8 maxU32
    else if b = 0xfe then wide rest 4 maxU16
    else if b = 0xfd then wide rest 2 0xfc
    else .ok (b, rest)

/-! ## Streams -/

/-- A parsed stream: `(type, value)` records. -/
abbrev Records := List (Nat × Bytes)

theorem wide_shrinks {rest r : Bytes} {n floor v : Nat}
    (h : wide rest n floor = .ok (v, r)) : r.length ≤ rest.length := by
  unfold wide at h
  split at h
  · cases h
  · split at h
    · cases h; simp
    · cases h

theorem decodeBigSize_shrinks {l r : Bytes} {v : Nat}
    (h : decodeBigSize l = .ok (v, r)) : r.length < l.length := by
  cases l with
  | nil => cases h
  | cons b rest =>
    simp only [decodeBigSize] at h
    simp only [List.length_cons]
    split at h
    · have := wide_shrinks h; omega
    · split at h
      · have := wide_shrinks h; omega
      · split at h
        · have := wide_shrinks h; omega
        · cases h; omega

set_option linter.unusedVariables false in
/-- `parse_records`: reads records until the input is empty. The checks run in
the Gleam order: type, length, ascending, then the value's bounds. -/
def parseRecords (bits : Bytes) (previous : Int) : Except TlvError Records :=
  if bits = [] then .ok []
  else
    match h1 : decodeBigSize bits with
    | .error e => .error e
    | .ok (tag, rest1) =>
      match h2 : decodeBigSize rest1 with
      | .error e => .error e
      | .ok (length, rest2) =>
        if (tag : Int) > previous then
          if length > rest2.length then .error .truncated
          else
            match parseRecords (rest2.drop length) tag with
            | .error e => .error e
            | .ok recs => .ok ((tag, rest2.take length) :: recs)
        else .error (.outOfOrder tag)
termination_by bits.length
decreasing_by
  have := decodeBigSize_shrinks h1
  have := decodeBigSize_shrinks h2
  simp only [List.length_drop]
  omega

/-- `parse`: the limit first, then the records, starting below every type. -/
def parse (bytes : Bytes) (maxBytes : Int) : Except TlvError Records :=
  if (bytes.length : Int) > maxBytes then .error .inputTooLarge
  else parseRecords bytes (-1)

/-- One record's bytes, as `encode` writes it. -/
def encodeRecord (r : Nat × Bytes) : Bytes :=
  encodeBigSize r.1 ++ encodeBigSize r.2.length ++ r.2

/-- `encode_stream`: the records in order, each with minimal BigSizes. -/
def encodeRecords : Records → Bytes
  | [] => []
  | r :: rs => encodeRecord r ++ encodeRecords rs

/-! ## Builder -/

/-- `put`: the type clamped below at zero, replacing any earlier value. -/
def put (builder : Records) (tag : Int) (value : Bytes) : Records :=
  (tag.toNat, value) :: builder.filter (fun r => r.1 != tag.toNat)

/-- A builder made by a sequence of `put`s from `new()`. -/
def build (puts : List (Int × Bytes)) : Records :=
  puts.foldl (fun b p => put b p.1 p.2) []

/-- `encode`: the records sorted by type, then written out. -/
def encodeBuilder (builder : Records) : Bytes :=
  encodeRecords (builder.mergeSort (fun x y => decide (x.1 ≤ y.1)))

/-! ## Decoders -/

/-- The field codecs the model reads with. -/
inductive Codec where
  | bytes
  | u8
  deriving DecidableEq, Repr

/-- Whether a field's absence is an error. -/
inductive Want where
  | required
  | optional
  deriving DecidableEq, Repr

/-- One `required(tag, codec)` or `optional(tag, codec)` step of a decoder. -/
structure Entry where
  tag : Nat
  want : Want
  codec : Codec
  deriving DecidableEq, Repr

/-- A decoded field value. -/
inductive Value where
  | raw (b : Bytes)
  | int (n : Nat)
  deriving DecidableEq, Repr

/-- `tlv.bytes` and `tlv.u8`. -/
def Codec.read : Codec → Bytes → Except TlvError Value
  | .bytes, raw => .ok (.raw raw)
  | .u8, [b] => .ok (.int b)
  | .u8, _ => .error .invalidValue

/-- `locate`: names the type in a field codec's anonymous failure. -/
def locate (e : TlvError) (tag : Nat) : TlvError :=
  match e with
  | .invalidValue => .invalidField tag
  | e => e

/-- `dict.get` on records with distinct types. -/
def lookup (tag : Nat) : Records → Option Bytes
  | [] => none
  | (t, v) :: rs => if t = tag then some v else lookup tag rs

/-- `dict.delete`. -/
def erase (tag : Nat) (rs : Records) : Records := rs.filter (fun r => r.1 != tag)

/-- A decoder built from `required`/`optional` steps ending in `success`:
the values read, in step order, and the records not consumed. -/
def runSpec : List Entry → Records → Except TlvError (List (Nat × Option Value) × Records)
  | [], remaining => .ok ([], remaining)
  | e :: es, remaining =>
    match lookup e.tag remaining with
    | some raw =>
      match e.codec.read raw with
      | .error err => .error (locate err e.tag)
      | .ok v =>
        match runSpec es (erase e.tag remaining) with
        | .error err => .error err
        | .ok (vs, rem) => .ok ((e.tag, some v) :: vs, rem)
    | none =>
      match e.want with
      | .required => .error (.missingRequired e.tag)
      | .optional =>
        match runSpec es remaining with
        | .error err => .error err
        | .ok (vs, rem) => .ok ((e.tag, none) :: vs, rem)

/-- Whether a type is even, the "it's okay to be odd" test. -/
def isEven (r : Nat × Bytes) : Bool := r.1 % 2 == 0

/-- `run`: the decoder, then a failure naming the smallest even type it left
unread. The leftovers keep the stream's increasing order, so the first even
one is the smallest. -/
def runStream (spec : List Entry) (recs : Records) : Except TlvError (List (Nat × Option Value)) :=
  match runSpec spec recs with
  | .error e => .error e
  | .ok (vs, rem) =>
    match rem.find? isEven with
    | some r => .error (.unknownRequired r.1)
    | none => .ok vs

/-- `decode`: `parse` then `run`. -/
def decode (spec : List Entry) (bytes : Bytes) (maxBytes : Int) :
    Except TlvError (List (Nat × Option Value)) :=
  match parse bytes maxBytes with
  | .error e => .error e
  | .ok recs => runStream spec recs

end Pondline
