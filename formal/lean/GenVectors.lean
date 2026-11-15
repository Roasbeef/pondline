import Pondline

/-
Writes the conformance vectors `packages/core/test/core/formal_vectors_test.gleam`
replays against the real Gleam functions. Every expected value is computed
by the Lean definitions the theorems are about, so a vector that disagrees
with Gleam is a place where the proofs are about a different function.

One vector per line, fields separated by single spaces:

  bs.enc  <int> <hex>
  bs.dec  <hex> <result>                 result: ok:<value>:<rest hex> | err:<error>
  parse   <max> <hex> <result>           result: ok:<records> | err:<error>
  decode  <max> <hex> <spec> <result>    result: ok:<values> | err:<error>
  build   <puts> <hex>
  psize   <int> <bucket | none>
  pad     <rle> <rle | none>
  unwire  <rle> <rle | wire-refused | unpad-refused>
  offers  <expires_at> <now> <first> <shorter>
  due     <window> <kind> <stored_at> <retransmits> <deadline> <due | none>
  kem.enc <key hex> <draws> <encoded hex | err>
  kem.dec <encoded hex> <key hex | err>
  np.str  <int> <text | none>             from_int, then to_string
  np.parse <text hex> <int | none>
  code.idx <drawn hex> <indices>          the word indices generate picks
  lv      <rle> <rle | none>
  epc     <sid hex> <client hex> <server hex> <hex | none>
  pctx    <nameplate> <rendezvous hex> <hex>
  ell2    <int> <int>                     map_to_curve
  ell2.u  <hex> <hex | none>              decode_u_coordinate, map_to_curve, encode_u_coordinate

`-` is the empty byte string or the empty list. Records are `tag:hex`,
comma-separated; a decoder spec is `r<tag>:<b|u8>` (required) or
`o<tag>:<b|u8>` (optional); decoded values are `tag=n` (absent),
`tag=x<hex>` or `tag=i<int>`. An RLE byte string is `<byte hex>*<count>`
runs, comma-separated. Errors are `truncated`, `nonminimal`,
`outoforder.<tag>`, `toolarge`, `unknownreq.<tag>`, `missingreq.<tag>`,
`invalidfield.<tag>` and `invalidvalue`.
-/

open Pondline

/-! ## Rendering -/

def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)

def hexByte (b : Nat) : String := String.ofList [hexDigit (b / 16 % 16), hexDigit (b % 16)]

def hex (l : Bytes) : String :=
  if l.isEmpty then "-" else String.join (l.map hexByte)

def commas (l : List String) : String :=
  if l.isEmpty then "-" else String.intercalate "," l

def renderError : TlvError → String
  | .truncated => "truncated"
  | .nonMinimalBigSize => "nonminimal"
  | .outOfOrder t => s!"outoforder.{t}"
  | .inputTooLarge => "toolarge"
  | .unknownRequired t => s!"unknownreq.{t}"
  | .missingRequired t => s!"missingreq.{t}"
  | .invalidField t => s!"invalidfield.{t}"
  | .invalidValue => "invalidvalue"

def renderRecords (recs : Records) : String :=
  commas (recs.map fun r => s!"{r.1}:{hex r.2}")

def renderEntry (e : Entry) : String :=
  let w := match e.want with | .required => "r" | .optional => "o"
  let c := match e.codec with | .bytes => "b" | .u8 => "u8"
  s!"{w}{e.tag}:{c}"

def renderValue : Nat × Option Value → String
  | (t, none) => s!"{t}=n"
  | (t, some (.raw b)) => s!"{t}=x{hex b}"
  | (t, some (.int n)) => s!"{t}=i{n}"

/-- Run-length runs of a byte string, front to back (a left fold, so a
256 KiB padded ciphertext does not exhaust the stack). -/
def runs (l : Bytes) : List (Nat × Nat) :=
  (l.foldl (fun acc b =>
    match acc with
    | (b', n) :: rs => if b = b' then (b', n + 1) :: rs else (b, 1) :: (b', n) :: rs
    | [] => [(b, 1)]) []).reverse

def rle (l : Bytes) : String := commas ((runs l).map fun (b, n) => s!"{hexByte b}*{n}")

def renderKind : Kind → String
  | .application => "application"
  | .control => "control"
  | .receipt => "receipt"
  | .handshake => "handshake"

/-! ## A deterministic generator -/

structure Rng where
  state : Nat

def Rng.next (g : Rng) : Nat × Rng :=
  let s := (g.state * 6364136223846793005 + 1442695040888963407) % 2 ^ 64
  (s / 2 ^ 16, ⟨s⟩)

/-- A number below `n`. -/
def Rng.below (g : Rng) (n : Nat) : Nat × Rng :=
  let (x, g) := g.next
  (x % n, g)

def Rng.bytes (g : Rng) : Nat → Bytes × Rng
  | 0 => ([], g)
  | n + 1 =>
    let (b, g) := g.below 256
    let (rest, g) := g.bytes n
    (b :: rest, g)

/-- A number of a random magnitude, so every BigSize width is exercised. -/
def Rng.wideNat (g : Rng) : Nat × Rng :=
  let (w, g) := g.below 5
  let bound := match w with
    | 0 => 0xfd | 1 => 0x10000 | 2 => 0x100000000 | 3 => 2 ^ 64 | _ => 300
  g.below bound

/-! ## Vector groups -/

def bigSizeEncode : List String := Id.run do
  let fixed : List Int := [0, 1, 0xfc, 0xfd, 0xfe, 0xff, 0x100, 0xfffe, 0xffff, 0x10000,
    0x10001, 0xfffffffe, 0xffffffff, 0x100000000, 0x100000001, 2 ^ 64 - 2, 2 ^ 64 - 1,
    2 ^ 64, 2 ^ 64 + 5, 2 ^ 70, -1, -2 ^ 70]
  let mut values := fixed ++ (List.range 300).map Int.ofNat
  let mut g : Rng := ⟨1⟩
  for _ in [0:200] do
    let (v, g') := g.wideNat
    g := g'
    values := values ++ [Int.ofNat v]
  return values.map fun v => s!"bs.enc {v} {hex (encodeBigSizeInt v)}"

def renderBigSize (l : Bytes) : String :=
  match decodeBigSize l with
  | .ok (v, rest) => s!"bs.dec {hex l} ok:{v}:{hex rest}"
  | .error e => s!"bs.dec {hex l} err:{renderError e}"

def bigSizeDecode : List String := Id.run do
  let mut inputs : List Bytes := [[]]
  -- Every one-byte input, and every two-byte input whose first byte is a
  -- marker or a boundary value.
  for b in List.range 256 do
    inputs := inputs ++ [[b]]
  for b in [0x00, 0x07, 0xfc, 0xfd, 0xfe, 0xff] do
    for c in List.range 256 do
      inputs := inputs ++ [[b, c]]
  -- `0xfd` with the payloads around the minimality floor and the top.
  for v in List.range 0x200 ++ (List.range 0x100).map (· + 0xff00) do
    inputs := inputs ++ [0xfd :: writeBE 2 v]
  -- `0xfe` and `0xff` around their floors and tops, and with trailing bytes.
  for v in [0, 1, 0xfc, 0xfd, 0xfffe, 0xffff, 0x10000, 0x10001, 0xfffffffe, 0xffffffff] do
    inputs := inputs ++ [0xfe :: writeBE 4 v, 0xfe :: writeBE 4 v ++ [9, 9]]
  for v in [0, 0xfc, 0xffff, 0xffffffff, 0x100000000, 0x100000001, 2 ^ 64 - 1] do
    inputs := inputs ++ [0xff :: writeBE 8 v, 0xff :: writeBE 8 v ++ [7]]
  -- Every truncation of each wide form.
  for (m, n) in [(0xfd, 2), (0xfe, 4), (0xff, 8)] do
    for k in List.range n do
      inputs := inputs ++ [m :: List.replicate k 0xab]
  -- Random encodings of random values, with a random tail.
  let mut g : Rng := ⟨2⟩
  for _ in [0:300] do
    let (v, g1) := g.wideNat
    let (k, g2) := g1.below 3
    let (tail, g3) := g2.bytes k
    g := g3
    inputs := inputs ++ [encodeBigSize v ++ tail]
  return inputs.map renderBigSize

def renderParse (max : Int) (l : Bytes) : String :=
  match parse l max with
  | .ok recs => s!"parse {max} {hex l} ok:{renderRecords recs}"
  | .error e => s!"parse {max} {hex l} err:{renderError e}"

/-- Every string over `alphabet` of length at most `n`. -/
def strings (alphabet : List Nat) : Nat → List Bytes
  | 0 => [[]]
  | n + 1 => [[]] ++ (strings alphabet n).flatMap (fun s => alphabet.map (fun a => a :: s))

/-- A random record list, sometimes with types past one byte. -/
def randomRecords (g : Rng) : Records × Rng := Id.run do
  let (count, g) := g.below 5
  let mut g := g
  let mut tag := 0
  let mut recs : Records := []
  for _ in [0:count] do
    let (wideTag, g1) := g.below 4
    let (step, g2) := if wideTag == 0 then g1.wideNat else g1.below 4
    let (len, g3) := g2.below 4
    let (value, g4) := g3.bytes len
    g := g4
    tag := tag + step + (if recs.isEmpty then 0 else 1)
    if tag ≤ maxU64 then
      recs := recs ++ [(tag, value)]
  return (recs, g)

def parseVectors : List String := Id.run do
  let mut out : List String := []
  -- Exhaustive over a small alphabet: the markers, small types, and 0xff.
  for s in strings [0x00, 0x01, 0x02, 0x03, 0xfd, 0xff] 4 do
    out := out ++ [renderParse s.length s]
  -- The bound: one byte over the limit, a negative limit.
  for s in strings [0x01, 0x02] 3 do
    out := out ++ [renderParse (s.length - 1 : Int) s, renderParse (-1) s]
  -- Random well-formed streams, each also mutated: a repeated record, two
  -- records swapped, every truncation, a non-minimal type, a non-minimal
  -- length.
  let mut g : Rng := ⟨3⟩
  for _ in [0:250] do
    let (recs, g') := randomRecords g
    g := g'
    let bytes := encodeRecords recs
    out := out ++ [renderParse bytes.length bytes]
    match recs with
    | r :: rest =>
      out := out ++ [renderParse 4096 (encodeRecords (r :: r :: rest))]
      out := out ++ [renderParse 4096 (encodeRecord r ++ [0xfd, 0x00, r.2.length] ++ r.2 ++ encodeRecords rest)]
      out := out ++ [renderParse 4096 ([0xfe] ++ writeBE 4 r.1 ++ encodeBigSize r.2.length ++ r.2 ++ encodeRecords rest)]
      match rest with
      | r2 :: rest2 => out := out ++ [renderParse 4096 (encodeRecords (r2 :: r :: rest2))]
      | [] => pure ()
    | [] => pure ()
    if bytes.length ≤ 12 then
      for k in List.range bytes.length do
        out := out ++ [renderParse 4096 (bytes.take k)]
  -- A hostile length: a u64 length on a short input.
  out := out ++ [renderParse 4096 ([0x01, 0xff] ++ writeBE 8 (2 ^ 64 - 1) ++ [1, 2, 3])]
  return out

def specs : List (List Entry) := [
  [],
  [⟨1, .optional, .bytes⟩],
  [⟨0, .required, .u8⟩, ⟨1, .optional, .bytes⟩],
  [⟨2, .required, .bytes⟩, ⟨3, .optional, .u8⟩, ⟨4, .optional, .bytes⟩],
  (List.range 6).map (fun t => ⟨t, .optional, .bytes⟩),
  [⟨5, .required, .u8⟩],
  [⟨3, .optional, .u8⟩, ⟨1, .required, .bytes⟩],
  [⟨4, .optional, .u8⟩, ⟨4, .optional, .bytes⟩]
]

def decodeVectors : List String := Id.run do
  let mut out : List String := []
  for mask in List.range 64 do
    for style in List.range 3 do
      let recs : Records := (List.range 6).filterMap fun t =>
        if mask / 2 ^ t % 2 == 1 then
          some (t, match style with | 0 => [t] | 1 => [] | _ => [t, 0xee])
        else none
      let bytes := encodeRecords recs
      for spec in specs do
        let rendered := match decode spec bytes bytes.length with
          | .ok vs => s!"ok:{commas (vs.map renderValue)}"
          | .error e => s!"err:{renderError e}"
        out := out ++ [s!"decode {bytes.length} {hex bytes} {commas (spec.map renderEntry)} {rendered}"]
  return out

def renderPuts (puts : List (Int × Bytes)) : String :=
  commas (puts.map fun p => s!"{p.1}:{hex p.2}")

def buildVectors : List String := Id.run do
  let fixed : List (List (Int × Bytes)) := [
    [],
    [(1, [7]), (1, [8])],
    [(4, []), (2, [1])],
    [(-5, [1]), (0, [2])],
    [(0xfd, [1]), (0xfc, [2]), (0x10000, [3])],
    [(2 ^ 64 - 1, [1])],
    [(2 ^ 64, []), (2 ^ 64 + 1, [])]
  ]
  let mut cases := fixed
  let mut g : Rng := ⟨4⟩
  for _ in [0:150] do
    let (n, g1) := g.below 6
    g := g1
    let mut puts : List (Int × Bytes) := []
    for _ in [0:n] do
      let (small, g2) := g.below 3
      let (t, g3) := if small == 0 then g2.wideNat else g2.below 6
      let (len, g4) := g3.below 3
      let (v, g5) := g4.bytes len
      g := g5
      puts := puts ++ [(Int.ofNat t, v)]
    cases := cases ++ [puts]
  let mut out : List String := []
  for puts in cases do
    let bytes := encodeBuilder (build puts)
    out := out ++ [s!"build {renderPuts puts} {hex bytes}", renderParse bytes.length bytes]
  return out

def paddedSizeVectors : List String := Id.run do
  let mut sizes : List Int := (List.range 11).map (fun (n : Nat) => (n : Int) - 5)
  for b in paddingBuckets do
    for d in [-3, -2, -1, 0, 1, 2, 3] do
      sizes := sizes ++ [(b : Int) + d]
  sizes := sizes ++ [300000, 2 ^ 40, -2 ^ 40]
  let mut g : Rng := ⟨5⟩
  for _ in [0:100] do
    let (s, g') := g.below 270000
    g := g'
    sizes := sizes ++ [(s : Int)]
  return sizes.map fun s =>
    s!"psize {s} {match paddedSize s with | some b => toString b | none => "none"}"

/-- A ciphertext of `n` bytes in a few runs, so its RLE stays short. -/
def sealedOf (n seed : Nat) : Bytes :=
  if n ≤ 24 then (List.range n).map (fun i => (i * 37 + seed * 11 + 5) % 256)
  else
    let a := n / 3
    List.replicate a ((seed * 7 + 1) % 256) ++ List.replicate (n - 2 * a) 0 ++
      List.replicate a ((seed * 13 + 200) % 256)

def padVectors : List String := Id.run do
  let mut lengths : List Nat := List.range 9
  for b in paddingBuckets do
    for d in [0, 1, 2, 3, 4, 5, 6] do
      lengths := lengths ++ [b + 2 - d]
  lengths := lengths ++ [300000]
  let mut out : List String := []
  for (n, i) in lengths.zipIdx do
    let sealed := sealedOf n i
    let result := match pad sealed with | some p => rle p | none => "none"
    out := out ++ [s!"pad {rle sealed} {result}"]
  return out

def unwireVectors : List String := Id.run do
  let mut inputs : List Bytes := [[], [0], [0, 0, 0], [0, 0, 0, 0]]
  for b in paddingBuckets do
    inputs := inputs ++ [List.replicate (b - 1) 0, List.replicate (b + 1) 0]
    let restLen := b - 4
    for len in [0, 1, 2, restLen - 1, restLen, restLen + 1, 2 ^ 32 - 1] do
      inputs := inputs ++ [writeBE 4 len ++ List.replicate (restLen / 2) 0x5a ++
        List.replicate (restLen - restLen / 2) 0xc3]
  return inputs.map fun w =>
    let result := match fromWire w with
      | none => "wire-refused"
      | some p => match unpad p with
        | some s => rle s
        | none => "unpad-refused"
    s!"unwire {rle w} {result}"

def renderOffers (e n : Int) : String :=
  let (first, shorter) := offers e n
  s!"offers {e} {n} {first} {commas (shorter.map toString)}"

def offersVectors : List String := Id.run do
  let mut out : List String := []
  for n in [0, 1000000000, -500] do
    for d in List.range 304 do
      out := out ++ [renderOffers (n + (d : Int) - 3) n]
    for d in [75149, 75150, 75151, 150300, 300600, 601199, 601200, 601201, 604800, 1209600, 2 ^ 40] do
      out := out ++ [renderOffers (n + d) n]
  let mut g : Rng := ⟨6⟩
  for _ in [0:300] do
    let (n, g1) := g.below 4000000000
    let (d, g2) := g1.below 1300000
    g := g2
    out := out ++ [renderOffers ((n : Int) + d - 1000) n]
  return out

def renderDue (w : Int) (kind : Kind) (t k d : Int) : String :=
  let result := match dueAt w kind t k d with | some u => toString u | none => "none"
  s!"due {w} {renderKind kind} {t} {k} {d} {result}"

def dueVectors : List String := Id.run do
  let mut out : List String := []
  let kinds := [Kind.application, .control, .receipt, .handshake]
  for w in [0, 1, 60, 3600] do
    for kind in kinds do
      for k in [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7] do
        let t : Int := 1000000000
        let due := t + w * shiftOne k
        for d in [due - 1, due, due + 1, t + 10 ^ 9] do
          out := out ++ [renderDue w kind t k d]
  let mut g : Rng := ⟨7⟩
  for _ in [0:300] do
    let (wi, g1) := g.below 4
    let (ki, g2) := g1.below 4
    let (k, g3) := g2.below 9
    let (t, g4) := g3.below 4000000000
    let (d, g5) := g4.below 200000
    g := g5
    let w : Int := match wi with | 0 => 3600 | 1 => 60 | 2 => 1 | _ => 7200
    out := out ++ [renderDue w (kinds.getD ki .application) t ((k : Int) - 1) ((t : Int) + d)]
  return out

/-! ## Kemeleon -/

/-- ByteEncode_12 of a coefficient list (pairs, three bytes each); used only
to build inputs, never to compute an expected value. -/
def byteEncode12 : List Nat → Bytes
  | a :: b :: rest => [a % 256, a / 256 % 16 + 16 * (b % 16), b / 16 % 256] ++ byteEncode12 rest
  | _ => []

/-- A uniformly distributed number of `48 * k` bits. -/
def Rng.big (g : Rng) : Nat → Nat × Rng
  | 0 => (0, g)
  | k + 1 =>
    let (x, g) := g.next
    let (rest, g) := g.big k
    (rest * 2 ^ 48 + x, g)

def Rng.coefficients (g : Rng) (n bound : Nat) : List Nat × Rng := Id.run do
  let mut g := g
  let mut out : List Nat := []
  for _ in [0:n] do
    let (c, g') := g.below bound
    g := g'
    out := out ++ [c]
  return (out, g)

def renderEncode (key : Bytes) (draws : List Nat) : String :=
  let result := match Kemeleon.encode key draws with | some e => hex e | none => "err"
  s!"kem.enc {hex key} {commas (draws.map toString)} {result}"

def renderDecode (encoded : Bytes) : String :=
  let result := match Kemeleon.decode encoded with | some k => hex k | none => "err"
  s!"kem.dec {hex encoded} {result}"

def kemeleonVectors : List String := Id.run do
  let zeroPoly := List.replicate 384 0
  let maxPoly := byteEncode12 (List.replicate 256 3328)
  -- The polynomial whose value is 2^3128 mod 3329^256, the one point where
  -- the draft's range (`draftRange`) admits one multiple more than fits: its
  -- top multiple is now out of range and reduces, and the code's own top
  -- multiple round-trips.
  let star := Kemeleon.ceiling % Kemeleon.span
  let starPoly := Kemeleon.vectorDecode star
  let starTop := Kemeleon.draftRange star - 1
  let starTopInRange := Kemeleon.range star - 1
  let seedA := List.replicate 32 0xab
  let mut g : Rng := ⟨8⟩
  let mut cases : List (Bytes × List Nat) := [
    (zeroPoly ++ zeroPoly ++ zeroPoly ++ zeroPoly ++ List.replicate 32 0, [0, 0, 0, 0]),
    (zeroPoly ++ zeroPoly ++ zeroPoly ++ zeroPoly ++ seedA,
      [Kemeleon.range 0 - 1, Kemeleon.range 0, 2 ^ 384 - 1, 1]),
    (maxPoly ++ maxPoly ++ maxPoly ++ maxPoly ++ List.replicate 32 0xff,
      [0, Kemeleon.range (Kemeleon.span - 1) - 1, Kemeleon.range (Kemeleon.span - 1), 2 ^ 384 - 1]),
    (starPoly ++ zeroPoly ++ maxPoly ++ starPoly ++ seedA, [starTop, 0, 0, starTopInRange]),
    (zeroPoly ++ starPoly ++ starPoly ++ zeroPoly ++ seedA, [0, starTop + Kemeleon.range star, starTop - 1, 7])
  ]
  -- Random keys with every coefficient in range, under random 384-bit draws.
  for _ in [0:6] do
    let (cs, g1) := g.coefficients 1024 3329
    let (seed, g2) := g1.bytes 32
    let (d1, g3) := g2.big 8
    let (d2, g4) := g3.big 8
    let (d3, g5) := g4.big 3
    let (d4, g6) := g5.big 8
    g := g6
    cases := cases ++ [(byteEncode12 cs ++ seed, [d1, d2, d3, d4])]
  -- Keys a coefficient of 3329 or more makes invalid, at both positions of
  -- a pair, and keys of the wrong length.
  let (cs, g1) := g.coefficients 1024 3329
  g := g1
  let valid := byteEncode12 cs ++ seedA
  let bad (i v : Nat) : Bytes := byteEncode12 (cs.set i v) ++ seedA
  cases := cases ++ [(valid, [1, 2, 3, 4]), (bad 256 3329, [1, 2, 3, 4]), (bad 1023 3329, [1, 2, 3, 4]),
    (bad 512 3328, [1, 2, 3, 4]), (bad 5 4095, [1, 2, 3, 4]), (valid.take 1567, [1, 2, 3, 4]),
    (valid ++ [0], [1, 2, 3, 4])]
  let mut out : List String := []
  let mut encoded : List Bytes := []
  for (key, draws) in cases do
    out := out ++ [renderEncode key draws]
    match Kemeleon.encode key draws with
    | some e => encoded := encoded ++ [e]
    | none => pure ()
  -- Every encoding decodes; so do arbitrary strings of the right length.
  let mut inputs : List Bytes := encoded ++ [List.replicate 1596 0, List.replicate 1596 0xff]
  for _ in [0:4] do
    let (e, g') := g.bytes 1596
    g := g'
    inputs := inputs ++ [e]
  inputs := inputs ++ [[], List.replicate 1595 0, List.replicate 1597 0]
  return out ++ inputs.map renderDecode

/-! ## Nameplates, word indices and framing -/

def ascii (s : String) : Bytes := s.toUTF8.toList.map (·.toNat)

def text (l : Bytes) : String := String.ofList (l.map Char.ofNat)

def nameplateVectors : List String := Id.run do
  let mut values : List Int := (List.range 125).map (fun (n : Nat) => (n : Int) - 3)
  values := values ++ [999, 1000, 1001, 99999, 100000, 999998, 999999, 1000000, 1000001, 10 ^ 12, -10 ^ 12]
  let mut g : Rng := ⟨9⟩
  for _ in [0:150] do
    let (v, g') := g.below 1000000
    g := g'
    values := values ++ [(v : Int)]
  let mut out : List String := []
  let mut texts : List Bytes := []
  for v in values do
    match Nameplate.fromInt v with
    | some n =>
      out := out ++ [s!"np.str {v} {text (Nameplate.toString n)}"]
      texts := texts ++ [Nameplate.toString n]
    | none => out := out ++ [s!"np.str {v} none"]
  -- Every printable ASCII byte at every position of a valid spelling, and
  -- shapes that are near one: a sign, a space, a short or long spelling,
  -- multi-byte characters whose byte count is six.
  for i in List.range 6 do
    for b in (List.range 95).map (· + 0x20) do
      texts := texts ++ [(ascii "048271").set i b]
  texts := texts ++ ["", "0", "42", "00042", "0000042", "+00042", "-00042", " 00042", "00042 ",
    "00042\n", "4827190", "١٢٣", "é4827", "000000", "999999"].map ascii
  for t in texts do
    let result := match Nameplate.parse t with | some n => toString n | none => "none"
    out := out ++ [s!"np.parse {hex t} {result}"]
  return out

def indexVectors : List String := Id.run do
  let mut inputs : List Bytes := [List.replicate 5 0, List.replicate 5 0xff,
    [], [0x80], [0xff, 0xff], [0xff, 0xff, 0xff, 0xff], [0xff, 0xff, 0xff, 0xff, 0x7f, 0x12]]
  for bit in List.range 40 do
    inputs := inputs ++ [writeBE 5 (2 ^ bit)]
  let mut g : Rng := ⟨10⟩
  for _ in [0:150] do
    let (b, g') := g.bytes 5
    g := g'
    inputs := inputs ++ [b]
  return inputs.map fun b => s!"code.idx {hex b} {commas ((PairingCode.indices b).map toString)}"

def framingVectors : List String := Id.run do
  let mut out : List String := []
  for n in [0, 1, 2, 3, 255, 256, 65534, 65535, 65536, 70000] do
    let field := List.replicate (n / 2) 0x5a ++ List.replicate (n - n / 2) 0xc3
    let result := match PakeCommon.lvEncode field with | some x => rle x | none => "none"
    out := out ++ [s!"lv {rle field} {result}"]
  let mut g : Rng := ⟨11⟩
  for _ in [0:60] do
    let (a, g1) := g.below 4
    let (b, g2) := g1.below 4
    let (c, g3) := g2.below 20
    let (s, g4) := g3.bytes (a * 5)
    let (u, g5) := g4.bytes b
    let (v, g6) := g5.bytes c
    g := g6
    let result := match PakeCommon.encodePublicContext s u v with | some x => hex x | none => "none"
    out := out ++ [s!"epc {hex s} {hex u} {hex v} {result}"]
  for n in [0, 1, 42, 99999, 482719, 999999] do
    for _ in [0:4] do
      let (sid, g') := g.bytes 16
      g := g'
      let result := match PakeCommon.rendezvousContext n sid with | some x => hex x | none => "none"
      out := out ++ [s!"pctx {n} {hex sid} {result}"]
  return out

/-! ## Elligator 2 -/

def hexBytes (s : String) : Bytes :=
  let digit (c : Char) : Nat := if c.isDigit then c.toNat - 48 else c.toLower.toNat - 87
  let rec go : List Char → Bytes
    | a :: b :: rest => (digit a * 16 + digit b) :: go rest
    | _ => []
  go s.toList

def elligatorVectors : List String := Id.run do
  let p := Elligator2.p
  let mut values : List Int := [0, 1, 2, 3, 4, 5, p - 1, p - 2, p, p + 1, p + 18, 2 * p, -1, -2, -p,
    -p - 1, 2 ^ 255 - 1, 2 ^ 255, 2 ^ 256, -2 ^ 256, (p - 1) / 2, (p + 1) / 2,
    0x1234567890ABCDEF * 2 ^ 100, Elligator2.curveA, -Elligator2.curveA]
  let mut g : Rng := ⟨12⟩
  for _ in [0:120] do
    let (r, g') := g.big 6
    g := g'
    let r : Int := ((r % 2 ^ 255 : Nat) : Int)
    values := values ++ [r, p - r]
  let mut out := values.map fun r => s!"ell2 {r} {Elligator2.mapToCurve r}"
  -- cpace-21 B.1.1's hash and its field element, then arbitrary strings.
  let mut inputs : List Bytes := [
    hexBytes "03998087BDB1A2617BBE25EF5A7C18CD4F84F902328701790958755EE4AED1D3",
    hexBytes "03998087BDB1A2617BBE25EF5A7C18CD4F84F902328701790958755EE4AED153",
    List.replicate 32 0, List.replicate 32 0xff, [9] ++ List.replicate 31 0,
    List.replicate 31 0, List.replicate 33 0, []]
  for _ in [0:40] do
    let (b, g') := g.bytes 32
    g := g'
    inputs := inputs ++ [b]
  for b in inputs do
    let result := match Elligator2.decodeU b with
      | some r => hex (Elligator2.encodeU (Elligator2.mapToCurve r))
      | none => "none"
    out := out ++ [s!"ell2.u {hex b} {result}"]
  return out

def main : IO Unit := do
  IO.println "# Conformance vectors generated by formal/lean (lake exe gen-vectors)."
  IO.println "# DO NOT EDIT. Regenerate with formal/lean/check.sh --write."
  let groups := [bigSizeEncode, bigSizeDecode, parseVectors, decodeVectors, buildVectors,
    paddedSizeVectors, padVectors, unwireVectors, offersVectors, dueVectors, kemeleonVectors,
    nameplateVectors, indexVectors, framingVectors, elligatorVectors]
  for group in groups do
    for line in group do
      IO.println line
