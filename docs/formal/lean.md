# Lean proofs for the pure core

`formal/lean` holds Lean 4 proofs about pure parts of `packages/core`: the
TLV codec, the padding buckets, the retention deadlines a sender offers, the
retransmit schedule, and the arithmetic of spoken pairing codes (ADR-016):
Kemeleon, the nameplate's spelling, the word indices `generate` draws, the
PAKE's length framing, and the Elligator 2 map. Each proof is about a Lean transcription of the
Gleam function, written to follow the Gleam code branch for branch with the
same constants. The proofs only say something about the Gleam code if the two
agree, so the Lean build also writes conformance vectors that a Gleam test
replays against the real functions. This document covers what is proved, how
the vectors close the gap between the two languages, how to rebuild, and which
Gleam changes need the Lean side updated.

## Layout and rebuilding

| Path | What it holds |
| --- | --- |
| `formal/lean/Pondline/Bytes.lean` | Byte strings as `List Nat`, big-endian reads and writes, and their lemmas. |
| `formal/lean/Pondline/Tlv.lean` | The transcription of `core/tlv.gleam`. |
| `formal/lean/Pondline/TlvProofs.lean` | BigSize and stream round trips, canonicality, the input bound. |
| `formal/lean/Pondline/TlvDecode.lean` | Unknown even and odd types, and the `Builder`. |
| `formal/lean/Pondline/Padding.lean` | `limits.padded_size` and `envelope.pad`, `unpad`, `from_wire`. |
| `formal/lean/Pondline/Retention.lean` | `retention.offers` and the ADR-008 and ADR-006 addendum claims. |
| `formal/lean/Pondline/Retransmit.lean` | `retransmit.due_at` and the ADR-006 schedule claims. |
| `formal/lean/Pondline/Kemeleon.lean` | `kemeleon.encode` and `decode`: round trip, totality, range, counting. |
| `formal/lean/Pondline/Nameplate.lean` | `nameplate.from_int`, `parse`, `to_string`: one spelling per nameplate. |
| `formal/lean/Pondline/PairingCode.lean` | `pairing_code.generate`'s `read_indices`: no modulo bias. |
| `formal/lean/Pondline/PakeCommon.lean` | `pake_common.lv_encode`, `encode_public_context`, `rendezvous.public_context`: one parse. |
| `formal/lean/Pondline/Elligator2.lean` | `elligator2.map_to_curve` and the u-coordinate conversions: reduced output, evenness. |
| `formal/lean/GenVectors.lean` | The vector generator; its header documents the line format. |
| `formal/lean/Axioms.lean` | `#print axioms` for every main theorem. |
| `formal/lean/check.sh` | The gate. |
| `packages/core/test/core/formal_vectors.txt` | The generated vectors (do not edit). |
| `packages/core/test/core/formal_vectors_test.gleam` | Replays the vectors against the Gleam functions. |

The project uses core Lean only, with no Mathlib and no dependencies, so it
builds offline. `lean-toolchain` pins `leanprover/lean4:v4.34.1`. Run:

```
formal/lean/check.sh            # build, check axioms, diff the vectors
formal/lean/check.sh --write    # the same, but rewrite the committed vectors
cd packages/core && gleam test  # replays the vectors against Gleam
```

`check.sh` fails if any source contains `sorry`, `admit`, a declared `axiom`,
`native_decide`, `implemented_by` or `@[extern]`; if `lake build` fails; if
any theorem in `Axioms.lean` depends on an axiom other than `propext`,
`Classical.choice` and `Quot.sound`; or if the regenerated vectors differ from
the committed file. A cold run (no `.lake/build`) takes about 12 seconds and
a warm one under 2. Kernel arithmetic on the Kemeleon constants
(`3329^256`, `2^3128`) is checked with `decide +kernel`, which asks the
kernel, not compiled code, to evaluate the comparison; it adds no axiom, and
`check.sh` still refuses `native_decide`.

## What is proved

Each theorem below is stated about the transcription. Byte strings are
`List Nat`; `Bytes.Valid l` says every element is below 256, which every real
`BitArray` satisfies. Instants are `Int` seconds, as in `core/time`.

### TLV and BigSize (`core/tlv.gleam`)

- `decodeBigSize_encode`: for every `v ≤ 2^64 - 1` and any `rest`,
  `decodeBigSize (encodeBigSize v ++ rest) = ok (v, rest)`. Every value in
  the u64 range decodes from its encoding, whatever follows it.
- `decodeBigSize_canonical`: if `l` is valid and `decodeBigSize l = ok (v, r)`
  then `l = encodeBigSize v ++ r` and `v ≤ 2^64 - 1`. An accepted BigSize is
  the minimal encoding of its value, so a non-minimal one is never accepted.
- `parseRecords_encode` and `parse_encode`: a record list whose types strictly
  increase, whose types and lengths fit a u64 and whose values are byte
  strings (`RecsOk`) parses from its encoding, given the input fits
  `max_bytes`.
- `parseRecords_canonical`: if `bits` is valid and `parseRecords bits prev =
  ok recs`, then `encodeRecords recs = bits` and `RecsOk prev recs`. Every
  accepted stream re-encodes byte for byte, and its types strictly increase,
  which rules out duplicates.
- `parse_injective`: two valid byte strings that `parse` accepts with the same
  records are equal. This is the module's "one encoding per set of records".
- `parse_bound`: if `parse bytes max = ok _` then `bytes.length ≤ max`.
- `decode_fail_closed`: if `decode spec bytes max = ok _`, every even type in
  the parsed stream is a type the decoder reads.
- `runStream_odd_ignored`: removing every record whose type is odd and not
  read by the decoder does not change the result of `run`.
- `builder_accepted`: for any sequence of `put`s whose types are at most
  `2^64 - 1` and whose values are byte strings no longer than that,
  `parse (encode builder) max` accepts and returns the builder's records
  sorted by type.
- `builder_overflow_rejected`: `put(2^64, <<>>)` then `put(2^64 + 1, <<>>)`
  encodes to twenty bytes that `parse` refuses with `OutOfOrder(2^64 - 1)`.
  See the findings below.

Totality needs no theorem: Lean accepts `parseRecords` only with a
termination proof (each record consumes at least two bytes), and every other
definition is structural, so the decoder returns on every input.

### Padding (`core/limits.gleam`, `core/envelope.gleam`)

- `largest_bucket`: the last bucket is `max_ciphertext_bytes` and every bucket
  is at most that.
- `paddedSize_isSome`: `padded_size size` is defined exactly when
  `size ≤ max_ciphertext_bytes`.
- `paddedSize_spec`: a returned bucket is one of the buckets, at least the
  size, and the smallest bucket that holds it.
- `paddedSize_mono`: if `s ≤ t` and `t` has a padded size `bt`, then `s` has
  one no larger than `bt`.
- `pad_spec`: if `pad sealed = some p`, then `p`'s length is a bucket and is
  `padded_size (length + 4)`, `unpad p = some sealed`, and
  `from_wire p = some p`.
- `pad_none_iff`: `pad` fails exactly when `length + 4 > max_ciphertext_bytes`.
- `fromWire_spec`: `from_wire` accepts exactly the bucket sizes.

### Retention offers (`core/retention.gleam`, ADR-008)

`accepted d m` is the mailbox's rule in `mailbox/service.insert_new`: `m < d`
and `d ≤ m + message_retention_seconds`. `allOffers` is the first offer
followed by the shorter ones.

- `offers_length`: there are at most `max_deadline_offers` offers.
- `offers_window`: if `now < expires_at`, every offer `d` has
  `now < d ≤ expires_at`.
- `offers_decreasing`: the offers strictly decrease.
- `offers_full`: for a row whose deadline is at least 601 200 seconds away,
  the offers are `now` plus 601 200, 300 600, 150 300 and 75 150 seconds
  (167 h, 83.5 h, 41.75 h and 20.875 h), the "about 21 hours" of ADR-008.
- `slack_accepted_first` and `slack_tight`: a mailbox whose clock trails by
  `s` with `0 ≤ s ≤ retention_slack_seconds` accepts the first offer; one
  second more and a full-lifetime first offer is refused.
- `reach_accepted`: if `now < expires_at` and `0 ≤ s ≤ 604 800 - 75 150`
  (529 650 seconds, about 6.13 days), some offer is accepted by a mailbox
  whose clock reads `now - s`.
- `six_days_accepted`: the same for `s ≤ 6 × 86 400`. This is ADR-008's "a
  sender up to about six days ahead".
- `reach_tight`: one second past 529 650, a full-lifetime row meets no
  accepted offer, so the reach is exact.
- `offers_at_deadline_refused`: `offers(now, now) = (now, [])`, and the mailbox
  refuses that one offer. See the findings below.
- `slack_le_window`: `retention_slack_seconds ≤ receipt_window_seconds`, the
  premise of ADR-006's addendum.
- `copy_first_offer_is_expiry`: for any retention, slack and window with
  `slack ≤ window`, a message sealed at `sealedAt` with a lifetime of at most
  the retention, first stored at `stored ≥ sealedAt`, has every copy sent at
  `copy ≥ stored + window` offered `sealedAt + lifetime`, its own expiry, as
  the first deadline. `copy_first_offer_is_expiry_prod` instantiates it with
  the production limits.
- `copy_short_if_slack_exceeds_window`: with `window < slack`, a copy sent one
  window after a full-lifetime original is offered less than the expiry,
  which is the addendum's last sentence.

### Retransmit schedule (`core/retransmit.gleam`, ADR-006)

`daemon/store.record_send` calls `due_at` with the time the mailbox stored
that copy, so the schedule is a chain in which copy `k + 1` is stored no
earlier than copy `k` came due. `chain` models it with no latency.

- `dueAt_spec`: if `due_at` returns `u`, then `u ≤ deadline`,
  `retransmits < max_retransmits`, the kind is an application message or a
  control, and `u = stored_at + window * 2^retransmits`.
- `dueAt_exhausted`: no copy is scheduled once `retransmits ≥ 5`.
- `retransmit_after_window`: for `retransmits ≥ 0` and `window ≥ 0`, a copy
  is due at least one window after the copy before it was stored.
- `chain_length` and `chain_le_deadline`: the chain from the first copy has at
  most five retransmits, none past the deadline.
- `chain_zero_latency` and `chain_hours`: with no latency and a deadline at
  least 31 windows out, the retransmits go out at 1, 3, 7, 15 and 31 windows,
  so the last is 31 hours after the first copy was stored.
- `span_lower_bound`: under any latency, the fifth retransmit is stored at
  least `31 * window` after the first copy. "31 hours" is exact with no
  latency and a lower bound otherwise.
- `day_outage_five_copies`: four retransmits fall within 24 hours of the
  first store, so a day-long outage sees five copies, as ADR-006 says.
- `span_inside_retention`: `31 * receipt_window_seconds <
  message_retention_seconds`.

### Kemeleon (`core/crypto/kemeleon.gleam`, ADR-016)

The transcription follows `encode`, `encode_polynomials`, `accumulate`,
`read_coefficients`, `vector_encode`, `decode`, `decode_polynomials`,
`vector_decode` and `write_coefficients` step for step. The randomness is the
list of non-negative draws `randomness.draws()` yields; both constructors give
four, and every theorem quantifies over every draw, so the reduction
`draw % range` is part of what is proved. `PolyValid p` says `p` is 384
bytes, each below 256, whose 256 coefficients are all below 3329: what FIPS
203's modulus check and `read_coefficients` accept. `span` is `3329^256`,
`ceiling` is `2^3128`, and `range x = (2^3128 - 1 - x) / 3329^256 + 1` is
the number of multiples `vector_encode` reduces a draw into. That is one
fewer than the Kemeleon draft's range, `draftRange x = (2^3128 - x) /
3329^256 + 1`, at a single value; see finding 1.

- `round_trip`: for four `PolyValid` polynomials, any 32-byte seed and any
  four draws, `encode` succeeds, its output is 1596 bytes, and `decode`
  returns the key. There is no exception.
- `vector_round_trip`: the same for one polynomial.
- `decode_total`: every 1596-byte input decodes, to four `PolyValid`
  polynomials followed by the input's last 32 bytes unchanged.
- `decode_then_encode`: whatever `decode` returns, `encode` accepts under any
  four draws. A wrong password's unmasking is always a key the modulus check
  passes, which is the property OQUAKE rests on.
- `encodedValue_lt`: for every value below `3329^256` and every draw, the
  integer `vector_encode` writes is below `2^3128`, so 391 bytes hold it
  without loss.
- `vector_bits_tight`: `2^2995 ≤ 3329^256 < 2^2996`, so `vector_bits = 2996`
  is `⌈256 log₂ 3329⌉`; `encoded_width`: `8 × 391 = 2996 + 132`, and the
  key and encoding sizes add up (`4 × 384 + 32 = 1568`,
  `4 × 391 + 32 = 1596`); `ceiling_eq`: `2^3128 = 256^391`;
  `span_lt_ceiling`.
- `encoding_injective`: `x + m × 3329^256` determines `x < 3329^256` and `m`.
- `encoding_image`: an integer is `x + m × 3329^256` for some value `x` and
  some `m < range x` exactly when it is below `2^3128`. The image is exactly
  `[0, 2^3128)`, so `N = 2^3128`.
- `encoding_bijective`: writing `x + m × 3329^256` as 391 little-endian
  bytes is a bijection between pairs `(x, m)` with `x < 3329^256` and
  `m < range x`, and 391-byte strings.
- `range_bounds` and `range_large`: every value's range has
  `⌊2^3128 / 3329^256⌋` or one more multiples, and that floor is at least
  `2^132`.
- About the draft's formula, not the code: `draft_bound_overflows` says that
  for `x* = 2^3128 mod 3329^256` (nonzero, below `3329^256`) the draft's top
  multiple makes the sum exactly `2^3128`; `range_eq_draftRange` says the
  code's range equals the draft's for every other value and is one smaller
  at `x*`. So any multiple the draft allows for another value, as every
  draft vector's is, is used unchanged.

What the counting reduces the statistical-distance claim to: the encoded
integer is uniform over its value's range, every range has `K` or `K + 1`
members with `K ≥ 2^132`, and the ranges tile `[0, 2^3128)` exactly, one
pair per 391-byte string. With `N = 2^3128` the term `(2^3128 - N) /
2^3128` is zero: no string is left uncovered, and the distance from uniform
comes only from the one-member difference between ranges, at most about
`1/K ≤ 2^-132` per polynomial. The probability argument itself is not
formalised.

### Nameplates (`core/nameplate.gleam`)

Text is its UTF-8 bytes, which is what `parse` reads. `decimal` transcribes
`int.to_string` on a non-negative integer and `padStart` `string.pad_start`
on ASCII text; the vectors check both against the real functions.

- `fromInt_some_iff`: `from_int` accepts exactly `[0, 10^6)`.
- `toString_digits`: for every nameplate, `to_string` is exactly six ASCII
  digits.
- `parse_toString`: `parse (to_string n) = n` for every nameplate.
- `parse_isSome_iff`: `parse` accepts a string exactly when it is six bytes,
  every one an ASCII digit. No sign, no space, no five- or seven-digit
  spelling, and no multi-byte character whose byte count happens to be six.
- `parse_canonical`: whatever `parse` accepts is `to_string` of the value it
  returns: one spelling per nameplate.

### Word indices (`core/pairing_code.gleam`)

`read_indices` is transcribed over a bit string modelled as its value and
width, including the short-draw path, which the vectors exercise.

- `bytesDrawn_eq`: `bytes_drawn` is 5.
- `indices_eq`: for five bytes, the indices are the top 33 of the 40 bits as
  three eleven-bit fields, most significant first.
- `split_lt`, `join_split`, `split_join`: those fields are a bijection
  between 33-bit numbers and triples in `[0, 2048)^3`; every field is a
  valid word index.
- `indices_preimage`: for every triple of indices, the five-byte draws that
  yield it are exactly the 128 strings `join a b c × 128 + j`, `j < 128`. No
  modulo bias: every triple has the same number of draws behind it.

### PAKE framing (`core/crypto/pake_common.gleam`, `core/rendezvous.gleam`)

- `lvEncode_prefix`: `lv_encode` is a prefix code. If `lv(a) ++ r =
  lv(b) ++ r'` then `a = b` and `r = r'`.
- `lvEncode_none_iff`: `lv_encode` refuses exactly fields longer than 65 535
  bytes; it never wraps a length.
- `framePart_prefix` and `encodePublicContext_prefix`: the same for the
  four-byte framing and for `EncodePublicContext(sid, U, S)` as a whole.
- `publicContext_injective`: equal values of `lv(label) || lv(nameplate) ||
  EncodePublicContext(sid, U, S)` come from equal labels, nameplates,
  session identifiers and identities.
- `rendezvousContext_injective`: equal `rendezvous.public_context` outputs
  come from the same nameplate and the same rendezvous identifier; this
  composes the framing with `parse_toString`.

### Elligator 2 (`core/crypto/elligator2.gleam`)

`map_to_curve`, `curve_right_side`, `is_square`, the private `reduce`,
`multiply`, `inverse`, `power` and `power_loop`, and the RFC 7748
conversions are transcribed exactly, with Gleam's truncated `%` as
`Int.tmod`. The vectors pin the transcription to the Gleam on cpace-21's
B.1.1 hash and field element, on the six reference inputs of
`elligator2_test.gleam`, at 0, 1, p ± 1, p + 18, 2p, negatives and
`2^255`, `2^256`, and on 120 random field elements each with its `p - r`.

- `constants`: the module's literals are `p = 2^255 - 19`,
  `2^255 - 1`, `(p - 1) / 2` and `p - 2`.
- `mapToCurve_range`: every output is in `[0, p)`.
- `mapToCurve_neg` and `mapToCurve_periodic`: `map(p - r) = map(r)` and
  `map(r + p) = map(r)` for every integer `r`, because the map reads its
  input only through `r^2 mod p`.

**Not proved: that the output is on the curve.** That is a statement about
quadratic residues in GF(2^255 - 19): Euler's criterion for `is_square`,
that `Z = 2` is a non-square so one of `g(x1)`, `g(x2)` is a square, and that
`-1/Z` is a non-square so the denominator never vanishes. Proving it would
need a formalisation of finite fields, Fermat's little theorem and the
Legendre symbol (Mathlib has them; core Lean does not), plus a certificate
that p is prime. It is tested instead: by the Gleam property test
`every_input_maps_onto_the_curve_property_test`, by the draft's B.1.1 vector
and the reference implementation's values, and, through the vectors, by this
transcription agreeing with the Gleam on those inputs.

`#print axioms` reports `propext`, `Quot.sound` and in most cases
`Classical.choice` for every theorem, and no axioms for those decided on
constants.

## The transcription gap, and how the vectors close it

The proofs are about Lean definitions. A transcription error, or a later Gleam
change, would leave every theorem true and every claim about Gleam false. The
vectors are the check against that. `GenVectors.lean` evaluates the Lean
definitions on 12 995 inputs and writes each with its expected output.
`formal_vectors_test.gleam` runs the real Gleam function on each input,
renders the result in the same notation, and requires the rendered line to
equal the vector line.

| Operation | Vectors | Coverage |
| --- | --- | --- |
| `encode_big_size` | 522 | 0 to 299, every width boundary, values past `2^64`, negatives, random |
| `decode_big_size` | 2 909 | every one-byte input, every two-byte input after a marker or boundary byte, `0xfd` payloads around the floor and the top, every truncation, random encodings with tails |
| `parse` and `encode_stream` | 3 672 | every string of up to four bytes over `00 01 02 03 fd ff`, the input bound and a negative bound, random streams with a repeated record, swapped records, a non-minimal type, a non-minimal length, every truncation, a u64 length on a short input |
| `decode` (`required`, `optional`, `run`) | 1 536 | every subset of types 0 to 5 with three value shapes, against eight decoders |
| `Builder` (`put`, `encode`) | 157 | replacements, negative types, the u64 overflow pair, random |
| `padded_size` | 142 | -5 to 5, every bucket ±3, random |
| `pad` | 38 | lengths 0 to 8 and every bucket boundary for the four-byte prefix, past the limit |
| `from_wire` and `unpad` | 40 | sizes around every bucket, length prefixes around the remaining bytes and `2^32 - 1` |
| `retention.offers` | 1 245 | lifetimes -3 to 300 at three clocks, every rung boundary, random |
| `retransmit.due_at` | 940 | four windows, four kinds, `k` from -2 to 7, deadline at the due time ±1, random |
| `kemeleon.encode` | 18 | the zero and all-3328 keys, the polynomial `x*` of finding 1 in two slots under the draft's top multiple (given directly and as a draw one range above it) and under the code's own top multiple, draws at the range, one past it and `2^384 - 1`, six random keys under random draws, a coefficient of 3329 in each half of a pair, 3328 and 4095, keys of 1567 and 1569 bytes |
| `kemeleon.decode` | 22 | every successful encoding above, all-zero and all-`ff` inputs, four random inputs, 0, 1595 and 1597 bytes |
| `nameplate.from_int`, `to_string` | 286 | -3 to 121, around 10^3, 10^5 and 10^6, ±10^12, random |
| `nameplate.parse` | 864 | every value spelled above, every printable ASCII byte at each of the six positions, signs, spaces, a newline, five and seven digits, multi-byte digits of six bytes |
| `pairing_code.generate` (indices) | 197 | all zeros, all ones, each of the 40 bits alone, short draws of 0, 1, 2 and 4 bytes, a six-byte draw, random |
| `pake_common.lv_encode` | 10 | 0 to 3 bytes, 255, 256, 65 534, 65 535, 65 536, 70 000 |
| `pake_common.encode_public_context` | 60 | random parts, empty parts included |
| `rendezvous.public_context` | 24 | six nameplates from 0 to 999 999, random rendezvous identifiers |
| `elligator2.map_to_curve` | 265 | boundaries, negatives, B.1.1 and reference inputs, random `r` with `p - r` |
| `elligator2` bytes (`decode_u_coordinate`, map, `encode_u_coordinate`) | 48 | B.1.1's hash and field element, all zero, all `ff`, nine, 31, 33 and 0 bytes, random |

The new groups grew the file from 437 030 to 759 352 bytes (1.74 times),
almost all of it the 40 Kemeleon vectors at about 6 KB each. The whole
conformance module runs in about 1.2 seconds, of which the ten new tests take
about 0.55.

An accepted `parse` vector also checks that `encode_stream` reproduces the
input, and every `build` output is also a `parse` vector.

The vectors have teeth. Each of these one-line changes to the Gleam code,
applied alone, fails the conformance test named beside it, and the other
nine conformance tests still pass:

| Change | Failing test |
| --- | --- |
| `minimal` accepts `value >= floor` (non-minimal BigSize) | `big_size_decode_test` |
| `ascending` accepts `tag >= previous` | `parse_test` |
| `run` ignores unknown even types | `decode_test` |
| `halved` uses `(lifetime + 1) / 2` | `retention_offers_test` |
| `halved` recurses with `left` instead of `left - 1` | `retention_offers_test` |
| `offers` drops the slack | `retention_offers_test` |
| `due_at` uses `due < deadline` instead of `!is_past` | `retransmit_due_at_test` |
| `due_at` uses `retransmits <= max_retransmits` | `retransmit_due_at_test` |
| `padded_size` uses `size < bucket` | `padded_size_test`, `pad_test` |
| `pad` counts a three-byte prefix | `pad_test` |
| `vector_encode` writes `size(3128)` (big-endian) | `kemeleon_encode_test` |
| `vector_encode` uses the draft's `(ceiling - value)` (undoing the fix for finding 1) | `kemeleon_encode_test`, and `kemeleon_test.the_drafts_overflow_point_round_trips_test` |
| `read_indices` reads `size(10)` | `pairing_code_indices_test` |
| `map_to_curve` leaves `x2` unreduced | `elligator2_map_test` |

The new transcriptions were mutated the same way, each mutant applied alone
to the Lean definition and judged twice: by whether the proofs still check,
and by whether the definitions alone (proofs removed) generate vectors that
differ from the committed ones, which the Gleam passes.

| Lean mutant | Proofs | Vectors that diverge |
| --- | --- | --- |
| `accumulate` in base 3328 | break | `kem.enc`, `kem.dec` |
| `vector_encode` big-endian | break | `kem.enc`, `kem.dec` |
| draw not reduced into its range | break | `kem.enc`, `kem.dec` |
| range one too large | break | `kem.enc`, `kem.dec` |
| range back to the draft's `(ceiling - value)` | break | the two `x*` `kem.enc` lines and their `kem.dec` |
| ByteEncode_12 middle nibbles swapped | break | `kem.enc`, `kem.dec` |
| modulus check at 4096 instead of 3329 | break | `kem.enc` (the 3329 and 4095 keys now encode) |
| `vector_decode` without `% 3329^256` | break | none: an equivalent mutant, as the Gleam module doc says |
| `parse` accepts fewer than six bytes | break | `np.parse` |
| `to_string` pads to five | break | `np.str`, `np.parse`, `pctx` |
| digits admit `:` | break | `np.parse` |
| `from_int` admits 10^6 | break | `np.str` |
| ten-bit index fields | break | `code.idx` |
| low bits read first | break | `code.idx` |
| `lv_encode` one-byte length | break | `lv`, `pctx` |
| `lv_encode` bound 65 536 | break | `lv` |
| context parts swapped | break | `epc`, `pctx` |
| server part unframed | break | `epc`, `pctx` |
| `x2` unreduced | break | `ell2` |
| `reduce` without the lift | break | `ell2`, `ell2.u` |
| Z = 3 | check | `ell2`, `ell2.u` |
| branch inverted | check | `ell2`, `ell2.u` |
| bit 255 not cleared | check | `ell2.u` |

The last three are the on-curve property and the decoding mask, which no
theorem covers; the vectors are what catch them. The `vector_decode`
mutant breaks proofs only because they name the reduction; its outputs are
the same on every input.

What the vectors cannot cover: Gleam bit arrays that are not a whole number
of bytes (the model has bytes only), and the `TooManyItems` path of
`sequence`.

## Findings: where the code and its documents disagree

Places where a document stated more than the code did. Finding 1 was
fixed in the code; the others change no behaviour that matters today and
left the code as it was.

1. **Kemeleon's round trip failed at one point; the cause is the draft's
   bound, and it is fixed.** `draft-irtf-cfrg-kemeleon-02`'s `VectorEncode`
   draws `m <--$ [0,...,floor((2^(b+t)-r)/(q^(n)))]` (§4.1), an inclusive
   bound; `draft-vos-cfrg-pqpake-03` does not restate it, it fixes only
   `t = 132` and the 391-byte little-endian form. `vector_encode` followed
   the draft with `range = (2^3128 - value) / 3329^256 + 1`. When
   `3329^256` divides `2^3128 - value`, the top multiple makes the sum
   exactly `2^3128`, and `<<encoded:little-size(3128)>>` keeps its low 3128
   bits: 391 zero bytes. That happens for exactly one polynomial value,
   `x* = 2^3128 mod 3329^256`, a valid polynomial, and `decode` then
   returned the zero polynomial, not the key. Two `kem.enc` vectors showed
   the Gleam doing exactly that, so it was the code's behaviour and not the
   model's; its doc said "the sum never reaches 2^3128". It was unreachable
   in practice (a key polynomial equals `x*` with probability about
   `2^-2995`). The code now uses `range = (2^3128 - 1 - value) / 3329^256 +
   1`, a deliberate one-point deviation from the draft that the module doc
   records. `range_eq_draftRange` proves it changes the range only at `x*`,
   so every draft vector is unchanged (the primitives' E.1.2, E.2 and E.4
   vectors still match), and `draft_bound_overflows` records the draft's
   overflow. What now holds is `round_trip` with no exception,
   `encodedValue_lt`, and `encoding_bijective`: the encoding is a
   bijection onto 391-byte strings. The two `x*` vectors are kept and now
   round-trip, and `kemeleon_test` pins the fix with its own test.
2. **An offer can be `now`.** `packages/core/CLAUDE.md` said "no offer is
   `now` or earlier" of every offer. ADR-008 says "An offer is never `now` or
   earlier" in its bullet about the halved fallbacks, where it holds
   (`shorter_bounds`), but the sentence reads as a rule for every offer. For a
   row at exactly its deadline, the first offer is the deadline itself, which
   equals `now` (`offers_at_deadline_refused`). The scheduler
   reaches this case: it fails a row without a send only when `is_past`
   holds for the row's deadline, which is false at the deadline itself
   (`daemon/scheduler.gleam:463`). The mailbox then refuses the one offer
   with `BadDeadline`, which costs one append; the retry finds the row past
   its deadline and fails it. The module doc
   of `retention.gleam` and its test (`no_offer_is_made_for_a_deadline_already_reached_test`)
   describe this boundary correctly. The precise statement is
   `offers_window`: every offer is in `(now, expires_at]` when
   `now < expires_at`. This change corrects the package doc; the ADR is left
   for an addendum, as ADRs are never edited in place.
3. **The builder can emit a repeated type.** The `core/tlv.gleam` module doc
   says a `Builder` "cannot emit a duplicate, an out-of-order record, or a
   non-minimal BigSize". `encode_big_size` clamps a type above `2^64 - 1` to
   `2^64 - 1`, so two types past the u64 range encode as the same type and
   `parse` refuses the output (`builder_overflow_rejected`, and the `build`
   vector for `2^64` and `2^64 + 1`). No codec uses such a type; every type
   in the codec tables is a small constant. `builder_accepted` is the precise
   claim: types up to `2^64 - 1` always encode to an accepted stream.

The ADR-006 "31 hours" is exact only with no latency between a copy coming
due and the next being stored; in general it is a lower bound
(`span_lower_bound`). The ADR's wording "goes out 31 hours after" reads as
the zero-latency figure, which is consistent with the proofs.

## Keeping the two sides in step

A change to any of these Gleam functions must be mirrored in its Lean
definition, followed by `check.sh --write` and `gleam test`:

| Gleam | Lean |
| --- | --- |
| `tlv.encode_big_size`, `decode_big_size`, `minimal` | `encodeBigSize`, `decodeBigSize`, `wide` |
| `tlv.parse`, `parse_records`, `ascending`, `take`, `encode_stream`, `records` | `parse`, `parseRecords`, `encodeRecords` |
| `tlv.required`, `optional`, `run`, `decode`, `locate`, `bytes`, `u8` | `runSpec`, `runStream`, `decode`, `locate`, `Codec.read` |
| `tlv.put`, `encode` | `put`, `build`, `encodeBuilder` |
| `limits.padding_buckets`, `max_ciphertext_bytes`, `padded_size` | `paddingBuckets`, `maxCiphertextBytes`, `paddedSize` |
| `envelope.pad`, `unpad`, `from_wire` | `fill`, `pad`, `unpad`, `fromWire` |
| `limits.message_retention_seconds`, `retention_slack_seconds`, `max_deadline_offers`, `receipt_window_seconds` | the constants of the same names in `Retention.lean` |
| `retention.offers`, `halved` | `offersWith`, `offers`, `halved` |
| `limits.max_retransmits`, `retransmit.due_at`, `is_retransmitted` | `maxRetransmits`, `dueAt`, `Kind.retransmitted` |
| `kemeleon` constants, `encode`, `encode_polynomials`, `accumulate`, `read_coefficients`, `vector_encode` | `Kemeleon.q` and the constants, `encode`, `encodePolynomials`, `accumulate`, `readCoefficients`, `range`, `encodedValue`, `vectorEncode` |
| `kemeleon.decode`, `decode_polynomials`, `vector_decode`, `write_coefficients`, `polynomial_span` | `decode`, `decodePolynomials`, `vectorDecode`, `writeCoefficients`, `span` |
| `limits.nameplate_digits`, `nameplate.from_int`, `parse`, `read_digits`, `to_string` | `Nameplate.nameplateDigits`, `fromInt`, `parse`, `readDigits`, `toString` (`decimal`, `padStart`) |
| `words.index_bits`, `word_count`, `limits.pairing_code_words`, `pairing_code.bytes_drawn`, `read_indices` | `PairingCode.indexBits`, `wordCount`, `pairingCodeWords`, `bytesDrawn`, `readIndices` |
| `pake_common.lv_encode`, `encode_public_context`, `frame_context_part`, `rendezvous.public_context` and its label and identities | `PakeCommon.lvEncode`, `encodePublicContext`, `framePart`, `rendezvousContext` |
| `elligator2` constants, `map_to_curve`, `curve_right_side`, `is_square`, `reduce`, `multiply`, `inverse`, `power`, `power_loop`, `decode_u_coordinate`, `encode_u_coordinate` | the `Elligator2` definitions of the same names |

If the conformance test fails after a Gleam change, either the change was a
mistake, or the transcription must change with it and the affected proofs
must be repaired before the vectors are regenerated. Regenerating the vectors
without updating the transcription defeats the check: `check.sh` would then
fail on the diff, since the vectors come from the Lean definitions.

Two modelling choices are worth knowing when editing. `halved` takes its bound
as a `Nat`, since Gleam only ever passes `max_deadline_offers - 1`. Gleam's
`lifetime / 2` truncates toward zero, so the model uses `tdiv2`, which agrees
with it on negative lifetimes as well. A `Dict` in Gleam is the ascending
association list `parse` builds; `encode`'s sort is the identity on such a
list.

## Open gaps

- `tlv.items`, `sequence`, `nested`, `text`, `peek` and the fixed-width
  integer codecs other than `u8` are not transcribed.
- `retransmit.retransmit` and its `check_bounds` are not transcribed; the
  bound on copies is proved for `due_at` alone.
- The mailbox codec (`core/mailbox/codec`) is built on the TLV codec but is
  not modelled; its canonicality follows from the stream theorems only if its
  field codecs are themselves canonical.
- Kemeleon's statistical distance is reduced to arithmetic (`encoding_image`,
  `range_bounds`, `range_large`) but the probability argument is not
  formalised. Its timing behaviour is outside any model here.
- `kemeleon.randomness` (the 192-byte split into four 48-byte draws) is not
  transcribed; the vectors use `randomness_from_multiples`, and the theorems
  hold for every draw either constructor can produce.
- The Elligator 2 on-curve property is tested, not proved (see above).
- `pairing_code.encode`, `decode`, the word list and `words.index_of` are
  not transcribed; the index vectors reach them only through `generate`'s
  password and `index_of`. `encode_public_context`'s four-byte bound is
  proved but not exercised, since no vector can be 2^32 bytes.
- Clock behaviour (a clock that jumps backwards between copies) is outside
  the model: `copy_first_offer_is_expiry` assumes `copy ≥ stored + window` on
  the sender's clock.
