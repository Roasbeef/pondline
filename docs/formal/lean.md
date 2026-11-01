# Lean proofs for the pure core

`formal/lean` holds Lean 4 proofs about four pure parts of `packages/core`:
the TLV codec, the padding buckets, the retention deadlines a sender offers,
and the retransmit schedule. Each proof is about a Lean transcription of the
Gleam function, written to follow the Gleam code branch for branch with the
same constants. The proofs only say something about the Gleam code if the two
agree, so the Lean build also writes conformance vectors that a Gleam test
replays against the real functions. This document covers what is proved, how
the vectors close the gap between the two languages, how to rebuild, and which
Gleam changes need the Lean side updated.

## Layout and rebuilding

| Path | What it holds |
| --- | --- |
| `formal/lean/Reedwire/Bytes.lean` | Byte strings as `List Nat`, big-endian reads and writes, and their lemmas. |
| `formal/lean/Reedwire/Tlv.lean` | The transcription of `core/tlv.gleam`. |
| `formal/lean/Reedwire/TlvProofs.lean` | BigSize and stream round trips, canonicality, the input bound. |
| `formal/lean/Reedwire/TlvDecode.lean` | Unknown even and odd types, and the `Builder`. |
| `formal/lean/Reedwire/Padding.lean` | `limits.padded_size` and `envelope.pad`, `unpad`, `from_wire`. |
| `formal/lean/Reedwire/Retention.lean` | `retention.offers` and the ADR-008 and ADR-006 addendum claims. |
| `formal/lean/Reedwire/Retransmit.lean` | `retransmit.due_at` and the ADR-006 schedule claims. |
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
the committed file. A cold run takes about 6 seconds and a warm one about 3.

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

`#print axioms` reports `propext`, `Quot.sound` and in most cases
`Classical.choice` for every theorem, and no axioms for the two that are
decided on constants.

## The transcription gap, and how the vectors close it

The proofs are about Lean definitions. A transcription error, or a later Gleam
change, would leave every theorem true and every claim about Gleam false. The
vectors are the check against that. `GenVectors.lean` evaluates the Lean
definitions on 11 201 inputs and writes each with its expected output.
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

What the vectors cannot cover: Gleam bit arrays that are not a whole number
of bytes (the model has bytes only), and the `TooManyItems` path of
`sequence`.

## Findings: where the code and its documents disagree

Two places where a document states more than the code does. Neither changes
behaviour that matters today, and no production code was changed.

1. **An offer can be `now`.** `packages/core/CLAUDE.md` said "no offer is
   `now` or earlier" of every offer. ADR-008 says "An offer is never `now` or
   earlier" in its bullet about the halved fallbacks, where it holds
   (`shorter_bounds`), but the sentence reads as a rule for every offer. For a
   row at exactly its deadline, the first offer is the deadline itself, which
   equals `now` (`offers_at_deadline_refused`). The scheduler
   reaches this case: it fails a row without a send only when `is_past`
   holds for the row's deadline, which is false at the deadline itself
   (`daemon/scheduler.gleam:453`). The mailbox then refuses the one offer
   with `BadDeadline`, which costs one append; the retry finds the row past
   its deadline and fails it. The module doc
   of `retention.gleam` and its test (`no_offer_is_made_for_a_deadline_already_reached_test`)
   describe this boundary correctly. The precise statement is
   `offers_window`: every offer is in `(now, expires_at]` when
   `now < expires_at`. This change corrects the package doc; the ADR is left
   for an addendum, as ADRs are never edited in place.
2. **The builder can emit a repeated type.** The `core/tlv.gleam` module doc
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
- Clock behaviour (a clock that jumps backwards between copies) is outside
  the model: `copy_first_offer_is_expiry` assumes `copy ≥ stored + window` on
  the sender's clock.
