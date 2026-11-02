# core

## Purpose

The pure protocol core: the domain types, the wire codecs, the
cryptographic protocols and (next) the pairing and relationship state
machines, written as `transition(model, event)` functions with time,
randomness, network and storage outcomes arriving as arguments rather
than reached for (`docs/spec.md` §10.1).

`core` is held to the portable subset by lint R6: no `@external` of any
target, and no `gleam_erlang` or `gleam_otp`, in source or in
`gleam.toml`. That is what lets a property test enumerate states,
interleavings and crash points without spawning a process. Cryptography
reaches `core` only through `core/crypto/suite.Suite`, a record of
primitive functions the shell builds from `packages/primitives`.

## Key Types

- `core/id`: `Id(kind)`, sixteen random bytes with a phantom kind
  (`Agent`, `Contact`, `Queue`, `Envelope`, `Message`, `Invitation`,
  `Blob`), so one kind of identifier cannot stand in for another.
- `core/capability`: `Capability(authority)`, thirty-two random bytes held
  as a `Secret`, typed `Append`, `Read`, `Admin`, `Provision` or
  `Retrieve` (a ticket's blob, ADR-009).
- `core/secret`: `Secret`, bytes held inside a closure so `inspect`, logs
  and crash reports print `#Fun<..>`; `expose` is the only way out.
- `core/endpoint`: `Endpoint` is a v3 `Onion` or a `Loopback` port, with no
  constructor for a public host; `admit` checks a `CarrierPolicy`. An
  `OnionAddress` also holds its decoded label (`onion_bytes`, 35 bytes),
  and `onion_from_bytes` is the inverse.
- `core/envelope`: `Padded`, a ciphertext at exactly a bucket size, built
  only by `pad` or `from_wire`; `StoredEnvelope`.
- `core/time`: `Instant` in Unix seconds; `is_past` treats the deadline
  itself as still valid.
- `core/limits`: the spec's §11.3 provisional limits and the ratchet's
  skip bounds, as named constants, and `padded_size`. The shell's bounds
  live here too: `max_process_attempts` (ADR-010), `max_send_key_bytes` and
  `send_key_seconds` (ADR-011).
- `core/tlv`: a BOLT #1 TLV codec (BigSize, `parse`/`Stream`, a `use`-style
  `Decoder` with `required`/`optional`/`run`, field codecs, `Builder`).
  Canonical by construction.
- `core/mailbox/protocol` and `core/mailbox/codec`: the mailbox protocol as
  typed `Request`/`Response` values and their TLV bytes; type tables in the
  codec's module doc; `refusal/1` maps decode errors to a `Refusal`.
  `PutBlob`/`GetBlob` and `BlobStored`/`SealedBlob` carry a ticket's
  sealed invitation (ADR-009).
- `core/codex32`: the bech32 alphabet and prefix expansion with BIP-93's
  long codex32 BCH checksum (fifteen symbols, any eight substitutions
  detected up to 1023 symbols), and strict byte/5-bit regrouping.
- `core/ticket` (ADR-009): `Ticket` (an endpoint and a 32-byte secret `K`,
  opaque), `encode`/`decode` of the `pl1` text (130 characters onion, 74
  loopback), `keys` (locator, retrieve capability, AEAD key and nonce,
  commitment key, each under its own HKDF label), `seal` and `open` (the
  AEAD, then the HMAC commitment to the plaintext).
- `core/http1`: pure, total HTTP/1.1 framing for the mailbox binding; an
  incremental response parser bounded as bytes arrive.
- `core/crypto/keys`, `identity`, `hkdf`: typed X25519, Ed25519, ML-DSA-65
  and ML-KEM keys, and `HybridSignature` (Ed25519 and ML-DSA-65 over one
  message); the per-relationship `Identity` (two signing keys and an
  agreement key) whose `PublicIdentity` exists only with a verified hybrid
  binding; RFC 5869 HKDF.
- `core/crypto/pqxdh`: opaque `Bundle` (hybrid signatures verified on
  decode), `Prekeys`, `InitialMessage` (with the joiner's hybrid transcript
  signature), `initiate` and `respond`.
- `core/crypto/ratchet`: the Double Ratchet as `encrypt`/`decrypt`
  returning `#(State, output)`, and a total, bounded state codec.
- `core/plan`: what a transition returns (`Plan`, `Record`, `Effect`),
  including `Fingerprint` and the `Remembered` record, the receiver's memory
  of a ciphertext it stored a message from, and `RepeatedMessage`, the
  record of an ignored repeated identifier (ADR-010).
- `core/relationship`: the relationship state machine; `fingerprint` and
  `resend_receipt` answer a ciphertext that arrives again with the same
  logical receipt (ADR-006). An inbound ratchet message is received in two
  steps: `open` decrypts it into an opaque `Opened`, the shell looks
  `opened_message` up and answers with an `IdHistory` (`FreshId`,
  `UsedId`), and `receive(opened, history)` decides (ADR-010).
- `core/retransmit`: end-to-end retransmission (ADR-006). `due_at` is the
  schedule (`limits.receipt_window_seconds`, doubling, at most
  `limits.max_retransmits` copies, never past the deadline);
  `retransmit(suite, relationship, Unreceipted, now)` returns a
  `Retransmission` (a fresh envelope for a copy of a stored row's bytes) or
  a `Stop`.
- `core/retention`: the retention deadlines a sender offers a mailbox
  (ADR-008). `offers(expires_at:, now:)` returns the default,
  `retention_slack_seconds` below the mailbox's maximum and never past
  `expires_at`, and up to `max_deadline_offers - 1` shorter ones, each
  halving the lifetime, all after `now`.

## Relationships

Depends on `gleam_stdlib` alone. Depended on by `primitives` (which builds
the `Suite`), `mailbox`, `daemon`.

## Traffic

None. `core` sends no messages and owns no processes.

## Invariants

- The largest padding bucket equals `max_ciphertext_bytes`, so padding
  never admits a ciphertext the mailbox would refuse
  (`test/core/limits_test.gleam`).
- Every limit is named in `core/limits` and imported; a literal restating
  one at a call site is a review finding (`docs/gleam-style.md` Part IV §8).
- The TLV decoder is total and strict: strictly increasing types, minimal
  BigSize, bounded input, unknown even types fail closed, unknown odd
  types are never readable; anything it accepts re-encodes byte for byte
  (`test/core/tlv_test.gleam`).
- The mailbox codec checks the version before any other field; its errors
  hold type numbers only, so no capability reaches an error rendering
  (`test/core/mailbox/codec_test.gleam`).
- Every `core/http1` bound is exact, and any chunking of a response parses
  identically (`test/core/http1_test.gleam`).
- A ratchet state is never changed by `encrypt` or `decrypt`; a failed
  decrypt consumes nothing, and a key is spent exactly when the caller
  keeps the returned state (spec §5.3). Encryption is deterministic in the
  state, so a ciphertext must not leave the process before its state is
  committed.
- Authentication is hybrid (`docs/adr/005-hybrid-authentication.md`):
  every signature check (identity binding, both prekey signatures, the
  joiner's transcript) requires the Ed25519 and the ML-DSA-65 half, and
  `keys` has no function that verifies one half alone. `respond` verifies
  the transcript before any agreement. Each check is mutation-tested in
  `packages/primitives/test/primitives/hybrid_auth_test.gleam`.
- Skip bounds are checked before any key is derived; the skipped-key store
  evicts its oldest keys rather than refusing, and `decode_state` refuses
  a stored count over the bound.
- A sender never offers the mailbox's full retention by its own clock: the
  first offer sits `retention_slack_seconds` below it, the list of offers is
  finite (`max_deadline_offers`), no offer is past the row's deadline, and
  for a row whose deadline is still ahead no offer is `now` or earlier (a
  row exactly at its deadline is offered the deadline, which the mailbox
  refuses) (`test/core/retention_test.gleam`, with properties). A mailbox
  whose clock trails the sender's by up to the slack accepts the first
  offer, and one up to 529 650 s (about 6.1 days) behind accepts some
  offer. The pure simulation does not model clock skew and still stores
  envelopes under the row's deadline.
- A ticket's decoder is total and strict: lowercase, the checksum before
  the payload, exact lengths, zero padding; whatever it accepts re-encodes
  to the same text, and every single substitution and any eight are
  caught (`test/core/ticket_test.gleam`, with properties; the checksum
  against BIP-93's vector 5 in `codex32_test.gleam`). `open` returns
  nothing that has not passed both the AEAD and the commitment, and every
  derived value has its own label. Mutation-checked: dropping the
  commitment check, or deriving the commitment key under the AEAD key's
  label, each fail a test there.
- An application message the relationship would store under an identifier
  it already used (`UsedId`) is ignored: the session advances, the plan is
  the `Processed` record and one `RepeatedMessage`, with no delivery, receipt
  or budget; only application messages consult the history
  (`test/core/dedup_test.gleam`, ADR-010). Mutation-checked: ignoring the
  history fails it.
- The fake `Suite` used by tests lives under `test/` only, so it cannot be
  compiled into a release (spec §13.3).
- A retransmit is the same committed padded ciphertext under a new envelope
  identifier, never a re-encryption; only application messages (while
  `Active`) and `Accept`/`Reject`/`Close` are sent again, never receipts or
  the handshake. A receiver answers a known fingerprint with
  `resend_receipt` and never delivers it again, at most
  `max_retransmits` extra times per ciphertext and never after the message
  expired (`test/core/retransmit_test.gleam`).
- The pure simulation (`test/core/world.gleam`, §13.1) models the shell as
  production behaves: an outbox row stops being resent once the mailbox
  answered it, the mailbox keeps a tombstone for every acknowledged
  envelope and sweeps envelopes past their retention deadline, and a stored
  row whose receipt window passes is retransmitted (`Retransmit`). The heal
  phase (`world.heal`) only turns faults off and lets time pass, moving the
  clock through the receipt windows, so a message a mailbox corrupted or lost
  (`Corrupt`, `Lose`) must still be delivered once and receipted. The
  remaining excuses are `receiver-closed`, `message-expired`,
  `message-expired-before-receipt`, `sender-closed`, `close-expired` and
  `row-for-a-queue-never-created`. Mutation-checked: never scheduling a
  retransmit fails the swarm with "committed message was never delivered",
  and never remembering a fingerprint with "delivered message was never
  receipted". HeldFull is reached by `held_full_test`, not by random
  schedules; its refused messages are now delivered by their retransmit
  once the budget is raised.
- Swarm seeds (`test/core/swarm.gleam`): byte 0 mode (chaotic or benign,
  approval, budget), bytes 1..2 the fault mask (one bit per `world.Fault`,
  nine classes, `Loss` the newest at bit 8),
  then three-byte ops. `swarm_test` plays 40 generated seeds and checks that
  a seed replays to an identical world. For a campaign, build with
  `gleam test` once, then
  `erl -noshell -pa build/dev/erlang/*/ebin -eval 'core@swarm:campaign(5000, 7), halt().'`
  (prints the seed and run index of the first failure); replay one seed
  with `PONDLINE_REPLAY=<hex> gleam test` or
  `core@swarm:replay("<hex>")`.
- `core/tlv`, `limits.padded_size`, `envelope.pad`/`unpad`/`from_wire`,
  `retention.offers` and `retransmit.due_at` are transcribed into Lean and
  proved (`formal/lean`, `docs/formal/lean.md`). The proofs hold for Gleam
  only while `test/core/formal_vectors_test.gleam` passes: it replays the
  11 201 generated vectors in `test/core/formal_vectors.txt` against the real
  functions. Changing one of these functions means changing its Lean
  definition and rerunning `formal/lean/check.sh --write`; never edit the
  vectors by hand. Mutation-checked: a non-minimal BigSize, a repeated type,
  ignored unknown even types, an off-by-one halving, a dropped slack, `<`
  for `<=` on the retransmit deadline or on a bucket, and a miscounted
  length prefix each fail it.
- `fake_suite.seeded(n)` draws identifiers from a seeded counter, so a
  simulation run depends only on its seed; `fake_suite.suite()` keeps a
  process-wide counter for tests that build several suites.

## Deep Docs

- `docs/spec.md` §10.1 (functional core), §11.3 (limits), §13 (invariants
  and test strategy).
- `docs/adr/006-end-to-end-retransmit.md` (retransmission and
  regenerated receipts).
- `docs/adr/008-deadline-slack.md` (retention slack and shorter offers).
- `docs/adr/009-invitation-tickets.md` (tickets, the sealed blob) and
  `docs/crypto-profile-v1.md` §11.
- `docs/adr/010-dedup-and-quarantine.md` (repeated identifiers).
- `docs/crypto-profile-v1.md` (the profile, byte for byte),
  `docs/adr/002-pq-crypto-over-otp.md` and
  `docs/adr/005-hybrid-authentication.md`.
- `docs/gleam-style.md` Part IV §5 (purity layering).
- `docs/formal/lean.md` (the Lean proofs and the conformance vectors).
