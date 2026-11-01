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
  (`Agent`, `Contact`, `Queue`, `Envelope`, `Message`, `Invitation`), so
  one kind of identifier cannot stand in for another.
- `core/capability`: `Capability(authority)`, thirty-two random bytes held
  as a `Secret`, typed `Append`, `Read`, `Admin` or `Provision`.
- `core/secret`: `Secret`, bytes held inside a closure so `inspect`, logs
  and crash reports print `#Fun<..>`; `expose` is the only way out.
- `core/endpoint`: `Endpoint` is a v3 `Onion` or a `Loopback` port, with no
  constructor for a public host; `admit` checks a `CarrierPolicy`.
- `core/envelope`: `Padded`, a ciphertext at exactly a bucket size, built
  only by `pad` or `from_wire`; `StoredEnvelope`.
- `core/time`: `Instant` in Unix seconds; `is_past` treats the deadline
  itself as still valid.
- `core/limits`: the spec's §11.3 provisional limits and the ratchet's
  skip bounds, as named constants, and `padded_size`.
- `core/tlv`: a BOLT #1 TLV codec (BigSize, `parse`/`Stream`, a `use`-style
  `Decoder` with `required`/`optional`/`run`, field codecs, `Builder`).
  Canonical by construction.
- `core/mailbox/protocol` and `core/mailbox/codec`: the mailbox protocol as
  typed `Request`/`Response` values and their TLV bytes; type tables in the
  codec's module doc; `refusal/1` maps decode errors to a `Refusal`.
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
- The fake `Suite` used by tests lives under `test/` only, so it cannot be
  compiled into a release (spec §13.3).
- The pure simulation (`test/core/world.gleam`, §13.1) models the shell as
  production behaves: an outbox row stops being resent once the mailbox
  answered it, and the mailbox keeps a tombstone for every acknowledged
  envelope. The heal phase (`world.heal`) only turns faults off and lets
  time pass; it never retransmits a stored row, so a mailbox that corrupts
  the only copy of a message loses it, and the delivery audit records that as
  the counted excuse `message-corrupted-in-mailbox` (a policy gap, not a
  pass). Other excuses are `receiver-closed`, `message-expired`,
  `sender-closed` and the corrupted close and receipt twins. HeldFull is
  reached by `held_full_test`, not by random schedules.
- Swarm seeds (`test/core/swarm.gleam`): byte 0 mode (chaotic or benign,
  approval, budget), bytes 1..2 the fault mask (one bit per `world.Fault`),
  then three-byte ops. `swarm_test` plays 40 generated seeds and checks that
  a seed replays to an identical world. For a campaign, build with
  `gleam test` once, then
  `erl -noshell -pa build/dev/erlang/*/ebin -eval 'core@swarm:campaign(5000, 7), halt().'`
  (prints the seed and run index of the first failure); replay one seed
  with `REEDWIRE_REPLAY=<hex> gleam test` or
  `core@swarm:replay("<hex>")`.
- `fake_suite.seeded(n)` draws identifiers from a seeded counter, so a
  simulation run depends only on its seed; `fake_suite.suite()` keeps a
  process-wide counter for tests that build several suites.

## Deep Docs

- `docs/spec.md` §10.1 (functional core), §11.3 (limits), §13 (invariants
  and test strategy).
- `docs/crypto-profile-v1.md` (the profile, byte for byte),
  `docs/adr/002-pq-crypto-over-otp.md` and
  `docs/adr/005-hybrid-authentication.md`.
- `docs/gleam-style.md` Part IV §5 (purity layering).
