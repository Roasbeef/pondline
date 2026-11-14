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

That rule holds for the spoken-code PAKE of ADR-016 too. CPaceOQUAKE is
written here in Gleam over the `Suite` (the X25519 multiplications,
ML-KEM, HKDF and the AEAD run in OpenSSL), and the parts OpenSSL has no
call for, the Elligator 2 map and the Kemeleon encoding, are big-integer
arithmetic on the BEAM, which is not constant time. ADR-016 accepts that
on a stated argument and records it as assumed, not shown. No outside
cryptographer has reviewed this code.

## Key Types

- `core/id`: `Id(kind)`, sixteen random bytes with a phantom kind
  (`Agent`, `Contact`, `Queue`, `Envelope`, `Message`, `Invitation`,
  `Blob`, `Rendezvous`), so one kind of identifier cannot stand in for
  another. `Rendezvous` (ADR-016) names a slot at a mailbox; the inviter
  draws it, and it doubles as the PAKE's session identifier.
- `core/capability`: `Capability(authority)`, thirty-two random bytes held
  as a `Secret`, typed `Append`, `Read`, `Admin`, `Provision` or
  `Retrieve` (a ticket's blob, ADR-009).
- `core/secret`: `Secret`, bytes held inside a closure so `inspect`, logs
  and crash reports print `#Fun<..>`; `expose` is the only way out.
- `core/endpoint`: `Endpoint` is a v3 `Onion` or a `Loopback` port, with no
  constructor for a public host; `parse` and `to_string` convert `HOST:PORT` text, and `admit` checks a `CarrierPolicy`. An
  `OnionAddress` also holds its decoded label (`onion_bytes`, 35 bytes),
  and `onion_from_bytes` is the inverse.
- `core/envelope`: `Padded`, a ciphertext at exactly a bucket size, built
  only by `pad` or `from_wire`; `StoredEnvelope`.
- `core/time`: `Instant` in Unix seconds; `is_past` treats the deadline
  itself as still valid.
- `core/limits`: the spec's §11.3 provisional limits and the ratchet's
  skip bounds, as named constants, and `padded_size`. The shell's bounds
  live here too: `max_process_attempts` (ADR-010), `max_send_key_bytes` and
  `send_key_seconds` (ADR-011). ADR-016's are `nameplate_digits` (6),
  `pairing_code_words` (3), `max_pairing_code_bytes` (64),
  `rendezvous_seconds` (600), `rendezvous_claimed_seconds` (120),
  `max_rendezvous_body_bytes` (2048), `max_rendezvous_messages` (4 per
  side), `max_grant_rendezvous` (4), `max_live_rendezvous` (1000),
  `max_rendezvous_failures` (3) and `rendezvous_failure_window_seconds`
  (86 400). The last two are the daemon's, which has not landed.
- `core/tlv`: a BOLT #1 TLV codec (BigSize, `parse`/`Stream`, a `use`-style
  `Decoder` with `required`/`optional`/`run`, field codecs, `Builder`).
  Canonical by construction.
- `core/mailbox/protocol` and `core/mailbox/codec`: the mailbox protocol as
  typed `Request`/`Response` values and their TLV bytes; type tables in the
  codec's module doc; `refusal/1` maps decode errors to a `Refusal`.
  `PutBlob`/`GetBlob` and `BlobStored`/`SealedBlob` carry a ticket's
  sealed invitation (ADR-009). ADR-016 added the rendezvous:
  `OpenRendezvous`, `ClaimRendezvous`, `RendezvousSend`, `RendezvousFetch`
  and `CloseRendezvous` (request kinds 8 to 12), answered by
  `RendezvousOpened`, `RendezvousClaimed`, `RendezvousSent`,
  `RendezvousMessages` and `RendezvousClosed` (response kinds 9 to 13),
  with field types 40 to 54 and `RendezvousMessage(index, body)`. The wire
  carries `RendezvousFetch.after + 1` (type 52), because `after` starts at
  `-1`; an index past the per-side bound is left to the mailbox's
  `QuotaExceeded` rather than refused as malformed.
- `core/nameplate` (ADR-016): `Nameplate`, an integer below
  10^`nameplate_digits` with exactly one spelling, its six zero-padded
  digits; `parse` reads ASCII digits itself because `int.parse` accepts a
  sign. Public: it finds a slot and carries no secret.
- `core/pairing_code` (ADR-016): `PairingCode` (a nameplate and the words
  as a `Secret`, opaque) and the text `NNNNNN-word-word-word`; `generate`
  takes the first 33 bits of a five-byte `suite.random` draw as three
  eleven-bit indices, `decode` returns a `CodeError` (`TooLong`,
  `BadShape`, `BadNameplate`, `UnknownWord(position)`), and `password` is
  the words joined by hyphens, the PAKE's password.
  `core/pairing_code/words` is the BIP-39 English list (SHA-256
  `2f5eed53...`) as one binary constant of nine-byte slots, with
  `word_at` and a binary-search `index_of`.
- `core/rendezvous` (ADR-016): the spoken-code run as type-state steps.
  The inviter goes `invite` then `inviter_answer` (on `m1`) then
  `inviter_release` (on `m3`, returning `Released(message, transcript_hash)`);
  the joiner goes `join` (making `m1`) then `joiner_confirm` (on `m2`) then
  `joiner_receive` (on `m4`, returning the ticket text as a `Secret`). The
  states (`InviterWaiting`, `InviterAnswered`, `JoinerSent`,
  `JoinerConfirmed`) are opaque. `RunError` is `MalformedMessage`,
  `LowOrderShare`, `ConfirmationFailed` (the only one that may be a spent
  guess), `TicketLength` and `PrimitiveFailed`. `public_context` frames
  the label, the nameplate and the rendezvous identifier. Message sizes
  are `join_message_bytes` (34), `answer_message_bytes` (1694),
  `confirm_message_bytes` (1632) and `max_release_message_bytes()` (208).
- `core/codex32`: the bech32 alphabet and prefix expansion with BIP-93's
  long codex32 BCH checksum (fifteen symbols, any eight substitutions
  detected up to 1023 symbols), and strict byte/5-bit regrouping.
- `core/ticket` (ADR-009): `Ticket` (an endpoint and a 32-byte secret `K`,
  opaque), `encode`/`decode` of the `pl1` text (130 characters onion, 74
  loopback), `keys` (locator, retrieve capability, AEAD key and nonce,
  commitment key, each under its own HKDF label), `seal` and `open` (the
  AEAD, then the HMAC commitment to the plaintext).
- `core/grant` (ADR-015): `GrantToken` (an `Endpoint` and a 32-byte `Capability(Provision)`, opaque), `encode`/`decode` of the `plg1` codex32 text (131 characters onion, 75 loopback), domain-separated from `pl1` tickets.
- `core/http1`: pure, total HTTP/1.1 framing for the mailbox binding; an
  incremental response parser bounded as bytes arrive.
- `core/crypto/keys`, `identity`, `hkdf`: typed X25519, Ed25519, ML-DSA-65
  and ML-KEM keys, and `HybridSignature` (Ed25519 and ML-DSA-65 over one
  message); the per-relationship `Identity` (two signing keys and an
  agreement key) whose `PublicIdentity` exists only with a verified hybrid
  binding; RFC 5869 HKDF.
- `core/crypto/suite`: `Suite`, the record of primitive functions. It
  gained `sha512` for CPace, the only SHA-512 user in the profile.
- The hybrid PAKE of `draft-vos-cfrg-pqpake-03`, configuration
  `cpaceoquake-x25519-mlbuaskem1024` (ADR-016), one module per layer:
  `core/crypto/elligator2` (RFC 9380's map onto Curve25519, over `Int`);
  `core/crypto/pake_common` (the configuration's `dst`, `lv_encode`,
  `encode_public_context`, and `transcript_hash` with the DST as an
  argument); `core/crypto/cpace` (CPace over X25519 and SHA-512 in the
  draft's Appendix B wrapper, `CpaceError`); `core/crypto/kemeleon` (the
  rejection-free encoding of an ML-KEM-1024 key at `t = 132`, 1596
  bytes, with opaque `Randomness`); `core/crypto/bua_skem` (ML-BUA-sKEM:
  `keygen`, `split` at byte 1564, `combine`, `encapsulate`,
  `decapsulate`); `core/crypto/oquake` (OQUAKE, messages of 1660 and 1600
  bytes); `core/crypto/cpace_oquake` (the sequential combiner, `msg1` 34,
  `msg2` 1694, `msg3` 1600 bytes, `CombinerError`). The steps that draw
  randomness have variants that take it as an argument
  (`cpace.init_with_scalar`, `oquake.init_with`,
  `cpace_oquake.respond_with`, `kemeleon.randomness_from_multiples`,
  `bua_skem.key_pair_from` and their siblings) so the draft's vectors can
  drive them; nothing but a test calls them.
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
  process-wide counter for tests that build several suites. Its `sha512`
  is a deterministic 64-byte stand-in, not SHA-512.

The spoken-code PAKE and run (ADR-016). Implemented and tested as below;
assumed, per the ADR, are that the draft's argument carries over to a
store-and-forward rendezvous, that the confirmation and hand-off
derivations are sound uses of the session key, and the timing argument.

- Kemeleon's `decode` is total: every string of `encoded_key_bytes`
  decodes to a well-formed ML-KEM-1024 encapsulation key, so a wrong
  password at OQUAKE unmasks to something indistinguishable from a key.
  That is the property OQUAKE rests on, checked over arbitrary bytes with
  the test file's own FIPS 203 decoder
  (`decode_is_total_and_yields_valid_keys_test` in
  `test/core/crypto/kemeleon_test.gleam`) and, over the real primitives,
  as a key OpenSSL accepts
  (`every_string_of_the_right_length_is_a_public_key_test` in
  `packages/primitives/test/primitives/bua_skem_test.gleam`). The formal
  model finds Kemeleon load-bearing for the hybrid claim specifically:
  without it the code falls to an X25519 break alone
  (`docs/formal/crypto.md`, rendezvous finding 2).
- OQUAKE's `finish` and the combiner's `responder_finish` never report a
  wrong password. A tag that does not verify, or a failed decapsulation,
  yields a fresh random key, drawn whether or not it is used, so both
  outcomes make the same suite calls. Completion is therefore no evidence
  the peer held the words, and `core/rendezvous` confirms explicitly
  (`a_changed_tag_finishes_with_the_fallback_test`,
  `e4_changed_tag_gives_an_unrelated_key_test`).
- CPace aborts with `LowOrderShare` when the shared point is the
  identity, checked in `cpace` itself as well as by the suite's X25519,
  so the abort does not rest on OpenSSL refusing zero
  (`the_abort_holds_for_a_suite_that_returns_zero_test`; over the real
  primitives, cpace-21 B.1.10 and pqpake-03 E.5.4).
- `pairing_code.decode` is total and strict: at most
  `max_pairing_code_bytes`, lowercase ASCII letters, digits and single
  hyphens, exactly six nameplate digits and three listed words, no case
  folding or trimming. What it accepts re-encodes to the same text, so a
  mistyped word is refused locally and never spends the code. No
  `CodeError` carries any of the text; `UnknownWord` carries a position
  (`errors_never_carry_the_text_test`, and the properties in
  `test/core/pairing_code_test.gleam`). `nameplate.parse` accepts only the
  zero-padded spelling.
- The rendezvous states fix the order of the steps but not single use:
  a Gleam value can be stepped twice. Each step run on a second message at
  the same index hands the peer another guess at the words, so the shell
  MUST take only the first message at each index and drop the run on any
  `RunError`. Nothing in `core` enforces this; the daemon side that will
  is in progress.
- `m4` is sealed once. The hand-off key and nonce are fixed by the
  session key, so `inviter_release` is the only sealing path, it seals
  only after `confirm_J` matched in constant time, and the caller keeps
  and resends the returned bytes. The release is deterministic in the
  run, which the tests state as a property
  (`the_release_is_deterministic_in_the_run_test`,
  `a_release_is_the_same_bytes_every_time_test`).
- Secrets stay opaque: the password, generator, scalars, shared points,
  decapsulation key, Kemeleon randomness, every session key, the
  confirmation key and the ticket are `Secret`s or live inside opaque
  states, and no `CpaceError`, `CombinerError`, `RunError` or `CodeError`
  carries bytes. Each module's test file renders its values and checks
  that no secret appears (in `primitives`, `nothing_prints_a_secret_test`
  for the whole run).
- Every message's length is checked before anything else, so a message
  of the wrong shape is `MalformedMessage`, never a counted guess.
  `MalformedMessage` and `LowOrderShare` are interference; only
  `ConfirmationFailed` may be a spent guess.
- What the draft's vectors pin, through fixtures in
  `packages/primitives/test/vectors/`: cpace-21 B.1 the CPace suite
  (generator, shares, shared point, key) and B.1.10 its low-order aborts;
  pqpake-03 E.4 the CPace wrapper, the OQUAKE stage and CPaceOQUAKE end
  to end for both roles, and E.5.4 the neutral-element abort; E.2 OQUAKE
  alone under its own DST; E.1.2 Kemeleon alone (the vector key
  re-encodes byte for byte). The run's key schedule and public context
  are pinned by a vector from an independent script, not from the draft.
  Elligator 2 is also checked against cpace-21 A.5's reference map, run
  in Python on inputs that take both branches.
- Not reproduced: ML-KEM's own steps inside the vectors. They fix
  ML-KEM's randomness (`keygen_seed`, `encaps_m`), which OTP cannot take,
  and list no decapsulation key. In the vector tests the suite's ML-KEM
  fields are overridden to answer exactly what the vector says ML-KEM
  answered, and only for the key and ciphertext the vector names;
  everything OQUAKE computes runs for real. Honest and wrong-password runs
  over the real ML-KEM are separate tests.
- In `core`'s own tests ML-KEM is a stand-in: `kem_suite` in
  `test/core/crypto/oquake_test.gleam` and, made public for
  `rendezvous_test`, in `test/core/crypto/cpace_oquake_test.gleam`. The
  fake suite's ML-KEM keys fail Kemeleon's modulus check, so these
  replace the three ML-KEM fields with a KEM whose keys are well formed
  and whose secret is a hash of key and ciphertext. It is no KEM against
  an attacker; it keeps only what agreement depends on.
- Mutation results recorded in the test files cover the code text, not
  the cryptography: `nameplate_test` (both range bounds, and a digit
  guard admitting `+`, which only a stray byte mid-string exposes) and
  `pairing_code_test` (uppercase admitted, a fourth word accepted,
  ten-bit fields, a four-byte draw, a wrong slot width, a skipped first
  bit; `search` was not mutated). The PAKE and run tests record no
  mutation runs.
- `elligator2` and `kemeleon` compute over Gleam's `Int`, which is a
  float on the JavaScript target; they are correct on the BEAM only.

## Deep Docs

- `docs/spec.md` §10.1 (functional core), §11.3 (limits), §13 (invariants
  and test strategy).
- `docs/adr/006-end-to-end-retransmit.md` (retransmission and
  regenerated receipts).
- `docs/adr/008-deadline-slack.md` (retention slack and shorter offers).
- `docs/adr/009-invitation-tickets.md` (tickets, the sealed blob) and
  `docs/crypto-profile-v1.md` §11.
- `docs/adr/010-dedup-and-quarantine.md` (repeated identifiers).
- `docs/adr/016-spoken-pairing-codes.md` (the spoken code, the PAKE, the
  rendezvous), `docs/crypto-profile-v1.md` §12 (its bytes), and
  `docs/formal/crypto.md`, "Spoken pairing codes" (the ProVerif model).
- `docs/crypto-profile-v1.md` (the profile, byte for byte),
  `docs/adr/002-pq-crypto-over-otp.md` and
  `docs/adr/005-hybrid-authentication.md`.
- `docs/gleam-style.md` Part IV §5 (purity layering).
- `docs/formal/lean.md` (the Lean proofs and the conformance vectors).
