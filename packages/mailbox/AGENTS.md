# mailbox

## Purpose

The mailbox service's durable store and request handling (`docs/spec.md`
§6, §8.4, §10.2). It serves the typed commands of
`core/mailbox/protocol` against one SQLite file and runs the few processes
a mailbox node needs. It has no HTTP, no TLV and no CLI: the HTTP binding
decodes a body into a `Request`, calls `node.handle` and encodes the
`Response`. Time arrives as an `Instant` and randomness as a function, so
the rules are plain functions of a `Store` that tests call without a
process.

## Key Types

- `mailbox/store`: `Store`, the schema, the pragmas (WAL, `synchronous=FULL`,
  `fullfsync=ON`, `foreign_keys=ON`, a busy timeout), `PRAGMA user_version`
  migrations, `transaction`, and every SQL statement in the package.
- `mailbox/service`: `handle(store, now, request) -> Response`, `sweep`,
  and `create_grant(store, allowance, random)`, which returns the
  provisioning capability once and stores only its hash.
- `mailbox/coordinator`: the storage coordinator actor, the one writer. It
  receives complete commands and tells the notifier after an append commits.
- `mailbox/notifier`: the queue notification registry (queue to waiting
  callers), addressed by `Name`.
- `mailbox/sweeper`: a periodic actor that asks the coordinator to sweep.
- `mailbox/node`: the `rest_for_one` supervisor, `Names`, `Node`, and
  `handle`, which also performs the long poll in the caller's own process.

## Relationships

Depends on `core` (protocol, ids, capabilities, envelopes, limits, time)
and `primitives` (`sha256`, `constant_time_equal`), plus `sqlight` (esqlite,
Apache-2.0), `gleam_otp` and `gleam_erlang`. Nothing depends on it yet; the
HTTP binding will.

## Traffic

- Request process to coordinator: `Handle(now, request, reply_with)`,
  `Sweep` and `CreateGrant`, answered on a per-call subject. The call fails
  soft: no coordinator or no reply in time is `Refused(Unavailable)`.
- Coordinator to notifier: `Notify(queue)` after an `Appended` response,
  following the commit.
- Long-polling caller to notifier: `Wait`, then a synchronous `Forget`, so no
  wake-up can reach the caller after cleanup.
- Sweeper to coordinator: a `Sweep` every `sweep_period_ms`.

## Invariants

- The coordinator is the only process holding a connection, and every
  change is one `store.transaction` run inside one call. No transaction
  spans a message, and no one waits while holding one.
- Capabilities are stored and compared only as SHA-256 hashes, with
  `constant_time_equal`. A missing queue and a wrong capability are both
  `Unauthorized`.
- Quota is reserved and the envelope row inserted in one transaction, and
  the receipt is built after the commit.
- An acknowledged envelope leaves a tombstone (digest and deadline), and an
  append for a known identifier is answered from the stored envelope or the
  tombstone before anything is inserted, so a retry never resurrects it.
- `Ack` deletes exactly the named envelopes; it is never a cursor.
- A long poll registers with the notifier before its last look at the
  database, so an append between the look and the wait is not missed.
- No secret reaches an error, a log or a message. Refusals carry no request
  data.
- Known gaps: no per-operation rate limit beyond the byte quota; no
  replication; no revocation or rotation; a `Fetch` and the sweeper share the
  coordinator's single connection, so reads are serialized with writes.

## Deep Docs

- `docs/spec.md` §6.4, §6.5 (append and fetch semantics), §8.4, §10.2.
- `docs/review/2026-10-31-design-review.md` Review B §3.8 (tombstones) and
  §3.10 (SQLite durability, no interactive transactions).
- `docs/gleam-style.md` Part III (actors) and Part IV.
