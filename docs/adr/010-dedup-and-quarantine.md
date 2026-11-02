# ADR-010 — A repeated message identifier is ignored, and an envelope that keeps failing is quarantined

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §7.3, §8.3, §11.3, §12.4

## Decision

Both halves are the owner's ruling on the DST audit (`docs/dst/plan.md`,
Rulings): "A message id an authenticated peer already used is ignored (no
second delivery; the envelope is still processed and acknowledged). An
envelope that fails to process a bounded number of times is recorded,
dropped and acknowledged, so one envelope cannot block its queue. Both are
visible to the operator."

**A repeated identifier is a decision of the core.** Receiving a ratchet
message takes two steps, because only the store knows which identifiers a
relationship used and the identifier is known only after decryption:

- `relationship.open(suite, relationship, now, envelope, ratchet_bytes)`
  decrypts and decodes into an opaque `Opened`, changing nothing. A failure
  is a refusal, dropped and acknowledged as before.
- The shell reads `relationship.opened_message(opened)` against its
  deliveries (`store.message_history`, any row under `(contact,
  message_id)`, held, ready, consumed or expired) and answers with an
  `IdHistory`: `FreshId` or `UsedId`.
- `relationship.receive(opened, history)` decides. An application message
  the relationship would store under a `UsedId` is ignored: the session
  advances past it, the envelope is recorded `Processed` (`Applied`), and the
  only other record is `plan.RepeatedMessage`. It is not delivered, earns no
  receipt and spends no budget. Every other message is handled as before;
  only application messages consult the history.
- A history the store cannot read answers `Unavailable` and commits nothing.

The store's `UNIQUE (contact, message_id)` on `deliveries` stays, and a
second `Delivered` row still fails the whole commit
(`store_test.a_second_delivery_of_one_message_fails_the_whole_commit_test`).
It is the backstop; the core never plans one.

**An envelope that keeps failing is quarantined by the shell.** The engine
counts each attempt to process an envelope that is not a repeat (identifier
and digest both matching its `Processed` row), before the core sees it:

- `store.count_attempt` increments `attempts(queue, envelope)` in a
  transaction of its own, which commits before processing starts.
- When the count passes `limits.max_process_attempts` (5), the envelope is
  not processed again. `store.Quarantined` writes its `Processed` row as
  `Dropped`, so the fetcher acknowledges it, and an incident.
- The `Processed` row that settles an envelope, by any path, deletes its
  count in the same transaction.

**Both are visible to the operator.** Schema version 3 adds `incidents`:
kind (`repeated_message` or `quarantined`), queue, envelope, the contact and
repeated message identifier when known, the failure count for a quarantine,
and a time. Never a payload. `api.incidents` lists them newest first,
`api.health` counts them, the local API has an operator-only `incidents`
op and the CLI `pondline incidents [--limit N]`.

## Why

The shell DST found H2 blind (seed `000001…08c0`, now in `sim.corpus()`):
a byzantine authenticated peer that repeated a message identifier made the
receiver plan a second `Delivered` row, the store refused the commit,
`engine.process` answered `Unavailable`, and the fetcher, which hands a batch
over in order and stops at the first failure, never acknowledged the
envelope. Every later envelope on the queue waited behind it until mailbox
retention.

**Why in the core and not `INSERT OR IGNORE`.** An ignored insert hides the
duplicate from the store but not from the transition: the budget counted the
message twice (the audit saw this at 3f57317), a receipt was queued for it,
and its fingerprint replaced the first. The earlier hardening made a
duplicate delivery fail the commit precisely so that state and store could
not diverge silently. Deciding in the core keeps the budget, receipts and
fingerprints consistent, and keeps the constraint as a check rather than a
mask.

**Why advance the session.** The message authenticated; its key is spent
either way. Advancing keeps the forger's next honest message decryptable in
order, and a replay of the same ciphertext is then undecryptable instead of
being opened, found used, and recorded again forever.

**How this differs from ADR-006.** The same ciphertext arriving again is a
retransmit or a replay, matched by its fingerprint and answered with the
same logical receipt before it is ever opened. Different bytes under a used
identifier cannot come from an honest sender, which never re-encrypts a
message (ADR-006), so they are ignored and earn nothing.

**Why count before processing.** A count written after a failure misses the
failure that crashes the engine, and a crash loop would never end. Writing
it first, durably, counts every failure mode. The ambiguous case is
excluded by ordering: an attempt whose commit landed and whose answer was
lost (an `AckLost` commit, an engine job that applied and then failed) left
a `Processed` row, so its redelivery is a `Repeat` before any counting and
its count was already cleared.

**Why quarantine is safe for an honest message.** It changes no
relationship state. A legitimate message that failed for a transient reason
(a disk that failed five commits in a row, say) is not receipted, so its
sender sends the same ciphertext again under a new envelope once the
receipt window passes (ADR-006), and the copy is processed fresh. The bound
trades how long one envelope may block a queue (about fifteen seconds of
fetcher backoff for five attempts) against how readily a transient failure
sets an envelope aside; recovery through the retransmit makes the second
cheap.

What is implemented and tested:

- `core`: `relationship.open`, `opened_message`, `receive(opened, history)`,
  `IdHistory`, `plan.RepeatedMessage`, `limits.max_process_attempts`
  (`test/core/dedup_test.gleam`; ignoring the history fails it).
- `daemon`: schema 3 (`incidents`) and 4 (`attempts`), `store.message_history`,
  `count_attempt`, `Quarantined`, `incidents`, `incident_count`; the engine's
  `open_and_receive`, `attempt` and `quarantine`; the operator surface.
  `test/daemon/dedup_test.gleam` forges a repeated identifier between two
  real daemons over a real mailbox: the receiver records the incident,
  drains the queue and delivers the next honest message; telling the core
  `FreshId` always fails it. `test/daemon/quarantine_test.gleam` poisons the
  receiver's deliveries with a trigger: the envelope is quarantined after
  five failures, the queue drains, and once healed the sender's retransmit
  is delivered once; never quarantining fails it.
- `sim`: the H2 seed passes in the corpus under the double run, and swarm
  campaigns over every fault class find no failure.

## Consequences

- Each inbound envelope that is not a repeat costs one more durable
  transaction (the attempt count) under `synchronous=FULL`. Inbound volume
  in this system is low; if it matters, counting only after a fetcher has
  seen a failure or restarted would remove it from the steady state.
- `incidents` grows by one row per repeated identifier or quarantine and is
  not pruned, like `processed`. A peer that floods repeated identifiers
  costs the receiver a row each; closing the relationship ends it.
- An `attempts` row for an envelope that is never served again (its queue
  retired before it settled) stays. Each needs a failed processing, so the
  table stays small.
- An honest message quarantined by a transient failure arrives a receipt
  window late (an hour), not never. The exception is a joiner's `Initial`
  frame (its `Hello`): the handshake is never retransmitted (ADR-006), so a
  quarantined `Hello` leaves the joiner in `AwaitingAccept` with nothing to
  move it. Before this ADR the `Hello` would have been retried until the
  inviter's store healed. The operator recovers by closing the joiner and
  accepting the invitation again while the offer is open; a closed joiner
  releases its invitation for that (ADR-011). Retransmitting the handshake
  would close this, at the cost of ADR-006's rule that it is sent once.
- A fetcher whose queue retired keeps retrying its acknowledgements until
  the mailbox takes them, so a mailbox that refuses them for good (its queue
  deleted behind the daemon's back) keeps that fetcher backing off at its
  cap. The daemon never deletes a queue, so this needs an operator's hand.
- Revisit if a production deployment shows quarantines of honest traffic, or
  if the inbound commit rate makes the extra transaction measurable.

## Addendum (2026-11-01): a repeat served after its acknowledgement

The ruling says one envelope cannot block its queue. A repeat could. The
engine answered an envelope whose identifier and digest match its
`Processed` row `Repeat` and committed nothing, and the fetcher
acknowledges only `store.unacked`, the rows with `acked = 0`. That is right
for the usual repeat, an envelope served again before the round that
acknowledges it. It is wrong for one the mailbox serves again after the
acknowledgement, which happens two ways:

- **A restore.** The mailbox's database is restored from a backup taken
  before the acknowledgement (or a lagging replica is promoted). The
  envelope comes back at its old place, at the head of its queue, and its
  tombstone was never written.
- **A late retry.** The sender's append was stored but its answer lost.
  ADR-008 has the mailbox hold the envelope, and then its tombstone, only
  until the retention deadline, up to `retention_slack_seconds` before the
  message expires, while the sender retries until the expiry. A retry in
  that last stretch finds neither and `insert_new` stores the envelope
  again.

The row was already acknowledged, so nothing ever named the envelope in an
`Ack` again. The mailbox served it until its retention deadline (up to a
week for a restore), the fetcher looped on it with no pause (a finished
round starts the next at once), and sixteen of them at the head of a queue
(`limits.fetch_batch_envelopes`) filled every fetch, so messages behind
them could expire undelivered, past the 31 hours of retransmits. Safety
held; liveness did not.

The P model of end-to-end delivery (`formal/p`, `docs/formal/p.md`) found
it with no fault aimed at it: its design case `tcExpiry` reached the late
retry. The `cx*` cases in `formal/p/PTst/judge.p` reproduce both paths and
the generic fault mix of `tcAll`. Neither earlier judge saw it: the pure
simulation's honest shell acknowledges every matching stored envelope with
no acknowledged flag, and no fault class of the shell DST served an
acknowledged envelope again.

**Decision.** A `Repeat` marks its processed row unacknowledged
(`store.mark_unacked`, the `MarkUnacked` query), so the next round's
acknowledgement names it, and the mailbox deletes it and writes a fresh
tombstone. For a repeat that was never acknowledged the update changes
nothing. This keeps the fetcher's one rule, acknowledge exactly what the
store says is committed and unacknowledged:

- The processed row and its digest stay, so the envelope is never
  processed or delivered again.
- No attempt is counted: the repeat check comes before `count_attempt`, and
  a repeat is not a failure.
- A queue that retires between the repeat and the next round still has an
  unacknowledged row, so `draining_inboxes` gives it a fetcher that
  acknowledges and stops. A retired queue is never polled, so it cannot be
  handed a repeat in the first place.
- It cannot loop: a round acknowledges before it polls, so the repeat is
  gone from the mailbox before the next fetch. A mailbox that keeps
  restoring is a mailbox serving byzantine answers, which it can do anyway.

The other shape, the fetcher acknowledging every `Repeat` from the batch it
fetched, was rejected. It gives the fetcher a second source of
acknowledgements beside the store, which the no-acknowledgement-before-
commit tests mutate against, and the intent lives only in the fetcher's
memory: a fetcher that crashes, or whose queue retires, before it names
the repeat leaves it at the mailbox.

**Verification.**

- `daemon/test/daemon/reack_test.gleam`, two real daemons and a real
  mailbox: B delivers and acknowledges sixteen messages; the mailbox brings
  them back by a restore (the rows under their old `seq`, tombstones gone,
  bytes counted again) or by A's own appends after the tombstones are
  swept; a seventeenth must arrive, the queue drain and the agent see each
  message once. Without the unack both time out waiting for the
  seventeenth.
- `sim`: a `restore` fault class (`sim/restore`). A trigger in the
  mailbox's database keeps a backup of every envelope it stores, and the
  `RestoreMailbox` op puts back every one it has since tombstoned. On the
  pre-fix code the blind swarm finds the defect (`queues_drained`: the
  mailbox still holds them; and the runner's livelock check on the spin).
  `--seed 1 --runs 200 --keep-going` first fails at run 23 (4 of 200
  seeds) and `--seed 2` at run 9 (9 of 200). With the fix, `--seed 1` and
  `--seed 2` at 1000 runs each, every class on, find nothing (three
  `lied_append` excuses). The corpus's last seed is a minimal restore.
- The P model's `reackRepeat` is on in `Base()`, so every design case runs
  the fixed rule; the `cx*` cases keep it off and stay in the judge as
  recall cases.

## Addendum: 2026-11-02

The project was renamed from Reedwire, and this record was updated to match. [ADR-014](014-the-name-is-pondline.md) has the decision.
