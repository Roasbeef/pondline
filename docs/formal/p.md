# A P model of end-to-end delivery

This is a model of Reedwire's message delivery protocol in the P language
(P 3.0.4), checked with P's systematic tester. It covers one relationship
between two daemons and one mailbox: commit-then-send outboxes, the
mailbox's idempotent append, tombstones, fetch and ack, the processed rule,
ADR-006 retransmission and fingerprints, ADR-004's implicit accept, the H2
ruling on repeated message identifiers and the quarantine ruling on poison
envelopes, with crashes at the commit points and a bounded menu of network
and mailbox faults.

The model lives in `formal/p/`. It is judged by more than passing: every
monitor is tripped by a mutant, four historical bugs are recovered by
restoring the rule each fix replaced, the fault budget under which liveness
is claimed is shown to be tight, and each recall has a control that passes.

The model found one defect in the design as it stood: **an envelope the
receiver already acknowledged, served again by the mailbox under the same
identifier and bytes, was never acknowledged again**. The receiver's
fetcher then fetched it forever, and enough of them at the head of a queue
blocked the queue until their retention deadlines. It is fixed (ADR-010,
addendum): the engine answers such an envelope `Repeat` and marks its
processed row unacknowledged, so the next round names it to the mailbox.
It is described in full under
[The counterexample](#the-counterexample-an-acknowledged-envelope-served-again).

## Running it

```sh
formal/p/check.sh      # the design test cases; non-zero on any bug
formal/p/judge.sh      # mutants, recalls, calibration, counterexamples;
                       # non-zero if any of them is NOT caught
```

Both compile the model first (`p compile` in `formal/p/`), run one checker
process at a time with a fixed seed (20261101) and fixed schedule counts,
and write logs and bug traces under `formal/p/out/`. `check.sh` runs every
design case twice, once with the random scheduler and once with PCT (10
priority switch points), which favours long delays of one machine: the
shape of a receiver offline for a day or a receipt slower than a window.
`check.sh 4` multiplies every budget by four. On the development machine
`check.sh` takes about six minutes and `judge.sh` under a minute.

P is a .NET tool: `dotnet tool install --global p --version 3.0.4`, with
the .NET 8 SDK. The scripts add `~/.dotnet/tools` to `PATH` and set
`DOTNET_ROOT` to `~/.dotnet` when it is unset.

To read a bug, open `out/<script>/<case>/BugFinding/Reedwire_0_0.txt`.
`p check <dll> -tc <case> --replay <file>.schedule` replays it.

## What is modelled

| Machine | File | Mirrors |
|---|---|---|
| `Daemon` (two instances) | `PSrc/daemon.p` | `daemon/scheduler.gleam` (send, classify, retry), `daemon/store.gleam` (outbox rows, `record_send`, `copy_row`, `unacked`, `mark_acked`), `daemon/engine.gleam` (`handle_envelope`, `receive`, `retransmit_one`), `daemon/fetcher.gleam` (rounds: ack what is processed, fetch, process in order, stop at the first failure), `core/relationship.gleam` (`receive`, `in_awaiting`, `store_application`, `resend_receipt`), `core/retransmit.gleam` (`due_at`, `retransmit`) |
| `Mailbox` | `PSrc/mailbox.p` | `mailbox/service.gleam` (`append_to`, `replay`, `insert_new`, `fetch_batch`, `ack_envelopes`), `mailbox/store.gleam` (`sweep`), `mailbox/sql/envelopes.sql` (`LiveEnvelopes` order and limit) |
| `Timer` | `PSrc/mailbox.p` | the scheduler's tick, the receipt window and every backoff |
| `Clock` | `PSrc/mailbox.p` | the clock passing a message's expiry, learnt by each node separately |

Daemon A is the inviter. It commits an `Accept` (when pairing is in the
test case) and the agent's application messages, sends them, retransmits
stored rows whose receipt window passed, and reads receipts from its queue.
Daemon B is the joiner. It starts in `AwaitingAccept`, reads its queue,
stores application messages for its agent and queues receipts back to A.
Both run the same code; only the role differs.

**Durable and volatile state.** Everything a SQLite commit writes is
durable in the model: outbox rows with their status, copy count and
schedule, the sent-message state, the processed records and their acked
flag, fingerprints with their answer counts, deliveries, the spent ratchet
keys, the phase and the quarantine attempt counts. The in-flight set, the
fetcher's state and an epoch are volatile. A crash resets the volatile
state, bumps the epoch, and restarts from the durable state the way the
daemon does: every queued row is sent, every running schedule is re-armed,
and the fetcher begins a round, which acknowledges what was processed and
never acknowledged. Replies to requests from an older epoch are ignored, as
a reply to a dead connection is lost.

**Atomicity and crash points.** A P handler runs atomically, so a handler
is one transaction plus the sends that follow it. A crash point is a
nondeterministic choice placed between a commit and the network action that
must follow it: after an outbox commit and before its send (both the
agent's send and a retransmit copy), after an inbound commit and before the
next round's ack, and after an append's answer arrives and before it is
recorded (the append response lost).

**The inbound path** follows `handle_envelope` in order: the processed rule
(same identifier and digest is a `Repeat`, and nothing is committed);
quarantine (an envelope that failed `maxAttempts` times is recorded,
dropped and acknowledged); a transient process failure (nothing commits,
the attempt is counted); the fingerprint lookup (a known, undamaged
ciphertext goes to `resend_receipt`); decryption (a damaged ciphertext or a
spent key is dropped); then the phase and body. `store_application` checks
expiry, then the H2 rule, then stores, remembers the fingerprint with one
receipt, and queues the receipt in the same commit.

### Abstractions, and what each could hide

- **Cryptography is tokens.** A ciphertext is the tuple `(kind, msg, mid,
  seal, dmg, pad)`. Tuple equality is the digest. `(kind, mid, seal)` is the
  ratchet key a decrypt spends; `(mid, seal)` is the fingerprint. Sound for
  delivery properties because the protocol only ever compares, hashes and
  decrypts ciphertexts, and AEAD makes "decrypts" equivalent to "is an
  undamaged ciphertext under an unspent key". It hides everything about
  the ratchet's own state, including the bound on skipped message keys
  (`max_skipped_message_keys`): reordering deep enough to exceed it would
  lose messages and is not modelled.
- **Padding damage keeps the fingerprint.** `pad` changes the envelope
  digest and nothing else, because the zero padding is not authenticated
  (`core/envelope.gleam`) and the fingerprint hashes inside it (ADR-006).
- **Time is events.** "A receipt window passed" and "a backoff elapsed" are
  `Timer` events the scheduler delivers whenever it likes, so every
  ordering of windows against deliveries is reachable, including all copies
  sent before the receiver fetches anything. The doubling of the window is
  not modelled, and neither are durations: the model cannot say how long
  anything takes, only what happens in which order.
- **Expiry is one event per message per node.** The clock tells A, B and
  the mailbox separately, so their views of a message's expiry can differ
  in either direction, which covers clock skew. Receipts' own week-long
  expiry is not advanced. The mailbox sweeps a message's envelopes and
  tombstones when it learns the message expired, and refuses a new append
  of it from then on (every offered deadline is at most the expiry, so the
  real mailbox answers `BadDeadline`, which the sender retries).
- **Retention slack is one fault.** ADR-008 offers an original's retention
  deadline up to `retention_slack_seconds` short of the message's expiry,
  so its tombstone can go before the message expires. `fEarlySweep` removes
  one tombstone early. Envelopes swept early (the original lost to retention
  while the receiver is offline) are covered by `fLoss`, which is the same
  event at the receiver.
- **One relationship, one direction of application messages, a single
  mailbox holding both queues.** The joiner sends only receipts. Close,
  Reject, budgets (`Held`, `HeldFull`) and the handshake's `Initial` frame
  are not modelled; the joiner begins having sent its Hello.
- **Small numbers.** Two messages, `maxRetx = 2` and `maxAttempts = 2`
  (the limits are 5 and 5), one case with `maxRetx = 3`. Every argument
  below is about counts relative to `maxRetx`, so the small values exercise
  the same boundaries.
- **A fetch returns the whole queue** in insertion order unless a case sets
  `batchMax`. `cxBlock` sets it to one, standing in for
  `limits.fetch_batch_envelopes` (16).
- **Quarantine is modelled from the ruling, not from code.** It is being
  implemented on branch `dedup` (ADR-010 draft, `limits.max_process_attempts`
  and `packages/daemon/sql/004_attempts.sql`, uncommitted). The model
  counts an attempt for every process failure, transient ones included, as
  the draft's `limits.gleam` comment and `quarantine_test.gleam` describe.
- **H2 is modelled from branch `dedup`** (`relationship.open` and
  `receive(opened, history)`, commit 2aab7aa): a repeated identifier under
  different bytes advances the session, is processed and acknowledged, and
  earns no delivery and no receipt.

### Faults

Every fault is bounded by a per-test-case budget, so every run of a
correct model reaches a point where nothing is left to do.

| Fault | Where | Effect |
|---|---|---|
| `fDrop` | mailbox | a request or its response is lost; the client times out |
| `fDown` | mailbox | a request is answered `Unavailable` |
| `fDupReq` | mailbox | an Append is delivered again later; its answer goes nowhere |
| `fDup` | mailbox | one envelope is served twice in a batch |
| `fReorder` | mailbox | one envelope is moved to the head of its queue |
| `fLoss` | mailbox | a stored envelope is deleted after `Appended`, no tombstone |
| `fCorrupt` | mailbox | a stored envelope's ratchet bytes are damaged |
| `fPad` | mailbox | a stored envelope's padding is damaged |
| `fReplay` | mailbox | a ciphertext it holds or held is inserted under a new identifier |
| `fRestore` | mailbox | an acknowledged envelope is back under its own identifier at the head of the queue, its tombstone gone (a restore from backup) |
| `fEarlySweep` | mailbox | a tombstone is swept before its message expires |
| `fCrashA`, `fCrashB` | daemon | a crash at one of the commit points above |
| `fProcFailA`, `fProcFailB` | daemon | a transient store fault fails one process attempt |
| `fExpire` | clock | the clock passes one message's expiry |
| `fForge` | daemon A | A seals different bytes under an identifier it used |

**Spoiling faults.** A loss, a corruption and a quarantine each cost a
message one of its `1 + maxRetx` chances: one envelope of the message, or
one of its receipts, is gone. Every other fault is recovered without
spending a copy (the same bytes are retried under the same identifier, the
processed rule answers a duplicate, and so on). The design cases keep the
spoiling faults at or below `maxRetx` and budget the rest freely; the
calibration cases in the judge show that one more spoiling fault breaks
liveness, so the budget is the edge of the claim.

## Monitors

| Monitor | Kind | Rule | Source |
|---|---|---|---|
| `AtMostOnceDelivery` | safety | the agent sees each logical message at most once | spec §13.1, no replay-driven redelivery |
| `NoSendBeforeCommit` | safety | every ciphertext on the wire was committed to an outbox first | spec §13.1, §8.2 |
| `NoAckBeforeCommit` | safety | an envelope is acknowledged only after its processing committed | spec §13.1, §8.3 |
| `ReceiptOnlyForStored` | safety | a receipt is queued, and a sender marks `ReceivedByPeer`, only for a message the receiver stored | spec §7.3 |
| `NoExpiredDelivery` | safety | nothing the receiver's clock holds expired reaches its agent | spec §8.3 |
| `DeliveredAndReceipted` | liveness (hot) | every committed message whose expiry has not passed is eventually stored for the agent and its sender eventually commits the receipt | ADR-006 |
| `QueuesDrain` | liveness (hot) | every envelope a mailbox holds is eventually acknowledged or swept, so no envelope blocks its queue | the quarantine ruling, `docs/dst/plan.md` |

P reports a liveness violation in two ways. "Detected liveness bug in hot
state ... at the end of program execution" means every machine ran out of
work with an obligation open. "Detected potential liveness bug in hot
state" means a run stayed hot until the checker's fair-step bound (100,000
steps) ran out, which in this model only happens when something loops
forever: a fetcher retrying the same envelope, or fetching one it never
acknowledges. A correct run of this model ends in a few hundred steps.

## Test cases

Design cases (`PTst/design.p`, run by `check.sh`), budgets per scheduler:

| Case | Faults | Schedules |
|---|---|---|
| `tcHappy` | none | 200 |
| `tcNetwork` | drop 3, down 2, dupReq 2, dup 1, reorder 2 | 1000 |
| `tcCrash` | crash 2 on each daemon, drop 1 | 1000 |
| `tcMailbox` | loss 1, corrupt 1, pad 1, restore 1, earlySweep 1, reorder 1, drop 1 | 1500 |
| `tcReplay` | replay 2, loss 1, pad 1, crash B 1 | 1000 |
| `tcBoundReplay` | one message, replay 2, loss 2 | 1500 |
| `tcQuarantine` | process failures 2 on each daemon (one quarantine each), crash B 1, drop 1 | 1000 |
| `tcForger` | forge 1, reorder 1, drop 1 | 800 |
| `tcH2Off` | H2 off, quarantine on, forge 1 | 800 |
| `tcExpiry` | expire 1, earlySweep 1, loss 1, crash 1 on each, drop 1 | 1000 |
| `tcAll` | every fault class, spoils within the bound | 2000 |
| `tcThreeSpoils` | one message, `maxRetx = 3`, loss 2, corrupt 1, drop 1 | 1000 |
| `tcCtlTwoLosses` | one message, loss 2 | 800 |
| `tcCtlNoRetransmit` | retransmit off; drop 2, down 1, dupReq 1, dup 1, crash 1 on each | 600 |
| `tcCtlNoFingerprint` | fingerprint lookup off; the same faults | 600 |
| `tcCtlPreH2` | H2 and quarantine off, honest peer; drop 2, loss 1, crash B 1 | 600 |
| `tcCtlNoImplicitAccept` | implicit accept off; no faults | 200 |
| `tcCtlNoReack` | the pre-fix Repeat handling; every fault but restore and early sweep | 1000 |

Every design case asserts all seven monitors. All but `tcCtlNoReack`
run with `reackRepeat` on, which is the code's behaviour since the fix
(see the counterexample). The `tcCtl*` cases are controls for the judge:
each keeps a rule the judge restores and drops the fault that breaks it.

`check.sh` output:

```text
== compiling
tcHappy                random    200 schedules  ok
tcHappy                pct       200 schedules  ok
tcNetwork              random   1000 schedules  ok
tcNetwork              pct      1000 schedules  ok
tcCrash                random   1000 schedules  ok
tcCrash                pct      1000 schedules  ok
tcMailbox              random   1500 schedules  ok
tcMailbox              pct      1500 schedules  ok
tcReplay               random   1000 schedules  ok
tcReplay               pct      1000 schedules  ok
tcBoundReplay          random   1500 schedules  ok
tcBoundReplay          pct      1500 schedules  ok
tcQuarantine           random   1000 schedules  ok
tcQuarantine           pct      1000 schedules  ok
tcForger               random    800 schedules  ok
tcForger               pct       800 schedules  ok
tcH2Off                random    800 schedules  ok
tcH2Off                pct       800 schedules  ok
tcExpiry               random   1000 schedules  ok
tcExpiry               pct      1000 schedules  ok
tcAll                  random   2000 schedules  ok
tcAll                  pct      2000 schedules  ok
tcThreeSpoils          random   1000 schedules  ok
tcThreeSpoils          pct      1000 schedules  ok
tcCtlTwoLosses         random    800 schedules  ok
tcCtlTwoLosses         pct       800 schedules  ok
tcCtlNoRetransmit      random    600 schedules  ok
tcCtlNoRetransmit      pct       600 schedules  ok
tcCtlNoFingerprint     random    600 schedules  ok
tcCtlNoFingerprint     pct       600 schedules  ok
tcCtlPreH2             random    600 schedules  ok
tcCtlPreH2             pct       600 schedules  ok
tcCtlNoImplicitAccept  random    200 schedules  ok
tcCtlNoImplicitAccept  pct       200 schedules  ok
tcCtlNoReack           random   1000 schedules  ok
tcCtlNoReack           pct      1000 schedules  ok
```

## The judge

`judge.sh` runs every case in `PTst/judge.p` and requires a bug from the
named monitor. P stops at the first bug, so the schedule count is the
number of schedules the random scheduler needed (seed 20261101).

```text
mutReencrypt             caught at schedule 1     <ErrorLog> Assertion Failed: PSpec/safety.p:11:7 message 0 delivered to the agent twice
mutSendBeforeCommit      caught at schedule 1     <ErrorLog> Assertion Failed: PSpec/safety.p:30:7 ciphertext <kind:0, msg:0, mid:0, seal:0, dmg:False, pad:False, > sent before it was committed
mutAckBeforeCommit       caught at schedule 1     <ErrorLog> Assertion Failed: PSpec/safety.p:50:9 envelope 1001 acknowledged before its processing committed
mutReceiptForExpired     caught at schedule 59    <ErrorLog> Assertion Failed: PSpec/safety.p:67:7 receipt queued for message 0, which was never stored
mutIgnoreExpiry          caught at schedule 59    <ErrorLog> Assertion Failed: PSpec/safety.p:86:7 message 0 delivered after the receiver saw it expire
mutTightAnswers          caught at schedule 51    <ErrorLog> PImplementation.DeliveredAndReceipted detected liveness bug in hot state 'Owed' at the end of program execution.
recallNoRetransmit       caught at schedule 1     <ErrorLog> PImplementation.DeliveredAndReceipted detected liveness bug in hot state 'Owed' at the end of program execution.
recallNoFingerprint      caught at schedule 3     <ErrorLog> PImplementation.DeliveredAndReceipted detected liveness bug in hot state 'Owed' at the end of program execution.
recallPreH2              caught at schedule 1     <ErrorLog> PImplementation.DeliveredAndReceipted detected potential liveness bug in hot state 'Owed'.
recallNoImplicitAccept   caught at schedule 1     <ErrorLog> PImplementation.DeliveredAndReceipted detected liveness bug in hot state 'Owed' at the end of program execution.
calibSpoils              caught at schedule 26    <ErrorLog> PImplementation.DeliveredAndReceipted detected liveness bug in hot state 'Owed' at the end of program execution.
calibQuarantine          caught at schedule 273   <ErrorLog> PImplementation.DeliveredAndReceipted detected liveness bug in hot state 'Owed' at the end of program execution.
cxGeneric                caught at schedule 1     <ErrorLog> PImplementation.QueuesDrain detected potential liveness bug in hot state 'Holding'.
cxRestore                caught at schedule 1     <ErrorLog> PImplementation.QueuesDrain detected potential liveness bug in hot state 'Holding'.
cxBlock                  caught at schedule 2     <ErrorLog> PImplementation.DeliveredAndReceipted detected potential liveness bug in hot state 'Owed'.
cxLateRetry              caught at schedule 22    <ErrorLog> PImplementation.QueuesDrain detected potential liveness bug in hot state 'Holding'.
```

A count of 1 means the first random schedule already broke the rule. The
checker's faults fire with probability one half at each opportunity, and
the restored rules sit on the main path, so most of these need no search.
The counts are not the evidence that the faults matter; the controls are.
The mutants found later (`mutReceiptForExpired` and `mutIgnoreExpiry` need
the clock to pass an expiry between a send and its delivery,
`calibQuarantine` needs two process failures on one envelope plus two
losses) show the checker reaching the narrower interleavings too.

### Every monitor is falsifiable

| Monitor | Mutant | Caught at schedule |
|---|---|---|
| `AtMostOnceDelivery` | `mutReencrypt`: a retransmit is sealed again from the current session, a new message under a new identifier (ADR-006, "Why the same bytes") | 1 |
| `NoSendBeforeCommit` | `mutSendBeforeCommit`: the agent's message is appended before its row commits | 1 |
| `NoAckBeforeCommit` | `mutAckBeforeCommit`: the fetched batch is acknowledged before it is processed | 1 |
| `ReceiptOnlyForStored` | `mutReceiptForExpired`: an expired message, which is not stored, is answered with a receipt | 59 |
| `NoExpiredDelivery` | `mutIgnoreExpiry`: `store_application` skips the expiry check | 59 |
| `DeliveredAndReceipted` | the four recalls, the calibration cases, `mutTightAnswers` and `cxBlock` | below |
| `QueuesDrain` | `cxRestore`, `cxLateRetry`, `cxGeneric` | below |

### Blind recall of real history

Each recall restores the rule a fix replaced and adds one generic fault
class from the menu, with nothing aimed at the code path. Each has a
control in the design cases that keeps the old rule and drops the fault,
and passes.

| Recall | Old rule restored | Fault added | Report | Schedule | Control |
|---|---|---|---|---|---|
| (a) `recallNoRetransmit` | stop at `Appended` (before ADR-006) | loss 1, drop 1 | `DeliveredAndReceipted`, end of execution | 1 | `tcCtlNoRetransmit` passes |
| (b) `recallNoFingerprint` | no fingerprint lookup (ADR-006 without its receiver half) | loss 1, drop 1 | `DeliveredAndReceipted`, end of execution: a delivered message whose receipt was lost never earns another | 3 | `tcCtlNoFingerprint` passes |
| (c) `recallPreH2` | a repeated identifier fails the store's `UNIQUE (contact, message_id)`, no quarantine | forge 1, drop 1 | `DeliveredAndReceipted`, potential liveness: the fetcher retries the poisoned envelope forever and the message behind it never arrives | 1 | `tcCtlPreH2` passes; `tcH2Off` (quarantine alone) passes |
| (d) `recallNoImplicitAccept` | an application message in `AwaitingAccept` advances the session and is dropped (before ADR-004) | reorder 1, drop 1 | `DeliveredAndReceipted`, end of execution | 1 | `tcCtlNoImplicitAccept` passes |

Recall (b) shows the second half of ADR-006's argument concretely: without
the lookup the copy fails to decrypt (its key is spent), so it is never
delivered twice, but it is never answered either.

## New knowledge

### The retransmit bound is exact, and quarantine and replays fit it

ADR-006 sends at most `max_retransmits` copies and answers a remembered
ciphertext at most `max_retransmits` times beyond the first receipt. The
DST swarm runs faults at random rates and could only say that campaigns
passed. The model establishes the bound as a count, for the configurations
checked (one or two messages, `maxRetx` of 2 and 3):

- **Holds at the bound.** With at most `maxRetx` spoiling faults (losses
  and corruptions in either queue, and quarantines) and any mix of the
  non-spoiling faults, crashes and expiry, every committed unexpired
  message is delivered once and receipted (`tcMailbox`, `tcAll`,
  `tcThreeSpoils`, `tcCtlTwoLosses`).
- **Fails one past it.** `calibSpoils` (three spoils, `maxRetx = 2`) is a
  liveness violation, found at schedule 26.
- **Quarantine is a spoil.** `calibQuarantine` is `tcCtlTwoLosses` plus
  enough transient process failures to quarantine one envelope: it fails
  (schedule 273) where the control passes. The draft
  `limits.max_process_attempts` comment on branch `dedup` says dropping an
  honest message this way "loses nothing for good" because the sender
  retransmits. That holds while the message has a copy left; a quarantine
  of the last copy, or of the last receipt, loses it, exactly as a mailbox
  loss would. A transient store fault that lasts five fetch rounds now
  costs a copy, which before quarantine it did not.
- **Replays do not lower the bound.** A replaying mailbox spends the
  receiver's answers, but every answer it provokes sends a receipt that
  reaches the sender unless that receipt is also lost, so starving the
  sender still takes `maxRetx + 1` lost receipts. `tcBoundReplay` (two
  replays and two losses at `maxRetx = 2`) passes.
- **The answer bound is the smallest that works.** `mutTightAnswers`
  answers one time fewer (`receipts >= max_retransmits` instead of `>`); it
  fails at `maxRetx` spoils (schedule 51), the configuration
  `tcCtlTwoLosses` passes with. The off-by-one in
  `relationship.check_answerable` is load-bearing: `known.receipts >
  limits.max_retransmits` is right and `>=` would lose messages.

### The counterexample: an acknowledged envelope served again

This section describes the defect as the model found it, in the code as it
stood before the fix; the fix and how it is tested follow at the end.

**Claim.** If a mailbox serves an envelope the receiver has already
acknowledged, under the same identifier and with the same bytes, the
receiver never acknowledges it again. The mailbox keeps serving it until
its retention deadline, the fetcher loops on it without pause, and enough
of them at the head of a queue stop every later envelope from being
fetched.

**Found by** the design case `tcExpiry` in the first version of the model,
with no fault aimed at it. That first trace relied on a slip in the model's
mailbox, which accepted an append of a message it had already swept for
expiry; the real mailbox refuses such an append (`BadDeadline`). With the
slip fixed, the same defect is reachable through two paths the real system
has, `cxRestore`/`cxBlock` and `cxLateRetry` below, and the generic fault
mix of `tcAll` finds it at once when the code's behaviour is restored
(`cxGeneric`, schedule 1).

**The path, in protocol terms** (`cxBlock`, schedule 2, minimal:
two messages, no pairing, one restore, a batch of one):

1. A appends message 0 as envelope E and message 1 as envelope F. B fetches
   E, commits the delivery, the receipt and `Processed(E, digest)`, and
   acknowledges E in its next round. The mailbox deletes E and writes its
   tombstone; B marks E acknowledged.
2. The mailbox serves E again, at the head of the queue, with the same
   identifier and bytes. Two real events do this:
   - **A restore.** The mailbox's database is restored from a backup taken
     before the acknowledgement (or a replica that lagged is promoted). E
     and its old position come back, and its tombstone was never written.
   - **A late retry** (`cxLateRetry`). A's first append of E was stored,
     but A never saw the answer and kept retrying. ADR-008 offers the
     original's retention deadline `retention_slack_seconds` short of the
     message's expiry, and the tombstone lives only until that deadline. A
     retry that arrives in the last hour before the message expires finds
     neither E nor its tombstone, and `insert_new` stores E again.
3. B fetches E. `handle_envelope` finds `Processed(E)` with the same digest
   and answers `Repeat`, committing nothing. That is correct for safety:
   the message is not delivered again.
4. B's next round acknowledges what `unacked` returns, the processed rows
   with `acked = 0`. E's row says `acked = 1`, so E is never named in an
   `Ack` again.
5. The fetcher starts the next round at once after any non-empty batch, so
   it fetches E again, gets `Repeat` again, and loops without the long poll
   that paces a quiet queue.
6. With a batch of one, F sits behind E and is never fetched. A's copies of
   message 1 are appended behind E too. A runs out of copies, and message 1
   is never delivered: `DeliveredAndReceipted` reports it.

**The same in the code, before the fix** (`8b290bd`). `handle_envelope`
answered a processed record with the same digest `Ok(Repeat)` and
committed nothing. `ack_pending` in `daemon/fetcher.gleam` acknowledges
only what `engine.unacked` returns, the processed rows with `acked = 0`
(`Unacked` in `daemon/sql/inbound.sql`), and `mark_acked` set the flag to
1 for good; `process_batch` discards the `Handled` value, so a `Repeat`
was never acknowledged on the spot either. `polled` starts the next round
at once after a finished one ("the long poll is what paces a quiet
queue"), and a queue holding a zombie is never quiet. On the mailbox side:

- `mailbox/sql/envelopes.sql:18` (`LiveEnvelopes`) returns the oldest
  `limits.fetch_batch_envelopes` (16) live envelopes `ORDER BY seq`, so
  sixteen zombies at the head (a restored backup puts them back at their
  old positions) hide everything behind them.
- `mailbox/service.gleam:358` (`append_to`) answers a repeat from the
  stored envelope or the tombstone, and otherwise inserts;
  `mailbox/store.gleam:828` (`sweep`) deletes tombstones past their
  deadline (`DeleteStaleTombstones`).
- The pure simulation does not show this: `core/world.gleam:1036` (`ack`)
  acknowledges every stored envelope whose processed record matches, with
  no acknowledged flag, so its honest shell is more forgiving than the
  daemon's. The shell DST in `packages/sim` ran the real fetcher, but none
  of its fault classes served an acknowledged envelope again under its own
  identifier; the `restore` class now does (below).

**Consequences.** Safety holds: nothing is delivered twice. Liveness does
not. After a mailbox restore, every queue with an acknowledged envelope in
the backup spins its fetcher (one Tor round trip per spin) until those
envelopes' retention deadlines, up to `message_retention_seconds` (a week)
after their original appends. A queue with sixteen or more of them at its
head delivers nothing for that long, which outlasts the 31 hours of
retransmits, so messages behind them expire undelivered. The late-retry
path needs a sender that got no answer for about a week, and costs one
zombie for at most `retention_slack_seconds`; it matters because it needs
no operator action.

**The fix** (ADR-010, addendum). `engine.gleam:1062` (`repeat`) answers
a `Repeat` by marking the envelope's processed row unacknowledged
(`daemon/store.gleam:1769`, `mark_unacked`; `MarkUnacked` in
`daemon/sql/inbound.sql`), so the next round's `ack_pending` names it and
the mailbox deletes it and writes a fresh tombstone. The fetcher keeps its
one rule, acknowledge exactly what the store says is committed and
unacknowledged. The processed row and its digest stay, so nothing is
delivered twice; a repeat counts no quarantine attempt; and a queue that
retires between the repeat and the next round still owes the
acknowledgement, so the fetch manager drains it. Acknowledging every
`Repeat` from the fetched batch was the other shape; it would give the
fetcher a second source of acknowledgements, and a fetcher that retired or
crashed before naming the repeat would leave it at the mailbox.

**How the model carries it.** `reackRepeat` (in `tCfg`) is the fix: a
`Repeat` whose envelope is already marked acknowledged clears the mark, so
the next round names it again. It is on in `Base()` and in every design
case except `tcCtlNoReack`, which runs the pre-fix handling under every
fault but the two that serve an acknowledged envelope again, as the
control. `cxRestore`, `cxBlock`, `cxLateRetry` and `cxGeneric` stay in the
judge as recall cases with the flag off: they document the defect and
must keep failing.

**Tested in the code.** `test/daemon/reack_test.gleam` in `packages/daemon`
stages both paths against a real mailbox with a full batch of sixteen
zombies and a seventeenth message behind them; both time out without the
fix. The shell DST's `restore` fault class (`sim/restore`) restores every
acknowledged envelope from a backup the mailbox's own database keeps; on
the pre-fix code the swarm finds the defect blind (`queues_drained`, and
the runner's livelock check on the fetcher's spin).

## Open gaps

- **Durations.** The model orders events and cannot compare times, so it
  says nothing about whether the doubling window, the slack and the
  backoffs interact well in wall-clock terms (for example a receiver
  offline for longer than 31 hours but less than a week). That needs a
  model with explicit time.
- **Not modelled:** Close and Reject (and their retransmits), budgets and
  `HeldFull`, the handshake's `Initial` frame (which ADR-006 does not
  retransmit; a quarantine of it would strand the pairing just as a mailbox
  loss does), the skipped-message-key bound, more than one relationship or
  queue per daemon, and several daemons' fetchers sharing a mailbox.
- **Quarantine is modelled from its ruling.** When ADR-010 and its code
  land, compare the attempt counting (which failures count, when the count
  is written, whether the check precedes the processed rule) with
  `Process` in `PSrc/daemon.p`.
- **Byzantine peers** are modelled only as the H2 forger. A peer sending
  receipts for messages it never received is out of scope; the
  `ReceiptOnlyForStored` monitor assumes an honest receiver.
- **Small scopes.** The verdicts are for two messages and `maxRetx` of 2
  or 3, explored by random and PCT scheduling, not exhaustively. The
  counting arguments above say why larger values should behave the same;
  the model does not prove it.

## Changing the model when the protocol changes

Change the model in the same change as the protocol, and run both scripts.

- **Outbox, scheduler, retransmit** (`daemon/scheduler.gleam`,
  `daemon/store.gleam` outbox, `core/retransmit.gleam`,
  `core/retention.gleam`): `CommitRow`, `SendRow`, `OnAppendResp`,
  `RecordStored`, `Schedulable` and `Retransmit` in `PSrc/daemon.p`.
- **Inbound path** (`daemon/engine.gleam` `handle_envelope` and `receive`,
  `core/relationship.gleam` `receive`, `resend_receipt`,
  `store_application`, the ADR-010 quarantine): `Process`,
  `ResendReceipt`, `OnReceipt` and `OnApplication`.
- **Fetcher** (`daemon/fetcher.gleam`): `StartRound`, `OnAckResp`,
  `OnFetchResp`, `Backoff`.
- **Mailbox** (`mailbox/service.gleam`, `mailbox/store.gleam`,
  `mailbox/sql/envelopes.sql`): `Append`, `AckAll`, `Sweep`, `Serve` and
  the faults in `Faults` in `PSrc/mailbox.p`.
- **A new ruling** becomes a `tCfg` flag that is true in `Base()`
  (`PTst/world.p`), a recall in `PTst/judge.p` with the flag off and one
  generic fault, a control in `PTst/design.p`, and lines in both scripts.
- **A new rule worth guarding** becomes a monitor in `PSpec/`, added to the
  `assert` list of every test case, with a mutant in `PTst/judge.p` that
  breaks it. A monitor no mutant trips is not evidence of anything.
- **Test case names** are matched by prefix (`p check -tc`), so no name may
  be a prefix of another.
