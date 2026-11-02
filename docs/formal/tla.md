# TLA+ models of the scheduler and the fetcher

Two parts of the daemon have concurrency arguments that live only in
comments: the delivery scheduler's per-run claims and `Held` pacing, and
the fetcher's rule of acknowledging only what the store committed. The
package doc said so of the first: the `Held` pacing and per-run claims
"have no test" (`packages/daemon/CLAUDE.md`, Invariants). The models in
`formal/tla/` check both arguments exhaustively with TLC, within stated
bounds, and every property they check is shown to fail on a mutant that
reintroduces the hazard it guards against.

Neither model found a violation against the current code. The scheduler
holds every safety property and its liveness property; the fetcher, as it
stands after `ef9d5c2` (acknowledge before the liveness check) and the
fetch manager's draining reconcile, holds its safety properties and
delivers every committed acknowledgement. The pre-`ef9d5c2` fetcher is kept
as a mutant, and TLC finds the `closed_queue_unacked` liveness violation in
it. The model also shows that each half of that fix is necessary on its
own (see [The closed-queue gap](#the-closed-queue-gap)).

## How to run

```sh
formal/tla/check.sh                       # every configuration
formal/tla/check.sh Fetcher SchedulerLive # named configurations only
make formal                               # every formal/*/check.sh
```

The script translates the PlusCal in `Scheduler.tla` and `Fetcher.tla`
(`pcal.trans -nocfg`), runs TLC with `-workers 2` on each configuration,
and compares each result with the one its `plan` expects: a configuration
of the current design must pass, each mutant must fail on its named
invariant or on liveness, and anything else (an unexpected violation, a
deadlock, a TLC error) exits non-zero. Each line it prints gives the
distinct states, the search depth and, for a violation, the length of
TLC's trace. `TLA2TOOLS` names the jar (default
`~/tools/tla2tools.jar`, TLC 2.19) and `TLC_WORKERS` the
worker count; it was run on Java 1.8. A full run takes about 23 minutes on
two workers, nearly all of it in `Scheduler` and `SchedulerLive`. TLC's
working files go to a temporary directory the script removes, so a run
leaves nothing behind in `formal/tla/` except the translation.

The translation is committed, so the `.tla` files read without running the
translator; `check.sh` regenerates it in place, so an edit to the PlusCal
that was not re-translated shows up as a diff.

## Scope

**`Scheduler.tla`** models the scheduler actor
(`packages/daemon/src/daemon/scheduler.gleam`) and what it talks to:

- the actor's one mailbox, holding `Tick`, `Nudge`, its own
  `Finished(row, Refused)` and what each run's relay pushes;
- concurrent `weft` runs, each sending a batch, completing tasks as
  Accepted, Refused or Transient, ending at a deadline (`Abandoned`, or
  `NeverStarted` as a fault) or lost (`RunLost`, a fault), each pushing its
  outcomes and then exactly one end marker;
- the store's outbox (`status`, `attempts`, `next_attempt_at`), with
  `record_send` answering Ok, Error before it writes, or Error after it
  writes (the engine's `ApplyThenFail`);
- the periodic timer, which is also the clock: a firing is time passing;
- other engine clients committing rows with or without a nudge, and a
  Tick's `retransmit` committing copies of stored rows;
- a scheduler crash and supervisor restart.

**`Fetcher.tla`** models one inbound queue
(`packages/daemon/src/daemon/fetcher.gleam`):

- the fetcher's `weft/state_machine` (Acking, Polling, BackingOff) and its
  mailbox;
- the work inside each one-task run, one engine or mailbox call per step:
  `engine.unacked`, the mailbox `Ack`, `engine.mark_acked`, the long-poll
  `Fetch`, and `engine.process` per envelope, each able to fail before or
  after its effect;
- the run deadline and a lost run, at any step;
- the BackingOff state timeout;
- the fetch manager, which starts a fetcher for a live queue and, for a
  retired queue that still owes acknowledgements, a draining one;
- the relationship closing, envelopes arriving, and a daemon crash.

Nothing else in the daemon is modelled: not the protocol core, the mailbox
server, message bytes, other queues, or offers.

## Properties

### Scheduler

| Name | Kind | Statement |
|---|---|---|
| `OneOwner` | invariant | A row with an unsettled task in run s (still sending, or its outcome still in the mailbox) is claimed `Sending(s)`, and a row whose `Finished` is queued is claimed `Expiring`. This is "at most one claim per envelope" made precise: one claim, held by the right owner. |
| `NoDoubleSend` | invariant | No row is being sent by two runs at once. |
| `NoStaleRelease` | invariant | An end marker never releases a claim its own run does not hold. |
| `HeldUntilTick` | invariant | A row whose record failed is not dispatched again before the next Tick is handled. |
| `NoBusyLoop` | invariant | Between two timer firings a row is started at most once, plus once per run fault or restart in that period. |
| `SendCommitted` | invariant | A run only ever holds rows the store committed. |
| `TypeOK` | invariant | The state has the declared types. |
| `Settles` | liveness | Every queued row is eventually stored or failed, under weak fairness of the actor, the runs and the timer. |

### Fetcher

| Name | Kind | Statement |
|---|---|---|
| `NoAckBeforeCommit` | invariant | The mailbox deleted only envelopes the store committed as processed. |
| `StoreAckConsistent` | invariant | The store marks acked only envelopes it processed and the mailbox deleted. |
| `NothingOwedAtRest` | invariant | Once no fetcher runs and the fetch manager has no reason to start one, nothing committed is unacknowledged. It is the safety shadow of `AllAcked`, kept because breadth-first search gives its shortest trace. |
| `AllAcked` | liveness | Every committed envelope is eventually acknowledged, under weak fairness of the machine, the worker, the timer and the fetch manager. |
| `TypeOK` | invariant | The state has the declared types. |

## Configurations and results

Every scheduler configuration has two run slots, `MaxInFlight = 2` and
`MaxAttempts = 1` (a row past one failed attempt is past its deadline).
Every fetcher configuration has three envelopes, one in the mailbox at the
start, and up to two crashes unless noted.

There are 18 configurations: 4 of the current design and 14 mutants. The
pass configurations below were run with `TLC_WORKERS=2`, and their state
counts are exact and repeat from run to run.

| Configuration | What it checks | Distinct states | Depth | Time |
|---|---|---|---|---|
| `Scheduler` | every safety invariant, two queued rows, one late row, record failures, a run fault and a restart | 20108516 | 31 | 12 min 16 s |
| `SchedulerCopies` | every safety invariant, with a retransmit copy | 2700012 | 27 | 1 min 36 s |
| `SchedulerLive` | `Settles` | 163306 | 22 | 8 min 50 s |
| `Fetcher` | every fetcher invariant and `AllAcked` | 31453 | 30 | 4 s |

## Mutation table

Each mutant is a constant switch in the model, named in the configuration
file's first line. The first group mirrors the scheduler fixes of commit
`3035697` and the fetcher fix of `ef9d5c2`; the rest show that the
remaining properties are not vacuous. "Trace" is the length of TLC's
counterexample in states; for a liveness violation it counts the states up
to and including the loop.

| Mutant | What it reintroduces | Fails on | Trace |
|---|---|---|---|
| `SchedulerMutBatch` | claims keyed per batch, as before `3035697`, no run faults | `NoDoubleSend` | 9 |
| `SchedulerMutBatchOwner` | claims keyed per batch, with `NeverStarted` | `OneOwner` | 6 |
| `SchedulerMutBatchStale` | claims keyed per batch: a marker releases a claim it does not own | `NoStaleRelease` | 6 |
| `SchedulerMutAnyEnd` | any end marker releases every `Sending` claim | `NoDoubleSend` | 6 |
| `SchedulerMutImmediate` | a failed record drops the claim and the row is resent at once, as before `3035697` | `HeldUntilTick` | 4 |
| `SchedulerMutStorm` | a failed record drops the claim: the H3 send storm | `NoBusyLoop` | 4 |
| `SchedulerMutSticky` | a Tick never releases a `Held` claim | `Settles` (liveness) | 10 or 11 |
| `SchedulerMutPlan` | dispatch reads a row before its commit | `SendCommitted` | 2 |
| `FetcherMutBeforeAck` | liveness checked before the ack and no draining, as before `ef9d5c2` | `AllAcked` (liveness) | 16 |
| `FetcherMutBeforeAckRest` | the same with no crashes, for the shortest trace | `NothingOwedAtRest` | 9 |
| `FetcherMutNoDrain` | ack first, but no draining | `NothingOwedAtRest` | 8 |
| `FetcherMutDrainOnly` | draining, but liveness checked before the ack | `AllAcked` (liveness) | 16 to 18 |
| `FetcherMutBatch` | acknowledge the fetched batch instead of the store's rows | `NoAckBeforeCommit` | 11 |
| `FetcherMutBatchStore` | the same, checked at the store | `StoreAckConsistent` | 12 |

A mutant's distinct-state count and a liveness trace's length change from
run to run, because TLC stops at whichever worker finds the violation first.
The length of an invariant's trace did not change across the runs compared,
since breadth-first search reaches each violation at the same depth.

TLC's own lines for each, from `check.sh`'s run:

```
ok   Scheduler                expect=pass               got=pass               distinct=20108516 depth=31 time=12min 16s
ok   SchedulerCopies          expect=pass               got=pass               distinct=2700012 depth=27 time=01min 36s
ok   SchedulerLive            expect=pass               got=pass               distinct=163306 depth=22 time=08min 50s
ok   SchedulerMutBatch        expect=NoDoubleSend       got=NoDoubleSend       distinct=2348 depth=9 trace=9 time=02s
ok   SchedulerMutBatchOwner   expect=OneOwner           got=OneOwner           distinct=1253 depth=7 trace=6 time=02s
ok   SchedulerMutBatchStale   expect=NoStaleRelease     got=NoStaleRelease     distinct=689 depth=6 trace=6 time=01s
ok   SchedulerMutAnyEnd       expect=NoDoubleSend       got=NoDoubleSend       distinct=1513 depth=7 trace=6 time=01s
ok   SchedulerMutImmediate    expect=HeldUntilTick      got=HeldUntilTick      distinct=45 depth=4 trace=4 time=01s
ok   SchedulerMutStorm        expect=NoBusyLoop         got=NoBusyLoop         distinct=45 depth=4 trace=4 time=01s
ok   SchedulerMutSticky       expect=liveness           got=liveness           distinct=2501 depth= trace=11 time=09s
ok   SchedulerMutPlan         expect=SendCommitted      got=SendCommitted      distinct=2 depth=2 trace=2 time=01s
ok   Fetcher                  expect=pass               got=pass               distinct=31453 depth=30 time=04s
ok   FetcherMutBeforeAck      expect=liveness           got=liveness           distinct=32918 depth= trace=16 time=04s
ok   FetcherMutBeforeAckRest  expect=NothingOwedAtRest  got=NothingOwedAtRest  distinct=396 depth=9 trace=9 time=01s
ok   FetcherMutNoDrain        expect=NothingOwedAtRest  got=NothingOwedAtRest  distinct=432 depth=8 trace=8 time=01s
ok   FetcherMutDrainOnly      expect=liveness           got=liveness           distinct=34164 depth= trace=16 time=04s
ok   FetcherMutBatch          expect=NoAckBeforeCommit  got=NoAckBeforeCommit  distinct=1854 depth=11 trace=11 time=01s
ok   FetcherMutBatchStore     expect=StoreAckConsistent got=StoreAckConsistent distinct=2768 depth=12 trace=12 time=01s
check.sh: every configuration gave its expected result
```

### The stale end marker, as TLC found it

`SchedulerMutBatch` (claims keyed per batch as before `3035697`, no run
faults) reproduces the interleaving the package doc said no test could
build, "a failed record, a resend into a newer run and an old marker", in
nine states:

1. The first Tick dispatches rows 1 and 2 into run 1.
2. Row 1 is Accepted; `record_send` answers Error, so row 1 is `Held`.
3. The timer fires and its Tick releases the hold; row 1 goes into run 2
   while run 1 is still sending row 2.
4. Run 1's deadline abandons row 2 and queues run 1's end marker.
5. The scheduler handles row 2's Transient outcome, then run 1's marker.
   Keyed per batch, the marker releases every row of run 1, row 1
   included, although run 2 holds it.
6. The dispatch that ends `close` starts row 1 in run 1's recycled slot
   while run 2 is still sending it, and `NoDoubleSend` fails.

With the current `close` (`close` at `scheduler.gleam:689`, its filter on
`Sending(sink:)` at `scheduler.gleam:693`), step 5 releases only run 1's
own `Sending` claims, and row 1 stays with run 2.

`SchedulerMutBatchOwner` and `SchedulerMutAnyEnd` find a shorter path to
the same hazard, with no failed record at all: a run whose deadline reports
`NeverStarted` for both rows. The first `NeverStarted` deletes row 1's
claim and the dispatch that follows puts row 1 into a newer run (in
`conclude`, the `Unattempted` arm at `scheduler.gleam:675`); the old run's end
marker then releases row 1 although the newer run holds it. The per-run
claim closes this path too, which the comments did not mention.

### The H3 send storm

`SchedulerMutStorm` (a failed record drops the claim, as before `3035697`)
starts row 1 twice without the clock moving: sent, Refused, the record
fails, and the dispatch that ends `finish` resends it at once. Each further
failure adds a start. With `Held`, the resend waits for a Tick handled
after the failure. A Tick that fires while the failing record is written
arrives in the mailbox behind the outcome being handled, so the period
boundary always falls between a send and the resend it releases, and
`NoBusyLoop` holds with a bound of one start per row per period: the "one
resend per period" of the comment at `scheduler.gleam:87`.

### The closed-queue gap

`FetcherMutBeforeAck` is the fetcher before `ef9d5c2`: `begin_round`
checked liveness first and the fetch manager started fetchers only for
live queues. TLC reports `AllAcked` violated, and `FetcherMutBeforeAckRest`
gives the shortest trace, with no crash and no fault:

1. The first round's ack run finds nothing to acknowledge, and the poll
   starts.
2. The relationship closes.
3. The poll fetches envelope 1 and `engine.process` commits it.
4. The poll's outcome reaches `polled`, which begins the next round; the
   liveness check answers Retired and the machine stops before the round
   that would have acknowledged envelope 1.
5. No fetcher ever starts again for a queue that is not live, so the
   mailbox keeps envelope 1 until its retention ends.

The current code checks liveness in `after_ack` (`fetcher.gleam:262`),
after the round's acknowledgements, and the fetch manager's `reconcile`
also asks `engine.draining_inboxes` (`fetch_manager.gleam:161`) for retired
queues with unacknowledged rows. Both halves are needed:

- `FetcherMutNoDrain` keeps ack-first but drops draining. TLC still
  strands a commit in eight states, with no fault: the round's liveness
  check reads Live, the relationship closes just after it, the poll commits
  envelope 1, and the daemon crashes before the next round. (An engine
  error at the check has the same effect, since `liveness` treats it as
  Live.) After
  the restart the queue is not live, so nothing acknowledges envelope 1.
- `FetcherMutDrainOnly` keeps draining but checks liveness first. The
  draining fetcher stops at its own first liveness check, before
  acknowledging, and the fetch manager starts it again: a loop that never
  acknowledges, which TLC reports as an `AllAcked` violation whose lasso
  returns to the fetch manager's step.

With both, `Fetcher.cfg` holds every invariant and `AllAcked`.

## Model to code

Each step of the PlusCal carries a comment naming the Gleam function it
mirrors, with its line. The tables below give the same map, against main at
`48bdacb`.

### `Scheduler.tla`

| Model step | Code |
|---|---|
| `Handle`, Tick | the Tick arm of `handle` (`scheduler.gleam:400`): `release_held` (`scheduler.gleam:527`), `retransmit_due` (`scheduler.gleam:411`), then `dispatch` |
| `Handle`, Nudge | the Nudge arm of `handle` (`scheduler.gleam:399`) |
| `Handle`, Finished | the `Finished` arm (`scheduler.gleam:401`), for the `Finished` an expired row is sent (`scheduler.gleam:461`) |
| `Handle`, outcome with an attempt | `settle` (`scheduler.gleam:610`), `settlement` (`scheduler.gleam:641`), `conclude` (`scheduler.gleam:666`), `finish` (`scheduler.gleam:708`) |
| `Handle`, outcome NeverStarted | in `conclude`, the `Unattempted` arm (`scheduler.gleam:675`): the claim is deleted whatever it is |
| `Handle`, end or lost marker | `settle`'s `AllDelivered` and `RunLost` arms (`scheduler.gleam:635`), `close` (`scheduler.gleam:689`) |
| `Handle`, restart | `supervised` (`scheduler.gleam:267`), `builder` with `continuing(Tick)` (`scheduler.gleam:286`) |
| `Dispatch` operator | `dispatch` (`scheduler.gleam:440`), reading `due_outbox` (`scheduler.gleam:445`), and `start_batch` (`scheduler.gleam:476`) |
| `Finish` macro | `finish` (`scheduler.gleam:708`), whose `Held` insert is at `scheduler.gleam:742`; `record_send` (`engine.gleam:1439`), `answer` (`engine.gleam:425`) |
| `Run`, complete | `send_row` (`scheduler.gleam:543`) and `classify` (`scheduler.gleam:337`); `Crashed` and `Failed` settle as Transient (`settlement`, `scheduler.gleam:641`) |
| `Run`, end | the relay's `AllDelivered` after the scope's `Done` (`start_relayed` in weft) |
| `Run`, deadline | `send_batch` (`scheduler.gleam:504`) with `weft.deadline`: running tasks are `Abandoned` |
| `Run`, early deadline | `NeverStarted`, spent from the run-fault budget |
| `Run`, lost | `RunLost`, spent from the run-fault budget |
| `Timer` | `builder`'s `actor.periodic` (`scheduler.gleam:291`) |
| `Engine` | a committed row and `nudge` (`scheduler.gleam:304`) |

### `Fetcher.tla`

| Model step | Code |
|---|---|
| `Machine` | `handle` (`fetcher.gleam:218`), every state and message pair |
| `Machine`, Begin | `begin_round` (`fetcher.gleam:250`) |
| `Machine`, Acked | `acked` (`fetcher.gleam:271`), then `after_ack` (`fetcher.gleam:262`) with `liveness` (`fetcher.gleam:361`), then `begin_poll` (`fetcher.gleam:306`) |
| `Machine`, Polled | `polled` (`fetcher.gleam:288`), which begins the next round |
| `Fail` macro | `failed` (`fetcher.gleam:319`) and its state timeout |
| `Worker`, unacked | `ack_pending` (`fetcher.gleam:376`), `unacked` (`engine.gleam:1458`) |
| `Worker`, call | `acknowledge` (`fetcher.gleam:396`), the mailbox `Ack` |
| `Worker`, mark | `mark_acked` (`engine.gleam:1473`), then `ack_pending` repeats |
| `Worker`, fetch | `fetch_batch` (`fetcher.gleam:423`) |
| `Worker`, process | `process_batch` (`fetcher.gleam:450`), `process` (`engine.gleam:1015`); a repeat's `repeat` (`engine.gleam:1076`) and a poison envelope's `attempt` (`engine.gleam:1079`) |
| `Worker`, abandon | `start_run` (`fetcher.gleam:327`) with its deadline, and `RunLost`, both read by `step_result` (`fetcher.gleam:345`) as a failed step |
| `Timer` | the state timeout armed in `failed` (`fetcher.gleam:319`) |
| `Manager` | `reconcile` (`fetch_manager.gleam:150`) and `draining_inboxes` (`engine.gleam:1394`) |

## Abstractions, and what each could hide

- **A handler is one atomic step.** The engine calls inside one scheduler
  message (`due_outbox`, `record_send`, `retransmit`) are folded into one
  step. The engine is a FIFO actor and each call touches only its own row,
  so the one other writer, a new row's commit, commutes with them. Hidden:
  an engine whose calls interleave.
- **A run's workers die with it.** A scheduler restart kills every worker
  in the same step, and `Abandoned` means the worker is gone (weft reports
  it only after the worker's exit). In Erlang the scope kills its workers
  after it sees the relay die, so for a moment an old worker can still be
  appending while the restarted scheduler dispatches the same row, and a
  request already on the wire outlives any kill. `NoDoubleSend` is
  therefore a statement about one scheduler incarnation; overlapping
  appends of one envelope rely on the mailbox answering the original
  receipt (spec §6.4), outside this model.
- **Time is the timer.** A retry becomes due at the next timer firing, the
  soonest it could in production (backoff starts at 2 s, the tick is 1 s).
  Expiry is "attempts reached `MaxAttempts`", not a wall-clock deadline.
  Hidden: anything that depends on exact durations.
- **One Tick at a time.** The timer fires only when no Tick is queued,
  which is what weft's fixed-delay heartbeat does: the next beat is armed
  after the Tick handler returns.
- **Small bounds.** Two run slots, `MaxInFlight = 2`, at most three rows,
  one or two record failures, one run fault, one restart. `due_outbox`'s
  limit (twice `MaxInFlight`) never truncates at these sizes, and a full
  slot pool skips a dispatch as an engine error would. Hidden: anything
  that needs three concurrent runs, or a row starved behind a truncated
  read.
- **Run slots are recycled** once the end marker is handled, when no claim
  or message names them. Sound because `close` removes every `Sending(s)`
  claim and the marker is the run's last message.
- **Batches are sets.** The code maps an outcome's index back to its row
  with `list.drop`; the model names the row directly.
- **Fetcher end markers are omitted.** Every arm keeps its state on
  `AllDelivered`, and a `RunLost` after an outcome needs something outside
  the run to kill a scope that has already delivered, which nothing does.
  A `RunLost` before the outcome is modelled, as a failed step.
- **The mailbox forgets an acknowledged envelope for good.** A mailbox that
  serves an acknowledged envelope again (the P model's finding,
  `docs/formal/p.md`, and ADR-010's addendum) is outside this model. The
  model does take `repeat`'s write, which marks the row unacknowledged, but
  every repeat it can reach is still unacknowledged, so the write changes
  nothing here. The fix is judged by the P model, `reack_test` and the
  simulation's restore fault class, not by this one.
- **One fetcher, one queue, one relationship.** Offers, offer expiry and
  other queues are not modelled.
- **Faults are bounded.** Every fault kind has a budget, which is what lets
  the liveness properties hold under weak fairness. A poison envelope's
  repeated `engine.process` failures end in quarantine after
  `limits.max_process_attempts`, which commits it; the budget stands for
  that bound. A store that fails every record forever, or a mailbox that
  never answers, stalls delivery, and the models say nothing about that
  case beyond the safety invariants.

## What the models say about the current code

- No interleaving within the bounds violates any scheduler property or any
  fetcher property against the current code.
- The per-run claim also guards the `NeverStarted` path, not only the
  failed-record path the comments describe: before `3035697` a run whose
  deadline beat its tasks could release a newer run's claim with no failed
  record at all (`SchedulerMutBatchOwner`, six states).
- The `Held` pacing gives exactly one start per row per clock period, not
  two, because a Tick that fires during a failing record queues behind the
  outcome being handled.
- Each half of the closed-queue fix is necessary: ack-first alone loses a
  commit across a crash, and draining alone loops without acknowledging.
- The outbox writes in `record_send` (`daemon/store.gleam:1350`) are not guarded
  by `status = 'queued'` (`MarkStored`, `MarkFailed` and `Reschedule` in
  `outbox.sql`). The claims are what keep two outcomes for one row from
  landing, so the store relies on `OneOwner`; the model writes the rows the
  same unguarded way.

## When the models must change

- `scheduler.gleam`: a change to `Claim`, `close`, `finish`,
  `release_held`, `conclude`, `dispatch`'s room or read, or the order of
  `release_held`, `retransmit_due` and `dispatch` in the Tick arm.
- `fetcher.gleam`: a change to `begin_round`, `after_ack`, `acked`,
  `polled`, the order of ack, liveness check and poll in a round, or what
  `ack_pending` reads.
- `fetch_manager.gleam`: a change to which queues get a fetcher.
- weft: a change to `start_relayed`'s promise of every outcome then exactly
  one end marker, to `Abandoned` meaning the worker has exited, or to the
  actor's fixed-delay heartbeat.
- A second writer of outbox status, which would make the unguarded writes
  above reachable from two places at once.
- Line numbers: the comments in the PlusCal and the tables above cite
  lines; `scripts/doc_check.sh` checks the tables, and the PlusCal comments
  move with them.
