# sim

## Purpose

The deterministic simulation test (DST) of the real shell: two daemon trees
and one mailbox tree, production code throughout, running in one VM against
a simulated network, clock, timer wheel and store faults driven by a seed
(`docs/dst/plan.md`; method: the `/dst` skill). A test harness that compiles
as a library, so its campaign entry points run with `gleam run -m`. It is
registered in `lint/policy.harness_packages()` (panics and `let assert`
allowed in `src/`, each assert still named) and no production package
depends on it, so its fake crypto can never reach a release (spec §13.3).

## What is real and what is simulated

| Component | Real | Simulated |
| --- | --- | --- |
| Daemon trees (`daemon/node`: engine, store, scheduler, fetchers, fetch manager, provisioner, carrier, status, events, lock) | all of it, started with `node.start` | nothing |
| Mailbox tree (`mailbox/node`: coordinator, notifier, sweeper, `service`, the long poll) | all of it | nothing |
| Operator and agent | `daemon/api` calls from op processes | which calls, from the seed |
| HTTP | the client's framing (`mailbox_client`, `core/http1`) and the mailbox codec | mist; `sim/net` frames the server side as `mailbox/http` does |
| Network | `transport.Dialer` seam | `world.dialer`: requests and responses park with the runner |
| Stores | SQLite with full strictness | shared-cache in-memory databases kept alive by a keeper connection |
| Clocks and timers | weft's `Injected` timer source, `weft/poll` | one virtual clock in `atomics`, a timer wheel in the runner |
| Randomness and crypto | SHA-256, HMAC, ChaCha20-Poly1305, X25519, Ed25519 | `sim/suite`: entropy from seed and counter; fake ML-KEM and ML-DSA at real sizes |
| Cross-actor mail | `daemon/mail`, `mailbox/mail` handles | interceptors park every parcel |

## Key Types

- `sim/seed`: `Script(mode, enabled, ops)` decoded from bytes: byte 0 mode
  (`% 4`: approval × budget), bytes 1–2 a little-endian fault mask over
  `FaultClass` (`StoreDaemon`, `StoreMailbox`, `Engine`, `NetLoss`,
  `NetDelay`, `MailboxDown`, `Byzantine`, `Skew`, `Peer`, `Limits`,
  `Restarts`, `Kills`), then two-byte ops (`op % 20`, argument). A masked op
  is an honest send or a short advance. `mask_off` clears classes.
- `sim/world`: `World` (inbox, `Cells`, fault `Table`), the `Inbound` message
  every seam reports with, and one builder per seam.
- `sim/runner`: `run(seed, Options) -> Report` (violations, excuses, the
  snapshot, steps, virtual time).
- `sim/oracle`: `View`, `Facts`, `safety`, `liveness`, `Violation`, `Excuse`.
- `sim`: `double_run`, `corpus`, `regressions`.
- `sim/swarm`, `sim/replay`: the campaign and replay entry points.

## Relationships

Depends on `core`, `primitives`, `daemon`, `mailbox`, `weft`,
`gleam_erlang`, `gleam_otp`, `sqlight`, `simplifile`, `argv`, `qcheck`.
Nothing depends on it. FFI is confined to `sim/internal/ffi_vm` over
`src/sim_ffi.erl` (quiescence, atomics, ETS, the supervisor's children, the
stderr sink, the logger level, a term digest).

## Traffic

The runner is the event loop. It releases one parked event (a parcel, a due
timer, a request, a response), waits until the VM is quiescent, drains the
reports the release caused, runs the safety oracle if a transaction began,
and picks the next event: the ready set sorted by a key independent of BEAM
scheduling, then indexed by the seeded generator. Time jumps to the earliest
timer only when nothing is ready. Ask replies, self-sends, weft-internal
wakes and run outcomes, the event fan-out, the notifier's wake-ups and
supervisor traffic are not parked; each is caused by one release and settles
inside its step.

## Invariants

- **Exact replay.** Every corpus and regression seed runs twice and the
  snapshots (event trace, op outcomes, log lines, a digest of every row of
  every table) must be identical (`test/sim/corpus_test.gleam`);
  `sim/swarm --double` does the same over a campaign.
- **Quiescence sees dirty NIFs.** `erlang:statistics(total_active_tasks_all)`
  does not count a process inside a dirty NIF, and every SQLite call is one;
  `ffi_vm.quiesce` also checks that every registered process is `waiting`
  (every process, after a kill or restart). Without it, about one seed in
  ten diverged.
- **Keys are content, not arrival order.** Parcels are keyed by sender role
  (`op<n>`, `req<n>`, `forge<n>`, `net:<its first request>` for a run's
  task, or the seam's label), target, label and a sequence per that stem;
  requests by node and content; timers by deadline and the arming role;
  request ids are assigned at release. Two parcels with one stem from two
  processes are the same message to the same target, so their numbering
  cannot change a run.
- **One sender's parcels in program order.** Only the head of each sender's
  queue is ready.
- **The heal phase only stops misbehaving.** It clears armed faults, brings
  the mailbox up, zeroes skews, stops holding the network, and lets time run
  in five-second rounds (liveness checked every thirty) for at most fifteen
  virtual minutes. It never restarts, reconnects or resets anything.
- **Excuses are exact and counted** (the swarm prints a census):
  `h4_retried_send` (a payload delivered twice whose send answered
  `Unavailable` and was retried), `h4_retried_accept` (one joiner with no
  peer per `Unavailable` accept answer), `lied_append` (a failed row whose
  `Append` response was a lie), `closed_queue_unacked` (a processed row left
  unacknowledged on the queue of a closed relationship: the fetcher retires
  before its round acknowledges), `corrupted_fetch` (a message, receipt or
  handshake whose envelope reached its reader in a lied-about fetch
  response, which the reader dropped and acknowledged). `sim/oracle`'s
  module doc is the reference.
- **Kill budget.** At most two kills per daemon incarnation and two on the
  mailbox, so the supervisors' wall-clock restart intensity never decides a
  run.

## Entry points

```sh
gleam test                                          # corpus + regressions, each twice
gleam run -m sim/swarm -- --seed 1 --runs 1000      # stop at the first failure
gleam run -m sim/swarm -- --seed 1 --runs 1000 --keep-going --without skew,peer
gleam run -m sim/swarm -- --seed 1 --runs 200 --double   # determinism campaign
gleam run -m sim/replay -- <seed hex>               # every event and log line
```

`--from N` starts at run index N of the generator, so a campaign shards over
several VMs (`erl ... -eval "'sim@@main':run('sim@swarm')" -extra ...`). Long
campaigns need `+t` raised: each daemon start makes atoms for its names.

## Regressions

`sim.regressions()` holds the seeds of production bugs the swarm found and
that are not fixed yet; the test asserts each still fails its check:

- H1: a daemon clock five seconds ahead of the mailbox; the default
  deadline (`now + retention`) is refused `BadDeadline`, which the
  scheduler treats as permanent (`outbox_settled`).
- H2: a byzantine peer repeats a message id; the receiver's commit fails on
  `UNIQUE (contact, message_id)`, the envelope is never acknowledged and
  every later one on that queue waits behind it (`queues_drained`).

When a fix lands, move its seed to the corpus.

## Known gaps

- Not driven: the Tor carrier (`tor: None`; the dialer is overridden), the
  local API socket and CLI, mist, `node.stop`'s lock wait (the runner kills
  the supervisor itself), the sweeper's expiry of envelopes (virtual time
  never reaches retention).
- A store fault is armed per node and fires on the next transactions, so
  which job it hits depends on the schedule, not on its kind.
- The swarm draws op arguments uniformly; ops that need an earlier op's
  result (an accept needs an invitation) fall back to a short wait.
