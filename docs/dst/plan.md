# DST plan

The plan of record for the deterministic simulation test of the real
shell: two client daemons and a mailbox, run in one VM against a simulated
network, clock, timers and store faults driven by a seed. The evidence for
it is `docs/review/2026-11-01-dst-audit.md`; the method is the `/dst` skill
(neutrino header-sync DST, lightninglabs/neutrino PR 415).

## Rulings

Made by the owner on 2026-11-01, after the audit.

- **The full plan.** Every item below, judged at the end by blind recall,
  mutation score, coverage and an independent review.
- **Exact replay from the start.** Every cross-actor ask and tell in the
  daemon and the mailbox goes through an interception seam the runner
  owns, so a seed replays bit for bit. A double run of every corpus seed
  compares full snapshots and must match exactly.
- **Repeated message ids are deduplicated, and poison envelopes are
  quarantined.** A message id an authenticated peer already used is
  ignored (no second delivery; the envelope is still processed and
  acknowledged). An envelope that fails to process a bounded number of
  times is recorded, dropped and acknowledged, so one envelope cannot
  block its queue. Both are visible to the operator.
- **Clock skew: sender slack and a retryable refusal.** A sender's default
  retention deadline sits a margin below the mailbox's maximum, and
  `BadDeadline` is retried with a shortened deadline rather than failing
  the row. The mailbox stays strict.

The two production fixes are made *after* the harness has found the bugs
they address blind, so the recall table can count them.

## Items

1. **Store and engine fault seams.** `store.transaction` can fail before
   writing or after committing (an ambiguous commit); the engine can fail a
   job before applying it or after (an ask that applies and then errors).
   Nil by default.
2. **Determinism seams.** A timer source on every weft actor and state
   machine (weft's `with_timer_source`), a timer source for weft run
   deadlines (a weft extension), an injected clock for every `poll`, the
   long-poll wait, the dialer, the database location, and the mail
   interception seam for exact replay. Nil or wall clock by default; a
   test starts each node with the defaults.
3. **A deterministic suite** for the harness only, in a package production
   never depends on (spec §13.3).
4. **The shell DST** in `packages/sim`: the real daemon and mailbox trees,
   a simulated network into the real `mailbox/node.handle`, in-memory
   SQLite that keeps full SQL strictness, a virtual timer wheel, the
   runner owning the event loop, seeds as a mode byte, a fault mask and
   ops, and every corpus seed run twice.
5. **Faults** at production boundaries: ambiguous commits, asks that apply
   then error, network drop, apply-then-lose, delay and reorder, mailbox
   down, byzantine responses, clock skew per node, byzantine authenticated
   peers, operator inputs at and past the limits, restart churn.
6. **The oracle**: safety invariants after every event, liveness after a
   heal phase that only turns faults off and lets time run, and narrow,
   counted excuses for known policy gaps.
7. **The core simulation**: a faster fake hash, a seeded generator, swarm
   seeds with a fault mask, and a heal phase that matches production
   (stop at stored, mailbox tombstones).
8. **CI**: `make check` on every push, and a nightly swarm.
9. **Judges**: blind recall of the known fixes, mutation score, coverage,
   and an independent review of the harness.
10. **The architecture doc** for the harness.

## Known fixes for blind recall

From the audit: implicit accept (42d4f6f), stale session after send,
the processed id-and-digest rule, the scheduler's per-batch claims and
held rows (3035697), the carrier re-bootstrap (3035697), the description
bound (42d4f6f), and expired-message payloads (42d4f6f). The
hypotheses H1 (clock skew) and H2 (repeated ids) join the table once the
harness finds them.
