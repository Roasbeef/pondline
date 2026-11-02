# Review of the shell DST for false passes (2026-11-02)

One independent read of `packages/sim` at `1e770a7`, asking where a run reports
clean while something the system promises is broken. The measurements it builds
on are in [docs/architecture/sim.md](../architecture/sim.md).

**Status of these claims.** The figures are from a model: a script porting
`sim/rng` and `seed.decode` that walks the first 500 seeds of generator 1 without
a VM. It assumes no fault delays pairing, so real numbers are worse. The false-pass
scenarios were read from the code, whose quoted arms were then checked, but none
has been executed. Each needs a mutant before its fix.

## Most swarm seeds never send

`setup` doesn't pair, and `swarm.draw` draws uniformly, so a relationship exists
only if a seed happens to draw an invite, time, an accept on the other side, and an
approval. Of 500 modelled seeds:

| Reached | Seeds |
| --- | --- |
| An accept | 127 |
| A usable relationship | 91 |
| A send op after pairing | 70 |
| A corrupting lie after a send | 2 |
| 3,600 s of virtual time, even with the full heal budget | 0 |

So about 86% of seeds never send, and their delivery checks have nothing to check
while the fault classes still count as enabled. This likely explains much of the low
recall and the empty swarm column for mutation survivors.

**Proposed fix.** Prefix three of four drawn seeds in `swarm.draw` with the corpus's
pairing ops, leaving the fourth to fuzz pairing. The corpus is untouched, but a
generator seed then decodes differently, so earlier runs-to-find stop being comparable.

## False passes, most severe first

| Where | Claim | Proposed fix |
| --- | --- | --- |
| `runner`, the `corrupted` fold | Any lie, including ones that lose nothing, excuses every envelope in the batch for the whole run, so a later real loss of an intact message reads as `corrupted_fetch`. | Insert only under `seed.Corrupt`, and require the reader's `processed` row to say `dropped`. |
| `oracle.delivered_and_receipted`, the `lied` arm | A lie on any of a message's appends skips the check even when the row ended `stored`, and files no excuse, which contradicts "excuses are exact and counted". | Require a `failed` row, and file an `Excuse`. |
| `oracle.either_closed` | A bug that wrongly closes a relationship excuses all of its losses. | A closed row with no `seed.End` in the script is a violation. |
| `ops.send`, `world.Sent` | `Ok` from `send` is never compared with the store, so a lost committed send has no row to check, and a daemon that refuses every send passes. | Keep returned ids and require each in `node.sent`; treat refusal on an active contact as a failure unless a close raced it. |
| `oracle.corrupted_on` | The excuse for a missing receipt or a stuck pairing is relationship-wide. | Narrow to that message's own receipt rows. |
| `oracle.budget_books` | It can't see a raise that releases nothing, or a grant past the ceiling. `RaiseHuge` has no check, so that mutant can't die. | Check the ceiling, and that held implies the budget is spent. |
| `oracle`, delivered payloads | Payload bytes are never compared with what was sent; ids alone match. | Compare against `payload(tag, size)`. |
| `runner.heal_rounds` | Heal stops at the first passing check, and liveness only asks about pending rows, so a dead fetcher with nothing pending is invisible. | After heal, send one probe each way per active pair and heal again. |

## Why retransmit and quarantine never run

**Retransmit is a time problem.** A retransmittable row gets `retransmit_at` 3,600 s
out, even with no loss. Modelled op time is p50 154 s, p90 367 s, max 717 s, and the
heal budget caps at 900 s. `live` also discards excuses, so a run with an excused loss
leaves heal early and the retransmit that would repair it never fires. Proposed: raise
`heal_budget_ms` past the window, keep healing while excuses remain, and soak about one
seed in sixteen through the whole window. The step cost is an estimate and unmeasured.

**Quarantine is unreachable by construction.** It needs more than five committed
attempts, and `FailBeforeApply`, `ApplyThenFail` and a `StoreDown` on the count itself
don't produce them, while a store key is taken once. Proposed: one op in the style of
`sim/restore`, a keeper trigger that raises on `deliveries` for about twenty virtual
seconds, as `quarantine_test` does.

## Small trims

`oracle.safety`'s always-empty excuses and its stale H4 comment; dead `Mailbox.kills`,
`seed.daemon_fate`, `ffi_vm.active_tasks`, `world.now`; `sized_send`'s constant count.
Nothing structural.
