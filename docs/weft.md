# Weft in Pondline

[weft](https://github.com/Roasbeef/weft) is the concurrency library every
effectful package here builds its process machinery on. It is a sibling
repository by the same author, published to Hex as `weft`, and it exists
because the same few shapes kept being written by hand, each copy
re-deciding the same races: a spawn raced against a deadline and reaped, a
poll-until-deadline loop, a timer whose handler re-checks for a stale fire,
a process written as mutually recursive phase functions, and a list of
waiters flushed on a state change. `docs/gleam-style.md` Part III states the
rule; this page says what weft gives, when to reach for it, when not to,
and the rules a port is held to. It is adapted from Loom's page of the same
name, where these rules were learned.

## What it gives

All modules are Erlang-target and interoperate with `gleam_otp`: a weft
`start` returns upstream's `StartResult`, a weft `supervised` returns
upstream's `ChildSpecification`, and every weft process answers the OTP
system messages.

| Module | What it is | The hand-rolled shape it replaces |
|---|---|---|
| `weft` | The run engine: a scope process owns every worker by link, with `limit`, `deadline`, an external cancel signal, input-order `start` and completion-order `fold`. Every task gets exactly one `Outcome`. `start_detached` and `start_relayed` let an actor run work without blocking its loop. | spawn + monitor + race a reply against `DOWN` + kill on timeout |
| `weft` managed tasks | `prepared_task` and `managed` with a `Ledger`, for work whose owner outlives the worker (a socket under a client library's supervisor). The scope's exit is the drain witness. | an ad-hoc ledger of monitored pids with cancel closures |
| `weft/actor` | A superset of `gleam/otp/actor`: `continuing` (a message handled before anything in the mailbox), `periodic` (a fixed-delay tick), `idle_timeout`, `on_shutdown`, `trapping_exits`, `unlinked`. | a `ready` subject handshake; a `send_after` its own handler re-arms |
| `weft/state_machine` | A typed gen_statem: a state ADT with exhaustive `case state, message` dispatch, `postpone`, state, event, named and periodic timeouts with generation-stamped cancel, enter callbacks, `selecting` for monitors and ports, and `with_timer_source` for an injected clock. | phase functions that recurse into each other; a timer carrying an id so its handler can spot a stale fire; a hand-kept list of waiters |
| `weft/poll` | `until(within:, every:, attempt:)`, bounded polling in the caller's own process, with `until_on` for an injected clock and `fold_until` to thread state between attempts. | sleep-and-recurse until a deadline |
| `weft/event_manager` | A typed gen_event: ordered handlers, each with sealed state; a failing handler is dropped while its siblings carry on. | a hand-written fan-out with per-subscriber state and a removal policy |
| `weft/registry` | Reclaimable typed addresses for actors that restart inside a long-lived scope; a lookup resolves the current incarnation, and a dead recipient's binding is removed. | a process name checked with `process.named` before every send |

## Where it applies here

These are the sites in this tree that are one of the shapes above, and the
primitive each one should be built on. A new process that matches a row is
built on the primitive from the start.

| Site | Shape | Primitive |
|---|---|---|
| `tor` (the sidecar's port owner) | phases (starting, bootstrapping, ready, restarting), a bounded restart count, requests waiting on a reply | `weft/state_machine`, the shape `spindle` uses for its helper process |
| `daemon/scheduler` | one task per outbox row, each bounded by a deadline | a `weft` run with `limit` and `deadline`, relayed into the scheduler |
| `daemon/fetcher` | long poll, then backoff on failure, re-armed by hand | `weft/state_machine` with a named timeout for the backoff |
| `daemon/provisioner`, `daemon/fetch_manager` | a scan on start, on a nudge and on a timer | `weft/actor` `periodic`, or a named timeout when the next wake is computed |
| `mailbox/sweeper` | a `send_after` its own handler re-arms | `weft/actor` `periodic` |
| `daemon/api.invite`'s wait for its queue | a foreground wait on a durable row landing | `weft/poll` |
| actors that hand back a subject through a `ready` message | an init handshake | `weft/actor` `continuing` |

## When not to

- **`core` never imports it.** `core` is the portable subset (no
  `@external`, no `gleam_erlang`, no `gleam_otp`; lint R6 gates), and weft
  imports both OTP packages. What moves onto weft is a *driver*, never the
  state machine: `core/relationship` is a pure function whose state lives
  in the store, and a weft state machine is a process whose state dies with
  its pid.
- **A homogeneous subscriber list with no per-subscriber state stays a list
  of subjects.** `weft/event_manager` is for handlers that each hold
  different state and must fail independently.
- **Per-key deadline tables stay.** N independent deadlines are not one
  machine's state timeout.
- **A janitor that defends against an untrappable kill stays.**
  `on_shutdown` cannot run on a brutal kill.

## The rules a port is held to

1. **A state's payload does not change while the machine is in that
   state.** A state timeout is cancelled by a transition to a state that
   compares unequal, and a transition to an equal value is not a state
   change, so re-entering a state with mutated payload silently restarts
   its deadline. Anything that moves per event goes in the machine's data.
2. **Every `case state, message` pair is written.** No `_ ->`. An arm that
   is unreachable by construction says so in a comment and keeps the
   state. A port is bigger than what it replaced, and that is the point: a
   reviewer can see every transition.
3. **Start unlinked when the starter must not share fate.** A supervisor
   always links; `supervised` ignores the setting.
4. **Children are published beneath their parent.** A child owner is
   adopted under the process that coordinates it (`adopt_under`), so the
   parent keeps custody of cancelling what it started.
5. **Mutation-test the timeout.** Remove the state timeout, the periodic
   arm or the deadline and name the test that fails. A poll loop's `Retry`
   arm gets the same treatment. A port whose timeout no test notices has
   not been ported yet.
6. **A periodic timeout is armed at one place, not on every entry.** It
   belongs to the machine, not to a state; arming it in an enter callback
   for a state the machine keeps returning to builds an idle timeout by
   accident.
7. **Match all seven `Outcome` variants.** Plain tasks never produce
   `DrainProofLost` or `CancellationUnconfirmed`, but the arms exist so a
   run that grows an owner fails exhaustiveness rather than falling into a
   catch-all.

## Extending it

Weft is `../weft` beside this checkout. While a body of work needs new
primitives, the packages that use weft point at the sibling checkout as a
path dependency (`weft = { path = "../../../weft" }`), so a change lands in
weft's `main`, passes weft's own `make check`, and is used here at once.
When the surface settles, a Hex release is cut and the path dependencies
switch back to a pinned Hex version in one commit. The current release is
0.4.6. When a primitive is missing, say so in the port rather than forcing
a fit, and extend weft.
