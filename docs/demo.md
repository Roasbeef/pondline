# The demonstration

`scripts/demo.sh` runs the whole system once, end to end: one mailbox, two
daemons, and two toy agents, each confined by a macOS sandbox. It exits 0
only if every check passed.

```
scripts/demo.sh --carrier=loopback          # about 20 s after the build
scripts/demo.sh --carrier=tor               # about 100 s; needs the network
scripts/demo.sh --carrier=tor --messages 4  # fewer tasks (1 to 10)
scripts/demo.sh --carrier=loopback --pairing=file  # move the invitation file, not a ticket
make demo CARRIER=tor                       # the same, through make
```

Options: `--skip-build` reuses the shipments from an earlier run, `--keep`
leaves the temporary workspace (logs, databases) for inspection.

`--release DIR` runs the demo from a release tree instead of the
shipments, with nothing built: `build/release/<platform>/reedwire` after
`make release`, an unpacked `make dist` tarball, or an installed copy
(`--release ~/.local/lib/reedwire/current` after `make install`). Every
program, the agents' CLI included, then runs on the tree's own Erlang
runtime and OpenSSL, the Tor sidecar is the tree's, and the sandbox is
given the tree in place of the host's Erlang. With `--carrier=loopback`
it passes every check in about 15 s. The script
needs `erl`, `gleam`, `jq`, `shasum` and `sandbox-exec` (all present on a
recent macOS with Homebrew's Erlang), and for `--carrier=tor` the sidecar
(`make sidecar`, built for you). Run it outside any other sandbox: it opens
sockets and applies its own.

## What it sets up

```
  agent B (asker)      agent A (responder)        each agent: sandbox-exec,
      | unix socket        | unix socket          a copy of agent.cred, and
  daemon B  <-- mailbox -->  daemon A             one socket. Nothing else.
              (onion service with --carrier=tor)
```

The asker belongs to the acceptor (B) and the responder to the inviter (A).
That is the reverse of the obvious assignment, and deliberate: the message
budget is the inbound limit a party grants its peer, so A's budget of 10 is
what bounds B's tasks, and the demo can show messages being held.

## What each step proves

1. **Grants.** Two provisioning capabilities are written to 0600 files and
   never printed (spec §9).
2. **Mailbox.** With `--carrier=tor` the mailbox publishes an onion service
   (`mailbox serve --tor-bin ... --tor-state ...` prints `onion <host>:80`)
   and the daemons are given only that address. Nothing reaches it over the
   clearnet.
3. **Pairing.** A creates an invitation (it carries the post-quantum key
   bundle), B accepts, A's operator approves. Both sides become `active`
   through messages that cross the mailbox. The invitation moves out of
   band as a ticket by default (ADR-009): A prints a short `rw1` string,
   and B redeems it on standard input, fetching the sealed invitation
   from the mailbox. `--pairing=file` moves the invitation file instead.
4. **Sandbox.** Probes run inside each agent's sandbox: it can use the
   daemon with its own credential; it cannot read `operator.cred`, the
   daemon database or the original `agent.cred`, cannot list the state
   directory, cannot use the operator credential (the CLI cannot open it),
   is refused operator actions by the daemon (exit 3), cannot write outside
   its directory, cannot reach the internet and cannot read the home
   directory. The same read of `operator.cred` works outside the sandbox, so
   the denial is the sandbox's.
5. **Tasks.** The asker sends N `sha256` tasks; the responder answers each
   as a reply and acknowledges it. The script recomputes every digest itself
   and compares. Payloads are end-to-end encrypted with the post-quantum
   session; the mailbox sees only padded ciphertext.
6. **Receipts.** Every task reaches `received_by_peer` on B: a receipt is
   A's own authenticated message, not the mailbox's say-so. Durable
   delivery shows in the daemon's outbox and acknowledgement rules (a
   message is acknowledged to the mailbox only after it is committed).
7. **Audit.** A's `audit` prints the plaintext of both directions. The log
   lives in the daemon's database, outside the agent's reach.
8. **Budget.** The asker sends `budget - N + 2` more tasks. The ones within
   the budget are answered; the last two are held at A (`held=2`, and
   unanswered). The operator then raises the budget (`contact budget
   --add 5`), the held tasks are released, answered and verified.
9. **Cleanup.** An exit trap stops every process group it started, on
   success, failure or interrupt.

## The sandbox

`scripts/agents/agent.sb` is a Seatbelt profile: deny by default (on top of
Apple's `system.sb` baseline), read access to system libraries, the Erlang
installation and the built CLI (`packages/daemon/build/erlang-shipment`,
code only), read and write access to the agent's own directory, and network
access to exactly one path, the daemon's `api.sock`. The state directory is
denied by name, last, so the denial holds if an earlier rule is widened.
The agent's credential is a copy of `agent.cred` in its directory. The
agent scope permits only contacts, send, receive, acknowledge, status and
health, so a hijacked agent can still send messages, but only within the
budget, and it can neither approve contacts, raise the budget nor read the
audit log.

On Linux the equivalent is bubblewrap or Landlock plus a network namespace
with only the socket bind-mounted; the profile has not been ported.

## Measured timings

One run each, on an Apple-silicon Mac, six tasks, wall clock from the start of
the script (the build is included in the first line).

| Step | loopback | tor |
| --- | --- | --- |
| build (shipments; sidecar for tor) | 19 s | 25 s |
| mailbox up (onion published for tor) | 1 s | 10 s |
| daemons up (Tor clients bootstrapped) | 2 s | 8 s |
| pairing (invite, accept, approve, both active) | 1 s | 28 s |
| sandbox probes | 1 s | 1 s |
| six tasks answered | 4 s | 23 s |
| budget phase (hold, raise, release) | 8 s | 29 s |
| total | 38 s | 125 s |

## Burst behavior and pacing

The agents queue their sends back to back (`PACE_SENDS=0`, the default).
`PACE_SENDS=1` makes each send wait until the daemon reports the message
stored by the mailbox, which orders the sends.

While the demo was being built, unpaced runs showed two symptoms, and the
demo was paced to work around them:

- Over Tor, five tasks queued back to back were all dropped by the receiver
  (`processed.outcome = 'dropped'`, acknowledged to the mailbox, so lost),
  after the first was applied, as if they had reached the mailbox out of
  order.
- Over loopback, the two messages over budget appeared in `contacts list`
  as `held=2` yet were stored as `ready` and delivered to the agent.

Neither reproduced after the weft port, in the daemon's tests or in the
demo. The earlier failures most likely came from a half-ported working tree,
though that was not proven. Unpaced, the demo passed five loopback runs and
one Tor run at the commit that made `PACE_SENDS=0` the default. The symptoms
are now guarded by tests, so a regression fails the build and not only a
demo run:

- `packages/core/test/core/reorder_test.gleam`: five sends delivered to the
  mailbox newest first are all delivered, once each.
- `packages/core/test/core/world.gleam`, checked by the simulation: every
  held message has a `Held` delivery, and the `Ready` deliveries equal the
  budget's `used`.
- `packages/daemon/test/daemon/burst_test.gleam`: a burst appended out of
  order is applied in full, and a burst over a budget of three is held
  (`used=3 held=2`, three `ready` rows, two `held` rows) and released by
  `raise_budget`.
- `packages/daemon/test/daemon/store_test.gleam`: a second `Delivered` for
  the same contact and message fails the commit and rolls it back, so the
  store can no longer keep one row while the state believes another.

Set `PACE_SENDS=1` to pace the sends if a run fails and you want to separate
a burst problem from another one.

## What it does not show

No real language-model agents (the agents are shell scripts); no Linux
sandbox; no packaged daemon release (the CLI runs from a Gleam shipment);
no mailbox failure, restart or crash recovery (those are in the daemon's
tests); no message expiry; one pairing only; no key rotation or revocation;
Tor timings are one run on one network and vary from tens of seconds to
minutes.
