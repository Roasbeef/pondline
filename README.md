# Reedwire

Reedwire is an end-to-end encrypted, Tor-first messaging substrate for
agents run by different people on different machines. Two agents pair
once through an invitation, a short ticket or a file, and from then on they can exchange
messages while either side is offline, through a mailbox that stores
only padded ciphertext and never learns who is talking to whom beyond
what Tor and queue timing leak. The name is provisional.

The problem we're after is narrow: agents across trust boundaries need
a way to reach each other that doesn't require a shared account at some
hosted relay, keeps working when one side is asleep, and doesn't ask
anyone to trust the relay with plaintext. A message is a durable,
replay-aware delivery, not a remote procedure call, and an incoming
message is never permission to do anything: what an agent does with a
message is its host's policy, enforced outside Reedwire.

## How it works

Each daemon picks a mailbox to receive at and creates one queue per
relationship there. An invitation is a small file carrying the inviter's
post-quantum prekey bundle and the address of a queue to write to. The
joiner runs [PQXDH](https://signal.org/docs/specifications/pqxdh/)
against that bundle, sends a `Hello` naming its own return queue, and
the two settle into Signal's [Double
Ratchet](https://signal.org/docs/specifications/doubleratchet/). The
inviter's operator approves the contact (or the invitation was minted
to approve automatically), and the relationship becomes active.

The bundle makes an invitation about 14 KB, too much to paste into a
chat. So an invitation can also travel as a **ticket**, a 130-character
`rw1...` string (74 for a loopback mailbox in tests) that carries only
the inviter's mailbox and a random secret. The invitation itself waits
at that mailbox, encrypted under keys derived from the secret, until it
expires; the joiner's daemon fetches it, checks that it opens and that
its commitment matches, and pairs from there. The mailbox holds only
ciphertext it cannot open. A ticket is a bearer secret like the file it
replaces: whoever holds it can try to pair, so hand it over a channel
you trust ([ADR-009](docs/adr/009-invitation-tickets.md)).

```
 agent A ── local API ──> daemon A ─┐                ┌─ daemon B <── local API ── agent B
 (sandboxed)              (state,   │   Tor onion    │  (state,              (sandboxed)
                           keys)    └─> mailbox <────┘   keys)
                                       (ciphertext,
                                        capabilities)
```

Messages travel as padded envelopes (4, 16, 64 or 256 KiB) appended to
the recipient's queue, authorized by a per-queue capability. The
recipient fetches with a long poll, processes each envelope in one
SQLite transaction, and only then acknowledges it to the mailbox. An
encrypted receipt goes back so the sender learns the message was
durably received, which is a different fact from the mailbox having
stored it.

The daemon is written in [Gleam](https://gleam.run) on the BEAM, and
the protocol logic is pure: every pairing and messaging step is a
`transition(state, event)` that returns the new state plus the rows to
commit, and the shell sends only what it reads back from the committed
store. Tor is [Arti](https://gitlab.torproject.org/tpo/core/arti) in a
separate `reedwire-tor` process driven over an Erlang port, so a crash
in the Tor stack can't take the VM with it. The cryptographic
primitives (ML-KEM-1024, X25519, Ed25519, ChaCha20-Poly1305,
HMAC-SHA-256) come from OTP's `crypto` over OpenSSL 3.5+; there is no
crypto NIF of our own.

## What it promises, and what it doesn't

A few properties are held by the types or by tests rather than by
convention:

- _No send before commit, no ack before commit._ Ciphertext exists only
  in committed outbox rows and acknowledgment only in committed
  processed rows, so the network never sees bytes the local state
  doesn't account for. A simulation drives three parties through
  generated schedules of duplicates, replays, corruption, reordering and
  crashes, restarting at every step, and checks this along with no
  redelivery, no double consumption of an invitation, and no delivery
  before a contact is approved.
- _No silent downgrade._ A mailbox endpoint is a v3 onion address or a
  loopback port (for tests and the offline demo, only when the operator
  asks for it); there's no constructor for a public host.
- _Secrets don't print._ Keys, capabilities, payloads and ratchet state
  live in closures, which the BEAM renders as `#Fun<..>`. A log line can
  only hold typed fields (identifier prefixes, counts, durations,
  constructor names), and OTP's crash reports are rebuilt from their
  shape, without the state, mailbox or call arguments in which a key or a
  payload would otherwise show up
  ([ADR-012](docs/adr/012-logging-and-crash-reports.md)).
- _Bounded inbound work._ Each pairing carries a message budget; past
  it, messages are held until the operator raises it, so a contact can't
  turn into an unlimited prompt-injection channel. Every application
  message in or out lands in a plaintext audit log the operator can
  read.

What it doesn't claim: authentication is classical (Ed25519 and
X25519), so the post-quantum part protects confidentiality against an
adversary recording traffic today, not identity. There's no
post-quantum post-compromise security yet (the profile reserves a
version for Signal's sparse post-quantum ratchet), ratchet headers are
not encrypted, and the mailbox sees queue identifiers, padded sizes and
timing. Nothing is described as metadata-free. The state directory is
protected by file permissions only. [docs/crypto-profile-v1.md](docs/crypto-profile-v1.md)
states the cryptographic profile byte for byte, along with its limits.

## Status

This is early. Phase 0's three feasibility spikes are done and recorded
as ADRs ([Tor sidecar](docs/adr/001-tor-sidecar.md), [PQ crypto over
OTP](docs/adr/002-pq-crypto-over-otp.md),
[packaging](docs/adr/003-packaging.md)). The mailbox, the pure protocol
core and the client daemon with its local API and CLI exist and pass
their tests, and two daemons have paired and exchanged messages through
a real mailbox over loopback. The demo with two sandboxed agents over
Tor, and hardening (fuzzing, load limits, an outside review), are what's
next. [docs/next.md](docs/next.md) is the honest, current picture.

None of this has had an independent security review. Don't use it for
anything that matters yet.

## Layout

| Path | What lives there |
| --- | --- |
| `packages/core` | The pure protocol: ids, capabilities, TLV codec, mailbox protocol, PQXDH and the ratchet, invitations, the relationship state machine. No I/O. |
| `packages/primitives` | OTP `crypto` bindings, and the `Suite` that feeds them to `core`. |
| `packages/mailbox` | The mailbox service: SQLite store, single-writer coordinator, long poll, HTTP binding, `serve` and `grant`. |
| `packages/daemon` | The client daemon: store, engine, delivery scheduler, fetchers, local API over a Unix socket, and the `reedwire` CLI. |
| `packages/telemetry` | Logging: typed log lines, and the `logger` formatter that keeps secrets out of OTP's crash reports. |
| `packages/tor` | The BEAM side of the Tor sidecar: an actor that owns the port and restarts it. |
| `native/reedwire-tor` | The Arti sidecar, in Rust. |
| `packages/lint` | The house lint, which `make lint` runs. |
| `docs/` | The spec, design intent, ADRs, crypto profile, architecture docs and the handoff. |

## Building and testing

You'll need Gleam 1.18+, Erlang/OTP 29 linked against OpenSSL 3.5 or
newer (ML-KEM needs it), and a Rust toolchain for the sidecar.

```bash
make check
```

That's the full gate: formatting, a warning-free build of every
package, every test suite, the lint and the documentation check. `make
help` lists the rest, among them `make sidecar` to build the Tor
sidecar on its own (`make test` builds it first).

## Install

`make install` builds a self-contained release (its own Erlang runtime,
OpenSSL and Tor sidecar, so the machine running it needs none of the
build tools) and installs two commands:

```bash
make install                        # PREFIX defaults to ~/.local
make install PREFIX=/opt/reedwire
reedwire --version                  # reedwire 0.1.0 (commit <sha>)
```

That puts the release tree in `$PREFIX/lib/reedwire/` and the
`reedwire` and `reedwire-mailbox` commands in `$PREFIX/bin`; it never
replaces a file it did not create, and never touches a running build's
tree or your state directories. `make uninstall` (with the same `PREFIX`)
removes it. The pieces are separate targets too: `make release` builds
the tree into `build/release/<platform>/reedwire`, `make release-smoke`
boots it with no Erlang on the `PATH` and pairs two daemons through a
mailbox, and `make dist` packs it into a tarball with a SHA-256, which
installs itself with `PREFIX=... ./install.sh` once unpacked. Releases are
built and tested on macOS on Apple silicon only; the Linux recipe in
[ADR-003](docs/adr/003-packaging.md) is written but has never been run.

### Logs

Both programs log to standard error, one logfmt line per event, and keep
standard output for their own output (`listening`, `ready`, payloads):

```
time=2026-11-01T23:43:27.890Z level=info component=http event=request method=post status=200 response=queue_created elapsed_ms=8
time=2026-11-01T23:43:28.004Z level=error component=otp event=crash_report process=daemon_engine$4614 class=error reason=badarg at=crypto:crypto_one_time_aead/7:1783,...
```

`REEDWIRE_LOG_LEVEL` sets the threshold: `debug`, `info` (the default),
`warning` or `error`. `info` is the lifecycle and the mailbox's access
log; `warning` is something degraded that will be retried; `error` is a
crash or something nothing will retry. Redirect standard error to keep
them (`reedwire daemon ... 2>>daemon.log`).

Installed, the walkthrough below is the same with `reedwire` and
`reedwire-mailbox` in place of `gleam run -m reedwire --` and `gleam run
-m mailbox --`, run from any directory.

The Tor tests talk to the live network, so they're off by default:

```bash
REEDWIRE_TOR_NETWORK=1 make test-tor
```

## Trying it on one machine

The loopback carrier runs everything locally without Tor. First a
mailbox, with a provisioning capability for each daemon:

```bash
cd packages/mailbox
gleam run -m mailbox -- grant --db /tmp/rw/mb.db --queues 100 --out /tmp/rw/provA
gleam run -m mailbox -- grant --db /tmp/rw/mb.db --queues 100 --out /tmp/rw/provB
gleam run -m mailbox -- serve --db /tmp/rw/mb.db --port 0
```

It prints `listening 127.0.0.1:<port>`. Then a daemon per agent, from
`packages/daemon`, each in its own terminal:

```bash
gleam run -m reedwire -- daemon --state-dir /tmp/rw/A --mailbox 127.0.0.1:<port> --provision-file /tmp/rw/provA --carrier loopback
```

```bash
gleam run -m reedwire -- daemon --state-dir /tmp/rw/B --mailbox 127.0.0.1:<port> --provision-file /tmp/rw/provB --carrier loopback
```

A invites, B accepts, A approves. The ticket is printed on standard
output and handed to B on standard input, never as an argument:

```bash
gleam run -m reedwire -- invite create --state-dir /tmp/rw/A --description "agent A" --budget 10 --ticket > /tmp/rw/a.ticket
```

```bash
gleam run -m reedwire -- invite accept --state-dir /tmp/rw/B --ticket --stdin < /tmp/rw/a.ticket
```

The file path still works, for a mailbox you would rather not ask to hold
the invitation: `invite create ... --out /tmp/rw/a.invite`, then
`invite accept ... --file /tmp/rw/a.invite`.

```bash
gleam run -m reedwire -- contacts list --state-dir /tmp/rw/A --json
```

```bash
gleam run -m reedwire -- contact approve --state-dir /tmp/rw/A --contact <hex>
```

From here an agent only ever needs its daemon's socket and the _agent_
credential, which can send, receive, acknowledge and check status but
can't approve contacts, mint invitations or read the audit log. Payloads
come from a file or stdin, never from argv:

```bash
gleam run -m reedwire -- send --state-dir /tmp/rw/B --credential-file /tmp/rw/B/agent.cred --contact <hex> --content-type application/json --file task.json
```

```bash
gleam run -m reedwire -- receive --state-dir /tmp/rw/A --credential-file /tmp/rw/A/agent.cred --wait 25 --json
```

Run `gleam run -m reedwire -- help` for the rest (`ack`, `status`,
`audit`, `contact budget`, `health`). Every command takes `--json`, and
exit codes are stable: 0 ok, 1 local failure, 2 usage, 3 unauthorized or forbidden, 4
not found, 5 refused or invalid, 6 unavailable.

## Where to read next

Start with [docs/next.md](docs/next.md) for where things stand and
what's been decided. [docs/design-intent.md](docs/design-intent.md) is
the why, and [docs/spec.md](docs/spec.md) is the protocol and its
invariants; where they disagree, the spec wins on mechanics.
[docs/architecture/](docs/architecture/) maps each subsystem's processes
and state, and [docs/gleam-style.md](docs/gleam-style.md) is required
reading before writing code here. [CLAUDE.md](CLAUDE.md) (mirrored as
`AGENTS.md`) carries the house rules.
