# Reedwire

Reedwire is an end-to-end encrypted, Tor-first messaging system for software
agents run by different people on different machines. Two agents pair once,
with a short ticket or an invitation file, and from then on they can exchange
messages while either side is offline, through a mailbox that stores only
padded ciphertext.

Agents working across trust boundaries need a way to reach each other that
doesn't require a shared account at a hosted relay, keeps working when one
side is asleep, and doesn't ask anyone to trust the relay with plaintext.
Reedwire treats a message as a durable, replay-aware delivery, not a remote
procedure call. An incoming message is never permission to do anything: what
an agent does with a message is its host's policy, enforced outside Reedwire.

- **Post-quantum from the first message.** Pairing uses hybrid
  [PQXDH](https://signal.org/docs/specifications/pqxdh/) with ML-KEM-1024, and
  every authentication step needs both an Ed25519 and an ML-DSA-65 proof. The
  session then runs Signal's [Double
  Ratchet](https://signal.org/docs/specifications/doubleratchet/).
- **Asynchronous and durable.** Every send and receive commits to SQLite before
  it touches the network, so a crash at any point retries the same ciphertext
  and never redelivers a message.
- **Tor by construction.** A mailbox address is a v3 onion address or, when an
  operator explicitly asks for it in testing, a loopback port. There is no way
  to name a public host.
- **Least privilege for agents.** An agent holds a socket and a credential that
  can send, receive and acknowledge, but can't approve contacts, mint
  invitations or read the audit log. Each pairing has a message budget.
- **Self-contained releases.** One tree ships its own Erlang runtime, OpenSSL
  and Tor sidecar, so the machine running it needs none of the build tools.

## Quick start

Building needs Gleam 1.18+, Erlang/OTP 29 linked against OpenSSL 3.5 or newer
(ML-KEM needs it), and a Rust toolchain for the Tor sidecar.

```bash
git clone https://github.com/Roasbeef/reedwire.git
cd reedwire
make install                        # PREFIX defaults to ~/.local
reedwire --version
```

To see the whole system run once, `make demo` starts a mailbox, two daemons and
two sandboxed agents, then checks that tasks and answers arrive and that the
limits hold:

```bash
make demo CARRIER=loopback          # on one machine
make demo CARRIER=tor               # over real onion services
```

[docs/quickstart.md](docs/quickstart.md) walks through pairing and messaging by
hand, and covers install layout, logs and the CLI's exit codes. The demo's
checks are listed in [docs/demo.md](docs/demo.md).

The core of the flow looks like this. A ticket goes out on standard output and
comes back in on standard input, never as a command-line argument, and the same
holds for payloads:

```bash
reedwire invite create --state-dir ./a --description "agent A" --budget 10 --ticket > a.ticket
reedwire invite accept --state-dir ./b --ticket --stdin < a.ticket
reedwire contact approve --state-dir ./a --contact <hex>
reedwire send --state-dir ./b --credential-file ./b/agent.cred --contact <hex> \
    --content-type application/json --file task.json
reedwire receive --state-dir ./a --credential-file ./a/agent.cred --wait 25 --json
```

## How it works

```
 agent A ── local API ──> daemon A ─┐                ┌─ daemon B <── local API ── agent B
 (sandboxed)              (state,   │   Tor onion    │  (state,              (sandboxed)
                           keys)    └─> mailbox <────┘   keys)
                                       (ciphertext,
                                        capabilities)
```

Each daemon picks a mailbox to receive at and creates one queue per
relationship there. An invitation carries the inviter's prekey bundle and the
address of a queue to write to. The joiner runs the handshake against that
bundle and sends a `Hello` naming its own return queue. The inviter's operator
approves the contact (or the invitation was minted to approve automatically),
and the relationship becomes active.

The bundle makes an invitation file about 14 KB, too much to paste into a chat.
So an invitation can also travel as a _ticket_, a 130-character `rw1...` string
that carries only the mailbox address and a random secret. The invitation waits
at that mailbox, sealed under keys derived from the secret, and the joiner's
daemon fetches and checks it ([ADR-009](docs/adr/009-invitation-tickets.md)). A
ticket is a bearer secret, like the file: whoever holds it can try to pair, so
hand it over a channel you trust.

Messages travel as padded envelopes (4, 16, 64 or 256 KiB) appended to the
recipient's queue, authorized by a per-queue capability. The recipient fetches
with a long poll, processes each envelope in one SQLite transaction, and only
then acknowledges it. An encrypted receipt goes back so the sender learns the
message was durably received, which is a different fact from the mailbox having
stored it. If no receipt arrives, the sender retransmits the same committed
bytes end to end ([ADR-006](docs/adr/006-end-to-end-retransmit.md)).

The daemon is written in [Gleam](https://gleam.run) on the BEAM, and the
protocol logic is pure: every pairing and messaging step is a
`transition(state, event)` that returns the new state plus the rows to commit,
and the shell sends only what it reads back from the committed store. Tor is
[Arti](https://gitlab.torproject.org/tpo/core/arti) in a separate
`reedwire-tor` process driven over an Erlang port, so a crash in the Tor stack
can't take the VM with it. The primitives come from OTP's `crypto` over OpenSSL;
Reedwire has no crypto NIF of its own.
[docs/architecture/system.md](docs/architecture/system.md) follows one message
through all of this.

## Security model

These properties are held by types or checked by tests, not by convention:

- _No send before commit, no ack before commit._ Ciphertext exists only in
  committed outbox rows and acknowledgment only in committed processed rows, so
  the network never sees bytes the local state doesn't account for.
- _Secrets don't print._ Keys, capabilities, payloads and ratchet state are
  opaque values. A log line can only hold typed fields, and OTP's crash reports
  are rebuilt from their shape, without the state or call arguments in which a
  key would otherwise show up
  ([ADR-012](docs/adr/012-logging-and-crash-reports.md)).
- _Bounded inbound work._ Past a pairing's budget, messages are held until the
  operator raises it, so a contact can't turn into an unlimited prompt-injection
  channel. Every application message lands in an audit log the operator can read.

Reedwire doesn't claim to be metadata-free. The mailbox sees queue identifiers,
padded sizes and timing, and queues provisioned from one account can be linked
to each other. Ratchet headers aren't encrypted, and post-compromise recovery is
classical (each ratchet step is X25519). The joiner's signed first message isn't
deniable ([ADR-005](docs/adr/005-hybrid-authentication.md)). The state directory
is protected by file permissions only.
[docs/crypto-profile-v1.md](docs/crypto-profile-v1.md) specifies the
cryptography byte for byte, along with these limits.

Reedwire hasn't had an independent security review, and the wire format and
profile aren't frozen. Please weigh that before relying on it for anything
sensitive.

## Verification

We test the design at several levels, and hold each check to the same standard:
a check counts only if a deliberately broken variant makes it fail.

| Layer | What runs | Where |
| --- | --- | --- |
| Deterministic simulation | Two real daemons and a real mailbox in one VM under seeded faults, with exact replay | [packages/sim](packages/sim) |
| Protocol simulation | The pure core under generated duplicates, replays, reordering and crashes at every step | [packages/core](packages/core) |
| Lean 4 | 42 theorems on the codec, padding, retention and retransmit schedule, plus 11,201 vectors the Gleam code must match | [docs/formal/lean.md](docs/formal/lean.md) |
| P | End-to-end delivery across three parties, with faults and crash points | [docs/formal/p.md](docs/formal/p.md) |
| TLA+ | The scheduler's claims and the fetcher's acknowledgement rule, 18 configurations including mutants | [docs/formal/tla.md](docs/formal/tla.md) |
| ProVerif | The handshake and sealed tickets, 30 scenarios under broken-primitive and leaked-invitation adversaries | [docs/formal/crypto.md](docs/formal/crypto.md) |
| Vectors | Wycheproof and NIST ACVP through the same bindings the protocol calls | [packages/primitives](packages/primitives) |

`make check` is the gate for every change: formatting, a warning-free build,
every test suite, the house lint and a documentation check. `make formal` runs
the proofs and model checkers, which need their own tools.

## Platform support

Releases are built and tested on macOS on Apple silicon. A Linux recipe exists
in [ADR-003](docs/adr/003-packaging.md) but hasn't been run yet, and release
binaries aren't signed or notarized. Building from source needs an OTP linked
against OpenSSL 3.5 or newer, which rules out the OTP in current Ubuntu
packages.

## Documentation

| Read | For |
| --- | --- |
| [docs/quickstart.md](docs/quickstart.md) | Pairing and messaging by hand, logs, install layout |
| [docs/architecture/](docs/architecture/) | How the system and each subsystem work, with each package's `README.md` |
| [docs/spec.md](docs/spec.md) | The protocol and its invariants |
| [docs/crypto-profile-v1.md](docs/crypto-profile-v1.md) | The cryptographic profile |
| [docs/design-intent.md](docs/design-intent.md) | Why the system is shaped this way |
| [docs/adr/](docs/adr/) | Architecture decisions and their consequences |
| [docs/formal/](docs/formal/) | The formal models and what they do and don't show |
| [docs/next.md](docs/next.md) | Where the project stands and what's next |

## Repository layout

| Path | What lives there |
| --- | --- |
| [`packages/core`](packages/core) | The pure protocol: TLV codec, mailbox protocol, PQXDH and the ratchet, invitations, the relationship state machine. No I/O. |
| [`packages/primitives`](packages/primitives) | OTP `crypto` bindings, and the `Suite` that feeds them to `core`. |
| [`packages/mailbox`](packages/mailbox) | The mailbox service: SQLite store, single-writer coordinator, long poll, HTTP binding. |
| [`packages/daemon`](packages/daemon) | The client daemon: store, engine, delivery scheduler, fetchers, local API, and the `reedwire` CLI. |
| [`packages/telemetry`](packages/telemetry) | Typed logging, and the formatter that keeps secrets out of OTP's crash reports. |
| [`packages/tor`](packages/tor) | The BEAM side of the Tor sidecar. |
| [`native/reedwire-tor`](native/reedwire-tor) | The Arti sidecar, in Rust. |
| [`packages/sim`](packages/sim) | The deterministic simulation harness. |
| [`packages/lint`](packages/lint) | The house lint, which `make lint` runs. |
| [`formal`](formal) | Lean, P, TLA+ and ProVerif models. |

## Contributing

Run `make check` before sending a change, and read
[docs/gleam-style.md](docs/gleam-style.md) first: Gleam is young, and the style
guide covers the idioms and the policies the lint enforces.
[CLAUDE.md](CLAUDE.md) (mirrored as `AGENTS.md`) carries the house rules, and
each package's `CLAUDE.md` lists the invariants that break things when violated.
A change to protocol behaviour starts with an ADR, per
[docs/adr/README.md](docs/adr/README.md).
