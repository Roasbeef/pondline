# Quick start

This page installs Pondline, then pairs two daemons by hand and sends a
message between them. Everything runs on one machine over the loopback
carrier, without Tor. `make demo` runs the same flow automatically
([demo.md](demo.md)).

## Install

`make install` builds a self-contained release (its own Erlang runtime,
OpenSSL and Tor sidecar, so the machine running it needs none of the
build tools) and installs two commands:

```bash
make install                        # PREFIX defaults to ~/.local
make install PREFIX=/opt/pondline
pondline --version                  # pondline 0.1.0 (commit <sha>)
```

That puts the release tree in `$PREFIX/lib/pondline/` and the
`pondline` and `pondline-mailbox` commands in `$PREFIX/bin`; it never
replaces a file it did not create, and never touches a running build's
tree or your state directories. `make uninstall` (with the same `PREFIX`)
removes it. The pieces are separate targets too: `make release` builds
the tree into `build/release/<platform>/pondline`, `make release-smoke`
boots it with no Erlang on the `PATH` and pairs two daemons through a
mailbox, and `make dist` packs it into a tarball with a SHA-256, which
installs itself with `PREFIX=... ./install.sh` once unpacked. Releases are
built and tested on macOS on Apple silicon only; the Linux recipe in
[ADR-003](adr/003-packaging.md) is written but has never been run.

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
gleam run -m pondline -- daemon --state-dir /tmp/rw/A --mailbox 127.0.0.1:<port> --provision-file /tmp/rw/provA --carrier loopback
```

```bash
gleam run -m pondline -- daemon --state-dir /tmp/rw/B --mailbox 127.0.0.1:<port> --provision-file /tmp/rw/provB --carrier loopback
```

A invites, B accepts, A approves. The ticket is printed on standard
output and handed to B on standard input, never as an argument:

```bash
gleam run -m pondline -- invite create --state-dir /tmp/rw/A --description "agent A" --budget 10 --ticket > /tmp/rw/a.ticket
```

```bash
gleam run -m pondline -- invite accept --state-dir /tmp/rw/B --ticket --stdin < /tmp/rw/a.ticket
```

The file path still works, for a mailbox you would rather not ask to hold
the invitation: `invite create ... --out /tmp/rw/a.invite`, then
`invite accept ... --file /tmp/rw/a.invite`.

```bash
gleam run -m pondline -- contacts list --state-dir /tmp/rw/A --json
```

```bash
gleam run -m pondline -- contact approve --state-dir /tmp/rw/A --contact <hex>
```

From here an agent only ever needs its daemon's socket and the _agent_
credential, which can send, receive, acknowledge and check status but
can't approve contacts, mint invitations or read the audit log. Payloads
come from a file or stdin, never from argv:

```bash
gleam run -m pondline -- send --state-dir /tmp/rw/B --credential-file /tmp/rw/B/agent.cred --contact <hex> --content-type application/json --file task.json
```

```bash
gleam run -m pondline -- receive --state-dir /tmp/rw/A --credential-file /tmp/rw/A/agent.cred --wait 25 --json
```

Run `gleam run -m pondline -- help` for the rest (`ack`, `status`,
`audit`, `contact budget`, `health`). Every command takes `--json`, and
exit codes are stable: 0 ok, 1 local failure, 2 usage, 3 unauthorized or forbidden, 4
not found, 5 refused or invalid, 6 unavailable.

Installed, the commands are the same with `pondline` and `pondline-mailbox`
in place of `gleam run -m pondline --` and `gleam run -m mailbox --`, run from
any directory.

## Logs

Both programs log to standard error, one logfmt line per event, and keep
standard output for their own output (`listening`, `ready`, payloads):

```
time=2026-11-01T23:43:27.890Z level=info component=http event=request method=post status=200 response=queue_created elapsed_ms=8
time=2026-11-01T23:43:28.004Z level=error component=otp event=crash_report process=daemon_engine$4614 class=error reason=badarg at=crypto:crypto_one_time_aead/7:1783,...
```

`PONDLINE_LOG_LEVEL` sets the threshold: `debug`, `info` (the default),
`warning` or `error`. `info` is the lifecycle and the mailbox's access
log; `warning` is something degraded that will be retried; `error` is a
crash or something nothing will retry. Redirect standard error to keep
them (`pondline daemon ... 2>>daemon.log`).

## Testing against the Tor network

The Tor tests talk to the live network, so they're off by default:

```bash
PONDLINE_TOR_NETWORK=1 make test-tor
```
