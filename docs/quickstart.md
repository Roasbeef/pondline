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

The loopback carrier runs everything locally without Tor. Start a mailbox server first:

```bash
pondline-mailbox serve --db /tmp/rw/mb.db
```

It prints `listening 127.0.0.1:<port>`. Mint a copy-pasteable `plg1...` grant token for each daemon while the server stays running, and initialize each state directory (`pondline` defaults `--state-dir` to `~/.pondline` or `$PONDLINE_STATE_DIR` when omitted):

```bash
pondline-mailbox grant --db /tmp/rw/mb.db --queues 100 --mailbox 127.0.0.1:<port> --token \
  | pondline init --state-dir /tmp/rw/A --carrier loopback --stdin
pondline-mailbox grant --db /tmp/rw/mb.db --queues 100 --mailbox 127.0.0.1:<port> --token \
  | pondline init --state-dir /tmp/rw/B --carrier loopback --stdin
```

Then start each daemon in its own terminal (reloading its saved `config.json` and `provision.cap`):

```bash
pondline daemon --state-dir /tmp/rw/A
```

```bash
pondline daemon --state-dir /tmp/rw/B
```

A invites, B accepts, A approves (matching by petname, prefix, or full hex id). Tickets and payloads travel over stdout/stdin or files, never argv:

```bash
pondline invite create --state-dir /tmp/rw/A --description "agent B" --budget 10 --ticket > /tmp/rw/a.ticket
pondline invite accept --state-dir /tmp/rw/B --ticket --stdin --description "agent A" --budget 10 < /tmp/rw/a.ticket
pondline contact approve --state-dir /tmp/rw/A --contact "agent B"
```

From here an agent only ever needs its daemon's socket and `agent.cred`, which can send, receive, acknowledge and check status, but can't approve contacts, mint invitations or read the audit log:

```bash
pondline send --state-dir /tmp/rw/B --credential-file /tmp/rw/B/agent.cred --contact "agent A" \
  --content-type application/json --file task.json
pondline receive --state-dir /tmp/rw/A --credential-file /tmp/rw/A/agent.cred --wait 25 --json
pondline-mailbox status --db /tmp/rw/mb.db
```

Over live Tor, run `pondline-mailbox serve --db ~/.pondline-mailbox/mb.db --tor-state ~/.pondline-mailbox/tor` (the bundled `pondline-tor` sidecar is found automatically, and `contrib/` has `launchd` and `systemd` service templates). Mint user tokens with `pondline-mailbox grant --db ~/.pondline-mailbox/mb.db --tor-state ~/.pondline-mailbox/tor --queues 100 --token`, and each user runs `pondline init --stdin` once followed by `pondline daemon`.

Run `pondline help` for the rest (`ack`, `status`, `audit`, `contact budget`, `incidents`, `health`). Every command takes `--json`, and exit codes are stable: 0 ok, 1 local failure, 2 usage, 3 unauthorized or forbidden, 4 not found, 5 refused or invalid, 6 unavailable.

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
