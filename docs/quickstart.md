# Quick start

This page installs Pondline, explains the difference between a one-time mailbox
grant (`plg1...`) and a per-contact pairing ticket (`pl1...`), and walks
through pairing two machines over Tor as well as testing locally over loopback.
`make demo` runs the full flow automatically ([demo.md](demo.md)), and
[agent-quickstart.md](agent-quickstart.md) (plus the bundled
[skills/pondline/SKILL.md](../skills/pondline/SKILL.md) skill) covers wiring an
AI coding agent over `agent.cred` and `--json`.

## Install

On macOS (`darwin-arm64`) or Linux (`linux-x86_64`), install a self-contained
release (bundling its own Erlang runtime, OpenSSL 3.5+, and `pondline-tor`
sidecar) under `~/.local`:

```bash
curl -fsSL https://github.com/Roasbeef/pondline/releases/latest/download/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
pondline --version                  # pondline 0.1.1 (commit <sha>)
pondline-update --check             # check installed build against latest release
```

To give Claude Code, Loom, or Codex the Pondline workflow and safety rules,
install the [`pondline` skill](../skills/pondline/SKILL.md) from the repository
or directly from the installed release tree:

```bash
npx skills add Roasbeef/pondline
# or copy from the local release bundle:
mkdir -p ~/.claude/skills/pondline
cp ~/.local/lib/pondline/current/share/skills/pondline/SKILL.md ~/.claude/skills/pondline/SKILL.md
```

Building from source (`make install`, `PREFIX` defaults to `~/.local`) puts the
same release tree in `$PREFIX/lib/pondline/` and links `pondline`,
`pondline-mailbox`, and `pondline-update` in `$PREFIX/bin`; it never replaces a
file it did not create, and never touches a running build's tree or your state
directories (`make uninstall` removes it). Separate targets build individual
steps: `make release` assembles `build/release/<platform>/pondline`,
`make release-smoke` boots it with a scrubbed `PATH` and pairs two daemons,
`make dist` packs the tarball and SHA-256, and `make release-linux` builds and
smoke-tests the `linux-x86_64` bundle inside a clean Ubuntu 24.04 container
([ADR-003](adr/003-packaging.md)).

## Grant (`plg1...`) vs pairing ticket (`pl1...`)

Onboarding separates **where your daemon receives mail** from **whom you talk
to**:

```
  mailbox server (.onion)
     |                               |
     | 1. plg1 grant (once)          | 1. plg1 grant (once)
     v                               v
  daemon A (pondline init) ------> daemon B (pondline init)
                         2. pl1 ticket (once per peer)

  daemon A <=====================> daemon B
         3. E2E Double Ratchet over per-peer onion queues
```

1. **Mailbox grant (`plg1...`, done once per daemon):** A mailbox operator
   mints a `plg1...` token ([ADR-015](adr/015-grant-tokens-and-daemon-config.md))
   encoding the mailbox's `.onion` address and a random 32-byte capability
   secret with a queue quota (for example, 64 queues). Running
   `pondline init --stdin` saves that `.onion` endpoint in
   `~/.pondline/config.json` and that capability in `~/.pondline/provision.cap`
   (`0600`). It registers no user identity on the mailbox and connects you to
   no contacts yet; your daemon reuses that saved grant automatically whenever
   it needs a fresh inbound queue for a new peer. Two peers can share grants
   from the same mailbox server or use completely separate mailbox servers.
2. **Pairing ticket (`pl1...`, done once per contact):** Connecting two people
   or agents uses a 130-character `pl1...` ticket
   ([ADR-009](adr/009-invitation-tickets.md)). `pondline invite create --ticket`
   creates a dedicated inbound queue for that peer, seals a 14 KB post-quantum
   prekey bundle (`X25519 + ML-KEM-1024`, `Ed25519 + ML-DSA-65`) at A's
   mailbox, and prints the short `pl1...` ticket. `pondline invite accept --ticket`
   fetches and verifies that bundle over Tor, provisions B's own return queue
   using B's saved grant, runs hybrid PQXDH + Signal's Double Ratchet, and sets
   each side's inbound message budget.

## Pairing two machines over Tor

If you are running your own Tor mailbox server (`contrib/` includes `systemd`
and `launchd` templates), start it once and mint one `plg1...` grant token per
daemon:

```bash
pondline-mailbox serve --db ~/.local/state/pondline-mb/mailbox.db \
  --tor-state ~/.local/state/pondline-mb/tor
pondline-mailbox grant --db ~/.local/state/pondline-mb/mailbox.db \
  --tor-state ~/.local/state/pondline-mb/tor --queues 64 --token
```

### 1. One-time daemon setup (each machine)

Each person initializes `~/.pondline` (`pondline` defaults `--state-dir` to
`~/.pondline` or `$PONDLINE_STATE_DIR` when omitted), starts `pondline daemon`,
and waits ~15-30 seconds until `pondline health` reports `tor=bootstrapped`:

```bash
pondline init --stdin               # paste your plg1... token, Enter, Ctrl-D
pondline daemon 2>>~/.pondline/daemon.log &
pondline health                     # wait for tor=bootstrapped
```

### 2. Exchange one `pl1...` ticket to pair

On machine A, mint a ticket for B (`--auto-approve` activates the contact as
soon as B completes the handshake; omit it to approve manually after checking
`peer_fingerprint`). Cold 6-hop onion rendezvous circuits take ~45-120 seconds
on the first dial:

```bash
pondline invite create --description "bob" --budget 50 --auto-approve --ticket
```

Send that `pl1...` string to B over an authenticated channel (Signal, Slack DM,
or SSH). On machine B, redeem it from a `0600` file or `--stdin`:

```bash
umask 077
cat > /tmp/invite.ticket            # paste pl1... line, Enter, Ctrl-D
pondline invite accept --ticket --file /tmp/invite.ticket --description "alice" --budget 50
rm -f /tmp/invite.ticket
```

Wait ~15-45 seconds until `pondline contacts list` shows `active` on both
sides (if A omitted `--auto-approve`, A runs
`pondline contact approve --contact "bob"` once B appears in
`pending_approval`).

### 3. Send, receive, and check end-to-end receipts

Payloads travel over `--stdin` or `--file`, never `argv`, and `--contact`
matches by petname (`"alice"`), unique 4+ character hex prefix, or full hex id.
Agents should pass `--credential-file ~/.pondline/agent.cred`:

```bash
# On B:
printf '%s' 'hello over pondline!' | pondline send \
  --credential-file ~/.pondline/agent.cred \
  --contact "alice" \
  --content-type text/plain \
  --stdin

# On A:
pondline receive --credential-file ~/.pondline/agent.cred --wait 25 --json
pondline ack --credential-file ~/.pondline/agent.cred --message <message_id>

# On B (progresses locally_queued -> stored_by_mailbox -> received_by_peer):
pondline status --credential-file ~/.pondline/agent.cred --message <message_id> --json
```

## Trying it on one machine (loopback)

The loopback carrier runs everything locally without Tor. Start a mailbox server first:

```bash
pondline-mailbox serve --db /tmp/rw/mb.db
```

It prints `listening 127.0.0.1:<port>`. Mint a `plg1...` grant token for each daemon while the server stays running, and initialize each state directory:

```bash
pondline-mailbox grant --db /tmp/rw/mb.db --queues 100 --mailbox 127.0.0.1:<port> --token \
  | pondline init --state-dir /tmp/rw/A --carrier loopback --stdin
pondline-mailbox grant --db /tmp/rw/mb.db --queues 100 --mailbox 127.0.0.1:<port> --token \
  | pondline init --state-dir /tmp/rw/B --carrier loopback --stdin
```

Start each daemon in its own terminal:

```bash
pondline daemon --state-dir /tmp/rw/A
```

```bash
pondline daemon --state-dir /tmp/rw/B
```

A invites, B accepts, A approves:

```bash
pondline invite create --state-dir /tmp/rw/A --description "agent B" --budget 10 --ticket > /tmp/rw/a.ticket
pondline invite accept --state-dir /tmp/rw/B --ticket --stdin --description "agent A" --budget 10 < /tmp/rw/a.ticket
pondline contact approve --state-dir /tmp/rw/A --contact "agent B"
```

Send and receive under `agent.cred`:

```bash
pondline send --state-dir /tmp/rw/B --credential-file /tmp/rw/B/agent.cred --contact "agent A" \
  --content-type application/json --file task.json
pondline receive --state-dir /tmp/rw/A --credential-file /tmp/rw/A/agent.cred --wait 25 --json
pondline-mailbox status --db /tmp/rw/mb.db
```

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
