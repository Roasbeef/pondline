# daemon

## Purpose

The client side of Reedwire: what an agent's machine runs to talk to
mailboxes. It holds the mailbox HTTP client of spec §6.1, a carrier-neutral
transport, and the client daemon's runtime of spec §10.2: the durable store,
the single-writer engine that drives the pure `core` state machines, the
delivery scheduler, the per-queue fetchers, the queue provisioner and the
supervisor tree, behind the in-process `daemon/api`. It owns the effects that
`core` may not: sockets, SQLite, the wall and monotonic clocks, and
processes.

## Key Types

- `daemon/transport`: `Connection` (three functions over one open byte
  stream: `send`, `receive`, `close`), `Dialer` (the daemon's
  `CarrierPolicy` plus an injected `dial_onion`), `dial`, and
  `TransportError`. The loopback carrier is a `mug` TCP socket to
  `127.0.0.1`.
- `daemon/mailbox_client`: `call(dialer, endpoint, isolation_group, request,
  timeout_ms) -> Result(Response, ClientError)`, `effective_timeout` (a
  long-poll `Fetch` gets its wait plus `long_poll_margin_ms`), and
  `ClientError`.
- `daemon/internal/ffi_clock`: the one monotonic clock read, used for call
  deadlines.

## Relationships

Depends on `core` (the state machines, codec, typed protocol, snapshots,
endpoints and limits), `primitives` (the real `Suite`), `tor` (the sidecar and
onion streams, wrapped as a `transport.Connection` only in `daemon/carrier`),
`sqlight`, `simplifile`, `gleam_json` (the local API), `gleam_stdlib`,
`gleam_erlang`, `gleam_otp` and `mug` (loopback TCP). Dev: `glisten` runs the
test fake server and `mailbox` runs a real mailbox node in the end-to-end
tests. `transport` itself still takes the onion carrier as a function.

## Traffic

Outbound only. One `call` opens one connection, writes one `POST
/v1/mailbox` (`Connection: close`), reads one response and closes. No
process is spawned and no message is sent; the call blocks its caller up to
the deadline. The isolation group passed to the onion dialer is the queue id
in hex, one circuit group per queue.

## Invariants

- `dial` checks `endpoint.admit` against the policy before doing anything,
  so a loopback endpoint under `TorOnly` opens no socket
  (`test/daemon/mailbox_client_test.gleam`, `transport_test.gleam`).
- The client never follows a redirect, never reads a proxy setting and
  reaches the network only through its `Dialer`.
- One deadline covers the dial, the send and every read; each read gets only
  the time that remains. The connection closes on every path.
- A `ClientError` holds a status code or a typed parse or codec error, never
  a capability, a ciphertext or peer bytes.
- No retries here; the delivery scheduler owns retry policy.
- Known gaps: one connection per call (no keep-alive pool); the loopback
  carrier cannot bound a single read by `max_bytes` (the HTTP parser's bounds
  are the limit); a send has no deadline of its own.

## Runtime

The daemon's processes and the store they share (spec §8, §10.2, §12). Read
this before changing any of them.

- `daemon/store`: the one SQLite file (WAL, `synchronous=FULL`, `fullfsync`,
  `user_version` migrations, a newer schema refused) and every SQL string.
  `commit(store, now, Commit)` writes a whole `Plan` (state blob with a
  version check, every record, the `Processed` row) in one `BEGIN IMMEDIATE`
  transaction and returns `Committed`, which only this module can build and
  which is the only source of effects. Tables: `relationships`, `offers`,
  `outbox`, `processed`, `deliveries`, `sent_messages`, `audit`, `meta`.
- `daemon/engine`: the single writer. One `weft/actor` holds the connection and
  runs each operation as a job: load state, run the pure transition with the
  real `Suite` and injected clock, commit, then call `notify`. It never touches
  the network. `process` applies the id-and-digest rule before opening a
  frame. The store opens in the initialiser, not a `continuing` message, so a
  database that cannot open fails the start; it traps exits and `on_shutdown`
  closes the store.
- `daemon/scheduler`: a `weft/actor` that sends committed `queued` outbox
  rows, resending the same padded bytes. Each dispatch is one `weft` run
  (`send_batch`), `limit` `max_in_flight`, `deadline` `send_deadline_ms`,
  relayed to the actor so it never blocks; every run has its own subject and
  the selector is rebuilt from the table of running batches, so an outcome
  that carries only an index finds its row. All seven `Outcome` variants are
  written out: crashed, abandoned and failed sends are retried with backoff,
  `NeverStarted` leaves the row queued. A row claims its envelope in
  `in_flight` with a `Claim` that names its owner (`Sending` the run's
  subject, `Expiring`, or `Held`): a run's end marker releases only its own
  `Sending` claims, and a row whose outcome the engine could not record is
  `Held` until the next tick instead of being resent at once. The rescan is `actor.periodic`
  (`tick_ms`) plus a first tick via `continuing`; the engine has no soonest
  `next_attempt_at` query, so a computed named timeout is not possible yet.
  `classify` and `backoff_seconds` are the pure policy.
- `daemon/fetcher` (one process per live queue): a `weft/state_machine`,
  states `Acking`, `Polling`, `BackingOff`. Each network step is a one-task
  relayed run with a deadline (`ack_deadline_ms`, `poll_deadline_ms`) pushing
  to its own subject (`Acked`, `Polled`); a failure enters `BackingOff` with a
  state timeout of `backoff_ms(failures)` that sends `Begin`, and the failure
  count lives in the data. A round starts by checking liveness and ends the
  machine if the queue is retired. Each round acknowledges exactly the
  store's committed-and-unacknowledged envelopes, then long-polls.
  `daemon/fetch_manager` is a `weft/actor` (`continuing` first reconcile,
  `periodic` tick) that starts a linked fetcher per live queue and retires
  expired offers.
- `daemon/provisioner`: a one-state `weft/state_machine` (`Watching`) because
  the next scan's delay is computed (`delay_ms(failures)`), which needs the
  named `scan` timeout, re-armed in the one `Tick` arm; a `Nudge` scans
  without touching it. `CreateQueue` for inboxes already committed, then
  `engine.provisioned`; the first scan runs via `continuing`.
- `daemon/carrier`: a `weft/state_machine` (`Unused`, `Bootstrapping`,
  `Bootstrapped`, `Unavailable`) that owns the Tor handle, runs the bootstrap
  as a relayed one-task run bounded by `bootstrap_deadline_ms`, reports each
  decision to the status cell, and drops end markers after it settles. It
  subscribes to the sidecar's events: `SidecarRestarted` (the replacement is
  not bootstrapped) starts a new run and returns to `Bootstrapping` from any
  state with a sidecar, `SidecarGaveUp` settles `Unavailable`. The
  onion `Dialer` asks it for the handle on every dial.
- `daemon/node`: the `rest_for_one` tree (`lock`, `status`, `events`,
  `carrier`, `engine`, `scheduler`, `provisioner`, `fetch_manager`), the
  directory preparation and `route_notice`, the only engine-to-worker wiring.
  `start_offline` omits the three network workers. `stop` kills the tree and
  waits for the lock with `weft/poll`.
- `daemon/api`: the contract the local API codes against (`invite`, `accept`,
  `contacts`, `approve`, `decline`, `close`, `raise_budget`, `send`, `receive`,
  `acknowledge`, `status`, `audit`, `subscribe`, `health`). `invite` waits for
  its queue with `weft/poll` (a durable row landing, probed every
  `invite_poll_ms` for at most `invite_wait_ms`).
- `daemon/lock`: the exclusive SQLite lock held by a trapping `weft/actor`
  whose `on_shutdown` closes the connection. `daemon/status` (the Tor and
  mailbox cell) and `daemon/events` (the subscriber list) are plain
  `weft/actor`s: the subscribers are all alike and hold no state, so the
  list stays a list and is not a `weft/event_manager`.
- `daemon/mail` (soft `tell` and `ask` to named actors, through a `Handle`
  that carries the `Name` and, in a simulation only, an interceptor) stays
  hand-written because weft has no monitored, non-panicking call against a
  pre-existing pid. Known weft gap.
- `daemon/config`, `daemon/log` and `daemon/internal/ffi_runtime_clock`.

Traffic: the engine tells the shell through `notify` after each commit
(`Transmit` to the scheduler, `CreateQueue` to the provisioner, a topology
change to the fetch manager, `WakeAdapter` and relationship changes to the
event registry). Every nudge is advisory, since each worker also scans on a
timer. Workers read committed rows back through the engine.

Invariants:

- No send before commit: the scheduler's bytes come only from `store.due`.
  No acknowledgement before commit: a fetcher acknowledges only
  `store.unacked`. Both are checked by tests that make the commit fail by
  holding the database's write lock from outside
  (`test/daemon/recovery_test.gleam`), and by mutation: sending from the plan,
  or acknowledging from the fetched batch, fails them.
- Timeouts and retries are mutation-tested by `test/daemon/workers_test.gleam`:
  removing the scheduler run's `deadline` or `limit`, the scheduler's
  `periodic`, the fetcher's backoff state timeout or run deadline, the
  provisioner's named timeout, or the carrier's run deadline each fails a
  named test there. The fetch manager's `periodic` is not covered (it is the
  backstop for a lost nudge and offer expiry), nor is
  `node.wait_for_lock`'s `Retry` arm (a backstop: the lock's `on_shutdown`
  frees it before `node.start` probes it, so no test sees the first attempt
  fail). The fetcher's two run deadlines are covered by the hanging poll and
  hanging acknowledgement tests, and the carrier's restart handling by the
  restart tests there. The scheduler's `Held` pacing and per-run claims have
  no test: the store's 5 s busy timeout makes a failing record slow rather
  than hot, so a test cannot tell a resend per tick from a resend per
  message, and the stale end marker needs a failed record, a resend into a
  newer run and an old marker in one interleaving; both are argued in the
  code's comments.
- An envelope is a repeat only if its identifier and its digest both match
  its `Processed` row; anything else goes through the core.
- A restart resumes committed state: an unsent outbox row is sent on start,
  and an envelope committed but unacknowledged is acknowledged by the next
  fetcher round, with no second delivery to the agent.
- One daemon per state directory: `lock.db` holds an exclusive SQLite
  transaction, released by the OS when the process dies. The directory is
  `0700`, the database and lock `0600`.
- No log line carries a value: `daemon/log` is given fixed phrases, and
  `test/daemon/secrets_test.gleam` searches a whole exchange's stderr for
  capabilities, the invitation and the payload.
- Known gaps: nothing in the state directory is encrypted (permissions only);
  `invite` waits at most `api.invite_wait_ms` for the queue and a timed-out
  offer opens later unexported; a supervisor that fails to start takes its
  starter with it, so `node.start` probes the lock, the database and the Tor
  binary first; the TorOnly path with the real sidecar is behind
  `REEDWIRE_TOR_NETWORK=1` and is not run by default; no queue rotation at
  accept; no metrics.

## Simulation seams

Nil-by-default hooks a deterministic simulation (`docs/dst/plan.md`) uses to
run the real tree. `config.new` sets every one to production, and no `src`
module builds anything else: a `timer.Injected`, a fault hook, a dialer
override, a database override or an interceptor is constructed only under
`test/`. `test/daemon/seams_test.gleam` runs an exchange with every seam
written out at its default and checks each set seam reaches its boundary.

- **Timers** (`Config.timer`, default `timer.WallClock`): threaded by
  `node.launch` into `scheduler` and `fetch_manager`
  (`actor.with_timer_source`), `fetcher`, `provisioner` and `carrier`
  (`sm.with_timer_source`), and into every weft run deadline:
  `scheduler.send_batch`, `fetcher.start_run` and the carrier's bootstrap
  `run` (`weft.with_timer_source`, from the sibling weft checkout).
  `carrier.start_with_bootstrap` (tests only) stays on the wall clock.
- **Poll clock** (`Config.poll_clock`, default `poll.monotonic()`): kept in
  `api.Daemon`; `api.await_file` (invite) and `node.wait_for_lock` (stop)
  use `poll.until_on`.
- **Network** (`Config.dialer`, default `None` = `carrier.dialer`).
- **Database** (`Config.database`, default `None` = `daemon.db` in the state
  directory, created `0600`). An override, such as a shared-cache in-memory
  URI, is opened as given; `lock.db` stays a file.
- **Store faults** (`Config.store_faults`, `store.open_with`): consulted once
  per `store.transaction` after the migrations. `Down` fails before
  `BEGIN`, `AckLost` commits and then fails; both return an `Ioerr`.
- **Engine faults** (`Config.engine_faults: Option(fn(JobKind) -> JobFate)`):
  every engine job carries a `JobKind`; `handle` asks the hook and `run`
  applies the fate: `FailBeforeApply` answers `Unavailable` unrun,
  `ApplyThenFail` runs the job (commit and notices) and answers
  `Unavailable`.
- **Mail interception** (`Config.interceptor`): every cross-actor `tell` and
  `ask` (`engine`, `status`, `events`, `scheduler`, `provisioner`,
  `fetch_manager`, `carrier.GetTor`) goes through a `mail.Handle`. Without an
  interceptor it is a direct send, no extra hop. With one, the send becomes a
  `Parcel(from, to, label, deliver)` handed to the runner; `from` and `to` are
  roles (`fetcher/<queue hex>` per fetcher), `label` a fixed word (the
  engine's `kind_label`). Not intercepted: ask replies, self-sends, weft
  timers and run outcomes, the event registry's fan-out to subscribers, Tor
  port events, exits and monitors, and the network (the dialer's seam).
- **Randomness**: every id and capability draw in the runtime goes through
  `config.suite`; `credential` (the local API front door) uses
  `primitives.random_bytes` and is outside the simulated tree.

## Local API and CLI

The daemon's front door (spec §9): a Unix socket for an agent adapter and
the operator, and the `reedwire` command that speaks to it.

- `daemon/credential`: two scopes, `Operator` and `Agent`. At start,
  `ensure` creates `operator.cred` and `agent.cred` in the 0700 state dir
  (32 random bytes, exclusive create, mode 0600) and reads them back on a
  restart. `authenticate` compares in constant time and runs both
  comparisons; `permits` is the scope order. The agent file is what an
  operator copies into an agent's sandbox.
- `daemon/local_api_protocol`: the wire format, shared by server and client.
  Newline-delimited JSON, `{"v":1,"credential":b64,"op":...,"args":{...}}`
  answered by `{"ok":true,"result":...}` or `{"ok":false,"error":{"category",
  "message"}}`. Categories: `unauthorized`, `forbidden`, `not_found`,
  `invalid`, `refused`, `unavailable`, `too_large`. Bounds: `max_line_bytes`
  (256 KiB), `max_receive`, `max_wait_ms`.
- `daemon/local_api`: the server over `<state_dir>/api.sock` (mode 0600).
  One process per connection; one wake hub (`weft/actor`) holds the single
  runtime subscription and wakes waiting `receive` calls. A waiting `receive`
  is `weft/poll` on a clock whose rest is a wait on the hub's wake. The
  acceptor (blocked in `accept`) and the connection processes (an idle read
  timeout on the socket) stay plain `spawn_unlinked`: neither is a task with a
  deadline over its total time. It serves a `Backend` record
  (`daemon/local_api_types`), never the runtime directly.
- `daemon/local_api_backend`: the only module that maps the runtime's
  `daemon/api` onto `Backend` (`from_daemon`), and `start_node`, which turns
  the CLI's options into a runtime `Config` (`127.0.0.1:PORT` is a loopback
  mailbox, anything else must be an onion) and starts the node. Reconcile
  runtime API changes here.
- `daemon/local_api_client`: one request over the socket; used by the CLI
  and the tests.
- `daemon/cli` (pure parse and request building, exit codes), `cli_render`
  (human output), `cli_run` (effects), and the top-level `reedwire` module
  (`gleam run -m reedwire -- <command>`).
- `daemon/internal/ffi_local_socket` and `ffi_local_system` over
  `src/daemon_local_ffi.erl`: Unix sockets, the monotonic clock, private
  files and directories, raw stdout and stdin, the environment.

Invariants:

- Order of checks in `handle`: parse, version, credential, operation, scope,
  arguments, backend. A forbidden operation never has its arguments read and
  never reaches the backend.
- The agent scope may do contacts, send, receive, acknowledge, status and
  health only. Invite, accept, approve, decline, close, raise_budget and
  audit are operator-only (`required_scope`).
- A credential is a `Secret`, appears in no log or error text, and never in
  argv: the CLI reads it from `--credential-file`, `REEDWIRE_CREDENTIAL_FILE`
  or `<state-dir>/operator.cred`. A payload comes from `--file` or `--stdin`
  only. No option named for either exists, which `cli_test` checks for every
  command.
- Line framing is `recv_line` in the shim, not `{packet, line}`, because the
  built-in mode truncates a long line instead of refusing it. A line over
  `max_line_bytes` gets `too_large` and the connection closes.
- `receive` registers with the hub before its first read, so a wake between
  the read and the wait is not lost. One response is capped near 128 KiB of
  payload; the rest stays for the next call.
- `invite create` writes the invitation to its `--out` file (0600, refuses
  to overwrite, checked before the daemon is asked) and prints only the path.
- Exit codes: 0 ok, 1 local failure, 2 usage, 3 unauthorized or forbidden,
  4 not found, 5 refused, invalid or too large, 6 unavailable.
- Known gaps: a connection process that crashes leaves its socket open until the
  acceptor exits; a Unix socket path is limited to about 100 bytes, so a
  long state dir fails at `listen`.

## Deep Docs

- `docs/spec.md` §6.1 (transport), §6.2, §13.1 (no silent downgrade).
- `packages/core/src/core/http1.gleam` (framing and bounds) and
  `core/mailbox/codec.gleam` (the body).
