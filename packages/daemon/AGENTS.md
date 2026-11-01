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
- `daemon/engine`: the single writer. One actor holds the connection and runs
  each operation as a job: load state, run the pure transition with the real
  `Suite` and injected clock, commit, then call `notify`. It never touches the
  network. `process` applies the id-and-digest rule before opening a frame.
- `daemon/scheduler`: sends committed `queued` outbox rows, one linked task
  per row, resending the same padded bytes; `classify` and `backoff_seconds`
  are the pure policy.
- `daemon/fetcher` (one process per live queue) and `daemon/fetch_manager`
  (starts the fetchers, retires expired offers): each round acknowledges
  exactly the store's committed-and-unacknowledged envelopes, then long-polls.
- `daemon/provisioner`: `CreateQueue` for inboxes already committed, then
  `engine.provisioned`; scans on start, on nudge and on a timer.
- `daemon/carrier`: the Tor sidecar and its bootstrap, and the onion `Dialer`.
- `daemon/node`: the `rest_for_one` tree (`lock`, `status`, `events`,
  `carrier`, `engine`, `scheduler`, `provisioner`, `fetch_manager`), the
  directory preparation and `route_notice`, the only engine-to-worker wiring.
  `start_offline` omits the three network workers. `stop` kills the tree.
- `daemon/api`: the contract the local API codes against (`invite`, `accept`,
  `contacts`, `approve`, `decline`, `close`, `raise_budget`, `send`, `receive`,
  `acknowledge`, `status`, `audit`, `subscribe`, `health`).
- `daemon/config`, `daemon/lock`, `daemon/status`, `daemon/events`,
  `daemon/mail` (soft `tell` and `ask` to named actors), `daemon/log` and
  `daemon/internal/ffi_runtime_clock`.

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
  One process per connection; one wake hub actor holds the single runtime
  subscription and wakes waiting `receive` calls. It serves a `Backend`
  record (`daemon/local_api_types`), never the runtime directly.
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
