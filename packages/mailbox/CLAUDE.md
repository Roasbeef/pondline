# mailbox

## Purpose

The mailbox service's durable store and request handling (`docs/spec.md`
§6, §8.4, §10.2). It serves the typed commands of
`core/mailbox/protocol` against one SQLite file and runs the few processes
a mailbox node needs. Its HTTP binding and command line are thin: the
binding decodes a TLV body into a `Request`, calls `node.handle` and encodes
the `Response`. Time arrives as an `Instant` and randomness as a function, so
the rules are plain functions of a `Store` that tests call without a
process.

## Key Types

- `mailbox/store`: `Store`, the schema, the pragmas (WAL, `synchronous=FULL`,
  `fullfsync=ON`, `foreign_keys=ON`, a busy timeout), `PRAGMA user_version`
  migrations, `transaction`, and every SQL statement in the package.
- `mailbox/service`: `handle(store, now, request) -> Response`, `sweep`,
  and `create_grant(store, allowance, random)`, which returns the
  provisioning capability once and stores only its hash.
- `mailbox/coordinator`: the storage coordinator, a `weft/actor`, the one
  writer. It receives complete commands and tells the notifier after an
  append commits. It opens the store in its initialiser so a bad file fails
  the start. Callers reach it through `mailbox/mail`'s `ask` on a `Handle`
  over its `Name` (fail soft); that is the monitored, non-panicking call
  against a pre-existing pid that weft does not have, so it is not a
  `weft/registry` address.
- `mailbox/mail`: `Handle`, `tell`, `ask`, and the simulation's interception
  seam (`Interceptor`, `Parcel`), the same shape as `daemon/mail`.
- `mailbox/notifier`: the queue notification registry (queue to waiting
  callers), a `weft/actor` addressed by `Name`. A homogeneous subject table
  with no per-waiter state stays an actor, not a state machine.
- `mailbox/sweeper`: a `weft/actor` whose `periodic` tick (a fixed delay,
  armed once in the builder) asks the coordinator to sweep.
- `mailbox/http`: `start(node, Config(interface, port))` returns a `Server`
  with the bound port (port 0 is ephemeral); the mist handler, routing,
  bounded body read and one log line per request.
- `mailbox` (`gleam run -m mailbox -- ...`): `main`, `parse` and the two
  subcommands, `serve --db <path> --port <n> [--tor-bin <path> --tor-state
  <dir>]` (prints `listening 127.0.0.1:<port>`; with the Tor options it then
  starts the sidecar, bootstraps, hosts an onion service named `mailbox`
  that forwards to that port, and prints `onion <host>.onion:80`, the
  address a daemon dials; runs until stopped) and `grant --db <path> --queues <n> --out <file>` (writes
  the 32-byte provisioning capability to a new 0600 file, prints the path
  only, never overwrites). Bad arguments print one line and exit 1.
- `mailbox/internal/ffi_system`: the wall clock, a monotonic clock for
  durations, an exclusive 0600 file create, and `halt` (`src/mailbox_ffi.erl`).
- `mailbox/node`: the `rest_for_one` supervisor, `Names`, `Node`, and
  `handle`, which also performs the long poll in the caller's own process.

## Relationships

Depends on `core` (protocol, ids, capabilities, envelopes, limits, time)
and `primitives` (`sha256`, `constant_time_equal`), plus `sqlight` (esqlite,
Apache-2.0), `gleam_otp` and `gleam_erlang`, `weft` (the sibling checkout
as a path dependency while its run timer source is unreleased), `mist` 6.0.3 (with `glisten`, Apache-2.0),
`gleam_http` 4.5.0, `argv` 1.1.0 and `simplifile` 2.7.0. and `tor` (only to host the
onion service; the sidecar forwards every stream on any virtual port to the
loopback port, so 80 is just the conventional value the daemon dials).
Nothing depends on it as a library.

## Traffic

- Client to server: `POST /v1/mailbox`, body a TLV `Request`
  (`application/vnd.reedwire.mailbox+tlv`, `Content-Length` required). Every
  protocol outcome, refusals included, is `200` with a TLV `Response`; an
  undecodable body is `Refused(Malformed | UnsupportedVersion | TooLarge)`.
  HTTP statuses are only for the transport: `413` when `Content-Length`
  exceeds `codec.max_request_bytes()` (nothing is read), `404` other path,
  `405` other method (with `Allow: POST`), `400` unframeable (no or invalid
  `Content-Length`, or a transfer coding). Every response has
  `Connection: close`. Each connection is its own process, so a long-poll
  `Fetch` blocks only itself.

- Request process to coordinator: `Handle(now, request, reply_with)`,
  `Sweep` and `CreateGrant`, answered on a per-call subject. The call fails
  soft: no coordinator or no reply in time is `Refused(Unavailable)`.
- Coordinator to notifier: `Notify(queue)` after an `Appended` response,
  following the commit.
- Long-polling caller to notifier: `Wait`, then a synchronous `Forget`, so no
  wake-up can reach the caller after cleanup.
- Sweeper to coordinator: a `Sweep` every `sweep_period_ms`, from the
  actor's `periodic` tick.

## Invariants

- The coordinator is the only process holding a connection, and every
  change is one `store.transaction` run inside one call. No transaction
  spans a message, and no one waits while holding one.
- Capabilities are stored and compared only as SHA-256 hashes, with
  `constant_time_equal`. A missing queue and a wrong capability are both
  `Unauthorized`.
- Quota is reserved and the envelope row inserted in one transaction, and
  the receipt is built after the commit.
- An acknowledged envelope leaves a tombstone (digest and deadline), and an
  append for a known identifier is answered from the stored envelope or the
  tombstone before anything is inserted, so a retry never resurrects it.
- `Ack` deletes exactly the named envelopes; it is never a cursor.
- A long poll registers with the notifier before its last look at the
  database, so an append between the look and the wait is not missed.
- No secret reaches an error, a log or a message. Refusals carry no request
  data. A request logs only method, path, status, response kind and duration
  (spec §12.4); `grant` never prints the capability, and writes it to a file
  created exclusively and restricted to 0600 before the bytes go in.
- The Tor options are given both or neither. The onion service starts only
  after the HTTP server is listening, the `onion` line follows the
  `listening` line, and the sidecar is linked to the serving process, so it
  dies with it. The Tor state directory holds the service key and its path
  must be short (a Unix socket lives in it). The service exists before Tor
  can reach it; a client retries (ADR-001). The onion path is tested only
  with `REEDWIRE_TOR_NETWORK=1`.
- The server binds `127.0.0.1` by default and the binary offers no other
  interface.
- The sweep period is armed only by `actor.periodic`; the handler never
  re-arms it. `node_test` fails if it is removed. The long poll's wait is a
  `process.receive` with a timeout under the wall clock (a message wait, so
  not `weft/poll`), or a select on the wake and an armed deadline under an
  injected timer source, and
  `http.start`'s port report is a message already queued when `mist.start`
  returns, so its timeout is a bound that no test exercises.
- Known gaps: a long poll is not bounded by `long_poll_seconds` (up to three
  `call_timeout_ms` coordinator calls plus the wait, only when the
  coordinator is stuck); no TLS, auth headers, admin API or metrics; no per-connection
  or per-address rate limit and no cap on concurrent connections; no
  per-operation rate limit beyond the byte quota; no
  replication; no revocation or rotation; a `Fetch` and the sweeper share the
  coordinator's single connection, so reads are serialized with writes.

## Simulation seams

Nil-by-default hooks for the deterministic simulation (`docs/dst/plan.md`),
all in `node.Config` and set to production by `mailbox serve`; no `src`
module builds an injected timer, an interceptor or a fault hook.
`test/mailbox/seams_test.gleam` runs an exchange with every seam at its
default and checks each set seam reaches its boundary.

- **Timer** (`timer`, production `timer.WallClock`): the sweeper's
  `periodic` (`actor.with_timer_source`) and the long poll's deadline in
  `node.wait_for_append`, so a simulated 25 s poll costs no wall time.
- **Mail interception** (`interceptor`, production `None`): every call to the
  coordinator (`handle`, `sweep`, `create_grant`) and the notifier (`wait`,
  `forget`, `notify`) goes through a `mail.Handle`; without an interceptor it
  is a direct send. Not intercepted: ask replies, the notifier's wake-ups to
  waiting subjects, weft timers, exits and monitors.
- **Store faults** (`store_faults`, production `None`; `store.open_with`):
  `Down` fails a transaction before `BEGIN`, `AckLost` commits it and then
  fails.
- **Database location**: already `path`, which takes a shared-cache in-memory
  URI.

## Deep Docs

- `docs/spec.md` §6.4, §6.5 (append and fetch semantics), §8.4, §10.2.
- `docs/review/2026-10-31-design-review.md` Review B §3.8 (tombstones) and
  §3.10 (SQLite durability, no interactive transactions).
- `docs/gleam-style.md` Part III (actors) and Part IV.
