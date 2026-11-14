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
  migrations, `transaction`, and every SQL statement in the package. The SQL
  text is generated (ADR-007): the migrations are `sql/001_initial.sql`,
  `sql/002_blobs.sql` (ADR-009) and `sql/003_rendezvous.sql` (ADR-016),
  which `dev/embed_schema.gleam` embeds in
  `mailbox/schema` (`version`, `migrations`), and the statements are named
  queries in `src/mailbox/sql/*.sql` (`grants`, `queues`, `envelopes`,
  `blobs`, `rendezvous`), which parrot generates into `mailbox/sql`. The store's `query`, `write` and `bind`
  bridge binds the generated parameters as sqlight values; only the pragmas,
  the transaction statements and the migration runner are hand-written.
  After editing any `.sql` file run `make gen-sql` (needs `sqlite3`, and the
  network once for sqlc) and commit the regenerated modules; `.sql` files
  are ASCII only.
- `mailbox/service`: `handle(store, now, request) -> Response`, `sweep`,
  and `create_grant(store, allowance, random)`, which returns the
  provisioning capability once and stores only its hash. `PutBlob` and
  `GetBlob` (ADR-009) store and return a ticket's sealed invitation.
  `serve(store, now, random, request) -> Served(response, wakes)` is the
  full form: `random` draws a rendezvous nameplate, and `wakes` lists the
  notifier keys the commit owes. `handle` is `serve` over
  `primitives.random_bytes` with the wakes dropped. `rendezvous_wake(read)`
  is the key a `RendezvousFetch` waits under, the SHA-256 of its read
  capability. `nameplate_draws` (32) bounds the nameplate draw.
- The rendezvous slot (ADR-016), end to end. `003_rendezvous.sql` adds
  `rendezvous` (identifier, unique nameplate, grant hash, the opener's
  read and append hashes, the claimant's pair, NULL until claimed, the
  clamped lifetime and `expires_at`) and `rendezvous_messages` (keyed by
  slot, side 0 opener or 1 claimant, and index, with the body's SHA-256
  and the body, deleted with the slot by cascade). In `mailbox/store`, a
  slot is a `RendezvousRecord` with a `Claim` (`Unclaimed` or
  `Claimed(read_hash, append_hash)`) and a `Side` (`Opener`, `Claimant`);
  `live_rendezvous` and `live_rendezvous_at` (by nameplate) are the only
  ways a request reads a slot, both blind to an expired one;
  `rendezvous_counts` returns the grant's and the mailbox's live slots,
  `nameplate_taken` checks a drawn nameplate, `rendezvous_message_digest`
  and `rendezvous_messages` read a side's messages, and `purge_expired_rendezvous`,
  `put_rendezvous`, `claim_rendezvous`, `put_rendezvous_message` and
  `delete_rendezvous` are the writes. `SweepReport` gained `rendezvous`,
  the count of expired slots the sweep deleted.
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
  bounded body read and one `info` line per request (`telemetry/log`,
  `component=http event=request method= status= response= elapsed_ms=`).
- `mailbox` (`gleam run -m mailbox -- ...`): `main`, `parse` and three subcommands: `serve --db <path> [--port <n>] [--tor-state <dir> [--tor-bin <path>]]` (`--port` defaults to 0; with `--tor-state` it resolves `pondline-tor` via `--tor-bin`, `PONDLINE_TOR_BIN`, `PATH` or checkout build, hosts the onion service, writes `<dir>/onion` with mode 0600, and prints `onion <host>.onion:80`), `grant --db <path> --queues <n> [--out <file>] [--token (--mailbox <host:port> | --tor-state <dir>)]` (writes a 0600 capability file, prints a `plg1...` token on stdout, or both; ADR-015), and `status --db <path> [--tor-state <dir>] [--json]` (single-transaction aggregate counts and byte totals via `store.status`). `--version` prints the build's identity (`mailbox/build`).
- `mailbox/internal/ffi_system`: the wall clock, a monotonic clock for
  durations, exclusive and atomic 0600 file writes, checked fd-1 stdout, executable lookup, the environment and `halt`
  (`src/mailbox_ffi.erl`).
- `mailbox/node`: the `rest_for_one` supervisor, `Names`, `Node`, and
  `handle`, which also performs the long poll in the caller's own process,
  for `Fetch` and `RendezvousFetch` alike: a queue's fetch waits under
  the queue identifier, a rendezvous fetch under `rendezvous_wake(read)`,
  and `is_empty` decides which answers are worth waiting past.

## Relationships

Depends on `core` (protocol, ids, capabilities, envelopes, limits, time),
`primitives` (`sha256`, `constant_time_equal`) and `telemetry` (logging,
ADR-012), plus `sqlight` (esqlite,
Apache-2.0), `gleam_otp` and `gleam_erlang`, `weft` (the sibling checkout
as a path dependency while its run timer source is unreleased), `mist` 6.0.3 (with `glisten`, Apache-2.0),
`gleam_http` 4.5.0, `argv` 1.1.0 and `simplifile` 2.7.0. and `tor` (only to host the
onion service; the sidecar forwards every stream on any virtual port to the
loopback port, so 80 is just the conventional value the daemon dials).
Dev: `parrot` generates `mailbox/sql` under `make gen-sql`, which imports
the trimmed copy of its runtime in `mailbox/internal/sql_param` instead
(ADR-007, addendum). Nothing depends on it as a library.

## Traffic

- Client to server: `POST /v1/mailbox`, body a TLV `Request`
  (`application/vnd.pondline.mailbox+tlv`, `Content-Length` required). Every
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
- Coordinator to notifier: a `Notify` for each key in `Served.wakes`,
  following the commit and preceding the reply: the queue identifier after
  an `Appended` (16 bytes), and after a rendezvous send or close the read
  hash of each side that reads it (32 bytes). The lengths differ, so a
  queue key never wakes a rendezvous waiter or the reverse.
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
- A sealed invitation (ADR-009) is stored only by its queue's admin
  capability, charged to that queue's quota in the inserting transaction,
  kept with the hash of its retrieve capability, bounded by
  `limits.max_ticket_blob_bytes` and a deadline inside the envelope
  retention window. A taken locator answers first: identical is
  `BlobStored`, anything else `Conflict`. `GetBlob` never deletes; a
  missing, expired or wrongly authorized blob is `Unauthorized` alike. The
  sweep removes expired blobs and returns their bytes; a queue's deletion
  cascades to its blobs (`test/mailbox/blob_test.gleam`).
- A rendezvous slot (ADR-016) holds hashes and opaque bodies only: the
  four capabilities as SHA-256, the grant's hash, the nameplate, the
  expiry and each body with its digest. It never holds the code's words,
  a key or an identity, and nothing it stores is charged to a queue's
  quota (the sweep deletes slots with no accounting).
- An open needs a provisioning grant and spends no queue allowance; it is
  refused `QuotaExceeded` when the grant holds `max_grant_rendezvous` live
  slots or the mailbox `max_live_rendezvous`, the grant's cap checked
  first. The mailbox-wide cap is what keeps a blind claim's hit rate at
  most one in a thousand. The requested lifetime is clamped to 1 to
  `rendezvous_seconds`. The identical open (same grant, same two hashes,
  same clamped lifetime) answers the slot's nameplate and current
  expiry; anything else under the identifier is `Conflict`.
- Every open first purges expired slots, inside its transaction, so an
  expired slot holds neither a nameplate nor its identifier. The
  nameplate is drawn by rejection from four random bytes, uniform over
  the free six-digit values; after `nameplate_draws` failed tries the open
  is `Unavailable` and writes nothing. The unique index is a second guard.
- The first claim stands. Claiming binds the claimant's pair, refused if
  either equals an opener capability, and shortens the expiry to the
  earlier of the current one and claim plus `rendezvous_claimed_seconds`.
  The identical claim answers the same; the `ClaimRendezvous` statement
  only updates a slot whose claimant is NULL, behind the service's check.
- The mailbox tells the sides apart only by which stored hash a presented
  capability matches, in constant time (`side_of`). A send is filed under
  its sender's side, and a fetch returns only the other side's messages
  past `after`, in index order. A missing slot, an expired one, a
  different claim on a claimed slot, a repeated close and a capability of
  neither side are all the same `Unauthorized`.
- A send is checked for authority first, then size (`TooLarge` above
  `max_rendezvous_body_bytes`), then index (`QuotaExceeded` outside 0 to
  `max_rendezvous_messages - 1`). The same bytes at a filed index answer
  `RendezvousSent` again and wake the reader again; different bytes are
  `Conflict` and never replace the first. The opener may send before the
  claim; that send wakes nobody, and the claimant finds it on its first
  fetch. A close wakes both sides' waiting fetches, which then find the
  slot gone.
- An expired slot is invisible from the instant of expiry, before the
  sweep runs: every query that serves a request filters on
  `expires_at >= now`, so a slot is live at its expiry second and the
  sweep spares it then.
- Nameplate randomness is injectable in `service.serve` but not through
  `node.Config`: the coordinator always passes `primitives.random_bytes`.
  A simulation that opened a rendezvous would draw from the system source.
- `mailbox/schema` and `mailbox/sql` are generated and never edited by hand,
  and a migration file that has shipped never changes: a schema change is a
  new `sql/NNN_*.sql`. `test/mailbox/sql_drift_test.gleam` checks offline
  that the embedded migrations equal the files and that `mailbox/sql` holds
  every query file's statement as sqlc emits it, with no `Dynamic`
  parameter. It also pins the SHA-256 of
  every shipped migration, so an edited one fails even after a regenerate.
- A long poll registers with the notifier before its last look at the
  database, so an append between the look and the wait is not missed.
- No secret reaches an error, a log or a message. Refusals carry no request
  data. A request logs only method, status, response kind and duration,
  each a typed field (spec §12.4, ADR-012): the method and response kind
  are constructor tags, and the client-chosen path is not logged (a wrong
  one is `response=not_found`). `mailbox.main` installs the `telemetry`
  handler first, for every command, so OTP's reports (a request handler's
  crash included) reach standard error rebuilt from their shape; `grant` never prints the capability, and writes it to a file
  created exclusively and restricted to 0600 before the bytes go in.
- `--tor-bin` requires `--tor-state`, while `--tor-state` alone resolves
  `pondline-tor` automatically. The onion service starts only after the HTTP
  server is listening, the `onion` line follows the `listening` line, a linked
  watcher logs `onion_state` transitions and re-hosts on `SidecarRestarted`,
  and the sidecar is linked to the serving process so it dies with it. The Tor state directory holds the service key and its path
  must be short (a Unix socket lives in it). The service exists before Tor
  can reach it; a client retries (ADR-001). The onion path is tested only
  with `PONDLINE_TOR_NETWORK=1`.
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

- `docs/spec.md` §6.4, §6.5 (append and fetch semantics), §6.2 (the
  rendezvous operations), §8.4, §10.2.
- `docs/adr/016-spoken-pairing-codes.md` (the rendezvous slot and its
  limits).
- `docs/review/2026-10-31-design-review.md` Review B §3.8 (tombstones) and
  §3.10 (SQLite durability, no interactive transactions).
- `docs/gleam-style.md` Part III (actors) and Part IV.
