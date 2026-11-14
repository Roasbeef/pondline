# daemon

## Purpose

The client side of Pondline: what an agent's machine runs to talk to
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
`telemetry` (logging, ADR-012), `sqlight`, `simplifile`, `gleam_json` (the
local API), `gleam_stdlib`, `gleam_erlang`, `gleam_otp` and `mug` (loopback
TCP). Dev: `parrot` generates `daemon/sql` under `make gen-sql`, which imports
the trimmed copy of its runtime in `daemon/internal/sql_param` instead
(ADR-007, addendum); `glisten` runs the
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
  `user_version` migrations, a newer schema refused) and every statement the
  daemon runs. The SQL text is generated (ADR-007): the migrations are
  `sql/NNN_<name>.sql`, one per schema version, which
  `dev/embed_schema.gleam` embeds in `daemon/schema` (`version`,
  `migrations`); the statements are named queries in `src/daemon/sql/*.sql`
  (`state`, `outbox`, `inbound`, `agent`, `meta`, `incident`, `send_key`,
  `rendezvous`),
  which parrot generates into `daemon/sql`. The store's `query`, `write` and `bind` bridge binds the
  generated parameters as sqlight values; only the pragmas, the transaction
  statements and the migration runner are hand-written. After editing any
  `.sql` file run `make gen-sql` (needs `sqlite3`, and the network once for
  sqlc) and commit the regenerated modules; `.sql` files are ASCII only.
  `commit(store, now, Commit)` writes a whole `Plan` (state blob with a
  version check, every record, the `Processed` row) in one `BEGIN IMMEDIATE`
  transaction and returns `Committed`, which only this module can build and
  which is the only source of effects. Tables: `relationships`, `offers`,
  `outbox`, `processed`, `deliveries`, `sent_messages`, `audit`, `meta`,
  and (schema 2, ADR-006) `fingerprints`, with `outbox.retransmits` and
  `outbox.retransmit_at`. `record_send(store, now, envelope, outcome)` sets
  `retransmit_at` from `retransmit.due_at` when the mailbox stored a row and
  its peer has not receipted it; a `PeerReceived` record clears it.
  `Retransmitted` copies a stored row under a fresh envelope with an
  `INSERT ... SELECT`, so a retransmit's bytes come only from the committed
  row; `RetransmitStopped` ends a schedule. `due_retransmits` and
  `fingerprint` are the readers; a `Remembered` record replaces a
  fingerprint and prunes the expired ones. Schema 3 (ADR-010) adds
  `incidents` (kind, queue, envelope, optional contact, message and
  attempts, time; never a payload), written by a `RepeatedMessage` record
  and by the `Quarantined` commit, and read by `incidents` and
  `incident_count`; `message_history` answers the core's `IdHistory` from
  `deliveries`. Schema 4 adds `attempts(queue, envelope, count)`:
  `count_attempt` increments it in its own transaction and every
  `Processed` row clears it. Schema 5 (ADR-011) adds
  `relationships.invitation` (a joiner's, with a partial unique index;
  `contact_by_invitation`) and `send_keys(contact, key, message_id,
  digest, expires_at)`, written by the `KeyedSend` commit and pruned as each
  key is stored (`send_by_key`). `draining_inboxes` lists retired inboxes
  whose processed rows are not all acknowledged. Schema 6 (ADR-016,
  `sql/006_rendezvous_failures.sql`) adds `rendezvous_failures(seq,
  endpoint, at)` with an index on `(endpoint, at)`: one row per failed
  spoken-code confirmation, keyed by the rendezvous endpoint's text as
  `endpoint.to_string` spells it, and never a code, a word or a message.
  `rendezvous_failures(store, endpoint, now)` counts the rows with `at`
  inside `limits.rendezvous_failure_window_seconds` before `now`;
  `record_rendezvous_failure(store, endpoint, now)` deletes every row past
  the window and inserts the new one in one transaction. It is the only
  rendezvous state the daemon stores.
- `daemon/engine`: the single writer. One `weft/actor` holds the connection and
  runs each operation as a job: load state, run the pure transition with the
  real `Suite` and injected clock, commit, then call `notify`. It never touches
  the network. `process` applies the id-and-digest rule before opening a
  frame (a repeat marks its processed row unacknowledged,
  `store.mark_unacked`), then counts the attempt (`store.count_attempt`, its own
  transaction) and quarantines an envelope past
  `limits.max_process_attempts` (`store.Quarantined`: dropped, acknowledged,
  an incident; ADR-010). It looks a `Ratchet` frame's fingerprint up before
  the session: a known ciphertext goes to `relationship.resend_receipt`,
  never to `receive`. Anything else is `relationship.open`ed, its
  identifier's history read (`store.message_history`), and
  `relationship.receive`d with it; a repeat is ignored and recorded.
  `accept` returns the relationship an invitation already started, and
  `send` takes an optional idempotency key (`KeyedSend`; ADR-011).
  `retransmit` (job `Retransmit`, label `retransmit`) commits a copy of each
  stored row whose receipt window passed, or ends its schedule.
  `rendezvous_failures(name, endpoint)` and
  `record_rendezvous_failure(name, endpoint)` (jobs `RendezvousFailures`
  and `RecordRendezvousFailure`, labels `rendezvous_failures` and
  `record_rendezvous_failure`) run the store's two failure-count calls at
  the engine's clock; the pairing code reaches the count only through
  them.
  The store opens in the initialiser, not a `continuing` message, so a
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
  `Held` until the next tick instead of being resent at once. Every `Tick`
  first asks `engine.retransmit` (ADR-006), so the copies it commits are
  queued rows the same tick's dispatch sends; the window is in the injected
  clock's seconds. The rescan is `actor.periodic`
  (`tick_ms`) plus a first tick via `continuing`; the engine has no soonest
  `next_attempt_at` query, so a computed named timeout is not possible yet.
  `classify` and `backoff_seconds` are the pure policy. A send offers the
  retention deadlines `core/retention.offers` gives for the row at that
  moment (ADR-008): a `BadDeadline` moves to the next, shorter offer in the
  same attempt, and one to the last offer is `Transient`, retried until
  the row's deadline. Nothing about the offers is stored.
- `daemon/fetcher` (one process per live queue): a `weft/state_machine`,
  states `Acking`, `Polling`, `BackingOff`. Each network step is a one-task
  relayed run with a deadline (`ack_deadline_ms`, `poll_deadline_ms`) pushing
  to its own subject (`Acked`, `Polled`); a failure enters `BackingOff` with a
  state timeout of `backoff_ms(failures)` that sends `Begin`, and the failure
  count lives in the data. Each round acknowledges exactly the store's
  committed-and-unacknowledged envelopes first, then checks liveness
  (`after_ack`): a live queue long-polls, a retired one ends the machine
  with nothing committed left unacknowledged. `daemon/fetch_manager` is a
  `weft/actor` (`continuing` first reconcile, `periodic` tick) that starts a
  linked fetcher per live queue, and per retired queue that still owes
  acknowledgements (`engine.draining_inboxes`, the restart case), and
  retires expired offers.
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
  `carrier`, `engine`, `scheduler`, `provisioner`, `fetch_manager`,
  `pairing`), the directory preparation and `route_notice`, the only
  engine-to-worker wiring. `start_offline` omits the three network workers
  and keeps `pairing`, whose code calls then fail at the mailbox.
  `pairing` is last, so its restart touches nothing else, but a crash of
  any child before it restarts it too. `launch` builds the `api.Rendezvous`
  from the configured mailbox endpoint, the provisioning capability and
  the engine's wall clock. `stop` kills the tree and waits for the lock
  with `weft/poll`.
- `daemon/api`: the contract the local API codes against (`invite`, `accept`,
  `contacts`, `approve`, `decline`, `close`, `raise_budget`, `send`,
  `send_with_key`, `receive`, `acknowledge`, `status`, `audit`, `incidents`,
  `subscribe`, `health`, and ADR-016's `invite_code`, `await_code` and
  `accept_code`; health counts incidents). `invite` waits for
  its queue with `weft/poll` (a durable row landing, probed every
  `invite_poll_ms` for at most `invite_wait_ms`). `invite_ticket` and
  `accept_ticket` (ADR-009) are the only calls that reach a mailbox
  themselves, in the caller's process, through the tree's dialer, which
  `api.Daemon` carries: the inviter stores the sealed invitation with
  `PutBlob` (paid for by the offer queue's admin capability) and returns
  the ticket only after `BlobStored`; the joiner admits the ticket's
  endpoint under the carrier policy, fetches with `GetBlob`, opens (AEAD,
  then commitment), checks the invitation names the ticket's mailbox, and
  then calls `accept`. Each call is retried with `weft/poll` for at most
  `ticket_wait_ms` on the poll clock; neither writes durable state of its
  own. The spoken-code calls (ADR-016) reach a mailbox from the caller's
  process too. `invite_code(daemon, description, approval, budget) ->
  CodeInvite(run, code, expires_at)` checks the failure count at the
  daemon's own mailbox (refused past the cap, before anything is minted),
  runs `invite_ticket` whole, so the ticket's blob is `BlobStored` before
  a slot exists, draws a fresh `Id(Rendezvous)` and two capabilities,
  opens the slot (`open_slot`, `OpenRendezvous` with
  `limits.rendezvous_seconds` under `Rendezvous.provision`), builds the
  code from the nameplate the mailbox drew, and hands
  `pairing.run_inviter` to the registry with a deadline of the slot's
  lifetime plus `pairing.run_slack_ms`; every failure after the open
  closes the slot first (`or_close_slot`). The code is a `Secret`.
  `await_code(daemon, run)` waits up to `code_wait_ms` (700 s) for the
  registry's answer: `Paired(contact: None)` or the ending, `NotFound` for
  a run the registry does not know (never started here, a restart since,
  or kept past `pairing.keep_ms`), `Unavailable` for no answer.
  `accept_code(daemon, code, rendezvous, description, budget)` decodes the
  code strictly (an error names a word's position, never a word), parses
  `rendezvous` (`HOST:PORT`, else the daemon's own mailbox) and admits it
  under the carrier policy, waits for Tor as a ticket does, checks the
  count at that endpoint, claims the slot (`claim_slot`; a refused claim
  is a plain `Refused` and counts nothing), runs `pairing.run_joiner` in
  the caller's process, and redeems the delivered ticket with
  `accept_ticket_with_budget`, answering `Paired(contact: Some(_))`.
  `PairingOutcome` is `Paired(contact)`, `NeverClaimed`, `Stalled` or
  `ConfirmationFailed`. Opens and claims are retried as a ticket's calls
  are (`rendezvous_call`: `ticket_wait_ms`, `ticket_retry_ms`,
  `ticket_call_ms`). A run's lifetime is the remainder of the slot by the
  mailbox's `expires_at` read against `Rendezvous.clock`, used only when it
  lies between 1 s and the cap (600 s inviting, 120 s joining) and the cap
  otherwise, since the two clocks may disagree. `Rendezvous(mailbox,
  provision, clock)` is what `node` passes in for these calls.
- `daemon/pairing` (ADR-016): the two run drivers and the registry that
  owns an inviter's run. A `Link(call, clock)` is one rendezvous call
  with a budget and the poll clock every wait uses; `api` builds it over
  the daemon's dialer, one onion circuit group per run, and a test over a
  fake mailbox. A `Slot(rendezvous, read, append)` is one side's hold on
  the slot and is never logged. `run_inviter(suite, link, slot, waiting,
  lifetime_ms, record_failure)` waits for `m1`, sends `m2`, waits for `m3`,
  calls `rendezvous.inviter_release` once and sends `m4`, then lingers
  until the joiner closes or the slot ends so its own close cannot delete
  `m4` unread; `run_joiner(suite, link, slot, code, lifetime_ms,
  record_failure)` sends `m1`, waits for `m2`, sends `m3`, waits for `m4`
  and returns the ticket text. Both close the slot on every path
  (`close`, retried for `close_ms`, best effort) and end `Ok` or with an
  `Ending`: `NeverClaimed` (the inviter's slot gone or timed out before
  `m1`), `Stalled` (stopped or interfered with before a verdict; a
  malformed message or a low-order share is interference) or
  `ConfirmationFailed`. Each side numbers its own messages 0 and 1
  (`first_index`, `second_index`). Every wait is `weft/poll` on the link's
  clock against the run's deadline, and each long poll asks the mailbox
  to hold it no longer than what remains. Constants: `call_ms` (60 s),
  `retry_ms` (250 ms), `close_ms` (30 s), `run_slack_ms` (95 s), `keep_ms`
  (600 s). `describe_code_error` words a `pairing_code.CodeError` by
  position. The registry is a supervised `weft/actor` named
  `daemon_pairing`, the last child of the node's tree. `begin` hands it a
  run, which it starts as a relayed one-task `weft` run with a `deadline`
  on the configured timer source; `await` answers `Unknown` or
  `Ended(result)`, at once for a finished run or when it ends. Every run
  has its own subject and the selector is rebuilt from the table after
  each message, as the scheduler does. A run that crashes, is abandoned at
  its deadline or never reports ends `Stalled`, uncounted, and its slot is
  closed by its `abandon` function in a one-task cleanup run of its own
  (deadline `close_ms + call_ms`), so the registry never waits on the
  network. A finished outcome is kept `keep_ms` and pruned on the next
  `Begin`. The relay is linked to the registry, so a registry restart
  takes its runs with it; their slots are left to the mailbox's expiry.
- `daemon/lock`: the exclusive SQLite lock held by a trapping `weft/actor`
  whose `on_shutdown` closes the connection. `daemon/status` (the Tor and
  mailbox cell) and `daemon/events` (the subscriber list) are plain
  `weft/actor`s: the subscribers are all alike and hold no state, so the
  list stays a list and is not a `weft/event_manager`.
- `daemon/mail` (soft `tell` and `ask` to named actors, through a `Handle`
  that carries the `Name` and, in a simulation only, an interceptor) stays
  hand-written because weft has no monitored, non-panicking call against a
  pre-existing pid. Known weft gap.
- `daemon/config` and `daemon/internal/ffi_runtime_clock`. Logging is
  `telemetry/log` (ADR-012): `engine` (`version_conflict`,
  `storage_failed` with the store error's and SQLite code's tags),
  `scheduler` (`retransmit_failed`, `record_failed` with the envelope's id
  prefix), `provisioner` (`queue_refused` with the queue's id prefix and
  the refusal's tag), all `warning`, and `node started` at `info`.

Traffic: the engine tells the shell through `notify` after each commit
(`Transmit` to the scheduler, `CreateQueue` to the provisioner, a topology
change to the fetch manager, `WakeAdapter` and relationship changes to the
event registry). Every nudge is advisory, since each worker also scans on a
timer. Workers read committed rows back through the engine.

The pairing registry's mailbox is `pairing.Message`, opaque: `Begin(run,
work, within, abandon, reply_with: Subject(Nil))` from `api.invite_code`
through a `mail.Handle` (`from` `api`, `to` `pairing`, labels `begin` and
`await`), answered once the run has started; `Await(run, reply_with:
Subject(Watch))` from `api.await_code`, answered with `Unknown` or
`Ended(Result(Nil, Ending))`; `Settled(key, pulled: weft.Pulled(Nil,
Ending))`, mapped from each run's own relay subject; and `Cleaned`, mapped
from the shared cleanup subject and ignored. A run calls the engine only
through the `record_failure` function `api` gives it
(`engine.record_rendezvous_failure`). The joiner's run has no process of
its own: it runs inside the local API connection that asked for it.

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
- A repeat is owed an acknowledgement: `process` marks its processed row
  unacknowledged, so an envelope the mailbox serves again after it was
  acknowledged (a restored backup, a sender's retry stored again once its
  tombstone was swept) is named in the next round's `Ack` and leaves the
  queue, without a second delivery or a counted attempt (ADR-010,
  addendum; found by the P model, `docs/formal/p.md`).
  `test/daemon/reack_test.gleam` stages both paths with sixteen zombies
  and a message behind them. Mutation-checked: answering `Repeat` without
  the unack fails both tests (the seventeenth message never arrives).
- A repeated message identifier from an authenticated peer is ignored, not
  delivered, and recorded as an incident, and the queue moves on
  (`test/daemon/dedup_test.gleam`, two real daemons and a real mailbox, the
  sender forging the repeat with its own session). Mutation-checked: telling
  the core `FreshId` always fails it (ADR-010).
- An envelope that fails to process `limits.max_process_attempts` times is
  quarantined and its queue drains; healed, the sender's retransmit is
  delivered once (`test/daemon/quarantine_test.gleam`, a trigger in the
  receiver's database refusing every delivery). Mutation-checked: never
  quarantining fails it; never clearing the count fails
  `store_test.attempts_count_durably_and_settle_with_the_envelope_test`.
- A batch whose last envelope closed the relationship is acknowledged
  before the fetcher retires, and a retired queue a restart left owing is
  drained (`test/daemon/closed_queue_test.gleam`). Mutation-checked:
  checking liveness before acknowledging fails both tests, and leaving
  draining inboxes out of the reconcile fails the restart one.
- A retried accept is one relationship and a retried keyed send one message
  (`test/daemon/idempotency_test.gleam`, an engine fault hook that makes
  both apply and then answer `Unavailable`). Mutation-checked: dropping the
  accept's invitation lookup, or treating a keyed send as unkeyed, fails it
  (ADR-011).
- `daemon/schema` and `daemon/sql` are generated and never edited by hand,
  and a migration file that has shipped never changes: a schema change is a
  new `sql/NNN_*.sql`. `test/daemon/sql_drift_test.gleam` checks offline that
  the embedded migrations equal the files (numbered from `001` without a
  gap) and that `daemon/sql` holds every query file's statement as sqlc
  emits it, with no `Dynamic` parameter. It also pins the SHA-256 of
  every shipped migration, so an edited one fails even after a regenerate.
- End-to-end retransmission (ADR-006) is tested against a real mailbox whose
  database the test damages after `Appended`
  (`test/daemon/retransmit_test.gleam`): a corrupted message is delivered
  once by its retransmit and receipted, and a lost receipt is regenerated
  when the retransmit arrives. The sender runs on
  `support.shiftable_clock`, so the window passes at once. Mutation-checked:
  never scheduling a retransmit fails both, and skipping the fingerprint
  lookup fails the lost-receipt test.
- A sender whose clock disagrees with the mailbox's still delivers
  (ADR-008, `test/daemon/clock_skew_test.gleam`, two real daemons and a
  real mailbox): an hour ahead is stored on the first offer, two days ahead
  under a halved one, and a mailbox no offer satisfies leaves the row
  queued until its clock is corrected. Mutation-checked: a zero slack, no
  shorter offers, and a permanent `BadDeadline` each fail one of them.
- A restart resumes committed state: an unsent outbox row is sent on start,
  and an envelope committed but unacknowledged is acknowledged by the next
  fetcher round, with no second delivery to the agent.
- One daemon per state directory: `lock.db` holds an exclusive SQLite
  transaction, released by the OS when the process dies, and `pondline init` and `pondline daemon` verify lock freedom and sidecar availability before writing state files. The directory is `0700`, the database and lock `0600`.
- No log line or crash report carries a secret (ADR-012). Our lines take
  only `telemetry/field`'s typed kinds; `pondline.main` installs the
  `telemetry` handler before anything runs, for every command, so OTP's
  reports reach standard error rebuilt from their shape.
  `test/daemon/secrets_test.gleam` searches a whole exchange's stderr, and a
  run with injected crashes in the engine (mid-send), the scheduler and a
  mailbox request process, for the payload, the sealing key, capabilities,
  the invitation, and a ticket with its `K` and derived keys, in every
  spelling (text, decimal byte list, hex).
  `test/daemon/crash_report_test.gleam` is the reproduction: an engine whose
  seal raises from OpenSSL printed the key and the plaintext in its crash
  and supervisor reports before the handler; installing OTP's
  `logger_formatter` instead fails it.
- The send payload is a `Secret` from the local API's decode
  (`local_api.parse_send`) through `Backend.send`, `api.send` and
  `send_with_key` to `engine.send`, exposed only inside the job for the
  core to seal and digest; `engine.invitation_file` answers with a
  `Secret`. Delivered payloads were already `Secret`s.
- Pairing by ticket is tested end to end against a real mailbox
  (`test/daemon/ticket_test.gleam`): pairing and a message; a mailbox
  answering with another ticket's invitation refused; an expired ticket,
  a ticket for nothing and a mistyped one refused cleanly; a loopback
  ticket refused under `TorOnly` before any connection.
- Pairing by spoken code (ADR-016) is tested two ways:
  `test/daemon/pairing_test.gleam` drives `daemon/pairing` against a
  scripted, adversarial mailbox on a fake clock, and
  `test/daemon/pairing_code_test.gleam` runs real daemons and a real
  mailbox over loopback (an honest pairing and a message,
  `a_spoken_code_pairs_two_daemons_and_a_message_crosses_test`). The rules
  it holds, each with its test:
  - Each step runs on the first message at its index only, and any step
    error ends the run: given a malformed message and then an honest one
    at index 0, either side ends `Stalled`, sends nothing further, closes
    the slot and counts nothing
    (`an_inviter_steps_once_on_the_first_message_at_an_index_test`,
    `a_joiner_steps_once_on_the_first_message_at_an_index_test`).
  - `m4` is sealed once and a resend is the same bytes: a hand-off whose
    first answer is lost is sent again byte for byte, and the suite saw
    one AEAD seal (`a_retried_hand_off_carries_the_bytes_sealed_once_test`).
  - The ticket and its blob exist before `m1` is read: `invite_code` runs
    `invite_ticket`, which returns only after `BlobStored`, before it opens
    the slot, and `rendezvous.invite` takes the ticket text, so the run's
    state cannot exist without it. That order is held by construction; no
    test isolates it. The refusal past the cap is checked to store no blob.
  - A run never outlives its slot: an unclaimed inviter ends at its
    lifetime on the link's clock and no long poll asked for more than
    remained (`a_run_never_outlives_its_slot_test`); a run that hangs past
    the registry's deadline is abandoned, reported `Stalled` and its slot
    closed (`the_registry_abandons_a_run_at_its_deadline_test`).
  - Only a confirmation failure is counted, on the side that saw it: an
    inviter whose check fails sends no `m4` and counts one
    (`an_inviter_whose_check_fails_counts_it_and_sends_nothing_test`); a
    joiner whose `m3` was stored and answered by nothing, the slot empty
    until its end or closed, counts one
    (`a_joiner_whose_confirmation_goes_unanswered_counts_it_test`); one
    misheard word counts once on each side
    (`one_wrong_word_fails_and_counts_on_both_sides_test`); a slot gone
    before `m1`, a code nobody claims and a joiner that stops after `m1`
    count nothing (`a_slot_gone_before_the_first_message_was_never_claimed_test`,
    `a_code_nobody_claims_ends_never_claimed_test`,
    `a_joiner_that_stops_stalls_the_inviter_test`). A stranger who claims
    first spends the code: the real joiner's claim is refused at no cost
    and the inviter counts the stranger's guess
    (`a_stranger_who_claims_first_spends_the_code_test`).
  - The cap and its window: failures older than
    `limits.rendezvous_failure_window_seconds` do not count and are pruned
    by the next record; at `limits.max_rendezvous_failures` the daemon
    refuses codes at that endpoint to invite (no blob stored) and to join,
    while another endpoint is unaffected
    (`failures_past_the_cap_refuse_codes_at_that_endpoint_test`;
    `store_test.rendezvous_failures_count_inside_their_window_test` at the
    window's last second).
  - A daemon stopped mid-run loses the run (`await_code` is `NotFound`
    after a restart) and its database files hold no rendezvous row and no
    spelling of the code or its words
    (`a_restart_mid_run_leaves_nothing_of_the_run_test`).
  - The code reaches no log and no rendering: a whole pairing, a misheard
    code and refusals that read a code leave no spelling of the code, its
    words, the password or the delivered ticket in stderr or in any
    rendered result
    (`secrets_test.a_spoken_code_reaches_no_log_and_no_rendering_test`).
    The one line that prints it is `invite create --code`'s answer to the
    operator; no command takes it in argv
    (`cli_test.no_command_accepts_a_code_in_argv_test`).
  No mutation results are recorded for these tests.
- Known gaps: nothing in the state directory is encrypted (permissions only);
  `invite` waits at most `api.invite_wait_ms` for the queue and a timed-out
  offer opens later unexported; a supervisor that fails to start takes its
  starter with it, so `node.start` probes the lock, the database and the Tor
  binary first; the TorOnly path with the real sidecar is behind
  `PONDLINE_TOR_NETWORK=1` and is not run by default; no queue rotation at
  accept; no metrics. For spoken codes: a registry restart, its own or one
  caused by an earlier child's crash, loses the runs it held and leaves
  their slots to the mailbox's expiry (at most `limits.rendezvous_seconds`),
  and a caller waiting in `await_code` hears `NotFound` or `Unavailable`,
  not an ending; a failure the engine fails to record goes uncounted, so
  the cap can let one more code through; the simulation's
  `seed.job_kinds` does not include `RendezvousFailures` or
  `RecordRendezvousFailure`, and no simulation op opens or claims a
  rendezvous; no outside cryptographer has reviewed the exchange.

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
  `scheduler.send_batch`, `fetcher.start_run`, the carrier's bootstrap
  `run` and the pairing registry's run and cleanup deadlines
  (`weft.with_timer_source`, from the sibling weft checkout).
  `carrier.start_with_bootstrap` (tests only) stays on the wall clock.
- **Poll clock** (`Config.poll_clock`, default `poll.monotonic()`): kept in
  `api.Daemon`; `api.await_file` (invite), `node.wait_for_lock` (stop),
  the rendezvous open and claim, and every wait of a pairing run (the
  `pairing.Link` clock) use `poll.until_on`. The registry measures a kept
  outcome's age on the same clock's `now`.
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
  `fetch_manager`, `pairing`, `carrier.GetTor`) goes through a
  `mail.Handle`. Without an
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
the operator, and the `pondline` command that speaks to it.

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
  (`daemon/local_api_types`), never the runtime directly. Spoken codes
  (ADR-016) add `Backend.invite_code`, `await_code` and `accept_code` and
  the types `CodeInvite(run, code, expires_at)` and `PairingOutcome`
  (`Paired(contact)`, `NeverClaimed`, `Stalled`, `ConfirmationFailed`).
  On the wire: `invite` with `"code": true` (with `"ticket"` true as well
  it is `invalid`) answers `{"run": hex, "code": text, "expires_at":
  unix seconds}` and nothing of the invitation; `await_code` takes
  `{"run": hex}` and holds the connection until the run ends, up to
  `api.code_wait_ms`; `accept` takes `"code"` (text) and an optional
  `"rendezvous"` (`HOST:PORT`, refused without a code) in place of
  `"invitation"` or `"ticket"`, exactly one of the three. `await_code` and
  a code `accept` answer `{"outcome": "paired" | "never_claimed" |
  "stalled" | "confirmation_failed", "contact": hex | null}`, the contact
  set only when a joiner paired. The run belongs to the registry, so a
  client that goes away between `invite` and `await_code` strands
  nothing.
- `daemon/local_api_backend`: the only module that maps the runtime's
  `daemon/api` onto `Backend` (`from_daemon`), and `start_node`, which turns
  the CLI's options into a runtime `Config` (`127.0.0.1:PORT` is a loopback
  mailbox, anything else must be an onion) and starts the node. Reconcile
  runtime API changes here.
- `daemon/local_api_client`: one request over the socket; used by the CLI
  and the tests.
- `daemon/cli` (pure parse, `Environment` default `~/.pondline` / `PONDLINE_STATE_DIR`, `ContactRef` petname/prefix resolution, request building, exit codes), `cli_render` (human output), `cli_run` (`init` and persisted `<state-dir>/config.json` + `provision.cap`, `plg1` grant token materialization, runtime effects; ADR-015), and the top-level `pondline` module (`gleam run -m pondline -- <command>`). Release launchers export `PONDLINE_TOR_BIN` and `start_node` resolves `pondline-tor` automatically or fails fast under `--carrier tor`. `invite accept` takes an optional `--budget N` (`api.accept_with_budget`).
  Spoken codes (ADR-016): `invite create --description TEXT --budget N
  [--auto-approve] --code`, with `--code` alone (beside `--out` or
  `--ticket` it is a usage error), and `invite accept --code [--file FILE
  | --stdin] [--rendezvous HOST:PORT] [--description TEXT] [--budget N]`,
  where neither source means a prompt (`Input.InputPrompt`), `--rendezvous`
  is checked as `HOST:PORT` and goes only with `--code`, and `--ticket`
  with `--code` is a usage error (`InviteOutput.SpokenCode`,
  `AcceptForm.FromCode(rendezvous)`). `cli_run.run_with(command,
  announce)` is `run` with the function that writes what must appear
  before the command ends: `hand_out_code` prints the code alone on
  standard output (with `waiting for the joiner to enter the code` on
  standard error) the moment the daemon answers, then sends
  `cli.await_code_request(run)` and reports the outcome; in JSON mode the
  first answer is printed as a response line and the outcome's as the
  second. A prompt writes `pairing code: ` to standard error and reads one
  line. `prepare_input` trims a code and refuses one that does not decode,
  locally and with exit 5, before the daemon is asked. Timeouts: the
  first `invite create --code` call waits `cli.invitation_timeout_ms`
  (670 s), the wait for the run `cli.code_wait_timeout_ms` (710 s), and a
  code accept `cli.code_accept_timeout_ms` (1120 s: a bootstrap, the claim
  retried as a ticket's call, the claimed slot's run with one call and the
  close, and the ticket's redemption); `cli_test` checks both bounds. Only
  `paired` exits 0; `never_claimed`, `stalled` and `confirmation_failed`
  exit 5 with a message naming the operator's next step, different for
  the inviter and the joiner.
- `daemon/build`: the running build's identity (`Identity(version,
  commit)`), read from `PONDLINE_BUILD_VERSION` and `PONDLINE_BUILD_COMMIT`,
  which the release launcher exports (`scripts/release.sh`, ADR-003
  addendum); a build run from source reports `dev` and `unknown`. It is
  printed by `pondline --version` and is the `version` and `commit` fields
  of `health` (added in `local_api_backend`, so a test backend has none).
- `daemon/internal/ffi_local_socket` and `ffi_local_system` over
  `src/daemon_local_ffi.erl`: Unix sockets, the monotonic clock, private
  files and directories, raw fd-1 stdout and stdin, executable lookup, and the environment.
  `read_stdin_line(max)` (`file:read_line` on `/dev/stdin`, raw) is the
  code prompt's one line, newline included, empty at end of input and
  `too_large` past `max`; the prompt passes `limits.max_pairing_code_bytes
  * 4`. It exists because `gleam_stdlib` and `gleam_erlang` read nothing
  from standard input, and `read_stdin` reads to end of input, which a
  prompt cannot wait for.

Invariants:

- Order of checks in `handle`: parse, version, credential, operation, scope,
  arguments, backend. A forbidden operation never has its arguments read and
  never reaches the backend.
- The agent scope may do contacts, send, receive, acknowledge, status and
  health only. Invite, await_code, accept, approve, decline, close,
  raise_budget, audit and incidents are operator-only (`required_scope`).
- `send` takes an optional `idempotency_key` (CLI `--idempotency-key`),
  sent only when given; `incidents` (CLI `pondline incidents [--limit N]`)
  lists identifiers, counts and times and never a payload.
- A credential is a `Secret`, appears in no log or error text, and never in
  argv: the CLI reads it from `--credential-file`, `PONDLINE_CREDENTIAL_FILE`
  or `<state-dir>/operator.cred`. A payload comes from `--file` or `--stdin`
  only. No option named for either exists, which `cli_test` checks for every
  command. A spoken code is the same: it comes from `--file`, `--stdin` or
  the prompt, `--code` is a flag, and a code typed after it or anywhere
  else is a stray word refused without repeating it or any of its words
  (`cli_test.no_command_accepts_a_code_in_argv_test`); a mistyped code's
  refusal names the word's position and never the word
  (`cli_run_test.a_mistyped_code_is_refused_locally_test`).
- Line framing is `recv_line` in the shim, not `{packet, line}`, because the
  built-in mode truncates a long line instead of refusing it. A line over
  `max_line_bytes` gets `too_large` and the connection closes.
- `receive` registers with the hub before its first read, so a wake between
  the read and the wait is not lost. One response is capped near 128 KiB of
  payload; the rest stays for the next call.
- `invite create` writes the invitation to its `--out` file (0600, refuses
  to overwrite, checked before the daemon is asked) and prints only the path.
  With `--ticket` it prints the ticket alone on standard output (and the
  path, if `--out` was also given, on standard error). `invite accept
  --ticket` reads the ticket from `--file` or `--stdin`. `--ticket` is a
  flag, and a stray word is refused without being repeated, so a ticket
  never reaches argv or an error; `cli_test` checks every command. The
  local API's `invite` takes `"ticket": true`; `accept` takes exactly one
  of `invitation`, `ticket` and `code` (ADR-016). `api.invite` and onion `api.accept_ticket` wait up to `api.bootstrap_wait_ms` (180 s) while Tor is `TorStarting`, `carrier` nudges `provisioner`, `scheduler`, and `fetch_manager` when bootstrap completes, and `pondline service install|uninstall|status` (`daemon/service`) manages per-user `launchd` and `systemd --user` daemon units. The CLI waits `cli.invitation_timeout_ms` (670 s) for
  `invite create` and a ticket accept, at least the daemon's own bound
  (`cli_test`), and refuses a ticket input that is not text locally. An
  unknown `--name=value` is named without its value.
- Exit codes: 0 ok, 1 local failure, 2 usage, 3 unauthorized or forbidden,
  4 not found, 5 refused, invalid or too large, 6 unavailable.
- The spoken-code surface is tested at each layer:
  `local_api_test.invite_await_and_accept_carry_a_spoken_code_test`,
  `every_code_outcome_has_its_own_name_test` and
  `a_code_is_one_source_and_its_refusals_do_not_repeat_it_test`;
  `cli_test.invite_create_with_a_code_test` and
  `invite_accept_with_a_code_test`;
  `cli_run_test.invite_create_with_a_code_prints_it_then_waits_test`,
  `invite_accept_with_a_code_trims_and_sends_it_test` and
  `every_code_outcome_is_told_apart_test`.
- Known gaps: a connection process that crashes leaves its socket open until the
  acceptor exits; a Unix socket path is limited to about 100 bytes, so a
  long state dir fails at `listen`. The code prompt does not turn off the
  terminal's echo, so the typed code stays on the screen, and no test
  drives the prompt.

## Deep Docs

- `docs/spec.md` §6.1 (transport), §6.2, §13.1 (no silent downgrade).
- `docs/adr/010-dedup-and-quarantine.md` (repeated identifiers, quarantine,
  incidents) and `docs/adr/011-idempotent-accept-and-send.md` (idempotency
  keys).
- `docs/adr/016-spoken-pairing-codes.md` (pairing by spoken code, both
  addenda), `docs/spec.md` §4.3, §4.4 and §9.2, and
  `packages/core/src/core/rendezvous.gleam` (the steps the drivers run).
- `packages/core/src/core/http1.gleam` (framing and bounds) and
  `core/mailbox/codec.gleam` (the body).
