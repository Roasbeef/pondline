# mailbox

The `mailbox` package stores padded ciphertext for recipients who are offline and returns it when they ask (`docs/spec.md` §2.2, §6). It keeps queues, envelopes, sealed ticket blobs, short-lived rendezvous slots for pairing by spoken code, the SHA-256 hashes of the capabilities that authorize each operation, and tombstones for acknowledged envelopes. It never sees plaintext. This README is the short map of the package at commit `49a51b3`, with the rendezvous slot as of `a2aadc2`; the full walk-through of the append and long-poll paths, the state machines and the schema is [docs/architecture/mailbox.md](../../docs/architecture/mailbox.md). The per-package contract (key types, traffic, invariants) is in [CLAUDE.md](CLAUDE.md).

The wire format is `core/mailbox/codec` and the request and response types are `core/mailbox/protocol`, both in `packages/core`. The Tor sidecar that forwards an onion service to the mailbox's loopback port is described in [ADR-001](../../docs/adr/001-tor-sidecar.md). Actor mechanics come from [weft](../../docs/weft.md).

## Components

One HTTP connection is one BEAM process (a mist connection). It decodes the body, calls `node.handle`, and encodes the answer. All durable work happens in a single `coordinator` actor that owns the SQLite connection. Two further actors sit beside it: the `notifier` records which connection processes wait on which queue, and the `sweeper` asks the coordinator to delete expired rows on a timer.

```mermaid
flowchart TB
    subgraph Main["mailbox.gleam"]
        direction TB
        serve["serve<br/>node.start, http.start"]
        onion["host_onion<br/>tor sidecar (optional)"]
    end

    subgraph HTTP["mailbox/http.gleam (mist)"]
        direction TB
        conn["connection process<br/>serve, route, exchange, answer"]
    end

    subgraph Node["mailbox/node.gleam"]
        direction TB
        handle["node.handle<br/>run, long_poll, wait_for_append"]
    end

    subgraph Sup["static_supervisor RestForOne (node.start)"]
        direction TB
        notifier["notifier actor<br/>Wait, Forget, Notify"]
        coord["coordinator actor<br/>Handle, Sweep, CreateGrant"]
        sweeper["sweeper actor<br/>periodic Tick"]
    end

    service["service.handle, service.sweep<br/>(service.gleam)"]
    store[("store.transaction<br/>(store.gleam)")]
    db[("SQLite file")]

    serve --> conn
    serve -. "--tor-state (auto pondline-tor)" .-> onion
    conn -- "codec.decode_request" --> handle
    handle -- "Handle(now, request)" --> coord
    handle -- "Wait, Forget" --> notifier
    coord --> service
    service --> store
    store --> db
    coord -- "Notify(key) after Appended,<br/>RendezvousSent, RendezvousClosed" --> notifier
    notifier -- "Nil on wake subject" --> handle
    sweeper -- "Sweep(now)" --> coord
```

The connection process does all waiting, so a parked long poll blocks only its own connection. The coordinator waits on nothing except SQLite, and the notifier never touches SQLite. The supervisor is `RestForOne` with the children in the order notifier, coordinator, sweeper (`node.gleam:180`), so a notifier crash restarts all three. The mist listener is linked to `main` and is not under this supervisor.

| Module | Owns | Does not own |
| --- | --- | --- |
| `mailbox.gleam` | Argument parsing, `serve`, `grant` (raw capability or `plg1` token), `status`, sidecar discovery, the optional onion service | Any request handling |
| `mailbox/http` | Framing: the `413`, `404`, `405` and `400` decisions, the per-request log line | Protocol semantics; durable state |
| `mailbox/node` | The `rest_for_one` supervisor, `Names`, and the long-poll sequence run in the caller's process | The waiter table; the database |
| `mailbox/coordinator` | The one `Store`, and the order commands run in | What a request means |
| `mailbox/service` | Authorization, idempotency, quota, deadlines, tombstones, blobs, rendezvous slots and their caps, the nameplate draw | The connection and the SQL text; time (passed in as `now`) |
| `mailbox/store` | Pragmas, migrations, `transaction`, every SQL statement | Protocol rules; which process calls it |
| `mailbox/notifier` | The table from wake key (a queue identifier, or a rendezvous reader's capability hash) to waiting wake subjects | Envelopes; timers |
| `mailbox/sweeper` | Its periodic tick | The sweep itself, which runs in the coordinator |
| `mailbox/mail` | `tell`, `ask` and the simulation interception seam | Message types of the actors |

`mailbox/schema` and `mailbox/sql` are generated from `sql/*.sql` and `src/mailbox/sql/*.sql` and are not edited by hand (ADR-007).

## Request path

A request reaches the coordinator through `node.handle`, which sends a `Fetch` or `RendezvousFetch` with a positive `wait_seconds` to `long_poll` and every other request straight to `run`. Every protocol answer, refusals included, is HTTP `200` with a TLV `Response`. HTTP statuses are only for transport failures.

```mermaid
flowchart TB
    start(["POST /v1/mailbox"]) --> route{"http.route<br/>path and method"}
    route -- "other path" --> r404["404"]
    route -- "other method" --> r405["405, Allow: POST"]
    route -- "POST" --> len{"http.exchange:<br/>Content-Length<br/>≤ max_request_bytes?"}
    len -- "missing, invalid or<br/>Transfer-Encoding" --> r400["400"]
    len -- "over the limit" --> r413["413, body not read"]
    len -- "ok" --> dec{"codec.decode_request"}
    dec -- "error" --> refused["200 Refused(Malformed,<br/>UnsupportedVersion, TooLarge)"]
    dec -- "ok" --> handle["node.handle"]
    handle -- "Fetch, wait_seconds > 0" --> poll["long_poll"]
    handle -- "any other request" --> ask["coordinator.handle<br/>(30_000 ms)"]
    poll --> ask
    ask -- "no reply in time or<br/>no coordinator" --> unavail["200 Refused(Unavailable)"]
    ask --> svc["service.handle<br/>one transaction"]
    svc -- "store error" --> unavail
    svc --> commit["COMMIT, then<br/>coordinator.announce"]
    commit -- "Appended" --> notify["Notify(queue)"]
    commit --> reply["200 TLV Response"]
```

1. **Frame.** `http.route` selects by path and then method (`http.gleam:197`). `http.exchange` refuses a declared `Content-Length` over `codec.max_request_bytes()` before reading the body, and answers `400` for a missing or invalid length or any transfer coding (`http.gleam:216`, `http.gleam:241`). `max_request_bytes()` is 263_168 (`codec.gleam:131`).
2. **Decode.** `http.answer` runs `codec.decode_request`; a failure becomes `Refused(codec.refusal(error))` so the client reads one kind of answer (`http.gleam:259`).
3. **Dispatch.** `node.handle` reads the clock and calls `coordinator.handle` with a 30_000 ms call timeout (`node.gleam:138`). A timeout or a missing coordinator is `Refused(Unavailable)`, and the command may still commit afterwards, so a client treats `Unavailable` as outcome unknown.
4. **Apply.** `coordinator.handle_message` runs `service.handle` to completion before reading the next message (`coordinator.gleam:197`). Each write is one `store.transaction`, which issues `BEGIN IMMEDIATE` (`store.gleam:347`). A storage error becomes `Refused(Unavailable)` without the error text.
5. **Wake.** After the commit, `announce` sends a `Notify` for each wake key the command named (`service.Served.wakes`): the queue after an `Appended`, the other side's reader after a `RendezvousSent`, both sides' readers after a `RendezvousClosed`. Then the reply goes to the caller.
6. **Long poll.** `wait_for_append` registers a wake subject with the notifier before its last look at the database, then waits `min(wait_seconds, limits.long_poll_seconds)` (25) seconds, fetches once more, and calls `notifier.forget` (`node.gleam:284`). The step-by-step sequence is in [docs/architecture/mailbox.md](../../docs/architecture/mailbox.md#pipeline-a-long-poll-fetch).

The sweeper sends `Sweep(now)` to the coordinator on a fixed-delay `actor.periodic` tick every `sweep_period_ms` (60_000, set at `mailbox.gleam:71`), with a 30_000 ms reply timeout (`sweeper.gleam:55`). It drops the result; the next tick retries.

## The rendezvous slot

Pairing by spoken code ([ADR-016](../../docs/adr/016-spoken-pairing-codes.md)) needs a place where two daemons that share only a six-digit nameplate can trade four opaque messages. The slot is that place, held at the inviter's mailbox for at most `limits.rendezvous_seconds` (600). The mailbox files and serves bodies; it does not run the PAKE, learns no word of the code, and cannot tell a guess from an honest message. Its job is to keep the nameplate space sparse, bound what a slot can hold, and authenticate each side by the capabilities it registered. The step-by-step account is [docs/architecture/mailbox.md](../../docs/architecture/mailbox.md#pipeline-a-rendezvous-slot).

```mermaid
sequenceDiagram
    participant I as Inviter daemon
    participant M as Mailbox (service)
    participant J as Joiner daemon
    I->>M: OpenRendezvous(provision, id, read, append, lifetime)
    Note over M: purge expired, check caps,<br/>draw nameplate, insert row
    M-->>I: RendezvousOpened(nameplate, expires_at)
    Note over I,J: the operators speak the code
    J->>M: ClaimRendezvous(nameplate, read, append)
    Note over M: first claim binds the claimant,<br/>expiry shortened to at most 120 s
    M-->>J: RendezvousClaimed(id, expires_at)
    J->>M: RendezvousSend(id, append, 0, m1)
    M-->>I: wakes the opener's waiting RendezvousFetch
    Note over I,J: m2, m3, m4 the same way,<br/>each side fetching the other's bodies
    I->>M: CloseRendezvous(id, read)
    Note over M: delete slot and messages,<br/>wake both readers
```

**Tables.** Migration `sql/003_rendezvous.sql` adds `rendezvous` (the opener's chosen identifier, a nameplate unique among stored slots, the hash of the opening grant, the opener's two capability hashes, the claimant's two once it has claimed, the clamped lifetime and the expiry) and `rendezvous_messages` (one body and its digest per slot, side and index, removed with the slot by cascade). Both are `STRICT`. Capabilities are stored only as SHA-256 hashes, as everywhere else in the mailbox.

**Operations.** `OpenRendezvous` is authorized by a provisioning grant alone; an identical repeat answers the same nameplate, anything else under the identifier is `Conflict`. `ClaimRendezvous` carries only the nameplate and the joiner's own capabilities: the first claim binds them, and an unknown, expired or already claimed nameplate is `Unauthorized`, one answer for all three. `RendezvousSend` files a body under the sender's side and index, the side known only from which stored append hash the presented capability matches (`side_of`, constant-time comparisons); the same bytes again are a retry and answer as before, different bytes at a filed index are `Conflict` and never replace the first. `RendezvousFetch` returns the other side's bodies past `after`, never the reader's own. `CloseRendezvous`, by either side's reader, deletes the slot and wakes both sides.

**Wake keys.** A waiting rendezvous fetch parks with the notifier under `service.rendezvous_wake(read)`, the 32-byte hash of its reader's capability, which is the form the mailbox already holds. A queue's key is its 16-byte identifier, so the two kinds of key cannot collide and one never wakes the other.

**Caps.** A grant may hold at most `limits.max_grant_rendezvous` (4) live slots and the mailbox at most `limits.max_live_rendezvous` (1000), both answered `QuotaExceeded`, the grant's checked first. The mailbox-wide cap is what keeps a blind claim of a random nameplate from hitting a live slot more than about once in a thousand. A body is at most `limits.max_rendezvous_body_bytes` (2048, `TooLarge`), and a side at most `limits.max_rendezvous_messages` (4) indices, `QuotaExceeded` past that. A nameplate draw that finds no free value within `service.nameplate_draws` (32) tries answers `Unavailable` and writes nothing, since that many collisions means the randomness source is broken.

**Sweep.** Every open first purges expired slots, so a nameplate is only ever compared with live ones and an expired identifier is free again. The periodic sweep deletes expired slots too, in the same transaction as the envelope, tombstone and blob sweep, and reports their count; until then an expired slot is already invisible to every operation, which compares `expires_at` with `now`.

The guess cap ADR-016 rests on is not here. The mailbox cannot see a failed confirmation; the daemon counts those per endpoint and refuses a code once the count is reached.

## Startup

`pondline-mailbox serve --db <path> [--port <n>] [--tor-state <dir> [--tor-bin <path>]]` resolves any requested Tor sidecar before starting the node, and starts the node before the listener, so no request arrives before the database is open and migrated (`mailbox.gleam:562`). `--port` defaults to `0` (ephemeral loopback port). The coordinator opens the store in its initialiser with a 5000 ms start timeout, so a bad file fails the start (`coordinator.gleam:109`). The server binds `127.0.0.1` only. With `--tor-state`, `host_onion` starts the resolved `pondline-tor` sidecar, hosts an onion service named `mailbox` that forwards to the bound port, writes `<tor-state>/onion` (`0600`), and prints `onion <host>.onion:80` after the `listening` line ([ADR-015](../../docs/adr/015-grant-tokens-and-daemon-config.md)). `pondline-mailbox status --db <path>` queries `store.status` (`store.gleam:899`) directly in one read transaction without booting the supervisor.

## Storage

One SQLite file, opened by `store.open_with` with WAL, `synchronous=FULL`, `fullfsync` and `foreign_keys` on, and a 5000 ms busy timeout (`store.gleam:227`). The schema is at version 3 (`schema.gleam:6`): `sql/001_initial.sql` creates `grants`, `queues`, `envelopes` and `tombstones`, `sql/002_blobs.sql` adds `blobs`, and `sql/003_rendezvous.sql` adds `rendezvous` and `rendezvous_messages`. `store.migrate` applies the list through `PRAGMA user_version` and refuses a file written by a newer build (`store.gleam:298`). Table detail and the missing foreign keys are explained in [docs/architecture/mailbox.md](../../docs/architecture/mailbox.md#storage).

## Where to go next

| Question | Read |
| --- | --- |
| How an `Append` is authorized and de-duplicated | [docs/architecture/mailbox.md](../../docs/architecture/mailbox.md), "Pipeline: an Append"; `docs/spec.md` §6.4 |
| How the long poll avoids a missed append | [docs/architecture/mailbox.md](../../docs/architecture/mailbox.md), "Pipeline: a long-poll Fetch" |
| The rendezvous slot for spoken codes | [docs/architecture/mailbox.md](../../docs/architecture/mailbox.md), "Pipeline: a rendezvous slot"; [ADR-016](../../docs/adr/016-spoken-pairing-codes.md); `service.serve` |
| Sealed ticket blobs | [ADR-009](../../docs/adr/009-invitation-tickets.md); `service.store_blob`, `service.fetch_blob` |
| Why SQL is generated | [ADR-007](../../docs/adr/007-parrot-sql-codegen.md) |
| Log fields and crash reports | [ADR-012](../../docs/adr/012-logging-and-crash-reports.md) |
| Simulation seams (`timer`, `interceptor`, `store_faults`) | `node.Config` (`node.gleam:111`), `docs/dst/plan.md`, [CLAUDE.md](CLAUDE.md) |

## Known gaps

- Nothing here was confirmed by running code. Restart behaviour under `RestForOne`, and whether mist stops a handler when a client disconnects mid long poll, are not checked.
- The onion path is exercised only with `PONDLINE_TOR_NETWORK=1` (see `CLAUDE.md`); it is not described step by step here.
