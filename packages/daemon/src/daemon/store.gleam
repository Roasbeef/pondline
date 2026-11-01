//// The daemon's durable state: one SQLite file, the typed statements that
//// read and write it, and `commit`, the only way a `Plan` becomes durable
//// (spec §8.1, §8.2, §8.3).
////
//// This module owns the schema, the durability pragmas and every statement
//// the daemon runs. Nothing above it writes SQL, and nothing below it knows
//// what a transition is. The shape follows `mailbox/store`: a connection
//// held by exactly one process (the engine), pragmas that make a commit
//// durable (a write-ahead log, `synchronous=FULL`, `fullfsync` because
//// macOS `fsync` does not flush the drive cache), and `user_version`
//// migrations that refuse a file written by a newer build.
////
//// ## Where the SQL text lives
////
//// None of the static SQL is written in this file (ADR-007). The schema is
//// the migration files under `packages/daemon/sql/`, one per version, which
//// `make gen-sql` embeds in the generated `daemon/schema`. Every statement
//// is a named query under `src/daemon/sql/`, which parrot turns into the
//// generated `daemon/sql`: one function per statement, returning its text,
//// its parameters typed by the columns they bind, and a decoder for its rows.
//// `query` and `write` are the bridge that binds those parameters as sqlight
//// values. What stays hand-written here is what is not a static statement:
//// the pragmas, `BEGIN IMMEDIATE`, `COMMIT` and `ROLLBACK`, and the runner
//// that applies each migration. After editing a `.sql` file, run `make
//// gen-sql`; `test/daemon/sql_drift_test.gleam` fails until it is run.
////
//// ## The commit is the gate
////
//// `commit` takes one `Commit`, a whole `Plan` together with the state
//// version it was computed from, and writes the new state blob and every
//// record in one `BEGIN IMMEDIATE` transaction. It returns a `Committed`,
//// an opaque value only this module constructs, and that value is the only
//// source of the effects the engine may act on. The delivery scheduler and
//// the fetchers never receive bytes from a plan; they read outbox and
//// processed rows back from this module, so "no send before commit" and "no
//// ack before commit" (spec §13.1) are consequences of where their bytes
//// come from and not of anyone remembering an order.
////
//// A state write checks the version it read. An `UPDATE ... WHERE version =
//// ?` that touches no row is a `Conflict`, the transaction rolls back and
//// nothing of the plan survives. The engine is a single writer, so a
//// conflict means a bug or a second process on the same file; the version is
//// the backstop spec §8.4 asks for.
////
//// ## Layout
////
//// `relationships` and `offers` keep the `core/snapshot` blob as the truth
//// and a few plain columns (phase, queue, inbox) so the shell can find work
//// without decoding every blob. `outbox` holds immutable ciphertext, and
//// `processed` the envelopes already handled, keyed by queue and envelope
//// with the digest they were handled under. `deliveries`, `sent_messages`
//// and `audit` are what the local API reads.
////
//// ## End-to-end retransmission
////
//// Schema version 2 adds the two halves of ADR-006. On the sending side an
//// outbox row carries `retransmits` (how many copies of its bytes were
//// committed before it) and `retransmit_at`, set from `retransmit.due_at`
//// when the mailbox's receipt is recorded and cleared when the peer's
//// receipt names the message or the row is replaced. A retransmit
//// (`Retransmitted`) is an `INSERT ... SELECT` from the replaced row, so the
//// copy's bytes, route and deadline come from the committed row and from
//// nowhere else. On the receiving side `fingerprints` maps a relationship's
//// ratchet-message digest to the message it carried, written with the
//// delivery and pruned once the message expires, which is all the bound it
//// needs: no honest sender retransmits past a message's expiry.
////
//// ## Secrets
////
//// The blobs hold identity keys, ratchet state and capabilities, and
//// `deliveries` and `audit` hold plaintext, as the owner ruled for the audit
//// log. All of it is protected by file permissions alone (see
//// `daemon/config`). Error values here name tables and statements and never
//// a bound value, so none of it can reach a log through an error.
////
//// ## The fault hook
////
//// `open_with` takes an optional `Faults` hook for a deterministic
//// simulation, and `open` is `open_with` without one. `transaction`
//// consults the hook once per transaction, through `faulted`: `Down` fails
//// before `BEGIN` and writes nothing, `AckLost` commits and then fails, and
//// both return the I/O error `injected` builds, which is what a failing disk
//// returns. The migrations run before the hook is attached. Without a hook,
//// which is every production store, `transaction` is `BEGIN IMMEDIATE`,
//// the body and `COMMIT`, as written.
////
//// ## Flow
////
//// 1. `open` configures the connection and migrates the schema.
//// 2. The `*_by_*` readers give the engine the state a transition starts
////    from, with its version.
//// 3. `commit` writes the transition's result through `apply` and
////    `put_record`.
//// 4. `due` and `record_send` are what the scheduler reads and updates after
////    a commit, and `unacked` and `mark_acked` what the fetchers do.

import core/crypto/suite.{type Suite}
import core/envelope.{type Padded}
import core/id.{
  type Contact, type Envelope, type Id, type Invitation as InvitationKind,
  type Message as MessageKind, type Queue,
}
import core/invitation
import core/limits
import core/mailbox/codec
import core/mailbox/protocol
import core/offer.{type Offer}
import core/plan.{type Effect, type EnvelopeRef, type Plan, type Record}
import core/relationship.{type Relationship}
import core/retransmit.{type Retransmission, type Unreceipted}
import core/route.{type Inbox, type Route}
import core/secret
import core/snapshot
import core/time.{type Instant, Instant}
import daemon/internal/sql_param.{type Param}
import daemon/schema
import daemon/sql
import gleam/dynamic/decode
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import sqlight

/// The schema version this build writes and understands: the number of
/// migration files under `packages/daemon/sql/`, as `daemon/schema` embeds
/// them.
pub const schema_version = schema.version

/// How long SQLite waits on a locked database before giving up. Only an
/// outside process can contend with the engine, so this is a courtesy.
pub const busy_timeout_ms = 5000

/// An open daemon database. The suite is held only to rebuild typed values
/// from snapshot blobs.
pub opaque type Store {
  Store(connection: sqlight.Connection, suite: Suite, faults: Option(Faults))
}

/// What a fault hook makes of one transaction. Only a simulation sets a
/// hook; a production store runs every transaction as written.
pub type Fate {
  /// Run the transaction as written.
  Proceed

  /// Fail before `BEGIN`: nothing is written and the caller gets an error,
  /// as when the database cannot be reached.
  Down

  /// Run and commit the transaction, then return an error, as when the
  /// commit reached the disk but its acknowledgement did not reach the
  /// caller. The caller cannot tell this from `Down`.
  AckLost
}

/// A fault hook, consulted once per transaction after the store is open.
/// SQLite transactions are atomic, so there is no torn mode to offer.
pub type Faults =
  fn() -> Fate

/// Why a storage operation failed.
pub type Error {
  /// SQLite reported an error. Messages name tables and statements, never
  /// bound values.
  Sql(error: sqlight.Error)

  /// The file was written by a newer build than this one.
  FutureSchema(found: Int, supported: Int)

  /// A stored value does not decode as what its column promises, or a
  /// commit was asked to write something its rows cannot hold.
  Corrupt(detail: String)

  /// A state write found the version it read already replaced. The whole
  /// commit rolled back.
  Conflict
}

/// The durability settings in effect, as SQLite reports them.
pub type Settings {
  Settings(
    journal_mode: String,
    synchronous: Int,
    fullfsync: Int,
    foreign_keys: Int,
    busy_timeout: Int,
    user_version: Int,
  )
}

/// A relationship as stored: the operator's label for it, and the version
/// the next write must name.
pub type ContactRecord {
  ContactRecord(
    /// The row's version, incremented by every state write.
    version: Int,
    /// The operator's label for the peer, unverified.
    description: String,
    /// The decoded relationship.
    relationship: Relationship,
  )
}

/// An offer as stored.
pub type OfferRecord {
  OfferRecord(
    /// The row's version, incremented by every state write.
    version: Int,
    /// The operator's label for the invitation.
    description: String,
    /// The decoded offer.
    offer: Offer,
  )
}

/// One transition's result, in the shape each caller produces. Each variant
/// carries exactly what its write needs, so a plan with outbox rows cannot be
/// committed without the relationship that owns them.
pub type Commit {
  /// An envelope the core refused or ignored: only the `Processed` row, so
  /// the mailbox can be acknowledged.
  Dropped(ref: EnvelopeRef)

  /// A new relationship the operator started by accepting an invitation.
  Started(plan: Plan(Relationship), description: String)

  /// A transition of an existing relationship, computed from `version`.
  Revised(plan: Plan(Relationship), version: Int)

  /// An invitation consumed: the offer is replaced and the relationship it
  /// produced is inserted, atomically, under the offer's label.
  Redeemed(
    offer: Offer,
    offer_version: Int,
    description: String,
    plan: Plan(Relationship),
  )

  /// A new offer the operator created. It must hold its stock, because the
  /// row keeps the invitation file and the inbox. An offer plan carries no
  /// records, only the queue to create.
  OfferStarted(plan: Plan(Offer), description: String)

  /// A transition of an existing offer, computed from `version`.
  OfferRevised(offer: Offer, version: Int)

  /// A stored row sent again: a copy of its bytes under a fresh envelope,
  /// queued, and the replaced row's schedule ended. The commit fails with
  /// `Conflict` if the replaced row's schedule already ended.
  Retransmitted(retransmission: Retransmission)

  /// A stored row that will not be sent again; its schedule ends.
  RetransmitStopped(envelope: Id(Envelope))
}

/// Proof that a `Commit` is durable, and the effects the engine may now
/// act on. Only `commit` builds one.
pub opaque type Committed {
  Committed(effects: List(Effect))
}

/// What the mailbox's receipt for an outbox row says, as the scheduler
/// reports it.
pub type SendOutcome {
  /// The mailbox stored the envelope. The bytes are the encoded response,
  /// kept as evidence (spec §6.4).
  Stored(receipt: BitArray)

  /// The mailbox refused for a reason a retry will not change.
  Rejected

  /// A transient failure; try again at this instant, this being the
  /// `attempts`th.
  Retry(attempts: Int, next_attempt_at: Instant)
}

/// An outbox row the scheduler may send.
pub type OutboxRow {
  OutboxRow(
    /// The identifier the mailbox deduplicates retries by.
    envelope: Id(Envelope),
    /// Where to send it.
    route: Route,
    /// The committed ciphertext, resent byte for byte.
    padded: Padded,
    /// After this instant the mailbox may discard it, and so do we.
    deadline: Instant,
    /// How many sends have already failed.
    attempts: Int,
  )
}

/// A stored row due to be sent again, with the relationship that sent it.
pub type DueRetransmit {
  DueRetransmit(contact: Id(Contact), row: Unreceipted)
}

/// Where an outbound message stands (spec §7.2).
pub type SentState {
  LocallyQueued
  StoredByMailbox
  ReceivedByPeer
  Failed
}

/// An inbound message stored for the agent.
pub type DeliveryRecord {
  DeliveryRecord(
    message: Id(MessageKind),
    contact: Id(Contact),
    content_type: String,
    payload: secret.Secret,
    in_reply_to: Option(Id(MessageKind)),
    received_at: Instant,
  )
}

/// Which way an audited message went.
pub type Direction {
  Inbound
  Outbound
}

/// One plaintext audit entry.
pub type AuditRecord {
  AuditRecord(
    contact: Id(Contact),
    direction: Direction,
    message: Id(MessageKind),
    content_type: String,
    payload: secret.Secret,
    at: Instant,
  )
}

/// Why the daemon set an inbound envelope aside without delivering it
/// (ADR-010). Both are written for the operator, never for the agent.
pub type IncidentKind {
  /// An authenticated peer sent an application message under an identifier
  /// it had already used on the relationship. The session advanced past
  /// it; nothing was delivered.
  RepeatedMessageId
}

/// One incident as the operator reads it: identifiers, a count and a time,
/// never a payload.
pub type IncidentRecord {
  IncidentRecord(
    /// What happened.
    kind: IncidentKind,
    /// The queue the envelope came from.
    queue: Id(Queue),
    /// The envelope.
    envelope: Id(Envelope),
    /// The relationship that owns the queue, when one does.
    contact: Option(Id(Contact)),
    /// The repeated message identifier, for a `RepeatedMessageId`.
    message: Option(Id(MessageKind)),
    /// How many times the envelope was handed to the core, when counted.
    attempts: Option(Int),
    /// When it was recorded.
    at: Instant,
  )
}

/// What `invitation_file` found.
pub type InvitationFile {
  /// The offer is open: the file may be handed out.
  FileReady(bytes: BitArray)

  /// The offer's queue is still being created.
  FileNotYet

  /// The offer is consumed or expired, or there is none.
  FileGone
}

// -------------------------------------------------------------- lifecycle

/// Opens (creating if absent) the database at `path`, applies the durability
/// pragmas and migrates the schema to `schema_version`. The file is created
/// `0600` by the caller before this runs; SQLite gives its `-wal` and `-shm`
/// files the same mode.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(store) = store.open("/var/lib/reedwire/daemon.db", suite)
/// store.close(store)
/// // -> Ok(Nil)
/// ```
pub fn open(path: String, suite: Suite) -> Result(Store, Error) {
  open_with(path, suite, None)
}

/// `open`, with a fault hook that every transaction after the migrations
/// consults. `None` is `open`. The migrations run without it, so a hook
/// cannot fail the open itself; a simulation that wants a store that will
/// not open points `path` somewhere unusable instead.
///
/// ## Examples
///
/// ```gleam
/// store.open_with("file:d1?mode=memory&cache=shared", suite, None)
/// // -> Ok(store)
/// ```
pub fn open_with(
  path: String,
  suite: Suite,
  faults: Option(Faults),
) -> Result(Store, Error) {
  use connection <- result.try(sqlight.open(path) |> result.map_error(Sql))
  let store = Store(connection:, suite:, faults: None)

  // A failure after the connection exists must not leak it: the file would
  // stay locked until the process exits.
  case configure(store) |> result.try(fn(_) { migrate(store) }) {
    Ok(Nil) -> Ok(Store(..store, faults:))

    Error(error) -> {
      let _ = sqlight.close(connection)
      Error(error)
    }
  }
}

/// Closes the database.
///
/// ## Examples
///
/// ```gleam
/// store.close(store)
/// // -> Ok(Nil)
/// ```
pub fn close(store: Store) -> Result(Nil, Error) {
  sqlight.close(store.connection) |> result.map_error(Sql)
}

/// Reads the durability settings back from SQLite, so a test can see what
/// is in effect rather than what was requested.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(settings) = store.settings(store)
/// settings.journal_mode
/// // -> "wal"
/// ```
pub fn settings(store: Store) -> Result(Settings, Error) {
  use journal_mode <- result.try(pragma_text(store, "journal_mode"))
  use synchronous <- result.try(pragma_int(store, "synchronous"))
  use fullfsync <- result.try(pragma_int(store, "fullfsync"))
  use foreign_keys <- result.try(pragma_int(store, "foreign_keys"))
  use busy_timeout <- result.try(pragma_int(store, "busy_timeout"))
  use user_version <- result.try(pragma_int(store, "user_version"))

  Ok(Settings(
    journal_mode:,
    synchronous:,
    fullfsync:,
    foreign_keys:,
    busy_timeout:,
    user_version:,
  ))
}

/// Applies the durability pragmas, one statement each, because SQLite
/// reports a bad one by name and `exec` stops at the first failure.
fn configure(store: Store) -> Result(Nil, Error) {
  // WAL must be chosen before the first write and persists in the file; the
  // other pragmas are per connection and so are reapplied on every open.
  use _ <- result.try(pragma_text(store, "journal_mode=WAL"))
  use _ <- result.try(run(store, "PRAGMA synchronous=FULL"))
  use _ <- result.try(run(store, "PRAGMA fullfsync=ON"))
  use _ <- result.try(run(store, "PRAGMA checkpoint_fullfsync=ON"))
  use _ <- result.try(run(store, "PRAGMA foreign_keys=ON"))
  run(store, "PRAGMA busy_timeout=" <> int.to_string(busy_timeout_ms))
}

/// Brings the file to `schema_version`, refusing one written by a newer
/// build rather than guessing at a schema it cannot describe.
fn migrate(store: Store) -> Result(Nil, Error) {
  use found <- result.try(pragma_int(store, "user_version"))

  // A file ahead of this build is refused; one at or behind it replays only
  // the migrations it has not seen.
  case found > schema_version {
    True -> Error(FutureSchema(found:, supported: schema_version))
    False -> apply_migrations(store, list.drop(schema.migrations, found), found)
  }
}

/// Applies each pending migration in its own transaction, in order, bumping
/// `user_version` in the same transaction as the schema it describes.
fn apply_migrations(
  store: Store,
  pending: List(String),
  from: Int,
) -> Result(Nil, Error) {
  // The empty list is a file at the current version.
  case pending {
    [] -> Ok(Nil)

    [statements, ..rest] -> {
      use _ <- result.try(
        transaction(store, fn() {
          use _ <- result.try(run(store, statements))
          run(store, "PRAGMA user_version=" <> int.to_string(from + 1))
        }),
      )

      apply_migrations(store, rest, from + 1)
    }
  }
}

/// Runs `body` as one transaction: committed if it returns `Ok`, rolled back
/// if it returns `Error`. The write lock is taken at the start, so nothing
/// the body reads can change underneath it.
///
/// ## Examples
///
/// ```gleam
/// store.transaction(store, fn() { store.meta_put(store, "k", <<1>>) })
/// // -> Ok(Nil)
/// ```
pub fn transaction(
  store: Store,
  body: fn() -> Result(a, Error),
) -> Result(a, Error) {
  // Without a hook this is the transaction as written; a hook may fail it
  // before it starts or after it commits.
  case store.faults {
    None -> atomically(store, body)
    Some(decide) -> faulted(store, decide(), body)
  }
}

/// A transaction under the fate a fault hook chose for it.
fn faulted(
  store: Store,
  fate: Fate,
  body: fn() -> Result(a, Error),
) -> Result(a, Error) {
  case fate {
    Proceed -> atomically(store, body)

    Down -> Error(injected("the database is unavailable"))

    // The commit is real; only the caller's view of it is lost.
    AckLost ->
      atomically(store, body)
      |> result.try(fn(_) { Error(injected("the commit's outcome was lost")) })
  }
}

/// The error a fault hook's failure returns: an I/O error, which is what a
/// real unreachable or failing disk looks like to the caller.
fn injected(message: String) -> Error {
  Sql(sqlight.SqlightError(sqlight.Ioerr, message, -1))
}

/// Runs `body` between `BEGIN IMMEDIATE` and `COMMIT`, rolling back on any
/// error.
fn atomically(
  store: Store,
  body: fn() -> Result(a, Error),
) -> Result(a, Error) {
  use _ <- result.try(run(store, "BEGIN IMMEDIATE"))

  // The body's own result decides: `Ok` commits, `Error` rolls back.
  case body() {
    Ok(value) ->
      case run(store, "COMMIT") {
        Ok(Nil) -> Ok(value)

        Error(error) -> {
          // A failed COMMIT can leave the transaction open; end it so the
          // connection is usable for the next request.
          let _ = run(store, "ROLLBACK")
          Error(error)
        }
      }

    Error(error) -> {
      let _ = run(store, "ROLLBACK")
      Error(error)
    }
  }
}

// ---------------------------------------------------------------- commit

/// Writes one transition's result in one transaction and returns proof that
/// it is durable. Nothing of a failed commit survives: the state blob, the
/// outbox rows and the processed record roll back together.
///
/// ## Examples
///
/// ```gleam
/// store.commit(store, now, store.Dropped(ref))
/// // -> Ok(committed)
/// ```
pub fn commit(
  store: Store,
  now: Instant,
  change: Commit,
) -> Result(Committed, Error) {
  transaction(store, fn() { apply(store, now, change) })
}

/// The effects a commit's plan asked for, now that it is durable.
///
/// ## Examples
///
/// ```gleam
/// store.effects(committed)
/// // -> [plan.Transmit]
/// ```
pub fn effects(committed: Committed) -> List(Effect) {
  committed.effects
}

/// Runs one `Commit` inside the caller's transaction.
fn apply(
  store: Store,
  now: Instant,
  change: Commit,
) -> Result(Committed, Error) {
  // Each variant writes its state, then its records, and the effects come
  // only from the plan that was written.
  case change {
    Dropped(ref:) -> {
      use _ <- result.try(put_record(store, now, None, plan.dropped(ref)))
      Ok(Committed(effects: []))
    }

    Started(plan:, description:) -> {
      use _ <- result.try(insert_relationship(store, plan.state, description))
      settle(store, now, plan)
    }

    Revised(plan:, version:) -> {
      use _ <- result.try(update_relationship(store, plan.state, version))
      settle(store, now, plan)
    }

    Redeemed(offer:, offer_version:, description:, plan:) -> {
      use _ <- result.try(update_offer(store, offer, offer_version))
      use _ <- result.try(insert_relationship(store, plan.state, description))
      settle(store, now, plan)
    }

    OfferStarted(plan:, description:) -> {
      use _ <- result.try(insert_offer(store, plan.state, description))
      Ok(Committed(effects: plan.effects))
    }

    OfferRevised(offer:, version:) -> {
      use _ <- result.try(update_offer(store, offer, version))
      Ok(Committed(effects: []))
    }

    Retransmitted(retransmission:) -> {
      use _ <- result.try(copy_row(store, now, retransmission))
      Ok(Committed(effects: [plan.Transmit]))
    }

    RetransmitStopped(envelope:) -> {
      use _ <- result.try(end_schedule(store, envelope))
      Ok(Committed(effects: []))
    }
  }
}

/// Commits a retransmit: the replaced row's bytes, route, deadline, kind
/// and message are copied under the fresh envelope, due at once, and the
/// replaced row's schedule ends. Copying in SQL is what keeps a retransmit
/// to the committed ciphertext: no bytes enter from outside the store. A
/// replaced row whose schedule already ended copies nothing, which is a
/// `Conflict`: something settled it since it was read.
fn copy_row(
  store: Store,
  now: Instant,
  retransmission: Retransmission,
) -> Result(Nil, Error) {
  use rows <- result.try(query(
    store,
    sql.copy_for_retransmit(
      fresh: id.to_bytes(retransmission.envelope),
      now: now.unix_seconds,
      retransmits: retransmission.retransmits,
      replaces: id.to_bytes(retransmission.replaces),
    ),
  ))
  use _ <- result.try(one_row_or_conflict(rows))

  end_schedule(store, retransmission.replaces)
}

/// Ends one row's retransmit schedule.
fn end_schedule(store: Store, envelope: Id(Envelope)) -> Result(Nil, Error) {
  write(store, sql.end_schedule(envelope: id.to_bytes(envelope)))
}

/// Writes a relationship plan's records, in order, under its contact.
fn settle(
  store: Store,
  now: Instant,
  plan: Plan(Relationship),
) -> Result(Committed, Error) {
  let contact = Some(plan.state.contact)

  use _ <- result.try(
    list.try_each(plan.records, fn(record) {
      put_record(store, now, contact, record)
    }),
  )

  Ok(Committed(effects: plan.effects))
}

/// Inserts a new relationship at version 1.
fn insert_relationship(
  store: Store,
  relationship: Relationship,
  description: String,
) -> Result(Nil, Error) {
  write(
    store,
    sql.insert_relationship(
      contact: id.to_bytes(relationship.contact),
      phase: relationship_phase(relationship),
      description:,
      inbox_queue: id.to_bytes(relationship.inbox.queue),
      inbox: route.encode_inbox(relationship.inbox),
      blob: secret.expose(snapshot.encode_relationship(relationship)),
    ),
  )
}

/// Replaces a relationship's state if its version is still the one the
/// transition read.
fn update_relationship(
  store: Store,
  relationship: Relationship,
  version: Int,
) -> Result(Nil, Error) {
  use rows <- result.try(query(
    store,
    sql.update_relationship(
      phase: relationship_phase(relationship),
      blob: secret.expose(snapshot.encode_relationship(relationship)),
      contact: id.to_bytes(relationship.contact),
      version:,
    ),
  ))

  one_row_or_conflict(rows)
}

/// Inserts a new offer at version 1, keeping its invitation file and inbox,
/// which are readable only while it holds its stock.
fn insert_offer(
  store: Store,
  offer: Offer,
  description: String,
) -> Result(Nil, Error) {
  // The file and the inbox exist only in the phases that hold the stock; an
  // offer that has already lost it has nothing to export or fetch.
  case offer.phase {
    offer.Provisioning(stock) | offer.Open(stock) ->
      write(
        store,
        sql.insert_offer(
          invitation: id.to_bytes(offer.id),
          phase: offer_phase(offer),
          description:,
          deadline: stock.invitation.expires_at.unix_seconds,
          inbox_queue: id.to_bytes(stock.inbox.queue),
          inbox: route.encode_inbox(stock.inbox),
          blob: secret.expose(snapshot.encode_offer(offer)),
          file: secret.expose(invitation.encode(stock.invitation)),
        ),
      )

    offer.Consumed(..) | offer.Expired ->
      Error(Corrupt("a new offer must hold its prekey stock"))
  }
}

/// Replaces an offer's state if its version is still the one read.
fn update_offer(
  store: Store,
  offer: Offer,
  version: Int,
) -> Result(Nil, Error) {
  use rows <- result.try(query(
    store,
    sql.update_offer(
      phase: offer_phase(offer),
      blob: secret.expose(snapshot.encode_offer(offer)),
      invitation: id.to_bytes(offer.id),
      version:,
    ),
  ))

  one_row_or_conflict(rows)
}

/// A state write that touched no row lost a race. The rows are whatever the
/// statement's `RETURNING` clause gave back; only their number matters.
fn one_row_or_conflict(rows: List(a)) -> Result(Nil, Error) {
  case rows {
    [_] -> Ok(Nil)
    [] | [_, ..] -> Error(Conflict)
  }
}

/// Writes one record. Records that belong to a relationship need its
/// contact, which every relationship plan supplies; a `Processed` row needs
/// none.
fn put_record(
  store: Store,
  now: Instant,
  owner: Option(Id(Contact)),
  record: Record,
) -> Result(Nil, Error) {
  // The record's own variant says which table it lands in.
  case record, owner {
    plan.Processed(queue:, envelope:, digest:, outcome:), _ ->
      write(
        store,
        sql.put_processed(
          queue: id.to_bytes(queue),
          envelope: id.to_bytes(envelope),
          digest:,
          outcome: outcome_name(outcome),
        ),
      )

    plan.Outbound(envelope:, route:, padded:, retention_deadline:, kind:),
      Some(contact)
    ->
      put_outbound(
        store,
        now,
        contact,
        envelope,
        route,
        padded,
        kind,
        retention_deadline,
      )

    plan.Delivered(
      message:,
      contact:,
      content_type:,
      payload:,
      in_reply_to:,
      status:,
      at:,
    ),
      _
    ->
      // A plain `INSERT`: `UNIQUE (contact, message_id)` makes a second
      // delivery of the same message fail the commit and roll it back. The
      // core delivers each message once, so a duplicate means the state and
      // the store have diverged, and `OR IGNORE` would hide exactly that by
      // keeping the first row.
      write(
        store,
        sql.insert_delivery(
          contact: id.to_bytes(contact),
          message_id: id.to_bytes(message),
          content_type:,
          payload: secret.expose(payload),
          in_reply_to: option.map(in_reply_to, id.to_bytes),
          status: delivery_status(status),
          received_at: at.unix_seconds,
        ),
      )

    plan.Released(contact:, messages:), _ ->
      list.try_each(messages, fn(message) {
        write(
          store,
          sql.release_delivery(
            contact: id.to_bytes(contact),
            message_id: id.to_bytes(message),
          ),
        )
      })

    // The receipt also ends the retransmit schedule of every row that
    // carries the message; a regenerated receipt for a message already
    // received changes nothing.
    plan.PeerReceived(contact:, messages:), _ ->
      list.try_each(messages, fn(message) {
        let contact = id.to_bytes(contact)
        let message_id = id.to_bytes(message)

        use _ <- result.try(write(
          store,
          sql.mark_received_by_peer(contact:, message_id:),
        ))

        // `outbox.message_id` is nullable, so sqlc makes the parameter
        // optional; a receipt always names its message.
        write(
          store,
          sql.end_message_schedules(contact:, message_id: Some(message_id)),
        )
      })

    // A fingerprint replaces the one with the same digest, which is how a
    // regenerated receipt counts. Expired fingerprints are pruned in the
    // same transaction, so the table holds only messages still alive.
    plan.Remembered(contact:, fingerprint:), _ -> {
      use _ <- result.try(write(
        store,
        sql.put_fingerprint(
          contact: id.to_bytes(contact),
          digest: fingerprint.digest,
          message_id: id.to_bytes(fingerprint.message),
          expires_at: fingerprint.expires_at.unix_seconds,
          receipts: fingerprint.receipts,
        ),
      ))

      write(store, sql.prune_fingerprints(now: now.unix_seconds))
    }

    plan.Audit(direction:, contact:, message:, content_type:, payload:, at:), _
    ->
      write(
        store,
        sql.insert_audit(
          contact: id.to_bytes(contact),
          direction: direction_name(direction),
          message_id: id.to_bytes(message),
          content_type:,
          payload: secret.expose(payload),
          at: at.unix_seconds,
        ),
      )

    // The core ignored a repeated identifier; the operator hears of it.
    plan.RepeatedMessage(contact:, message:, queue:, envelope:), _ ->
      write(
        store,
        sql.insert_incident(
          kind: incident_kind_name(RepeatedMessageId),
          queue: id.to_bytes(queue),
          envelope: id.to_bytes(envelope),
          contact: Some(id.to_bytes(contact)),
          message_id: Some(id.to_bytes(message)),
          attempts: None,
          at: now.unix_seconds,
        ),
      )

    plan.Outbound(..), None ->
      Error(Corrupt("an outbox row needs the relationship that owns it"))
  }
}

/// Inserts an outbox row, due at once, and for an application message the
/// `sent_messages` row that `status` reads.
fn put_outbound(
  store: Store,
  now: Instant,
  contact: Id(Contact),
  envelope: Id(Envelope),
  target: Route,
  padded: Padded,
  kind: plan.OutboundKind,
  deadline: Instant,
) -> Result(Nil, Error) {
  let #(kind_name, message) = outbound_kind(kind)

  use _ <- result.try(write(
    store,
    sql.insert_outbound(
      envelope: id.to_bytes(envelope),
      contact: id.to_bytes(contact),
      kind: kind_name,
      message_id: option.map(message, id.to_bytes),
      route: route.encode(target),
      padded: envelope.to_wire(padded),
      deadline: deadline.unix_seconds,
      next_attempt_at: now.unix_seconds,
    ),
  ))

  // Only application messages have a state the agent can ask about.
  case kind {
    plan.ApplicationOut(message: sent) ->
      write(
        store,
        sql.insert_sent_message(
          message_id: id.to_bytes(sent),
          contact: id.to_bytes(contact),
        ),
      )

    plan.Handshake | plan.ReceiptOut(_) | plan.ControlOut(_) -> Ok(Nil)
  }
}

// ---------------------------------------------------------- state readers

/// The relationship with this contact, if any.
///
/// ## Examples
///
/// ```gleam
/// store.relationship_by_contact(store, contact)
/// // -> Ok(Some(record))
/// ```
pub fn relationship_by_contact(
  store: Store,
  contact: Id(Contact),
) -> Result(Option(ContactRecord), Error) {
  use rows <- result.try(query(
    store,
    sql.relationship_by_contact(contact: id.to_bytes(contact)),
  ))

  rows
  |> list.map(fn(row) { #(row.version, row.description, row.blob) })
  |> one_contact(store, _)
}

/// The relationship whose inbox is this queue, if any.
///
/// ## Examples
///
/// ```gleam
/// store.relationship_by_queue(store, queue)
/// // -> Ok(None)
/// ```
pub fn relationship_by_queue(
  store: Store,
  queue: Id(Queue),
) -> Result(Option(ContactRecord), Error) {
  use rows <- result.try(query(
    store,
    sql.relationship_by_queue(inbox_queue: id.to_bytes(queue)),
  ))

  rows
  |> list.map(fn(row) { #(row.version, row.description, row.blob) })
  |> one_contact(store, _)
}

/// Every relationship, oldest first.
///
/// ## Examples
///
/// ```gleam
/// store.contacts(store)
/// // -> Ok([record])
/// ```
pub fn contacts(store: Store) -> Result(List(ContactRecord), Error) {
  use rows <- result.try(query(store, sql.relationships()))

  list.try_map(rows, fn(row) {
    contact_record(store, #(row.version, row.description, row.blob))
  })
}

/// The offer whose inbox is this queue, if any.
///
/// ## Examples
///
/// ```gleam
/// store.offer_by_queue(store, queue)
/// // -> Ok(None)
/// ```
pub fn offer_by_queue(
  store: Store,
  queue: Id(Queue),
) -> Result(Option(OfferRecord), Error) {
  use rows <- result.try(query(
    store,
    sql.offer_by_queue(inbox_queue: id.to_bytes(queue)),
  ))

  rows
  |> list.map(fn(row) { #(row.version, row.description, row.blob) })
  |> one_offer(store, _)
}

/// Offers still waiting to be redeemed whose acceptance deadline is before
/// `now`.
///
/// ## Examples
///
/// ```gleam
/// store.expirable_offers(store, now)
/// // -> Ok([])
/// ```
pub fn expirable_offers(
  store: Store,
  now: Instant,
) -> Result(List(OfferRecord), Error) {
  use rows <- result.try(query(
    store,
    sql.expirable_offers(now: now.unix_seconds),
  ))

  list.try_map(rows, fn(row) {
    offer_record(store, #(row.version, row.description, row.blob))
  })
}

/// The invitation file of an offer, once its queue exists.
///
/// ## Examples
///
/// ```gleam
/// store.invitation_file(store, invitation)
/// // -> Ok(FileReady(bytes))
/// ```
pub fn invitation_file(
  store: Store,
  invitation: Id(InvitationKind),
) -> Result(InvitationFile, Error) {
  use rows <- result.try(query(
    store,
    sql.invitation_file(invitation: id.to_bytes(invitation)),
  ))

  // The phase column says whether the file may leave the daemon yet.
  case rows {
    [sql.InvitationFile(phase: "open", file:), ..] -> Ok(FileReady(file))
    [sql.InvitationFile(phase: "provisioning", file: _), ..] -> Ok(FileNotYet)
    [sql.InvitationFile(..), ..] | [] -> Ok(FileGone)
  }
}

/// The inboxes the daemon should be fetching from: open offers and
/// relationships that have a session.
///
/// ## Examples
///
/// ```gleam
/// store.live_inboxes(store)
/// // -> Ok([inbox])
/// ```
pub fn live_inboxes(store: Store) -> Result(List(Inbox), Error) {
  use rows <- result.try(query(store, sql.live_inboxes()))
  decode_inboxes(list.map(rows, fn(row) { row.inbox }))
}

/// The inboxes whose queue the mailbox has not been asked to create yet:
/// offers still `Provisioning` and relationships still `Joining`.
///
/// ## Examples
///
/// ```gleam
/// store.pending_inboxes(store)
/// // -> Ok([inbox])
/// ```
pub fn pending_inboxes(store: Store) -> Result(List(Inbox), Error) {
  use rows <- result.try(query(store, sql.pending_inboxes()))
  decode_inboxes(list.map(rows, fn(row) { row.inbox }))
}

/// Decodes the stored inbox columns an inbox query selected.
fn decode_inboxes(rows: List(BitArray)) -> Result(List(Inbox), Error) {
  list.try_map(rows, fn(bytes) {
    route.decode_inbox(bytes)
    |> result.replace_error(Corrupt("a stored inbox does not decode"))
  })
}

// ----------------------------------------------------------- the outbox

/// The queued rows whose time has come, oldest first. A scheduler sends only
/// what this returns, and everything here was committed.
///
/// ## Examples
///
/// ```gleam
/// store.due(store, now, 8)
/// // -> Ok([row])
/// ```
pub fn due(
  store: Store,
  now: Instant,
  limit: Int,
) -> Result(List(OutboxRow), Error) {
  use rows <- result.try(query(
    store,
    sql.due(now: now.unix_seconds, max: limit),
  ))

  list.try_map(rows, fn(row) {
    use envelope <- result.try(
      id.from_bytes(row.envelope)
      |> result.map_error(fn(_) { corrupt("outbox") }),
    )
    use route <- result.try(
      route.decode(row.route) |> result.map_error(fn(_) { corrupt("outbox") }),
    )
    use padded <- result.try(
      envelope.from_wire(row.padded)
      |> result.map_error(fn(_) { corrupt("outbox") }),
    )

    Ok(OutboxRow(
      envelope:,
      route:,
      padded:,
      deadline: Instant(row.deadline),
      attempts: row.attempts,
    ))
  })
}

/// Applies the scheduler's report on one row, and moves the message state
/// with it: `stored_by_mailbox` only from `locally_queued`, so a receipt
/// that already arrived is never downgraded, and `failed` likewise. A row
/// the mailbox stored at `now` is scheduled to be sent again
/// (`retransmit.due_at`), unless its peer already receipted it.
///
/// ## Examples
///
/// ```gleam
/// store.record_send(store, now, envelope, store.Rejected)
/// // -> Ok(Nil)
/// ```
pub fn record_send(
  store: Store,
  now: Instant,
  envelope: Id(Envelope),
  outcome: SendOutcome,
) -> Result(Nil, Error) {
  let key = id.to_bytes(envelope)

  // One transaction per report, so a row never says `stored` while its
  // message still says `locally_queued`.
  transaction(store, fn() {
    // The outcome decides the row's status and the message's next state.
    case outcome {
      Stored(receipt:) -> {
        use due <- result.try(retransmit_schedule(store, now, envelope))
        use _ <- result.try(write(
          store,
          sql.mark_stored(
            receipt: Some(receipt),
            retransmit_at: option.map(due, fn(at) { at.unix_seconds }),
            envelope: key,
          ),
        ))
        advance_message(store, key, "stored_by_mailbox")
      }

      Rejected -> {
        use _ <- result.try(write(store, sql.mark_failed(envelope: key)))
        advance_message(store, key, "failed")
      }

      Retry(attempts:, next_attempt_at:) ->
        write(
          store,
          sql.reschedule(
            attempts:,
            next_attempt_at: next_attempt_at.unix_seconds,
            envelope: key,
          ),
        )
    }
  })
}

/// When a row the mailbox stored at `now` is due to be sent again, if ever:
/// `retransmit.due_at` over the row's kind, copies so far and deadline, and
/// never for a message its peer already receipted, which can happen when the
/// receipt overtakes the scheduler's report of the mailbox's answer.
fn retransmit_schedule(
  store: Store,
  now: Instant,
  envelope: Id(Envelope),
) -> Result(Option(Instant), Error) {
  use rows <- result.try(query(
    store,
    sql.retransmit_schedule(envelope: id.to_bytes(envelope)),
  ))

  // A row that is gone has nothing to schedule; a receipted message needs
  // no copy.
  case rows {
    [] -> Ok(None)

    [sql.RetransmitSchedule(receipted: True, ..), ..] -> Ok(None)

    [sql.RetransmitSchedule(receipted: False, ..) as row, ..] -> {
      use kind <- result.try(outbound_kind_of(row.kind, row.message_id))

      Ok(retransmit.due_at(
        limits.receipt_window_seconds,
        kind,
        now,
        row.retransmits,
        Instant(row.deadline),
      ))
    }
  }
}

/// The stored rows whose retransmit is due at `now`, earliest first, at
/// most `limit` of them.
///
/// ## Examples
///
/// ```gleam
/// store.due_retransmits(store, now, 16)
/// // -> Ok([DueRetransmit(contact, row)])
/// ```
pub fn due_retransmits(
  store: Store,
  now: Instant,
  limit: Int,
) -> Result(List(DueRetransmit), Error) {
  // sqlc types the bound instant by the column it is compared with, and
  // `retransmit_at` is nullable, so the generated parameter is optional.
  use rows <- result.try(query(
    store,
    sql.due_retransmits(now: Some(now.unix_seconds), max: limit),
  ))

  list.try_map(rows, fn(row) {
    use envelope <- result.try(
      id.from_bytes(row.envelope)
      |> result.map_error(fn(_) { corrupt("outbox") }),
    )
    use contact <- result.try(
      id.from_bytes(row.contact)
      |> result.map_error(fn(_) { corrupt("outbox") }),
    )
    use kind <- result.try(outbound_kind_of(row.kind, row.message_id))

    Ok(DueRetransmit(
      contact:,
      row: retransmit.Unreceipted(
        envelope:,
        kind:,
        deadline: Instant(row.deadline),
        retransmits: row.retransmits,
      ),
    ))
  })
}

/// Moves the application message behind an outbox row out of
/// `locally_queued`, and never out of a later state.
fn advance_message(
  store: Store,
  envelope: BitArray,
  to: String,
) -> Result(Nil, Error) {
  write(store, sql.advance_message(state: to, envelope:))
}

/// How many outbox rows are still waiting to be stored by a mailbox.
///
/// ## Examples
///
/// ```gleam
/// store.pending_count(store)
/// // -> Ok(0)
/// ```
pub fn pending_count(store: Store) -> Result(Int, Error) {
  use rows <- result.try(query(store, sql.pending_count()))

  rows
  |> list.map(fn(row) { row.pending })
  |> first_or(0)
  |> Ok
}

// ------------------------------------------------------- the inbound log

/// The digest an envelope was processed under, if it was.
///
/// ## Examples
///
/// ```gleam
/// store.processed_digest(store, queue, envelope)
/// // -> Ok(Some(digest))
/// ```
pub fn processed_digest(
  store: Store,
  queue: Id(Queue),
  envelope: Id(Envelope),
) -> Result(Option(BitArray), Error) {
  use rows <- result.try(query(
    store,
    sql.processed_digest(
      queue: id.to_bytes(queue),
      envelope: id.to_bytes(envelope),
    ),
  ))

  Ok(first(list.map(rows, fn(row) { row.digest })))
}

/// The fingerprint a relationship remembers for a ratchet message's digest,
/// if any. Expiry is the core's to judge (`relationship.resend_receipt`).
///
/// ## Examples
///
/// ```gleam
/// store.fingerprint(store, contact, digest)
/// // -> Ok(Some(plan.Fingerprint(..)))
/// ```
pub fn fingerprint(
  store: Store,
  contact: Id(Contact),
  digest: BitArray,
) -> Result(Option(plan.Fingerprint), Error) {
  use rows <- result.try(query(
    store,
    sql.fingerprint(contact: id.to_bytes(contact), digest:),
  ))

  // The primary key admits one row at most.
  case rows {
    [] -> Ok(None)

    [row, ..] -> {
      use message <- result.try(
        id.from_bytes(row.message_id)
        |> result.map_error(fn(_) { corrupt("fingerprints") }),
      )

      Ok(
        Some(plan.Fingerprint(
          digest:,
          message:,
          expires_at: Instant(row.expires_at),
          receipts: row.receipts,
        )),
      )
    }
  }
}

/// Whether a relationship already stored a message under `message`, held,
/// ready, consumed or recorded expired: the `IdHistory` the core's
/// `relationship.receive` is told (ADR-010). `UNIQUE (contact, message_id)`
/// admits one row at most.
///
/// ## Examples
///
/// ```gleam
/// store.message_history(store, contact, message)
/// // -> Ok(relationship.FreshId)
/// ```
pub fn message_history(
  store: Store,
  contact: Id(Contact),
  message: Id(MessageKind),
) -> Result(relationship.IdHistory, Error) {
  use rows <- result.try(query(
    store,
    sql.delivery_of(
      contact: id.to_bytes(contact),
      message_id: id.to_bytes(message),
    ),
  ))

  // Any row at all means the identifier was used.
  case rows {
    [] -> Ok(relationship.FreshId)
    [_, ..] -> Ok(relationship.UsedId)
  }
}

/// The envelopes of `queue` that are processed and committed but not yet
/// acknowledged to the mailbox. This is the only list a fetcher acknowledges
/// from.
///
/// ## Examples
///
/// ```gleam
/// store.unacked(store, queue)
/// // -> Ok([envelope])
/// ```
pub fn unacked(
  store: Store,
  queue: Id(Queue),
) -> Result(List(Id(Envelope)), Error) {
  use rows <- result.try(query(
    store,
    sql.unacked(queue: id.to_bytes(queue), max: unacked_batch),
  ))

  list.try_map(rows, fn(row) {
    id.from_bytes(row.envelope)
    |> result.map_error(fn(_) { corrupt("processed") })
  })
}

/// The most envelopes one acknowledgement names, the mailbox's own fetch
/// batch.
const unacked_batch = 16

/// Records that the mailbox acknowledged these envelopes.
///
/// ## Examples
///
/// ```gleam
/// store.mark_acked(store, queue, [envelope])
/// // -> Ok(Nil)
/// ```
pub fn mark_acked(
  store: Store,
  queue: Id(Queue),
  envelopes: List(Id(Envelope)),
) -> Result(Nil, Error) {
  transaction(store, fn() {
    list.try_each(envelopes, fn(envelope) {
      write(
        store,
        sql.mark_acked(
          queue: id.to_bytes(queue),
          envelope: id.to_bytes(envelope),
        ),
      )
    })
  })
}

// ------------------------------------------------- what the agent reads

/// Ready deliveries, oldest first, for one contact or for all of them.
///
/// ## Examples
///
/// ```gleam
/// store.ready_deliveries(store, None, 10)
/// // -> Ok([record])
/// ```
pub fn ready_deliveries(
  store: Store,
  contact: Option(Id(Contact)),
  max: Int,
) -> Result(List(DeliveryRecord), Error) {
  use rows <- result.try(query(
    store,
    sql.ready_deliveries(contact: option.map(contact, id.to_bytes), max:),
  ))

  list.try_map(rows, delivery_record)
}

/// Marks a ready delivery consumed. `False` when no ready delivery has this
/// identifier, which includes a held one: the agent cannot consume what it
/// has not been shown.
///
/// ## Examples
///
/// ```gleam
/// store.consume(store, message)
/// // -> Ok(True)
/// ```
pub fn consume(store: Store, message: Id(MessageKind)) -> Result(Bool, Error) {
  use rows <- result.try(query(
    store,
    sql.consume(message_id: id.to_bytes(message)),
  ))

  // An update that touched a row consumed a ready delivery.
  case rows {
    [] -> Ok(False)
    [_, ..] -> Ok(True)
  }
}

/// Where an outbound message stands, if the daemon sent it.
///
/// ## Examples
///
/// ```gleam
/// store.sent_state(store, message)
/// // -> Ok(Some(StoredByMailbox))
/// ```
pub fn sent_state(
  store: Store,
  message: Id(MessageKind),
) -> Result(Option(SentState), Error) {
  use rows <- result.try(query(
    store,
    sql.sent_state(message_id: id.to_bytes(message)),
  ))

  // The column's text names the state; any other text is a damaged row.
  case rows {
    [] -> Ok(None)

    [sql.SentState(state:), ..] ->
      case state {
        "locally_queued" -> Ok(Some(LocallyQueued))
        "stored_by_mailbox" -> Ok(Some(StoredByMailbox))
        "received_by_peer" -> Ok(Some(ReceivedByPeer))
        "failed" -> Ok(Some(Failed))
        _ -> Error(corrupt("sent_messages"))
      }
  }
}

/// The most recent audit entries, newest first.
///
/// ## Examples
///
/// ```gleam
/// store.audit(store, None, 20)
/// // -> Ok([entry])
/// ```
pub fn audit(
  store: Store,
  contact: Option(Id(Contact)),
  limit: Int,
) -> Result(List(AuditRecord), Error) {
  use rows <- result.try(query(
    store,
    sql.audit_entries(contact: option.map(contact, id.to_bytes), max: limit),
  ))

  list.try_map(rows, audit_record)
}

/// The most recent incidents, newest first (ADR-010).
///
/// ## Examples
///
/// ```gleam
/// store.incidents(store, 20)
/// // -> Ok([IncidentRecord(..)])
/// ```
pub fn incidents(
  store: Store,
  limit: Int,
) -> Result(List(IncidentRecord), Error) {
  use rows <- result.try(query(store, sql.incidents(max: limit)))

  list.try_map(rows, incident_record)
}

/// How many incidents were ever recorded, for the daemon's health.
///
/// ## Examples
///
/// ```gleam
/// store.incident_count(store)
/// // -> Ok(0)
/// ```
pub fn incident_count(store: Store) -> Result(Int, Error) {
  use rows <- result.try(query(store, sql.incident_count()))

  Ok(first_or(list.map(rows, fn(row) { row.total }), 0))
}

// ------------------------------------------------------------------ meta

/// A stored daemon-wide value, such as the agent identifier.
///
/// ## Examples
///
/// ```gleam
/// store.meta_get(store, "agent_id")
/// // -> Ok(Some(<<...>>))
/// ```
pub fn meta_get(store: Store, key: String) -> Result(Option(BitArray), Error) {
  use rows <- result.try(query(store, sql.meta_get(key:)))

  Ok(first(list.map(rows, fn(row) { row.value })))
}

/// Stores a daemon-wide value, replacing any earlier one.
///
/// ## Examples
///
/// ```gleam
/// store.meta_put(store, "agent_id", <<1:128>>)
/// // -> Ok(Nil)
/// ```
pub fn meta_put(
  store: Store,
  key: String,
  value: BitArray,
) -> Result(Nil, Error) {
  write(store, sql.meta_put(key:, value:))
}

// --------------------------------------------------------------- helpers

/// Decodes a relationship row's snapshot from its version, description and
/// blob columns, the three every state reader selects.
fn contact_record(
  store: Store,
  row: #(Int, String, BitArray),
) -> Result(ContactRecord, Error) {
  let #(version, description, blob) = row

  use relationship <- result.try(
    snapshot.decode_relationship(store.suite, blob)
    |> result.map_error(fn(_) { corrupt("relationships") }),
  )

  Ok(ContactRecord(version:, description:, relationship:))
}

/// Decodes an offer row's snapshot.
fn offer_record(
  store: Store,
  row: #(Int, String, BitArray),
) -> Result(OfferRecord, Error) {
  let #(version, description, blob) = row

  use offer <- result.try(
    snapshot.decode_offer(store.suite, blob)
    |> result.map_error(fn(_) { corrupt("offers") }),
  )

  Ok(OfferRecord(version:, description:, offer:))
}

/// The first row decoded as a relationship, or none.
fn one_contact(
  store: Store,
  rows: List(#(Int, String, BitArray)),
) -> Result(Option(ContactRecord), Error) {
  case rows {
    [] -> Ok(None)
    [row, ..] -> contact_record(store, row) |> result.map(Some)
  }
}

/// The first row decoded as an offer, or none.
fn one_offer(
  store: Store,
  rows: List(#(Int, String, BitArray)),
) -> Result(Option(OfferRecord), Error) {
  case rows {
    [] -> Ok(None)
    [row, ..] -> offer_record(store, row) |> result.map(Some)
  }
}

/// Builds a delivery record from its row, decoding each identifier.
fn delivery_record(row: sql.ReadyDeliveries) -> Result(DeliveryRecord, Error) {
  use message <- result.try(
    id.from_bytes(row.message_id)
    |> result.map_error(fn(_) { corrupt("deliveries") }),
  )
  use contact <- result.try(
    id.from_bytes(row.contact)
    |> result.map_error(fn(_) { corrupt("deliveries") }),
  )
  use in_reply_to <- result.try(optional_id(row.in_reply_to, "deliveries"))

  Ok(DeliveryRecord(
    message:,
    contact:,
    content_type: row.content_type,
    payload: secret.new(row.payload),
    in_reply_to:,
    received_at: Instant(row.received_at),
  ))
}

/// An optional identifier column of `table`: absent is fine, present must
/// decode.
fn optional_id(
  bytes: Option(BitArray),
  table: String,
) -> Result(Option(Id(kind)), Error) {
  // A reply target or an incident's contact is optional, but a stored one
  // must decode.
  case bytes {
    None -> Ok(None)

    Some(raw) ->
      id.from_bytes(raw)
      |> result.map(Some)
      |> result.map_error(fn(_) { corrupt(table) })
  }
}

/// The direction an audit row names; only the writer's two names are valid.
fn parse_direction(name: String) -> Result(Direction, Error) {
  // Any other text is a damaged row.
  case name {
    "in" -> Ok(Inbound)
    "out" -> Ok(Outbound)
    _ -> Error(corrupt("audit"))
  }
}

/// Builds an audit record from its row, decoding each identifier and the
/// direction.
fn audit_record(row: sql.AuditEntries) -> Result(AuditRecord, Error) {
  use contact <- result.try(
    id.from_bytes(row.contact) |> result.map_error(fn(_) { corrupt("audit") }),
  )
  use message <- result.try(
    id.from_bytes(row.message_id)
    |> result.map_error(fn(_) { corrupt("audit") }),
  )
  use direction <- result.try(parse_direction(row.direction))

  Ok(AuditRecord(
    contact:,
    direction:,
    message:,
    content_type: row.content_type,
    payload: secret.new(row.payload),
    at: Instant(row.at),
  ))
}

/// Builds an incident record from its row.
fn incident_record(row: sql.Incidents) -> Result(IncidentRecord, Error) {
  use kind <- result.try(parse_incident_kind(row.kind))
  use queue <- result.try(
    id.from_bytes(row.queue) |> result.map_error(fn(_) { corrupt("incidents") }),
  )
  use envelope <- result.try(
    id.from_bytes(row.envelope)
    |> result.map_error(fn(_) { corrupt("incidents") }),
  )
  use contact <- result.try(optional_id(row.contact, "incidents"))
  use message <- result.try(optional_id(row.message_id, "incidents"))

  Ok(IncidentRecord(
    kind:,
    queue:,
    envelope:,
    contact:,
    message:,
    attempts: row.attempts,
    at: Instant(row.at),
  ))
}

/// The `kind` column of an incident.
fn incident_kind_name(kind: IncidentKind) -> String {
  case kind {
    RepeatedMessageId -> "repeated_message"
  }
}

/// The incident kind a `kind` column names; only the writer's names are
/// valid.
fn parse_incident_kind(name: String) -> Result(IncidentKind, Error) {
  // Any other text is a damaged row.
  case name {
    "repeated_message" -> Ok(RepeatedMessageId)
    _ -> Error(corrupt("incidents"))
  }
}

fn corrupt(table: String) -> Error {
  Corrupt("a row of " <> table <> " does not decode")
}

/// The `phase` column of a relationship.
fn relationship_phase(relationship: Relationship) -> String {
  case relationship.phase {
    relationship.Joining(..) -> "joining"
    relationship.AwaitingAccept(_) -> "awaiting"
    relationship.PendingApproval(_) -> "pending"
    relationship.Active(_) -> "active"
    relationship.Closed(_) -> "closed"
  }
}

/// The `phase` column of an offer.
fn offer_phase(offer: Offer) -> String {
  case offer.phase {
    offer.Provisioning(_) -> "provisioning"
    offer.Open(_) -> "open"
    offer.Consumed(..) -> "consumed"
    offer.Expired -> "expired"
  }
}

fn outcome_name(outcome: plan.ProcessedOutcome) -> String {
  case outcome {
    plan.Applied -> "applied"
    plan.Dropped -> "dropped"
  }
}

/// The `status` column of a delivery.
fn delivery_status(status: plan.DeliveryStatus) -> String {
  case status {
    plan.Ready -> "ready"
    plan.Held -> "held"
    plan.Expired -> "expired"
  }
}

fn direction_name(direction: plan.Direction) -> String {
  case direction {
    plan.In -> "in"
    plan.Out -> "out"
  }
}

/// The outbox kind its `kind` and `message_id` columns name, the inverse of
/// `outbound_kind`.
fn outbound_kind_of(
  name: String,
  message: Option(BitArray),
) -> Result(plan.OutboundKind, Error) {
  // A present identifier must decode; an absent one is valid only for the
  // handshake, which the case below decides.
  let message = case message {
    Some(bytes) -> id.from_bytes(bytes) |> result.replace_error(Nil)
    None -> Error(Nil)
  }

  // Only the writer's four names are valid, and every kind but the
  // handshake names its message.
  case name, message {
    "handshake", _ -> Ok(plan.Handshake)
    "application", Ok(sent) -> Ok(plan.ApplicationOut(sent))
    "receipt", Ok(sent) -> Ok(plan.ReceiptOut(sent))
    "control", Ok(sent) -> Ok(plan.ControlOut(sent))
    _, _ -> Error(corrupt("outbox"))
  }
}

/// The `kind` column and the message an outbox row is about, if any.
fn outbound_kind(
  kind: plan.OutboundKind,
) -> #(String, Option(Id(MessageKind))) {
  case kind {
    plan.Handshake -> #("handshake", None)
    plan.ApplicationOut(message:) -> #("application", Some(message))
    plan.ReceiptOut(message:) -> #("receipt", Some(message))
    plan.ControlOut(message:) -> #("control", Some(message))
  }
}

fn first(rows: List(a)) -> Option(a) {
  case rows {
    [row, ..] -> Some(row)
    [] -> None
  }
}

fn first_or(rows: List(a), default: a) -> a {
  case rows {
    [row, ..] -> row
    [] -> default
  }
}

/// Runs hand-written SQL with no parameters and no rows: a pragma, a
/// transaction boundary, or a whole migration, which may hold several
/// statements.
fn run(store: Store, statements: String) -> Result(Nil, Error) {
  sqlight.exec(statements, on: store.connection) |> result.map_error(Sql)
}

// ---------------------------------------------------------- the bridge
//
// A generated function in `daemon/sql` returns its statement's text, its
// parameters as parrot's `dev.Param`, and, for a statement that returns rows,
// the decoder for them. `query` and `write` bind those parameters as sqlight
// values and run the statement, so values travel as bound parameters and are
// never spliced into the SQL.

/// Runs a generated statement and decodes every row it returns with the
/// decoder generated beside it.
fn query(
  store: Store,
  statement: #(String, List(Param), decode.Decoder(a)),
) -> Result(List(a), Error) {
  let #(text, parameters, decoder) = statement
  let arguments = list.map(parameters, bind)

  sqlight.query(text, on: store.connection, with: arguments, expecting: decoder)
  |> result.map_error(Sql)
}

/// Runs a generated statement for its effect.
fn write(
  store: Store,
  statement: #(String, List(Param)),
) -> Result(Nil, Error) {
  let #(text, parameters) = statement

  query(store, #(text, parameters, decode.success(Nil)))
  |> result.replace(Nil)
}

/// One generated parameter as the sqlight value it binds as.
///
/// Every table is `STRICT` over `INTEGER`, `TEXT` and `BLOB`, so sqlc types
/// each parameter as an integer, a string or a bit array, optional where
/// the column is nullable, and `daemon/internal/sql_param` has exactly
/// those variants. A statement that needed any other kind would not compile,
/// so every parameter binds and this cannot fail.
fn bind(parameter: Param) -> sqlight.Value {
  case parameter {
    sql_param.ParamInt(value) -> sqlight.int(value)
    sql_param.ParamString(value) -> sqlight.text(value)
    sql_param.ParamBitArray(value) -> sqlight.blob(value)
    sql_param.ParamNullable(Some(inner)) -> bind(inner)
    sql_param.ParamNullable(None) -> sqlight.null()
  }
}

/// Reads one integer pragma, such as `user_version`. A pragma's name is
/// composed here, so it is the one read that does not come from
/// `daemon/sql`.
fn pragma_int(store: Store, name: String) -> Result(Int, Error) {
  use rows <- result.try(
    query(store, #("PRAGMA " <> name, [], decode.at([0], decode.int))),
  )

  first_or_corrupt(rows, name)
}

/// Reads one text pragma, such as `journal_mode`.
fn pragma_text(store: Store, name: String) -> Result(String, Error) {
  use rows <- result.try(
    query(store, #("PRAGMA " <> name, [], decode.at([0], decode.string))),
  )

  first_or_corrupt(rows, name)
}

fn first_or_corrupt(rows: List(a), name: String) -> Result(a, Error) {
  case rows {
    [row, ..] -> Ok(row)
    [] -> Error(Corrupt("pragma " <> name <> " returned no row"))
  }
}

/// An encoded `Appended` response, for the receipt column.
///
/// ## Examples
///
/// ```gleam
/// store.receipt_bytes(receipt)
/// // -> <<...>>
/// ```
pub fn receipt_bytes(receipt: protocol.AppendReceipt) -> BitArray {
  codec.encode_response(protocol.Appended(receipt:))
}
