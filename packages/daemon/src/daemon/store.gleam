//// The daemon's durable state: one SQLite file, the typed statements that
//// read and write it, and `commit`, the only way a `Plan` becomes durable
//// (spec §8.1, §8.2, §8.3).
////
//// This module owns the schema, the durability pragmas and every SQL string
//// in the daemon. Nothing above it writes SQL, and nothing below it knows
//// what a transition is. The shape follows `mailbox/store`: a connection
//// held by exactly one process (the engine), pragmas that make a commit
//// durable (a write-ahead log, `synchronous=FULL`, `fullfsync` because
//// macOS `fsync` does not flush the drive cache), and `user_version`
//// migrations that refuse a file written by a newer build.
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
//// ## Secrets
////
//// The blobs hold identity keys, ratchet state and capabilities, and
//// `deliveries` and `audit` hold plaintext, as the owner ruled for the audit
//// log. All of it is protected by file permissions alone (see
//// `daemon/config`). Error values here name tables and statements and never
//// a bound value, so none of it can reach a log through an error.
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
import core/mailbox/codec
import core/mailbox/protocol
import core/offer.{type Offer}
import core/plan.{type Effect, type EnvelopeRef, type Plan, type Record}
import core/relationship.{type Relationship}
import core/route.{type Inbox, type Route}
import core/secret
import core/snapshot
import core/time.{type Instant, Instant}
import gleam/dynamic/decode
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import sqlight

/// The schema version this build writes and understands.
pub const schema_version = 1

/// How long SQLite waits on a locked database before giving up. Only an
/// outside process can contend with the engine, so this is a courtesy.
pub const busy_timeout_ms = 5000

/// An open daemon database. The suite is held only to rebuild typed values
/// from snapshot blobs.
pub opaque type Store {
  Store(connection: sqlight.Connection, suite: Suite)
}

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

/// What `invitation_file` found.
pub type InvitationFile {
  /// The offer is open: the file may be handed out.
  FileReady(bytes: BitArray)

  /// The offer's queue is still being created.
  FileNotYet

  /// The offer is consumed or expired, or there is none.
  FileGone
}

/// The statements that bring an empty database to each version. Entry `n`
/// moves version `n` to `n + 1`, so the list is append-only.
const migrations = [
  "
CREATE TABLE meta (
  key TEXT NOT NULL PRIMARY KEY,
  value BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE relationships (
  contact BLOB NOT NULL PRIMARY KEY,
  version INTEGER NOT NULL,
  phase TEXT NOT NULL,
  description TEXT NOT NULL,
  inbox_queue BLOB NOT NULL UNIQUE,
  inbox BLOB NOT NULL,
  blob BLOB NOT NULL
) STRICT;

CREATE TABLE offers (
  invitation BLOB NOT NULL PRIMARY KEY,
  version INTEGER NOT NULL,
  phase TEXT NOT NULL,
  description TEXT NOT NULL,
  deadline INTEGER NOT NULL,
  inbox_queue BLOB NOT NULL UNIQUE,
  inbox BLOB NOT NULL,
  blob BLOB NOT NULL,
  file BLOB NOT NULL
) STRICT;

CREATE TABLE outbox (
  envelope BLOB NOT NULL PRIMARY KEY,
  contact BLOB NOT NULL,
  kind TEXT NOT NULL,
  message_id BLOB,
  route BLOB NOT NULL,
  padded BLOB NOT NULL,
  deadline INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'stored', 'failed')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at INTEGER NOT NULL,
  receipt BLOB
) STRICT;

CREATE INDEX outbox_due ON outbox (status, next_attempt_at);

CREATE TABLE processed (
  queue BLOB NOT NULL,
  envelope BLOB NOT NULL,
  digest BLOB NOT NULL,
  outcome TEXT NOT NULL,
  acked INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (queue, envelope)
) STRICT, WITHOUT ROWID;

CREATE TABLE deliveries (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  contact BLOB NOT NULL,
  message_id BLOB NOT NULL,
  content_type TEXT NOT NULL,
  payload BLOB NOT NULL,
  in_reply_to BLOB,
  status TEXT NOT NULL
    CHECK (status IN ('ready', 'held', 'expired', 'consumed')),
  received_at INTEGER NOT NULL,
  UNIQUE (contact, message_id)
) STRICT;

CREATE TABLE sent_messages (
  message_id BLOB NOT NULL PRIMARY KEY,
  contact BLOB NOT NULL,
  state TEXT NOT NULL CHECK (
    state IN ('locally_queued', 'stored_by_mailbox', 'received_by_peer',
              'failed')
  )
) STRICT;

CREATE TABLE audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  contact BLOB NOT NULL,
  direction TEXT NOT NULL,
  message_id BLOB NOT NULL,
  content_type TEXT NOT NULL,
  payload BLOB NOT NULL,
  at INTEGER NOT NULL
) STRICT;
",
]

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
  use connection <- result.try(sqlight.open(path) |> result.map_error(Sql))
  let store = Store(connection:, suite:)

  // A failure after the connection exists must not leak it: the file would
  // stay locked until the process exits.
  case configure(store) |> result.try(fn(_) { migrate(store) }) {
    Ok(Nil) -> Ok(store)

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
    False -> apply_migrations(store, list.drop(migrations, found), found)
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
  }
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
    "INSERT INTO relationships
       (contact, version, phase, description, inbox_queue, inbox, blob)
     VALUES (?, 1, ?, ?, ?, ?, ?)",
    [
      sqlight.blob(id.to_bytes(relationship.contact)),
      sqlight.text(relationship_phase(relationship)),
      sqlight.text(description),
      sqlight.blob(id.to_bytes(relationship.inbox.queue)),
      sqlight.blob(route.encode_inbox(relationship.inbox)),
      sqlight.blob(secret.expose(snapshot.encode_relationship(relationship))),
    ],
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
    "UPDATE relationships
     SET version = version + 1, phase = ?, blob = ?
     WHERE contact = ? AND version = ?
     RETURNING version",
    [
      sqlight.text(relationship_phase(relationship)),
      sqlight.blob(secret.expose(snapshot.encode_relationship(relationship))),
      sqlight.blob(id.to_bytes(relationship.contact)),
      sqlight.int(version),
    ],
    decode.success(Nil),
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
        "INSERT INTO offers
           (invitation, version, phase, description, deadline, inbox_queue,
            inbox, blob, file)
         VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)",
        [
          sqlight.blob(id.to_bytes(offer.id)),
          sqlight.text(offer_phase(offer)),
          sqlight.text(description),
          sqlight.int(stock.invitation.expires_at.unix_seconds),
          sqlight.blob(id.to_bytes(stock.inbox.queue)),
          sqlight.blob(route.encode_inbox(stock.inbox)),
          sqlight.blob(secret.expose(snapshot.encode_offer(offer))),
          sqlight.blob(secret.expose(invitation.encode(stock.invitation))),
        ],
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
    "UPDATE offers
     SET version = version + 1, phase = ?, blob = ?
     WHERE invitation = ? AND version = ?
     RETURNING version",
    [
      sqlight.text(offer_phase(offer)),
      sqlight.blob(secret.expose(snapshot.encode_offer(offer))),
      sqlight.blob(id.to_bytes(offer.id)),
      sqlight.int(version),
    ],
    decode.success(Nil),
  ))

  one_row_or_conflict(rows)
}

/// A state write that touched no row lost a race.
fn one_row_or_conflict(rows: List(Nil)) -> Result(Nil, Error) {
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
        "INSERT OR REPLACE INTO processed
           (queue, envelope, digest, outcome, acked)
         VALUES (?, ?, ?, ?, 0)",
        [
          sqlight.blob(id.to_bytes(queue)),
          sqlight.blob(id.to_bytes(envelope)),
          sqlight.blob(digest),
          sqlight.text(outcome_name(outcome)),
        ],
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
      write(
        store,
        "INSERT OR IGNORE INTO deliveries
           (contact, message_id, content_type, payload, in_reply_to, status,
            received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          sqlight.blob(id.to_bytes(contact)),
          sqlight.blob(id.to_bytes(message)),
          sqlight.text(content_type),
          sqlight.blob(secret.expose(payload)),
          sqlight.nullable(sqlight.blob, option.map(in_reply_to, id.to_bytes)),
          sqlight.text(delivery_status(status)),
          sqlight.int(at.unix_seconds),
        ],
      )

    plan.Released(contact:, messages:), _ ->
      list.try_each(messages, fn(message) {
        write(
          store,
          "UPDATE deliveries SET status = 'ready'
           WHERE contact = ? AND message_id = ? AND status = 'held'",
          [
            sqlight.blob(id.to_bytes(contact)),
            sqlight.blob(id.to_bytes(message)),
          ],
        )
      })

    plan.PeerReceived(contact:, messages:), _ ->
      list.try_each(messages, fn(message) {
        write(
          store,
          "UPDATE sent_messages SET state = 'received_by_peer'
           WHERE contact = ? AND message_id = ?",
          [
            sqlight.blob(id.to_bytes(contact)),
            sqlight.blob(id.to_bytes(message)),
          ],
        )
      })

    plan.Audit(direction:, contact:, message:, content_type:, payload:, at:), _
    ->
      write(
        store,
        "INSERT INTO audit
           (contact, direction, message_id, content_type, payload, at)
         VALUES (?, ?, ?, ?, ?, ?)",
        [
          sqlight.blob(id.to_bytes(contact)),
          sqlight.text(direction_name(direction)),
          sqlight.blob(id.to_bytes(message)),
          sqlight.text(content_type),
          sqlight.blob(secret.expose(payload)),
          sqlight.int(at.unix_seconds),
        ],
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

  use _ <- result.try(
    write(
      store,
      "INSERT INTO outbox
       (envelope, contact, kind, message_id, route, padded, deadline, status,
        attempts, next_attempt_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', 0, ?)",
      [
        sqlight.blob(id.to_bytes(envelope)),
        sqlight.blob(id.to_bytes(contact)),
        sqlight.text(kind_name),
        sqlight.nullable(sqlight.blob, option.map(message, id.to_bytes)),
        sqlight.blob(route.encode(target)),
        sqlight.blob(envelope.to_wire(padded)),
        sqlight.int(deadline.unix_seconds),
        sqlight.int(now.unix_seconds),
      ],
    ),
  )

  // Only application messages have a state the agent can ask about.
  case kind {
    plan.ApplicationOut(message: sent) ->
      write(
        store,
        "INSERT INTO sent_messages (message_id, contact, state)
         VALUES (?, ?, 'locally_queued')",
        [
          sqlight.blob(id.to_bytes(sent)),
          sqlight.blob(id.to_bytes(contact)),
        ],
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
    "SELECT version, description, blob FROM relationships WHERE contact = ?",
    [sqlight.blob(id.to_bytes(contact))],
    contact_row(),
  ))

  one_contact(store, rows)
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
    "SELECT version, description, blob FROM relationships
     WHERE inbox_queue = ?",
    [sqlight.blob(id.to_bytes(queue))],
    contact_row(),
  ))

  one_contact(store, rows)
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
  use rows <- result.try(query(
    store,
    "SELECT version, description, blob FROM relationships ORDER BY rowid",
    [],
    contact_row(),
  ))

  list.try_map(rows, fn(row) { contact_record(store, row) })
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
    "SELECT version, description, blob FROM offers WHERE inbox_queue = ?",
    [sqlight.blob(id.to_bytes(queue))],
    contact_row(),
  ))

  one_offer(store, rows)
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
    "SELECT version, description, blob FROM offers
     WHERE phase IN ('provisioning', 'open') AND deadline < ?",
    [sqlight.int(now.unix_seconds)],
    contact_row(),
  ))

  list.try_map(rows, fn(row) { offer_record(store, row) })
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
  let row = {
    use phase <- decode.field(0, decode.string)
    use file <- decode.field(1, decode.bit_array)
    decode.success(#(phase, file))
  }

  use rows <- result.try(query(
    store,
    "SELECT phase, file FROM offers WHERE invitation = ?",
    [sqlight.blob(id.to_bytes(invitation))],
    row,
  ))

  // The phase column says whether the file may leave the daemon yet.
  case rows {
    [#("open", file), ..] -> Ok(FileReady(file))
    [#("provisioning", _), ..] -> Ok(FileNotYet)
    [#(_, _), ..] | [] -> Ok(FileGone)
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
  inboxes(
    store,
    "SELECT inbox FROM offers WHERE phase = 'open'
     UNION ALL
     SELECT inbox FROM relationships
     WHERE phase IN ('awaiting', 'pending', 'active')",
  )
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
  inboxes(
    store,
    "SELECT inbox FROM offers WHERE phase = 'provisioning'
     UNION ALL
     SELECT inbox FROM relationships WHERE phase = 'joining'",
  )
}

/// Runs a query that selects one inbox column and decodes each value.
fn inboxes(store: Store, sql: String) -> Result(List(Inbox), Error) {
  use rows <- result.try(query(
    store,
    sql,
    [],
    decode.field(0, decode.bit_array, decode.success),
  ))

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
  let row = {
    use envelope <- decode.field(0, decode.bit_array)
    use route <- decode.field(1, decode.bit_array)
    use padded <- decode.field(2, decode.bit_array)
    use deadline <- decode.field(3, decode.int)
    use attempts <- decode.field(4, decode.int)
    decode.success(#(envelope, route, padded, deadline, attempts))
  }

  use rows <- result.try(query(
    store,
    "SELECT envelope, route, padded, deadline, attempts FROM outbox
     WHERE status = 'queued' AND next_attempt_at <= ?
     ORDER BY rowid LIMIT ?",
    [sqlight.int(now.unix_seconds), sqlight.int(limit)],
    row,
  ))

  list.try_map(rows, fn(columns) {
    let #(envelope, route_bytes, padded, deadline, attempts) = columns

    use envelope <- result.try(
      id.from_bytes(envelope) |> result.map_error(fn(_) { corrupt("outbox") }),
    )
    use route <- result.try(
      route.decode(route_bytes) |> result.map_error(fn(_) { corrupt("outbox") }),
    )
    use padded <- result.try(
      envelope.from_wire(padded)
      |> result.map_error(fn(_) { corrupt("outbox") }),
    )

    Ok(OutboxRow(
      envelope:,
      route:,
      padded:,
      deadline: Instant(deadline),
      attempts:,
    ))
  })
}

/// Applies the scheduler's report on one row, and moves the message state
/// with it: `stored_by_mailbox` only from `locally_queued`, so a receipt
/// that already arrived is never downgraded, and `failed` likewise.
///
/// ## Examples
///
/// ```gleam
/// store.record_send(store, envelope, store.Rejected)
/// // -> Ok(Nil)
/// ```
pub fn record_send(
  store: Store,
  envelope: Id(Envelope),
  outcome: SendOutcome,
) -> Result(Nil, Error) {
  let key = sqlight.blob(id.to_bytes(envelope))

  // One transaction per report, so a row never says `stored` while its
  // message still says `locally_queued`.
  transaction(store, fn() {
    // The outcome decides the row's status and the message's next state.
    case outcome {
      Stored(receipt:) -> {
        use _ <- result.try(
          write(
            store,
            "UPDATE outbox SET status = 'stored', receipt = ? WHERE envelope = ?",
            [sqlight.blob(receipt), key],
          ),
        )
        advance_message(store, key, "stored_by_mailbox")
      }

      Rejected -> {
        use _ <- result.try(
          write(
            store,
            "UPDATE outbox SET status = 'failed' WHERE envelope = ?",
            [key],
          ),
        )
        advance_message(store, key, "failed")
      }

      Retry(attempts:, next_attempt_at:) ->
        write(
          store,
          "UPDATE outbox SET attempts = ?, next_attempt_at = ?
           WHERE envelope = ?",
          [
            sqlight.int(attempts),
            sqlight.int(next_attempt_at.unix_seconds),
            key,
          ],
        )
    }
  })
}

/// Moves the application message behind an outbox row out of
/// `locally_queued`, and never out of a later state.
fn advance_message(
  store: Store,
  envelope_key: sqlight.Value,
  to: String,
) -> Result(Nil, Error) {
  write(
    store,
    "UPDATE sent_messages SET state = ?
     WHERE state = 'locally_queued'
       AND message_id = (SELECT message_id FROM outbox WHERE envelope = ?)",
    [sqlight.text(to), envelope_key],
  )
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
  use rows <- result.try(query(
    store,
    "SELECT COUNT(*) FROM outbox WHERE status = 'queued'",
    [],
    decode.field(0, decode.int, decode.success),
  ))

  Ok(first_or(rows, 0))
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
    "SELECT digest FROM processed WHERE queue = ? AND envelope = ?",
    [
      sqlight.blob(id.to_bytes(queue)),
      sqlight.blob(id.to_bytes(envelope)),
    ],
    decode.field(0, decode.bit_array, decode.success),
  ))

  Ok(first(rows))
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
    "SELECT envelope FROM processed
     WHERE queue = ? AND acked = 0 LIMIT ?",
    [sqlight.blob(id.to_bytes(queue)), sqlight.int(unacked_batch)],
    decode.field(0, decode.bit_array, decode.success),
  ))

  list.try_map(rows, fn(bytes) {
    id.from_bytes(bytes) |> result.map_error(fn(_) { corrupt("processed") })
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
        "UPDATE processed SET acked = 1 WHERE queue = ? AND envelope = ?",
        [
          sqlight.blob(id.to_bytes(queue)),
          sqlight.blob(id.to_bytes(envelope)),
        ],
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
  let row = {
    use message <- decode.field(0, decode.bit_array)
    use contact <- decode.field(1, decode.bit_array)
    use content_type <- decode.field(2, decode.string)
    use payload <- decode.field(3, decode.bit_array)
    use in_reply_to <- decode.field(4, decode.optional(decode.bit_array))
    use received_at <- decode.field(5, decode.int)
    decode.success(#(
      message,
      contact,
      content_type,
      payload,
      in_reply_to,
      received_at,
    ))
  }

  use rows <- result.try(query(
    store,
    "SELECT message_id, contact, content_type, payload, in_reply_to,
            received_at
     FROM deliveries
     WHERE status = 'ready' AND (?1 IS NULL OR contact = ?1)
     ORDER BY seq LIMIT ?2",
    [
      sqlight.nullable(sqlight.blob, option.map(contact, id.to_bytes)),
      sqlight.int(max),
    ],
    row,
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
    "UPDATE deliveries SET status = 'consumed'
     WHERE message_id = ? AND status = 'ready'
     RETURNING seq",
    [sqlight.blob(id.to_bytes(message))],
    decode.success(Nil),
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
    "SELECT state FROM sent_messages WHERE message_id = ?",
    [sqlight.blob(id.to_bytes(message))],
    decode.field(0, decode.string, decode.success),
  ))

  // The column's text names the state; any other text is a damaged row.
  case rows {
    [] -> Ok(None)

    [name, ..] ->
      case name {
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
  let row = {
    use contact <- decode.field(0, decode.bit_array)
    use direction <- decode.field(1, decode.string)
    use message <- decode.field(2, decode.bit_array)
    use content_type <- decode.field(3, decode.string)
    use payload <- decode.field(4, decode.bit_array)
    use at <- decode.field(5, decode.int)
    decode.success(#(contact, direction, message, content_type, payload, at))
  }

  use rows <- result.try(query(
    store,
    "SELECT contact, direction, message_id, content_type, payload, at
     FROM audit
     WHERE (?1 IS NULL OR contact = ?1)
     ORDER BY seq DESC LIMIT ?2",
    [
      sqlight.nullable(sqlight.blob, option.map(contact, id.to_bytes)),
      sqlight.int(limit),
    ],
    row,
  ))

  list.try_map(rows, audit_record)
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
  use rows <- result.try(query(
    store,
    "SELECT value FROM meta WHERE key = ?",
    [sqlight.text(key)],
    decode.field(0, decode.bit_array, decode.success),
  ))

  Ok(first(rows))
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
  write(store, "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", [
    sqlight.text(key),
    sqlight.blob(value),
  ])
}

// --------------------------------------------------------------- helpers

/// The raw columns of a state row: version, description, blob.
fn contact_row() -> decode.Decoder(#(Int, String, BitArray)) {
  use version <- decode.field(0, decode.int)
  use description <- decode.field(1, decode.string)
  use blob <- decode.field(2, decode.bit_array)
  decode.success(#(version, description, blob))
}

/// Decodes a relationship row's snapshot.
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

/// Builds a delivery record from its raw columns.
fn delivery_record(
  columns: #(BitArray, BitArray, String, BitArray, Option(BitArray), Int),
) -> Result(DeliveryRecord, Error) {
  let #(message, contact, content_type, payload, in_reply_to, received_at) =
    columns

  use message <- result.try(
    id.from_bytes(message) |> result.map_error(fn(_) { corrupt("deliveries") }),
  )
  use contact <- result.try(
    id.from_bytes(contact) |> result.map_error(fn(_) { corrupt("deliveries") }),
  )
  use in_reply_to <- result.try(optional_id(in_reply_to))

  Ok(DeliveryRecord(
    message:,
    contact:,
    content_type:,
    payload: secret.new(payload),
    in_reply_to:,
    received_at: Instant(received_at),
  ))
}

/// An optional identifier column: absent is fine, present must decode.
fn optional_id(bytes: Option(BitArray)) -> Result(Option(Id(kind)), Error) {
  // A reply target is optional, but a stored one must decode.
  case bytes {
    None -> Ok(None)

    Some(raw) ->
      id.from_bytes(raw)
      |> result.map(Some)
      |> result.map_error(fn(_) { corrupt("deliveries") })
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

/// Builds an audit record from its raw columns.
fn audit_record(
  columns: #(BitArray, String, BitArray, String, BitArray, Int),
) -> Result(AuditRecord, Error) {
  let #(contact, direction, message, content_type, payload, at) = columns

  use contact <- result.try(
    id.from_bytes(contact) |> result.map_error(fn(_) { corrupt("audit") }),
  )
  use message <- result.try(
    id.from_bytes(message) |> result.map_error(fn(_) { corrupt("audit") }),
  )
  use direction <- result.try(parse_direction(direction))

  Ok(AuditRecord(
    contact:,
    direction:,
    message:,
    content_type:,
    payload: secret.new(payload),
    at: Instant(at),
  ))
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

fn run(store: Store, sql: String) -> Result(Nil, Error) {
  sqlight.exec(sql, on: store.connection) |> result.map_error(Sql)
}

/// Runs a statement for its effect and discards any rows.
fn write(
  store: Store,
  sql: String,
  arguments: List(sqlight.Value),
) -> Result(Nil, Error) {
  query(store, sql, arguments, decode.success(Nil))
  |> result.replace(Nil)
}

/// Runs a parameterized statement and decodes every row with `decoder`.
/// Values travel as bound parameters, never spliced into the SQL.
fn query(
  store: Store,
  sql: String,
  arguments: List(sqlight.Value),
  decoder: decode.Decoder(a),
) -> Result(List(a), Error) {
  sqlight.query(sql, on: store.connection, with: arguments, expecting: decoder)
  |> result.map_error(Sql)
}

/// Reads one integer pragma, such as `user_version`.
fn pragma_int(store: Store, name: String) -> Result(Int, Error) {
  use rows <- result.try(query(
    store,
    "PRAGMA " <> name,
    [],
    decode.field(0, decode.int, decode.success),
  ))

  first_or_corrupt(rows, name)
}

/// Reads one text pragma, such as `journal_mode`.
fn pragma_text(store: Store, name: String) -> Result(String, Error) {
  use rows <- result.try(query(
    store,
    "PRAGMA " <> name,
    [],
    decode.field(0, decode.string, decode.success),
  ))

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
