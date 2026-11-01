//// The mailbox's durable state: one SQLite file and the typed statements
//// that read and write it (spec §8.1).
////
//// This module owns the schema, the pragmas that make a commit durable, and
//// every SQL string in the package. Nothing above it writes SQL, and nothing
//// below it knows what a request is. That split is what lets `mailbox/service`
//// state the protocol's rules as plain functions of a `Store`, and lets the
//// storage coordinator be the only process that ever holds one.
////
//// Three decisions shape the file:
////
//// - Durability is configured, then read back by tests. The journal is a
////   write-ahead log, `synchronous` is `FULL` so a commit is on disk before
////   it returns, and `fullfsync` is on because macOS `fsync` does not flush
////   the drive cache (design review B, §3.10). The pragma is harmless on
////   other platforms.
//// - Capabilities are stored only as SHA-256 hashes. A copy of this file
////   therefore grants no authority; the hash of a 256-bit random value
////   cannot be inverted into the value.
//// - A multi-statement change is one `transaction`, begun `IMMEDIATE` so the
////   write lock is taken up front and a later statement can never fail for
////   want of it. The body is an ordinary function that runs to the end in
////   one call, so a transaction never spans a process hop.
////
//// Functions that change state assume the caller opened a transaction; they
//// are individually correct only inside one.
////
//// ## The fault hook
////
//// `open_with` takes an optional `Faults` hook for a deterministic
//// simulation, and `open` is `open_with` without one. `transaction`
//// consults the hook once per transaction, through `faulted`: `Down` fails
//// before `BEGIN` and writes nothing, `AckLost` commits and then fails, and
//// both return the I/O error `injected` builds. The migrations run before
//// the hook is attached, and a production store has no hook.
////
//// ## Flow
////
//// 1. `open` configures the connection and migrates the schema through
////    `PRAGMA user_version`.
//// 2. `transaction` wraps one change, and `put_envelope` and
////    `remove_envelope` are the row-level steps `mailbox/service` calls
////    inside it, in the order the protocol needs.
//// 3. `sweep` is the one maintenance change, a transaction of its own.

import core/envelope.{type StoredEnvelope, StoredEnvelope}
import core/id.{type Envelope, type Id, type Queue}
import core/time.{type Instant, Instant}
import gleam/bit_array
import gleam/dynamic/decode
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import sqlight

/// The schema version this build writes and understands.
pub const schema_version = 1

/// How long SQLite waits on a locked database before giving up. Only an
/// outside process (a backup tool, a stray `sqlite3` shell) can contend with
/// the coordinator, so this is a courtesy, not a queue.
pub const busy_timeout_ms = 5000

/// An open mailbox database.
pub opaque type Store {
  Store(connection: sqlight.Connection, faults: Option(Faults))
}

/// What a fault hook makes of one transaction. Only a simulation sets a
/// hook; a production store runs every transaction as written.
pub type Fate {
  /// Run the transaction as written.
  Proceed

  /// Fail before `BEGIN`: nothing is written and the caller gets an error.
  Down

  /// Run and commit the transaction, then return an error: written, but the
  /// caller cannot tell this from `Down`.
  AckLost
}

/// A fault hook, consulted once per transaction after the store is open.
pub type Faults =
  fn() -> Fate

/// Why a storage operation failed.
pub type Error {
  /// SQLite reported an error. Messages name tables and statements, never
  /// bound values, so no capability can appear here.
  Sql(error: sqlight.Error)

  /// The file was written by a newer build than this one.
  FutureSchema(found: Int, supported: Int)

  /// A stored value does not decode as what its column promises, which means
  /// the file was damaged or written by something else.
  Corrupt(detail: String)
}

/// The durability settings in effect on a connection, as SQLite reports
/// them.
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

/// A provisioning grant: how many queues the holder may still create.
pub type Grant {
  Grant(allowance: Int, queues_used: Int)
}

/// A queue's row. The three hashes are SHA-256 of the capabilities, never
/// the capabilities themselves.
pub type QueueRecord {
  QueueRecord(
    queue: Id(Queue),
    read_hash: BitArray,
    append_hash: BitArray,
    admin_hash: BitArray,
    created_at: Instant,
    bytes_used: Int,
    capacity: Int,
  )
}

/// What the mailbox remembers of a stored envelope when it needs only to
/// answer an append retry or an acknowledgment.
pub type EnvelopeRecord {
  EnvelopeRecord(digest: BitArray, deadline: Instant, size: Int)
}

/// The deduplication record an acknowledgment leaves behind (design review
/// B, §3.8): the content digest, so a retry with different bytes is still a
/// conflict, and the deadline after which the record is worthless.
pub type Tombstone {
  Tombstone(digest: BitArray, deadline: Instant)
}

/// What a sweep removed.
pub type SweepReport {
  SweepReport(envelopes: Int, tombstones: Int)
}

/// The statements that bring an empty database to each version. Entry `n`
/// moves version `n` to `n + 1`, so the list is append-only: an edit to a
/// shipped entry would leave deployed files on a schema nothing describes.
const migrations = [
  "
CREATE TABLE grants (
  capability_hash BLOB NOT NULL PRIMARY KEY,
  allowance INTEGER NOT NULL,
  queues_used INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE queues (
  queue_id BLOB NOT NULL PRIMARY KEY,
  read_hash BLOB NOT NULL,
  append_hash BLOB NOT NULL,
  admin_hash BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  bytes_used INTEGER NOT NULL,
  capacity INTEGER NOT NULL
) STRICT;

CREATE TABLE envelopes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  queue_id BLOB NOT NULL REFERENCES queues(queue_id) ON DELETE CASCADE,
  envelope_id BLOB NOT NULL,
  digest BLOB NOT NULL,
  deadline INTEGER NOT NULL,
  size INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,
  UNIQUE (queue_id, envelope_id)
) STRICT;

CREATE INDEX envelopes_by_deadline ON envelopes (deadline);

CREATE TABLE tombstones (
  queue_id BLOB NOT NULL REFERENCES queues(queue_id) ON DELETE CASCADE,
  envelope_id BLOB NOT NULL,
  digest BLOB NOT NULL,
  deadline INTEGER NOT NULL,
  PRIMARY KEY (queue_id, envelope_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX tombstones_by_deadline ON tombstones (deadline);
",
]

// -------------------------------------------------------------- lifecycle

/// Opens (creating if absent) the database at `path`, applies the durability
/// pragmas and migrates the schema to `schema_version`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(store) = store.open("/var/lib/mailbox/mailbox.db")
/// store.close(store)
/// // -> Ok(Nil)
/// ```
pub fn open(path: String) -> Result(Store, Error) {
  open_with(path, None)
}

/// `open`, with a fault hook that every transaction after the migrations
/// consults. `None` is `open`; the migrations run without the hook, so it
/// cannot fail the open itself.
///
/// ## Examples
///
/// ```gleam
/// store.open_with("file:m1?mode=memory&cache=shared", None)
/// // -> Ok(store)
/// ```
pub fn open_with(path: String, faults: Option(Faults)) -> Result(Store, Error) {
  use connection <- result.try(sqlight.open(path) |> result.map_error(Sql))
  let store = Store(connection:, faults: None)

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

/// Reads the durability settings back from SQLite, so a test (or an
/// operator) can see what is in effect rather than what was requested.
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

/// Applies the durability pragmas. Each is a separate statement because
/// SQLite reports a bad one by name, and `exec` stops at the first failure.
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
/// `user_version` as it goes.
fn apply_migrations(
  store: Store,
  pending: List(String),
  from: Int,
) -> Result(Nil, Error) {
  // Recurse down the pending list; the empty list is a file at the current
  // version.
  case pending {
    [] -> Ok(Nil)

    [statements, ..rest] -> {
      // The version bump rides in the same transaction as the schema it
      // describes, so a crash leaves either the old version with the old
      // schema or the new with the new.
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
/// store.transaction(store, fn() { store.put_grant(store, hash, 3) })
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
/// real failing disk looks like to the caller.
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

// ----------------------------------------------------------------- grants

/// Records a provisioning grant under the hash of its capability.
///
/// ## Examples
///
/// ```gleam
/// store.put_grant(store, primitives.sha256(<<1:256>>), 5)
/// // -> Ok(Nil)
/// ```
pub fn put_grant(
  store: Store,
  hash: BitArray,
  allowance: Int,
) -> Result(Nil, Error) {
  write(store, "INSERT INTO grants (capability_hash, allowance) VALUES (?, ?)", [
    sqlight.blob(hash),
    sqlight.int(allowance),
  ])
}

/// The grant stored under `hash`, if any, with its stored hash so the caller
/// can compare it in constant time.
///
/// ## Examples
///
/// ```gleam
/// store.grant_by_hash(store, primitives.sha256(<<1:256>>))
/// // -> Ok(None)
/// ```
pub fn grant_by_hash(
  store: Store,
  hash: BitArray,
) -> Result(Option(#(BitArray, Grant)), Error) {
  let row = {
    use stored <- decode.field(0, decode.bit_array)
    use allowance <- decode.field(1, decode.int)
    use used <- decode.field(2, decode.int)
    decode.success(#(stored, Grant(allowance:, queues_used: used)))
  }

  query(
    store,
    "SELECT capability_hash, allowance, queues_used FROM grants
     WHERE capability_hash = ?",
    [sqlight.blob(hash)],
    row,
  )
  |> result.map(first)
}

/// Counts one more queue against a grant.
///
/// ## Examples
///
/// ```gleam
/// store.use_grant(store, primitives.sha256(<<1:256>>))
/// // -> Ok(Nil)
/// ```
pub fn use_grant(store: Store, hash: BitArray) -> Result(Nil, Error) {
  write(
    store,
    "UPDATE grants SET queues_used = queues_used + 1
     WHERE capability_hash = ?",
    [sqlight.blob(hash)],
  )
}

// ----------------------------------------------------------------- queues

/// The queue stored under `queue`, if any.
///
/// ## Examples
///
/// ```gleam
/// store.queue_by_id(store, queue)
/// // -> Ok(None)
/// ```
pub fn queue_by_id(
  store: Store,
  queue: Id(Queue),
) -> Result(Option(QueueRecord), Error) {
  let row = {
    use read_hash <- decode.field(0, decode.bit_array)
    use append_hash <- decode.field(1, decode.bit_array)
    use admin_hash <- decode.field(2, decode.bit_array)
    use created_at <- decode.field(3, decode.int)
    use bytes_used <- decode.field(4, decode.int)
    use capacity <- decode.field(5, decode.int)

    decode.success(QueueRecord(
      queue:,
      read_hash:,
      append_hash:,
      admin_hash:,
      created_at: Instant(created_at),
      bytes_used:,
      capacity:,
    ))
  }

  query(
    store,
    "SELECT read_hash, append_hash, admin_hash, created_at, bytes_used,
            capacity
     FROM queues WHERE queue_id = ?",
    [sqlight.blob(id.to_bytes(queue))],
    row,
  )
  |> result.map(first)
}

/// Inserts a new queue with nothing stored in it.
///
/// ## Examples
///
/// ```gleam
/// store.put_queue(store, record)
/// // -> Ok(Nil)
/// ```
pub fn put_queue(store: Store, record: QueueRecord) -> Result(Nil, Error) {
  write(
    store,
    "INSERT INTO queues (queue_id, read_hash, append_hash, admin_hash,
                         created_at, bytes_used, capacity)
     VALUES (?, ?, ?, ?, ?, ?, ?)",
    [
      sqlight.blob(id.to_bytes(record.queue)),
      sqlight.blob(record.read_hash),
      sqlight.blob(record.append_hash),
      sqlight.blob(record.admin_hash),
      sqlight.int(record.created_at.unix_seconds),
      sqlight.int(record.bytes_used),
      sqlight.int(record.capacity),
    ],
  )
}

/// Deletes a queue; its envelopes and tombstones go with it through the
/// foreign keys' cascade.
///
/// ## Examples
///
/// ```gleam
/// store.delete_queue(store, queue)
/// // -> Ok(Nil)
/// ```
pub fn delete_queue(store: Store, queue: Id(Queue)) -> Result(Nil, Error) {
  write(store, "DELETE FROM queues WHERE queue_id = ?", [
    sqlight.blob(id.to_bytes(queue)),
  ])
}

// -------------------------------------------------------------- envelopes

/// The stored envelope's bookkeeping row, if the envelope is still stored.
///
/// ## Examples
///
/// ```gleam
/// store.envelope_record(store, queue, envelope)
/// // -> Ok(None)
/// ```
pub fn envelope_record(
  store: Store,
  queue: Id(Queue),
  envelope: Id(Envelope),
) -> Result(Option(EnvelopeRecord), Error) {
  let row = {
    use digest <- decode.field(0, decode.bit_array)
    use deadline <- decode.field(1, decode.int)
    use size <- decode.field(2, decode.int)
    decode.success(EnvelopeRecord(digest:, deadline: Instant(deadline), size:))
  }

  query(
    store,
    "SELECT digest, deadline, size FROM envelopes
     WHERE queue_id = ? AND envelope_id = ?",
    key(queue, envelope),
    row,
  )
  |> result.map(first)
}

/// The tombstone left by an acknowledged envelope, if any.
///
/// ## Examples
///
/// ```gleam
/// store.tombstone(store, queue, envelope)
/// // -> Ok(None)
/// ```
pub fn tombstone(
  store: Store,
  queue: Id(Queue),
  envelope: Id(Envelope),
) -> Result(Option(Tombstone), Error) {
  let row = {
    use digest <- decode.field(0, decode.bit_array)
    use deadline <- decode.field(1, decode.int)
    decode.success(Tombstone(digest:, deadline: Instant(deadline)))
  }

  query(
    store,
    "SELECT digest, deadline FROM tombstones
     WHERE queue_id = ? AND envelope_id = ?",
    key(queue, envelope),
    row,
  )
  |> result.map(first)
}

/// Reserves the ciphertext's bytes of the queue's quota and inserts the
/// envelope: the two halves of spec §6.4's atomic append. The caller has
/// already checked the quota and holds the transaction that makes the pair
/// indivisible.
///
/// ## Examples
///
/// ```gleam
/// store.put_envelope(store, queue, envelope, digest, deadline, bytes)
/// // -> Ok(Nil)
/// ```
pub fn put_envelope(
  store: Store,
  queue: Id(Queue),
  envelope: Id(Envelope),
  digest: BitArray,
  deadline: Instant,
  ciphertext: BitArray,
) -> Result(Nil, Error) {
  let size = bit_array.byte_size(ciphertext)

  use _ <- result.try(adjust_bytes(store, queue, size))

  write(
    store,
    "INSERT INTO envelopes (queue_id, envelope_id, digest, deadline, size,
                            ciphertext)
     VALUES (?, ?, ?, ?, ?, ?)",
    list.append(key(queue, envelope), [
      sqlight.blob(digest),
      sqlight.int(deadline.unix_seconds),
      sqlight.int(size),
      sqlight.blob(ciphertext),
    ]),
  )
}

/// Up to `limit` unexpired envelopes of the queue, oldest first. An envelope
/// whose deadline equals `now` is still live (`core/time.is_past`).
///
/// ## Examples
///
/// ```gleam
/// store.live_envelopes(store, queue, now, 16)
/// // -> Ok([])
/// ```
pub fn live_envelopes(
  store: Store,
  queue: Id(Queue),
  now: Instant,
  limit: Int,
) -> Result(List(StoredEnvelope), Error) {
  let row = {
    use envelope_bytes <- decode.field(0, decode.bit_array)
    use deadline <- decode.field(1, decode.int)
    use ciphertext <- decode.field(2, decode.bit_array)
    decode.success(#(envelope_bytes, deadline, ciphertext))
  }

  use rows <- result.try(query(
    store,
    "SELECT envelope_id, deadline, ciphertext FROM envelopes
     WHERE queue_id = ? AND deadline >= ?
     ORDER BY seq ASC LIMIT ?",
    [
      sqlight.blob(id.to_bytes(queue)),
      sqlight.int(now.unix_seconds),
      sqlight.int(limit),
    ],
    row,
  ))

  list.try_map(rows, fn(row) {
    let #(envelope_bytes, deadline, ciphertext) = row

    // Stored bytes are decoded as totally as wire bytes: a row that no
    // longer parses is reported as damage, never served.
    case id.from_bytes(envelope_bytes), envelope.from_wire(ciphertext) {
      Ok(envelope), Ok(padded) ->
        Ok(StoredEnvelope(
          queue:,
          envelope:,
          retention_deadline: Instant(deadline),
          ciphertext: padded,
        ))

      _, _ -> Error(Corrupt("an envelope row does not decode"))
    }
  })
}

/// Deletes one stored envelope: its bytes are released from the quota and a
/// tombstone with its digest and deadline is written, all in the caller's
/// transaction. Returns the bytes released, zero if the envelope was not
/// stored.
///
/// ## Examples
///
/// ```gleam
/// store.remove_envelope(store, queue, envelope)
/// // -> Ok(4096)
/// ```
pub fn remove_envelope(
  store: Store,
  queue: Id(Queue),
  envelope: Id(Envelope),
) -> Result(Int, Error) {
  use found <- result.try(envelope_record(store, queue, envelope))

  // An envelope that is not stored releases nothing and leaves no
  // tombstone: there is no digest to remember.
  case found {
    None -> Ok(0)

    Some(record) -> {
      use _ <- result.try(write(
        store,
        "DELETE FROM envelopes WHERE queue_id = ? AND envelope_id = ?",
        key(queue, envelope),
      ))

      use _ <- result.try(write(
        store,
        "INSERT OR REPLACE INTO tombstones
           (queue_id, envelope_id, digest, deadline) VALUES (?, ?, ?, ?)",
        list.append(key(queue, envelope), [
          sqlight.blob(record.digest),
          sqlight.int(record.deadline.unix_seconds),
        ]),
      ))

      use _ <- result.try(adjust_bytes(store, queue, -record.size))

      Ok(record.size)
    }
  }
}

// ------------------------------------------------------------ maintenance

/// Deletes every envelope whose deadline is before `now`, releasing each
/// queue's bytes, and every tombstone past its deadline. Expired envelopes
/// leave no tombstone: the tombstone would carry the same deadline, so it
/// would already be worthless.
///
/// ## Examples
///
/// ```gleam
/// store.sweep(store, now)
/// // -> Ok(SweepReport(envelopes: 0, tombstones: 0))
/// ```
pub fn sweep(store: Store, now: Instant) -> Result(SweepReport, Error) {
  let cutoff = [sqlight.int(now.unix_seconds)]

  let per_queue = {
    use queue <- decode.field(0, decode.bit_array)
    use bytes <- decode.field(1, decode.int)
    use count <- decode.field(2, decode.int)
    decode.success(#(queue, bytes, count))
  }

  transaction(store, fn() {
    use expired <- result.try(query(
      store,
      "SELECT queue_id, SUM(size), COUNT(*) FROM envelopes
       WHERE deadline < ? GROUP BY queue_id",
      cutoff,
      per_queue,
    ))

    use _ <- result.try(
      list.try_each(expired, fn(entry) {
        write(
          store,
          "UPDATE queues SET bytes_used = bytes_used - ? WHERE queue_id = ?",
          [sqlight.int(entry.1), sqlight.blob(entry.0)],
        )
      }),
    )

    use _ <- result.try(write(
      store,
      "DELETE FROM envelopes WHERE deadline < ?",
      cutoff,
    ))

    use stale <- result.try(query(
      store,
      "SELECT COUNT(*) FROM tombstones WHERE deadline < ?",
      cutoff,
      decode.field(0, decode.int, decode.success),
    ))

    use _ <- result.try(write(
      store,
      "DELETE FROM tombstones WHERE deadline < ?",
      cutoff,
    ))

    Ok(SweepReport(
      envelopes: list.fold(expired, 0, fn(sum, entry) { sum + entry.2 }),
      tombstones: list.fold(stale, 0, int.add),
    ))
  })
}

// ---------------------------------------------------------------- helpers

/// Adds `delta` (negative to release) to the queue's byte count.
fn adjust_bytes(
  store: Store,
  queue: Id(Queue),
  delta: Int,
) -> Result(Nil, Error) {
  write(
    store,
    "UPDATE queues SET bytes_used = bytes_used + ? WHERE queue_id = ?",
    [sqlight.int(delta), sqlight.blob(id.to_bytes(queue))],
  )
}

fn key(queue: Id(Queue), envelope: Id(Envelope)) -> List(sqlight.Value) {
  [
    sqlight.blob(id.to_bytes(queue)),
    sqlight.blob(id.to_bytes(envelope)),
  ]
}

fn first(rows: List(a)) -> Option(a) {
  case rows {
    [row, ..] -> Some(row)
    [] -> None
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
/// Values travel as bound parameters, never spliced into the SQL, so no
/// request field can alter a statement.
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
