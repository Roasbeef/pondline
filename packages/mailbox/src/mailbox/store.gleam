//// The mailbox's durable state: one SQLite file and the typed statements
//// that read and write it (spec §8.1).
////
//// This module owns the schema, the pragmas that make a commit durable, and
//// every statement the package runs. Nothing above it writes SQL, and
//// nothing below it knows what a request is. That split is what lets
//// `mailbox/service` state the protocol's rules as plain functions of a
//// `Store`, and lets the storage coordinator be the only process that ever
//// holds one.
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
//// ## Where the SQL text lives
////
//// None of the static SQL is written in this file (ADR-007). The schema is
//// the migration files under `packages/mailbox/sql/`, one per version, which
//// `make gen-sql` embeds in the generated `mailbox/schema`. Every statement
//// is a named query under `src/mailbox/sql/`, which parrot turns into the
//// generated `mailbox/sql`: one function per statement, returning its text,
//// its parameters typed by the columns they bind, and a decoder for its rows.
//// `query` and `write` are the bridge that binds those parameters as sqlight
//// values. What stays hand-written here is what is not a static statement:
//// the pragmas, `BEGIN IMMEDIATE`, `COMMIT` and `ROLLBACK`, and the runner
//// that applies each migration. After editing a `.sql` file, run `make
//// gen-sql`; `test/mailbox/sql_drift_test.gleam` fails until it is run.
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
import mailbox/internal/sql_param.{type Param}
import mailbox/schema
import mailbox/sql
import sqlight

/// The schema version this build writes and understands: the number of
/// migration files under `packages/mailbox/sql/`, as `mailbox/schema` embeds
/// them.
pub const schema_version = schema.version

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
    False -> apply_migrations(store, list.drop(schema.migrations, found), found)
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
  write(store, sql.insert_grant(capability_hash: hash, allowance:))
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
  use rows <- result.try(query(store, sql.grant_by_hash(capability_hash: hash)))

  rows
  |> list.map(fn(row) {
    #(
      row.capability_hash,
      Grant(allowance: row.allowance, queues_used: row.queues_used),
    )
  })
  |> first
  |> Ok
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
  write(store, sql.use_grant(capability_hash: hash))
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
  use rows <- result.try(query(
    store,
    sql.queue_by_id(queue_id: id.to_bytes(queue)),
  ))

  rows
  |> list.map(fn(row) {
    QueueRecord(
      queue:,
      read_hash: row.read_hash,
      append_hash: row.append_hash,
      admin_hash: row.admin_hash,
      created_at: Instant(row.created_at),
      bytes_used: row.bytes_used,
      capacity: row.capacity,
    )
  })
  |> first
  |> Ok
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
    sql.insert_queue(
      queue_id: id.to_bytes(record.queue),
      read_hash: record.read_hash,
      append_hash: record.append_hash,
      admin_hash: record.admin_hash,
      created_at: record.created_at.unix_seconds,
      bytes_used: record.bytes_used,
      capacity: record.capacity,
    ),
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
  write(store, sql.delete_queue(queue_id: id.to_bytes(queue)))
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
  use rows <- result.try(query(
    store,
    sql.envelope_record(
      queue_id: id.to_bytes(queue),
      envelope_id: id.to_bytes(envelope),
    ),
  ))

  rows
  |> list.map(fn(row) {
    EnvelopeRecord(
      digest: row.digest,
      deadline: Instant(row.deadline),
      size: row.size,
    )
  })
  |> first
  |> Ok
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
  use rows <- result.try(query(
    store,
    sql.tombstone(
      queue_id: id.to_bytes(queue),
      envelope_id: id.to_bytes(envelope),
    ),
  ))

  rows
  |> list.map(fn(row) {
    Tombstone(digest: row.digest, deadline: Instant(row.deadline))
  })
  |> first
  |> Ok
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
    sql.insert_envelope(
      queue_id: id.to_bytes(queue),
      envelope_id: id.to_bytes(envelope),
      digest:,
      deadline: deadline.unix_seconds,
      size:,
      ciphertext:,
    ),
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
  use rows <- result.try(query(
    store,
    sql.live_envelopes(
      queue_id: id.to_bytes(queue),
      now: now.unix_seconds,
      max: limit,
    ),
  ))

  list.try_map(rows, fn(row) {
    // Stored bytes are decoded as totally as wire bytes: a row that no
    // longer parses is reported as damage, never served.
    case id.from_bytes(row.envelope_id), envelope.from_wire(row.ciphertext) {
      Ok(envelope), Ok(padded) ->
        Ok(StoredEnvelope(
          queue:,
          envelope:,
          retention_deadline: Instant(row.deadline),
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
      let queue_id = id.to_bytes(queue)
      let envelope_id = id.to_bytes(envelope)

      use _ <- result.try(write(
        store,
        sql.delete_envelope(queue_id:, envelope_id:),
      ))

      use _ <- result.try(write(
        store,
        sql.put_tombstone(
          queue_id:,
          envelope_id:,
          digest: record.digest,
          deadline: record.deadline.unix_seconds,
        ),
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
  let cutoff = now.unix_seconds

  transaction(store, fn() {
    use expired <- result.try(query(store, sql.expired_per_queue(now: cutoff)))

    // Each queue gives back the bytes its expired envelopes held, before the
    // envelopes go.
    use _ <- result.try(
      list.try_each(expired, fn(entry) {
        write(
          store,
          sql.adjust_bytes(delta: -entry.bytes, queue_id: entry.queue_id),
        )
      }),
    )

    use _ <- result.try(write(store, sql.delete_expired_envelopes(now: cutoff)))
    use stale <- result.try(query(store, sql.stale_tombstones(now: cutoff)))
    use _ <- result.try(write(store, sql.delete_stale_tombstones(now: cutoff)))

    Ok(SweepReport(
      envelopes: list.fold(expired, 0, fn(sum, entry) { sum + entry.envelopes }),
      tombstones: list.fold(stale, 0, fn(sum, row) { sum + row.stale }),
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
  write(store, sql.adjust_bytes(delta:, queue_id: id.to_bytes(queue)))
}

fn first(rows: List(a)) -> Option(a) {
  case rows {
    [row, ..] -> Some(row)
    [] -> None
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
// A generated function in `mailbox/sql` returns its statement's text, its
// parameters as parrot's `dev.Param`, and, for a statement that returns rows,
// the decoder for them. `query` and `write` bind those parameters as sqlight
// values and run the statement, so values travel as bound parameters, never
// spliced into the SQL, and no request field can alter a statement.

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
/// the column is nullable, and `mailbox/internal/sql_param` has exactly
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
/// `mailbox/sql`.
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
