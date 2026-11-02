//// Raw reads of the daemons' and the mailbox's tables, for the oracle and
//// the snapshot.
////
//// The oracle reads what is durable, not what any process believes: each
//// node's database is an in-memory SQLite shared cache, and the harness
//// holds its own connection to it (the keeper that also keeps the data
//// alive across restarts). Reading at quiescence, when no transaction is
//// open, sees exactly the committed state. Nothing here writes.
////
//// A read that fails is a harness fault, not a finding, so it panics with
//// the table's name.

import gleam/dynamic
import gleam/dynamic/decode
import gleam/list
import gleam/option.{type Option}
import gleam/string
import sim/internal/ffi_vm
import sqlight.{type Connection}

/// One daemon outbox row.
pub type Outbox {
  Outbox(
    envelope: BitArray,
    contact: BitArray,
    kind: String,
    message: Option(BitArray),
    padded: BitArray,
    status: String,
    attempts: Int,
  )
}

/// One daemon `processed` row.
pub type Processed {
  Processed(queue: BitArray, envelope: BitArray, outcome: String, acked: Int)
}

/// One daemon delivery.
pub type Delivery {
  Delivery(
    seq: Int,
    contact: BitArray,
    message: BitArray,
    payload: BitArray,
    status: String,
  )
}

/// One daemon `sent_messages` row.
pub type Sent {
  Sent(message: BitArray, contact: BitArray, state: String)
}

/// One daemon offer row.
pub type Offer {
  Offer(
    invitation: BitArray,
    phase: String,
    inbox_queue: BitArray,
    blob: BitArray,
  )
}

/// One daemon relationship row.
pub type Relationship {
  Relationship(
    contact: BitArray,
    phase: String,
    inbox_queue: BitArray,
    blob: BitArray,
  )
}

/// One mailbox envelope or tombstone: which queue, which envelope.
pub type Stored {
  Stored(queue: BitArray, envelope: BitArray)
}

/// Every outbox row, in insertion order.
///
/// ## Examples
///
/// ```gleam
/// tables.outbox(keeper)
/// // -> [Outbox(..)]
/// ```
pub fn outbox(connection: Connection) -> List(Outbox) {
  let row = {
    use envelope <- decode.field(0, decode.bit_array)
    use contact <- decode.field(1, decode.bit_array)
    use kind <- decode.field(2, decode.string)
    use message <- decode.field(3, decode.optional(decode.bit_array))
    use padded <- decode.field(4, decode.bit_array)
    use status <- decode.field(5, decode.string)
    use attempts <- decode.field(6, decode.int)
    decode.success(Outbox(
      envelope:,
      contact:,
      kind:,
      message:,
      padded:,
      status:,
      attempts:,
    ))
  }

  read(
    connection,
    "SELECT envelope, contact, kind, message_id, padded, status, attempts
     FROM outbox ORDER BY rowid",
    row,
  )
}

/// Every `processed` row.
///
/// ## Examples
///
/// ```gleam
/// tables.processed(keeper)
/// ```
pub fn processed(connection: Connection) -> List(Processed) {
  let row = {
    use queue <- decode.field(0, decode.bit_array)
    use envelope <- decode.field(1, decode.bit_array)
    use outcome <- decode.field(2, decode.string)
    use acked <- decode.field(3, decode.int)
    decode.success(Processed(queue:, envelope:, outcome:, acked:))
  }

  read(
    connection,
    "SELECT queue, envelope, outcome, acked FROM processed
     ORDER BY queue, envelope",
    row,
  )
}

/// Every delivery, oldest first.
///
/// ## Examples
///
/// ```gleam
/// tables.deliveries(keeper)
/// ```
pub fn deliveries(connection: Connection) -> List(Delivery) {
  let row = {
    use seq <- decode.field(0, decode.int)
    use contact <- decode.field(1, decode.bit_array)
    use message <- decode.field(2, decode.bit_array)
    use payload <- decode.field(3, decode.bit_array)
    use status <- decode.field(4, decode.string)
    decode.success(Delivery(seq:, contact:, message:, payload:, status:))
  }

  read(
    connection,
    "SELECT seq, contact, message_id, payload, status FROM deliveries
     ORDER BY seq",
    row,
  )
}

/// Every `sent_messages` row.
///
/// ## Examples
///
/// ```gleam
/// tables.sent(keeper)
/// ```
pub fn sent(connection: Connection) -> List(Sent) {
  let row = {
    use message <- decode.field(0, decode.bit_array)
    use contact <- decode.field(1, decode.bit_array)
    use state <- decode.field(2, decode.string)
    decode.success(Sent(message:, contact:, state:))
  }

  read(
    connection,
    "SELECT message_id, contact, state FROM sent_messages ORDER BY rowid",
    row,
  )
}

/// Every offer row.
///
/// ## Examples
///
/// ```gleam
/// tables.offers(keeper)
/// ```
pub fn offers(connection: Connection) -> List(Offer) {
  let row = {
    use invitation <- decode.field(0, decode.bit_array)
    use phase <- decode.field(1, decode.string)
    use inbox_queue <- decode.field(2, decode.bit_array)
    use blob <- decode.field(3, decode.bit_array)
    decode.success(Offer(invitation:, phase:, inbox_queue:, blob:))
  }

  read(
    connection,
    "SELECT invitation, phase, inbox_queue, blob FROM offers ORDER BY rowid",
    row,
  )
}

/// Every relationship row.
///
/// ## Examples
///
/// ```gleam
/// tables.relationships(keeper)
/// ```
pub fn relationships(connection: Connection) -> List(Relationship) {
  let row = {
    use contact <- decode.field(0, decode.bit_array)
    use phase <- decode.field(1, decode.string)
    use inbox_queue <- decode.field(2, decode.bit_array)
    use blob <- decode.field(3, decode.bit_array)
    decode.success(Relationship(contact:, phase:, inbox_queue:, blob:))
  }

  read(
    connection,
    "SELECT contact, phase, inbox_queue, blob FROM relationships
     ORDER BY rowid",
    row,
  )
}

/// Every envelope the mailbox stores.
///
/// ## Examples
///
/// ```gleam
/// tables.envelopes(mailbox_keeper)
/// ```
pub fn envelopes(connection: Connection) -> List(Stored) {
  read(
    connection,
    "SELECT queue_id, envelope_id FROM envelopes ORDER BY seq",
    stored(),
  )
}

/// Every tombstone the mailbox keeps.
///
/// ## Examples
///
/// ```gleam
/// tables.tombstones(mailbox_keeper)
/// ```
pub fn tombstones(connection: Connection) -> List(Stored) {
  read(
    connection,
    "SELECT queue_id, envelope_id FROM tombstones
     ORDER BY queue_id, envelope_id",
    stored(),
  )
}

/// The envelopes the mailbox's backup holds that it has tombstoned since,
/// oldest first: what a restore from the backup brings back
/// (`sim/restore`).
///
/// ## Examples
///
/// ```gleam
/// tables.restorable(mailbox_keeper)
/// ```
pub fn restorable(connection: Connection) -> List(Stored) {
  read(
    connection,
    "SELECT b.queue_id, b.envelope_id FROM sim_backup AS b
     JOIN tombstones AS t
       ON t.queue_id = b.queue_id AND t.envelope_id = b.envelope_id
     ORDER BY b.seq",
    stored(),
  )
}

/// A `(queue, envelope)` row.
fn stored() -> decode.Decoder(Stored) {
  use queue <- decode.field(0, decode.bit_array)
  use envelope <- decode.field(1, decode.bit_array)
  decode.success(Stored(queue:, envelope:))
}

/// Every row of `table` as a digest of its whole value, sorted: the
/// snapshot's view. A digest rather than the printed row, because printing
/// a padded envelope byte by byte cost more than the run that wrote it.
///
/// ## Examples
///
/// ```gleam
/// tables.dump(keeper, "outbox")
/// // -> ["0a1b..", ..]
/// ```
pub fn dump(connection: Connection, table: String) -> List(String) {
  read(connection, "SELECT * FROM " <> table, decode.dynamic)
  |> list.map(fn(row: dynamic.Dynamic) { ffi_vm.term_digest(row) })
  |> list.sort(string.compare)
}

/// Runs one read, panicking with the statement if it fails.
fn read(
  connection: Connection,
  sql: String,
  row: decode.Decoder(a),
) -> List(a) {
  let assert Ok(rows) =
    sqlight.query(sql, on: connection, with: [], expecting: row)
    as "the harness's read of a node's table failed"

  rows
}
