//// Sealed invitations at the mailbox (ADR-009): `PutBlob` and `GetBlob`
//// against a real store, through `service.handle`.

import core/capability.{type Capability}
import core/id.{type Blob, type Id}
import core/limits
import core/mailbox/protocol.{type Response}
import core/time.{type Instant}
import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/option.{Some}
import gleam/string
import mailbox/service
import mailbox/store
import mailbox/support.{cap, now, qid}
import sqlight

/// The fixture's queue 1 has admin capability 13 and read capability 11.
const admin = 13

fn locator(n: Int) -> Id(Blob) {
  let assert Ok(value) = id.from_bytes(<<n:size(128)>>)
  value
}

fn sealed(n: Int, size: Int) -> BitArray {
  bit_array.concat(list.repeat(<<n>>, size))
}

fn put(
  db: store.Store,
  admin admin: Capability(capability.Admin),
  blob blob: Int,
  retrieve retrieve: Int,
  deadline deadline: Instant,
  bytes bytes: BitArray,
) -> Response {
  service.handle(
    db,
    now,
    protocol.PutBlob(
      queue: qid(1),
      admin:,
      blob: locator(blob),
      retrieve: cap(retrieve),
      retention_deadline: deadline,
      sealed: bytes,
    ),
  )
}

/// A day from `now`, an invitation's usual lifetime.
fn tomorrow() -> Instant {
  time.add(now, 86_400)
}

fn get(db: store.Store, at: Instant, blob: Int, retrieve: Int) -> Response {
  service.handle(
    db,
    at,
    protocol.GetBlob(blob: locator(blob), retrieve: cap(retrieve)),
  )
}

fn bytes_used(db: store.Store) -> Int {
  let assert Ok(Some(record)) = store.queue_by_id(db, qid(1))
  record.bytes_used
}

/// A stored blob comes back to the holder of its retrieve capability, as
/// often as asked: a fetch consumes nothing.
pub fn a_blob_is_stored_and_fetched_repeatedly_test() {
  use db, _ <- support.with_queue

  assert put(db, cap(admin), 1, 50, tomorrow(), sealed(7, 300))
    == protocol.BlobStored(locator(1))
  assert get(db, now, 1, 50) == protocol.SealedBlob(sealed(7, 300))
  assert get(db, now, 1, 50) == protocol.SealedBlob(sealed(7, 300))
}

/// The blob is charged to the queue that stored it.
pub fn a_blob_is_charged_to_its_queue_test() {
  use db, _ <- support.with_queue

  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 1, 50, tomorrow(), sealed(7, 300))

  assert bytes_used(db) == 300
}

/// Only the queue's administrator may store, and a missing queue answers
/// like a wrong capability.
pub fn storing_needs_the_queues_admin_capability_test() {
  use db, _ <- support.with_queue

  // The read and append capabilities are not admin.
  assert put(db, cap(11), 1, 50, tomorrow(), sealed(1, 10))
    == protocol.Refused(protocol.Unauthorized)
  assert put(db, cap(12), 1, 50, tomorrow(), sealed(1, 10))
    == protocol.Refused(protocol.Unauthorized)

  let missing =
    service.handle(
      db,
      now,
      protocol.PutBlob(
        queue: qid(9),
        admin: cap(admin),
        blob: locator(1),
        retrieve: cap(50),
        retention_deadline: tomorrow(),
        sealed: sealed(1, 10),
      ),
    )
  assert missing == protocol.Refused(protocol.Unauthorized)
  assert get(db, now, 1, 50) == protocol.Refused(protocol.Unauthorized)
}

/// A wrong retrieve capability, an unknown locator and an expired blob all
/// get the same answer.
pub fn fetching_needs_the_retrieve_capability_test() {
  use db, _ <- support.with_queue

  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 1, 50, tomorrow(), sealed(7, 30))

  assert get(db, now, 1, 51) == protocol.Refused(protocol.Unauthorized)
  assert get(db, now, 2, 50) == protocol.Refused(protocol.Unauthorized)
  assert get(db, time.add(tomorrow(), 1), 1, 50)
    == protocol.Refused(protocol.Unauthorized)

  // The deadline itself is still live, as for an envelope.
  assert get(db, tomorrow(), 1, 50) == protocol.SealedBlob(sealed(7, 30))
}

/// The identical store twice is one blob and one charge; anything else
/// under the same locator is a conflict and changes nothing.
pub fn a_store_is_idempotent_and_conflicts_are_refused_test() {
  use db, _ <- support.with_queue

  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 1, 50, tomorrow(), sealed(7, 30))
  assert put(db, cap(admin), 1, 50, tomorrow(), sealed(7, 30))
    == protocol.BlobStored(locator(1))

  // A retry with a later deadline still answers from the original.
  assert put(db, cap(admin), 1, 50, time.add(tomorrow(), 60), sealed(7, 30))
    == protocol.BlobStored(locator(1))
  assert bytes_used(db) == 30

  assert put(db, cap(admin), 1, 50, tomorrow(), sealed(8, 30))
    == protocol.Refused(protocol.Conflict)
  assert put(db, cap(admin), 1, 51, tomorrow(), sealed(7, 30))
    == protocol.Refused(protocol.Conflict)
  assert get(db, now, 1, 50) == protocol.SealedBlob(sealed(7, 30))
  assert bytes_used(db) == 30
}

/// The deadline must be in the future and inside the retention window.
pub fn a_blob_deadline_is_bounded_test() {
  use db, _ <- support.with_queue

  assert put(db, cap(admin), 1, 50, now, sealed(1, 10))
    == protocol.Refused(protocol.BadDeadline)
  assert put(
      db,
      cap(admin),
      1,
      50,
      time.add(now, limits.message_retention_seconds + 1),
      sealed(1, 10),
    )
    == protocol.Refused(protocol.BadDeadline)
  let assert protocol.BlobStored(_) =
    put(
      db,
      cap(admin),
      1,
      50,
      time.add(now, limits.message_retention_seconds),
      sealed(1, 10),
    )
}

/// A blob over the bound is refused even through `handle`, which has
/// callers other than the codec; the bound itself is accepted.
pub fn a_blob_size_is_bounded_test() {
  use db, _ <- support.with_queue

  assert put(
      db,
      cap(admin),
      1,
      50,
      tomorrow(),
      sealed(1, limits.max_ticket_blob_bytes + 1),
    )
    == protocol.Refused(protocol.TooLarge)
  let assert protocol.BlobStored(_) =
    put(
      db,
      cap(admin),
      2,
      50,
      tomorrow(),
      sealed(1, limits.max_ticket_blob_bytes),
    )
}

/// A blob that does not fit the queue's remaining quota is refused.
pub fn a_blob_must_fit_the_quota_test() {
  use db, _, path <- support.with_queue_at

  let assert Ok(other) = sqlight.open(path)
  let assert Ok(Nil) =
    sqlight.exec("UPDATE queues SET capacity = 100", on: other)
  let assert Ok(Nil) = sqlight.close(other)

  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 1, 50, tomorrow(), sealed(1, 60))
  assert put(db, cap(admin), 2, 50, tomorrow(), sealed(1, 60))
    == protocol.Refused(protocol.QuotaExceeded)
}

/// The sweep removes a blob past its deadline and gives its bytes back,
/// and leaves a live one alone.
pub fn the_sweep_removes_expired_blobs_test() {
  use db, _ <- support.with_queue

  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 1, 50, tomorrow(), sealed(1, 40))
  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 2, 50, time.add(tomorrow(), 100), sealed(2, 20))

  let assert Ok(report) = service.sweep(db, time.add(tomorrow(), 1))
  assert report == store.SweepReport(envelopes: 0, tombstones: 0, blobs: 1)
  assert bytes_used(db) == 20
  assert get(db, now, 1, 50) == protocol.Refused(protocol.Unauthorized)
  assert get(db, now, 2, 50) == protocol.SealedBlob(sealed(2, 20))

  // Once swept, the locator is free again.
  assert put(db, cap(admin), 1, 50, tomorrow(), sealed(9, 40))
    == protocol.BlobStored(locator(1))
}

/// Deleting the queue deletes its blobs.
pub fn deleting_the_queue_deletes_its_blobs_test() {
  use db, _ <- support.with_queue

  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 1, 50, tomorrow(), sealed(1, 40))
  assert service.handle(
      db,
      now,
      protocol.DeleteQueue(queue: qid(1), admin: cap(admin)),
    )
    == protocol.QueueDeleted

  assert get(db, now, 1, 50) == protocol.Refused(protocol.Unauthorized)
  assert store.blob_record(db, locator(1)) == Ok(option.None)
}

/// The retrieve capability is stored only as its hash, and no refusal
/// carries a capability's bytes.
pub fn the_retrieve_capability_is_stored_as_a_hash_test() {
  use db, _, path <- support.with_queue_at

  let assert protocol.BlobStored(_) =
    put(db, cap(admin), 1, 50, tomorrow(), sealed(1, 40))

  let assert Ok(other) = sqlight.open(path)
  let assert Ok(rows) =
    sqlight.query(
      "SELECT hex(retrieve_hash) FROM blobs",
      on: other,
      with: [],
      expecting: decode.at([0], decode.string),
    )
  let assert Ok(Nil) = sqlight.close(other)

  let raw =
    string.uppercase(bit_array.base16_encode(capability.expose(cap(50))))
  assert rows != []
  assert list.all(rows, fn(row) { row != raw })

  let refused = string.inspect(get(db, now, 1, 51))
  assert !string.contains(refused, raw)
}
