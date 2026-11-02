import core/capability
import core/envelope
import core/limits
import core/mailbox/protocol.{type Response}
import core/time.{Instant}
import gleam/list
import gleam/option.{Some}
import gleam/string
import mailbox/service
import mailbox/store
import mailbox/support.{append, batch_ids, cap, eid, fetch, now, padded, qid}
import primitives
import qcheck
import sqlight

const property_seed = 20_261_031

// ------------------------------------------------------------ CreateQueue

fn create(db, provision, queue, read, append, admin) -> Response {
  service.handle(
    db,
    now,
    protocol.CreateQueue(
      provision:,
      queue: qid(queue),
      read: cap(read),
      append: cap(append),
      admin: cap(admin),
    ),
  )
}

pub fn create_queue_is_idempotent_test() {
  use db, provision <- support.with_queue

  // The fixture already created queue 1; the identical request again must
  // answer the same and must not spend a second unit of allowance.
  assert create(db, provision, 1, 11, 12, 13) == protocol.QueueCreated(qid(1))
  assert create(db, provision, 1, 11, 12, 13) == protocol.QueueCreated(qid(1))

  let assert Ok(Some(#(_, grant))) =
    store.grant_by_hash(db, primitives.sha256(capability_bytes(provision)))
  assert grant.queues_used == 1
}

pub fn create_queue_conflict_test() {
  use db, provision <- support.with_queue

  // Same identifier, each of the three capabilities differing in turn.
  assert create(db, provision, 1, 99, 12, 13)
    == protocol.Refused(protocol.Conflict)
  assert create(db, provision, 1, 11, 99, 13)
    == protocol.Refused(protocol.Conflict)
  assert create(db, provision, 1, 11, 12, 99)
    == protocol.Refused(protocol.Conflict)
}

pub fn create_queue_needs_a_grant_test() {
  use db, _ <- support.with_store

  // No grant at all, and then a capability that is not a grant. Neither may
  // reveal whether the queue exists.
  assert service.handle(
      db,
      now,
      protocol.CreateQueue(
        provision: cap(5),
        queue: qid(1),
        read: cap(1),
        append: cap(2),
        admin: cap(3),
      ),
    )
    == protocol.Refused(protocol.Unauthorized)
}

pub fn conflict_is_not_an_oracle_for_strangers_test() {
  use db, _ <- support.with_queue

  // A stranger probing an existing queue identifier is Unauthorized, not
  // Conflict.
  assert service.handle(
      db,
      now,
      protocol.CreateQueue(
        provision: cap(5),
        queue: qid(1),
        read: cap(1),
        append: cap(2),
        admin: cap(3),
      ),
    )
    == protocol.Refused(protocol.Unauthorized)
}

pub fn allowance_is_enforced_test() {
  use db, _ <- support.with_store
  let assert Ok(provision) = service.create_grant(db, 2, support.random(5))

  assert create(db, provision, 1, 1, 2, 3) == protocol.QueueCreated(qid(1))
  assert create(db, provision, 2, 1, 2, 3) == protocol.QueueCreated(qid(2))
  assert create(db, provision, 3, 1, 2, 3)
    == protocol.Refused(protocol.QuotaExceeded)
}

pub fn queue_capacity_is_the_limit_test() {
  use db, _ <- support.with_queue

  let assert Ok(Some(record)) = store.queue_by_id(db, qid(1))
  assert record.capacity == limits.queue_capacity_bytes
  assert record.bytes_used == 0
}

pub fn grant_rejects_bad_randomness_and_allowance_test() {
  use db, _ <- support.with_store

  assert service.create_grant(db, 1, fn(_) { <<1>> })
    == Error(service.BadRandomness)
  assert service.create_grant(db, 0, support.random(1))
    == Error(service.BadAllowance)
}

// ----------------------------------------------------------------- Append

fn receipt_of(response: Response) -> protocol.AppendReceipt {
  let assert protocol.Appended(receipt:) = response
  receipt
}

pub fn append_returns_a_receipt_that_binds_the_content_test() {
  use db, _ <- support.with_queue

  let ciphertext = padded(1)
  let receipt = receipt_of(append(db, 7, ciphertext))

  assert receipt.queue == qid(1)
  assert receipt.envelope == eid(7)
  assert receipt.digest == primitives.sha256(envelope.to_wire(ciphertext))
  assert receipt.retention_deadline == time.add(now, 3600)
}

pub fn identical_append_twice_is_one_envelope_test() {
  use db, _ <- support.with_queue

  let first = append(db, 7, padded(1))
  assert append(db, 7, padded(1)) == first
  assert batch_ids(fetch(db, 10)) == [7]

  // Quota was reserved once.
  let assert Ok(Some(record)) = store.queue_by_id(db, qid(1))
  assert record.bytes_used == 4096
}

pub fn conflicting_append_is_refused_test() {
  use db, _ <- support.with_queue

  let _ = append(db, 7, padded(1))
  assert append(db, 7, padded(2)) == protocol.Refused(protocol.Conflict)
  assert batch_ids(fetch(db, 10)) == [7]
}

// -------------------------------------------------------------- Tombstone

fn ack(db, ids) -> Response {
  service.handle(
    db,
    now,
    protocol.Ack(queue: qid(1), read: cap(11), envelopes: list.map(ids, eid)),
  )
}

pub fn reappend_after_ack_returns_the_original_receipt_test() {
  use db, _ <- support.with_queue

  let original = append(db, 7, padded(1))
  assert ack(db, [7]) == protocol.Acked
  assert batch_ids(fetch(db, 10)) == []

  // Same bytes: the original receipt, and the envelope stays deleted.
  assert append(db, 7, padded(1)) == original
  assert batch_ids(fetch(db, 10)) == []

  // Quota is not charged again for the replay.
  let assert Ok(Some(record)) = store.queue_by_id(db, qid(1))
  assert record.bytes_used == 0
}

pub fn reappend_different_bytes_after_ack_conflicts_test() {
  use db, _ <- support.with_queue

  let _ = append(db, 7, padded(1))
  let _ = ack(db, [7])

  assert append(db, 7, padded(2)) == protocol.Refused(protocol.Conflict)
  assert batch_ids(fetch(db, 10)) == []
}

pub fn tombstone_keeps_the_original_deadline_test() {
  use db, _ <- support.with_queue

  let original = receipt_of(append(db, 7, padded(1)))
  let _ = ack(db, [7])

  // A retry that asks for a different deadline still gets the first one.
  let retry =
    service.handle(
      db,
      now,
      protocol.Append(
        queue: qid(1),
        append: cap(12),
        envelope: eid(7),
        retention_deadline: time.add(now, 60),
        ciphertext: padded(1),
      ),
    )

  assert receipt_of(retry) == original
}

// -------------------------------------------------------------------- Ack

pub fn ack_unknown_and_repeated_is_harmless_test() {
  use db, _ <- support.with_queue

  let _ = append(db, 7, padded(1))
  assert ack(db, [99, 7, 7]) == protocol.Acked
  assert ack(db, [7]) == protocol.Acked
  assert batch_ids(fetch(db, 10)) == []
}

pub fn ack_too_many_ids_is_refused_test() {
  use db, _ <- support.with_queue

  let ids = support.upto(1, limits.fetch_batch_envelopes + 1)
  assert ack(db, ids) == protocol.Refused(protocol.TooLarge)
}

pub fn ack_deletes_exactly_the_named_envelopes_test() {
  use db, _ <- support.with_queue
  let envelopes = support.upto(1, 6)
  list.each(envelopes, fn(n) {
    let _ = append(db, n, padded(n))
  })

  qcheck.default_config()
  |> qcheck.with_test_count(15)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(qcheck.fixed_length_list_from(qcheck.bool(), 6), fn(flags) {
    // Re-append everything (acked ones answer from their tombstone, so
    // they cannot return); use a fresh queue per case instead.
    let queue = support.unique()
    let provision = service.create_grant(db, 1, support.random(queue))
    let assert Ok(provision) = provision
    let assert protocol.QueueCreated(_) =
      service.handle(
        db,
        now,
        protocol.CreateQueue(
          provision:,
          queue: qid(queue),
          read: cap(11),
          append: cap(12),
          admin: cap(13),
        ),
      )

    list.each(envelopes, fn(n) {
      let assert protocol.Appended(_) =
        service.handle(
          db,
          now,
          protocol.Append(
            queue: qid(queue),
            append: cap(12),
            envelope: eid(n),
            retention_deadline: time.add(now, 3600),
            ciphertext: padded(n),
          ),
        )
    })

    let chosen =
      list.zip(envelopes, flags)
      |> list.filter_map(fn(pair) {
        case pair.1 {
          True -> Ok(pair.0)
          False -> Error(Nil)
        }
      })
    let kept = list.filter(envelopes, fn(n) { !list.contains(chosen, n) })

    assert service.handle(
        db,
        now,
        protocol.Ack(
          queue: qid(queue),
          read: cap(11),
          envelopes: list.map(chosen, eid),
        ),
      )
      == protocol.Acked

    let after =
      service.handle(
        db,
        now,
        protocol.Fetch(
          queue: qid(queue),
          read: cap(11),
          wait_seconds: 0,
          max_envelopes: 10,
        ),
      )
    assert batch_ids(after) == kept
  })
}

// ------------------------------------------------------------------ Quota

pub fn quota_is_enforced_and_ack_releases_it_test() {
  use db, path <- support.with_store
  let assert Ok(provision) = service.create_grant(db, 1, support.random(3))
  let _ = create(db, provision, 1, 11, 12, 13)

  // Shrink the queue to two 4096-byte envelopes through a second
  // connection, so the test does not need to write sixty-four megabytes.
  let assert Ok(other) = sqlight.open(path)
  let assert Ok(Nil) =
    sqlight.exec("UPDATE queues SET capacity = 8192", on: other)
  let assert Ok(Nil) = sqlight.close(other)

  let assert protocol.Appended(_) = append(db, 1, padded(1))
  let assert protocol.Appended(_) = append(db, 2, padded(2))
  assert append(db, 3, padded(3)) == protocol.Refused(protocol.QuotaExceeded)
  assert batch_ids(fetch(db, 10)) == [1, 2]

  assert ack(db, [1]) == protocol.Acked
  let assert protocol.Appended(_) = append(db, 3, padded(3))
  assert batch_ids(fetch(db, 10)) == [2, 3]
}

// -------------------------------------------------------------- Deadlines

fn append_with_deadline(db, deadline) -> Response {
  service.handle(
    db,
    now,
    protocol.Append(
      queue: qid(1),
      append: cap(12),
      envelope: eid(1),
      retention_deadline: deadline,
      ciphertext: padded(1),
    ),
  )
}

pub fn deadline_bounds_test() {
  use db, _ <- support.with_queue
  let latest = time.add(now, limits.message_retention_seconds)

  assert append_with_deadline(db, now) == protocol.Refused(protocol.BadDeadline)
  assert append_with_deadline(db, Instant(1))
    == protocol.Refused(protocol.BadDeadline)
  assert append_with_deadline(db, time.add(latest, 1))
    == protocol.Refused(protocol.BadDeadline)

  // The boundaries themselves are accepted.
  let assert protocol.Appended(_) = append_with_deadline(db, time.add(now, 1))
  let assert protocol.Appended(_) = append_with_deadline(db, latest)
}

pub fn fetch_excludes_expired_and_sweep_removes_them_test() {
  use db, _ <- support.with_queue

  let soon = time.add(now, 10)
  let assert protocol.Appended(_) = append_with_deadline(db, soon)
  let _ = append(db, 2, padded(2))

  let later = time.add(now, 11)
  let at = fn(instant) {
    service.handle(
      db,
      instant,
      protocol.Fetch(
        queue: qid(1),
        read: cap(11),
        wait_seconds: 0,
        max_envelopes: 10,
      ),
    )
  }

  // At its deadline an envelope is still live; one second after, it is
  // hidden even before the sweep runs.
  assert batch_ids(at(soon)) == [1, 2]
  assert batch_ids(at(later)) == [2]

  let assert Ok(report) = service.sweep(db, later)
  assert report == store.SweepReport(envelopes: 1, tombstones: 0, blobs: 0)

  let assert Ok(Some(record)) = store.queue_by_id(db, qid(1))
  assert record.bytes_used == 4096
  assert batch_ids(at(later)) == [2]
}

pub fn sweep_removes_stale_tombstones_test() {
  use db, _ <- support.with_queue

  let _ = append(db, 1, padded(1))
  let _ = ack(db, [1])

  let assert Ok(early) = service.sweep(db, now)
  assert early == store.SweepReport(envelopes: 0, tombstones: 0, blobs: 0)

  let assert Ok(late) = service.sweep(db, time.add(now, 3601))
  assert late == store.SweepReport(envelopes: 0, tombstones: 1, blobs: 0)

  // With the tombstone gone and the deadline past, the same append is a new
  // request: its deadline must be valid, and then it is accepted afresh.
  let assert protocol.Appended(_) = append(db, 1, padded(1))
}

// ------------------------------------------------------------------ Fetch

pub fn fetch_is_non_destructive_and_oldest_first_test() {
  use db, _ <- support.with_queue

  list.each([5, 3, 9, 1], fn(n) {
    let _ = append(db, n, padded(n))
  })

  assert batch_ids(fetch(db, 10)) == [5, 3, 9, 1]
  assert batch_ids(fetch(db, 10)) == [5, 3, 9, 1]
  assert batch_ids(fetch(db, 2)) == [5, 3]
}

pub fn fetch_count_is_clamped_to_the_limit_test() {
  use db, _ <- support.with_queue
  list.each(support.upto(1, 20), fn(n) {
    let _ = append(db, n, padded(n))
  })

  assert list.length(batch_ids(fetch(db, 1000))) == limits.fetch_batch_envelopes
  assert batch_ids(fetch(db, 0)) == [1]
  assert batch_ids(fetch(db, -4)) == [1]
}

pub fn fetch_bytes_are_clamped_to_the_limit_test() {
  use db, _ <- support.with_queue

  // Five envelopes of 256 KiB are 1.25 MiB; only four fit in one MiB.
  list.each(support.upto(1, 5), fn(n) {
    let assert protocol.Appended(_) = append(db, n, support.big(n))
  })

  assert batch_ids(fetch(db, 16)) == [1, 2, 3, 4]
}

pub fn fetched_ciphertext_is_what_was_appended_test() {
  use db, _ <- support.with_queue
  let _ = append(db, 1, padded(42))

  let assert protocol.Batch(envelopes: [stored]) = fetch(db, 1)
  assert envelope.to_wire(stored.ciphertext) == envelope.to_wire(padded(42))
  assert stored.retention_deadline == time.add(now, 3600)
}

// ---------------------------------------------------------- Authorization

fn unauthorized() -> Response {
  protocol.Refused(protocol.Unauthorized)
}

pub fn wrong_capability_kinds_and_values_are_unauthorized_test() {
  use db, _ <- support.with_queue
  let q = qid(1)
  let _ = append(db, 1, padded(1))

  // Each operation presented with another kind's real capability, and with
  // an unknown value.
  let append_with = fn(c) {
    service.handle(
      db,
      now,
      protocol.Append(
        queue: q,
        append: c,
        envelope: eid(2),
        retention_deadline: time.add(now, 60),
        ciphertext: padded(2),
      ),
    )
  }
  assert append_with(cap(11)) == unauthorized()
  assert append_with(cap(13)) == unauthorized()
  assert append_with(cap(99)) == unauthorized()

  let fetch_with = fn(c) {
    service.handle(
      db,
      now,
      protocol.Fetch(queue: q, read: c, wait_seconds: 0, max_envelopes: 5),
    )
  }
  assert fetch_with(cap(12)) == unauthorized()
  assert fetch_with(cap(13)) == unauthorized()
  assert fetch_with(cap(99)) == unauthorized()

  let ack_with = fn(c) {
    service.handle(
      db,
      now,
      protocol.Ack(queue: q, read: c, envelopes: [eid(1)]),
    )
  }
  assert ack_with(cap(12)) == unauthorized()
  assert ack_with(cap(99)) == unauthorized()

  let delete_with = fn(c) {
    service.handle(db, now, protocol.DeleteQueue(queue: q, admin: c))
  }
  assert delete_with(cap(11)) == unauthorized()
  assert delete_with(cap(12)) == unauthorized()
  assert delete_with(cap(99)) == unauthorized()

  // Nothing above changed anything.
  assert batch_ids(fetch(db, 10)) == [1]
}

pub fn missing_queue_looks_like_a_wrong_capability_test() {
  use db, _ <- support.with_queue
  let ghost = qid(404)

  assert service.handle(
      db,
      now,
      protocol.Append(
        queue: ghost,
        append: cap(12),
        envelope: eid(1),
        retention_deadline: time.add(now, 60),
        ciphertext: padded(1),
      ),
    )
    == unauthorized()
  assert service.handle(
      db,
      now,
      protocol.Fetch(
        queue: ghost,
        read: cap(11),
        wait_seconds: 0,
        max_envelopes: 1,
      ),
    )
    == unauthorized()
  assert service.handle(
      db,
      now,
      protocol.Ack(queue: ghost, read: cap(11), envelopes: []),
    )
    == unauthorized()
  assert service.handle(
      db,
      now,
      protocol.DeleteQueue(queue: ghost, admin: cap(13)),
    )
    == unauthorized()
}

pub fn refusals_never_carry_capability_bytes_test() {
  use db, _ <- support.with_queue

  let response =
    service.handle(
      db,
      now,
      protocol.Fetch(
        queue: qid(1),
        read: cap(99),
        wait_seconds: 0,
        max_envelopes: 1,
      ),
    )

  // The presented value is 99 in the low byte; the rendered answer is
  // exactly the refusal and nothing derived from the request.
  assert string.inspect(response) == "Refused(Unauthorized)"
  assert !string.contains(string.inspect(response), "99")
}

pub fn delete_queue_removes_everything_test() {
  use db, _, path <- support.with_queue_at

  let _ = append(db, 1, padded(1))
  let _ = append(db, 2, padded(2))
  let _ = ack(db, [1])

  assert service.handle(
      db,
      now,
      protocol.DeleteQueue(queue: qid(1), admin: cap(13)),
    )
    == protocol.QueueDeleted

  let assert Ok(other) = sqlight.open(path)
  let count = fn(table) {
    let assert Ok([n]) =
      sqlight.query(
        "SELECT count(*) FROM " <> table,
        on: other,
        with: [],
        expecting: support.first_int(),
      )
    n
  }
  assert count("queues") == 0
  assert count("envelopes") == 0
  assert count("tombstones") == 0
  let assert Ok(Nil) = sqlight.close(other)

  assert fetch(db, 1) == unauthorized()
}

fn capability_bytes(c) -> BitArray {
  capability.expose(c)
}
