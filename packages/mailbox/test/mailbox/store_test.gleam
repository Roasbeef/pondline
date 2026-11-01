import core/mailbox/protocol
import core/time
import gleam/option.{None, Some}
import mailbox/service
import mailbox/store
import mailbox/support.{append, batch_ids, cap, eid, fetch, now, padded, qid}
import primitives
import sqlight

pub fn durability_pragmas_are_in_effect_test() {
  use db, _ <- support.with_store

  let assert Ok(settings) = store.settings(db)
  assert settings
    == store.Settings(
      journal_mode: "wal",
      // 2 is FULL.
      synchronous: 2,
      fullfsync: 1,
      foreign_keys: 1,
      busy_timeout: store.busy_timeout_ms,
      user_version: store.schema_version,
    )
}

pub fn state_survives_close_and_reopen_test() {
  let path = support.fresh_path()
  let assert Ok(db) = store.open(path)
  let assert Ok(provision) = service.create_grant(db, 3, support.random(8))

  let assert protocol.QueueCreated(_) =
    service.handle(
      db,
      now,
      protocol.CreateQueue(
        provision:,
        queue: qid(1),
        read: cap(11),
        append: cap(12),
        admin: cap(13),
      ),
    )
  let first = append(db, 1, padded(1))
  let _ = append(db, 2, padded(2))
  let _ = append(db, 3, padded(3))
  let _ =
    service.handle(
      db,
      now,
      protocol.Ack(queue: qid(1), read: cap(11), envelopes: [eid(2)]),
    )
  let assert Ok(Nil) = store.close(db)

  let assert Ok(db) = store.open(path)

  // Envelopes, the tombstone, the quota and the capabilities all came back.
  assert batch_ids(fetch(db, 10)) == [1, 3]
  assert append(db, 1, padded(1)) == first
  assert append(db, 2, padded(22)) == protocol.Refused(protocol.Conflict)
  let assert Ok(Some(record)) = store.queue_by_id(db, qid(1))
  assert record.bytes_used == 8192

  // Reopening migrated nothing and changed nothing.
  let assert Ok(settings) = store.settings(db)
  assert settings.user_version == store.schema_version

  let assert Ok(Nil) = store.close(db)
  support.remove_files(path)
}

pub fn capabilities_are_stored_only_as_hashes_test() {
  use _, _, path <- support.with_queue_at

  let assert Ok(other) = sqlight.open(path)
  let count = fn(sql, value) {
    let assert Ok([n]) =
      sqlight.query(
        sql,
        on: other,
        with: [sqlight.blob(value)],
        expecting: support.first_int(),
      )
    n
  }

  let raw_read = <<11:256>>
  let hash_read = primitives.sha256(raw_read)
  assert count("SELECT count(*) FROM queues WHERE read_hash = ?", raw_read) == 0
  assert count("SELECT count(*) FROM queues WHERE read_hash = ?", hash_read)
    == 1

  let assert Ok(Nil) = sqlight.close(other)
  Nil
}

pub fn a_newer_schema_is_refused_test() {
  let path = support.fresh_path()
  let assert Ok(db) = store.open(path)
  let assert Ok(Nil) = store.close(db)

  let assert Ok(raw) = sqlight.open(path)
  let assert Ok(Nil) = sqlight.exec("PRAGMA user_version=99", on: raw)
  let assert Ok(Nil) = sqlight.close(raw)

  assert result_error(store.open(path))
    == Ok(store.FutureSchema(found: 99, supported: store.schema_version))
  support.remove_files(path)
}

fn result_error(result: Result(a, e)) -> Result(e, Nil) {
  case result {
    Ok(_) -> Error(Nil)
    Error(error) -> Ok(error)
  }
}

pub fn a_failed_transaction_leaves_nothing_behind_test() {
  use db, _ <- support.with_store
  let hash = primitives.sha256(<<5:256>>)

  let outcome =
    store.transaction(db, fn() {
      let assert Ok(Nil) = store.put_grant(db, hash, 4)
      Error(store.Corrupt("forced"))
    })

  assert outcome == Error(store.Corrupt("forced"))
  assert store.grant_by_hash(db, hash) == Ok(None)
}

pub fn quota_and_row_are_one_transaction_test() {
  use db, _ <- support.with_queue

  let _ = append(db, 1, padded(1))

  // Inserting a duplicate envelope identifier fails on the row after the
  // quota was already bumped; the transaction must take the bump back.
  let outcome =
    store.transaction(db, fn() {
      store.put_envelope(db, qid(1), eid(1), <<0>>, time.add(now, 60), <<
        0:size(32_768),
      >>)
    })

  let assert Error(store.Sql(_)) = outcome
  let assert Ok(Some(record)) = store.queue_by_id(db, qid(1))
  assert record.bytes_used == 4096
}
