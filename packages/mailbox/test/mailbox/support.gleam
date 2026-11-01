//// Shared fixtures for the mailbox tests: deterministic ids and
//// capabilities, a throwaway database file, and a settable clock.

import core/capability.{type Capability, type Provision}
import core/envelope.{type Padded}
import core/id.{type Envelope, type Id, type Queue}
import core/mailbox/protocol
import core/time.{type Instant, Instant}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/int
import mailbox/service
import mailbox/store.{type Store}

/// The instant every service test treats as the present.
pub const now = Instant(1_000_000)

pub fn cap(n: Int) -> Capability(a) {
  let assert Ok(value) = capability.from_bytes(<<n:256>>)
  value
}

pub fn qid(n: Int) -> Id(Queue) {
  let assert Ok(value) = id.from_bytes(<<n:128>>)
  value
}

pub fn eid(n: Int) -> Id(Envelope) {
  let assert Ok(value) = id.from_bytes(<<n:128>>)
  value
}

/// A 4096-byte padded ciphertext whose content depends on `n`.
pub fn padded(n: Int) -> Padded {
  let assert Ok(value) = envelope.pad(<<n:64>>)
  value
}

/// A 262144-byte padded ciphertext, the largest bucket.
pub fn big(n: Int) -> Padded {
  let assert Ok(value) = envelope.pad(<<n:64, 0:size(2_000_000)>>)
  value
}

/// Randomness for `create_grant`: bytes that depend on `seed`.
pub fn random(seed: Int) -> fn(Int) -> BitArray {
  fn(bytes) {
    let bits = bytes * 8
    <<seed:size(bits)>>
  }
}

pub fn unique() -> Int {
  erlang_unique_integer()
}

/// Opens a fresh database file, runs `body`, then closes and deletes it.
pub fn with_store(body: fn(Store, String) -> a) -> a {
  let path = fresh_path()
  let assert Ok(db) = store.open(path)
  let value = body(db, path)
  let _ = store.close(db)
  remove_files(path)
  value
}

/// A path under `build/` for a database that does not exist yet. The
/// identifier restarts with every VM, so a file left by an earlier failed
/// run could share it; remove any such file rather than inherit its state.
pub fn fresh_path() -> String {
  let path = "build/mailbox_test_" <> int.to_string(unique()) <> ".db"
  remove_files(path)
  path
}

pub fn remove_files(path: String) -> Nil {
  let _ = file_delete(path)
  let _ = file_delete(path <> "-wal")
  let _ = file_delete(path <> "-shm")
  Nil
}

/// A store with one grant and one queue (`qid(1)`, capabilities 11, 12, 13
/// for read, append and admin), and the provisioning capability.
pub fn with_queue(body: fn(Store, Capability(Provision)) -> a) -> a {
  use db, provision, _ <- with_queue_at
  body(db, provision)
}

/// `with_queue`, also giving the database file's path.
pub fn with_queue_at(body: fn(Store, Capability(Provision), String) -> a) -> a {
  use db, path <- with_store
  let assert Ok(provision) = service.create_grant(db, 5, random(77))

  let created =
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
  let assert protocol.QueueCreated(_) = created

  body(db, provision, path)
}

/// The integers from `from` to `to`, inclusive.
pub fn upto(from: Int, to: Int) -> List(Int) {
  case from > to {
    True -> []
    False -> [from, ..upto(from + 1, to)]
  }
}

pub fn append(
  db: Store,
  envelope: Int,
  ciphertext: Padded,
) -> protocol.Response {
  service.handle(
    db,
    now,
    protocol.Append(
      queue: qid(1),
      append: cap(12),
      envelope: eid(envelope),
      retention_deadline: time.add(now, 3600),
      ciphertext:,
    ),
  )
}

pub fn fetch(db: Store, max: Int) -> protocol.Response {
  service.handle(
    db,
    now,
    protocol.Fetch(
      queue: qid(1),
      read: cap(11),
      wait_seconds: 0,
      max_envelopes: max,
    ),
  )
}

/// The envelope identifiers in a `Batch`, in order, as integers.
pub fn batch_ids(response: protocol.Response) -> List(Int) {
  let assert protocol.Batch(envelopes:) = response
  envelope_ints(envelopes)
}

fn envelope_ints(envelopes: List(envelope.StoredEnvelope)) -> List(Int) {
  case envelopes {
    [] -> []
    [first, ..rest] -> {
      let assert <<n:128>> = id.to_bytes(first.envelope)
      [n, ..envelope_ints(rest)]
    }
  }
}

pub fn monotonic_ms() -> Int {
  erlang_monotonic_time(millisecond())
}

/// A clock that tests can move: it reads a persistent term.
pub fn set_clock(key: String, instant: Instant) -> Nil {
  let _ = persistent_term_put(key, instant.unix_seconds)
  Nil
}

pub fn read_clock(key: String) -> Instant {
  Instant(persistent_term_get(key))
}

@external(erlang, "erlang", "unique_integer")
fn erlang_unique_integer() -> Int

@external(erlang, "file", "delete")
fn file_delete(path: String) -> Dynamic

@external(erlang, "persistent_term", "put")
fn persistent_term_put(key: String, value: Int) -> Dynamic

@external(erlang, "persistent_term", "get")
fn persistent_term_get(key: String) -> Int

@external(erlang, "erlang", "monotonic_time")
fn erlang_monotonic_time(unit: Unit) -> Int

type Unit

@external(erlang, "support_ffi", "millisecond")
fn millisecond() -> Unit

/// A decoder for a single integer column, for raw count queries.
pub fn first_int() -> decode.Decoder(Int) {
  decode.field(0, decode.int, decode.success)
}
