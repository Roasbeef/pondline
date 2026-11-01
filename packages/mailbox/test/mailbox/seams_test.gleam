//// The simulation seams of a mailbox node: unset, they are production; set,
//// each one reaches the boundary it claims to.

import core/mailbox/protocol
import core/time
import gleam/erlang/process
import gleam/list
import gleam/option.{type Option, None, Some}
import mailbox/coordinator
import mailbox/mail
import mailbox/node
import mailbox/store
import mailbox/support.{cap, eid, now, padded, qid}
import weft/timer

/// Starts a node on a fresh file with the given seams.
fn start(
  source: timer.Source,
  interceptor: Option(mail.Interceptor),
  store_faults: Option(store.Faults),
) -> #(node.Node, String) {
  let path = support.fresh_path()
  let assert Ok(#(_, running)) =
    node.start(node.Config(
      path:,
      sweep_period_ms: 60_000,
      clock: fn() { now },
      names: node.new_names(),
      timer: source,
      interceptor:,
      store_faults:,
    ))

  #(running, path)
}

/// Grants an allowance and creates queue 1 through the node.
fn create_queue(running: node.Node) -> protocol.Response {
  let assert Ok(Ok(provision)) =
    coordinator.create_grant(
      mail.direct(running.names.coordinator),
      5,
      support.random(41),
      5000,
    )

  node.handle(
    running,
    protocol.CreateQueue(
      provision:,
      queue: qid(1),
      read: cap(11),
      append: cap(12),
      admin: cap(13),
    ),
  )
}

fn append(running: node.Node, n: Int) -> protocol.Response {
  node.handle(
    running,
    protocol.Append(
      queue: qid(1),
      append: cap(12),
      envelope: eid(n),
      retention_deadline: time.add(now, 3600),
      ciphertext: padded(n),
    ),
  )
}

fn fetch(running: node.Node, wait: Int) -> protocol.Response {
  node.handle(
    running,
    protocol.Fetch(
      queue: qid(1),
      read: cap(11),
      wait_seconds: wait,
      max_envelopes: 10,
    ),
  )
}

/// Every message already waiting on `subject`, oldest first.
fn drain(subject: process.Subject(a), seen: List(a)) -> List(a) {
  // An empty mailbox ends the drain.
  case process.receive(subject, 0) {
    Ok(next) -> drain(subject, [next, ..seen])
    Error(Nil) -> list.reverse(seen)
  }
}

pub fn a_node_with_every_seam_at_its_default_serves_an_exchange_test() {
  let #(running, path) = start(timer.WallClock, None, None)
  assert create_queue(running) == protocol.QueueCreated(qid(1))

  // A long poll is woken by an append from another process.
  let _ =
    process.spawn(fn() {
      process.sleep(200)
      append(running, 1)
    })
  assert support.batch_ids(fetch(running, 5)) == [1]

  let acked =
    node.handle(
      running,
      protocol.Ack(queue: qid(1), read: cap(11), envelopes: [eid(1)]),
    )
  assert acked == protocol.Acked
  assert support.batch_ids(fetch(running, 0)) == []

  support.remove_files(path)
}

pub fn an_injected_timer_ends_a_long_poll_without_wall_time_test() {
  // A source whose every deadline is already due: the 25 second wait ends
  // as soon as it is armed.
  let due = timer.Injected(after: fn(_delay, wake) { wake() })
  let #(running, path) = start(due, None, None)
  assert create_queue(running) == protocol.QueueCreated(qid(1))

  let started = support.monotonic_ms()
  assert support.batch_ids(fetch(running, 25)) == []
  assert support.monotonic_ms() - started < 5000

  support.remove_files(path)
}

pub fn an_interceptor_sees_and_delivers_the_node_calls_test() {
  let parcels = process.new_subject()

  // This interceptor releases each parcel at once and reports its labels.
  let interceptor =
    mail.Interceptor(park: fn(parcel: mail.Parcel) {
      let delivered = parcel.deliver()
      process.send(parcels, #(parcel.from, parcel.to, parcel.label, delivered))
    })
  let #(running, path) = start(timer.WallClock, Some(interceptor), None)
  assert create_queue(running) == protocol.QueueCreated(qid(1))
  let assert protocol.Appended(_) = append(running, 1)
  let seen = drain(parcels, [])

  // The request's call and the coordinator's wake-up both went through it.
  assert list.contains(seen, #(
    "request",
    "coordinator",
    "handle",
    mail.Delivered,
  ))
  assert list.contains(seen, #(
    "coordinator",
    "notifier",
    "notify",
    mail.Delivered,
  ))

  support.remove_files(path)
}

pub fn a_store_fault_fails_the_coordinator_transaction_test() {
  let #(running, path) = start(timer.WallClock, None, Some(fn() { store.Down }))

  // The grant's transaction never begins, so the coordinator answers with
  // the storage fault and nothing is written.
  let assert Ok(Error(_)) =
    coordinator.create_grant(
      mail.direct(running.names.coordinator),
      5,
      support.random(43),
      5000,
    )

  support.remove_files(path)
}
