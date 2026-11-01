import core/mailbox/protocol
import core/time
import gleam/erlang/process
import gleam/list
import mailbox/coordinator
import mailbox/node
import mailbox/support.{cap, eid, now, padded, qid}
import simplifile
import sqlight
import weft/poll

fn start(sweep_period_ms: Int, clock_key: String) -> #(node.Node, String) {
  let path = support.fresh_path()
  support.set_clock(clock_key, now)

  let config =
    node.Config(
      path:,
      sweep_period_ms:,
      clock: fn() { support.read_clock(clock_key) },
      names: node.new_names(),
    )
  let assert Ok(#(_, running)) = node.start(config)

  // Grant and queue through the same coordinator the requests use.
  let create = node.handle(running, create_request(running))
  assert create == protocol.QueueCreated(qid(1))

  #(running, path)
}

fn create_request(running: node.Node) -> protocol.Request {
  let assert Ok(Ok(provision)) = coordinator_grant(running)
  protocol.CreateQueue(
    provision:,
    queue: qid(1),
    read: cap(11),
    append: cap(12),
    admin: cap(13),
  )
}

fn coordinator_grant(running: node.Node) {
  coordinator.create_grant(
    running.names.coordinator,
    5,
    support.random(31),
    5000,
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

pub fn requests_flow_through_the_processes_test() {
  let #(running, path) = start(60_000, "clock_flow")

  let assert protocol.Appended(_) = append(running, 1)
  assert support.batch_ids(fetch(running, 0)) == [1]

  let acked =
    node.handle(
      running,
      protocol.Ack(queue: qid(1), read: cap(11), envelopes: [eid(1)]),
    )
  assert acked == protocol.Acked
  assert support.batch_ids(fetch(running, 0)) == []

  support.remove_files(path)
}

pub fn long_poll_returns_promptly_when_an_append_lands_test() {
  let #(running, path) = start(60_000, "clock_wake")

  let _ =
    process.spawn(fn() {
      process.sleep(300)
      append(running, 5)
    })

  let started = support.monotonic_ms()
  let answer = fetch(running, 10)
  let elapsed = support.monotonic_ms() - started

  assert support.batch_ids(answer) == [5]
  // Woken by the append, not by the ten-second wait.
  assert elapsed >= 250
  assert elapsed < 3000

  support.remove_files(path)
}

pub fn long_poll_times_out_with_an_empty_batch_test() {
  let #(running, path) = start(60_000, "clock_timeout")

  let started = support.monotonic_ms()
  let answer = fetch(running, 1)
  let elapsed = support.monotonic_ms() - started

  assert answer == protocol.Batch(envelopes: [])
  assert elapsed >= 900
  assert elapsed < 4000

  support.remove_files(path)
}

pub fn long_poll_with_a_wrong_capability_does_not_wait_test() {
  let #(running, path) = start(60_000, "clock_unauth")

  let started = support.monotonic_ms()
  let answer =
    node.handle(
      running,
      protocol.Fetch(
        queue: qid(1),
        read: cap(99),
        wait_seconds: 10,
        max_envelopes: 10,
      ),
    )

  assert answer == protocol.Refused(protocol.Unauthorized)
  assert support.monotonic_ms() - started < 1000

  support.remove_files(path)
}

pub fn many_waiters_are_all_woken_test() {
  let #(running, path) = start(60_000, "clock_many")
  let results = process.new_subject()

  list.each(support.upto(1, 3), fn(_) {
    process.spawn(fn() { process.send(results, fetch(running, 10)) })
  })

  process.sleep(300)
  let assert protocol.Appended(_) = append(running, 9)

  list.each(support.upto(1, 3), fn(_) {
    let assert Ok(answer) = process.receive(results, 3000)
    assert support.batch_ids(answer) == [9]
  })

  support.remove_files(path)
}

pub fn the_sweeper_removes_expired_envelopes_test() {
  let #(running, path) = start(50, "clock_sweep")
  let assert protocol.Appended(_) = append(running, 1)

  // Move the clock past the deadline; the periodic sweep, not any request,
  // must release the row and its bytes.
  support.set_clock("clock_sweep", time.add(now, 7200))

  let released =
    poll.until(within: 5000, every: 25, attempt: fn() {
      case stored(path) {
        #(0, 0) -> poll.Done(Nil)
        _ -> poll.Retry
      }
    })

  assert released == poll.Answered(Nil)

  support.remove_files(path)
}

pub fn the_node_answers_unavailable_when_stopped_test() {
  let names = node.new_names()
  let running = node.Node(names:, clock: fn() { now })

  assert fetch(running, 0) == protocol.Refused(protocol.Unavailable)
}

/// The coordinator closes its connection when the node is shut down in an
/// orderly way. SQLite removes the write-ahead log only when the last
/// connection closes cleanly, so its absence is the observable proof.
pub fn an_orderly_shutdown_closes_the_store_test() {
  let path = support.fresh_path()
  let started = process.new_subject()

  // The helper is the supervisor's parent, and only a parent's exit signal
  // makes a supervisor shut its children down in order. It is unlinked from
  // this test so that the supervisor's exit cannot take the test with it.
  let _ =
    process.spawn_unlinked(fn() {
      let config =
        node.Config(
          path:,
          sweep_period_ms: 60_000,
          clock: fn() { now },
          names: node.new_names(),
        )
      let assert Ok(#(supervisor, _)) = node.start(config)

      // A subject belongs to the process that made it, so the helper makes
      // the one it waits on and hands it out.
      let stop = process.new_subject()
      process.send(started, #(supervisor.pid, stop))

      process.receive_forever(stop)
      process.send_exit(supervisor.pid)
    })

  let assert Ok(#(supervisor, stop)) = process.receive(started, 5000)
  let down = process.monitor(supervisor)
  let selector =
    process.new_selector()
    |> process.select_specific_monitor(down, fn(_) { Nil })

  // While the node runs, the connection is open and the log exists.
  assert simplifile.is_file(path <> "-wal") == Ok(True)

  process.send(stop, Nil)
  let assert Ok(Nil) = process.selector_receive(selector, 5000)

  // The supervisor stops its children before it exits, so the connection
  // is already closed when the monitor fires and no wait is needed.
  assert simplifile.is_file(path <> "-wal") == Ok(False)

  support.remove_files(path)
}

/// The envelope count and the bytes charged to the queue, read through a
/// separate connection.
fn stored(path: String) -> #(Int, Int) {
  let assert Ok(raw) = sqlight.open(path)
  let assert Ok([rows]) =
    sqlight.query(
      "SELECT count(*) FROM envelopes",
      on: raw,
      with: [],
      expecting: support.first_int(),
    )
  let assert Ok([bytes]) =
    sqlight.query(
      "SELECT bytes_used FROM queues",
      on: raw,
      with: [],
      expecting: support.first_int(),
    )
  let assert Ok(Nil) = sqlight.close(raw)

  #(rows, bytes)
}
