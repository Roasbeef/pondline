//// Shared fixtures for the runtime tests: an in-process mailbox node with
//// its HTTP server on an ephemeral port, daemons on throwaway state
//// directories, and a bounded wait built on `weft/poll`.

import core/capability
import core/endpoint
import core/envelope
import core/id
import core/mailbox/protocol
import core/route
import core/time.{Instant}
import daemon/api
import daemon/config.{type Config}
import daemon/mailbox_client
import daemon/node
import daemon/transport
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/option.{type Option, None, Some}
import mailbox/http as mailbox_http
import mailbox/node as mailbox_node
import mailbox/service
import mailbox/store as mailbox_store
import primitives
import simplifile
import sqlight
import weft/poll
import weft/timer

/// A running mailbox and what a daemon needs to use it.
pub type Mailbox {
  Mailbox(
    /// The port its HTTP server is bound to.
    port: Int,
    /// A file holding its provisioning capability.
    provisioning_file: String,
    /// The node, for tests that talk to it directly.
    node: mailbox_node.Node,
    /// The HTTP listener, for tests that take the mailbox off the network
    /// and bring it back on the same port.
    server: mailbox_http.Server,
    /// The mailbox's database file, for tests that play a mailbox damaging
    /// what it already stored.
    path: String,
  )
}

/// A path under `build/` that no other test uses.
pub fn fresh(prefix: String) -> String {
  "build/daemon_test_"
  <> prefix
  <> "_"
  <> int.to_string(int.random(1_000_000_000))
}

/// Starts a mailbox with a large provisioning allowance.
pub fn start_mailbox() -> Mailbox {
  let path = fresh("mailbox") <> ".db"
  let assert Ok(db) = mailbox_store.open(path)
  let assert Ok(provision) =
    service.create_grant(db, 1000, primitives.random_bytes)
  let assert Ok(Nil) = mailbox_store.close(db)

  let file = fresh("provision") <> ".cap"
  let assert Ok(Nil) = simplifile.write_bits(file, capability.expose(provision))

  let clock = config.system_clock()
  let assert Ok(#(_, running)) =
    mailbox_node.start(mailbox_node.Config(
      path:,
      sweep_period_ms: 60_000,
      clock:,
      names: mailbox_node.new_names(),
      timer: timer.WallClock,
      interceptor: None,
      store_faults: None,
    ))
  let assert Ok(server) =
    mailbox_http.start(
      running,
      mailbox_http.Config(interface: "127.0.0.1", port: 0),
    )

  Mailbox(
    port: server.port,
    provisioning_file: file,
    node: running,
    server:,
    path:,
  )
}

/// A configuration for a daemon on `directory` that uses `mailbox` over
/// loopback.
pub fn daemon_config(mailbox: Mailbox, directory: String) -> Config {
  let assert Ok(port) = endpoint.port(mailbox.port)

  config.new(
    directory,
    config.Mailbox(
      endpoint: endpoint.Loopback(port),
      provisioning_file: mailbox.provisioning_file,
    ),
    endpoint.TorOrLoopback,
  )
}

/// Starts a daemon on a fresh directory.
pub fn start_daemon(mailbox: Mailbox) -> #(api.Daemon, Config) {
  let settings = daemon_config(mailbox, fresh("state"))
  let assert Ok(daemon) = node.start(settings)

  #(daemon, settings)
}

/// Polls `check` every 50 ms until it returns `Some`, and panics after
/// `timeout_ms`. The panic is the test failing.
pub fn eventually(timeout_ms: Int, check: fn() -> Option(a)) -> a {
  let waited =
    poll.until(within: timeout_ms, every: 50, attempt: fn() {
      case check() {
        Some(value) -> poll.Done(value)
        None -> poll.Retry
      }
    })

  case waited {
    poll.Answered(value:) -> value
    poll.Failed(error: Nil) -> panic as "the probe cannot succeed"
    poll.Expired -> panic as "the condition did not become true in time"
  }
}

/// `Some(Nil)` when `condition` holds, for `eventually`.
pub fn when(condition: Bool) -> Option(Nil) {
  case condition {
    True -> Some(Nil)
    False -> None
  }
}

/// The current instant, from the same clock the daemons use.
pub fn now() -> time.Instant {
  let clock = config.system_clock()
  let Instant(seconds) = clock()
  Instant(seconds)
}

/// Takes the mailbox off the network: its HTTP listener dies and its port
/// refuses connections. The node and its store are untouched.
pub fn stop_listener(mailbox: Mailbox) -> Nil {
  let supervisor = mailbox.server.supervisor.pid

  // The listener's supervisor is linked to the test process, and killing it
  // would otherwise take the test down with it.
  process.unlink(supervisor)
  process.kill(supervisor)

  // The port is free once the listener's socket is closed.
  let gone =
    poll.until(within: 5000, every: 20, attempt: fn() {
      case process.is_alive(supervisor) {
        True -> poll.Retry
        False -> poll.Done(Nil)
      }
    })

  let assert poll.Answered(Nil) = gone as "the listener stops"
  Nil
}

/// Brings a stopped mailbox back on the port it had.
pub fn restart_listener(mailbox: Mailbox) -> Mailbox {
  let assert Ok(server) =
    mailbox_http.start(
      mailbox.node,
      mailbox_http.Config(interface: "127.0.0.1", port: mailbox.port),
    )
    as "the port is free again"

  Mailbox(..mailbox, server:)
}

/// Takes the daemon database's write lock from outside, as a stuck backup
/// tool would, so the daemon's next commit cannot get in.
pub fn hold_database(directory: String) -> sqlight.Connection {
  let assert Ok(connection) = sqlight.open(directory <> "/daemon.db")
  let assert Ok(Nil) = sqlight.exec("PRAGMA busy_timeout=5000", connection)
  let assert Ok(Nil) = sqlight.exec("BEGIN IMMEDIATE", connection)

  connection
}

/// Lets a held database go.
pub fn release_database(connection: sqlight.Connection) -> Nil {
  let assert Ok(Nil) = sqlight.exec("ROLLBACK", connection)
  let assert Ok(Nil) = sqlight.close(connection)

  Nil
}

/// A dialer that reaches loopback only, for tests that talk to the mailbox
/// themselves.
pub fn loopback_dialer() -> transport.Dialer {
  transport.new_dialer(endpoint.TorOrLoopback, fn(_, _, _, _) {
    Error(transport.ConnectFailed)
  })
}

/// The envelopes the mailbox holds for an inbox right now, without waiting.
pub fn stored_in(inbox: route.Inbox) -> List(envelope.StoredEnvelope) {
  let request =
    protocol.Fetch(
      queue: inbox.queue,
      read: inbox.read,
      wait_seconds: 0,
      max_envelopes: 16,
    )

  let assert Ok(protocol.Batch(envelopes:)) =
    mailbox_client.call(
      loopback_dialer(),
      inbox.endpoint,
      "test",
      request,
      5000,
    )

  envelopes
}

/// Flips one byte inside an envelope the mailbox stored, behind its back, as
/// a mailbox whose disk or operator damaged it after answering `Appended`
/// would. Byte 20 is inside the ratchet message, past the length prefix and
/// the frame tag, so the copy can no longer be decrypted.
pub fn corrupt_stored(
  mailbox: Mailbox,
  queue: id.Id(id.Queue),
  envelope: id.Id(id.Envelope),
) -> Nil {
  let connection = mailbox_database(mailbox)
  let assert Ok([stored]) =
    sqlight.query(
      "SELECT ciphertext FROM envelopes WHERE queue_id = ? AND envelope_id = ?",
      on: connection,
      with: [
        sqlight.blob(id.to_bytes(queue)),
        sqlight.blob(id.to_bytes(envelope)),
      ],
      expecting: decode.field(0, decode.bit_array, decode.success),
    )
  let assert <<before:bytes-size(20), byte, after:bytes>> = stored
  let flipped = <<
    before:bits,
    { int.bitwise_exclusive_or(byte, 0xFF) },
    after:bits,
  >>
  let assert Ok(_) =
    sqlight.query(
      "UPDATE envelopes SET ciphertext = ? WHERE queue_id = ? AND envelope_id = ?",
      on: connection,
      with: [
        sqlight.blob(flipped),
        sqlight.blob(id.to_bytes(queue)),
        sqlight.blob(id.to_bytes(envelope)),
      ],
      expecting: decode.success(Nil),
    )
  let assert Ok(Nil) = sqlight.close(connection)

  Nil
}

/// Deletes an envelope the mailbox stored, behind its back and leaving no
/// tombstone, as a mailbox that lost it after answering `Appended` would.
pub fn lose_stored(
  mailbox: Mailbox,
  queue: id.Id(id.Queue),
  envelope: id.Id(id.Envelope),
) -> Nil {
  let connection = mailbox_database(mailbox)
  let assert Ok(_) =
    sqlight.query(
      "DELETE FROM envelopes WHERE queue_id = ? AND envelope_id = ?",
      on: connection,
      with: [
        sqlight.blob(id.to_bytes(queue)),
        sqlight.blob(id.to_bytes(envelope)),
      ],
      expecting: decode.success(Nil),
    )
  let assert Ok(Nil) = sqlight.close(connection)

  Nil
}

/// A second connection to a running mailbox's database. The mailbox's own
/// connection holds no long transaction, so a short write here gets in.
fn mailbox_database(mailbox: Mailbox) -> sqlight.Connection {
  let assert Ok(connection) = sqlight.open(mailbox.path)
  let assert Ok(Nil) = sqlight.exec("PRAGMA busy_timeout=5000", connection)
  connection
}

/// A clock for a daemon's `Config.clock` that runs on the wall clock plus a
/// shift the test sets with `shift_clock`, so a test can let a window of
/// seconds pass at once. `name` keeps one test's shift from another's.
pub fn shiftable_clock(name: String) -> fn() -> time.Instant {
  let wall = config.system_clock()

  fn() {
    let Instant(seconds) = wall()
    Instant(seconds + clock_shift(name))
  }
}

/// Moves a `shiftable_clock` to `seconds` ahead of the wall clock.
@external(erlang, "daemon_test_ffi", "set_clock_shift")
pub fn shift_clock(name: String, seconds: Int) -> Nil

@external(erlang, "daemon_test_ffi", "clock_shift")
fn clock_shift(name: String) -> Int

/// An environment variable, if set.
@external(erlang, "daemon_test_ffi", "env")
pub fn env(name: String) -> Result(String, Nil)

/// Starts collecting everything written to standard error.
@external(erlang, "daemon_test_ffi", "capture_start")
pub fn capture_start() -> Nil

/// Stops collecting and returns what was written since `capture_start`.
@external(erlang, "daemon_test_ffi", "capture_stop")
pub fn capture_stop() -> BitArray
