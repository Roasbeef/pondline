//// Shared fixtures for the runtime tests: an in-process mailbox node with
//// its HTTP server on an ephemeral port, daemons on throwaway state
//// directories, and a polling wait.

import core/capability
import core/endpoint
import core/envelope
import core/mailbox/protocol
import core/route
import core/time.{Instant}
import daemon/api
import daemon/config.{type Config}
import daemon/mailbox_client
import daemon/node
import daemon/transport
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

/// A running mailbox and what a daemon needs to use it.
pub type Mailbox {
  Mailbox(
    /// The port its HTTP server is bound to.
    port: Int,
    /// A file holding its provisioning capability.
    provisioning_file: String,
    /// The node, for tests that talk to it directly.
    node: mailbox_node.Node,
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
    ))
  let assert Ok(server) =
    mailbox_http.start(
      running,
      mailbox_http.Config(interface: "127.0.0.1", port: 0),
    )

  Mailbox(port: server.port, provisioning_file: file, node: running)
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
  case check() {
    Some(value) -> value

    None ->
      case timeout_ms > 0 {
        True -> {
          process.sleep(50)
          eventually(timeout_ms - 50, check)
        }

        False -> panic as "the condition did not become true in time"
      }
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

/// An environment variable, if set.
@external(erlang, "daemon_test_ffi", "env")
pub fn env(name: String) -> Result(String, Nil)

/// Starts collecting everything written to standard error.
@external(erlang, "daemon_test_ffi", "capture_start")
pub fn capture_start() -> Nil

/// Stops collecting and returns what was written since `capture_start`.
@external(erlang, "daemon_test_ffi", "capture_stop")
pub fn capture_stop() -> BitArray
