//// The Tor carrier: owns the sidecar and turns it into a `Dialer`
//// (spec §6.1, §10.3, ADR-001).
////
//// The onion half of `transport.Dialer` is a function given to it, because
//// `transport` must not depend on Tor. This module is where that function is
//// built. An actor owns the `Tor` handle, so the sidecar's lifetime is the
//// actor's: the handle is linked to the process that started it, and when the
//// supervisor stops this actor the sidecar's stdin closes and it exits. The
//// dial function asks the actor for the handle on every call instead of
//// capturing one, so a restart that replaces the actor does not leave a stale
//// handle in a dialer that other processes already hold.
////
//// ## Bootstrapping
////
//// The sidecar starts when the actor does, but bootstrapping takes seconds
//// to minutes, so it runs in its own process and reports to the status cell.
//// Until it finishes, an onion dial fails like an unreachable mailbox does
//// and the workers back off; nothing blocks on it. With no sidecar
//// configured, every onion dial fails the same way and only loopback
//// endpoints work, which is the offline and test configuration.
////
//// One isolation group per queue is the caller's choice (`mailbox_client`
//// passes the queue id in hex); this module passes it through unchanged.

import core/endpoint
import daemon/mail
import daemon/status
import daemon/transport.{type Connection, type Dialer, type TransportError}
import gleam/erlang/process.{type Name, type Subject}
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import tor
import tor/address
import tor/stream

/// How long a bootstrap may take before the carrier calls it failed.
pub const bootstrap_timeout_ms = 180_000

/// The budget for one write to an onion stream.
pub const send_timeout_ms = 60_000

/// What the actor is told.
pub opaque type Message {
  GetTor(reply_with: Subject(Option(tor.Tor)))
}

/// Starts the carrier under `name`. With a sidecar `binary`, starts it and
/// begins bootstrapping; without one, holds nothing. Start fails when the
/// sidecar cannot be spawned.
///
/// ## Examples
///
/// ```gleam
/// carrier.start(name, status_name, Some("/opt/reedwire/reedwire-tor"), dir)
/// // -> Ok(started)
/// ```
pub fn start(
  name: Name(Message),
  status_name: Name(status.Message),
  binary: Option(String),
  state_dir: String,
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(60_000, fn(subject) {
    use handle <- result.try(launch(status_name, binary, state_dir))

    actor.initialised(handle)
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.on_message(handle_message)
  |> actor.named(name)
  |> actor.start
}

/// The carrier as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// carrier.supervised(name, status_name, None, dir)
/// ```
pub fn supervised(
  name: Name(Message),
  status_name: Name(status.Message),
  binary: Option(String),
  state_dir: String,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() { start(name, status_name, binary, state_dir) })
}

/// Starts the sidecar and its bootstrap, or notes there is none.
fn launch(
  status_name: Name(status.Message),
  binary: Option(String),
  state_dir: String,
) -> Result(Option(tor.Tor), String) {
  // Without a binary there is no Tor and nothing to start.
  case binary {
    None -> {
      status.set_tor(status_name, status.TorNotUsed)
      Ok(None)
    }

    Some(path) -> {
      status.set_tor(status_name, status.TorStarting)

      // The sidecar's unix socket lives under its state directory, which
      // must be short enough for a socket path.
      use started <- result.try(
        tor.start(tor.config(path, state_dir <> "/tor"))
        |> result.replace_error("the Tor sidecar could not be started"),
      )

      process.spawn(fn() { bootstrap(status_name, started) })
      Ok(Some(started))
    }
  }
}

/// Bootstraps and reports the result. Runs in its own process because it
/// can take minutes.
fn bootstrap(status_name: Name(status.Message), started: tor.Tor) -> Nil {
  case tor.bootstrap(started, bootstrap_timeout_ms) {
    Ok(Nil) -> status.set_tor(status_name, status.TorBootstrapped)
    Error(_) -> status.set_tor(status_name, status.TorUnavailable)
  }
}

/// Answers a request for the `Tor` handle.
fn handle_message(
  held: Option(tor.Tor),
  message: Message,
) -> actor.Next(Option(tor.Tor), Message) {
  // The only request is for the handle, answered from what the actor holds.
  case message {
    GetTor(reply_with:) -> {
      process.send(reply_with, held)
      actor.continue(held)
    }
  }
}

/// A dialer that enforces `policy`, reaches loopback with a socket and
/// onion services through the carrier named `name`.
///
/// ## Examples
///
/// ```gleam
/// carrier.dialer(name, endpoint.TorOnly)
/// ```
pub fn dialer(name: Name(Message), policy: endpoint.CarrierPolicy) -> Dialer {
  transport.new_dialer(policy, fn(host, port, group, timeout_ms) {
    dial_onion(name, host, port, group, timeout_ms)
  })
}

/// Opens one onion stream through the sidecar and wraps it as a
/// `Connection`.
fn dial_onion(
  name: Name(Message),
  host: endpoint.OnionAddress,
  port: endpoint.Port,
  group: String,
  timeout_ms: Int,
) -> Result(Connection, TransportError) {
  use held <- result.try(
    mail.ask(name, 1000, GetTor)
    |> result.replace_error(transport.ConnectFailed),
  )
  use started <- result.try(option.to_result(held, transport.ConnectFailed))

  // The address and port are re-parsed into the tor package's own types,
  // which mirror `core/endpoint` because `tor` cannot depend on `core`.
  use onion <- result.try(
    address.parse_onion(endpoint.onion_host(host))
    |> result.replace_error(transport.ConnectFailed),
  )
  use virtual <- result.try(
    address.port(endpoint.port_number(port))
    |> result.replace_error(transport.ConnectFailed),
  )
  use opened <- result.try(
    tor.connect(started, onion, virtual, group, timeout_ms)
    |> result.replace_error(transport.ConnectFailed),
  )

  Ok(wrap(opened))
}

/// An onion stream as the transport's three functions.
fn wrap(opened: stream.Stream) -> Connection {
  transport.Connection(
    send: fn(bytes) {
      stream.send(opened, bytes, send_timeout_ms)
      |> result.map_error(from_stream_error)
    },
    receive: fn(max_bytes, timeout_ms) {
      stream.recv(opened, max_bytes, timeout_ms)
      |> result.map_error(from_stream_error)
    },
    close: fn() { stream.close(opened) },
  )
}

/// A stream failure in the transport's three cases.
fn from_stream_error(error: stream.StreamError) -> TransportError {
  case error {
    stream.Closed -> transport.Closed
    stream.Timeout -> transport.TimedOut
    stream.Failed -> transport.Failed
  }
}
