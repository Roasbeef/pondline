//// The Tor carrier: owns the sidecar and turns it into a `Dialer`
//// (spec §6.1, §10.3, ADR-001).
////
//// The onion half of `transport.Dialer` is a function given to it, because
//// `transport` must not depend on Tor. This module is where that function is
//// built. A state machine owns the `Tor` handle, so the sidecar's lifetime is
//// the machine's: the handle is linked to the process that started it, and
//// when the supervisor stops the machine the sidecar's stdin closes and it
//// exits. The dial function asks the machine for the handle on every call
//// instead of capturing one, so a restart that replaces the machine does not
//// leave a stale handle in a dialer that other processes already hold.
////
//// ## Bootstrapping
////
//// The sidecar starts when the machine does, but bootstrapping takes
//// seconds to minutes, so it runs as a `weft` run of one task, relayed to
//// the machine and bounded by `bootstrap_deadline_ms`. Until it finishes, an
//// onion dial fails like an unreachable mailbox does and the workers back
//// off; nothing blocks on it. With no sidecar configured, every onion dial
//// fails the same way and only loopback endpoints work, which is the offline
//// and test configuration.
////
//// ## A `weft/state_machine`
////
//// | State | Meaning |
//// |---|---|
//// | `Unused` | no sidecar was configured |
//// | `Bootstrapping` | the run is going |
//// | `Bootstrapped` | the run completed |
//// | `Unavailable` | the run failed, crashed, was abandoned at its deadline or was lost, or the sidecar was given up on |
////
//// The machine is the one place that decides which of the last three the
//// carrier is in, and it reports each decision to the status cell. The run's
//// outcome is followed by an end marker. The outcome settles the machine in
//// `Bootstrapping`, and anything that arrives in a settled state is the end
//// marker and is dropped, so a late marker cannot overwrite the result. The
//// handle is requested in every state and always answered from the data.
////
//// ## The sidecar's restarts
////
//// `tor` restarts a crashed sidecar by itself, and the new one is not
//// bootstrapped, so a carrier that stayed `Bootstrapped` would fail every
//// onion dial from then on. The machine subscribes to the sidecar's events
//// (`tor.subscribe`). `SidecarRestarted` starts a new bootstrap run and
//// moves the machine back to `Bootstrapping`, whatever state it was in;
//// `SidecarGaveUp` settles it in `Unavailable` for good. The run is
//// replaced, not cancelled: the selector is rebuilt around the new run's
//// subject, so a stale outcome or end marker of the old run is never read,
//// and the old run ends by itself, because the death that preceded the
//// restart already failed its pending request and its deadline bounds it
//// anyway. The restart count is `tor`'s; a carrier that sees `SidecarDied`
//// has nothing to do until one of the other two follows.
////
//// One isolation group per queue is the caller's choice (`mailbox_client`
//// passes the queue id in hex); this module passes it through unchanged.

import core/endpoint
import daemon/mail
import daemon/status
import daemon/transport.{type Connection, type Dialer, type TransportError}
import gleam/erlang/process.{type Name, type Selector, type Subject}
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import tor
import tor/address
import tor/stream
import weft
import weft/state_machine as sm

/// How long a bootstrap may take before the carrier calls it failed.
pub const bootstrap_timeout_ms = 180_000

/// How long the bootstrap run may take: the client's own timeout and a
/// margin, so the client's decides first and the run's deadline is the
/// backstop for a call that never returns.
pub const bootstrap_deadline_ms = 190_000

/// The budget for one write to an onion stream.
pub const send_timeout_ms = 60_000

/// What the machine is told.
pub opaque type Message {
  GetTor(reply_with: Subject(Option(tor.Tor)))
  Bootstrap(pulled: weft.Pulled(Nil, Nil))
  SidecarEvent(event: tor.Event)
}

/// What the carrier knows about its sidecar.
type State {
  Unused
  Bootstrapping
  Bootstrapped
  Unavailable
}

/// What the machine keeps: the handle it answers requests with, where it
/// reports Tor's status, and what a new bootstrap run needs. The state never
/// carries any of it, so starting another run is not a state change.
type Data {
  Data(
    held: Option(tor.Tor),
    status: Name(status.Message),
    self: Subject(Message),
    events: Subject(tor.Event),
    bootstrap: fn() -> Result(Nil, Nil),
    deadline_ms: Int,
  )
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
  sm.start(builder(name, status_name, binary, state_dir))
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
  sm.supervised(builder(name, status_name, binary, state_dir))
}

/// Starts a carrier that bootstraps with `bootstrap` instead of a sidecar,
/// under a run deadline of `deadline_ms`. `subscribe` receives the subject
/// the machine listens to for the sidecar's events, as `tor.subscribe` does
/// for a real sidecar; a subject is read only by the process that made it,
/// so the machine makes it and hands it out. It holds no handle, so dials
/// fail, and exists to exercise the bootstrap's outcomes and the restarts
/// without Tor.
///
/// ## Examples
///
/// ```gleam
/// carrier.start_with_bootstrap(
///   name,
///   status_name,
///   fn() { Ok(Nil) },
///   1000,
///   fn(events) { process.send(handoff, events) },
/// )
/// // -> Ok(started), and Tor reports bootstrapped
/// ```
pub fn start_with_bootstrap(
  name: Name(Message),
  status_name: Name(status.Message),
  bootstrap: fn() -> Result(Nil, Nil),
  deadline_ms: Int,
  subscribe: fn(Subject(tor.Event)) -> Nil,
) -> actor.StartResult(Subject(Message)) {
  sm.new_with_initialiser(5000, fn(subject) {
    status.set_tor(status_name, status.TorStarting)

    let events = process.new_subject()
    subscribe(events)

    Ok(
      begin(Data(
        held: None,
        status: status_name,
        self: subject,
        events:,
        bootstrap:,
        deadline_ms:,
      )),
    )
  })
  |> sm.on_event(handle)
  |> sm.named(name)
  |> sm.start
}

/// The carrier's machine: named, and starting the sidecar and its bootstrap
/// in the new process, which then owns the handle.
fn builder(
  name: Name(Message),
  status_name: Name(status.Message),
  binary: Option(String),
  state_dir: String,
) -> sm.Builder(State, Data, Message, Subject(Message)) {
  sm.new_with_initialiser(60_000, fn(subject) {
    launch(subject, status_name, binary, state_dir)
  })
  |> sm.on_event(handle)
  |> sm.named(name)
}

/// Starts the sidecar and its bootstrap, or notes there is none.
fn launch(
  subject: Subject(Message),
  status_name: Name(status.Message),
  binary: Option(String),
  state_dir: String,
) -> Result(sm.Initialised(State, Data, Message, Subject(Message)), String) {
  // Without a binary there is no Tor and nothing to start.
  case binary {
    None -> {
      status.set_tor(status_name, status.TorNotUsed)

      // Nothing is ever subscribed, so the machine hears nothing but its own
      // mailbox in `Unused`.
      sm.initialised(
        Unused,
        Data(
          held: None,
          status: status_name,
          self: subject,
          events: process.new_subject(),
          bootstrap: fn() { Error(Nil) },
          deadline_ms: 0,
        ),
      )
      |> sm.returning(subject)
      |> Ok
    }

    Some(path) -> {
      status.set_tor(status_name, status.TorStarting)

      // The sidecar's unix socket lives under its state directory, which
      // must be short enough for a socket path.
      use started <- result.try(
        tor.start(tor.config(path, state_dir <> "/tor"))
        |> result.replace_error("the Tor sidecar could not be started"),
      )

      // The machine hears the sidecar's restarts, which un-bootstrap it.
      let events = process.new_subject()
      tor.subscribe(started, events)

      Ok(
        begin(Data(
          held: Some(started),
          status: status_name,
          self: subject,
          events:,
          bootstrap: fn() {
            tor.bootstrap(started, bootstrap_timeout_ms)
            |> result.replace_error(Nil)
          },
          deadline_ms: bootstrap_deadline_ms,
        )),
      )
    }
  }
}

/// Starts a bootstrap run and returns what the machine listens to while it
/// goes: its own mailbox, the sidecar's events and the run's subject, and
/// no other run's. The relay is linked to the machine, so the machine's end
/// takes the run with it.
fn run(data: Data) -> Selector(Message) {
  let sink = process.new_subject()
  let _relay =
    weft.new([data.bootstrap])
    |> weft.deadline(data.deadline_ms)
    |> weft.start_relayed(sink)

  process.new_selector()
  |> process.select(data.self)
  |> process.select_map(data.events, SidecarEvent)
  |> process.select_map(sink, Bootstrap)
}

/// Builds the machine's start in `Bootstrapping`, with the first run going.
fn begin(data: Data) -> sm.Initialised(State, Data, Message, Subject(Message)) {
  sm.initialised(Bootstrapping, data)
  |> sm.selecting(run(data))
  |> sm.returning(data.self)
}

/// Handles one event. Every state and message pair is written.
fn handle(
  state: State,
  data: Data,
  message: Message,
) -> sm.Next(State, Data, Message) {
  case state, message {
    // The handle is the same in every state; a caller that dials early gets
    // it and the sidecar's own answer.
    Unused, GetTor(reply_with:)
    | Bootstrapping, GetTor(reply_with:)
    | Bootstrapped, GetTor(reply_with:)
    | Unavailable, GetTor(reply_with:)
    -> {
      process.send(reply_with, data.held)
      sm.keep(data)
    }

    Bootstrapping, Bootstrap(pulled:) -> settled(data, pulled)

    // A settled carrier has decided; what arrives now is the end marker of
    // the run that decided it, and `Unused` never starts a run.
    Unused, Bootstrap(_) -> sm.keep(data)
    Bootstrapped, Bootstrap(_) -> sm.keep(data)
    Unavailable, Bootstrap(_) -> sm.keep(data)

    // Without a sidecar there is nothing to hear from.
    Unused, SidecarEvent(_) -> sm.keep(data)

    Bootstrapping, SidecarEvent(event:)
    | Bootstrapped, SidecarEvent(event:)
    | Unavailable, SidecarEvent(event:)
    -> followed(data, event)
  }
}

/// What the sidecar's own event means to a carrier that owns one.
fn followed(data: Data, event: tor.Event) -> sm.Next(State, Data, Message) {
  case event {
    // The replacement sidecar listens but is not bootstrapped, so whatever
    // the carrier had decided about the old one no longer holds.
    tor.SidecarRestarted -> {
      status.set_tor(data.status, status.TorStarting)

      sm.transition(to: Bootstrapping, data:)
      |> sm.with_selector(run(data))
    }

    // `tor` restarts nothing more; the carrier is done for good.
    tor.SidecarGaveUp -> fail(data)

    // A death is followed by a restart or by giving up; the verdict waits
    // for that. A service's state is not the carrier's business.
    tor.SidecarDied(_) -> sm.keep(data)
    tor.ServiceStateChanged(_, _) -> sm.keep(data)
  }
}

/// Decides from what the run pushed, and reports the decision.
fn settled(
  data: Data,
  pulled: weft.Pulled(Nil, Nil),
) -> sm.Next(State, Data, Message) {
  // The outcome decides. An end marker without an outcome cannot arrive
  // here, and a run that was lost without one failed.
  case pulled {
    weft.PulledOutcome(outcome:) ->
      case outcome {
        weft.Completed(index: _, value: Nil) -> succeed(data)
        weft.Failed(index: _, error: _) -> fail(data)
        weft.Crashed(index: _, reason: _) -> fail(data)
        weft.Abandoned(index: _) -> fail(data)
        weft.NeverStarted(index: _) -> fail(data)
        weft.DrainProofLost(index: _, reason: _) -> fail(data)
        weft.CancellationUnconfirmed(index: _) -> fail(data)
      }

    weft.AllDelivered -> sm.keep(data)
    weft.NotYet -> sm.keep(data)
    weft.RunLost(reason: _) -> fail(data)
  }
}

/// The bootstrap completed: report it and settle.
fn succeed(data: Data) -> sm.Next(State, Data, Message) {
  status.set_tor(data.status, status.TorBootstrapped)

  sm.transition(to: Bootstrapped, data:)
}

/// The bootstrap did not complete, for any reason: report it and settle.
fn fail(data: Data) -> sm.Next(State, Data, Message) {
  status.set_tor(data.status, status.TorUnavailable)

  sm.transition(to: Unavailable, data:)
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
