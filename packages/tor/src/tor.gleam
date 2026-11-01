//// Tor for Reedwire: onion streams and onion services through the
//// `reedwire-tor` sidecar, a separate OS process running Arti.
////
//// Why a sidecar and not a NIF: a crash or stall inside Arti must not take
//// the BEAM down, and bytes that cross a real socket give the BEAM ordinary
//// passive-mode backpressure end to end, so this package builds no
//// read-credit machinery (spec section 10.4; `docs/adr/001-tor-sidecar.md`).
////
//// ## How the pieces fit
////
//// One actor, started by `start`, owns the sidecar's Erlang port. It sends
//// control frames (`tor/internal/codec`), turns the replies into typed
//// results for the callers waiting on them, and watches for the process to
//// exit. Outbound streams do not go through the actor at all: `connect`
//// opens a unix socket to the sidecar directly (`tor/stream`), so stream
//// traffic never queues behind control traffic and a slow stream cannot
//// slow the actor.
////
//// ## The sidecar's lifetime
////
//// The port is owned by the actor, so if the actor dies the VM closes the
//// port, the sidecar's stdin reaches end of file, and the sidecar exits.
//// If the sidecar dies first, the actor is told through `exit_status` and
//// restarts it itself rather than leaving that to a supervisor. A
//// supervisor restart would hand callers a new `Tor` value and drop the
//// subscribers and the pending requests the actor holds, while a sidecar
//// restart inside the actor keeps all of them.
////
//// The restart policy is bounded by `max_restarts`: that many consecutive
//// restarts that do not end in a successful bootstrap, and the actor stops
//// restarting, tells subscribers with `SidecarGaveUp`, and answers every
//// later request with `SidecarUnavailable`. A sidecar that works and then
//// crashes once gets a full budget again, because a successful bootstrap
//// resets the count. After a restart the new sidecar is not bootstrapped:
//// the owner sees `SidecarRestarted` and must call `bootstrap` and
//// `host_onion` again. Onion services are expected to keep their address
//// across restarts because Arti persists the key under the state
//// directory.
////
//// ## Failure semantics
////
//// A request that is pending when the sidecar dies fails with
//// `SidecarExited`. A request made while the sidecar is restarting fails
//// at once with `SidecarUnavailable`; the caller may retry. A timeout
//// stops the caller waiting and withdraws the reply address, but does not
//// cancel work the sidecar already began: a bootstrap that times out for
//// the caller still finishes in the sidecar.

import gleam/dict.{type Dict}
import gleam/erlang/port.{type Port}
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/actor
import gleam/otp/supervision
import gleam/result
import gleam/string
import tor/address.{type OnionAddress, type Port as OnionPort}
import tor/internal/codec
import tor/internal/ffi_port.{PortData, PortExit}
import tor/stream.{type OpenError, type Stream}

/// The longest onion service nickname, in bytes. Arti enforces its own
/// grammar; this only keeps the control frame small.
pub const max_nickname_bytes = 64

/// How to run the sidecar.
pub type Config {
  Config(
    /// The path of the `reedwire-tor` binary.
    binary_path: String,
    /// The sidecar's state directory: Arti's keys and cache, and the
    /// outbound socket. Created mode 0700. It must be unique to one
    /// sidecar, and its path must be short enough for a unix socket
    /// (about 100 bytes on macOS).
    state_dir: String,
    /// How many consecutive restarts without a successful bootstrap are
    /// allowed before the actor gives up.
    max_restarts: Int,
    /// How long, in milliseconds, a freshly started sidecar has to report
    /// that it is listening.
    ready_timeout_ms: Int,
  )
}

/// The actor's mailbox protocol. Public only because the opaque `Tor`
/// carries a subject of it; callers use the functions in this module.
pub type Message {
  /// Wait until the sidecar is listening.
  AwaitReady(reply_to: Subject(Result(Nil, TorError)))

  /// Bootstrap the Tor client.
  Bootstrap(reply_to: Subject(Result(Nil, TorError)))

  /// Launch an onion service.
  HostOnion(
    nickname: String,
    local_port: Int,
    reply_to: Subject(Result(OnionHost, TorError)),
  )

  /// A bootstrap caller gave up; forget its reply address.
  AbandonBootstrap(reply_to: Subject(Result(Nil, TorError)))

  /// A host caller gave up; forget its reply address.
  AbandonHost(reply_to: Subject(Result(OnionHost, TorError)))

  /// Add an event subscriber.
  Subscribe(subscriber: Subject(Event))

  /// Ask for the sidecar's operating system pid.
  GetPid(reply_to: Subject(Result(Int, TorError)))

  /// A message from the port, or `Error(Nil)` for anything else that
  /// reached the mailbox.
  FromPort(message: Result(ffi_port.PortMessage, Nil))

  /// The sidecar on this port did not report ready in time.
  ReadyTimeout(port: Port)

  /// Stop the sidecar and the actor.
  Stop(reply_to: Subject(Result(Nil, TorError)))
}

/// A request that is waiting for its reply frame.
type Pending {
  PendingBootstrap(reply_to: Subject(Result(Nil, TorError)))
  PendingHost(nickname: String, reply_to: Subject(Result(OnionHost, TorError)))
}

/// Where the sidecar is in its life.
type Sidecar {
  /// Spawned, not yet listening. Requests are refused until it is.
  Starting(port: Port)

  /// Listening; requests go out.
  Serving(port: Port)

  /// The restart budget is spent.
  GivenUp
}

type State {
  State(
    config: Config,
    self: Subject(Message),
    sidecar: Sidecar,
    next_id: Int,
    pending: Dict(Int, Pending),
    subscribers: List(Subject(Event)),
    waiters: List(Subject(Result(Nil, TorError))),
    restarts: Int,
  )
}

/// A running onion service.
pub type OnionHost {
  OnionHost(
    /// The nickname the service was launched under; it selects the key.
    nickname: String,
    /// The service's `.onion` address, stable across restarts.
    address: OnionAddress,
  )
}

/// Why starting failed.
pub type StartFailure {
  /// The sidecar binary could not be spawned.
  SpawnFailed

  /// The sidecar spawned but never reported ready, or kept exiting, until
  /// the restart budget ran out.
  NeverReady
}

/// Why an operation failed.
pub type TorError {
  /// `start` failed.
  StartFailed(reason: StartFailure)

  /// The sidecar reported that it could not serve the request.
  RequestFailed(code: codec.FailCode, text: String)

  /// The sidecar died while the request was pending.
  SidecarExited(status: Int)

  /// The sidecar is restarting or has been given up on; no request can be
  /// served now.
  SidecarUnavailable

  /// The caller's deadline passed. The work may still finish in the
  /// sidecar.
  Timeout

  /// The nickname is empty or longer than `max_nickname_bytes`.
  BadNickname

  /// The sidecar answered with a hostname that is not a v3 onion address.
  BadHostname

  /// Opening an outbound stream failed.
  OpenFailed(reason: OpenError)
}

/// Something that happened to the sidecar or to a service, for
/// subscribers.
pub type Event {
  /// An onion service changed state.
  ServiceStateChanged(nickname: String, state: codec.ServiceState)

  /// The sidecar process exited with this status. `-1` means its control
  /// channel carried something undecodable, `-2` that it never reported
  /// ready; in both cases the actor closed it.
  SidecarDied(status: Int)

  /// A new sidecar is listening. It is not bootstrapped.
  SidecarRestarted

  /// The restart budget is spent; the actor serves no more requests.
  SidecarGaveUp
}

/// A handle to a running sidecar and the actor that owns it.
pub opaque type Tor {
  Tor(subject: Subject(Message), config: Config)
}

/// A configuration with the default restart budget (3) and ready timeout
/// (10 seconds).
///
/// ## Examples
///
/// ```gleam
/// tor.config("/opt/reedwire/reedwire-tor", "/var/lib/reedwire/tor")
/// ```
pub fn config(binary_path: String, state_dir: String) -> Config {
  Config(binary_path:, state_dir:, max_restarts: 3, ready_timeout_ms: 10_000)
}

/// Starts the sidecar and the actor that owns it, returning once the
/// sidecar is listening for outbound connections. Not bootstrapped yet:
/// call `bootstrap` next.
///
/// The actor is linked to the caller, so the caller's death takes the
/// actor, the port, and the sidecar with it.
///
/// ## Examples
///
/// ```gleam
/// tor.start(tor.config("./reedwire-tor", "/tmp/rw-tor"))
/// // -> Ok(tor)
/// ```
pub fn start(config: Config) -> Result(Tor, TorError) {
  use started <- result.try(start_actor(config))
  let tor = started.data

  // The actor answers once the sidecar reports ready, or once the restart
  // budget is spent. The extra second covers the actor's own scheduling.
  let wait = config.ready_timeout_ms * { config.max_restarts + 1 } + 1000

  // The reply decides whether the caller gets a handle or a failure.
  case ask(tor.subject, AwaitReady, wait) {
    Ok(Nil) -> Ok(tor)
    Error(error) -> {
      let _ = ask(tor.subject, Stop, 1000)
      Error(error)
    }
  }
}

/// A child specification that starts the actor under a supervisor. A
/// supervisor restart replaces the actor, so the `Tor` handle in the new
/// child's data must be fetched again; prefer `start` unless the actor
/// itself needs supervising.
///
/// ## Examples
///
/// ```gleam
/// tor.supervised(tor.config("./reedwire-tor", "/tmp/rw-tor"))
/// ```
pub fn supervised(config: Config) -> supervision.ChildSpecification(Tor) {
  supervision.worker(fn() { start_actor(config) |> result.map_error(to_start) })
  |> supervision.map_data(fn(tor) { tor })
}

/// The actor start error a supervisor expects.
fn to_start(error: TorError) -> actor.StartError {
  actor.InitFailed(string.inspect(error))
}

/// Starts the actor without waiting for the sidecar.
fn start_actor(config: Config) -> Result(actor.Started(Tor), TorError) {
  actor.new_with_initialiser(5000, fn(self) { init(config, self) })
  |> actor.on_message(handle_message)
  |> actor.start
  |> result.map(fn(started) {
    actor.Started(pid: started.pid, data: Tor(subject: started.data, config:))
  })
  |> result.map_error(fn(_) { StartFailed(SpawnFailed) })
}

/// Spawns the first sidecar and builds the actor's state. The sidecar is
/// `Starting` until its `Ready` frame arrives.
fn init(
  config: Config,
  self: Subject(Message),
) -> Result(actor.Initialised(State, Message, Subject(Message)), String) {
  use port <- result.try(
    ffi_port.open_sidecar(config.binary_path, config.state_dir)
    |> result.replace_error("cannot spawn the sidecar"),
  )
  let _ = process.send_after(self, config.ready_timeout_ms, ReadyTimeout(port))

  // `select_other` is the only way to receive port messages, and it takes
  // every message the other handlers do not. The classifier hands it to
  // the shim at once, so a stray message becomes `Error(Nil)`, not a frame.
  let selector =
    process.new_selector()
    |> process.select(self)
    |> process.select_other(fn(raw) { FromPort(ffi_port.classify_message(raw)) })
  let state =
    State(
      config:,
      self:,
      sidecar: Starting(port),
      next_id: 1,
      pending: dict.new(),
      subscribers: [],
      waiters: [],
      restarts: 0,
    )

  actor.initialised(state)
  |> actor.selecting(selector)
  |> actor.returning(self)
  |> Ok
}

/// Asks the actor and waits for a reply, withdrawing the reply address on
/// timeout so a late reply is dropped by the actor rather than left in the
/// caller's mailbox.
fn ask(
  subject: Subject(Message),
  make: fn(Subject(Result(a, TorError))) -> Message,
  timeout: Int,
) -> Result(a, TorError) {
  let reply_to = process.new_subject()
  process.send(subject, make(reply_to))

  // A reply is the answer; silence is a timeout, not an error from the sidecar.
  case process.receive(reply_to, timeout) {
    Ok(reply) -> reply
    Error(Nil) -> Error(Timeout)
  }
}

/// Bootstraps the Tor client: downloads the consensus and builds the first
/// circuits. Takes seconds on a warm state directory and tens of seconds
/// on a cold one.
///
/// ## Examples
///
/// ```gleam
/// tor.bootstrap(tor, 120_000)
/// // -> Ok(Nil)
/// ```
pub fn bootstrap(tor: Tor, timeout: Int) -> Result(Nil, TorError) {
  let reply_to = process.new_subject()
  process.send(tor.subject, Bootstrap(reply_to))

  // A timeout withdraws the reply address so a late reply is dropped.
  case process.receive(reply_to, timeout) {
    Ok(reply) -> reply
    Error(Nil) -> {
      process.send(tor.subject, AbandonBootstrap(reply_to))
      Error(Timeout)
    }
  }
}

/// Launches an onion service and returns its address once the sidecar has
/// created the service, which is before Tor can reach it. Reachability is
/// best learned by connecting: the `ServiceStateChanged` events are Arti's
/// own assessment and were observed to stay at `ServiceDegradedUnreachable`
/// while the service was already reachable (ADR-001). Every stream the
/// service accepts, on any virtual port, is
/// forwarded to `127.0.0.1:local_port`. Arti persists the key in the state
/// directory, so the same nickname is expected to yield the same address
/// across restarts (not yet exercised by the spike). Requires a bootstrapped client.
///
/// ## Examples
///
/// ```gleam
/// tor.host_onion(tor, "mailbox", 8080, 60_000)
/// // -> Ok(OnionHost("mailbox", address))
/// ```
pub fn host_onion(
  tor: Tor,
  nickname: String,
  local_port: Int,
  timeout: Int,
) -> Result(OnionHost, TorError) {
  let size = string.byte_size(nickname)

  // A nickname outside the bounds never reaches the sidecar.
  case size >= 1 && size <= max_nickname_bytes {
    False -> Error(BadNickname)
    True -> {
      let reply_to = process.new_subject()
      process.send(tor.subject, HostOnion(nickname, local_port, reply_to))

      // A timeout withdraws the reply address so a late reply is dropped.
      case process.receive(reply_to, timeout) {
        Ok(reply) -> reply
        Error(Nil) -> {
          process.send(tor.subject, AbandonHost(reply_to))
          Error(Timeout)
        }
      }
    }
  }
}

/// Opens an outbound stream to an onion service. Streams with the same
/// `isolation_group` may share Tor circuits; streams with different groups
/// never do. The target is an `OnionAddress`, so a clearnet destination
/// cannot be expressed. The returned stream is passive: read with
/// `stream.recv` when ready, which is the backpressure.
///
/// The stream belongs to the calling process. `timeout` bounds the whole
/// handshake, descriptor fetch and rendezvous included, so allow minutes
/// for a first connect to an onion service.
///
/// ## Examples
///
/// ```gleam
/// tor.connect(tor, onion, port, "queue-7", 120_000)
/// // -> Ok(stream)
/// ```
pub fn connect(
  tor: Tor,
  onion: OnionAddress,
  port: OnionPort,
  isolation_group: String,
  timeout: Int,
) -> Result(Stream, TorError) {
  let path = tor.config.state_dir <> "/connect.sock"

  stream.open(path, onion, port, isolation_group, timeout)
  |> result.map_error(OpenFailed)
}

/// Subscribes a subject to sidecar and service events. Events are sent to
/// the subject as they happen; nothing is replayed.
///
/// ## Examples
///
/// ```gleam
/// tor.subscribe(tor, process.new_subject())
/// // -> Nil
/// ```
pub fn subscribe(tor: Tor, subscriber: Subject(Event)) -> Nil {
  process.send(tor.subject, Subscribe(subscriber))
}

/// The sidecar's operating system pid, for tests and diagnostics. It
/// changes when the sidecar restarts.
///
/// ## Examples
///
/// ```gleam
/// tor.sidecar_pid(tor)
/// // -> Ok(12345)
/// ```
pub fn sidecar_pid(tor: Tor) -> Result(Int, TorError) {
  ask(tor.subject, GetPid, 5000)
}

/// Stops the sidecar and the actor. The sidecar is told to shut down and
/// its port is closed, so it exits even if it ignores the request. Returns
/// once the actor has done both; the process itself may take a moment to
/// disappear.
///
/// ## Examples
///
/// ```gleam
/// tor.shutdown(tor)
/// // -> Nil
/// ```
pub fn shutdown(tor: Tor) -> Nil {
  let _ = ask(tor.subject, Stop, 5000)
  Nil
}

// ---------------------------------------------------------------- the actor

/// Routes one mailbox message. Handlers return the next state; none of
/// them blocks except the short restart backoff.
fn handle_message(
  state: State,
  message: Message,
) -> actor.Next(State, Message) {
  // One arm per message; each handler returns the next state.
  case message {
    AwaitReady(reply_to) -> await_ready(state, reply_to)

    Bootstrap(reply_to) ->
      request(state, codec.encode_bootstrap, PendingBootstrap(reply_to), fn() {
        process.send(reply_to, Error(SidecarUnavailable))
      })

    HostOnion(nickname, local_port, reply_to) ->
      request(
        state,
        codec.encode_host_onion(_, nickname, local_port),
        PendingHost(nickname, reply_to),
        fn() { process.send(reply_to, Error(SidecarUnavailable)) },
      )

    AbandonBootstrap(reply_to) ->
      forget(state, fn(pending) { pending == PendingBootstrap(reply_to) })

    AbandonHost(reply_to) ->
      forget(state, fn(pending) {
        case pending {
          PendingHost(reply_to: other, ..) -> other == reply_to
          PendingBootstrap(..) -> False
        }
      })

    Subscribe(subscriber) ->
      actor.continue(
        State(..state, subscribers: [subscriber, ..state.subscribers]),
      )

    GetPid(reply_to) -> {
      process.send(reply_to, sidecar_pid_of(state.sidecar))
      actor.continue(state)
    }

    FromPort(Ok(PortData(port, data))) -> on_data(state, port, data)

    FromPort(Ok(PortExit(port, status))) -> on_exit(state, port, status)

    FromPort(Error(Nil)) -> actor.continue(state)

    ReadyTimeout(port) -> on_ready_timeout(state, port)

    Stop(reply_to) -> stop(state, reply_to)
  }
}

/// Answers an `AwaitReady` now if the sidecar is listening, parks it if the
/// sidecar is starting, and refuses it if the actor has given up.
fn await_ready(
  state: State,
  reply_to: Subject(Result(Nil, TorError)),
) -> actor.Next(State, Message) {
  // Whether the sidecar is listening decides if the waiter is answered,
  // parked or refused.
  case state.sidecar {
    Serving(..) -> {
      process.send(reply_to, Ok(Nil))
      actor.continue(state)
    }

    Starting(..) ->
      actor.continue(State(..state, waiters: [reply_to, ..state.waiters]))

    GivenUp -> {
      process.send(reply_to, Error(StartFailed(NeverReady)))
      actor.continue(state)
    }
  }
}

/// Sends a request frame and records who is waiting for the reply. The id
/// is allocated here, so replies are matched to requests by the actor alone.
/// `refuse` runs when the sidecar cannot take requests.
fn request(
  state: State,
  encode: fn(Int) -> BitArray,
  pending: Pending,
  refuse: fn() -> Nil,
) -> actor.Next(State, Message) {
  let id = state.next_id

  // Only a serving sidecar can take a frame.
  let sent = case state.sidecar {
    Serving(port) -> ffi_port.send_frame(port, encode(id))
    Starting(..) | GivenUp -> Error(Nil)
  }

  // A failed send means the port is already closed; its exit message is
  // behind this one in the mailbox and will fail everything pending.
  case sent {
    Ok(Nil) ->
      actor.continue(
        State(
          ..state,
          next_id: { id + 1 } % 4_294_967_296,
          pending: dict.insert(state.pending, id, pending),
        ),
      )

    Error(Nil) -> {
      refuse()
      actor.continue(state)
    }
  }
}

/// Drops the pending requests the predicate selects: a caller that timed
/// out no longer wants its reply.
fn forget(
  state: State,
  abandoned: fn(Pending) -> Bool,
) -> actor.Next(State, Message) {
  let pending = dict.filter(state.pending, fn(_, p) { !abandoned(p) })
  actor.continue(State(..state, pending:))
}

/// The pid of the running sidecar.
fn sidecar_pid_of(sidecar: Sidecar) -> Result(Int, TorError) {
  case sidecar {
    Serving(port) | Starting(port) ->
      ffi_port.os_pid(port) |> result.replace_error(SidecarUnavailable)
    GivenUp -> Error(SidecarUnavailable)
  }
}

/// Handles a frame from the sidecar. Frames from a port we no longer own
/// are ignored: after a restart, the old port's last messages can still be
/// in the mailbox.
fn on_data(
  state: State,
  port: Port,
  data: BitArray,
) -> actor.Next(State, Message) {
  case current_port(state.sidecar) == Some(port) {
    False -> actor.continue(state)

    True ->
      case codec.decode_event(data) {
        Ok(event) -> on_event(state, port, event)

        // Undecodable bytes mean the two ends disagree about the protocol.
        // Nothing the sidecar says can be trusted after that, so close it
        // and take the restart path.
        Error(_) -> {
          let _ = ffi_port.close_port(port)
          sidecar_failed(state, -1)
        }
      }
  }
}

/// Applies one decoded event.
fn on_event(
  state: State,
  port: Port,
  event: codec.Event,
) -> actor.Next(State, Message) {
  // Each event either answers a pending request or changes sidecar state.
  case event {
    codec.Ready(_) -> on_ready(state, port)

    codec.Bootstrapped(id) -> {
      let state = State(..state, restarts: 0)

      // Only a pending bootstrap with this id is answered; any other id is a
      // late reply.
      case dict.get(state.pending, id) {
        Ok(PendingBootstrap(reply_to)) -> {
          process.send(reply_to, Ok(Nil))
          actor.continue(
            State(..state, pending: dict.delete(state.pending, id)),
          )
        }
        _ -> actor.continue(state)
      }
    }

    codec.OnionReady(id, nickname, hostname) ->
      case dict.get(state.pending, id) {
        Ok(PendingHost(reply_to: reply_to, ..)) -> {
          let reply =
            address.parse_onion(hostname)
            |> result.map(OnionHost(nickname, _))
            |> result.replace_error(BadHostname)
          process.send(reply_to, reply)
          actor.continue(
            State(..state, pending: dict.delete(state.pending, id)),
          )
        }
        _ -> actor.continue(state)
      }

    codec.Failed(id, code, text) -> {
      let failure = RequestFailed(code, text)

      // The reply type depends on what was asked, so each arm builds its own
      // `Error`.
      case dict.get(state.pending, id) {
        Ok(PendingBootstrap(reply_to)) -> process.send(reply_to, Error(failure))
        Ok(PendingHost(reply_to: reply_to, ..)) ->
          process.send(reply_to, Error(failure))
        Error(Nil) -> Nil
      }

      actor.continue(State(..state, pending: dict.delete(state.pending, id)))
    }

    codec.ServiceStatus(nickname, service_state) -> {
      notify(state, ServiceStateChanged(nickname, service_state))
      actor.continue(state)
    }
  }
}

/// The sidecar is listening: requests may flow, and anyone parked in
/// `AwaitReady` is released. A ready after a restart is announced.
fn on_ready(state: State, port: Port) -> actor.Next(State, Message) {
  // Only a starting sidecar becomes ready; a repeat `Ready` changes nothing.
  case state.sidecar {
    Starting(..) -> {
      list.each(state.waiters, process.send(_, Ok(Nil)))
      let state = State(..state, sidecar: Serving(port), waiters: [])

      // Restarts only go up while the actor is running, so a positive count
      // here means this ready follows a restart, not the first start.
      case state.restarts > 0 {
        True -> notify(state, SidecarRestarted)
        False -> Nil
      }

      actor.continue(state)
    }

    Serving(..) | GivenUp -> actor.continue(state)
  }
}

/// The sidecar exited. A stale port's exit is ignored.
fn on_exit(
  state: State,
  port: Port,
  status: Int,
) -> actor.Next(State, Message) {
  case current_port(state.sidecar) == Some(port) {
    True -> sidecar_failed(state, status)
    False -> actor.continue(state)
  }
}

/// The sidecar never reported ready: close it and take the restart path.
fn on_ready_timeout(state: State, port: Port) -> actor.Next(State, Message) {
  // Only a sidecar still starting on this port is timed out; a ready one is
  // left alone.
  case state.sidecar == Starting(port) {
    True -> {
      let _ = ffi_port.close_port(port)
      sidecar_failed(state, -2)
    }

    False -> actor.continue(state)
  }
}

/// The port of a sidecar that has one.
fn current_port(sidecar: Sidecar) -> Option(Port) {
  case sidecar {
    Starting(port) | Serving(port) -> Some(port)
    GivenUp -> None
  }
}

/// The sidecar is gone. Every pending request fails with the exit status,
/// subscribers are told, and then the actor either spawns a replacement or,
/// with the budget spent, gives up. The restart count rises before the
/// spawn, so a binary that fails to start at all still ends in `GivenUp`.
fn sidecar_failed(state: State, status: Int) -> actor.Next(State, Message) {
  dict.each(state.pending, fn(_, pending) { fail(pending, status) })
  notify(state, SidecarDied(status))

  let restarts = state.restarts + 1
  let state = State(..state, pending: dict.new(), restarts:)

  // A spent budget gives up; otherwise a replacement is spawned.
  case restarts > state.config.max_restarts {
    True -> give_up(state)
    False -> respawn(state)
  }
}

/// Fails one pending request because the sidecar exited.
fn fail(pending: Pending, status: Int) -> Nil {
  case pending {
    PendingBootstrap(reply_to) ->
      process.send(reply_to, Error(SidecarExited(status)))
    PendingHost(reply_to: reply_to, ..) ->
      process.send(reply_to, Error(SidecarExited(status)))
  }
}

/// Spawns a replacement after a short backoff that grows with the number
/// of consecutive failures, so a crash loop does not spin.
fn respawn(state: State) -> actor.Next(State, Message) {
  process.sleep(200 * state.restarts)

  // Whether the spawn succeeded decides between waiting for ready and
  // counting another failure.
  case ffi_port.open_sidecar(state.config.binary_path, state.config.state_dir) {
    Ok(port) -> {
      let timeout = state.config.ready_timeout_ms
      let _ = process.send_after(state.self, timeout, ReadyTimeout(port))
      actor.continue(State(..state, sidecar: Starting(port)))
    }

    // Spawning itself failed. That counts as another failed attempt.
    Error(Nil) -> sidecar_failed(state, -1)
  }
}

/// The budget is spent: refuse everything from now on.
fn give_up(state: State) -> actor.Next(State, Message) {
  list.each(state.waiters, process.send(_, Error(StartFailed(NeverReady))))
  notify(state, SidecarGaveUp)

  actor.continue(State(..state, sidecar: GivenUp, waiters: []))
}

/// Tells every subscriber about an event.
fn notify(state: State, event: Event) -> Nil {
  list.each(state.subscribers, process.send(_, event))
}

/// Asks the sidecar to exit and closes its port, which closes its stdin and
/// ends it even if the request is ignored, then stops the actor. Pending
/// requests are failed, not abandoned.
fn stop(
  state: State,
  reply_to: Subject(Result(Nil, TorError)),
) -> actor.Next(State, Message) {
  // A sidecar with a port is told to exit; a given-up one has nothing to close.
  case current_port(state.sidecar) {
    Some(port) -> {
      let _ = ffi_port.send_frame(port, codec.encode_shutdown())
      let _ = ffi_port.close_port(port)
      Nil
    }
    None -> Nil
  }

  dict.each(state.pending, fn(_, pending) { fail(pending, -3) })
  process.send(reply_to, Ok(Nil))

  actor.stop()
}
