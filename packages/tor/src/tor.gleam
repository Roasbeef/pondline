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
//// One process, a `weft/state_machine` started by `start`, owns the
//// sidecar's Erlang port. It sends control frames (`tor/internal/codec`),
//// turns the replies into typed results for the callers waiting on them,
//// and watches for the process to exit. Outbound streams do not go through
//// the machine at all: `connect` opens a unix socket to the sidecar
//// directly (`tor/stream`), so stream traffic never queues behind control
//// traffic and a slow stream cannot slow the machine.
////
//// ## Flow
////
//// `start` builds the machine with `start_machine`, whose initialiser spawns
//// the first sidecar through `ffi_port.open_sidecar` and selects the port's
//// messages. `handle` is the one event handler: it dispatches every
//// `Phase` and `Message` pair, and the helpers it calls are `submit` for a
//// request frame, `frame` and `on_event` for what the sidecar says,
//// `sidecar_failed` for its death and `stop` for an orderly end. `entered`
//// arms the one state timeout. The public functions after the types are
//// thin callers that send a message and wait on a reply subject.
////
//// ## The phases
////
//// The sidecar's life is the machine's state, so a request is judged by
//// the phase it arrives in and not by a flag in a record:
////
//// <!-- transitions: tor.Phase -->
//// | Phase | Meaning and exits |
//// |---|---|
//// | `Starting` | Spawned, not yet listening. `Ready` moves to `Serving`; an exit, an undecodable frame or the ready timeout moves to `Restarting`, or to `GivenUp` when the budget is spent. |
//// | `Serving` | Listening; requests go out. An exit or an undecodable frame moves to `Restarting`, or to `GivenUp`. |
//// | `Restarting` | Waiting out the backoff. The `respawn` named timeout spawns a replacement and moves to `Starting`; a spawn that fails counts as another failure. |
//// | `GivenUp` | The restart budget is spent. Terminal; every request is refused. |
////
//// `AwaitReady` is the one request that waits for a phase to end: it is
//// postponed in `Starting` and `Restarting`, and the machine replays it on
//// the next phase change, so no list of waiters is kept. A `Bootstrap` or
//// `HostOnion` in any phase but `Serving` is answered at once with
//// `SidecarUnavailable`, which is the API's promise and not a missing case.
////
//// ## The sidecar's lifetime
////
//// The port is owned by the machine, so if the machine dies the VM closes
//// the port, the sidecar's stdin reaches end of file, and the sidecar
//// exits. If the sidecar dies first, the machine is told through
//// `exit_status` and restarts it itself rather than leaving that to a
//// supervisor. A supervisor restart would hand callers a new `Tor` value
//// and drop the subscribers and the pending requests the machine holds,
//// while a sidecar restart inside the machine keeps all of them.
////
//// The restart policy is bounded by `max_restarts`: that many consecutive
//// restarts that do not end in a successful bootstrap, and the machine
//// stops restarting, tells subscribers with `SidecarGaveUp`, and answers
//// every later request with `SidecarUnavailable`. A sidecar that works and
//// then crashes once gets a full budget again, because a successful
//// bootstrap resets the count. After a restart the new sidecar is not
//// bootstrapped: the owner sees `SidecarRestarted` and must call
//// `bootstrap` and `host_onion` again. Onion services are expected to keep
//// their address across restarts because Arti persists the key under the
//// state directory.
////
//// ## Deadlines
////
//// Two deadlines belong to the machine. The ready timeout is a state
//// timeout on `Starting`, so any move out of that phase cancels it and a
//// late fire cannot be mistaken for a current one. The restart backoff is
//// the named timeout `respawn`, armed in `sidecar_failed` and nowhere else.
//// `start` waits for the worst case of both, a sidecar silent every time: a
//// ready timeout per start plus `total_backoff_ms`, the backoffs before each
//// respawn, so it ends in `NeverReady` and not in its own `Timeout`.
//// A request's reply deadline belongs to its caller, which waits on its own
//// reply subject and sends `Abandon*` when it gives up.
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
import gleam/otp/supervision
import gleam/result
import gleam/string
import tor/address.{type OnionAddress, type Port as OnionPort}
import tor/internal/codec
import tor/internal/ffi_port.{PortData, PortExit}
import tor/stream.{type OpenError, type Stream}
import weft/state_machine as sm

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
    /// allowed before the machine gives up.
    max_restarts: Int,
    /// How long, in milliseconds, a freshly started sidecar has to report
    /// that it is listening.
    ready_timeout_ms: Int,
  )
}

/// The machine's mailbox protocol. Public only because the opaque `Tor`
/// carries a subject of it; callers use the functions in this module.
pub type Message {
  /// Wait until the sidecar is listening. Postponed while it is not.
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

  /// A message from the current port, or `Error(Nil)` for anything else
  /// that reached the mailbox.
  FromPort(message: Result(ffi_port.PortMessage, Nil))

  /// The sidecar did not report ready in time. The state timeout of
  /// `Starting` sends it, so it only arrives while that phase lasts.
  ReadyTimeout

  /// The restart backoff elapsed. The named timeout `respawn` sends it.
  Respawn

  /// Stop the sidecar and the machine.
  Stop(reply_to: Subject(Result(Nil, TorError)))
}

/// A request that is waiting for its reply frame.
type Pending {
  PendingBootstrap(reply_to: Subject(Result(Nil, TorError)))
  PendingHost(nickname: String, reply_to: Subject(Result(OnionHost, TorError)))
}

/// Where the sidecar is in its life. A phase's payload never changes while
/// the machine is in it: the ready timeout belongs to `Starting(port)` and
/// is cancelled by any move to a different phase.
type Phase {
  /// Spawned, not yet listening. Requests are refused until it is.
  Starting(port: Port)

  /// Listening; requests go out.
  Serving(port: Port)

  /// Dead, and waiting out the backoff before a replacement is spawned.
  Restarting

  /// The restart budget is spent.
  GivenUp
}

/// What the machine carries across phases. None of it may cancel the ready
/// timeout or replay a postponed request, which is why it is not part of
/// `Phase`.
type Data {
  Data(
    config: Config,
    self: Subject(Message),
    next_id: Int,
    pending: Dict(Int, Pending),
    subscribers: List(Subject(Event)),
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
  /// ready; in both cases the machine closed it.
  SidecarDied(status: Int)

  /// A new sidecar is listening. It is not bootstrapped.
  SidecarRestarted

  /// The restart budget is spent; the machine serves no more requests.
  SidecarGaveUp
}

/// A handle to a running sidecar and the machine that owns it.
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

/// Starts the sidecar and the machine that owns it, returning once the
/// sidecar is listening for outbound connections. Not bootstrapped yet:
/// call `bootstrap` next.
///
/// The machine is linked to the caller, so the caller's death takes the
/// machine, the port, and the sidecar with it.
///
/// ## Examples
///
/// ```gleam
/// tor.start(tor.config("./reedwire-tor", "/tmp/rw-tor"))
/// // -> Ok(tor)
/// ```
pub fn start(config: Config) -> Result(Tor, TorError) {
  use started <- result.try(start_machine(config))
  let tor = started.data

  // The machine answers once the sidecar reports ready, or once the restart
  // budget is spent. The worst case is a sidecar that is silent every time:
  // one ready timeout per start, plus the backoff before each respawn. The
  // extra second covers the machine's own scheduling.
  let wait =
    config.ready_timeout_ms
    * { config.max_restarts + 1 }
    + total_backoff_ms(config.max_restarts)
    + 1000

  // The reply decides whether the caller gets a handle or a failure.
  case ask(tor.subject, AwaitReady, wait) {
    Ok(Nil) -> Ok(tor)
    Error(error) -> {
      let _ = ask(tor.subject, Stop, 1000)
      Error(error)
    }
  }
}

/// The backoff before the respawn that follows the `restarts`-th
/// consecutive failure, in milliseconds. It grows linearly, so a crash loop
/// does not spin. `sidecar_failed` arms it and `start` bounds its wait by it.
fn backoff_ms(restarts: Int) -> Int {
  200 * restarts
}

/// The backoffs of every respawn a budget of `restarts` allows, summed. The
/// failure that spends the budget gives up and waits for nothing.
fn total_backoff_ms(restarts: Int) -> Int {
  case restarts < 1 {
    True -> 0
    False -> backoff_ms(restarts) + total_backoff_ms(restarts - 1)
  }
}

/// A child specification that starts the machine under a supervisor. A
/// supervisor restart replaces the machine, so the `Tor` handle in the new
/// child's data must be fetched again; prefer `start` unless the machine
/// itself needs supervising.
///
/// ## Examples
///
/// ```gleam
/// tor.supervised(tor.config("./reedwire-tor", "/tmp/rw-tor"))
/// ```
pub fn supervised(config: Config) -> supervision.ChildSpecification(Tor) {
  sm.supervised(machine(config))
}

/// Starts the machine without waiting for the sidecar.
fn start_machine(config: Config) -> Result(sm.Started(Tor), TorError) {
  machine(config)
  |> sm.start
  |> result.map_error(fn(_) { StartFailed(SpawnFailed) })
}

/// The machine's description, shared by `start` and `supervised`. The
/// initialiser runs in the new process, so the machine, not the caller, is
/// the port's owner.
fn machine(config: Config) -> sm.Builder(Phase, Data, Message, Tor) {
  sm.new_with_initialiser(5000, fn(self) { init(config, self) })
  |> sm.on_event(handle)
  |> sm.on_enter(entered)
}

/// Spawns the first sidecar and builds the machine's state. The sidecar is
/// `Starting` until its `Ready` frame arrives.
fn init(
  config: Config,
  self: Subject(Message),
) -> Result(sm.Initialised(Phase, Data, Message, Tor), String) {
  use port <- result.try(
    ffi_port.open_sidecar(config.binary_path, config.state_dir)
    |> result.replace_error("cannot spawn the sidecar"),
  )
  let data =
    Data(
      config:,
      self:,
      next_id: 1,
      pending: dict.new(),
      subscribers: [],
      restarts: 0,
    )

  sm.initialised(Starting(port), data)
  |> sm.selecting(selector_for(self, port))
  |> sm.returning(Tor(subject: self, config:))
  |> Ok
}

/// The mailbox selection for one port: the machine's own subject and
/// nothing from any other port. A replacement sidecar gets a new selector,
/// so the last messages of a dead port are never delivered as the new
/// port's, and no frame needs to be checked for which port sent it.
fn selector_for(
  self: Subject(Message),
  port: Port,
) -> process.Selector(Message) {
  process.new_selector()
  |> process.select(self)
  |> process.select_record(port, 1, fn(raw) {
    FromPort(ffi_port.classify_message(raw))
  })
}

/// Asks the machine and waits for a reply, withdrawing the reply address on
/// timeout so a late reply is dropped by the machine rather than left in the
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

/// Stops the sidecar and the machine. The sidecar is told to shut down and
/// its port is closed, so it exits even if it ignores the request. Returns
/// once the machine has done both; the process itself may take a moment to
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

// -------------------------------------------------------------- the machine

/// Dispatches one event against the phase it arrives in. Every pair of
/// phase and message is written, so a new phase or message is a compile
/// error here until someone decides what it does. A message that is the
/// same in every phase says so with `_` for the phase.
fn handle(
  phase: Phase,
  data: Data,
  message: Message,
) -> sm.Next(Phase, Data, Message) {
  case phase, message {
    // A caller waiting for the sidecar to listen waits inside the machine:
    // the next phase change replays it, so no list of waiters is kept.
    Starting(..), AwaitReady(..) | Restarting, AwaitReady(..) ->
      sm.keep(data) |> sm.postpone

    Serving(..), AwaitReady(reply_to) -> {
      process.send(reply_to, Ok(Nil))
      sm.keep(data)
    }

    GivenUp, AwaitReady(reply_to) -> {
      process.send(reply_to, Error(StartFailed(NeverReady)))
      sm.keep(data)
    }

    // Only a listening sidecar takes a request. In any other phase the
    // caller is told so at once, which the API promises.
    Serving(port), Bootstrap(reply_to) ->
      submit(
        port,
        data,
        codec.encode_bootstrap,
        PendingBootstrap(reply_to),
        fn() { process.send(reply_to, Error(SidecarUnavailable)) },
      )

    Starting(..), Bootstrap(reply_to)
    | Restarting, Bootstrap(reply_to)
    | GivenUp, Bootstrap(reply_to)
    -> {
      process.send(reply_to, Error(SidecarUnavailable))
      sm.keep(data)
    }

    Serving(port), HostOnion(nickname, local_port, reply_to) ->
      submit(
        port,
        data,
        codec.encode_host_onion(_, nickname, local_port),
        PendingHost(nickname, reply_to),
        fn() { process.send(reply_to, Error(SidecarUnavailable)) },
      )

    Starting(..), HostOnion(_, _, reply_to)
    | Restarting, HostOnion(_, _, reply_to)
    | GivenUp, HostOnion(_, _, reply_to)
    -> {
      process.send(reply_to, Error(SidecarUnavailable))
      sm.keep(data)
    }

    // A caller that timed out no longer wants its reply, in any phase.
    Starting(..), AbandonBootstrap(reply_to)
    | Serving(..), AbandonBootstrap(reply_to)
    | Restarting, AbandonBootstrap(reply_to)
    | GivenUp, AbandonBootstrap(reply_to)
    -> forget(data, fn(pending) { pending == PendingBootstrap(reply_to) })

    Starting(..), AbandonHost(reply_to)
    | Serving(..), AbandonHost(reply_to)
    | Restarting, AbandonHost(reply_to)
    | GivenUp, AbandonHost(reply_to)
    ->
      forget(data, fn(pending) {
        case pending {
          PendingHost(reply_to: other, ..) -> other == reply_to
          PendingBootstrap(..) -> False
        }
      })

    Starting(..), Subscribe(subscriber)
    | Serving(..), Subscribe(subscriber)
    | Restarting, Subscribe(subscriber)
    | GivenUp, Subscribe(subscriber)
    -> sm.keep(Data(..data, subscribers: [subscriber, ..data.subscribers]))

    Starting(port), GetPid(reply_to) | Serving(port), GetPid(reply_to) -> {
      process.send(
        reply_to,
        ffi_port.os_pid(port) |> result.replace_error(SidecarUnavailable),
      )
      sm.keep(data)
    }

    Restarting, GetPid(reply_to) | GivenUp, GetPid(reply_to) -> {
      process.send(reply_to, Error(SidecarUnavailable))
      sm.keep(data)
    }

    // The selector only delivers the current port's messages, so a frame in
    // `Starting` or `Serving` is from the sidecar this phase owns.
    Starting(port), FromPort(Ok(PortData(_, bytes))) ->
      frame(data, bytes, port, Booting)

    Serving(port), FromPort(Ok(PortData(_, bytes))) ->
      frame(data, bytes, port, Listening)

    Starting(..), FromPort(Ok(PortExit(_, status)))
    | Serving(..), FromPort(Ok(PortExit(_, status)))
    -> sidecar_failed(data, status)

    // A dead or abandoned port's last messages can still be in the mailbox
    // after the phase has moved on; they are not the new sidecar's.
    Restarting, FromPort(..) | GivenUp, FromPort(..) -> sm.keep(data)

    // Something other than a port frame or exit reached the mailbox.
    Starting(..), FromPort(Error(Nil)) | Serving(..), FromPort(Error(Nil)) ->
      sm.keep(data)

    // The state timeout of `Starting` fired: close the silent sidecar and
    // take the restart path. The timeout is cancelled by every move out of
    // `Starting`, so the other phases never see this; they keep the state.
    Starting(port), ReadyTimeout -> {
      let _ = ffi_port.close_port(port)
      sidecar_failed(data, -2)
    }

    Serving(..), ReadyTimeout
    | Restarting, ReadyTimeout
    | GivenUp, ReadyTimeout
    -> sm.keep(data)

    // The backoff elapsed: spawn the replacement. The new port gets its own
    // selector, and entering `Starting` arms the ready timeout.
    Restarting, Respawn -> respawn(data)

    // Armed only by `sidecar_failed` and cancelled by nothing, but it fires
    // in `Restarting` alone: a respawn that fails re-arms it from there.
    Starting(..), Respawn | Serving(..), Respawn | GivenUp, Respawn ->
      sm.keep(data)

    Starting(..), Stop(reply_to)
    | Serving(..), Stop(reply_to)
    | Restarting, Stop(reply_to)
    | GivenUp, Stop(reply_to)
    -> stop(phase, data, reply_to)
  }
}

/// Arms the one state timeout. Entering `Starting` from anywhere, including
/// the initial entry, starts the ready deadline, so every path into the
/// phase gets it. Leaving the phase cancels it.
fn entered(
  _from: Phase,
  to: Phase,
  data: Data,
) -> sm.Enter(Phase, Data, Message) {
  case to {
    Starting(..) ->
      sm.keep(data)
      |> sm.with_state_timeout(
        after: data.config.ready_timeout_ms,
        sending: ReadyTimeout,
      )

    Serving(..) | Restarting | GivenUp -> sm.keep(data)
  }
}

/// Sends a request frame and records who is waiting for the reply. The id
/// is allocated here, so replies are matched to requests by the machine
/// alone. `refuse` runs when the port will not take the frame.
fn submit(
  port: Port,
  data: Data,
  encode: fn(Int) -> BitArray,
  pending: Pending,
  refuse: fn() -> Nil,
) -> sm.Next(Phase, Data, Message) {
  let id = data.next_id

  // A failed send means the port is already closed; its exit message is
  // behind this one in the mailbox and will fail everything pending.
  case ffi_port.send_frame(port, encode(id)) {
    Ok(Nil) ->
      sm.keep(
        Data(
          ..data,
          next_id: { id + 1 } % 4_294_967_296,
          pending: dict.insert(data.pending, id, pending),
        ),
      )

    Error(Nil) -> {
      refuse()
      sm.keep(data)
    }
  }
}

/// Drops the pending requests the predicate selects: a caller that timed
/// out no longer wants its reply.
fn forget(
  data: Data,
  abandoned: fn(Pending) -> Bool,
) -> sm.Next(Phase, Data, Message) {
  let pending = dict.filter(data.pending, fn(_, p) { !abandoned(p) })
  sm.keep(Data(..data, pending:))
}

/// The two phases that own a port, as far as a frame cares: the caller
/// holds the port and the phase's payload is not needed again.
type Owned {
  /// `Starting`: a `Ready` frame ends it.
  Booting

  /// `Serving`: a `Ready` frame is a repeat.
  Listening
}

/// Handles a frame from the current sidecar, which is the port of the phase
/// it arrived in (`Restarting` and `GivenUp` have no port and never get here).
fn frame(
  data: Data,
  bytes: BitArray,
  port: Port,
  owned: Owned,
) -> sm.Next(Phase, Data, Message) {
  case codec.decode_event(bytes) {
    Ok(event) -> on_event(data, event, port, owned)

    // Undecodable bytes mean the two ends disagree about the protocol.
    // Nothing the sidecar says can be trusted after that, so close it and
    // take the restart path.
    Error(_) -> {
      let _ = ffi_port.close_port(port)
      sidecar_failed(data, -1)
    }
  }
}

/// Applies one decoded event.
fn on_event(
  data: Data,
  event: codec.Event,
  port: Port,
  owned: Owned,
) -> sm.Next(Phase, Data, Message) {
  // Each event either answers a pending request or changes sidecar state.
  case event {
    codec.Ready(_) -> on_ready(data, port, owned)

    codec.Bootstrapped(id) -> {
      let data = Data(..data, restarts: 0)

      // Only a pending bootstrap with this id is answered; any other id is a
      // late reply.
      case dict.get(data.pending, id) {
        Ok(PendingBootstrap(reply_to)) -> {
          process.send(reply_to, Ok(Nil))
          sm.keep(Data(..data, pending: dict.delete(data.pending, id)))
        }

        Ok(PendingHost(..)) | Error(Nil) -> sm.keep(data)
      }
    }

    codec.OnionReady(id, nickname, hostname) ->
      case dict.get(data.pending, id) {
        Ok(PendingHost(reply_to: reply_to, ..)) -> {
          let reply =
            address.parse_onion(hostname)
            |> result.map(OnionHost(nickname, _))
            |> result.replace_error(BadHostname)
          process.send(reply_to, reply)
          sm.keep(Data(..data, pending: dict.delete(data.pending, id)))
        }

        Ok(PendingBootstrap(..)) | Error(Nil) -> sm.keep(data)
      }

    codec.Failed(id, code, text) -> {
      let failure = RequestFailed(code, text)

      // The reply type depends on what was asked, so each arm builds its own
      // `Error`.
      case dict.get(data.pending, id) {
        Ok(PendingBootstrap(reply_to)) -> process.send(reply_to, Error(failure))
        Ok(PendingHost(reply_to: reply_to, ..)) ->
          process.send(reply_to, Error(failure))
        Error(Nil) -> Nil
      }

      sm.keep(Data(..data, pending: dict.delete(data.pending, id)))
    }

    codec.ServiceStatus(nickname, service_state) -> {
      notify(data, ServiceStateChanged(nickname, service_state))
      sm.keep(data)
    }
  }
}

/// The sidecar is listening: requests may flow, and the `AwaitReady`
/// callers postponed in `Starting` are replayed by this very transition. A
/// ready after a restart is announced.
fn on_ready(
  data: Data,
  port: Port,
  owned: Owned,
) -> sm.Next(Phase, Data, Message) {
  // Only a starting sidecar becomes ready; a repeat `Ready` changes nothing.
  case owned {
    Booting -> {
      // Restarts only go up while the machine is running, so a positive
      // count here means this ready follows a restart, not the first start.
      case data.restarts > 0 {
        True -> notify(data, SidecarRestarted)
        False -> Nil
      }

      sm.transition(to: Serving(port), data:)
    }

    Listening -> sm.keep(data)
  }
}

/// The sidecar is gone. Every pending request fails with the exit status,
/// subscribers are told, and then the machine either waits out a backoff
/// that grows with the number of consecutive failures, so a crash loop does
/// not spin, or, with the budget spent, gives up. The restart count rises
/// before the spawn, so a binary that fails to start at all still ends in
/// `GivenUp`. The backoff is the only place the `respawn` timeout is armed.
fn sidecar_failed(data: Data, status: Int) -> sm.Next(Phase, Data, Message) {
  dict.each(data.pending, fn(_, pending) { fail(pending, status) })
  notify(data, SidecarDied(status))

  let restarts = data.restarts + 1
  let data = Data(..data, pending: dict.new(), restarts:)

  // A spent budget gives up; otherwise a replacement is scheduled.
  case restarts > data.config.max_restarts {
    True -> {
      notify(data, SidecarGaveUp)
      sm.transition(to: GivenUp, data:)
    }

    False ->
      sm.transition(to: Restarting, data:)
      |> sm.with_named_timeout(
        name: "respawn",
        after: backoff_ms(restarts),
        sending: Respawn,
      )
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

/// Spawns the replacement once the backoff is over. Spawning itself can
/// fail, which counts as another failed attempt and so re-enters the
/// backoff or gives up.
fn respawn(data: Data) -> sm.Next(Phase, Data, Message) {
  case ffi_port.open_sidecar(data.config.binary_path, data.config.state_dir) {
    Ok(port) ->
      sm.transition(to: Starting(port), data:)
      |> sm.with_selector(selector_for(data.self, port))

    Error(Nil) -> sidecar_failed(data, -1)
  }
}

/// Tells every subscriber about an event.
fn notify(data: Data, event: Event) -> Nil {
  list.each(data.subscribers, process.send(_, event))
}

/// Asks the sidecar to exit and closes its port, which closes its stdin and
/// ends it even if the request is ignored, then stops the machine. Pending
/// requests are failed, not abandoned.
fn stop(
  phase: Phase,
  data: Data,
  reply_to: Subject(Result(Nil, TorError)),
) -> sm.Next(Phase, Data, Message) {
  // A sidecar with a port is told to exit; a dead one has nothing to close.
  case phase {
    Starting(port) | Serving(port) -> {
      let _ = ffi_port.send_frame(port, codec.encode_shutdown())
      let _ = ffi_port.close_port(port)
      Nil
    }

    Restarting | GivenUp -> Nil
  }

  dict.each(data.pending, fn(_, pending) { fail(pending, -3) })
  process.send(reply_to, Ok(Nil))

  sm.stop()
}
