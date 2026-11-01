//// Keeps one fetcher running for every live inbound queue (spec §10.2).
////
//// Which queues are live is a fact about committed state: open offers and
//// relationships that have a session. This actor does not track queue
//// events. On a nudge and on a timer it asks the engine for the live set and
//// starts a fetcher for any queue that has none, so a queue that appears
//// (an offer opened, a joiner's session started) gains its fetcher without
//// anyone sending it a queue-specific message, and a fetcher that crashed is
//// replaced by the next tick. A fetcher ends by itself when its queue stops
//// being live, so this actor never has to stop one. A retired queue whose
//// committed envelopes are not all acknowledged (a restart between the
//// commit and the acknowledgement) also gets a fetcher, which acknowledges
//// them and ends.
////
//// Fetchers are linked to this actor and not supervised individually. A
//// crashing fetcher takes the manager down, the node's supervisor restarts
//// it, and the first reconcile starts the fetchers again from committed
//// state; nothing a fetcher holds needs to survive.
////
//// The periodic tick also retires offers whose acceptance deadline passed,
//// which is what makes their queues stop being live.
////
//// ## Timers
////
//// The manager is a `weft/actor`. Its first `Tick` is handled before any
//// request (`continuing`), so fetchers for committed queues start at once,
//// and `periodic` sends one every `tick_ms`. The period is armed in the
//// builder and nowhere else; a nudge reconciles without touching it.

import core/id
import core/route.{type Inbox}
import daemon/engine
import daemon/fetcher
import daemon/mail.{type Handle}
import daemon/status
import daemon/transport.{type Dialer}
import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Name, type Pid, type Subject}
import gleam/list
import gleam/otp/actor as otp_actor
import gleam/otp/supervision
import weft/actor
import weft/timer

/// Milliseconds between reconciles.
pub const tick_ms = 2000

/// What the manager needs to start fetchers.
pub type Config {
  Config(
    /// How fetchers reach the mailbox.
    dialer: Dialer,
    /// The writer that knows the live queues.
    engine: Handle(engine.Message),
    /// Told whether the mailbox answered.
    status: Handle(status.Message),
    /// Where the manager's tick and every fetcher's timers are armed.
    timer: timer.Source,
  )
}

/// The manager's mailbox protocol.
pub opaque type Message {
  Reconcile
  Tick
}

type State {
  State(config: Config, running: Dict(BitArray, Pid))
}

/// Starts the manager under `name`. Its first reconcile runs before any
/// request, and the next ones every `tick_ms`.
///
/// ## Examples
///
/// ```gleam
/// fetch_manager.start(name, config)
/// // -> Ok(started)
/// ```
pub fn start(
  name: Name(Message),
  config: Config,
) -> otp_actor.StartResult(Subject(Message)) {
  actor.start(builder(name, config))
}

/// The manager as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// fetch_manager.supervised(name, config)
/// ```
pub fn supervised(
  name: Name(Message),
  config: Config,
) -> supervision.ChildSpecification(Subject(Message)) {
  actor.supervised(builder(name, config))
}

/// The manager's actor: named, reconciling first, then every `tick_ms`.
fn builder(
  name: Name(Message),
  config: Config,
) -> actor.Builder(State, Message, Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    actor.initialised(State(config:, running: dict.new()))
    |> actor.returning(subject)
    |> actor.continuing(Tick)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.periodic(every: tick_ms, sending: Tick)
  |> actor.with_timer_source(config.timer)
}

/// Tells the manager the set of live queues may have changed. Safe to lose.
///
/// ## Examples
///
/// ```gleam
/// fetch_manager.nudge(name)
/// // -> Nil
/// ```
pub fn nudge(name: Handle(Message)) -> Nil {
  mail.tell(name, "reconcile", Reconcile)
}

/// Reconciles on a nudge; on a tick also retires expired offers.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // A nudge reconciles at once; a tick also retires expired offers.
  case message {
    Reconcile -> actor.continue(reconcile(state))

    Tick -> {
      // Expiring first lets a retired offer's queue drop out of the same
      // reconcile's live set.
      let _ = engine.expire_offers(state.config.engine)
      actor.continue(reconcile(state))
    }
  }
}

/// Starts a fetcher for every live queue that has none running, and for
/// every retired queue that still owes the mailbox acknowledgements; the
/// second kind acknowledges and stops at the end of its first round.
fn reconcile(state: State) -> State {
  // The live queues first: each that has no fetcher gets one.
  let state = case engine.live_inboxes(state.config.engine) {
    Ok(inboxes) -> list.fold(inboxes, state, ensure_fetcher)

    // An engine that does not answer is asked again on the next tick.
    Error(_) -> state
  }

  // A retired queue with committed, unacknowledged envelopes is one a
  // fetcher retired from, or a restart left, before acknowledging them.
  case engine.draining_inboxes(state.config.engine) {
    Ok(inboxes) -> list.fold(inboxes, state, ensure_fetcher)
    Error(_) -> state
  }
}

/// Starts the fetcher for one inbox unless a live one exists.
fn ensure_fetcher(state: State, inbox: Inbox) -> State {
  let key = id.to_bytes(inbox.queue)

  // A recorded process that has since died, by retirement or by crash, is
  // replaced like a missing one.
  let running = case dict.get(state.running, key) {
    Ok(pid) -> process.is_alive(pid)
    Error(Nil) -> False
  }

  // A live fetcher is left alone; a missing or dead one is started.
  case running {
    True -> state

    False -> {
      // Each fetcher's messages are labelled with its own queue, so an
      // interceptor can tell two fetchers' calls apart.
      let holder = "fetcher/" <> bit_array.base16_encode(key)
      let config =
        fetcher.Config(
          dialer: state.config.dialer,
          engine: mail.from(state.config.engine, holder),
          status: mail.from(state.config.status, holder),
          inbox:,
          ack_deadline_ms: fetcher.ack_deadline_ms,
          poll_deadline_ms: fetcher.poll_deadline_ms,
          timer: state.config.timer,
        )

      // A fetcher that fails to start is simply absent; the next tick tries
      // again.
      case fetcher.start(config) {
        Ok(started) ->
          State(..state, running: dict.insert(state.running, key, started.pid))

        Error(_) -> state
      }
    }
  }
}
