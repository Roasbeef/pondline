//// Keeps one fetcher running for every live inbound queue (spec §10.2).
////
//// Which queues are live is a fact about committed state: open offers and
//// relationships that have a session. This actor does not track queue
//// events. On a nudge and on a timer it asks the engine for the live set and
//// starts a fetcher for any queue that has none, so a queue that appears
//// (an offer opened, a joiner's session started) gains its fetcher without
//// anyone sending it a queue-specific message, and a fetcher that crashed is
//// replaced by the next tick. A fetcher ends by itself when its queue stops
//// being live, so this actor never has to stop one.
////
//// Fetchers are linked to this actor and not supervised individually. A
//// crashing fetcher takes the manager down, the node's supervisor restarts
//// it, and the first reconcile starts the fetchers again from committed
//// state; nothing a fetcher holds needs to survive.
////
//// The periodic tick also retires offers whose acceptance deadline passed,
//// which is what makes their queues stop being live.

import core/id
import core/route.{type Inbox}
import daemon/engine
import daemon/fetcher
import daemon/mail
import daemon/status
import daemon/transport.{type Dialer}
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Name, type Pid, type Subject}
import gleam/list
import gleam/otp/actor
import gleam/otp/supervision

/// Milliseconds between reconciles.
pub const tick_ms = 2000

/// What the manager needs to start fetchers.
pub type Config {
  Config(
    /// How fetchers reach the mailbox.
    dialer: Dialer,
    /// The writer that knows the live queues.
    engine: Name(engine.Message),
    /// Told whether the mailbox answered.
    status: Name(status.Message),
  )
}

/// The manager's mailbox protocol.
pub opaque type Message {
  Reconcile
  Tick
}

type State {
  State(config: Config, self: Subject(Message), running: Dict(BitArray, Pid))
}

/// Starts the manager under `name` and arms its first reconcile.
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
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    process.send(subject, Tick)

    actor.initialised(State(config:, self: subject, running: dict.new()))
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.start
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
  supervision.worker(fn() { start(name, config) })
}

/// Tells the manager the set of live queues may have changed. Safe to lose.
///
/// ## Examples
///
/// ```gleam
/// fetch_manager.nudge(name)
/// // -> Nil
/// ```
pub fn nudge(name: Name(Message)) -> Nil {
  mail.tell(name, Reconcile)
}

/// Reconciles on a nudge; on a tick also retires expired offers and re-arms.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // A nudge reconciles at once; a tick also retires expired offers and arms the next tick.
  case message {
    Reconcile -> actor.continue(reconcile(state))

    Tick -> {
      process.send_after(state.self, tick_ms, Tick)

      // Expiring first lets a retired offer's queue drop out of the same
      // reconcile's live set.
      let _ = engine.expire_offers(state.config.engine)
      actor.continue(reconcile(state))
    }
  }
}

/// Starts a fetcher for every live queue that has none running.
fn reconcile(state: State) -> State {
  case engine.live_inboxes(state.config.engine) {
    Ok(inboxes) -> list.fold(inboxes, state, ensure_fetcher)

    // An engine that does not answer is asked again on the next tick.
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
      let config =
        fetcher.Config(
          dialer: state.config.dialer,
          engine: state.config.engine,
          status: state.config.status,
          inbox:,
        )
      let pid = process.spawn(fn() { fetcher.run(config) })

      State(..state, running: dict.insert(state.running, key, pid))
    }
  }
}
