//// The storage coordinator: the one process that owns the database
//// connection and so the one writer (spec §8.4, §10.2).
////
//// Every request, sweep and grant reaches the store through this actor's
//// mailbox, so changes are applied one at a time in arrival order and no
//// two transactions ever contend. The messages are complete commands: a
//// caller sends the whole request and the clock reading, and the coordinator
//// runs it to the end inside one `service.handle` call, which is one SQLite
//// transaction. There is no way to open a transaction here and finish it in a
//// later message, so a slow or dead caller can never leave a lock held
//// (design review B, §3.10).
////
//// After an append commits, the coordinator tells the notification registry,
//// so a long-polling fetch wakes on a row that is already durable. The tell
//// follows the commit and precedes the reply; a crash between them loses a
//// wake-up, never an envelope, and the waiter's own timeout answers it.
////
//// The actor is addressed by a `Name`, which survives a restart. The caller
//// functions below fail soft: if the coordinator is down or does not answer
//// within the timeout, the answer is `Refused(Unavailable)` and the client
//// retries, rather than the calling process crashing.
////
//// ## Why the store opens in the initialiser
////
//// `weft/actor`'s `continuing` is for an actor whose first work must run
//// before any request but may finish after `start` returns. This actor is
//// the opposite: a database that cannot be opened must fail the start, so
//// the supervisor sees it and the node never accepts an append it cannot
//// store. The initialiser is synchronous, so no request can reach a
//// coordinator that has no store, and there is no first message to inject.
////
//// There is no `on_shutdown` that closes the store, and the actor does not
//// trap exits to run one. The connection belongs to this process, and an
//// orderly node shutdown ends it with the process: SQLite removes the WAL
//// file when the last connection goes, which `node_test` observes. A
//// callback would be code for a case nothing exercises, and it could not
//// run on a brutal kill anyway.
////
//// ## Why `ask` stays on a `Name`
////
//// `ask` (`mailbox/mail`, which also holds the simulation's interception
//// seam) is a call against a process that was started elsewhere: look the
//// name up, send, wait on a per-call subject, and answer `Error(Nil)` for
//// a missing process or a late reply. That is the monitored, non-panicking
//// call against a pre-existing pid which weft does not yet have (Loom's
//// `docs/weft.md` records the same gap), so the shape stays here rather
//// than being forced onto `weft/registry`. A registry address would trade
//// the `process.named` check for `registry.lookup`, but it needs a
//// registry process whose lifetime the node would have to own, and it
//// would change `node.Names`, which the daemon's tests build. It would
//// also still wait the full timeout on a coordinator that dies mid-call,
//// because it does not monitor either.

import core/capability.{type Capability, type Provision}
import core/id
import core/mailbox/protocol.{type Request, type Response}
import core/time.{type Instant}
import gleam/erlang/process.{type Name, type Subject}
import gleam/option.{type Option}
import gleam/otp/supervision
import gleam/result
import mailbox/mail.{type Handle}
import mailbox/notifier
import mailbox/service.{type GrantError, type Random}
import mailbox/store.{type Store, type SweepReport}
import weft/actor

/// What the coordinator needs to start.
pub type Config {
  Config(
    /// The database file.
    path: String,
    /// The registry to tell after an append commits.
    notifier: Handle(notifier.Message),
    /// A fault hook for the store's transactions, or `None` in production.
    store_faults: Option(store.Faults),
  )
}

/// A complete command for the writer.
pub opaque type Message {
  Handle(now: Instant, request: Request, reply_with: Subject(Response))
  Sweep(now: Instant, reply_with: Subject(Result(SweepReport, store.Error)))
  CreateGrant(
    allowance: Int,
    random: Random,
    reply_with: Subject(Result(Capability(Provision), GrantError)),
  )
}

type State {
  State(store: Store, notifier: Handle(notifier.Message))
}

/// Opens the database and starts the coordinator under `name`. Start fails,
/// and the supervisor with it, if the file cannot be opened or migrated: a
/// mailbox that cannot reach its state must not accept appends.
///
/// ## Examples
///
/// ```gleam
/// let name = process.new_name("coordinator")
/// let assert Ok(_) = coordinator.start(name, Config(path, notifier, None))
/// ```
pub fn start(
  name: Name(Message),
  config: Config,
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    case store.open_with(config.path, config.store_faults) {
      Ok(store) ->
        actor.initialised(State(store:, notifier: config.notifier))
        |> actor.returning(subject)
        |> Ok

      Error(_) -> Error("the mailbox database could not be opened")
    }
  })
  |> actor.on_message(handle_message)
  |> actor.named(name)
  |> actor.start
}

/// The coordinator as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// coordinator.supervised(name, config)
/// ```
pub fn supervised(
  name: Name(Message),
  config: Config,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() { start(name, config) })
}

/// Runs one request. `Refused(Unavailable)` when the coordinator is not
/// running or does not answer within `timeout_ms`.
///
/// ## Examples
///
/// ```gleam
/// coordinator.handle(name, Instant(1_000), request, 5000)
/// ```
pub fn handle(
  name: Handle(Message),
  now: Instant,
  request: Request,
  timeout_ms: Int,
) -> Response {
  mail.ask(name, "handle", timeout_ms, fn(reply_with) {
    Handle(now:, request:, reply_with:)
  })
  |> result.unwrap(protocol.Refused(protocol.Unavailable))
}

/// Runs one sweep. `Error(Nil)` when the coordinator is not running or does
/// not answer within `timeout_ms`; a storage fault is the inner error.
///
/// ## Examples
///
/// ```gleam
/// coordinator.sweep(name, Instant(1_000), 5000)
/// ```
pub fn sweep(
  name: Handle(Message),
  now: Instant,
  timeout_ms: Int,
) -> Result(Result(SweepReport, store.Error), Nil) {
  mail.ask(name, "sweep", timeout_ms, fn(reply_with) {
    Sweep(now:, reply_with:)
  })
}

/// Creates a provisioning grant and returns its capability. `Error(Nil)`
/// when the coordinator is not running or does not answer in time.
///
/// ## Examples
///
/// ```gleam
/// coordinator.create_grant(name, 10, random, 5000)
/// ```
pub fn create_grant(
  name: Handle(Message),
  allowance: Int,
  random: Random,
  timeout_ms: Int,
) -> Result(Result(Capability(Provision), GrantError), Nil) {
  mail.ask(name, "create_grant", timeout_ms, fn(reply_with) {
    CreateGrant(allowance:, random:, reply_with:)
  })
}

/// Runs one command to completion before the next is read, which is what
/// makes the coordinator the single writer.
fn handle_message(
  state: State,
  message: Message,
) -> actor.Next(State, Message) {
  // One arm per command; each runs a whole transaction's worth of work.
  case message {
    Handle(now:, request:, reply_with:) -> {
      let response = service.handle(state.store, now, request)

      // The transaction inside `handle` has committed before this line, so
      // the woken fetch will see the row. The reply follows, so a client
      // that appended and then fetched never misses its own envelope.
      announce(state, response)
      process.send(reply_with, response)
      actor.continue(state)
    }

    Sweep(now:, reply_with:) -> {
      process.send(reply_with, service.sweep(state.store, now))
      actor.continue(state)
    }

    CreateGrant(allowance:, random:, reply_with:) -> {
      let granted = service.create_grant(state.store, allowance, random)
      process.send(reply_with, granted)
      actor.continue(state)
    }
  }
}

/// Wakes the queue's long-polling fetches after an append has committed.
/// Only `Appended` can add a row, so only it notifies.
fn announce(state: State, response: Response) -> Nil {
  // Every other answer leaves the set of fetchable envelopes unchanged.
  case response {
    protocol.Appended(receipt:) ->
      notifier.notify(state.notifier, id.to_bytes(receipt.queue))

    protocol.QueueCreated(..)
    | protocol.Batch(..)
    | protocol.Acked
    | protocol.QueueDeleted
    | protocol.Refused(..) -> Nil
  }
}
