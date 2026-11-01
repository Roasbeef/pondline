//// The mailbox supervisor and its front door (spec §10.2).
////
//// `start` brings up the processes of one mailbox node under a supervisor:
//// the notification registry, the storage coordinator and the sweeper.
//// `handle` is the entry point a request-serving process calls: a typed
//// `Request` in, a typed `Response` out, with the clock read from the node's
//// injected `clock` rather than from the system. The HTTP binding will be a
//// thin process that decodes a body, calls `handle` and encodes the answer.
////
//// The supervisor restarts `rest_for_one`, in the order the children depend
//// on one another. The coordinator names the registry, and the sweeper names
//// the coordinator, so a registry restart restarts the two after it and a
//// sweeper crash touches nothing else. Because every child is addressed by a
//// `Name`, none of them has to hand its replacement's address to anyone.
////
//// ## Long polling
////
//// Only `Fetch` can wait, and the wait happens here, in the caller's own
//// process, not in the coordinator and not inside a transaction:
////
//// 1. Fetch once. A non-empty batch, or a refusal, is the answer. A wrong
////    capability is refused here, before anything is registered, so an
////    unauthenticated caller cannot park state in the registry.
//// 2. If the batch is empty and the client asked to wait, register with the
////    notification registry, then fetch again. The second fetch closes the
////    window in which an append commits between the first fetch and the
////    registration.
//// 3. If that is still empty, sleep until the registry wakes this caller or
////    the clamped wait elapses, then fetch a last time and answer, possibly
////    with an empty batch.
////
//// ## Why the wait is not a weft primitive
////
//// The waiting side is a list of waiters flushed on a state change, but the
//// list lives in the notifier, a `weft/actor`, and it is a homogeneous list
//// of subjects with no per-waiter state (`docs/weft.md`, "When not to"), so
//// it is not a state machine or an event manager. The wait itself runs in
//// the connection's own process, which this package does not own, and it
//// waits on a message with one deadline: under the production timer source,
//// `process.receive` with a timeout. Under an injected source the deadline
//// is a message armed through that source and the wait selects on either,
//// so a simulation's 25 second long poll costs no wall time. `weft/poll` re-probes a synchronous check, so it has nothing to
//// ask here, and a `weft` run would add a scope process and a worker per
//// poll to do what one `receive` does.
////
//// The worst case of one poll is still not bounded by
//// `limits.long_poll_seconds`: each of the three `run` calls can wait out
//// `call_timeout_ms` on a coordinator that is stuck, so a poll may take
//// the wait plus up to three such timeouts. A `weft` deadline would bound
//// it only by running the whole poll in a worker killed at the deadline,
//// which needs a slack above the wait for the healthy case, an arbitrary
//// answer when it expires, and the caller's own `forget` after the kill.
//// That is more machinery than the case warrants, since a coordinator that
//// stuck already holds every other request for as long, so the gap stays.
////
//// ## Flow
////
//// 1. `start` brings up the three processes under one supervisor.
//// 2. `handle` sends everything but a waiting `Fetch` straight to the
////    coordinator through `run`.
//// 3. A waiting `Fetch` goes through `long_poll` and `wait_for_append`,
////    the three steps above.
////
//// ## Simulation seams
////
//// `Config` carries three values only a simulation changes: the `timer`
//// source the sweeper's tick and the long poll's deadline are armed on
//// (production: `timer.WallClock`), a mail `interceptor` that every call to
//// the coordinator and the notifier goes through (production: `None`, a
//// direct send), and `store_faults` for the coordinator's transactions
//// (production: `None`). The database location is already `path`.

import core/id
import core/limits
import core/mailbox/protocol.{type Request, type Response}
import core/time.{type Instant}
import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/option.{type Option}
import gleam/otp/actor
import gleam/otp/static_supervisor
import mailbox/coordinator
import mailbox/mail
import mailbox/notifier
import mailbox/store
import mailbox/sweeper
import weft/timer

/// The names of a node's processes. Create them once with `new_names`
/// and share them with every process that talks to the node.
pub type Names {
  Names(
    coordinator: Name(coordinator.Message),
    notifier: Name(notifier.Message),
  )
}

/// What a running node's callers need: where to send, what time it is,
/// where the long poll's deadline is armed, and whether calls go through a
/// simulation's interceptor.
pub type Node {
  Node(
    names: Names,
    clock: fn() -> Instant,
    timer: timer.Source,
    interceptor: Option(mail.Interceptor),
  )
}

/// How a node is started.
pub type Config {
  Config(
    /// The database file.
    path: String,
    /// Milliseconds between sweeps.
    sweep_period_ms: Int,
    /// The current time. Production passes the system clock; a test passes
    /// a function over a counter.
    clock: fn() -> Instant,
    /// The names to start the node's processes under.
    names: Names,
    /// Where the sweeper's tick and the long poll's deadline are armed.
    /// Production passes `timer.WallClock`.
    timer: timer.Source,
    /// Where calls between the node's processes are handed instead of sent.
    /// Production passes `None`.
    interceptor: Option(mail.Interceptor),
    /// A fault hook for the coordinator's transactions. Production passes
    /// `None`.
    store_faults: Option(store.Faults),
  )
}

/// How long one call to the coordinator may take before the request is
/// answered `Unavailable`. It is generous because a request waits behind
/// every earlier write, and a request that gave up early would only be
/// retried by the client into a longer queue.
const call_timeout_ms = 30_000

/// Fresh process names for one node.
///
/// ## Examples
///
/// ```gleam
/// let names = node.new_names()
/// ```
pub fn new_names() -> Names {
  Names(
    coordinator: process.new_name("mailbox_coordinator"),
    notifier: process.new_name("mailbox_notifier"),
  )
}

/// Starts the node's supervisor and its three children, and returns the
/// `Node` callers use.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(_supervisor, node)) = node.start(config)
/// node.handle(node, request)
/// ```
pub fn start(
  config: Config,
) -> Result(
  #(actor.Started(static_supervisor.Supervisor), Node),
  actor.StartError,
) {
  let Config(
    path:,
    sweep_period_ms:,
    clock:,
    names:,
    timer:,
    interceptor:,
    store_faults:,
  ) = config

  let started =
    static_supervisor.new(static_supervisor.RestForOne)
    |> static_supervisor.add(notifier.supervised(names.notifier))
    |> static_supervisor.add(coordinator.supervised(
      names.coordinator,
      coordinator.Config(
        path:,
        notifier: mail.address(
          names.notifier,
          interceptor,
          from: "coordinator",
          to: "notifier",
        ),
        store_faults:,
      ),
    ))
    |> static_supervisor.add(
      sweeper.supervised(sweeper.Config(
        coordinator: mail.address(
          names.coordinator,
          interceptor,
          from: "sweeper",
          to: "coordinator",
        ),
        period_ms: sweep_period_ms,
        clock:,
        timer:,
      )),
    )
    |> static_supervisor.start

  // The caller gets the node's addresses along with the supervisor.
  case started {
    Ok(supervisor) ->
      Ok(#(supervisor, Node(names:, clock:, timer:, interceptor:)))
    Error(error) -> Error(error)
  }
}

/// Answers one request, reading the time from the node's clock. A `Fetch`
/// with a positive `wait_seconds` may block this process for up to
/// `limits.long_poll_seconds`; nothing else does.
///
/// ## Examples
///
/// ```gleam
/// node.handle(node, protocol.Ack(queue, read, []))
/// // -> protocol.Acked
/// ```
pub fn handle(node: Node, request: Request) -> Response {
  case request {
    protocol.Fetch(wait_seconds:, ..) if wait_seconds > 0 ->
      long_poll(node, request, wait_seconds)

    protocol.CreateQueue(..)
    | protocol.Append(..)
    | protocol.Fetch(..)
    | protocol.Ack(..)
    | protocol.DeleteQueue(..) -> run(node, request)
  }
}

/// Sends a request to the coordinator with the node's clock reading.
fn run(node: Node, request: Request) -> Response {
  coordinator.handle(
    mail.address(
      node.names.coordinator,
      node.interceptor,
      from: "request",
      to: "coordinator",
    ),
    node.clock(),
    request,
    call_timeout_ms,
  )
}

/// The request process's handle on the notification registry.
fn registry(node: Node) -> mail.Handle(notifier.Message) {
  mail.address(
    node.names.notifier,
    node.interceptor,
    from: "request",
    to: "notifier",
  )
}

/// Step 1 of a long poll: one immediate fetch, which settles every case
/// except an empty batch.
fn long_poll(node: Node, request: Request, wait_seconds: Int) -> Response {
  // Only an empty batch is worth waiting on.
  case run(node, request), request {
    // Only an empty batch is worth waiting on; everything else, including
    // a refusal, is already the answer.
    protocol.Batch(envelopes: []), protocol.Fetch(queue:, ..) ->
      wait_for_append(node, request, id.to_bytes(queue), wait_seconds)

    first, _ -> first
  }
}

/// Steps 2 and 3 of a long poll: register, fetch again, sleep until woken
/// or timed out, fetch a last time, and clean up the registration.
fn wait_for_append(
  node: Node,
  request: Request,
  queue: BitArray,
  wait_seconds: Int,
) -> Response {
  let wake = process.new_subject()
  notifier.wait(registry(node), queue, wake)

  // Registered first, looked second: an append that committed between the
  // first fetch and the registration is visible here, and any later one
  // wakes the registration.
  let answer = case run(node, request) {
    protocol.Batch(envelopes: []) -> {
      let seconds = int.min(wait_seconds, limits.long_poll_seconds)
      await_wake(node.timer, wake, seconds * 1000)

      run(node, request)
    }

    settled -> settled
  }

  // After `forget` returns the registry will not send again, so draining
  // here leaves no stray wake-up in this process's mailbox.
  notifier.forget(registry(node), queue, wake)
  let _ = process.receive(wake, 0)

  answer
}

/// Sleeps until `wake` receives or `timeout_ms` passes on the timer source's
/// own time base.
fn await_wake(
  source: timer.Source,
  wake: Subject(Nil),
  timeout_ms: Int,
) -> Nil {
  // The wall clock is a receive with a timeout, exactly as before the seam.
  // An injected source arms the deadline as a message and the wait takes
  // whichever comes first; a deadline that fires after a wake-up leaves one
  // `Nil` in this process's mailbox, unread and released with the process.
  case source {
    timer.WallClock -> {
      let _ = process.receive(wake, timeout_ms)
      Nil
    }

    timer.Injected(after:) -> {
      let expired = process.new_subject()
      after(timeout_ms, fn() { process.send(expired, Nil) })

      process.new_selector()
      |> process.select(wake)
      |> process.select(expired)
      |> process.selector_receive_forever
    }
  }
}
