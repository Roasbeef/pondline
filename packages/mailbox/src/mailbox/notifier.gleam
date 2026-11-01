//// The queue notification registry (spec §10.2): who is waiting for which
//// queue to receive an envelope.
////
//// A long-polling `Fetch` must not hold a database transaction, a database
//// connection or the storage coordinator while it waits. So the waiting
//// lives here, in a process that knows nothing about storage: a waiter
//// registers a `Subject` under a queue identifier, and the coordinator calls
//// `notify` after an append has committed. `notify` wakes every waiter of
//// that queue once and forgets them; a woken caller fetches again and
//// registers again if it still wants to wait.
////
//// `waiters` is the table lookup every message starts from: a queue with no
//// entry has no waiters.
////
//// The registry holds one entry per queue that currently has a waiter, never
//// one per queue that exists (spec §10.2: no permanent process or state per
//// queue). A waiter that gives up removes itself with `forget`. A waiter
//// that dies leaves a dead subject behind until the next `notify` for its
//// queue clears it; sending to a dead process is harmless, and the cost is a
//// few bytes of a queue that never receives anything again.
////
//// The registry is addressed by a `Name`, not a subject, so it can be
//// restarted under the supervisor without callers learning a new address.
//// Losing it loses only the wake-ups: a waiter's own timeout still answers.
////
//// ## Why this is an actor and not a state machine
////
//// A list of waiters flushed on a state change is one of the shapes weft
//// names, but it is a state machine only when the process has phases. This
//// one has a single mode and a homogeneous table of subjects with no
//// per-waiter state or deadline (each waiter times out in its own process),
//// so `docs/weft.md` keeps it a plain `weft/actor`. `deliver` stays a
//// `process.named` check followed by a send, for the reason `coordinator`
//// gives for `ask`: moving to `weft/registry` would change `node.Names`
//// and need a registry process owned by the node.

import gleam/dict.{type Dict}
import gleam/erlang/process.{type Name, type Subject}
import gleam/list
import gleam/otp/supervision
import weft/actor

/// The registry's messages. The queue key is the queue identifier's bytes,
/// which is all the registry needs and keeps it free of protocol types.
pub opaque type Message {
  Wait(queue: BitArray, wake: Subject(Nil))
  Forget(queue: BitArray, wake: Subject(Nil), done: Subject(Nil))
  Notify(queue: BitArray)
}

/// Whether `deliver` found the registry running.
type Delivery {
  Delivered
  NotRunning
}

/// How long `forget` waits for the registry to confirm.
const forget_timeout_ms = 1000

type State =
  Dict(BitArray, List(Subject(Nil)))

/// Starts the registry under `name`.
///
/// ## Examples
///
/// ```gleam
/// let name = process.new_name("notifier")
/// let assert Ok(_) = notifier.start(name)
/// ```
pub fn start(name: Name(Message)) -> actor.StartResult(Subject(Message)) {
  actor.new(dict.new())
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.start
}

/// The registry as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// notifier.supervised(name)
/// ```
pub fn supervised(
  name: Name(Message),
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() { start(name) })
}

/// Registers `wake` to receive one `Nil` the next time `queue` is notified.
/// Register before the last look at the database, so an append that lands
/// between the look and the wait still wakes the waiter.
///
/// ## Examples
///
/// ```gleam
/// notifier.wait(name, queue_bytes, wake)
/// ```
pub fn wait(name: Name(Message), queue: BitArray, wake: Subject(Nil)) -> Nil {
  let _ = deliver(name, Wait(queue:, wake:))
  Nil
}

/// Removes a waiter that is giving up, and returns once the registry has
/// done so. The wait matters: after it, no further wake-up can be sent to
/// `wake`, so the caller can drain its subject and leave nothing behind in
/// its mailbox. Harmless if the waiter was already woken.
///
/// ## Examples
///
/// ```gleam
/// notifier.forget(name, queue_bytes, wake)
/// ```
pub fn forget(name: Name(Message), queue: BitArray, wake: Subject(Nil)) -> Nil {
  let done = process.new_subject()

  // Only wait for the confirmation if the registry got the message.
  case deliver(name, Forget(queue:, wake:, done:)) {
    Delivered -> {
      let _ = process.receive(done, forget_timeout_ms)
      Nil
    }

    NotRunning -> Nil
  }
}

/// Wakes every waiter of `queue`. The coordinator calls this after an
/// append has committed, so a woken waiter's fetch sees the new row.
///
/// ## Examples
///
/// ```gleam
/// notifier.notify(name, queue_bytes)
/// ```
pub fn notify(name: Name(Message), queue: BitArray) -> Nil {
  let _ = deliver(name, Notify(queue:))
  Nil
}

/// Sends to the registry if it is running. A registry that is down means
/// wake-ups are lost, which every waiter's own timeout already covers, so
/// a missing registry is not an error for any caller.
fn deliver(name: Name(Message), message: Message) -> Delivery {
  // Sending to an unregistered name would crash the sender, so look first.
  case process.named(name) {
    Ok(_) -> {
      process.send(process.named_subject(name), message)
      Delivered
    }

    Error(Nil) -> NotRunning
  }
}

/// Keeps the waiter table: `Wait` adds, `Forget` removes and confirms,
/// `Notify` wakes and clears.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // Each message changes the table for exactly one queue.
  case message {
    Wait(queue:, wake:) -> {
      let waiting = waiters(state, queue)
      actor.continue(dict.insert(state, queue, [wake, ..waiting]))
    }

    Forget(queue:, wake:, done:) -> {
      let remaining =
        list.filter(waiters(state, queue), fn(other) { other != wake })

      process.send(done, Nil)
      actor.continue(store_waiters(state, queue, remaining))
    }

    // The commit happened before this message was sent, so everyone woken
    // here can fetch the new envelope. Each is woken once and dropped; the
    // caller re-registers if its fetch comes back empty.
    Notify(queue:) -> {
      list.each(waiters(state, queue), fn(wake) { process.send(wake, Nil) })
      actor.continue(dict.delete(state, queue))
    }
  }
}

fn waiters(state: State, queue: BitArray) -> List(Subject(Nil)) {
  case dict.get(state, queue) {
    Ok(waiting) -> waiting
    Error(Nil) -> []
  }
}

/// Writes a queue's waiter list back, dropping the entry when it is empty so
/// the table holds only queues that have a waiter.
fn store_waiters(
  state: State,
  queue: BitArray,
  waiting: List(Subject(Nil)),
) -> State {
  case waiting {
    [] -> dict.delete(state, queue)
    _ -> dict.insert(state, queue, waiting)
  }
}
