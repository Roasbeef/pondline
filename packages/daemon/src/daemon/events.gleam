//// A registry of subscribers and the one-way fan-out to them (spec §9.3).
////
//// The daemon wakes a local adapter when there is something for it, and an
//// adapter that is not running must not hold anything up. So a commit never
//// calls a subscriber: the engine publishes after its transaction, and this
//// actor forwards the event to each subscribed `Subject` and forgets it. A
//// slow or dead subscriber costs the registry one `send` to a mailbox nobody
//// reads, never a wait. An event carries no data, only which contact has
//// something new, because the adapter reads the committed store through the
//// API: a lost event is recovered by the adapter's next poll, which is also
//// why nothing is replayed to a new subscriber.
////
//// The registry is generic in the event type so that `daemon/api`, which
//// defines the contract's `Event`, can use it without this module (or the
//// engine below it) importing the API.

import daemon/mail
import gleam/erlang/process.{type Name, type Subject}
import gleam/list
import gleam/otp/actor
import gleam/otp/supervision

/// The registry's mailbox protocol.
pub opaque type Message(event) {
  Subscribe(subscriber: Subject(event))
  Publish(event: event)
}

/// Starts the registry under `name`.
///
/// ## Examples
///
/// ```gleam
/// events.start(process.new_name("events"))
/// // -> Ok(started)
/// ```
pub fn start(
  name: Name(Message(event)),
) -> actor.StartResult(Subject(Message(event))) {
  actor.new([])
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.start
}

/// The registry as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// events.supervised(name)
/// ```
pub fn supervised(
  name: Name(Message(event)),
) -> supervision.ChildSpecification(Subject(Message(event))) {
  supervision.worker(fn() { start(name) })
}

/// Adds a subscriber. Events published from now on reach it.
///
/// ## Examples
///
/// ```gleam
/// events.subscribe(name, process.new_subject())
/// // -> Nil
/// ```
pub fn subscribe(
  name: Name(Message(event)),
  subscriber: Subject(event),
) -> Nil {
  mail.tell(name, Subscribe(subscriber))
}

/// Sends `event` to every subscriber.
///
/// ## Examples
///
/// ```gleam
/// events.publish(name, api.MessagesReady(contact))
/// // -> Nil
/// ```
pub fn publish(name: Name(Message(event)), event: event) -> Nil {
  mail.tell(name, Publish(event))
}

/// Adds a subscriber or forwards an event to all of them.
fn handle(
  subscribers: List(Subject(event)),
  message: Message(event),
) -> actor.Next(List(Subject(event)), Message(event)) {
  // Subscribing records the subject; publishing forwards to every recorded one.
  case message {
    Subscribe(subscriber:) -> actor.continue([subscriber, ..subscribers])

    Publish(event:) -> {
      list.each(subscribers, fn(subscriber) { process.send(subscriber, event) })
      actor.continue(subscribers)
    }
  }
}
