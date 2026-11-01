//// Messages to the node's named actors that fail soft, through a handle a
//// simulation can intercept.
////
//// The coordinator and the notifier are addressed by `Name`, so a restarted
//// process is found again without anyone handing out its new address. A
//// name may briefly have no process, and `process.send` to an unregistered
//// name crashes the sender, so every send here looks the name up first: a
//// `tell` to nobody is dropped, and an `ask` of nobody answers `Error(Nil)`.
//// That is the monitored, non-panicking call against a pre-existing pid that
//// weft does not have (`coordinator` says why it is not a `weft/registry`
//// address), written once instead of in each caller.
////
//// ## Handles, and the interception seam
////
//// A handle built by `direct`, or by `address` without an interceptor, sends
//// straight to the process with no extra hop. That is the production path,
//// and the only one `node.start` builds unless its `Config` says otherwise.
////
//// A deterministic simulation instead passes an `Interceptor`. A handle
//// built with one does not send: it wraps the send in a `Parcel` and hands
//// it to the interceptor, which the simulation's runner owns. The runner
//// parks every parcel and releases them in an order its seed chooses by
//// calling `deliver`, so two request processes racing to the coordinator,
//// or the coordinator's wake-up racing a waiter's registration, happen in
//// the same order on every run of a seed. A parcel carries the holder's
//// role (`from`), the target's role (`to`) and a fixed word for the kind of
//// message (`label`), never a value from it, so the runner can sort by a
//// key that does not depend on which process the BEAM ran first. The shape
//// is the daemon's `daemon/mail` parcel; the two packages do not depend on
//// each other, so the runner adapts one to the other.
////
//// Under interception the name is looked up when the parcel is delivered,
//// not when it is made, and a parcel for a dead target is dropped with
//// `NoRecipient`. An intercepted `ask` monitors the target it found, so a
//// target that dies before release answers `Error(Nil)` at once instead of
//// after the whole timeout on the wall clock. Parcels from one sender
//// process reach the interceptor in program order, and a runner must release
//// them in that order: a local send is enqueued before the sender's next
//// instruction, and the long poll's "register, then look" depends on it.
////
//// What is not intercepted: the reply to an `ask`, the notifier's wake-ups to
//// waiting subjects, weft's own timer messages, exits and monitor messages.

import gleam/erlang/process.{type Name, type Subject}
import gleam/option.{type Option, None, Some}
import gleam/result

/// How a sender reaches a named actor: the name, and whether its messages go
/// straight there or through an interceptor.
pub opaque type Handle(message) {
  Handle(name: Name(message), route: Route)
}

/// Where a handle's messages go.
type Route {
  /// Straight to the named process. The production path.
  Direct

  /// To the interceptor, as a parcel labelled with both ends.
  Intercepted(interceptor: Interceptor, from: String, to: String)
}

/// One message held back by an interceptor.
pub type Parcel {
  Parcel(
    /// The role of the process that sent it.
    from: String,
    /// The role of the process it is for.
    to: String,
    /// What kind of message it is: a fixed word per kind, never a value.
    label: String,
    /// Sends the message to the named process if one is registered now.
    deliver: fn() -> Delivery,
  )
}

/// Whether a send found its process.
pub type Delivery {
  /// The message is in the named process's mailbox.
  Delivered

  /// No process held the name, so the message was dropped.
  NoRecipient
}

/// What an intercepted handle hands its parcels to. `park` runs in the
/// sender's own process and must return promptly.
pub type Interceptor {
  Interceptor(park: fn(Parcel) -> Nil)
}

/// A handle that sends straight to `name`.
///
/// ## Examples
///
/// ```gleam
/// mail.direct(names.coordinator)
/// ```
pub fn direct(name: Name(message)) -> Handle(message) {
  Handle(name:, route: Direct)
}

/// A handle for the holder `from` to reach the target `to` under `name`:
/// direct without an interceptor, intercepted with one.
///
/// ## Examples
///
/// ```gleam
/// mail.address(names.notifier, None, from: "coordinator", to: "notifier")
/// // -> a direct handle
/// ```
pub fn address(
  name: Name(message),
  interceptor: Option(Interceptor),
  from from: String,
  to to: String,
) -> Handle(message) {
  // Without an interceptor the labels have no reader, so none is kept.
  case interceptor {
    None -> Handle(name:, route: Direct)

    Some(interceptor) ->
      Handle(name:, route: Intercepted(interceptor:, from:, to:))
  }
}

/// Sends `message` to the process behind `handle`, if there is one. A direct
/// handle says whether it found the process; an intercepted one cannot know
/// yet and answers `Delivered`.
///
/// ## Examples
///
/// ```gleam
/// mail.tell(notifier, "notify", Notify(queue))
/// // -> Delivered
/// ```
pub fn tell(
  handle: Handle(message),
  label: String,
  message: message,
) -> Delivery {
  // A direct handle sends now; an intercepted one parks the send.
  case handle.route {
    Direct -> send_named(handle.name, message)

    Intercepted(interceptor:, from:, to:) -> {
      interceptor.park(
        Parcel(from:, to:, label:, deliver: fn() {
          send_named(handle.name, message)
        }),
      )

      Delivered
    }
  }
}

/// Sends a request to the process behind `handle` and waits up to
/// `timeout_ms` for its reply. `Error(Nil)` when the process is not running
/// or does not answer in time; through an interceptor, also when it dies
/// before answering.
///
/// ## Examples
///
/// ```gleam
/// mail.ask(coordinator, "sweep", 5000, fn(reply_with) { Sweep(now, reply_with) })
/// ```
pub fn ask(
  handle: Handle(message),
  label: String,
  timeout_ms: Int,
  make: fn(Subject(reply)) -> message,
) -> Result(reply, Nil) {
  use pid <- result.try(process.named(handle.name))

  let reply_with = process.new_subject()

  // A direct ask is a send and a wait; an intercepted one parks the request
  // and also watches the target, because the runner may release the request
  // after the target is gone.
  case handle.route {
    Direct -> {
      process.send(process.named_subject(handle.name), make(reply_with))
      process.receive(reply_with, timeout_ms)
    }

    Intercepted(interceptor:, from:, to:) -> {
      let monitor = process.monitor(pid)
      let request = make(reply_with)
      interceptor.park(
        Parcel(from:, to:, label:, deliver: fn() {
          send_named(handle.name, request)
        }),
      )

      let answer =
        process.new_selector()
        |> process.select_map(reply_with, Ok)
        |> process.select_specific_monitor(monitor, fn(_) { Error(Nil) })
        |> process.selector_receive(timeout_ms)
        |> result.flatten

      process.demonitor_process(monitor)
      answer
    }
  }
}

/// Sends to the process registered under `name` now, if there is one.
fn send_named(name: Name(message), message: message) -> Delivery {
  // Sending to an unregistered name would crash the sender, so look first.
  case process.named(name) {
    Ok(_) -> {
      process.send(process.named_subject(name), message)
      Delivered
    }

    Error(Nil) -> NoRecipient
  }
}
