//// Messages to named actors that fail soft, through a handle that a
//// simulation can intercept.
////
//// Every long-lived process in the daemon is addressed by a `Name`, so a
//// restarted process is found again without anyone handing its replacement's
//// address around. The cost is that a name may briefly have no process, and
//// `process.send` to an unregistered name crashes the sender. A sender that
//// crashes because its peer is restarting would turn one restart into a
//// cascade, so these two functions check the name first: `tell` does
//// nothing when nobody is listening, and `ask` answers `Error(Nil)` when
//// nobody is or when the reply does not arrive in time. A caller treats that
//// as "unavailable" and retries; every operation behind these calls is
//// idempotent or reads committed state.
////
//// ## Handles, and the interception seam
////
//// Callers hold a `Handle`, not a bare `Name`. A handle built by `direct`, or
//// by `address` without an interceptor, is the name and nothing else: `tell`
//// and `ask` send straight to the process, with no extra process hop, exactly
//// as a bare name would. That is the production path, and the only one a
//// production `Config` can build.
////
//// A deterministic simulation needs more. Two actors that both send to the
//// engine in one step race to its mailbox, and the BEAM picks the winner, so
//// a seed would not replay. A handle built with an `Interceptor` therefore
//// does not send. It wraps the send in a `Parcel` and hands it to the
//// interceptor, which the simulation's runner owns: the runner parks every
//// parcel, and releases them one at a time in an order its seed chooses by
//// calling each parcel's `deliver`. A parcel says who sent it (`from`, the
//// holder's role, such as `"scheduler"` or `"fetcher/<queue hex>"`), who it
//// is for (`to`, the target's role) and what it is (`label`, a fixed word
//// per message kind, such as the engine job's kind), so the runner can sort
//// a step's parcels by a key that does not depend on which process the BEAM
//// happened to run first. None of the three is a value from the message.
////
//// Two consequences of interception that the default path does not have:
////
//// - The name is looked up when the parcel is delivered, not when it is
////   made, because the runner may release it after the target has died. A
////   parcel whose target is gone is dropped, as a `tell` to a missing name is
////   today, and `deliver` says so with `NoRecipient`.
//// - An intercepted `ask` monitors the target it found, so a target that dies
////   before the runner releases the parcel answers `Error(Nil)` at once
////   instead of after the whole timeout on the wall clock. The default path
////   keeps today's plain wait.
////
//// What is not intercepted, and so still reaches its process directly: the
//// reply to an `ask` (its caller is blocked on it alone), a process's sends
//// to itself, weft's own timer and run messages (timeouts, `continuing`,
//// task outcomes relayed to a run's subject), the event registry's fan-out
//// to subscriber subjects, the Tor sidecar's port events, exits and monitor
//// messages, and the network, which has its own seam in the `Dialer`.
////
//// Parcels from one sender process reach the interceptor in program order.
//// A local send on the BEAM is enqueued before the sender's next
//// instruction, so a runner that releases one sender's parcels out of that
//// order builds a schedule production cannot have; the mailbox long poll's
//// "register, then look" depends on it.
////
//// ## Why this is not `weft/registry`
////
//// `weft/registry` is the primitive for the restart problem: an
//// `Address(message)` that resolves to the current incarnation, with a
//// dead recipient's binding removed. It does not fit here yet, for two
//// reasons. First, the addresses are `process.Name` values that `node`
//// builds once for a `static_supervisor` tree, and the registry itself would
//// become one more process that the tree must start first. Second, a
//// registry `send` answers whether the binding existed, but a reply that
//// never comes is still a bare `process.receive` timeout in the caller. What
//// `ask` needs is a monitored, non-panicking call against a pre-existing pid:
//// one that returns early when the recipient dies mid-call instead of waiting
//// out the timeout. weft does not provide that call, so this module is the
//// known gap, and the check-then-send below is the best a named process
//// allows.
////
//// A reply that arrives after its caller stopped waiting is left in that
//// caller's mailbox. Actors select only their own subjects, so it is never
//// read and is released with the process.

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
    /// The role of the process that sent it, as its handle was labelled.
    from: String,
    /// The role of the process it is for.
    to: String,
    /// What kind of message it is: a fixed word per kind, never a value.
    label: String,
    /// Sends the message to the named process if one is registered now.
    deliver: fn() -> Delivery,
  )
}

/// What a parcel's `deliver` found.
pub type Delivery {
  /// The message is in the named process's mailbox.
  Delivered

  /// No process held the name, so the message was dropped.
  NoRecipient
}

/// What an intercepted handle hands its parcels to. `park` is called in the
/// sender's own process and must return promptly; it must not call
/// `deliver` itself on that process's behalf in the same breath unless it
/// means to send at once.
pub type Interceptor {
  Interceptor(park: fn(Parcel) -> Nil)
}

/// A handle that sends straight to `name`.
///
/// ## Examples
///
/// ```gleam
/// mail.direct(process.new_name("status"))
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
/// mail.address(names.engine, None, from: "scheduler", to: "engine")
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

/// The same handle, held by `holder`. A direct handle is unchanged.
///
/// ## Examples
///
/// ```gleam
/// mail.from(engine, "fetcher/0a1b")
/// ```
pub fn from(handle: Handle(message), holder: String) -> Handle(message) {
  // Only an intercepted handle carries a sender label.
  case handle.route {
    Direct -> handle

    Intercepted(interceptor:, from: _, to:) ->
      Handle(..handle, route: Intercepted(interceptor:, from: holder, to:))
  }
}

/// The name a handle sends to.
///
/// ## Examples
///
/// ```gleam
/// mail.name(mail.direct(name)) == name
/// // -> True
/// ```
pub fn name(handle: Handle(message)) -> Name(message) {
  handle.name
}

/// Sends `message` to the process behind `handle`, if there is one. `label`
/// names the kind of message for an interceptor.
///
/// ## Examples
///
/// ```gleam
/// mail.tell(scheduler, "nudge", scheduler.Nudge)
/// // -> Nil
/// ```
pub fn tell(handle: Handle(message), label: String, message: message) -> Nil {
  // A direct handle sends now; an intercepted one parks the send.
  case handle.route {
    Direct -> {
      let _ = send_named(handle.name, message)
      Nil
    }

    Intercepted(interceptor:, from:, to:) ->
      interceptor.park(
        Parcel(from:, to:, label:, deliver: fn() {
          send_named(handle.name, message)
        }),
      )
  }
}

/// Sends a request to the process behind `handle` and waits up to
/// `timeout_ms` for its reply. `Error(Nil)` when the process is not running
/// or does not answer in time; through an interceptor, also when the process
/// dies before answering.
///
/// ## Examples
///
/// ```gleam
/// mail.ask(status, "read", 1000, status.Read)
/// // -> Ok(snapshot)
/// ```
pub fn ask(
  handle: Handle(message),
  label: String,
  timeout_ms: Int,
  make: fn(Subject(reply)) -> message,
) -> Result(reply, Nil) {
  use pid <- result.try(process.named(handle.name))

  let reply_with = process.new_subject()

  // A direct ask is today's send and wait; an intercepted one parks the
  // request and also watches the target, because the runner may release
  // the request after the target is gone.
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
  // A name with no process is a peer that is restarting; its replacement
  // starts from committed state and does not need this message.
  case process.named(name) {
    Ok(_) -> {
      process.send(process.named_subject(name), message)
      Delivered
    }

    Error(Nil) -> NoRecipient
  }
}
