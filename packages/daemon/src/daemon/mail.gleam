//// Messages to named actors that fail soft.
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
//// ## Why this is not `weft/registry`
////
//// `weft/registry` is the primitive for exactly this problem: an
//// `Address(message)` that resolves to the current incarnation, with a
//// dead recipient's binding removed. It does not fit here yet, for two
//// reasons. First, the addresses are `process.Name` values that cross
//// package-internal signatures (`engine.Message`'s name is held by `api`,
//// `node`, the scheduler and the fetchers, and `node` builds them once for a
//// `static_supervisor` tree), so moving to addresses changes every worker's
//// handle at once, and the registry itself would become one more process
//// that the tree must start first. Second, a registry `send` answers whether
//// the binding existed, but a reply that never comes is still a bare
//// `process.receive` timeout in the caller. What `ask` needs is a
//// monitored, non-panicking call against a pre-existing pid: one that
//// returns early when the recipient dies mid-call instead of waiting out the
//// timeout. weft does not provide that call, so this module is the known
//// gap, and the check-then-send below is the best a named process allows.
////
//// A reply that arrives after its caller stopped waiting is left in that
//// caller's mailbox. Actors select only their own subjects, so it is never
//// read and is released with the process.

import gleam/erlang/process.{type Name, type Subject}
import gleam/result

/// Sends `message` to the process registered under `name`, if there is one.
///
/// ## Examples
///
/// ```gleam
/// mail.tell(scheduler_name, scheduler.Nudge)
/// // -> Nil
/// ```
pub fn tell(name: Name(message), message: message) -> Nil {
  // A name with no process is a peer that is restarting; its replacement
  // starts from committed state and does not need this message.
  case process.named(name) {
    Ok(_) -> process.send(process.named_subject(name), message)
    Error(Nil) -> Nil
  }
}

/// Sends a request to `name` and waits up to `timeout_ms` for its reply.
/// `Error(Nil)` when the process is not running or does not answer in time.
///
/// ## Examples
///
/// ```gleam
/// mail.ask(status_name, 1000, status.Read)
/// // -> Ok(snapshot)
/// ```
pub fn ask(
  name: Name(message),
  timeout_ms: Int,
  make: fn(Subject(reply)) -> message,
) -> Result(reply, Nil) {
  use _ <- result.try(process.named(name))

  let reply_with = process.new_subject()
  process.send(process.named_subject(name), make(reply_with))
  process.receive(reply_with, timeout_ms)
}
