//// What the daemon can say about itself: whether Tor is up and whether the
//// mailbox answered lately (spec §12.4).
////
//// The workers that talk to the network, the scheduler, the fetchers and the
//// provisioner, each learn something about reachability as a side effect of
//// their calls, and none of them owns the question. This actor is the one
//// place those observations land, so `api.health` reads one cell instead of
//// asking every worker. The observations are hints for the operator and
//// drive nothing: no worker decides anything from them, so a stale or lost
//// report costs a wrong line in a status display and nothing else.

import daemon/mail
import gleam/erlang/process.{type Name, type Subject}
import gleam/otp/actor
import gleam/otp/supervision

/// Where the Tor client stands.
pub type TorStatus {
  /// The daemon was not given a sidecar: only loopback carriers work.
  TorNotUsed

  /// The sidecar is starting or bootstrapping.
  TorStarting

  /// The client bootstrapped and onion streams can be opened.
  TorBootstrapped

  /// The sidecar could not be started or bootstrapped.
  TorUnavailable
}

/// Whether the last call to the mailbox got an answer.
pub type MailboxStatus {
  /// No call has finished yet.
  MailboxUnknown

  /// The last call reached the mailbox, whatever it answered.
  MailboxReachable

  /// The last call failed in transit.
  MailboxUnreachable
}

/// Both observations at one moment.
pub type Snapshot {
  Snapshot(
    /// The Tor client.
    tor: TorStatus,
    /// The mailbox.
    mailbox: MailboxStatus,
  )
}

/// The actor's mailbox protocol.
pub opaque type Message {
  SetTor(status: TorStatus)
  SetMailbox(status: MailboxStatus)
  Read(reply_with: Subject(Snapshot))
}

/// Starts the status cell under `name`, with Tor at `tor`.
///
/// ## Examples
///
/// ```gleam
/// status.start(name, status.TorNotUsed)
/// // -> Ok(started)
/// ```
pub fn start(
  name: Name(Message),
  tor: TorStatus,
) -> actor.StartResult(Subject(Message)) {
  actor.new(Snapshot(tor:, mailbox: MailboxUnknown))
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.start
}

/// The status cell as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// status.supervised(name, status.TorNotUsed)
/// ```
pub fn supervised(
  name: Name(Message),
  tor: TorStatus,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() { start(name, tor) })
}

/// Records the Tor client's state.
///
/// ## Examples
///
/// ```gleam
/// status.set_tor(name, status.TorBootstrapped)
/// // -> Nil
/// ```
pub fn set_tor(name: Name(Message), status: TorStatus) -> Nil {
  mail.tell(name, SetTor(status))
}

/// Records whether the last mailbox call got through.
///
/// ## Examples
///
/// ```gleam
/// status.set_mailbox(name, status.MailboxReachable)
/// // -> Nil
/// ```
pub fn set_mailbox(name: Name(Message), status: MailboxStatus) -> Nil {
  mail.tell(name, SetMailbox(status))
}

/// The current observations; unknown ones when the cell is not running.
///
/// ## Examples
///
/// ```gleam
/// status.read(name)
/// // -> Snapshot(TorNotUsed, MailboxReachable)
/// ```
pub fn read(name: Name(Message)) -> Snapshot {
  case mail.ask(name, 1000, Read) {
    Ok(snapshot) -> snapshot
    Error(Nil) -> Snapshot(tor: TorUnavailable, mailbox: MailboxUnknown)
  }
}

/// Applies one report or answers one read.
fn handle(state: Snapshot, message: Message) -> actor.Next(Snapshot, Message) {
  // A report replaces one observation; a read answers with both.
  case message {
    SetTor(status:) -> actor.continue(Snapshot(..state, tor: status))

    SetMailbox(status:) -> actor.continue(Snapshot(..state, mailbox: status))

    Read(reply_with:) -> {
      process.send(reply_with, state)
      actor.continue(state)
    }
  }
}
