//// The provisioner: asks the mailbox to create the queues the daemon has
//// already decided on (spec §3.2, §4.4).
////
//// A queue's identifier and all three capabilities are chosen by the daemon
//// and committed before any network call (`core/route.new_inbox`), which is
//// what makes creation idempotent without a server-side allocation: the same
//// `CreateQueue` twice is the same queue, so the provisioner can retry
//// blindly and a crash between "created" and "recorded" costs one repeated
//// request. The commit that follows success, `engine.provisioned`, is what
//// opens an offer for export or starts a joiner's session, so neither can
//// happen before the queue exists.
////
//// ## How work moves
////
//// A `Nudge` (the engine committed a `CreateQueue` effect), the startup tick
//// and a periodic `Tick` all run `provision`: ask the engine for inboxes
//// still waiting, create each at its own mailbox and report it. The scan on
//// startup and every tick is the recovery path, so a lost nudge or a crash
//// loses nothing. Creation blocks this actor for the length of one call,
//// which is fine: there is no other work for it, and a nudge that arrives
//// meanwhile waits in its mailbox. A failure doubles the next tick's delay
//// up to a cap, so an unreachable mailbox is not hammered.

import core/capability.{type Capability, type Provision}
import core/mailbox/protocol
import core/route.{type Inbox}
import daemon/engine
import daemon/log
import daemon/mail
import daemon/mailbox_client
import daemon/status
import daemon/transport.{type Dialer}
import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/list
import gleam/otp/actor
import gleam/otp/supervision

/// Milliseconds between scans when nothing is failing.
pub const tick_ms = 1000

/// The longest wait between scans while creation keeps failing.
pub const backoff_cap_ms = 60_000

/// The budget for one `CreateQueue`, dial included.
pub const create_timeout_ms = 120_000

/// What the provisioner needs to run.
pub type Config {
  Config(
    /// How to reach the mailbox.
    dialer: Dialer,
    /// The writer that knows which queues are pending.
    engine: Name(engine.Message),
    /// Told whether the mailbox answered.
    status: Name(status.Message),
    /// The allowance the mailbox operator issued.
    provision: Capability(Provision),
  )
}

/// The provisioner's mailbox protocol.
pub opaque type Message {
  Nudge
  Tick
}

type State {
  State(config: Config, self: Subject(Message), failures: Int)
}

/// Starts the provisioner under `name` and arms its first scan.
///
/// ## Examples
///
/// ```gleam
/// provisioner.start(name, config)
/// // -> Ok(started)
/// ```
pub fn start(
  name: Name(Message),
  config: Config,
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    process.send(subject, Tick)

    actor.initialised(State(config:, self: subject, failures: 0))
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.start
}

/// The provisioner as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// provisioner.supervised(name, config)
/// ```
pub fn supervised(
  name: Name(Message),
  config: Config,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() { start(name, config) })
}

/// Tells the provisioner a queue is waiting. Safe to lose.
///
/// ## Examples
///
/// ```gleam
/// provisioner.nudge(name)
/// // -> Nil
/// ```
pub fn nudge(name: Name(Message)) -> Nil {
  mail.tell(name, Nudge)
}

/// The delay before the next scan after `failures` failed scans in a row.
///
/// ## Examples
///
/// ```gleam
/// assert provisioner.delay_ms(0) == 1000
/// assert provisioner.delay_ms(2) == 4000
/// assert provisioner.delay_ms(30) == 60_000
/// ```
pub fn delay_ms(failures: Int) -> Int {
  let doublings = int.clamp(failures, 0, 16)

  int.min(tick_ms * int.bitwise_shift_left(1, doublings), backoff_cap_ms)
}

/// Scans on a nudge or a tick; only a tick re-arms the next one.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // A nudge scans once; a tick scans and arms the next tick with the delay its outcome earned.
  case message {
    Nudge -> actor.continue(scan(state))

    Tick -> {
      let next = scan(state)

      // The next scan is armed after this one, with the delay its own
      // outcome earned.
      process.send_after(state.self, delay_ms(next.failures), Tick)
      actor.continue(next)
    }
  }
}

/// Creates every pending queue and counts the scan as a failure if any
/// creation did not go through.
fn scan(state: State) -> State {
  // Inboxes still waiting are created one by one; an engine that does not answer counts as a failed scan.
  case engine.pending_inboxes(state.config.engine) {
    Ok(inboxes) -> {
      let failed = list.filter(inboxes, fn(inbox) { !create(state, inbox) })

      // Inboxes still waiting are created one by one; an engine that does not answer counts as a failed scan.
      case failed {
        [] -> State(..state, failures: 0)
        [_, ..] -> State(..state, failures: state.failures + 1)
      }
    }

    Error(_) -> State(..state, failures: state.failures + 1)
  }
}

/// Creates one queue and reports it. `True` when the queue exists and the
/// engine recorded it.
fn create(state: State, inbox: Inbox) -> Bool {
  let request =
    protocol.CreateQueue(
      provision: state.config.provision,
      queue: inbox.queue,
      read: inbox.read,
      append: inbox.append,
      admin: inbox.admin,
    )

  let answer =
    mailbox_client.call(
      state.config.dialer,
      inbox.endpoint,
      mailbox_client.isolation_group(inbox.queue),
      request,
      create_timeout_ms,
    )

  // Only a created queue is reported; every other answer is retried.
  case answer {
    Ok(protocol.QueueCreated(_)) -> {
      status.set_mailbox(state.config.status, status.MailboxReachable)

      // Only a created queue is reported to the engine; every other answer is retried on a later scan.
      case engine.provisioned(state.config.engine, inbox.queue) {
        Ok(Nil) -> True
        Error(_) -> False
      }
    }

    Ok(protocol.Refused(_)) -> {
      status.set_mailbox(state.config.status, status.MailboxReachable)
      log.line("provisioner", "the mailbox refused to create a queue")
      False
    }

    Ok(protocol.Appended(_))
    | Ok(protocol.Batch(_))
    | Ok(protocol.Acked)
    | Ok(protocol.QueueDeleted) -> False

    Error(_) -> {
      status.set_mailbox(state.config.status, status.MailboxUnreachable)
      False
    }
  }
}
