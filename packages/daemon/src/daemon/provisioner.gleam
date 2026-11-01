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
////
//// ## A `weft/state_machine` with one state and a named timeout
////
//// The delay to the next scan is computed from the scan that just ended, so
//// a fixed `periodic` tick cannot express it. Named timeouts belong to
//// `weft/state_machine`, so the provisioner is one, with a single state,
//// `Watching`, and the failure count in its data. Each `Tick` scans and
//// arms the `scan` timeout again with `delay_ms(failures)`; arming a name
//// replaces what was armed under it, so there is never more than one. A
//// `Nudge` scans without touching the timeout, and the first `Tick` is
//// handled before any request (`continuing`).

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
import weft/state_machine as sm

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

/// The provisioner's only state: waiting for a nudge or the `scan` timeout.
type State {
  Watching
}

/// What the machine keeps. The failure count is data, not part of the
/// state, so a failing scan does not look like a state change.
type Data {
  Data(config: Config, failures: Int)
}

/// The name of the timeout that arms the next scan.
const scan_timeout = "scan"

/// Starts the provisioner under `name`. Its first scan runs before any
/// request, which arms the ones that follow.
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
  sm.start(builder(name, config))
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
  sm.supervised(builder(name, config))
}

/// The provisioner's machine: named, scanning first.
fn builder(
  name: Name(Message),
  config: Config,
) -> sm.Builder(State, Data, Message, Subject(Message)) {
  sm.new_with_initialiser(5000, fn(subject) {
    sm.initialised(Watching, Data(config:, failures: 0))
    |> sm.returning(subject)
    |> sm.continuing(Tick)
    |> Ok
  })
  |> sm.on_event(handle)
  |> sm.named(name)
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

/// Scans on a nudge or a tick; only a tick arms the next one.
fn handle(
  state: State,
  data: Data,
  message: Message,
) -> sm.Next(State, Data, Message) {
  // A nudge scans once; a tick scans and arms the next tick with the delay its outcome earned.
  case state, message {
    Watching, Nudge -> sm.keep(scan(data))

    Watching, Tick -> {
      let next = scan(data)

      // The next scan is armed after this one, with the delay its own
      // outcome earned. This is the only place the timeout is armed.
      sm.keep(next)
      |> sm.with_named_timeout(
        name: scan_timeout,
        after: delay_ms(next.failures),
        sending: Tick,
      )
    }
  }
}

/// Creates every pending queue and counts the scan as a failure if any
/// creation did not go through.
fn scan(data: Data) -> Data {
  // Inboxes still waiting are created one by one; an engine that does not answer counts as a failed scan.
  case engine.pending_inboxes(data.config.engine) {
    Ok(inboxes) -> {
      let failed = list.filter(inboxes, fn(inbox) { !create(data, inbox) })

      // One creation that did not go through makes the whole scan a failure.
      case failed {
        [] -> Data(..data, failures: 0)
        [_, ..] -> Data(..data, failures: data.failures + 1)
      }
    }

    Error(_) -> Data(..data, failures: data.failures + 1)
  }
}

/// Creates one queue and reports it. `True` when the queue exists and the
/// engine recorded it.
fn create(data: Data, inbox: Inbox) -> Bool {
  let request =
    protocol.CreateQueue(
      provision: data.config.provision,
      queue: inbox.queue,
      read: inbox.read,
      append: inbox.append,
      admin: inbox.admin,
    )

  let answer =
    mailbox_client.call(
      data.config.dialer,
      inbox.endpoint,
      mailbox_client.isolation_group(inbox.queue),
      request,
      create_timeout_ms,
    )

  // Only a created queue is reported; every other answer is retried.
  case answer {
    Ok(protocol.QueueCreated(_)) -> {
      status.set_mailbox(data.config.status, status.MailboxReachable)

      // Only a created queue is reported to the engine; every other answer is retried on a later scan.
      case engine.provisioned(data.config.engine, inbox.queue) {
        Ok(Nil) -> True
        Error(_) -> False
      }
    }

    Ok(protocol.Refused(_)) -> {
      status.set_mailbox(data.config.status, status.MailboxReachable)
      log.line("provisioner", "the mailbox refused to create a queue")
      False
    }

    Ok(protocol.Appended(_))
    | Ok(protocol.Batch(_))
    | Ok(protocol.Acked)
    | Ok(protocol.QueueDeleted) -> False

    Error(_) -> {
      status.set_mailbox(data.config.status, status.MailboxUnreachable)
      False
    }
  }
}
