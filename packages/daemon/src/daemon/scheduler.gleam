//// The delivery scheduler: sends committed outbox rows to mailboxes and
//// records what happened (spec §8.2).
////
//// The scheduler is the other half of "no send before commit". It never
//// receives bytes from a transition; it asks the engine for the outbox rows
//// the store has committed and are due, and sends exactly those bytes. A
//// retry resends the same padded ciphertext under the same envelope
//// identifier, so the mailbox answers the original receipt (spec §6.4) and
//// no second encryption ever happens because a response was lost.
////
//// ## How work moves
////
//// A `Nudge` (the engine committed an outbox row), the startup tick and a
//// periodic `Tick` all run `dispatch`: read the due rows, skip any already
//// being sent, and start one short-lived task per row. The task does the
//// network call and reports `Finished`; the scheduler itself never blocks on
//// the network, so a slow mailbox cannot stop it from seeing new rows. Tasks
//// are linked to the scheduler, so a restart of the scheduler takes its
//// in-flight sends with it and the committed rows are read again.
////
//// ## Outcomes
////
//// `classify` is the policy, a pure function of the mailbox's answer. A
//// receipt marks the row stored. A refusal a retry cannot change (`Conflict`,
//// `Unauthorized`, `BadDeadline`, `TooLarge`, `Malformed`,
//// `UnsupportedVersion`) marks it failed. Everything else, a transport
//// error, `QuotaExceeded` and `Unavailable` included, is retried with
//// exponential backoff, capped. A row past its deadline is failed without a
//// send, because the mailbox would refuse it anyway.
////
//// ## Flow
////
//// 1. `start` arms the first `Tick`.
//// 2. `dispatch` reads due rows and calls `begin_send` for each.
//// 3. `send_row` runs in a task and ends with `classify`.
//// 4. `finish` records the outcome through the engine and dispatches again.

import core/envelope
import core/id
import core/mailbox/protocol
import core/time
import daemon/engine
import daemon/log
import daemon/mail
import daemon/mailbox_client
import daemon/status
import daemon/store
import daemon/transport.{type Dialer}
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/list
import gleam/otp/actor
import gleam/otp/supervision

/// Milliseconds between periodic dispatches. A retry that comes due is sent
/// within this long; an ordinary send is nudged and does not wait for it.
pub const tick_ms = 1000

/// The most sends in flight at once.
pub const max_in_flight = 8

/// The first retry waits this many seconds; each later one doubles it.
pub const backoff_base_seconds = 2

/// No retry waits longer than this many seconds.
pub const backoff_cap_seconds = 300

/// The budget for one append, dial included. Tor needs minutes for a first
/// connection to an onion service.
pub const append_timeout_ms = 120_000

/// What the scheduler needs to run.
pub type Config {
  Config(
    /// How to reach mailboxes.
    dialer: Dialer,
    /// The writer whose committed rows are sent.
    engine: Name(engine.Message),
    /// Told whether the mailbox answered.
    status: Name(status.Message),
    /// The current time.
    clock: fn() -> time.Instant,
    /// SHA-256, to check a receipt against the bytes sent.
    sha256: fn(BitArray) -> BitArray,
  )
}

/// What one send attempt decided.
pub type Verdict {
  /// The mailbox stored it; keep this receipt.
  Accepted(receipt: BitArray)

  /// A retry will not help.
  Refused

  /// Try again after backoff.
  Transient
}

/// The scheduler's mailbox protocol.
pub opaque type Message {
  Nudge
  Tick
  Finished(row: store.OutboxRow, verdict: Verdict)
}

type State {
  State(config: Config, self: Subject(Message), in_flight: Dict(BitArray, Nil))
}

/// Starts the scheduler under `name` and arms its first tick, so rows left
/// committed by an earlier run are sent without waiting for a nudge.
///
/// ## Examples
///
/// ```gleam
/// scheduler.start(name, config)
/// // -> Ok(started)
/// ```
pub fn start(
  name: Name(Message),
  config: Config,
) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    process.send(subject, Tick)

    actor.initialised(State(config:, self: subject, in_flight: dict.new()))
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.start
}

/// The scheduler as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// scheduler.supervised(name, config)
/// ```
pub fn supervised(
  name: Name(Message),
  config: Config,
) -> supervision.ChildSpecification(Subject(Message)) {
  supervision.worker(fn() { start(name, config) })
}

/// Tells the scheduler a row was committed. Safe to lose: the periodic tick
/// finds the row anyway.
///
/// ## Examples
///
/// ```gleam
/// scheduler.nudge(name)
/// // -> Nil
/// ```
pub fn nudge(name: Name(Message)) -> Nil {
  mail.tell(name, Nudge)
}

/// How many seconds to wait before the retry that follows `attempts` failed
/// sends: the base doubled per failure, never more than the cap.
///
/// ## Examples
///
/// ```gleam
/// assert scheduler.backoff_seconds(1) == 2
/// assert scheduler.backoff_seconds(3) == 8
/// assert scheduler.backoff_seconds(40) == 300
/// ```
pub fn backoff_seconds(attempts: Int) -> Int {
  // Past this many doublings the cap has long applied; stopping here keeps
  // the exponent small instead of growing a number nobody reads.
  let doublings = int.clamp(attempts - 1, 0, 16)
  let seconds = backoff_base_seconds * int.bitwise_shift_left(1, doublings)

  int.min(seconds, backoff_cap_seconds)
}

/// The policy for one attempt, from the mailbox's answer to the bytes sent.
/// A receipt must name the envelope and the digest of exactly the bytes sent;
/// one that does not means the mailbox holds something else and is a refusal.
///
/// ## Examples
///
/// ```gleam
/// scheduler.classify(sha256, row, Ok(protocol.Refused(protocol.Conflict)))
/// // -> Refused
/// ```
pub fn classify(
  sha256: fn(BitArray) -> BitArray,
  row: store.OutboxRow,
  answer: Result(protocol.Response, mailbox_client.ClientError),
) -> Verdict {
  // The mailbox's own words decide, and a transport error says nothing
  // about the envelope.
  case answer {
    Ok(protocol.Appended(receipt:)) -> check_receipt(sha256, row, receipt)

    Ok(protocol.Refused(reason:)) -> classify_refusal(reason)

    Ok(protocol.QueueCreated(_))
    | Ok(protocol.Batch(_))
    | Ok(protocol.Acked)
    | Ok(protocol.QueueDeleted) -> Transient

    Error(_) -> Transient
  }
}

/// Checks a receipt against the row it answers.
fn check_receipt(
  sha256: fn(BitArray) -> BitArray,
  row: store.OutboxRow,
  receipt: protocol.AppendReceipt,
) -> Verdict {
  let sent = sha256(envelope.to_wire(row.padded))

  // A receipt that names the envelope and the digest of the bytes sent is evidence of storage; any other is a refusal.
  case receipt.envelope == row.envelope && receipt.digest == sent {
    True -> Accepted(store.receipt_bytes(receipt))
    False -> Refused
  }
}

/// Whether a refusal can change on a retry.
fn classify_refusal(reason: protocol.Refusal) -> Verdict {
  case reason {
    protocol.Conflict
    | protocol.Unauthorized
    | protocol.BadDeadline
    | protocol.TooLarge
    | protocol.Malformed
    | protocol.UnsupportedVersion -> Refused

    protocol.QuotaExceeded | protocol.Unavailable -> Transient
  }
}

/// Runs one message.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // A nudge or a tick dispatches; a finished send is recorded.
  case message {
    Nudge -> dispatch(state)

    Tick -> {
      // The tick re-arms itself before dispatching, so a slow dispatch
      // cannot stop the next one from being scheduled.
      process.send_after(state.self, tick_ms, Tick)
      dispatch(state)
    }

    Finished(row:, verdict:) -> finish(state, row, verdict)
  }
}

/// Reads the due rows and starts a send for each that is not already
/// running, up to the in-flight cap.
fn dispatch(state: State) -> actor.Next(State, Message) {
  let room = max_in_flight - dict.size(state.in_flight)

  // A full house waits for a `Finished`; an engine that does not answer is
  // asked again on the next tick.
  case room > 0, engine.due_outbox(state.config.engine, max_in_flight * 2) {
    True, Ok(rows) -> {
      let fresh =
        list.filter(rows, fn(row) {
          !dict.has_key(state.in_flight, id.to_bytes(row.envelope))
        })

      actor.continue(list.fold(list.take(fresh, room), state, begin_send))
    }

    True, Error(_) | False, _ -> actor.continue(state)
  }
}

/// Starts the send of one row: an expired row fails at once, any other runs
/// in a linked task that reports back.
fn begin_send(state: State, row: store.OutboxRow) -> State {
  let expired = time.is_past(state.config.clock(), row.deadline)

  // A row past its deadline is not worth a connection.
  case expired {
    True -> {
      process.send(state.self, Finished(row:, verdict: Refused))
      track(state, row)
    }

    False -> {
      let config = state.config
      let self = state.self

      process.spawn(fn() {
        process.send(self, Finished(row:, verdict: send_row(config, row)))
      })

      track(state, row)
    }
  }
}

/// Remembers that a row is being sent.
fn track(state: State, row: store.OutboxRow) -> State {
  State(
    ..state,
    in_flight: dict.insert(state.in_flight, id.to_bytes(row.envelope), Nil),
  )
}

/// The network half, run in a task: one append of the committed bytes.
fn send_row(config: Config, row: store.OutboxRow) -> Verdict {
  let request =
    protocol.Append(
      queue: row.route.queue,
      append: row.route.append,
      envelope: row.envelope,
      retention_deadline: row.deadline,
      ciphertext: row.padded,
    )

  let answer =
    mailbox_client.call(
      config.dialer,
      row.route.endpoint,
      mailbox_client.isolation_group(row.route.queue),
      request,
      append_timeout_ms,
    )

  report_reachability(config, answer)
  classify(config.sha256, row, answer)
}

/// Tells the status cell whether the mailbox answered at all.
fn report_reachability(
  config: Config,
  answer: Result(protocol.Response, mailbox_client.ClientError),
) -> Nil {
  case answer {
    Ok(_) -> status.set_mailbox(config.status, status.MailboxReachable)
    Error(_) -> status.set_mailbox(config.status, status.MailboxUnreachable)
  }
}

/// Records a finished send and looks for more work.
fn finish(
  state: State,
  row: store.OutboxRow,
  verdict: Verdict,
) -> actor.Next(State, Message) {
  // The engine's recording of the outcome decides only whether to log; the send is repeated either way if it was not recorded.
  let outcome = case verdict {
    Accepted(receipt:) -> store.Stored(receipt)
    Refused -> store.Rejected

    Transient -> {
      let attempts = row.attempts + 1
      let wait = backoff_seconds(attempts)

      store.Retry(
        attempts:,
        next_attempt_at: time.add(state.config.clock(), wait),
      )
    }
  }

  // An engine that cannot record leaves the row `queued` and due, so the
  // send is simply repeated; the mailbox answers the same receipt.
  case engine.record_send(state.config.engine, row.envelope, outcome) {
    Ok(Nil) -> Nil
    Error(_) -> log.line("scheduler", "could not record a send outcome")
  }

  let next =
    State(..state, in_flight: dict.delete(state.in_flight, envelope_key(row)))

  dispatch(next)
}

fn envelope_key(row: store.OutboxRow) -> BitArray {
  id.to_bytes(row.envelope)
}
