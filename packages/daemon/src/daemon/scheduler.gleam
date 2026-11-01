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
//// being sent, and start one `weft` run for the batch. A run is bounded by
//// `max_in_flight` (its `limit`) and by `send_deadline_ms` (its `deadline`),
//// and it is relayed to the scheduler (`weft.start_relayed`), so the
//// scheduler never blocks on the network: a slow mailbox cannot stop it from
//// seeing new rows, and a send that hangs past its deadline is abandoned by
//// the run instead of waited for. The relay is linked to the scheduler, so a
//// restart of the scheduler takes its in-flight sends with it and the
//// committed rows are read again.
////
//// Every run has a subject of its own, and the scheduler's selector is
//// rebuilt from its table of running batches after each message. That is
//// what lets an outcome that carries only an index (a crash, a deadline) be
//// matched back to the row it belongs to.
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
//// The run adds the cases a send cannot report for itself. A send the run
//// crashed or abandoned at its deadline is a failed attempt and retried with
//// backoff like any other. A send the run never started (the run ended
//// first) did not happen: the row stays queued and is found again by the
//// next dispatch. The seven `weft.Outcome` variants are all written out
//// (`settlement`), so a run that gains an owner fails exhaustiveness here
//// instead of falling into a catch-all.
////
//// ## Timers
////
//// One `weft/actor` periodic tick is the rescan, armed in one place. A
//// retry's due time is committed in the outbox row, but the engine has no
//// "soonest `next_attempt_at`" query to size a single wake from, so the
//// tick polls at `tick_ms`; a retry that comes due is sent within that long.
////
//// The same tick paces a failing record. A row whose outcome the engine could
//// not record is still `queued` and due, and is held out of every dispatch
//// until the next tick (`Held`), so a store that keeps failing costs one
//// resend per period instead of a resend per message handled. Each row's
//// claim names the run that owns it, and a run's end marker releases only
//// its own claims, so a row sent again in a newer run is never started a
//// third time by an older run's marker.
////
//// ## Flow
////
//// 1. `start` builds the actor, which handles one tick before anything else
////    and then one every period.
//// 2. `dispatch` reads due rows and calls `start_batch` for the live ones.
//// 3. `send_batch` runs the batch; each task is `send_row`, ending in
////    `classify`.
//// 4. `settle` turns each outcome into a verdict, `finish` records it
////    through the engine and dispatches again.

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
import gleam/erlang/process.{type Name, type Pid, type Selector, type Subject}
import gleam/int
import gleam/list
import gleam/otp/actor as otp_actor
import gleam/otp/supervision
import weft
import weft/actor

/// Milliseconds between periodic dispatches. A retry that comes due is sent
/// within this long; an ordinary send is nudged and does not wait for it.
pub const tick_ms = 1000

/// The most sends in flight at once. It is the `limit` of every run and the
/// room `dispatch` leaves itself, so the two cannot disagree.
pub const max_in_flight = 8

/// The first retry waits this many seconds; each later one doubles it.
pub const backoff_base_seconds = 2

/// No retry waits longer than this many seconds.
pub const backoff_cap_seconds = 300

/// The budget for one append, dial included. Tor needs minutes for a first
/// connection to an onion service.
pub const append_timeout_ms = 120_000

/// How long a run may take before it abandons the sends still in it: the
/// append budget and a margin, so the client's own timeout decides first and
/// the run's deadline is the backstop for a dial that never returns.
pub const send_deadline_ms = 130_000

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
    /// The deadline of each run of sends, in milliseconds.
    send_deadline_ms: Int,
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

/// What a run of sends reports: one `Verdict` per task, pulled in
/// completion order. A task cannot fail on its own terms, so the error type
/// is empty.
pub type Sent =
  weft.Pulled(Verdict, Nil)

/// The scheduler's mailbox protocol.
pub opaque type Message {
  Nudge
  Tick
  Finished(row: store.OutboxRow, verdict: Verdict)
  Settled(batch: Batch, pulled: Sent)
}

/// One run of sends: its rows in task order, so an outcome's index names a
/// row, and the subject its relay pushes to, which names the run.
pub opaque type Batch {
  Batch(rows: List(store.OutboxRow), sink: Subject(Sent))
}

type State {
  State(
    config: Config,
    self: Subject(Message),
    in_flight: Dict(BitArray, Claim),
    batches: List(Batch),
  )
}

/// Why a row is kept out of the next dispatch, and who may release it.
///
/// A row's envelope is claimed from the moment `dispatch` chooses it until
/// something ends that claim. The claim names its owner because a row can
/// outlive the run it was first sent in: when `engine.record_send` fails the
/// row stays `queued` and due, a later dispatch sends it again in a newer
/// run, and the older run's end marker may still be on its way. That marker
/// may release only what its own run claimed, or the row would be started a
/// third time while the newer send is still going.
type Claim {
  /// Past its deadline: a `Finished(Refused)` to the scheduler itself is on
  /// the way, and it will end the claim.
  Expiring

  /// Being sent by the run that pushes to this subject.
  Sending(sink: Subject(Sent))

  /// Sent, but the outcome could not be recorded, so the row is still due.
  /// Only the next `Tick` releases it, which paces a failing record at one
  /// resend per period instead of one per message the scheduler handles.
  Held
}

/// What a run's outcome means for one row.
type Settlement {
  /// The attempt was made and ended this way.
  Attempted(Verdict)

  /// No attempt was made; the row is still queued.
  Unattempted
}

/// Starts the scheduler under `name`. The first `Tick` is handled before
/// anything else (`continuing`), so rows left committed by an earlier run
/// are sent without waiting for a nudge or for the first period.
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
) -> otp_actor.StartResult(Subject(Message)) {
  actor.start(builder(name, config))
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
  actor.supervised(builder(name, config))
}

/// The scheduler's actor: named, handling a `Tick` first, then one every
/// `tick_ms`. The period is armed here and nowhere else.
fn builder(
  name: Name(Message),
  config: Config,
) -> actor.Builder(State, Message, Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    let state =
      State(config:, self: subject, in_flight: dict.new(), batches: [])

    actor.initialised(state)
    |> actor.returning(subject)
    |> actor.continuing(Tick)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.named(name)
  |> actor.periodic(every: tick_ms, sending: Tick)
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

/// Runs one message, then listens to the runs that are still going.
fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  // A nudge or a tick dispatches; a finished send is recorded; a run's
  // outcome becomes a finished send or a release.
  let after = case message {
    Nudge -> dispatch(state)
    Tick -> dispatch(release_held(state))
    Finished(row:, verdict:) -> finish(state, row, verdict)
    Settled(batch:, pulled:) -> settle(state, batch, pulled)
  }

  actor.continue(after) |> actor.with_selector(listening(after))
}

/// What the scheduler receives: its own mailbox, and one subject per run
/// that has not yet said it is over.
fn listening(state: State) -> Selector(Message) {
  list.fold(
    state.batches,
    process.new_selector() |> process.select(state.self),
    fn(selector, batch) {
      process.select_map(selector, batch.sink, fn(pulled) {
        Settled(batch:, pulled:)
      })
    },
  )
}

/// Reads the due rows and starts a send for each that is not already
/// running, up to the in-flight cap.
fn dispatch(state: State) -> State {
  let room = max_in_flight - dict.size(state.in_flight)

  // A full house waits for a `Finished`; an engine that does not answer is
  // asked again on the next tick.
  case room > 0, engine.due_outbox(state.config.engine, max_in_flight * 2) {
    True, Ok(rows) -> {
      let chosen =
        rows
        |> list.filter(fn(row) {
          !dict.has_key(state.in_flight, id.to_bytes(row.envelope))
        })
        |> list.take(room)
      let #(expired, live) =
        list.partition(chosen, fn(row) {
          time.is_past(state.config.clock(), row.deadline)
        })

      // A row past its deadline is not worth a connection; it is failed
      // through the same path as any other verdict.
      list.each(expired, fn(row) {
        process.send(state.self, Finished(row:, verdict: Refused))
      })

      let expiring =
        list.fold(expired, state, fn(acc, row) { track(acc, row, Expiring) })

      start_batch(expiring, live)
    }

    True, Error(_) | False, _ -> state
  }
}

/// Starts one run for `rows` and records it, unless there is nothing to
/// send.
fn start_batch(state: State, rows: List(store.OutboxRow)) -> State {
  // Whether the dispatch left any live row to send.
  case rows {
    [] -> state

    [_, ..] -> {
      let sink = process.new_subject()
      let _relay = send_batch(state.config, rows, sink)
      let claimed =
        list.fold(rows, state, fn(acc, row) { track(acc, row, Sending(sink)) })

      State(..claimed, batches: [Batch(rows:, sink:), ..state.batches])
    }
  }
}

/// Runs the sends of `rows` as one `weft` run and relays each outcome to
/// `sink`, then `AllDelivered`. The run is bounded by `max_in_flight` and by
/// the config's `send_deadline_ms`: a send still going at the deadline is
/// `Abandoned`, and one that never got a slot is `NeverStarted`. Returns the
/// relay, which is linked to the caller.
///
/// ## Examples
///
/// ```gleam
/// scheduler.send_batch(config, rows, sink)
/// // -> relay, then PulledOutcome per row and AllDelivered on `sink`
/// ```
pub fn send_batch(
  config: Config,
  rows: List(store.OutboxRow),
  sink: Subject(Sent),
) -> Pid {
  rows
  |> list.map(fn(row) { fn() { Ok(send_row(config, row)) } })
  |> weft.new
  |> weft.limit(max_in_flight)
  |> weft.deadline(config.send_deadline_ms)
  |> weft.start_relayed(sink)
}

/// Remembers that a row is claimed, and by whom.
fn track(state: State, row: store.OutboxRow, claim: Claim) -> State {
  State(
    ..state,
    in_flight: dict.insert(state.in_flight, envelope_key(row), claim),
  )
}

/// Ends the claims that wait for a `Tick`.
fn release_held(state: State) -> State {
  State(
    ..state,
    in_flight: dict.filter(state.in_flight, fn(_, claim) {
      case claim {
        Held -> False
        Expiring | Sending(_) -> True
      }
    }),
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

/// Handles one thing a run pushed: an outcome for one row, or the end of the
/// run.
fn settle(state: State, batch: Batch, pulled: Sent) -> State {
  // The relay sends every outcome and then exactly one end marker, so an end
  // marker means no outcome of this run is still coming.
  case pulled {
    weft.PulledOutcome(outcome:) -> {
      let #(index, settlement) = settlement(outcome)

      // The index names the row of this run whose send ended.
      case list.drop(batch.rows, index) {
        [row, ..] -> conclude(state, row, settlement)

        // The index came from a task of this very run, so a row is always
        // there; a state that is unchanged is the safe reading of one that
        // is not.
        [] -> state
      }
    }

    weft.AllDelivered -> close(state, batch)

    // The run's scope died without an end marker, so whatever it had not
    // delivered is not coming either.
    weft.RunLost(reason: _) -> close(state, batch)

    // A relay never pushes `NotYet`; it is what a caller's own `pull` says
    // when it times out.
    weft.NotYet -> state
  }
}

/// What one outcome means: which row, and whether the attempt happened.
fn settlement(outcome: weft.Outcome(Verdict, Nil)) -> #(Int, Settlement) {
  case outcome {
    weft.Completed(index:, value:) -> #(index, Attempted(value))

    // The task cannot return an error; if it ever does, the attempt is a
    // failed one and is retried.
    weft.Failed(index:, error: _) -> #(index, Attempted(Transient))

    // A worker that died mid-send, or one the deadline abandoned, made an
    // attempt whose answer is unknown. The retry resends the same bytes.
    weft.Crashed(index:, reason: _) -> #(index, Attempted(Transient))
    weft.Abandoned(index:) -> #(index, Attempted(Transient))

    // The run ended before this send had a slot, so no attempt was made and
    // the row's retry count must not move.
    weft.NeverStarted(index:) -> #(index, Unattempted)

    // These two come from managed tasks, which this run does not have; they
    // are written out so a run that gains an owner is a compile error here.
    weft.DrainProofLost(index:, reason: _) -> #(index, Attempted(Transient))
    weft.CancellationUnconfirmed(index:) -> #(index, Attempted(Transient))
  }
}

/// Applies a settlement to its row.
fn conclude(
  state: State,
  row: store.OutboxRow,
  settlement: Settlement,
) -> State {
  case settlement {
    Attempted(verdict) -> finish(state, row, verdict)

    // The row stays queued and due, and the next dispatch picks it up.
    Unattempted ->
      dispatch(
        State(
          ..state,
          in_flight: dict.delete(state.in_flight, envelope_key(row)),
        ),
      )
  }
}

/// Forgets a run that is over, and releases the rows it still claims, which
/// are the ones that never got an outcome, so a later dispatch can send
/// them. A row that a newer run claimed since, or that is `Held`, is not
/// this run's to release.
fn close(state: State, batch: Batch) -> State {
  let kept =
    dict.filter(state.in_flight, fn(_, claim) {
      case claim {
        Sending(sink:) -> sink != batch.sink
        Expiring | Held -> True
      }
    })

  dispatch(
    State(
      ..state,
      in_flight: kept,
      batches: list.filter(state.batches, fn(other) { other.sink != batch.sink }),
    ),
  )
}

/// Records a finished send and looks for more work.
fn finish(state: State, row: store.OutboxRow, verdict: Verdict) -> State {
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
  // send is repeated; the mailbox answers the same receipt. The repeat waits
  // for the next `Tick`: dispatching at once would resend a still-due row as
  // fast as the record fails.
  let in_flight = case
    engine.record_send(state.config.engine, row.envelope, outcome)
  {
    Ok(Nil) -> dict.delete(state.in_flight, envelope_key(row))

    Error(_) -> {
      log.line("scheduler", "could not record a send outcome")
      dict.insert(state.in_flight, envelope_key(row), Held)
    }
  }

  dispatch(State(..state, in_flight:))
}

fn envelope_key(row: store.OutboxRow) -> BitArray {
  id.to_bytes(row.envelope)
}
