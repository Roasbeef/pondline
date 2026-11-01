//// One fetcher per live inbound queue: long-polls the mailbox, hands each
//// envelope to the engine, and acknowledges only what the committed store
//// says is processed (spec §6.5, §8.3).
////
//// The fetcher is the other half of "no delete before commit". It never
//// decides what to acknowledge from what it fetched. Each round starts by
//// asking the engine for the envelopes of its queue that are committed as
//// processed and not yet acknowledged, acknowledges exactly those, and
//// records that. A batch fetched and processed in one round is therefore
//// acknowledged at the start of the next, after its commit is a row it reads
//// back. The same step is the restart path: an envelope committed before a
//// crash and never acknowledged is just another unacknowledged row, so no
//// recovery code exists beyond the loop itself.
////
//// ## A `weft/state_machine`
////
//// The fetcher is a machine with three states.
////
//// | State | What it is waiting for |
//// |---|---|
//// | `Acking` | the run that acknowledges the committed envelopes |
//// | `Polling` | the run that long-polls and hands the batch to the engine |
//// | `BackingOff` | the backoff to pass |
////
//// Each network step is a one-task `weft` run, relayed to the machine and
//// bounded by a deadline, so the machine itself never blocks on the
//// mailbox and a call that hangs is abandoned by its run instead of waited
//// for. A run's outcome arrives as a message, followed by one end marker.
//// An outcome moves the machine on; the end marker of a run the machine
//// has already left is dropped. The two runs push to two subjects, `Acked` and `Polled`, so a message names the run that spoke and each
//// state reads like the step it waits for. That is mostly for readability:
//// the runs never overlap, and a stale end marker is ignored by any arm. The
//// one thing a single subject would risk is a late `RunLost` of the finished
//// run being read as the next run's failure.
////
//// A failure of either step enters `BackingOff` and arms a state timeout of
//// `backoff_ms(failures)`. The state timeout dies with the state, and the
//// failure count lives in the machine's data and not in the state, so a
//// transition into `BackingOff` is a real state change and arms the timeout
//// once. The mailbox's own retry semantics make every step safe to repeat.
////
//// The process ends by itself when its queue is no longer live (the
//// relationship closed, the offer expired), checked at the start of each
//// round, so retiring a queue needs no signal.
////
//// ## Flow
////
//// 1. `start` builds the machine, which handles `Begin` before anything else.
//// 2. `begin_round` stops the machine if the queue is retired, otherwise
////    runs `ack_pending` and enters `Acking`.
//// 3. `acked` runs `fetch_batch` and `process_batch` and enters `Polling`.
//// 4. `polled` begins the next round, or `failed` enters `BackingOff`.

import core/envelope.{type StoredEnvelope}
import core/id.{type Envelope, type Id}
import core/limits
import core/mailbox/protocol
import core/route.{type Inbox}
import daemon/engine
import daemon/mailbox_client
import daemon/status
import daemon/transport.{type Dialer}
import gleam/erlang/process.{type Name, type Subject}
import gleam/int
import gleam/list
import gleam/otp/actor as otp_actor
import gleam/result
import weft
import weft/state_machine as sm

/// The budget for a call that is not a long poll.
pub const call_timeout_ms = 30_000

/// The first wait after a failed round, in milliseconds.
pub const backoff_base_ms = 500

/// The longest wait after repeated failed rounds, in milliseconds.
pub const backoff_cap_ms = 30_000

/// How long the acknowledging run may take. Each acknowledgement is a call
/// of at most `call_timeout_ms`, and a queue may owe several batches.
pub const ack_deadline_ms = 120_000

/// How long the polling run may take: the long poll's own wait
/// (`limits.long_poll_seconds`) and the client's margin for it, and a minute
/// to hand the batch to the engine. A poll that hangs past it is abandoned
/// and the round is retried.
pub const poll_deadline_ms = 120_000

/// What a fetcher needs to run.
pub type Config {
  Config(
    /// How to reach the mailbox.
    dialer: Dialer,
    /// The writer that processes envelopes and knows what is committed.
    engine: Name(engine.Message),
    /// Told whether the mailbox answered.
    status: Name(status.Message),
    /// The queue to read, with the capability to read it.
    inbox: Inbox,
    /// The deadline of the acknowledging run, in milliseconds.
    ack_deadline_ms: Int,
    /// The deadline of the polling run, in milliseconds.
    poll_deadline_ms: Int,
  )
}

/// Why a round did not finish. Carries nothing: the cause is logged by the
/// worker that saw it, and the response is the same, wait and retry.
type RoundFailed {
  RoundFailed
}

/// What a run of one round's step reports.
type Pulled =
  weft.Pulled(Nil, RoundFailed)

/// Whether the queue this fetcher serves is still one the daemon fetches.
type Liveness {
  Live
  Retired
}

/// Where the fetcher is in its round.
type State {
  Acking
  Polling
  BackingOff
}

/// The fetcher's events.
pub opaque type Message {
  /// Start a round: the first one, and the end of a backoff.
  Begin

  /// The acknowledging run pushed something.
  Acked(Pulled)

  /// The polling run pushed something.
  Polled(Pulled)
}

/// What the machine keeps between events. None of it is part of a state, so
/// changing it never restarts a state timeout.
type Data {
  Data(
    config: Config,
    /// Rounds that failed in a row.
    failures: Int,
    /// Where the acknowledging runs push.
    acks: Subject(Pulled),
    /// Where the polling runs push.
    polls: Subject(Pulled),
  )
}

/// The wait after `failures` failed rounds in a row.
///
/// ## Examples
///
/// ```gleam
/// assert fetcher.backoff_ms(0) == 500
/// assert fetcher.backoff_ms(3) == 4000
/// assert fetcher.backoff_ms(30) == 30_000
/// ```
pub fn backoff_ms(failures: Int) -> Int {
  let doublings = int.clamp(failures, 0, 16)

  int.min(
    backoff_base_ms * int.bitwise_shift_left(1, doublings),
    backoff_cap_ms,
  )
}

/// Starts a fetcher, linked to the caller, which fetches and processes
/// until its queue is no longer live and then exits normally.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(started) = fetcher.start(config)
/// started.pid
/// ```
pub fn start(config: Config) -> otp_actor.StartResult(Subject(Message)) {
  sm.new_with_initialiser(1000, fn(subject) {
    let acks = process.new_subject()
    let polls = process.new_subject()
    let selector =
      process.new_selector()
      |> process.select(subject)
      |> process.select_map(acks, Acked)
      |> process.select_map(polls, Polled)

    sm.initialised(Acking, Data(config:, failures: 0, acks:, polls:))
    |> sm.selecting(selector)
    |> sm.returning(subject)
    |> sm.continuing(Begin)
    |> Ok
  })
  |> sm.on_event(handle)
  |> sm.start
}

/// Handles one event. Every state and message pair is written.
fn handle(
  state: State,
  data: Data,
  message: Message,
) -> sm.Next(State, Data, Message) {
  case state, message {
    // The first round starts from `Acking` before any run exists, and a
    // backoff ends with a `Begin`.
    Acking, Begin -> begin_round(data)
    BackingOff, Begin -> begin_round(data)

    // A round is already running; only the first start and the backoff send
    // `Begin`, so this does not happen.
    Polling, Begin -> sm.keep(data)

    Acking, Acked(pulled) -> acked(data, pulled)
    Polling, Polled(pulled) -> polled(data, pulled)

    // The end marker of a run the machine has already left, or an outcome
    // pushed to the other state's subject: nothing is waiting for it.
    Polling, Acked(_) -> sm.keep(data)
    BackingOff, Acked(_) -> sm.keep(data)
    Acking, Polled(_) -> sm.keep(data)
    BackingOff, Polled(_) -> sm.keep(data)
  }
}

/// Starts a round: ends the machine if the queue is retired, otherwise
/// starts the acknowledging run.
fn begin_round(data: Data) -> sm.Next(State, Data, Message) {
  // A retired queue ends the process; a live or unknowable one keeps going.
  case liveness(data.config) {
    Retired -> sm.stop()

    Live -> {
      let config = data.config
      start_run(data.acks, config.ack_deadline_ms, fn() { ack_pending(config) })

      sm.transition(to: Acking, data:)
    }
  }
}

/// Reads what the acknowledging run pushed.
fn acked(data: Data, pulled: Pulled) -> sm.Next(State, Data, Message) {
  // The first outcome decides the step. An end marker only says the run is
  // over, and if the run was lost before it said anything the step failed.
  case pulled {
    weft.PulledOutcome(outcome:) ->
      case step_result(outcome) {
        Ok(Nil) -> begin_poll(data)
        Error(RoundFailed) -> failed(data)
      }

    weft.AllDelivered -> sm.keep(data)
    weft.NotYet -> sm.keep(data)
    weft.RunLost(reason: _) -> failed(data)
  }
}

/// Reads what the polling run pushed.
fn polled(data: Data, pulled: Pulled) -> sm.Next(State, Data, Message) {
  case pulled {
    weft.PulledOutcome(outcome:) ->
      case step_result(outcome) {
        // A round that finished starts the next at once; the long poll is
        // what paces a quiet queue.
        Ok(Nil) -> begin_round(Data(..data, failures: 0))
        Error(RoundFailed) -> failed(data)
      }

    weft.AllDelivered -> sm.keep(data)
    weft.NotYet -> sm.keep(data)
    weft.RunLost(reason: _) -> failed(data)
  }
}

/// Starts the polling run: the long poll, and the batch it returns handed to
/// the engine.
fn begin_poll(data: Data) -> sm.Next(State, Data, Message) {
  let config = data.config
  start_run(data.polls, config.poll_deadline_ms, fn() {
    use batch <- result.try(fetch_batch(config))

    process_batch(config, batch)
  })

  sm.transition(to: Polling, data:)
}

/// Waits out a failed round. The count moves in the data, the wait is the
/// state's timeout, and `Begin` ends it.
fn failed(data: Data) -> sm.Next(State, Data, Message) {
  sm.transition(to: BackingOff, data: Data(..data, failures: data.failures + 1))
  |> sm.with_state_timeout(backoff_ms(data.failures), Begin)
}

/// One step as a `weft` run of one task, bounded by `deadline_ms` and
/// relayed to `sink`. The relay is linked to the machine, so a machine that
/// dies takes the run with it.
fn start_run(
  sink: Subject(Pulled),
  deadline_ms: Int,
  work: fn() -> Result(Nil, RoundFailed),
) -> Nil {
  let _relay =
    weft.new([work])
    |> weft.deadline(deadline_ms)
    |> weft.start_relayed(sink)

  Nil
}

/// Whether a step's outcome is a finished step. Only `Completed` is; a task
/// that failed, crashed, was abandoned at the deadline or never started did
/// not do its work, and the round is repeated.
fn step_result(
  outcome: weft.Outcome(Nil, RoundFailed),
) -> Result(Nil, RoundFailed) {
  case outcome {
    weft.Completed(index: _, value: Nil) -> Ok(Nil)
    weft.Failed(index: _, error: _) -> Error(RoundFailed)
    weft.Crashed(index: _, reason: _) -> Error(RoundFailed)
    weft.Abandoned(index: _) -> Error(RoundFailed)
    weft.NeverStarted(index: _) -> Error(RoundFailed)
    weft.DrainProofLost(index: _, reason: _) -> Error(RoundFailed)
    weft.CancellationUnconfirmed(index: _) -> Error(RoundFailed)
  }
}

/// Asks the engine whether this inbox is still in the set to fetch. An
/// engine that does not answer is not evidence the queue is gone.
fn liveness(config: Config) -> Liveness {
  case engine.live_inboxes(config.engine) {
    Ok(inboxes) ->
      case list.any(inboxes, fn(inbox) { inbox.queue == config.inbox.queue }) {
        True -> Live
        False -> Retired
      }

    Error(_) -> Live
  }
}

/// Acknowledges the committed, unacknowledged envelopes of the queue, and
/// repeats until none are left. The list comes from the store and from
/// nowhere else.
fn ack_pending(config: Config) -> Result(Nil, RoundFailed) {
  use pending <- result.try(
    engine.unacked(config.engine, config.inbox.queue)
    |> result.replace_error(RoundFailed),
  )

  // Nothing committed is waiting for an acknowledgement, or there is a
  // batch to name to the mailbox.
  case pending {
    [] -> Ok(Nil)

    [_, ..] -> {
      use _ <- result.try(acknowledge(config, pending))
      ack_pending(config)
    }
  }
}

/// Names exactly these envelopes to the mailbox, then records that it
/// acknowledged them.
fn acknowledge(
  config: Config,
  envelopes: List(Id(Envelope)),
) -> Result(Nil, RoundFailed) {
  let request =
    protocol.Ack(queue: config.inbox.queue, read: config.inbox.read, envelopes:)

  use answer <- result.try(call(config, request))

  // Only `Acked` means the mailbox deleted them; anything else leaves the
  // rows unacknowledged, and the next round names them again.
  case answer {
    protocol.Acked ->
      engine.mark_acked(config.engine, config.inbox.queue, envelopes)
      |> result.replace_error(RoundFailed)

    protocol.QueueCreated(_)
    | protocol.Appended(_)
    | protocol.Batch(_)
    | protocol.QueueDeleted
    | protocol.Refused(_) -> Error(RoundFailed)
  }
}

/// Long-polls for the next envelopes.
fn fetch_batch(config: Config) -> Result(List(StoredEnvelope), RoundFailed) {
  let request =
    protocol.Fetch(
      queue: config.inbox.queue,
      read: config.inbox.read,
      wait_seconds: limits.long_poll_seconds,
      max_envelopes: limits.fetch_batch_envelopes,
    )

  use answer <- result.try(call(config, request))

  // An empty batch is an ordinary long poll that saw nothing.
  case answer {
    protocol.Batch(envelopes:) -> Ok(envelopes)

    protocol.QueueCreated(_)
    | protocol.Appended(_)
    | protocol.Acked
    | protocol.QueueDeleted
    | protocol.Refused(_) -> Error(RoundFailed)
  }
}

/// Hands each fetched envelope to the engine, in order, stopping at the
/// first the engine cannot commit.
fn process_batch(
  config: Config,
  batch: List(StoredEnvelope),
) -> Result(Nil, RoundFailed) {
  list.try_each(batch, fn(stored) {
    engine.process(
      config.engine,
      config.inbox.queue,
      stored.envelope,
      stored.ciphertext,
    )
    |> result.replace(Nil)
    |> result.replace_error(RoundFailed)
  })
}

/// One mailbox call, with the status cell told whether it got through.
fn call(
  config: Config,
  request: protocol.Request,
) -> Result(protocol.Response, RoundFailed) {
  let answer =
    mailbox_client.call(
      config.dialer,
      config.inbox.endpoint,
      mailbox_client.isolation_group(config.inbox.queue),
      request,
      call_timeout_ms,
    )

  // Any answer, a refusal included, proves the mailbox is reachable.
  case answer {
    Ok(response) -> {
      status.set_mailbox(config.status, status.MailboxReachable)
      Ok(response)
    }

    Error(_) -> {
      status.set_mailbox(config.status, status.MailboxUnreachable)
      Error(RoundFailed)
    }
  }
}
