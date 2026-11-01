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
//// ## One round
////
//// 1. `ack_pending` acknowledges the committed, unacknowledged envelopes.
//// 2. A `Fetch` long-polls for up to `limits.long_poll_seconds`.
//// 3. Each envelope goes to `engine.process`. An engine that cannot commit
////    ends the round, and the unprocessed envelopes stay in the mailbox for
////    the next fetch.
////
//// A failure of any step waits an exponentially growing, capped time and
//// starts over; the mailbox's own retry semantics make every step safe to
//// repeat. The process ends by itself when its queue is no longer live
//// (the relationship closed, the offer expired), so retiring a queue needs
//// no signal.
////
//// ## Flow
////
//// 1. `run` loops through `round` until the queue is not live.
//// 2. `round` calls `ack_pending`, `fetch_batch` and `process_batch`.

import core/envelope.{type StoredEnvelope}
import core/id.{type Envelope, type Id}
import core/limits
import core/mailbox/protocol
import core/route.{type Inbox}
import daemon/engine
import daemon/mailbox_client
import daemon/status
import daemon/transport.{type Dialer}
import gleam/erlang/process.{type Name}
import gleam/int
import gleam/list
import gleam/result

/// The budget for a call that is not a long poll.
pub const call_timeout_ms = 30_000

/// The first wait after a failed round, in milliseconds.
pub const backoff_base_ms = 500

/// The longest wait after repeated failed rounds, in milliseconds.
pub const backoff_cap_ms = 30_000

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
  )
}

/// Why a round did not finish. Carries nothing: the cause is logged by the
/// worker that saw it, and the response is the same, wait and retry.
type RoundFailed {
  RoundFailed
}

/// Whether the queue this fetcher serves is still one the daemon fetches.
type Liveness {
  Live
  Retired
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

/// Fetches and processes until the queue is no longer live. Blocks the
/// calling process, which is the fetcher.
///
/// ## Examples
///
/// ```gleam
/// process.spawn(fn() { fetcher.run(config) })
/// ```
pub fn run(config: Config) -> Nil {
  loop(config, 0)
}

/// Runs rounds, waiting out failures.
fn loop(config: Config, failures: Int) -> Nil {
  // A retired queue ends the process; a live or unknowable one keeps going.
  case liveness(config) {
    Retired -> Nil

    Live ->
      case round(config) {
        Ok(Nil) -> loop(config, 0)

        Error(RoundFailed) -> {
          process.sleep(backoff_ms(failures))
          loop(config, failures + 1)
        }
      }
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

/// One round: acknowledge what is committed, fetch, process.
fn round(config: Config) -> Result(Nil, RoundFailed) {
  use _ <- result.try(ack_pending(config))
  use batch <- result.try(fetch_batch(config))

  process_batch(config, batch)
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
