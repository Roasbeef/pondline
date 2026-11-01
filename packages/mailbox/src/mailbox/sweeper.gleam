//// The periodic sweeper: expiration and quota maintenance (spec §10.2).
////
//// Expired envelopes and stale tombstones are already invisible to every
//// request (`Fetch` filters by deadline and a tombstone past its deadline is
//// only dead weight), so correctness never waits on this actor. It exists to
//// give back the disk and the quota that expired envelopes still occupy, on
//// a fixed period, by asking the storage coordinator to sweep. The sweep
//// itself runs inside the coordinator, so it is serialized with every write
//// and needs no locking of its own.
////
//// The tick is `weft/actor`'s `periodic`: a fixed delay armed in one place,
//// the actor's builder, and re-armed by the loop once the handler for the
//// last tick has returned. A sweep slower than the period therefore delays
//// the next tick instead of queueing a backlog of them, and the handler no
//// longer carries a `send_after` of its own to keep in step with the
//// builder.
////
//// A tick whose sweep fails, or finds the coordinator down, is dropped; the
//// next tick tries again. A sweeper that crashed on a transient fault would
//// only be restarted to do the same.
////
//// The clock is injected as a function, so a test can drive time, and the
//// tick is armed on the config's timer source, so a simulation decides when
//// it fires.

import core/time.{type Instant}
import gleam/erlang/process.{type Subject}
import gleam/otp/supervision
import mailbox/coordinator
import mailbox/mail.{type Handle}
import weft/actor
import weft/timer

/// What the sweeper needs to run.
pub type Config {
  Config(
    /// The coordinator to ask.
    coordinator: Handle(coordinator.Message),
    /// Milliseconds between sweeps.
    period_ms: Int,
    /// The current time, read at each tick.
    clock: fn() -> Instant,
    /// Where the periodic tick is armed.
    timer: timer.Source,
  )
}

/// The sweeper's only message, from its own periodic timer.
pub opaque type Message {
  Tick
}

/// How long a tick waits for the coordinator before giving up on this
/// round.
const reply_timeout_ms = 30_000

/// Builds the sweeper. The first tick comes one period after start.
fn builder(config: Config) -> actor.Builder(Config, Message, Subject(Message)) {
  actor.new(config)
  |> actor.periodic(every: config.period_ms, sending: Tick)
  |> actor.with_timer_source(config.timer)
  |> actor.on_message(handle)
}

/// Starts the sweeper; its first tick comes one period later.
///
/// ## Examples
///
/// ```gleam
/// sweeper.start(Config(coordinator, 60_000, clock, timer.WallClock))
/// ```
pub fn start(config: Config) -> actor.StartResult(Subject(Message)) {
  builder(config) |> actor.start
}

/// The sweeper as a supervised child.
///
/// ## Examples
///
/// ```gleam
/// sweeper.supervised(config)
/// ```
pub fn supervised(
  config: Config,
) -> supervision.ChildSpecification(Subject(Message)) {
  builder(config) |> actor.supervised
}

/// On each tick, asks the coordinator to sweep. The timer re-arms itself
/// whether or not this sweep succeeded.
fn handle(config: Config, message: Message) -> actor.Next(Config, Message) {
  // The only message is the tick.
  case message {
    Tick -> {
      // The result is dropped on purpose: a failed or unanswered sweep is
      // retried by the next tick, and the sweep has no caller to tell.
      let _ =
        coordinator.sweep(config.coordinator, config.clock(), reply_timeout_ms)

      actor.continue(config)
    }
  }
}
