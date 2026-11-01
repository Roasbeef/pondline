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
//// A tick whose sweep fails, or finds the coordinator down, is dropped; the
//// next tick tries again. A sweeper that crashed on a transient fault would
//// only be restarted to do the same.
////
//// The clock is injected as a function, so a test can drive time.

import core/time.{type Instant}
import gleam/erlang/process.{type Name, type Subject}
import gleam/otp/actor
import gleam/otp/supervision
import mailbox/coordinator

/// What the sweeper needs to run.
pub type Config {
  Config(
    /// The coordinator to ask.
    coordinator: Name(coordinator.Message),
    /// Milliseconds between sweeps.
    period_ms: Int,
    /// The current time, read at each tick.
    clock: fn() -> Instant,
  )
}

/// The sweeper's only message, from its own timer.
pub opaque type Message {
  Tick
}

/// How long a tick waits for the coordinator before giving up on this
/// round.
const reply_timeout_ms = 30_000

/// Starts the sweeper and schedules its first tick.
///
/// ## Examples
///
/// ```gleam
/// sweeper.start(Config(coordinator_name, 60_000, clock))
/// ```
pub fn start(config: Config) -> actor.StartResult(Subject(Message)) {
  actor.new_with_initialiser(1000, fn(subject) {
    process.send_after(subject, config.period_ms, Tick)

    actor.initialised(#(config, subject))
    |> actor.returning(subject)
    |> Ok
  })
  |> actor.on_message(handle)
  |> actor.start
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
  supervision.worker(fn() { start(config) })
}

/// On each tick, asks the coordinator to sweep and schedules the next tick.
/// The next tick is scheduled whether or not this sweep succeeded.
fn handle(
  state: #(Config, Subject(Message)),
  _message: Message,
) -> actor.Next(#(Config, Subject(Message)), Message) {
  let #(config, subject) = state

  // The result is dropped on purpose: a failed or unanswered sweep is
  // retried by the next tick, and the sweep has no caller to tell.
  let _ =
    coordinator.sweep(config.coordinator, config.clock(), reply_timeout_ms)

  process.send_after(subject, config.period_ms, Tick)
  actor.continue(state)
}
