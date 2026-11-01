//// The deterministic simulation of the real shell: the entry points the
//// tests and campaigns share.
////
//// `sim/runner` plays one seed through two real daemon trees and a real
//// mailbox tree; this module adds the determinism check (every seed run
//// twice, snapshots compared whole) and the corpus.
////
//// ## Flow
////
//// 1. `double_run` runs a seed twice through `runner.run` and compares the
////    snapshots with `first_difference`.
//// 2. `corpus` is the fixed seeds every test run replays twice, and
////    `regressions` the seeds that once failed.

import gleam/int
import gleam/list
import sim/runner.{type Report}
import sim/seed

/// What a double run found.
pub type Replayed {
  /// Both runs produced the same snapshot; the report of the first.
  Same(report: Report)

  /// The snapshots differ at `index`: the first run's line, then the
  /// second's.
  Diverged(index: Int, first: String, second: String)
}

/// Runs a seed twice and compares everything the runs left behind.
///
/// ## Examples
///
/// ```gleam
/// sim.double_run(<<0, 0, 0, 3, 0>>)
/// // -> Same(report)
/// ```
pub fn double_run(bytes: BitArray) -> Replayed {
  let options = runner.Options(verbose: runner.Quiet)
  let first = runner.run(bytes, options)
  let second = runner.run(bytes, options)

  // Equal snapshots are the whole claim; the first difference is the
  // place to start looking when they are not.
  case first.snapshot == second.snapshot {
    True -> Same(first)
    False -> first_difference(first.snapshot, second.snapshot, 0)
  }
}

/// The first line at which two snapshots differ.
fn first_difference(
  first: List(String),
  second: List(String),
  index: Int,
) -> Replayed {
  // A list that ends first differs at its end.
  case first, second {
    [x, ..xs], [y, ..ys] if x == y -> first_difference(xs, ys, index + 1)
    [x, ..], [y, ..] -> Diverged(index:, first: x, second: y)
    [x, ..], [] -> Diverged(index:, first: x, second: "<end>")
    [], [y, ..] -> Diverged(index:, first: "<end>", second: y)
    [], [] -> Diverged(index:, first: "<end>", second: "<end>")
  }
}

/// A one-line summary of a report: steps, virtual time, findings.
///
/// ## Examples
///
/// ```gleam
/// sim.summary(report)
/// // -> "812 events, 61000 ms, 0 violations, 0 excuses"
/// ```
pub fn summary(report: Report) -> String {
  int.to_string(report.steps)
  <> " events, "
  <> int.to_string(report.virtual_ms)
  <> " ms, "
  <> int.to_string(list.length(report.violations))
  <> " violations, "
  <> int.to_string(list.length(report.excuses))
  <> " excuses"
}

/// The fixed corpus, as hex: one honest pairing in each direction, then a
/// fault of one class at a time (the mask bit on, one or two armings, a
/// send behind each, time to recover). Every seed must pass with only the
/// excuses its class allows, and replay exactly.
///
/// ## Examples
///
/// ```gleam
/// list.length(sim.corpus())
/// // -> 17
/// ```
pub fn corpus() -> List(String) {
  [
    // honest, automatic approval.
    "0000000300085004010850000000010850020102000850",
    // honest, operator approval.
    "010000030008500401085005000850000000010850020102000850",
    // small budget: held, then raised.
    "020000030008500401085000000001085002010200085001100850070108500201",
    // daemon store: ack lost, then down.
    "00010003000850040108500000000108500201020008500a00000008500a0300000850000008c0",
    // mailbox store: ack lost, then down.
    "00020003000850040108500000000108500201020008500a02000008500a0500000850000008c0",
    // engine: send, record_send and process apply then fail.
    "00040003000850040108500000000108500201020008500b20000008500b4c000008500b2c000108c0",
    // network: a dropped request and a lost response.
    "00080003000850040108500000000108500201020008500c00000008500c02000008c0",
    // network delay.
    "00100003000850040108500000000108500201020008500110011108c0",
    // mailbox down, then up.
    "00200003000850040108500000000108500201020008500d00000008900d0008c0",
    // byzantine mailbox: truncated, corrupt, unauthorized.
    "00400003000850040108500000000108500201020008500e00000008500e03000108500e06000008c0",
    // small skews that stay within the deadline.
    "00800003000850040108500000000108500201020008500f020f0c0000000108c0",
    // byzantine peer: stray controls and garbage.
    "0000010300085004010850000000010850020102000850100210051006000008c0",
    // operator inputs at and past the limits.
    "000002030008500401085000000001085002010200085011001102110c110e111208c0",
    // daemon restarts.
    "0000040300085004010850000000010850020102000850120000001201000108c0",
    // kills: engine, coordinator, notifier.
    "000008030008500401085000000001085002010200085013000000130800010850130a08c0",
    // H1, fixed by ADR-008: daemon A's clock leads the mailbox by five
    // seconds. Its default deadline (now + retention) was refused as
    // BadDeadline and the row failed for good; the slack below the
    // mailbox's maximum now covers it.
    "00800003000850040108500000000108500201020008500f03000008c0",
    // H2, fixed by ADR-010: A, as an authenticated byzantine peer, repeats
    // a message id it already sent. B's commit failed on UNIQUE (contact,
    // message_id), the envelope was never acknowledged and every later one
    // on that queue waited behind it; the core now ignores the repeat and
    // records it as an incident.
    "00000103000850040108500000000108500201020008501000000008c0",
  ]
}

/// Seeds that found a production bug, with the check each must keep
/// failing until the fix lands (the plan makes the fixes after the harness
/// finds them blind, so the recall table can count them). Each is minimal:
/// the honest corpus pairing, one fault, one send. A fixed bug's seed moves
/// to `corpus`, where it must pass.
///
/// ## Examples
///
/// ```gleam
/// sim.regressions()
/// // -> []
/// ```
pub fn regressions() -> List(#(String, String)) {
  []
}

/// The corpus decoded, skipping anything that is not hex.
///
/// ## Examples
///
/// ```gleam
/// sim.corpus_seeds()
/// ```
pub fn corpus_seeds() -> List(BitArray) {
  list.filter_map(corpus(), seed.from_hex)
}
