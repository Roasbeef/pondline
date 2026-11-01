//// A swarm campaign: random seeds from a generator seed, run until one
//// fails or the count runs out, with the throughput at the end.
////
//// ```sh
//// gleam run -m sim/swarm -- --seed 1 --runs 1000
//// gleam run -m sim/swarm -- --seed 1 --runs 1000 --keep-going
//// gleam run -m sim/swarm -- --seed 1 --runs 200 --double
//// gleam run -m sim/swarm -- --seed 1 --runs 1000 --without skew,peer
//// ```
////
//// Each seed is `3 + 2n` random bytes with `n` between 8 and `max_ops`, so
//// each enables a random subset of fault classes (swarm testing). The
//// first failure prints its run index and seed, which `sim/replay` takes.
//// `--keep-going` does not stop: it groups failures by signature (the
//// check and its detail with hex and numbers masked) and prints the first
//// seed of each, the census triage starts from. `--double` runs every seed
//// twice and counts snapshot divergences instead.
////
//// ## Flow
////
//// 1. `main` reads the flags and calls `campaign`.
//// 2. `campaign` draws each seed with `draw` and runs it.
//// 3. `signature` masks a violation down to its shape.

import argv
import gleam/dict.{type Dict}
import gleam/int
import gleam/io
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import sim
import sim/internal/ffi_vm
import sim/rng.{type Rng}
import sim/runner
import sim/seed

/// What the flags asked for.
type Plan {
  Plan(
    generator: Int,
    runs: Int,
    on_failure: OnFailure,
    runs_per_seed: Runs,
    first: Int,
    without: List(seed.FaultClass),
  )
}

/// Whether a failure ends the campaign.
type OnFailure {
  Stop
  KeepGoing
}

/// How many times each seed runs.
type Runs {
  /// Once, reporting violations.
  Once

  /// Twice, reporting a snapshot divergence before anything else.
  Twice
}

/// The entry point.
///
/// ## Examples
///
/// ```sh
/// gleam run -m sim/swarm -- --seed 1 --runs 1000
/// ```
pub fn main() -> Nil {
  let flags = argv.load().arguments
  let plan =
    Plan(
      generator: flag(flags, "--seed", 1),
      runs: flag(flags, "--runs", 100),
      on_failure: case list.contains(flags, "--keep-going") {
        True -> KeepGoing
        False -> Stop
      },
      runs_per_seed: case list.contains(flags, "--double") {
        True -> Twice
        False -> Once
      },
      first: flag(flags, "--from", 0),
      without: without(flags),
    )

  campaign(plan)
}

/// The classes named after `--without`, comma-separated.
fn without(flags: List(String)) -> List(seed.FaultClass) {
  // The flag's value is a list of class names; unknown names are ignored.
  case flags {
    ["--without", names, ..] -> {
      let wanted = string.split(names, ",")
      list.filter(seed.classes(), fn(class) {
        list.contains(wanted, seed.class_name(class))
      })
    }
    [_, ..rest] -> without(rest)
    [] -> []
  }
}

/// The integer after `name`, or `default`.
fn flag(flags: List(String), name: String, default: Int) -> Int {
  // A flag is the name followed by its value.
  case flags {
    [found, value, ..] if found == name ->
      int.parse(value) |> result.unwrap(default)
    [_, ..rest] -> flag(rest, name, default)
    [] -> default
  }
}

/// Draws the generator forward to `--from`, then runs the campaign.
fn campaign(plan: Plan) -> Nil {
  let generator =
    int.range(
      from: 0,
      to: plan.first,
      with: rng.new(plan.generator),
      run: fn(acc, _) { draw(acc).1 },
    )
  let started = ffi_vm.monotonic_us()
  let #(ran, census) =
    loop(plan, generator, plan.first, 0, Census(dict.new(), dict.new()))
  let elapsed = int.max(ffi_vm.monotonic_us() - started, 1)

  report_census(census.failures)
  dict.to_list(census.excuses)
  |> list.sort(fn(x, y) { string.compare(x.0, y.0) })
  |> list.each(fn(pair) {
    io.println("excused " <> pair.0 <> " x " <> int.to_string(pair.1))
  })
  io.println(
    int.to_string(ran)
    <> " seeds in "
    <> int.to_string(elapsed / 1000)
    <> " ms: "
    <> int.to_string(ran * 1_000_000 / elapsed)
    <> "."
    <> int.to_string(ran * 100_000_000 / elapsed % 100 |> int.absolute_value)
    <> " seeds/s",
  )
}

/// The seeds runs `from` to `from + count - 1` of generator seed
/// `generator` draw, as a campaign would run them (no class masked off).
///
/// ## Examples
///
/// ```gleam
/// swarm.seeds(1, 0, 100)
/// // -> [<<..>>, ..]
/// ```
pub fn seeds(generator: Int, from: Int, count: Int) -> List(BitArray) {
  let start =
    int.range(from: 0, to: from, with: rng.new(generator), run: fn(acc, _) {
      draw(acc).1
    })

  int.range(from: 0, to: count, with: #([], start), run: fn(acc, _) {
    let #(bytes, next) = draw(acc.1)
    #([bytes, ..acc.0], next)
  }).0
  |> list.reverse
}

/// One seed from the generator: three header bytes and up to `max_ops`
/// two-byte ops.
fn draw(generator: Rng) -> #(BitArray, Rng) {
  let #(count, generator) = rng.below(generator, seed.max_ops - 7)
  rng.bytes(generator, 3 + 2 * { count + 8 })
}

/// Runs seeds until the count is spent or, without `--keep-going`, one
/// fails. Returns how many ran and the failure census.
fn loop(
  plan: Plan,
  generator: Rng,
  index: Int,
  ran: Int,
  census: Census,
) -> #(Int, Census) {
  let #(drawn, next) = draw(generator)
  let bytes = seed.mask_off(drawn, plan.without)

  // The count ends the campaign; a failure ends it too unless told not to.
  case index >= plan.first + plan.runs {
    True -> #(ran, census)

    False -> {
      let #(found, excused) = run_one(plan, bytes)
      let census =
        Census(
          failures: tally(census.failures, found, index, bytes),
          excuses: list.fold(excused, census.excuses, fn(acc, name) {
            dict.upsert(acc, name, fn(seen) { option.unwrap(seen, 0) + 1 })
          }),
        )

      // A failure stops the campaign unless it was told to keep going.
      case found, plan.on_failure {
        [_, ..], Stop -> {
          io.println(
            "failed after "
            <> int.to_string(ran + 1)
            <> " runs: run "
            <> int.to_string(index)
            <> " seed "
            <> seed.to_hex(bytes),
          )
          list.each(found, fn(line) { io.println("  " <> line) })
          #(ran + 1, census)
        }

        _, _ -> loop(plan, next, index + 1, ran + 1, census)
      }
    }
  }
}

/// Runs one seed, once or twice, and returns its violations as lines and
/// the names of the excuses it used.
fn run_one(plan: Plan, bytes: BitArray) -> #(List(String), List(String)) {
  // A double run reports a divergence; a single run its violations.
  case plan.runs_per_seed {
    Twice ->
      case sim.double_run(bytes) {
        sim.Same(report) -> findings(report)
        sim.Diverged(index:, first:, second:) -> #(
          [
            "diverged at "
            <> int.to_string(index)
            <> ": "
            <> first
            <> " / "
            <> second,
          ],
          [],
        )
      }

    Once -> findings(runner.run(bytes, runner.Options(verbose: runner.Quiet)))
  }
}

/// A report's violations as `check: detail` lines, and its excuses' names.
fn findings(report: runner.Report) -> #(List(String), List(String)) {
  #(
    list.map(report.violations, fn(found) {
      found.check <> ": " <> found.detail
    }),
    list.map(report.excuses, fn(found) { found.name }),
  )
}

/// What a campaign has seen: each failure signature with its count and
/// first seed, and how often each excuse was applied.
type Census {
  Census(failures: Dict(String, #(Int, String)), excuses: Dict(String, Int))
}

/// Counts each failure signature, keeping the first seed that showed it.
fn tally(
  census: Dict(String, #(Int, String)),
  found: List(String),
  index: Int,
  bytes: BitArray,
) -> Dict(String, #(Int, String)) {
  let first = "run " <> int.to_string(index) <> " seed " <> seed.to_hex(bytes)

  found
  |> list.map(signature)
  |> list.unique
  |> list.fold(census, fn(acc, shape) {
    dict.upsert(acc, shape, fn(seen) {
      case seen {
        option.Some(#(count, example)) -> #(count + 1, example)
        option.None -> #(1, first)
      }
    })
  })
}

/// A violation with its values masked: hex runs and numbers become `#`.
///
/// ## Examples
///
/// ```gleam
/// signature("outbox_settled: a message 0a1b2c3d failed")
/// // -> "outbox_settled: a message # failed"
/// ```
pub fn signature(line: String) -> String {
  string.split(line, " ")
  |> list.map(fn(word) {
    // A word that is all hex digits is a value, not part of the shape.
    case word != "" && is_value(word) {
      True -> "#"
      False -> word
    }
  })
  |> string.join(" ")
}

/// Whether a word is a number or a run of hex digits.
fn is_value(word: String) -> Bool {
  let digits = string.to_graphemes("0123456789abcdef")

  string.to_graphemes(word)
  |> list.all(fn(char) { list.contains(digits, char) })
  && list.any(string.to_graphemes(word), fn(char) {
    list.contains(string.to_graphemes("0123456789"), char)
  })
}

/// Prints the failure census, most common first.
fn report_census(census: Dict(String, #(Int, String))) -> Nil {
  dict.to_list(census)
  |> list.sort(fn(x, y) { int.compare(y.1.0, x.1.0) })
  |> list.each(fn(entry) {
    io.println(
      int.to_string(entry.1.0)
      <> " x "
      <> entry.0
      <> "\n    first: "
      <> entry.1.1,
    )
  })
}
