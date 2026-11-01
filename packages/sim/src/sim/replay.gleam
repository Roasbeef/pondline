//// Replays one seed with every event and the daemons' log lines printed,
//// then the violations and excuses it found.
////
//// ```sh
//// gleam run -m sim/replay -- <seed hex>
//// gleam run -m sim/replay -- <seed hex> --quiet   # the report only
//// ```

import argv
import gleam/int
import gleam/io
import gleam/list
import gleam/string
import sim/runner
import sim/seed

/// The entry point.
///
/// ## Examples
///
/// ```sh
/// gleam run -m sim/replay -- 00ffff0300
/// ```
pub fn main() -> Nil {
  // The seed is the first argument; `--quiet` drops the event stream.
  case argv.load().arguments {
    [hex, ..flags] ->
      case seed.from_hex(hex) {
        Ok(bytes) ->
          replay(bytes, case list.contains(flags, "--quiet") {
            True -> runner.Quiet
            False -> runner.Loud
          })
        Error(Nil) -> io.println_error("the seed is not hex")
      }

    [] -> io.println_error("usage: gleam run -m sim/replay -- <seed hex>")
  }
}

/// Runs one seed and prints its report.
fn replay(bytes: BitArray, verbose: runner.Verbosity) -> Nil {
  let script = seed.decode(bytes)
  io.println("mode " <> string.inspect(script.mode))
  io.println("faults " <> string.inspect(script.enabled))
  list.index_map(script.ops, fn(op, index) {
    io.println("op " <> int.to_string(index) <> " " <> string.inspect(op))
  })
  let report = runner.run(bytes, runner.Options(verbose:))

  io.println(
    "seed "
    <> seed.to_hex(bytes)
    <> ": "
    <> int.to_string(report.steps)
    <> " events, "
    <> int.to_string(report.virtual_ms)
    <> " virtual ms",
  )
  list.each(report.violations, fn(found) {
    io.println("VIOLATION " <> found.check <> ": " <> found.detail)
  })
  list.each(report.excuses, fn(found) {
    io.println("excused " <> found.name <> ": " <> found.detail)
  })
}
