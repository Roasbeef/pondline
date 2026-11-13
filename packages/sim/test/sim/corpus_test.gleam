//// The fixed corpus and the regression seeds, each run twice: the two
//// snapshots (both daemons' and the mailbox's tables, the event trace, the
//// network trace, every op's outcome, the daemons' log lines) must be
//// identical, and the findings must be what the seed is recorded to find.

import gleam/list
import gleam/string
import sim
import sim/seed

/// Double-runs one seed and returns the first run's violations as
/// `check: detail` lines, failing the test on any divergence.
fn replayed(hex: String) -> List(String) {
  let assert Ok(bytes) = seed.from_hex(hex)

  // A divergence is a harness failure whatever the seed found.
  case sim.double_run(bytes) {
    sim.Same(report) ->
      list.map(report.violations, fn(found) {
        found.check <> ": " <> found.detail
      })

    sim.Diverged(index:, first:, second:) ->
      panic as string.join(
          ["diverged at", string.inspect(index), first, "/", second],
          " ",
        )
  }
}

fn assert_corpus_slice(offset: Int, count: Int) {
  sim.corpus()
  |> list.drop(offset)
  |> list.take(count)
  |> list.each(fn(hex) {
    let found = replayed(hex)
    assert found == []
  })
}

pub fn corpus_slice_1_replays_exactly_and_passes_test() {
  assert_corpus_slice(0, 5)
}

pub fn corpus_slice_2_replays_exactly_and_passes_test() {
  assert_corpus_slice(5, 5)
}

pub fn corpus_slice_3_replays_exactly_and_passes_test() {
  assert_corpus_slice(10, 4)
}

pub fn corpus_slice_4_replays_exactly_and_passes_test() {
  let rest = list.length(sim.corpus()) - 14
  assert rest > 0
  assert_corpus_slice(14, rest)
}

pub fn every_regression_seed_still_finds_its_bug_test() {
  list.each(sim.regressions(), fn(entry) {
    let #(hex, check) = entry
    let found = replayed(hex)
    assert list.any(found, fn(line) { string.starts_with(line, check) })
  })
}
