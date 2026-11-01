//// Swarm seeds for the pure world: a byte string that fixes a whole run, a
//// generator that draws seeds from a number, and a runner that plays one
//// seed, heals the world and applies every audit.
////
//// ## The seed
////
//// ```text
//// byte 0       mode: bit 0 chaotic (0) or benign (1), bit 1 auto (0) or
////              operator (1) approval, bits 2-4 the inbound budget mod 5;
////              bits 5-7 are reserved and ignored, so a later mode keeps
////              the seeds that exist now
//// bytes 1..2   fault mask, little-endian: one bit per `world.Fault`
//// bytes 3..    ops, three bytes each: a step pick (uint16, big-endian) and
////              a choice byte, which thins the rare steps as in `enabled`
//// ```
////
//// A seed shorter than the three header bytes runs with every fault class
//// on. A trailing partial op is ignored, and a run stops at `max_ops`. The
//// world's own identifiers come from a seed derived from every byte, so one
//// seed replays the same run whatever else ran before it.
////
//// ## Entry points
////
//// `campaign(count, generator_seed)` plays `count` generated seeds and stops
//// at the first failure, printing the seed in hex and its run index.
//// `replay(hex)` plays one seed and prints what it saw. `swarm_test` calls
//// both with small defaults; for a long campaign, call them from a shell
//// (`packages/core/CLAUDE.md` has the command), since a test has five
//// seconds.

import core/offer
import core/world.{type World}
import gleam/bit_array
import gleam/int
import gleam/io
import gleam/list
import gleam/string

/// The most ops a seed runs.
pub const max_ops = 160

const word = 0xFFFFFFFFFFFFFFFF

/// A seed decoded: the run's configuration and its steps.
pub type Decoded {
  Decoded(
    mode: world.Mode,
    approval: offer.Approval,
    budget: Int,
    mask: Int,
    picks: List(#(Int, Int)),
    world_seed: Int,
  )
}

/// Reads a seed. Every byte string decodes, which is what lets a generator
/// draw bytes without checking them.
///
/// ## Examples
///
/// ```gleam
/// swarm.decode(<<>>).mask == world.every_fault
/// ```
pub fn decode(seed: BitArray) -> Decoded {
  case seed {
    <<header, low, high, ops:bytes>> -> {
      let mode = case int.bitwise_and(header, 1) {
        0 -> world.Chaotic
        _ -> world.Benign
      }
      let approval = case
        int.bitwise_and(int.bitwise_shift_right(header, 1), 1)
      {
        0 -> offer.AutoApprove
        _ -> offer.OperatorApproves
      }

      Decoded(
        mode:,
        approval:,
        budget: int.bitwise_shift_right(header, 2)
          |> int.bitwise_and(7)
          |> int.remainder(5)
          |> result_or_zero,
        mask: high * 256 + low,
        picks: picks(ops, max_ops),
        world_seed: fingerprint(seed, 0),
      )
    }
    _ ->
      Decoded(
        mode: world.Chaotic,
        approval: offer.AutoApprove,
        budget: 0,
        mask: world.every_fault,
        picks: [],
        world_seed: fingerprint(seed, 0),
      )
  }
}

fn result_or_zero(value: Result(Int, Nil)) -> Int {
  case value {
    Ok(number) -> number
    Error(Nil) -> 0
  }
}

fn picks(ops: BitArray, remaining: Int) -> List(#(Int, Int)) {
  case ops, remaining {
    _, 0 -> []
    <<pick:size(16), choice, rest:bytes>>, _ -> [
      #(pick, choice),
      ..picks(rest, remaining - 1)
    ]
    _, _ -> []
  }
}

/// A number that depends on every byte, for the world's identifier seed.
fn fingerprint(bytes: BitArray, accumulator: Int) -> Int {
  case bytes {
    <<byte, rest:bytes>> ->
      fingerprint(
        rest,
        int.bitwise_and(accumulator * 1_099_511_628_211 + byte + 1, word),
      )
    _ -> accumulator
  }
}

/// Plays a seed: the scripted steps with the seed's fault mask, then the
/// heal phase, then every audit.
pub fn run(seed: BitArray) -> World {
  let decoded = decode(seed)

  world.new_seeded(
    world.Correct,
    decoded.approval,
    decoded.budget,
    decoded.world_seed,
  )
  |> world.walk_with(decoded.picks, decoded.mode, decoded.mask)
  |> world.heal
  |> world.audit_all
}

/// The seed for run `index` of a campaign: the bytes of a linear
/// congruential generator started from both numbers, so the hex alone
/// reproduces it.
///
/// ## Examples
///
/// ```gleam
/// swarm.generate(7, 3) == swarm.generate(7, 3)
/// ```
pub fn generate(generator_seed: Int, index: Int) -> BitArray {
  let start =
    int.bitwise_and(
      generator_seed * 0x9E3779B97F4A7C15 + index * 0xBF58476D1CE4E5B9 + 1,
      word,
    )
  let state = advance(start)
  let ops = 40 + { state / 65_536 } % { max_ops - 39 }

  bytes(state, 3 + 3 * ops, <<>>)
}

fn advance(state: Int) -> Int {
  int.bitwise_and(
    state * 6_364_136_223_846_793_005 + 1_442_695_040_888_963_407,
    word,
  )
}

fn bytes(state: Int, count: Int, collected: BitArray) -> BitArray {
  case count <= 0 {
    True -> collected
    False -> {
      let next = advance(state)
      let byte = int.bitwise_and(int.bitwise_shift_right(next, 40), 255)

      bytes(next, count - 1, <<collected:bits, byte>>)
    }
  }
}

/// The run indices `0` up to but not including `count`.
pub fn runs(count: Int) -> List(Int) {
  int.range(from: 0, to: count, with: [], run: list.prepend)
  |> list.reverse
}

/// Runs `count` generated seeds and stops at the first that fails, printing
/// its hex and index. Panics on that failure so a test or a shell run
/// both report it.
pub fn campaign(count: Int, generator_seed: Int) -> Nil {
  runs(count)
  |> list.each(fn(index) {
    let seed = generate(generator_seed, index)
    let result = run(seed)

    case world.violations_of(result) {
      [] -> Nil
      violations -> {
        io.println(
          "swarm failure: "
          <> string.join(violations, "; ")
          <> " (generator seed "
          <> int.to_string(generator_seed)
          <> ", run "
          <> int.to_string(index)
          <> ", seed "
          <> hex(seed)
          <> ")",
        )
        panic as "a swarm seed violated an invariant or an audit"
      }
    }
  })
}

/// Plays one seed given in hex, prints its violations, excuses and events,
/// and panics if it violated anything.
pub fn replay(hex_seed: String) -> Nil {
  let assert Ok(seed) = bit_array.base16_decode(string.uppercase(hex_seed))
    as "the seed is hex"
  let result = run(seed)

  io.println("seed " <> hex_seed)
  io.println("violations: " <> string.join(world.violations_of(result), "; "))
  io.println("excuses: " <> string.join(world.excuses_of(result), "; "))
  io.println("events: " <> string.join(list.reverse(result.events), ", "))

  assert world.violations_of(result) == []
}

/// A seed as upper-case hex.
pub fn hex(seed: BitArray) -> String {
  bit_array.base16_encode(seed)
}
