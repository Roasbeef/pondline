//// A seeded pseudo-random generator, SplitMix64, as a plain value.
////
//// The runner threads one `Rng` through a run and the swarm threads one
//// through a campaign, so every choice is a pure function of the seed and
//// of how many choices came before it. Nothing here touches the VM's own
//// generator, whose state is shared with everything else in the node.

import gleam/int

const mask = 0xFFFFFFFFFFFFFFFF

/// The generator's state.
pub opaque type Rng {
  Rng(state: Int)
}

/// A generator seeded with `seed`.
///
/// ## Examples
///
/// ```gleam
/// rng.new(1)
/// ```
pub fn new(seed: Int) -> Rng {
  Rng(state: int.bitwise_and(seed, mask))
}

/// The next 64-bit value and the advanced generator.
///
/// ## Examples
///
/// ```gleam
/// let #(value, next) = rng.next(rng.new(1))
/// ```
pub fn next(rng: Rng) -> #(Int, Rng) {
  let state = int.bitwise_and(rng.state + 0x9E3779B97F4A7C15, mask)
  let z = state
  let z =
    int.bitwise_and(
      int.bitwise_exclusive_or(z, int.bitwise_shift_right(z, 30))
        * 0xBF58476D1CE4E5B9,
      mask,
    )
  let z =
    int.bitwise_and(
      int.bitwise_exclusive_or(z, int.bitwise_shift_right(z, 27))
        * 0x94D049BB133111EB,
      mask,
    )

  #(int.bitwise_exclusive_or(z, int.bitwise_shift_right(z, 31)), Rng(state:))
}

/// A value in `[0, bound)`; `0` when `bound` is not positive.
///
/// ## Examples
///
/// ```gleam
/// let #(index, next) = rng.below(rng.new(1), 10)
/// ```
pub fn below(rng: Rng, bound: Int) -> #(Int, Rng) {
  let #(value, rest) = next(rng)

  // A non-positive bound has only the one answer.
  case bound > 0 {
    True -> #(value % bound, rest)
    False -> #(0, rest)
  }
}

/// `count` pseudo-random bytes.
///
/// ## Examples
///
/// ```gleam
/// let #(bytes, next) = rng.bytes(rng.new(1), 16)
/// ```
pub fn bytes(rng: Rng, count: Int) -> #(BitArray, Rng) {
  fill(rng, count, <<>>)
}

/// Appends one byte at a time until `count` remain.
fn fill(rng: Rng, count: Int, acc: BitArray) -> #(BitArray, Rng) {
  // Zero remaining is the whole array.
  case count <= 0 {
    True -> #(acc, rng)

    False -> {
      let #(value, rest) = next(rng)
      fill(rest, count - 1, <<acc:bits, value:size(8)>>)
    }
  }
}
