//// Instants and durations, in whole seconds since the Unix epoch.
////
//// `core` never reads a clock (`docs/gleam-style.md` Part IV §6): every
//// instant arrives in an event, so a property test can drive time forward,
//// backward or not at all. Whole seconds are enough for every bound the
//// spec names (§11.3), and they are what crosses the wire.

import gleam/int
import gleam/order.{type Order}

/// A moment, in seconds since 1970-01-01T00:00:00Z.
pub type Instant {
  Instant(unix_seconds: Int)
}

/// The instant `seconds` after `instant`.
///
/// ## Examples
///
/// ```gleam
/// time.add(Instant(100), 5)
/// // -> Instant(105)
/// ```
pub fn add(instant: Instant, seconds: Int) -> Instant {
  Instant(unix_seconds: instant.unix_seconds + seconds)
}

/// Orders two instants.
///
/// ## Examples
///
/// ```gleam
/// time.compare(Instant(1), Instant(2))
/// // -> order.Lt
/// ```
pub fn compare(left: Instant, right: Instant) -> Order {
  int.compare(left.unix_seconds, right.unix_seconds)
}

/// Whether `instant` is strictly after `deadline`: the test every expiry
/// in the system uses, so "at the deadline" is uniformly still valid.
///
/// ## Examples
///
/// ```gleam
/// time.is_past(Instant(10), deadline: Instant(10))
/// // -> False
/// ```
pub fn is_past(instant: Instant, deadline deadline: Instant) -> Bool {
  instant.unix_seconds > deadline.unix_seconds
}
