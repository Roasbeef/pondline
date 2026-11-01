//// A monotonic millisecond clock for deadlines.
////
//// A call's deadline spans a dial, a send and several reads, so each step
//// needs to know how much of the budget is left. The pure `core` has no
//// clock (time is injected there), and this daemon-side module is where
//// the one real clock is read. A monotonic reading is used, never wall
//// time, so a clock adjustment cannot lengthen or cut a deadline.

import gleam/erlang/atom.{type Atom}

// Foreign function: `erlang:monotonic_time/1`. No Gleam package this
// package depends on exposes a monotonic clock (`gleam_erlang` has only
// sleep and timers), and the BIF is stock OTP rather than custom Erlang.
@external(erlang, "erlang", "monotonic_time")
fn monotonic_time(unit: Atom) -> Int

/// Milliseconds on the VM's monotonic clock. The origin is arbitrary, so
/// only differences between two readings mean anything.
///
/// ## Examples
///
/// ```gleam
/// let started = ffi_clock.now_milliseconds()
/// ffi_clock.now_milliseconds() >= started
/// // -> True
/// ```
pub fn now_milliseconds() -> Int {
  monotonic_time(atom.create("millisecond"))
}
