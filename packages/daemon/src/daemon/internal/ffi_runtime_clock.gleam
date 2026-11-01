//// The wall clock, read once per call.
////
//// The pure `core` has no clock and every instant reaches it as an
//// argument. The daemon shell is where the real one is read, because the
//// protocol's deadlines (a message's `expires_at`, an invitation's
//// acceptance window, a mailbox retention deadline) are all in wall-clock
//// seconds that two machines must agree on. A monotonic clock would be
//// wrong here, and `daemon/internal/ffi_clock` is kept for call deadlines
//// where it is exactly right.

import gleam/erlang/atom.{type Atom}

// Foreign function: `erlang:system_time/1`. `gleam_erlang` exposes no wall
// clock, and the BIF is stock OTP; the unit is an atom, which is built once
// per call from a fixed name rather than from any input.
@external(erlang, "erlang", "system_time")
fn system_time(unit: Atom) -> Int

/// Whole seconds since the Unix epoch.
///
/// ## Examples
///
/// ```gleam
/// ffi_runtime_clock.unix_seconds() > 1_700_000_000
/// // -> True
/// ```
pub fn unix_seconds() -> Int {
  system_time(atom.create("second"))
}
