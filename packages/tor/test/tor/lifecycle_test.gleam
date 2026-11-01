//// Lifecycle tests with stand-in sidecars: one that never reports ready and
//// one that exits at once. They exercise the two timeouts of the port
//// owner, the ready deadline and the restart backoff, which a real sidecar
//// never triggers on a healthy machine.

import tor
import tor/support

/// A sidecar that runs but never sends `Ready`. Only the ready deadline can
/// move the machine out of `Starting`, so `start` ending in `NeverReady`
/// (rather than the caller's own timeout) shows the deadline fired, the
/// silent process was closed, and the budget ran out.
pub fn silent_sidecar_is_given_up_test() {
  let dir = support.make_scratch_dir()
  let script = dir <> "/silent.sh"
  support.write_script(script, "#!/bin/sh\ncat > /dev/null\n")

  let config =
    tor.Config(
      binary_path: script,
      state_dir: dir,
      max_restarts: 1,
      ready_timeout_ms: 300,
    )
  assert tor.start(config) == Error(tor.StartFailed(tor.NeverReady))
  support.remove_dir(dir)
}

/// A sidecar that exits at once. Each death is followed by a backoff and a
/// respawn until the budget is spent; without the backoff timer the machine
/// would stay in `Restarting` and `start` would end in the caller's timeout.
pub fn crashing_sidecar_is_given_up_test() {
  let dir = support.make_scratch_dir()
  let script = dir <> "/crash.sh"
  support.write_script(script, "#!/bin/sh\nexit 3\n")

  let config =
    tor.Config(
      binary_path: script,
      state_dir: dir,
      max_restarts: 2,
      ready_timeout_ms: 300,
    )
  assert tor.start(config) == Error(tor.StartFailed(tor.NeverReady))
  support.remove_dir(dir)
}

/// With the default budget shape (several restarts, so the backoff sum is
/// larger than the margin), a sidecar that is silent every time still ends
/// in `NeverReady`. Bounding `start`'s wait by the ready timeouts alone
/// leaves out the backoff before each respawn (200, 400 and 600 ms here), so
/// the caller gave up first with `Timeout`.
pub fn the_wait_for_ready_covers_the_restart_backoff_test() {
  let dir = support.make_scratch_dir()
  let script = dir <> "/silent.sh"
  support.write_script(script, "#!/bin/sh\ncat > /dev/null\n")

  let config =
    tor.Config(
      binary_path: script,
      state_dir: dir,
      max_restarts: 3,
      ready_timeout_ms: 1,
    )
  assert tor.start(config) == Error(tor.StartFailed(tor.NeverReady))
  support.remove_dir(dir)
}
