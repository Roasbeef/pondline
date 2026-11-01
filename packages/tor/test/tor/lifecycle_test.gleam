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
