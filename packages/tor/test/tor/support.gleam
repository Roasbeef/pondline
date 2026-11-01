//// Shared helpers for the sidecar tests: environment, scratch
//// directories, process probes, and loopback servers.

import gleam/erlang/process
import gleam/io
import gleam/result
import tor
import weft/poll

@external(erlang, "tor_test_ffi", "write_script")
pub fn write_script(path: String, body: String) -> Nil

@external(erlang, "tor_test_ffi", "getenv")
pub fn getenv(name: String) -> Result(String, Nil)

@external(erlang, "tor_test_ffi", "make_scratch_dir")
pub fn make_scratch_dir() -> String

@external(erlang, "tor_test_ffi", "remove_dir")
pub fn remove_dir(dir: String) -> Nil

@external(erlang, "tor_test_ffi", "pid_alive")
pub fn pid_alive(pid: Int) -> Bool

@external(erlang, "tor_test_ffi", "kill_nine")
pub fn kill_nine(pid: Int) -> Nil

@external(erlang, "tor_test_ffi", "monotonic_ms")
pub fn monotonic_ms() -> Int

@external(erlang, "tor_test_ffi", "rss_kb")
pub fn rss_kb(pid: Int) -> Int

@external(erlang, "tor_test_ffi", "file_size")
pub fn file_size(path: String) -> Int

@external(erlang, "tor_test_ffi", "start_echo")
pub fn start_echo() -> Int

@external(erlang, "tor_test_ffi", "start_sink")
pub fn start_sink() -> #(Int, process.Pid)

@external(erlang, "tor_test_ffi", "drain_sink")
pub fn drain_sink(sink: process.Pid) -> Nil

/// The sidecar binary: `REEDWIRE_TOR_BIN`, or the release build in the
/// repository relative to the package directory.
pub fn binary_path() -> String {
  getenv("REEDWIRE_TOR_BIN")
  |> result.unwrap("../../native/reedwire-tor/target/release/reedwire-tor")
}

/// Whether the network spike is enabled.
pub fn network_enabled() -> Bool {
  getenv("REEDWIRE_TOR_NETWORK") == Ok("1")
}

/// Reports a skipped test on stderr, which EUnit does not discard.
pub fn skip(name: String) -> Nil {
  io.println_error("SKIP " <> name <> ": needs REEDWIRE_TOR_NETWORK=1")
}

/// Runs a body against a started sidecar with a fresh state directory,
/// and always stops the sidecar and removes the directory.
pub fn with_sidecar(body: fn(tor.Tor, String) -> a) -> a {
  let dir = make_scratch_dir()
  let assert Ok(t) = tor.start(tor.config(binary_path(), dir))
    as "start the sidecar; build it with `make sidecar`"
  let result = body(t, dir)
  tor.shutdown(t)
  remove_dir(dir)
  result
}

/// Polls until the check holds or the time is up.
pub fn wait_until(check: fn() -> Bool, timeout_ms: Int) -> Bool {
  case
    poll.until(within: timeout_ms, every: 50, attempt: fn() {
      case check() {
        True -> poll.Done(Nil)
        False -> poll.Retry
      }
    })
  {
    poll.Answered(Nil) -> True
    poll.Failed(Nil) | poll.Expired -> False
  }
}

/// Waits for an event satisfying the predicate, discarding the others.
pub fn wait_event(
  events: process.Subject(tor.Event),
  wanted: fn(tor.Event) -> Bool,
  timeout_ms: Int,
) -> Result(tor.Event, Nil) {
  // Each attempt drains whatever has arrived; `Retry` means nothing wanted
  // was in the mailbox yet.
  let drain = fn() { drain_until_wanted(events, wanted) }

  case poll.until(within: timeout_ms, every: 25, attempt: drain) {
    poll.Answered(event) -> Ok(event)
    poll.Failed(Nil) | poll.Expired -> Error(Nil)
  }
}

fn drain_until_wanted(
  events: process.Subject(tor.Event),
  wanted: fn(tor.Event) -> Bool,
) -> poll.Attempt(tor.Event, Nil) {
  case process.receive(events, 0) {
    Ok(event) ->
      case wanted(event) {
        True -> poll.Done(event)
        False -> drain_until_wanted(events, wanted)
      }
    Error(Nil) -> poll.Retry
  }
}
