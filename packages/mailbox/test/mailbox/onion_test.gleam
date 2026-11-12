//// The command line's Tor options, and the onion-hosting path itself.
////
//// Argument parsing is checked on every run. Hosting needs the Tor network,
//// so `run_onion` does its work only with `PONDLINE_TOR_NETWORK=1`;
//// `mailbox_slow_test.erl` calls it because EUnit's default timeout is
//// shorter than a bootstrap.

import core/time.{Instant}
import gleam/erlang/process
import gleam/io
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import mailbox.{Serve, TorHosting, TorOptions}
import mailbox/build
import mailbox/http
import mailbox/node
import mailbox/support
import weft/timer

@external(erlang, "support_ffi", "getenv")
fn getenv(name: String) -> Result(String, Nil)

@external(erlang, "support_ffi", "make_scratch_dir")
fn make_scratch_dir() -> String

@external(erlang, "support_ffi", "remove_dir")
fn remove_dir(dir: String) -> Nil

pub fn serve_without_tor_test() {
  assert mailbox.parse(["serve", "--db", "m.db"]) == Ok(Serve("m.db", 0, None))
  assert mailbox.parse(["serve", "--db", "m.db", "--port", "0"])
    == Ok(Serve("m.db", 0, None))
}

pub fn serve_with_tor_test() {
  let arguments = [
    "serve", "--db", "m.db", "--port", "8080", "--tor-bin", "./rt",
    "--tor-state", "/tmp/t",
  ]

  assert mailbox.parse(arguments)
    == Ok(Serve("m.db", 8080, Some(TorOptions(Some("./rt"), "/tmp/t"))))
}

pub fn tor_state_allows_auto_discovery_and_tor_bin_requires_state_test() {
  let binary_only = [
    "serve", "--db", "m.db", "--port", "0", "--tor-bin", "./rt",
  ]
  let state_only = ["serve", "--db", "m.db", "--tor-state", "/tmp/t"]

  assert mailbox.parse(binary_only) == Error("--tor-bin requires --tor-state")
  assert mailbox.parse(state_only)
    == Ok(Serve("m.db", 0, Some(TorOptions(None, "/tmp/t"))))
}

pub fn resolve_tor_bin_precedence_and_errors_test() {
  let none = fn(_) { Error(Nil) }
  let has = fn(expected) { fn(path) { path == expected } }

  assert mailbox.resolve_tor_bin(
      Some("/custom/tor"),
      none,
      none,
      has("/custom/tor"),
    )
    == Ok("/custom/tor")
  assert mailbox.resolve_tor_bin(Some("/missing"), none, none, fn(_) { False })
    == Error("pondline-tor binary not found at /missing")
  assert mailbox.resolve_tor_bin(
      None,
      fn(_) { Ok("/rel/bin/pondline-tor") },
      none,
      has("/rel/bin/pondline-tor"),
    )
    == Ok("/rel/bin/pondline-tor")
  assert mailbox.resolve_tor_bin(
      None,
      fn(_) { Ok("/gone/pondline-tor") },
      fn(_) { Ok("/usr/bin/pondline-tor") },
      has("/usr/bin/pondline-tor"),
    )
    == Error("PONDLINE_TOR_BIN points to missing binary /gone/pondline-tor")
  assert mailbox.resolve_tor_bin(
      None,
      none,
      fn(_) { Ok("/usr/local/bin/pondline-tor") },
      fn(_) { False },
    )
    == Ok("/usr/local/bin/pondline-tor")
  assert mailbox.resolve_tor_bin(None, none, none, fn(_) { False })
    == Error(
      "could not find pondline-tor; pass --tor-bin or set PONDLINE_TOR_BIN",
    )
}

pub fn grant_takes_no_tor_options_test() {
  let arguments = [
    "grant", "--db", "m.db", "--queues", "1", "--out", "f", "--tor-bin", "x",
  ]

  assert mailbox.parse(arguments) == Error("unknown option --tor-bin")
}

/// Hosts a mailbox on an onion service and checks the address it returns.
pub fn run_onion() -> Nil {
  case getenv("PONDLINE_TOR_NETWORK") == Ok("1") {
    True -> host()
    False ->
      io.println_error("SKIP onion_hosting: needs PONDLINE_TOR_NETWORK=1")
  }
}

fn host() -> Nil {
  let binary =
    getenv("PONDLINE_TOR_BIN")
    |> result.unwrap("../../native/pondline-tor/target/release/pondline-tor")
  let dir = make_scratch_dir()

  let config =
    node.Config(
      path: support.fresh_path(),
      sweep_period_ms: 60_000,
      clock: fn() { Instant(support.now.unix_seconds) },
      names: node.new_names(),
      timer: timer.WallClock,
      interceptor: None,
      store_faults: None,
    )
  let assert Ok(#(_, running)) = node.start(config)
  let assert Ok(server) =
    http.start(running, http.Config(interface: "127.0.0.1", port: 0))

  let hosted = mailbox.host_onion(TorHosting(binary, dir), server.port)
  process.sleep(500)
  remove_dir(dir)

  let assert Ok(host) = hosted
  assert string.ends_with(host, ".onion:80")
  assert string.length(host) == 56 + string.length(".onion:80")
}

pub fn version_is_a_command_of_its_own_test() {
  assert mailbox.parse(["--version"]) == Ok(mailbox.Version)
  assert mailbox.parse(["version"]) == Ok(mailbox.Version)
  assert build.describe(build.from_lookup(fn(_) { Error(Nil) }))
    == "mailbox dev (commit unknown)"
}
