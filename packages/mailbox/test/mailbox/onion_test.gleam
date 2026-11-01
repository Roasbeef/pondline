//// The command line's Tor options, and the onion-hosting path itself.
////
//// Argument parsing is checked on every run. Hosting needs the Tor network,
//// so `run_onion` does its work only with `REEDWIRE_TOR_NETWORK=1`;
//// `mailbox_slow_test.erl` calls it because EUnit's default timeout is
//// shorter than a bootstrap.

import core/time.{Instant}
import gleam/erlang/process
import gleam/io
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import mailbox.{Serve, TorHosting}
import mailbox/http
import mailbox/node
import mailbox/support

@external(erlang, "support_ffi", "getenv")
fn getenv(name: String) -> Result(String, Nil)

@external(erlang, "support_ffi", "make_scratch_dir")
fn make_scratch_dir() -> String

@external(erlang, "support_ffi", "remove_dir")
fn remove_dir(dir: String) -> Nil

pub fn serve_without_tor_test() {
  assert mailbox.parse(["serve", "--db", "m.db", "--port", "0"])
    == Ok(Serve("m.db", 0, None))
}

pub fn serve_with_tor_test() {
  let arguments = [
    "serve", "--db", "m.db", "--port", "8080", "--tor-bin", "./rt",
    "--tor-state", "/tmp/t",
  ]

  assert mailbox.parse(arguments)
    == Ok(Serve("m.db", 8080, Some(TorHosting("./rt", "/tmp/t"))))
}

pub fn tor_options_go_together_test() {
  let binary_only = [
    "serve", "--db", "m.db", "--port", "0", "--tor-bin", "./rt",
  ]
  let state_only = [
    "serve", "--db", "m.db", "--port", "0", "--tor-state", "/tmp/t",
  ]

  assert mailbox.parse(binary_only)
    == Error("--tor-bin and --tor-state go together")
  assert mailbox.parse(state_only)
    == Error("--tor-bin and --tor-state go together")
}

pub fn grant_takes_no_tor_options_test() {
  let arguments = [
    "grant", "--db", "m.db", "--queues", "1", "--out", "f", "--tor-bin", "x",
  ]

  assert mailbox.parse(arguments) == Error("unknown option --tor-bin")
}

/// Hosts a mailbox on an onion service and checks the address it returns.
pub fn run_onion() -> Nil {
  case getenv("REEDWIRE_TOR_NETWORK") == Ok("1") {
    True -> host()
    False ->
      io.println_error("SKIP onion_hosting: needs REEDWIRE_TOR_NETWORK=1")
  }
}

fn host() -> Nil {
  let binary =
    getenv("REEDWIRE_TOR_BIN")
    |> result.unwrap("../../native/reedwire-tor/target/release/reedwire-tor")
  let dir = make_scratch_dir()

  let config =
    node.Config(
      path: support.fresh_path(),
      sweep_period_ms: 60_000,
      clock: fn() { Instant(support.now.unix_seconds) },
      names: node.new_names(),
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
