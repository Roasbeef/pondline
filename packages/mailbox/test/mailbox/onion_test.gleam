//// The command line's Tor options, and the onion-hosting path itself.
////
//// Argument parsing is checked on every run. Hosting needs the Tor network,
//// so `run_onion` does its work only with `PONDLINE_TOR_NETWORK=1`;
//// `mailbox_slow_test.erl` calls it because EUnit's default timeout is
//// shorter than a bootstrap.

import core/endpoint
import core/grant
import core/secret
import core/time.{Instant}
import gleam/bit_array
import gleam/erlang/process
import gleam/io
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import mailbox.{
  ExplicitGrantEndpoint, Grant, GrantFile, GrantTokenAndFile, GrantTokenOnly,
  Serve, Status, StatusHuman, StatusJson, TorHosting, TorOptions,
  TorStateEndpoint,
}
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

pub fn grant_takes_no_tor_bin_option_test() {
  let arguments = [
    "grant", "--db", "m.db", "--queues", "1", "--out", "f", "--tor-bin", "x",
  ]

  assert mailbox.parse(arguments) == Error("unknown option --tor-bin")
}

pub fn grant_token_parsing_and_issuance_test() {
  let assert Ok(ep) = endpoint.parse("127.0.0.1:8080")
  assert mailbox.parse([
      "grant",
      "--db",
      "m.db",
      "--queues",
      "5",
      "--out",
      "a.cap",
    ])
    == Ok(Grant("m.db", 5, GrantFile("a.cap")))
  assert mailbox.parse([
      "grant", "--db", "m.db", "--queues", "5", "--token", "--mailbox",
      "127.0.0.1:8080",
    ])
    == Ok(Grant("m.db", 5, GrantTokenOnly(ExplicitGrantEndpoint(ep))))
  assert mailbox.parse([
      "grant", "--db", "m.db", "--queues", "5", "--out", "a.cap", "--token",
      "--tor-state", "/tmp/tor",
    ])
    == Ok(Grant(
      "m.db",
      5,
      GrantTokenAndFile("a.cap", TorStateEndpoint("/tmp/tor")),
    ))
  assert mailbox.parse(["grant", "--db", "m.db", "--queues", "5"])
    == Error("give --out <file>, --token, or both")
  assert mailbox.parse(["grant", "--db", "m.db", "--queues", "5", "--token"])
    == Error("--token requires --mailbox <host:port> or --tor-state <dir>")
  assert mailbox.parse([
      "grant",
      "--db",
      "m.db",
      "--queues",
      "5",
      "--out",
      "f",
      "--mailbox",
      "127.0.0.1:80",
    ])
    == Error("--mailbox requires --token")

  // End-to-end issuance: mint a `plg1...` token and decode it back to the capability.
  let db = support.fresh_path()
  let assert Ok(Some(token_secret)) =
    mailbox.issue_grant(db, 10, GrantTokenOnly(ExplicitGrantEndpoint(ep)))
  let assert Ok(token_text) = bit_array.to_string(secret.expose(token_secret))
  let assert Ok(decoded) = grant.decode(token_text)
  assert grant.endpoint(decoded) == ep

  // End-to-end `TorStateEndpoint`: record `<tor_dir>/onion` and mint a `plg1` token from it.
  let tor_dir = make_scratch_dir()
  let onion_host =
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:80"
  let assert Ok(onion_ep) = endpoint.parse(onion_host)
  let assert Ok(Nil) = mailbox.record_onion_endpoint(tor_dir, onion_host)
  let assert Ok(Some(tor_token_secret)) =
    mailbox.issue_grant(db, 10, GrantTokenOnly(TorStateEndpoint(tor_dir)))
  let assert Ok(tor_token_text) =
    bit_array.to_string(secret.expose(tor_token_secret))
  let assert Ok(tor_decoded) = grant.decode(tor_token_text)
  assert grant.endpoint(tor_decoded) == onion_ep
  remove_dir(tor_dir)
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

pub fn status_command_parses_and_reports_aggregates_test() {
  assert mailbox.parse(["status", "--db", "m.db"])
    == Ok(Status("m.db", None, StatusHuman))
  assert mailbox.parse([
      "status",
      "--db",
      "m.db",
      "--tor-state",
      "/tmp/t",
      "--json",
    ])
    == Ok(Status("m.db", Some("/tmp/t"), StatusJson))
  assert mailbox.inspect_status("/nonexistent_mb_status.db", None, StatusHuman)
    == Error("database not found at /nonexistent_mb_status.db")

  let db = support.fresh_path()
  let assert Ok(ep) = endpoint.parse("127.0.0.1:8080")
  let assert Ok(_) =
    mailbox.issue_grant(db, 25, GrantTokenOnly(ExplicitGrantEndpoint(ep)))
  let assert Ok(human) = mailbox.inspect_status(db, None, StatusHuman)
  assert string.contains(human, "grants: 1 (0/25 queues provisioned)")
  let assert Ok(json_out) = mailbox.inspect_status(db, None, StatusJson)
  assert string.contains(
    json_out,
    "\"grants\":1,\"allowance_total\":25,\"queues_used_total\":0",
  )
}
