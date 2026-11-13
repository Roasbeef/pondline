//// The mailbox command line (spec §6, §10.2).
////
//// Run it with `gleam run -m mailbox -- <subcommand> ...`:
////
//// - `serve --db <path> [--port <n>] [--tor-state <dir> [--tor-bin <path>]]`
////   opens the database, starts the node and the HTTP server on
////   `127.0.0.1`, prints `listening 127.0.0.1:<port>` on stdout, and runs
////   until the VM is stopped. Port 0 (the default) asks the system for a free
////   port, and the line names the one it chose. With `--tor-state` it resolves
////   `pondline-tor` (from `--tor-bin`, `PONDLINE_TOR_BIN`, `PATH`, or the
////   checkout build), starts and bootstraps the sidecar, hosts an onion service
////   that forwards to that port, and prints `onion <host>.onion:80`, which is
////   the address a daemon dials. The Tor state directory holds the service's
////   key, and its path must be short enough for a Unix socket.
//// - `grant --db <path> --queues <n> [--out <file>] [--token [--mailbox <host:port> | --tor-state <dir>]]`
////   creates a provisioning grant allowing `n` queues. With `--out` it writes
////   the 32-byte capability to a new 0600 file; with `--token` it prints a
////   copy-pasteable `plg1...` grant token carrying the mailbox endpoint and
////   capability on stdout (taking the endpoint from `--mailbox` or from the
////   `<dir>/onion` file written by `serve`).
//// - `status --db <path> [--tor-state <dir>] [--json]` prints aggregate grant,
////   queue, envelope, blob and tombstone counts without exposing any capability.
////
//// - `--version` prints the build's version and commit (`mailbox/build`).
////
//// Anything else prints a one-line message on stderr and exits with status
//// 1. The server listens on the loopback interface only, because the onion
//// service forwards to it and this program never serves a public address.
////
//// ## Flow
////
//// 1. `main` calls `parse` to turn the arguments into a `Command`, so a
////    malformed command line is rejected before anything is opened.
//// 2. `run` executes the command through `serve`, `run_grant` or `run_status`,
////    and returns a one-line failure message.
//// 3. `main` turns a failure into the exit status.

import argv
import core/capability
import core/endpoint.{type Endpoint}
import core/grant
import core/secret.{type Secret}
import core/time.{Instant}
import gleam/dict.{type Dict}
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import mailbox/build
import mailbox/http
import mailbox/internal/ffi_system
import mailbox/node
import mailbox/service
import mailbox/store
import primitives
import simplifile
import telemetry/field
import telemetry/handler
import telemetry/log
import tor
import tor/address
import weft/timer

/// The interface the server binds. It is not configurable.
const loopback = "127.0.0.1"

/// Milliseconds between expiry sweeps of a running node.
const sweep_period_ms = 60_000

/// The virtual port of the onion service. The sidecar forwards a stream
/// on any virtual port to the local port, so the value only has to be one
/// the daemon dials; 80 is the conventional one.
const onion_port = 80

/// How long the sidecar may take to bootstrap, in milliseconds.
const bootstrap_timeout_ms = 180_000

/// How long the sidecar may take to create the onion service.
const host_timeout_ms = 120_000

/// Where the Tor sidecar lives and keeps its state once resolved.
pub type TorHosting {
  TorHosting(
    /// The `pondline-tor` binary.
    binary: String,
    /// The sidecar's state directory, which holds the service key.
    state_dir: String,
  )
}

/// The Tor options parsed from `serve`, before sidecar auto-discovery runs.
pub type TorOptions {
  TorOptions(
    /// Explicit `--tor-bin`, or `None` to resolve automatically.
    binary: Option(String),
    /// The sidecar's state directory, which holds the service key.
    state_dir: String,
  )
}

/// Where `grant --token` obtains the mailbox endpoint it embeds.
pub type GrantEndpoint {
  /// Explicit `--mailbox HOST:PORT`.
  ExplicitGrantEndpoint(endpoint: Endpoint)

  /// Read `<state_dir>/onion` written by `serve`.
  TorStateEndpoint(state_dir: String)
}

/// What `grant` emits: a 0600 capability file, a `plg1...` token on stdout, or both.
pub type GrantOutput {
  /// Write the raw 32-byte capability to `path`.
  GrantFile(path: String)

  /// Print the `plg1...` token on standard output.
  GrantTokenOnly(endpoint: GrantEndpoint)

  /// Write the capability to `path` (reported on stderr) and print the token on stdout.
  GrantTokenAndFile(path: String, endpoint: GrantEndpoint)
}

/// How `status` prints its report.
pub type StatusOutput {
  StatusHuman
  StatusJson
}

/// Whether the onion sidecar watcher keeps listening after an event.
pub type WatcherStep {
  /// Keep draining sidecar events.
  KeepWatching

  /// The sidecar exhausted its restart budget; stop watching.
  StopWatching
}

/// Parsed command-line options for one subcommand.
type Options {
  Options(values: Dict(String, String), flags: List(String))
}

/// A parsed command line.
pub type Command {
  Serve(db: String, port: Int, tor: Option(TorOptions))
  Grant(db: String, queues: Int, output: GrantOutput)
  Status(db: String, tor_state: Option(String), output: StatusOutput)

  /// Print the build's version and commit and exit.
  Version
}

/// The entry point for `gleam run -m mailbox`.
pub fn main() -> Nil {
  // The handler goes in before anything can crash, so every report this
  // VM writes, from the argument parser on, is the scrubbed one on
  // standard error (ADR-012). A VM that cannot install it does not run.
  let outcome = {
    use _ <- result.try(
      handler.install_from_env()
      |> result.replace_error("the log handler could not be installed"),
    )
    use command <- result.try(parse(argv.load().arguments))
    run(command)
  }

  // Only a failure has anything to report; success exits normally.
  case outcome {
    Ok(Nil) -> Nil

    Error(message) -> {
      io.println_error("mailbox: " <> message)
      ffi_system.halt(1)
    }
  }
}

/// Turns arguments into a command, or says what is wrong with them.
///
/// ## Examples
///
/// ```gleam
/// mailbox.parse(["serve", "--db", "m.db"])
/// // -> Ok(Serve("m.db", 0, None))
/// mailbox.parse(["serve", "--db", "m.db", "--tor-bin", "t"])
/// // -> Error("--tor-bin requires --tor-state")
/// ```
pub fn parse(arguments: List(String)) -> Result(Command, String) {
  // The first word names the subcommand; its options are checked against
  // that subcommand's own list.
  case arguments {
    ["--version"] | ["version"] -> Ok(Version)

    ["serve", ..rest] -> {
      use options <- result.try(
        read_options(rest, ["--db", "--port", "--tor-bin", "--tor-state"], []),
      )
      use db <- result.try(required(options.values, "--db"))
      use port <- result.try(optional_number(
        options.values,
        "--port",
        0,
        0,
        65_535,
      ))
      use tor <- result.try(tor_options(options.values))

      Ok(Serve(db:, port:, tor:))
    }

    ["grant", ..rest] -> parse_grant(rest)
    ["status", ..rest] -> parse_status(rest)

    _ ->
      Error(
        "usage: serve --db <path> [--port <n>] [--tor-state <dir> [--tor-bin <path>]] | grant --db <path> --queues <n> [--out <file>] [--token (--mailbox <host:port> | --tor-state <dir>)] | status --db <path> [--tor-state <dir>] [--json] | --version",
      )
  }
}

/// Parses `status --db <path> [--tor-state <dir>] [--json]`.
fn parse_status(rest: List(String)) -> Result(Command, String) {
  use options <- result.try(
    read_options(rest, ["--db", "--tor-state"], ["--json"]),
  )
  use db <- result.map(required(options.values, "--db"))
  let tor_state = option.from_result(dict.get(options.values, "--tor-state"))

  // `--json` switches from human lines to machine-readable JSON.
  let output = case list.contains(options.flags, "--json") {
    True -> StatusJson
    False -> StatusHuman
  }

  Status(db:, tor_state:, output:)
}

/// The Tor options on `serve`: `--tor-state` enables onion hosting (resolving
/// the sidecar automatically when `--tor-bin` is omitted), while `--tor-bin`
/// alone has nowhere to store the service key and is refused.
fn tor_options(
  options: Dict(String, String),
) -> Result(Option(TorOptions), String) {
  // Only `--tor-bin` without `--tor-state` is invalid; `--tor-state` alone
  // asks `serve` to locate `pondline-tor` from the environment or PATH.
  case dict.get(options, "--tor-bin"), dict.get(options, "--tor-state") {
    Error(Nil), Error(Nil) -> Ok(None)
    binary, Ok(state_dir) ->
      Ok(Some(TorOptions(binary: option.from_result(binary), state_dir:)))
    Ok(_), Error(Nil) -> Error("--tor-bin requires --tor-state")
  }
}

/// Parses `grant` options and validates output mode before touching storage.
fn parse_grant(rest: List(String)) -> Result(Command, String) {
  use options <- result.try(
    read_options(
      rest,
      ["--db", "--queues", "--out", "--mailbox", "--tor-state"],
      ["--token"],
    ),
  )
  use db <- result.try(required(options.values, "--db"))
  use queues <- result.try(number(options.values, "--queues", 1, 1_000_000))
  use output <- result.try(grant_output(options))

  Ok(Grant(db:, queues:, output:))
}

/// Decides whether `grant` writes `--out`, prints `--token`, or both.
fn grant_output(options: Options) -> Result(GrantOutput, String) {
  let out = dict.get(options.values, "--out")
  let wants_token = list.contains(options.flags, "--token")

  // Without `--token`, `--mailbox` and `--tor-state` have nothing to attach to.
  case out, wants_token {
    Ok(path), False -> {
      use Nil <- result.map(reject_unused_endpoint_options(options.values))
      GrantFile(path:)
    }

    Error(Nil), True -> {
      use source <- result.map(grant_endpoint(options.values))
      GrantTokenOnly(endpoint: source)
    }

    Ok(path), True -> {
      use source <- result.map(grant_endpoint(options.values))
      GrantTokenAndFile(path:, endpoint: source)
    }

    Error(Nil), False -> Error("give --out <file>, --token, or both")
  }
}

/// Rejects `--mailbox` and `--tor-state` when `--token` was not requested.
fn reject_unused_endpoint_options(
  values: Dict(String, String),
) -> Result(Nil, String) {
  case dict.has_key(values, "--mailbox"), dict.has_key(values, "--tor-state") {
    False, False -> Ok(Nil)
    True, _ -> Error("--mailbox requires --token")
    False, True -> Error("--tor-state on grant requires --token")
  }
}

/// Resolves the endpoint source for `grant --token`: exactly one of `--mailbox` or `--tor-state`.
fn grant_endpoint(
  values: Dict(String, String),
) -> Result(GrantEndpoint, String) {
  case dict.get(values, "--mailbox"), dict.get(values, "--tor-state") {
    Ok(text), Error(Nil) ->
      endpoint.parse(text)
      |> result.map(ExplicitGrantEndpoint)
      |> result.replace_error("--mailbox must be ONION:PORT or 127.0.0.1:PORT")

    Error(Nil), Ok(state_dir) -> Ok(TorStateEndpoint(state_dir:))
    Ok(_), Ok(_) -> Error("give either --mailbox or --tor-state, not both")
    Error(Nil), Error(Nil) ->
      Error("--token requires --mailbox <host:port> or --tor-state <dir>")
  }
}

/// Reads `--name value` pairs and bare flags, rejecting unknown or repeated
/// options and refusing stray words without echoing them.
fn read_options(
  arguments: List(String),
  values: List(String),
  flags: List(String),
) -> Result(Options, String) {
  read_loop(arguments, values, flags, Options(dict.new(), []))
}

/// Walks `arguments` one option or flag at a time.
fn read_loop(
  arguments: List(String),
  values: List(String),
  flags: List(String),
  found: Options,
) -> Result(Options, String) {
  case arguments {
    [] -> Ok(found)
    [name, ..rest] ->
      case list.contains(flags, name), list.contains(values, name) {
        True, _ -> take_flag(name, rest, values, flags, found)
        False, True -> take_value(name, rest, values, flags, found)
        False, False -> Error(unknown_option(name))
      }
  }
}

/// Records one bare flag, rejecting duplicates.
fn take_flag(
  name: String,
  rest: List(String),
  values: List(String),
  flags: List(String),
  found: Options,
) -> Result(Options, String) {
  case list.contains(found.flags, name) {
    True -> Error("repeated option " <> name)
    False ->
      read_loop(
        rest,
        values,
        flags,
        Options(..found, flags: [name, ..found.flags]),
      )
  }
}

/// Records one `--name value` option, rejecting duplicates and missing values.
fn take_value(
  name: String,
  rest: List(String),
  values: List(String),
  flags: List(String),
  found: Options,
) -> Result(Options, String) {
  case rest {
    [] -> Error("missing value for " <> name)
    [value, ..more] ->
      case dict.has_key(found.values, name) {
        True -> Error("repeated option " <> name)
        False ->
          read_loop(
            more,
            values,
            flags,
            Options(..found, values: dict.insert(found.values, name, value)),
          )
      }
  }
}

/// Formats an unknown option error without echoing non-option values.
fn unknown_option(name: String) -> String {
  case string.starts_with(name, "-"), string.split_once(name, "=") {
    True, Ok(#(option, _)) -> "unknown option " <> option <> "=..."
    True, Error(Nil) -> "unknown option " <> name
    False, _ -> "unexpected argument"
  }
}

/// The value of a required option.
fn required(
  options: Dict(String, String),
  name: String,
) -> Result(String, String) {
  dict.get(options, name)
  |> result.map_error(fn(_) { "missing option " <> name })
}

/// The value of an optional integer option, defaulting to `default_value`.
fn optional_number(
  options: Dict(String, String),
  name: String,
  default_value: Int,
  low: Int,
  high: Int,
) -> Result(Int, String) {
  case dict.get(options, name) {
    Error(Nil) -> Ok(default_value)
    Ok(_) -> number(options, name, low, high)
  }
}

/// The value of a required integer option, within `low` to `high`.
fn number(
  options: Dict(String, String),
  name: String,
  low: Int,
  high: Int,
) -> Result(Int, String) {
  use text <- result.try(required(options, name))

  // Anything that is not an integer in range gets the same message.
  case int.parse(text) {
    Ok(value) if value >= low && value <= high -> Ok(value)

    _ ->
      Error(
        name
        <> " must be an integer from "
        <> int.to_string(low)
        <> " to "
        <> int.to_string(high),
      )
  }
}

/// Executes a command.
fn run(command: Command) -> Result(Nil, String) {
  case command {
    Serve(db:, port:, tor:) -> serve(db, port, tor)
    Grant(db:, queues:, output:) -> run_grant(db, queues, output)
    Status(db:, tor_state:, output:) -> run_status(db, tor_state, output)

    // The identity is the launcher's, so it needs no database.
    Version -> {
      io.println(build.describe(build.current()))
      Ok(Nil)
    }
  }
}

/// Resolves the `pondline-tor` binary path from an explicit `--tor-bin`,
/// `PONDLINE_TOR_BIN`, `PATH`, or the repository checkout build.
///
/// ## Examples
///
/// ```gleam
/// mailbox.resolve_tor_bin(Some("/bin/tor"), fn(_) { Error(Nil) }, fn(_) { Error(Nil) }, fn(_) { True })
/// // -> Ok("/bin/tor")
/// ```
pub fn resolve_tor_bin(
  explicit: Option(String),
  lookup_env: fn(String) -> Result(String, Nil),
  find_exec: fn(String) -> Result(String, Nil),
  exists: fn(String) -> Bool,
) -> Result(String, String) {
  // An explicit flag or environment variable must exist where named rather than
  // silently falling through to a different binary on the machine.
  case explicit {
    Some(path) ->
      check_binary(path, "pondline-tor binary not found at ", exists)
    None -> resolve_implicit_tor_bin(lookup_env, find_exec, exists)
  }
}

/// Searches `PONDLINE_TOR_BIN`, `PATH`, and local checkout build paths.
fn resolve_implicit_tor_bin(
  lookup_env: fn(String) -> Result(String, Nil),
  find_exec: fn(String) -> Result(String, Nil),
  exists: fn(String) -> Bool,
) -> Result(String, String) {
  case lookup_env("PONDLINE_TOR_BIN") {
    Ok(path) if path != "" ->
      check_binary(path, "PONDLINE_TOR_BIN points to missing binary ", exists)

    Ok(_) | Error(Nil) ->
      case find_exec("pondline-tor") {
        Ok(path) -> Ok(path)
        Error(Nil) -> find_checkout_tor_bin(exists)
      }
  }
}

/// Checks checkout-relative build locations so `gleam run` works after `make sidecar`.
fn find_checkout_tor_bin(exists: fn(String) -> Bool) -> Result(String, String) {
  let candidates = [
    "native/pondline-tor/target/release/pondline-tor",
    "../../native/pondline-tor/target/release/pondline-tor",
  ]

  // Pick the first checkout build artifact present on disk, or report how to supply one.
  case list.find(candidates, exists) {
    Ok(path) -> Ok(path)
    Error(Nil) ->
      Error(
        "could not find pondline-tor; pass --tor-bin or set PONDLINE_TOR_BIN",
      )
  }
}

/// Verifies that a named sidecar path exists as a regular file.
fn check_binary(
  path: String,
  prefix: String,
  exists: fn(String) -> Bool,
) -> Result(String, String) {
  case exists(path) {
    True -> Ok(path)
    False -> Error(prefix <> path)
  }
}

/// Resolves `TorOptions` against the live process environment and filesystem.
fn resolve_hosting(
  options: Option(TorOptions),
) -> Result(Option(TorHosting), String) {
  // Resolve the binary only when `--tor-state` enabled onion hosting.
  case options {
    None -> Ok(None)
    Some(TorOptions(binary:, state_dir:)) -> {
      use resolved <- result.map(
        resolve_tor_bin(
          binary,
          ffi_system.getenv,
          ffi_system.find_executable,
          fn(path) { simplifile.is_file(path) == Ok(True) },
        ),
      )
      Some(TorHosting(binary: resolved, state_dir:))
    }
  }
}

/// Starts the node and the server, announces the port and never returns.
fn serve(
  db: String,
  port: Int,
  tor_options: Option(TorOptions),
) -> Result(Nil, String) {
  // Resolve any requested Tor binary first so a missing sidecar fails before
  // opening the database or binding a local port.
  use hosting <- result.try(resolve_hosting(tor_options))
  let started =
    node.start(node.Config(
      path: db,
      sweep_period_ms:,
      clock: fn() { Instant(ffi_system.unix_seconds()) },
      names: node.new_names(),
      timer: timer.WallClock,
      interceptor: None,
      store_faults: None,
    ))
  use #(_supervisor, running) <- result.try(result.replace_error(
    started,
    "the node could not start",
  ))

  use server <- result.try(
    http.start(running, http.Config(interface: loopback, port:))
    |> result.map_error(fn(_) {
      "the server could not listen on port " <> int.to_string(port)
    }),
  )

  io.println("listening " <> loopback <> ":" <> int.to_string(server.port))
  log.info("mailbox", "serving", [field.count("port", server.port)])

  // The onion line follows the listening line, so a reader that stops at
  // the first line still gets the port it needs.
  use Nil <- result.try(case hosting {
    None -> Ok(Nil)

    Some(hosting) -> {
      use host <- result.try(host_onion(hosting, server.port))
      use Nil <- result.map(record_onion_endpoint(hosting.state_dir, host))
      io.println("onion " <> host)
    }
  })

  process.sleep_forever()

  Ok(Nil)
}

/// Starts the Tor sidecar, bootstraps it and hosts an onion service that
/// forwards to `127.0.0.1:local_port`. Returns the address a daemon dials,
/// `<host>.onion:80`. The sidecar is linked to the calling process, so it
/// stops when the caller does. The service is created before Tor can reach
/// it, so a client may need to retry for a while after this returns.
///
/// Both waits, for the bootstrap and for the service, are `tor`'s own
/// bounded calls into its `weft/state_machine`, which owns their deadlines;
/// nothing here polls, so there is no `weft/poll` to port.
///
/// ## Examples
///
/// ```gleam
/// mailbox.host_onion(TorHosting("./pondline-tor", "/tmp/mb-tor"), 8080)
/// // -> Ok("abc...xyz.onion:80")
/// ```
pub fn host_onion(
  hosting: TorHosting,
  local_port: Int,
) -> Result(String, String) {
  use started <- result.try(
    tor.start(tor.config(hosting.binary, hosting.state_dir))
    |> result.replace_error("the Tor sidecar could not start"),
  )

  // Shut the sidecar down if initial hosting fails; only spawn the linked
  // watcher once the service is live, so a failed start leaks neither process.
  case bootstrap_and_host(started, local_port) {
    Ok(onion) -> {
      spawn_onion_watcher(started, local_port)
      Ok(address.onion_host(onion.address) <> ":" <> int.to_string(onion_port))
    }

    Error(reason) -> {
      let _ = tor.shutdown(started)
      Error(reason)
    }
  }
}

/// Bootstraps `started` and launches the `mailbox` onion service.
fn bootstrap_and_host(
  started: tor.Tor,
  local_port: Int,
) -> Result(tor.OnionHost, String) {
  use Nil <- result.try(
    tor.bootstrap(started, bootstrap_timeout_ms)
    |> result.replace_error("Tor did not bootstrap"),
  )
  tor.host_onion(started, "mailbox", local_port, host_timeout_ms)
  |> result.replace_error("the onion service could not be created")
}

/// Starts a linked subscriber before the initial bootstrap so sidecar state
/// transitions are logged and a restarted sidecar re-hosts the onion service.
fn spawn_onion_watcher(started: tor.Tor, local_port: Int) -> Nil {
  let ready = process.new_subject()
  let _ =
    process.spawn(fn() {
      let events = process.new_subject()
      tor.subscribe(started, events)
      process.send(ready, Nil)
      watch_onion_loop(started, events, local_port)
    })
  let _ = process.receive(ready, 5000)
  Nil
}

/// Receives sidecar events for the lifetime of the serving mailbox.
fn watch_onion_loop(
  started: tor.Tor,
  events: process.Subject(tor.Event),
  local_port: Int,
) -> Nil {
  let event = process.receive_forever(events)
  let step =
    handle_sidecar_event(event, fn() {
      bootstrap_and_host(started, local_port) |> result.replace(Nil)
    })

  // Keep draining until the sidecar machine permanently exhausts its restarts.
  case step {
    KeepWatching -> watch_onion_loop(started, events, local_port)
    StopWatching -> Nil
  }
}

/// Logs one sidecar event and re-runs `rehost` when a replacement sidecar starts.
///
/// ## Examples
///
/// ```gleam
/// mailbox.handle_sidecar_event(tor.SidecarGaveUp, fn() { Ok(Nil) })
/// // -> mailbox.StopWatching
/// ```
pub fn handle_sidecar_event(
  event: tor.Event,
  rehost: fn() -> Result(Nil, String),
) -> WatcherStep {
  // Each sidecar transition logs structured fields and re-hosts after restart.
  case event {
    tor.ServiceStateChanged(state:, ..) -> {
      log.info("mailbox", "onion_state", [field.tag("state", state)])
      KeepWatching
    }

    tor.SidecarDied(status:) -> {
      log.warning("mailbox", "sidecar_died", [field.count("status", status)])
      KeepWatching
    }

    tor.SidecarRestarted -> {
      log.warning("mailbox", "sidecar_restarted", [])

      // A replacement sidecar starts unbootstrapped, so re-host the service.
      case rehost() {
        Ok(Nil) -> log.info("mailbox", "onion_rehosted", [])
        Error(_) -> log.error("mailbox", "onion_rehost_failed", [])
      }

      KeepWatching
    }

    tor.SidecarGaveUp -> {
      log.error("mailbox", "sidecar_gave_up", [])
      StopWatching
    }
  }
}

/// Creates a grant allowing `queues` queues and stores its capability in a
/// new owner-only file at `out`. Returns a one-line failure message.
///
/// ## Examples
///
/// ```gleam
/// mailbox.grant("mailbox.db", 10, "provision.cap")
/// // -> Ok(Nil)
/// ```
pub fn grant(db: String, queues: Int, out: String) -> Result(Nil, String) {
  run_grant(db, queues, GrantFile(path: out))
}

/// Mints a provisioning grant and writes or encodes it according to `output`,
/// returning any encoded `plg1...` token as a `Secret`.
///
/// ## Examples
///
/// ```gleam
/// mailbox.issue_grant("mailbox.db", 10, GrantFile("provision.cap"))
/// // -> Ok(None)
/// ```
pub fn issue_grant(
  db: String,
  queues: Int,
  output: GrantOutput,
) -> Result(Option(Secret), String) {
  // Validate output destinations and any stored onion address before opening
  // the database so a bad path or missing onion file never orphans a grant row.
  use Nil <- result.try(check_grant_file(output))
  use resolved_endpoint <- result.try(resolve_grant_endpoint(output))

  use opened <- result.try(
    store.open(db) |> result.replace_error("the database could not be opened"),
  )
  let created = service.create_grant(opened, queues, primitives.random_bytes)
  let _ = store.close(opened)
  use provision <- result.try(result.replace_error(
    created,
    "the grant could not be created",
  ))

  use Nil <- result.try(write_grant_file(output, capability.expose(provision)))
  Ok(
    option.map(resolved_endpoint, fn(ep) {
      grant.encode(grant.new(ep, provision))
    }),
  )
}

/// Runs `grant` and prints the path or `plg1...` token to stdout.
fn run_grant(
  db: String,
  queues: Int,
  output: GrantOutput,
) -> Result(Nil, String) {
  use token <- result.try(issue_grant(db, queues, output))

  // When both `--out` and `--token` are requested, the token owns stdout so it
  // can be piped directly, while the file path goes to stderr. A failed stdout
  // write returns an error rather than exiting 0 after losing the capability.
  case output, token {
    GrantFile(path:), _ ->
      ffi_system.write_stdout(<<path:utf8, "\n">>)
      |> result.map_error(fn(r) { "could not write standard output: " <> r })
    GrantTokenOnly(..), Some(encoded) -> print_secret_line(encoded)
    GrantTokenAndFile(path:, ..), Some(encoded) -> {
      io.println_error(path)
      print_secret_line(encoded)
    }
    _, None -> Ok(Nil)
  }
}

/// Writes `<host>\n` to `<state_dir>/onion` with mode 0600 so `grant` and `status` can read it.
///
/// ## Examples
///
/// ```gleam
/// mailbox.record_onion_endpoint("/tmp/mb-tor", "abc...d.onion:80")
/// // -> Ok(Nil)
/// ```
pub fn record_onion_endpoint(
  state_dir: String,
  host: String,
) -> Result(Nil, String) {
  let onion_file = state_dir <> "/onion"
  ffi_system.write_private_file(onion_file, <<host:utf8, "\n">>)
  |> result.map_error(fn(reason) {
    "could not record onion address in " <> onion_file <> ": " <> reason
  })
}

/// Writes an ASCII secret token line directly to fd 1, checking the write result.
fn print_secret_line(value: Secret) -> Result(Nil, String) {
  ffi_system.write_stdout(<<{ secret.expose(value) }:bits, "\n":utf8>>)
  |> result.map_error(fn(reason) {
    "could not write standard output: " <> reason
  })
}

/// Checks upfront that any `--out` destination does not already exist.
fn check_grant_file(output: GrantOutput) -> Result(Nil, String) {
  case grant_file_path(output) {
    None -> Ok(Nil)
    Some(out) ->
      case simplifile.file_info(out) {
        Error(simplifile.Enoent) -> Ok(Nil)
        _ -> Error("refusing to overwrite " <> out)
      }
  }
}

/// Writes the raw 32-byte capability when `output` names `--out`.
fn write_grant_file(
  output: GrantOutput,
  bytes: BitArray,
) -> Result(Nil, String) {
  case grant_file_path(output) {
    None -> Ok(Nil)
    Some(out) ->
      case ffi_system.create_private_file(out, bytes) {
        Ok(Nil) -> Ok(Nil)
        Error("eexist") -> Error("refusing to overwrite " <> out)
        Error(reason) -> Error("could not write " <> out <> ": " <> reason)
      }
  }
}

/// Extracts `--out` from a `GrantOutput`, if present.
fn grant_file_path(output: GrantOutput) -> Option(String) {
  case output {
    GrantFile(path:) | GrantTokenAndFile(path:, ..) -> Some(path)
    GrantTokenOnly(..) -> None
  }
}

/// Resolves the `Endpoint` needed when `--token` was requested.
fn resolve_grant_endpoint(
  output: GrantOutput,
) -> Result(Option(Endpoint), String) {
  // Only `--token` modes carry an endpoint; file-only grants leave it `None`.
  case output {
    GrantFile(..) -> Ok(None)
    GrantTokenOnly(endpoint: source)
    | GrantTokenAndFile(endpoint: source, ..) -> {
      use ep <- result.map(load_grant_endpoint(source))
      Some(ep)
    }
  }
}

/// Loads an endpoint from `--mailbox` or `<tor_state>/onion`.
fn load_grant_endpoint(source: GrantEndpoint) -> Result(Endpoint, String) {
  // `--mailbox` was parsed upfront; `--tor-state` reads the saved onion file.
  case source {
    ExplicitGrantEndpoint(endpoint:) -> Ok(endpoint)
    TorStateEndpoint(state_dir:) -> {
      let onion_file = state_dir <> "/onion"
      use text <- result.try(
        simplifile.read(onion_file)
        |> result.map_error(fn(_) {
          "could not read "
          <> onion_file
          <> "; start serve first or pass --mailbox"
        }),
      )
      endpoint.parse(string.trim(text))
      |> result.map_error(fn(_) {
        "stored onion endpoint in " <> onion_file <> " is malformed"
      })
    }
  }
}

/// Reads aggregate mailbox metrics and formats them as human text or JSON.
/// Refuses a missing database file so `status` never creates an empty SQLite file.
///
/// ## Examples
///
/// ```gleam
/// mailbox.inspect_status("/nonexistent.db", None, StatusHuman)
/// // -> Error("database not found at /nonexistent.db")
/// ```
pub fn inspect_status(
  db: String,
  tor_state: Option(String),
  output: StatusOutput,
) -> Result(String, String) {
  // Refuse an absent database file instead of creating an empty SQLite store.
  use Nil <- result.try(case simplifile.is_file(db) {
    Ok(True) -> Ok(Nil)
    _ -> Error("database not found at " <> db)
  })

  use opened <- result.try(
    store.open(db) |> result.replace_error("the database could not be opened"),
  )
  let queried = store.status(opened, Instant(ffi_system.unix_seconds()))
  let _ = store.close(opened)
  use report <- result.map(
    queried |> result.replace_error("could not read mailbox status"),
  )
  let onion = read_optional_onion(tor_state)
  format_status(report, onion, output)
}

/// Runs `status` and prints the formatted summary on stdout.
fn run_status(
  db: String,
  tor_state: Option(String),
  output: StatusOutput,
) -> Result(Nil, String) {
  use rendered <- result.map(inspect_status(db, tor_state, output))
  io.println(rendered)
}

/// Reads `<dir>/onion` if `--tor-state` was supplied and the file exists.
fn read_optional_onion(tor_state: Option(String)) -> Option(String) {
  case tor_state {
    None -> None
    Some(dir) ->
      case simplifile.read(dir <> "/onion") {
        Ok(text) ->
          endpoint.parse(string.trim(text))
          |> result.map(endpoint.to_string)
          |> option.from_result
        Error(_) -> None
      }
  }
}

/// Formats `store.StatusReport` alongside build identity and optional onion address.
fn format_status(
  report: store.StatusReport,
  onion: Option(String),
  output: StatusOutput,
) -> String {
  let identity = build.current()

  // Format either human key-value lines or compact JSON.
  case output {
    StatusHuman ->
      format_human_status(identity.version, identity.commit, onion, report)
    StatusJson ->
      format_json_status(identity.version, identity.commit, onion, report)
  }
}

/// Human-readable multi-line operator report.
fn format_human_status(
  version: String,
  commit: String,
  onion: Option(String),
  report: store.StatusReport,
) -> String {
  // Include the onion line only when `<tor-state>/onion` was present.
  let onion_line = case onion {
    Some(host) -> ["onion: " <> host]
    None -> []
  }

  let lines =
    list.flatten([
      ["version: " <> version <> " (" <> commit <> ")"],
      onion_line,
      [
        "grants: "
          <> int.to_string(report.grants)
          <> " ("
          <> int.to_string(report.queues_used_total)
          <> "/"
          <> int.to_string(report.allowance_total)
          <> " queues provisioned)",
        "queues: "
          <> int.to_string(report.queues)
          <> " ("
          <> int.to_string(report.bytes_used)
          <> "/"
          <> int.to_string(report.capacity_total)
          <> " bytes used)",
        "envelopes: "
          <> int.to_string(report.live_envelopes)
          <> " ("
          <> int.to_string(report.envelope_bytes)
          <> " bytes)",
        "blobs: "
          <> int.to_string(report.live_blobs)
          <> " ("
          <> int.to_string(report.blob_bytes)
          <> " bytes)",
        "tombstones: " <> int.to_string(report.live_tombstones),
      ],
    ])
  string.join(lines, "\n")
}

/// Machine-readable JSON status report.
fn format_json_status(
  version: String,
  commit: String,
  onion: Option(String),
  report: store.StatusReport,
) -> String {
  // Emit `"onion":null` when no onion state file is available.
  let onion_json = case onion {
    Some(host) -> json_quote(host)
    None -> "null"
  }

  "{\"version\":"
  <> json_quote(version)
  <> ",\"commit\":"
  <> json_quote(commit)
  <> ",\"onion\":"
  <> onion_json
  <> ",\"grants\":"
  <> int.to_string(report.grants)
  <> ",\"allowance_total\":"
  <> int.to_string(report.allowance_total)
  <> ",\"queues_used_total\":"
  <> int.to_string(report.queues_used_total)
  <> ",\"queues\":"
  <> int.to_string(report.queues)
  <> ",\"bytes_used\":"
  <> int.to_string(report.bytes_used)
  <> ",\"capacity_total\":"
  <> int.to_string(report.capacity_total)
  <> ",\"live_envelopes\":"
  <> int.to_string(report.live_envelopes)
  <> ",\"envelope_bytes\":"
  <> int.to_string(report.envelope_bytes)
  <> ",\"live_blobs\":"
  <> int.to_string(report.live_blobs)
  <> ",\"blob_bytes\":"
  <> int.to_string(report.blob_bytes)
  <> ",\"live_tombstones\":"
  <> int.to_string(report.live_tombstones)
  <> "}"
}

/// Escapes backslashes and quotes for a single-line JSON string field.
fn json_quote(text: String) -> String {
  let escaped =
    text
    |> string.replace("\\", "\\\\")
    |> string.replace("\"", "\\\"")
    |> string.replace("\n", "\\n")
  "\"" <> escaped <> "\""
}
