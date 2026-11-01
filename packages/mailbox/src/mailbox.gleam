//// The mailbox command line (spec §6, §10.2).
////
//// Run it with `gleam run -m mailbox -- <subcommand> ...`:
////
//// - `serve --db <path> --port <n> [--tor-bin <path> --tor-state <dir>]`
////   opens the database, starts the node and the HTTP server on
////   `127.0.0.1`, prints `listening 127.0.0.1:<port>` on stdout, and runs
////   until the VM is stopped. Port 0 asks the system for a free port, and
////   the line names the one it chose. With the two Tor options it then
////   starts the `reedwire-tor` sidecar, bootstraps it, hosts an onion
////   service that forwards to that port, and prints one more line,
////   `onion <host>.onion:80`, which is the address a daemon dials. The Tor
////   state directory holds the service's key, and its path must be short
////   enough for a Unix socket.
//// - `grant --db <path> --queues <n> --out <file>` creates a provisioning
////   grant allowing `n` queues and writes its 32-byte capability to `file`
////   with mode 0600. It refuses to overwrite a file and prints only the
////   path, never the capability.
////
//// Anything else prints a one-line message on stderr and exits with status
//// 1. The server listens on the loopback interface only, because the onion
//// service forwards to it and this program never serves a public address.
////
//// ## Flow
////
//// 1. `main` calls `parse` to turn the arguments into a `Command`, so a
////    malformed command line is rejected before anything is opened.
//// 2. `run` executes the command through `serve` or `grant`, and returns a
////    one-line failure message.
//// 3. `main` turns a failure into the exit status.

import argv
import core/capability
import core/time.{Instant}
import gleam/dict.{type Dict}
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import mailbox/http
import mailbox/internal/ffi_system
import mailbox/node
import mailbox/service
import mailbox/store
import primitives
import simplifile
import tor
import tor/address

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

/// Where the Tor sidecar lives and keeps its state.
pub type TorHosting {
  TorHosting(
    /// The `reedwire-tor` binary.
    binary: String,
    /// The sidecar's state directory, which holds the service key.
    state_dir: String,
  )
}

/// A parsed command line.
pub type Command {
  Serve(db: String, port: Int, tor: Option(TorHosting))
  Grant(db: String, queues: Int, out: String)
}

/// The entry point for `gleam run -m mailbox`.
pub fn main() -> Nil {
  let outcome = {
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
/// mailbox.parse(["serve", "--db", "m.db", "--port", "0"])
/// // -> Ok(Serve("m.db", 0, None))
/// mailbox.parse(["serve", "--db", "m.db", "--port", "0", "--tor-bin", "t"])
/// // -> Error("--tor-bin and --tor-state go together")
/// ```
pub fn parse(arguments: List(String)) -> Result(Command, String) {
  // The first word names the subcommand; its options are checked against
  // that subcommand's own list.
  case arguments {
    ["serve", ..rest] -> {
      use options <- result.try(
        pairs(rest, ["--db", "--port", "--tor-bin", "--tor-state"]),
      )
      use db <- result.try(required(options, "--db"))
      use port <- result.try(number(options, "--port", 0, 65_535))
      use tor <- result.try(tor_hosting(options))

      Ok(Serve(db:, port:, tor:))
    }

    ["grant", ..rest] -> {
      use options <- result.try(pairs(rest, ["--db", "--queues", "--out"]))
      use db <- result.try(required(options, "--db"))
      use queues <- result.try(number(options, "--queues", 1, 1_000_000))
      use out <- result.try(required(options, "--out"))

      Ok(Grant(db:, queues:, out:))
    }

    _ ->
      Error(
        "usage: serve --db <path> --port <n> [--tor-bin <path> --tor-state <dir>] | grant --db <path> --queues <n> --out <file>",
      )
  }
}

/// The Tor options, which are given both or neither: a binary without a
/// state directory has nowhere to keep the service key.
fn tor_hosting(
  options: Dict(String, String),
) -> Result(Option(TorHosting), String) {
  // Each option is present or absent, so there are four combinations and
  // only two of them are meaningful.
  case dict.get(options, "--tor-bin"), dict.get(options, "--tor-state") {
    Error(Nil), Error(Nil) -> Ok(None)
    Ok(binary), Ok(state_dir) -> Ok(Some(TorHosting(binary:, state_dir:)))
    _, _ -> Error("--tor-bin and --tor-state go together")
  }
}

/// Reads `--name value` pairs, rejecting an unknown or repeated name and a
/// name without a value.
fn pairs(
  arguments: List(String),
  allowed: List(String),
) -> Result(Dict(String, String), String) {
  // Each step takes one name and its value; a lone trailing word has no
  // value to pair with.
  case arguments {
    [] -> Ok(dict.new())

    [name, value, ..rest] ->
      case list.contains(allowed, name) {
        False -> Error("unknown option " <> name)

        True -> {
          use options <- result.try(pairs(rest, allowed))

          // The rest was read first, so a name already in it is a repeat.
          case dict.has_key(options, name) {
            True -> Error("repeated option " <> name)
            False -> Ok(dict.insert(options, name, value))
          }
        }
      }

    [name] -> Error("missing value for " <> name)
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
    Grant(db:, queues:, out:) -> grant(db, queues, out)
  }
}

/// Starts the node and the server, announces the port and never returns.
fn serve(
  db: String,
  port: Int,
  hosting: Option(TorHosting),
) -> Result(Nil, String) {
  let started =
    node.start(node.Config(
      path: db,
      sweep_period_ms:,
      clock: fn() { Instant(ffi_system.unix_seconds()) },
      names: node.new_names(),
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

  // The onion line follows the listening line, so a reader that stops at
  // the first line still gets the port it needs.
  use Nil <- result.try(case hosting {
    None -> Ok(Nil)

    Some(hosting) -> {
      use host <- result.map(host_onion(hosting, server.port))
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
/// mailbox.host_onion(TorHosting("./reedwire-tor", "/tmp/mb-tor"), 8080)
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
  use Nil <- result.try(
    tor.bootstrap(started, bootstrap_timeout_ms)
    |> result.replace_error("Tor did not bootstrap"),
  )
  use onion <- result.try(
    tor.host_onion(started, "mailbox", local_port, host_timeout_ms)
    |> result.replace_error("the onion service could not be created"),
  )

  Ok(address.onion_host(onion.address) <> ":" <> int.to_string(onion_port))
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
  // Refusing here avoids recording a grant whose capability is never
  // written. The exclusive create below is the check that cannot race.
  use Nil <- result.try(case simplifile.is_file(out) {
    Ok(False) -> Ok(Nil)
    _ -> Error("refusing to overwrite " <> out)
  })

  use opened <- result.try(
    store.open(db) |> result.replace_error("the database could not be opened"),
  )
  let created = service.create_grant(opened, queues, primitives.random_bytes)
  let _ = store.close(opened)
  use provision <- result.try(result.replace_error(
    created,
    "the grant could not be created",
  ))

  // The exclusive create reports an existing file as `eexist`.
  case ffi_system.create_private_file(out, capability.expose(provision)) {
    Ok(Nil) -> {
      io.println(out)
      Ok(Nil)
    }

    Error("eexist") -> Error("refusing to overwrite " <> out)
    Error(reason) -> Error("could not write " <> out <> ": " <> reason)
  }
}
