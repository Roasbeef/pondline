//// The mailbox command line (spec §6, §10.2).
////
//// Run it with `gleam run -m mailbox -- <subcommand> ...`:
////
//// - `serve --db <path> --port <n>` opens the database, starts the node and
////   the HTTP server on `127.0.0.1`, prints `listening 127.0.0.1:<port>` on
////   stdout, and runs until the VM is stopped. Port 0 asks the system for a
////   free port, and the line names the one it chose.
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
import gleam/result
import mailbox/http
import mailbox/internal/ffi_system
import mailbox/node
import mailbox/service
import mailbox/store
import primitives
import simplifile

/// The interface the server binds. It is not configurable.
const loopback = "127.0.0.1"

/// Milliseconds between expiry sweeps of a running node.
const sweep_period_ms = 60_000

/// A parsed command line.
type Command {
  Serve(db: String, port: Int)
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
fn parse(arguments: List(String)) -> Result(Command, String) {
  // The first word names the subcommand; its options are checked against
  // that subcommand's own list.
  case arguments {
    ["serve", ..rest] -> {
      use options <- result.try(pairs(rest, ["--db", "--port"]))
      use db <- result.try(required(options, "--db"))
      use port <- result.try(number(options, "--port", 0, 65_535))

      Ok(Serve(db:, port:))
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
        "usage: serve --db <path> --port <n> | grant --db <path> --queues <n> --out <file>",
      )
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
    Serve(db:, port:) -> serve(db, port)
    Grant(db:, queues:, out:) -> grant(db, queues, out)
  }
}

/// Starts the node and the server, announces the port and never returns.
fn serve(db: String, port: Int) -> Result(Nil, String) {
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
  process.sleep_forever()

  Ok(Nil)
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
