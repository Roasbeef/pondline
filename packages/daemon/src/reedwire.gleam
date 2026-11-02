//// The `reedwire` command: the client daemon and its command line.
////
//// Run it with `gleam run -m reedwire -- <command> ...`. `daemon/cli`
//// documents the commands and the exit codes. This module only wires the
//// pieces: it reads the arguments and the one environment variable
//// `REEDWIRE_CREDENTIAL_FILE`, parses them, runs the command and turns the
//// result into output and an exit status.

import argv
import daemon/cli
import daemon/cli_run.{type Outcome}
import daemon/internal/ffi_local_system
import gleam/io
import gleam/option
import gleam/result
import telemetry/handler

/// The entry point for `gleam run -m reedwire`.
pub fn main() -> Nil {
  let environment =
    ffi_local_system.getenv("REEDWIRE_CREDENTIAL_FILE")
    |> result.try(fn(path) {
      case path {
        "" -> Error(Nil)
        _ -> Ok(path)
      }
    })
    |> option.from_result

  // The handler goes in before anything can crash: a daemon's crash report,
  // and a command's, holds payloads and keys that only the scrubbed
  // formatter on standard error keeps out of the output (ADR-012). Standard
  // output stays the command's own. A VM that cannot install it does not
  // run.
  let installed = handler.install_from_env()

  // A parsed command runs, and a usage error is reported with the usage text.
  case installed, cli.parse(argv.load().arguments, environment) {
    Error(Nil), _ ->
      emit(cli_run.Outcome(
        cli.exit_local,
        <<>>,
        "reedwire: the log handler could not be installed",
      ))

    Ok(_), Ok(command) -> emit(cli_run.run(command))

    Ok(_), Error(message) ->
      emit(cli_run.Outcome(
        cli.exit_usage,
        <<>>,
        "reedwire: " <> message <> "\n" <> cli.usage,
      ))
  }
}

/// Writes an outcome's output and exits with its status.
fn emit(outcome: Outcome) -> Nil {
  // Standard output is written first and as raw bytes, so a payload is
  // never re-encoded.
  let _ = ffi_local_system.write_stdout(outcome.stdout)

  // Standard error is written only when there is something to say.
  case outcome.stderr {
    "" -> Nil
    message -> io.println_error(message)
  }

  // Success returns normally, and any other status halts the VM with it.
  case outcome.status {
    0 -> Nil
    status -> ffi_local_system.halt(status)
  }
}
