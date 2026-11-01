//// Runs a parsed `reedwire` command (spec §9.2).
////
//// `daemon/cli` decides what the user asked for; this module does the
//// effects: reading the credential and the payload, talking to the daemon
//// over its socket, writing an invitation file, or starting the daemon
//// itself. It returns an `Outcome`, the bytes and exit status, instead of
//// printing, so the entry point owns all output and the exit.
////
//// ## Flow
////
//// 1. `attempt` is a client command's path. It first calls
////    `check_output_file`: an invitation output file must not exist,
////    because the daemon would otherwise mint an invitation that could not
////    be saved.
//// 2. It reads the credential from its file and the command's one input
////    through `read_input`, from a file or standard input. The credential
////    never passes through argv and is never printed.
//// 3. It sends one request and maps the answer to output and an exit
////    status: a failed response to its category's code, an unreachable
////    daemon to 6.
//// 4. `hand_out_invitation` writes the invitation `invite create` got back
////    to its file with mode 0600 and prints only the path, so the
////    invitation never reaches a terminal or a log. With `--ticket` it
////    prints the ticket instead (ADR-009): the short string is meant to be
////    copied, and standard output is the operator's own, not argv or a log.
////
//// The daemon command goes through `run_daemon`, which starts the runtime
//// by way of the backend module, serves the local API and then waits
//// forever.

import core/limits
import core/secret
import daemon/build
import daemon/cli.{
  type Action, type Command, type Input, type Output, type Target, Client,
  CreateInvite, Help, InputFile, InputStdin, JsonOutput, NoInput, RunDaemon,
  Version,
}
import daemon/cli_render
import daemon/credential
import daemon/internal/ffi_local_system
import daemon/local_api
import daemon/local_api_backend
import daemon/local_api_client.{CannotConnect, ConnectionFailed, MalformedReply}
import daemon/local_api_protocol as protocol
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process
import gleam/io
import gleam/json
import gleam/option.{None, Some}
import gleam/result
import simplifile

/// The largest input file `reedwire` reads, in bytes. A payload is at most
/// `limits.max_body_bytes` and an invitation file is far smaller, so this
/// bound only stops a mistaken path from filling memory.
const max_input_bytes = 1_048_576

/// What a command produced.
pub type Outcome {
  Outcome(status: Int, stdout: BitArray, stderr: String)
}

/// Runs a command to completion. The `daemon` command does not return.
///
/// ## Examples
///
/// ```gleam
/// cli_run.run(Help)
/// // -> Outcome(0, <<usage text>>, "")
/// ```
pub fn run(command: Command) -> Outcome {
  case command {
    Help -> Outcome(cli.exit_ok, <<cli.usage:utf8, "\n">>, "")

    // The identity is the launcher's, so `--version` needs no daemon.
    Version ->
      Outcome(cli.exit_ok, <<build.describe(build.current()):utf8, "\n">>, "")

    RunDaemon(options) -> run_daemon(options)
    Client(target:, output:, action:) -> run_client(target, output, action)
  }
}

/// Starts the runtime and the local API, announces the socket and waits.
fn run_daemon(options: cli.DaemonOptions) -> Outcome {
  let started = {
    use credentials <- result.try(credential.ensure(options.state_dir))
    use backend <- result.try(local_api_backend.start_node(options))

    let socket = options.state_dir <> "/api.sock"
    use _server <- result.try(local_api.start(backend, credentials, socket))

    Ok(socket)
  }

  // Success announces the socket and waits; failure is a startup error.
  case started {
    Ok(socket) -> {
      io.println("ready " <> socket)
      process.sleep_forever()

      Outcome(cli.exit_ok, <<>>, "")
    }

    Error(message) -> failure(cli.exit_unavailable, message)
  }
}

/// Runs one client command.
fn run_client(target: Target, output: Output, action: Action) -> Outcome {
  case attempt(target, output, action) {
    Ok(outcome) -> outcome
    Error(outcome) -> outcome
  }
}

/// The steps of a client command, ending early with a failure outcome.
fn attempt(
  target: Target,
  output: Output,
  action: Action,
) -> Result(Outcome, Outcome) {
  use Nil <- result.try(check_output_file(action))
  use credential <- result.try(
    credential.read(target.credential_file)
    |> result.map_error(failure(cli.exit_unauthorized, _)),
  )
  use input <- result.try(read_input(cli.input_of(action)))
  use Nil <- result.try(check_ticket_text(action, input))

  let #(op, args) = cli.request(action, input)

  // This is the one place the credential's bytes leave this module: onto
  // the socket the daemon owns, base64-encoded by the client.
  use #(line, response) <- result.try(
    local_api_client.exchange(
      target.socket,
      secret.expose(credential),
      op,
      args,
      cli.timeout_ms(action),
    )
    |> result.map_error(unreachable(_, target.socket)),
  )

  // A refusal maps to its category's exit status, and a success is rendered.
  case response {
    protocol.Failed(category:, message:) ->
      Ok(failed(output, line, category, message))

    protocol.Succeeded(result:) -> succeeded(output, action, line, result)
  }
}

/// Refuses a ticket input that is not text before the daemon is asked. A
/// ticket is ASCII, so such input is usually an invitation file given
/// without dropping `--ticket`; the refusal does not repeat it.
fn check_ticket_text(action: Action, input: BitArray) -> Result(Nil, Outcome) {
  // Only a ticket accept reads its input as text.
  case action, bit_array.to_string(input) {
    cli.AcceptInvite(form: cli.FromTicket, ..), Error(Nil) ->
      Error(failure(
        cli.exit_refused,
        "the ticket is not text; an invitation file is accepted without --ticket",
      ))

    _, _ -> Ok(Nil)
  }
}

/// Refuses an invitation output file that already exists.
fn check_output_file(action: Action) -> Result(Nil, Outcome) {
  // Only `invite create` writes a file, and only when it was given one.
  case action {
    CreateInvite(output:, ..) ->
      case cli.invitation_path(output) {
        Some(out) ->
          case simplifile.is_file(out) {
            Ok(False) -> Ok(Nil)
            _ ->
              Error(failure(cli.exit_refused, "refusing to overwrite " <> out))
          }

        None -> Ok(Nil)
      }

    _ -> Ok(Nil)
  }
}

/// Reads a command's one input, bounded.
fn read_input(input: Input) -> Result(BitArray, Outcome) {
  // Each input source reads differently, and none is read without a bound.
  case input {
    NoInput -> Ok(<<>>)

    InputStdin ->
      ffi_local_system.read_stdin(limits.max_body_bytes)
      |> result.map_error(fn(reason) {
        case reason {
          "too_large" -> failure(cli.exit_refused, "the input is too large")
          _ -> failure(cli.exit_local, "could not read standard input")
        }
      })

    InputFile(path) -> {
      use info <- result.try(
        simplifile.file_info(path)
        |> result.map_error(unreadable(path, _)),
      )

      // A file over the bound is refused before it is read into memory.
      case info.size > max_input_bytes {
        True -> Error(failure(cli.exit_refused, path <> " is too large"))

        False ->
          simplifile.read_bits(path)
          |> result.map_error(unreadable(path, _))
      }
    }
  }
}

/// A failure to read an input file.
fn unreadable(path: String, error: simplifile.FileError) -> Outcome {
  failure(
    cli.exit_local,
    "could not read " <> path <> ": " <> simplifile.describe_error(error),
  )
}

/// The outcome for a daemon that could not be reached.
fn unreachable(error: local_api_client.ClientError, socket: String) -> Outcome {
  // Each way of getting no answer has its own message, and all of them exit with the same status.
  let reason = case error {
    CannotConnect(reason:) ->
      "cannot reach the daemon at " <> socket <> ": " <> reason
    ConnectionFailed(reason:) ->
      "the connection to the daemon failed: " <> reason
    MalformedReply -> "the daemon sent a malformed reply"
  }

  failure(cli.exit_unavailable, reason)
}

/// The outcome for a response that said no.
fn failed(
  output: Output,
  line: String,
  category: protocol.Category,
  message: String,
) -> Outcome {
  let status = cli.exit_code(category)

  // JSON mode repeats the response line for a program, and human mode prints one line on standard error.
  case output {
    JsonOutput -> Outcome(status, <<line:utf8, "\n">>, "")

    _ -> failure(status, protocol.category_name(category) <> ": " <> message)
  }
}

/// The outcome for a response that said yes.
fn succeeded(
  output: Output,
  action: Action,
  line: String,
  result: Dynamic,
) -> Result(Outcome, Outcome) {
  case action, output {
    CreateInvite(output: handed, ..), _ ->
      hand_out_invitation(output, handed, result)

    _, JsonOutput -> Ok(Outcome(cli.exit_ok, <<line:utf8, "\n">>, ""))

    _, _ ->
      cli_render.render(action, result)
      |> result.map(fn(rendered) {
        Outcome(cli.exit_ok, rendered.stdout, rendered.stderr)
      })
      |> result.map_error(failure(cli.exit_unavailable, _))
  }
}

/// Hands out what `invite create` asked for: the file, the ticket, or
/// both. The ticket is printed on standard output, alone on its line in
/// human mode, and when a file is also written its path goes to standard
/// error so the ticket can be captured by itself.
fn hand_out_invitation(
  output: Output,
  handed: cli.InviteOutput,
  result: Dynamic,
) -> Result(Outcome, Outcome) {
  // A file that was asked for is written before the ticket is printed, so
  // a failed write prints nothing.
  case handed {
    cli.InvitationFile(path:) -> save_invitation(output, path, result)

    cli.TicketOnly -> {
      use ticket <- result.try(read_ticket(result))
      Ok(ticket_outcome(output, ticket, None))
    }

    cli.TicketAndFile(path:) -> {
      use ticket <- result.try(read_ticket(result))
      use _ <- result.try(save_invitation(output, path, result))
      Ok(ticket_outcome(output, ticket, Some(path)))
    }
  }
}

/// The ticket of a result, or the outcome of a malformed one.
fn read_ticket(result: Dynamic) -> Result(String, Outcome) {
  cli_render.ticket(result)
  |> result.map_error(failure(cli.exit_unavailable, _))
}

/// What a command that printed a ticket answers: in JSON the ticket and
/// any written path; in human mode the ticket alone on standard output and
/// the path, if any, on standard error.
fn ticket_outcome(
  output: Output,
  ticket: String,
  path: option.Option(String),
) -> Outcome {
  // JSON carries both facts in one answer; human output separates them so
  // `$(reedwire invite create ... --ticket)` captures the ticket alone.
  case output {
    JsonOutput -> {
      let fields = [
        #("ticket", json.string(ticket)),
        #("out", json.nullable(path, json.string)),
      ]

      Outcome(
        cli.exit_ok,
        <<protocol.success_json(json.object(fields)):utf8, "\n">>,
        "",
      )
    }

    _ ->
      Outcome(cli.exit_ok, <<ticket:utf8, "\n">>, case path {
        Some(written) -> "wrote " <> written
        None -> ""
      })
  }
}

/// Writes the invitation to its file, readable only by its owner, and
/// prints the path alone. The invitation is a bearer offer to pair, so it
/// goes to the file and never to the terminal, in either output mode.
fn save_invitation(
  output: Output,
  out: String,
  result: Dynamic,
) -> Result(Outcome, Outcome) {
  use bytes <- result.try(
    cli_render.invitation(result)
    |> result.map_error(failure(cli.exit_unavailable, _)),
  )
  use Nil <- result.try(
    ffi_local_system.create_private_file(out, bytes)
    |> result.map_error(fn(reason) {
      case reason {
        "eexist" -> failure(cli.exit_refused, "refusing to overwrite " <> out)
        _ ->
          failure(cli.exit_local, "could not write " <> out <> ": " <> reason)
      }
    }),
  )

  // JSON mode answers with the written path as a response, and human mode prints it as text.
  case output {
    JsonOutput ->
      Ok(Outcome(
        cli.exit_ok,
        <<
          protocol.success_json(json.object([#("out", json.string(out))])):utf8,
          "\n",
        >>,
        "",
      ))

    _ -> Ok(Outcome(cli.exit_ok, <<"wrote ", out:utf8, "\n">>, ""))
  }
}

/// An outcome with a message for standard error and nothing on standard
/// output.
fn failure(status: Int, message: String) -> Outcome {
  Outcome(status, <<>>, "reedwire: " <> message)
}
