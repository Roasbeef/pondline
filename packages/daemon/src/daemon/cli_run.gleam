//// Runs a parsed `pondline` command (spec §9.2).
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

import core/capability
import core/endpoint.{TorOnly, TorOrLoopback}
import core/grant
import core/limits
import core/secret
import daemon/build
import daemon/cli.{
  type Action, type Carrier, type Command, type Input, type Output, type Target,
  Client, CreateInvite, DaemonOptions, ExplicitMailbox, GrantMailbox, Help,
  HumanOutput, InitDaemon, InputFile, InputStdin, JsonOutput, Loopback, NoInput,
  RunDaemon, SavedMailbox, Tor, Version,
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
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/io
import gleam/json
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import simplifile

/// The largest input file `pondline` reads, in bytes. A payload is at most
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

    InitDaemon(init_cmd) -> run_init(init_cmd)
    RunDaemon(options) -> run_daemon(options)
    Client(target:, output:, action:) -> run_client(target, output, action)
  }
}

/// Starts the runtime and the local API, announces the socket and waits.
fn run_daemon(command: cli.DaemonCommand) -> Outcome {
  case resolve_daemon_options(command) {
    Error(outcome) -> outcome
    Ok(options) -> start_resolved_daemon(options)
  }
}

/// Boots a daemon whose mailbox endpoint and provisioning file are resolved.
fn start_resolved_daemon(options: cli.DaemonOptions) -> Outcome {
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

/// Runs `pondline init`: materializes `provision.cap`, `config.json`, and credentials.
fn run_init(command: cli.InitCommand) -> Outcome {
  let initialized = {
    use options <- result.try(materialize_and_save_config(
      command.state_dir,
      command.setup,
      command.carrier,
      command.tor_bin,
    ))
    use _credentials <- result.map(
      credential.ensure(command.state_dir)
      |> result.map_error(failure(cli.exit_local, _)),
    )
    options
  }

  // Render human confirmation or a structured JSON envelope.
  case initialized, command.output {
    Error(outcome), _ -> outcome
    Ok(options), HumanOutput -> {
      let line =
        "initialized "
        <> options.state_dir
        <> " for "
        <> options.mailbox
        <> " ("
        <> carrier_name(options.carrier)
        <> ")\n"
      Outcome(cli.exit_ok, <<line:utf8>>, "")
    }
    Ok(options), JsonOutput -> {
      let body =
        json.object([
          #("ok", json.bool(True)),
          #(
            "result",
            json.object([
              #("state_dir", json.string(options.state_dir)),
              #("mailbox", json.string(options.mailbox)),
              #("carrier", json.string(carrier_name(options.carrier))),
            ]),
          ),
        ])
        |> json.to_string
      Outcome(cli.exit_ok, <<body:utf8, "\n">>, "")
    }
  }
}

/// Resolves `DaemonCommand` into `DaemonOptions`, saving `<state_dir>/config.json`
/// when explicit or grant options were supplied and loading it on `SavedMailbox`.
fn resolve_daemon_options(
  command: cli.DaemonCommand,
) -> Result(cli.DaemonOptions, Outcome) {
  // SavedMailbox loads persisted config and applies optional CLI overrides;
  // ExplicitMailbox and GrantMailbox validate and persist fresh config first.
  case command.setup {
    SavedMailbox -> {
      use saved <- result.map(load_daemon_config(command.state_dir))
      let chosen_carrier = option.unwrap(command.carrier, saved.carrier)
      let chosen_tor = option.or(command.tor_bin, saved.tor_bin)
      DaemonOptions(..saved, carrier: chosen_carrier, tor_bin: chosen_tor)
    }

    ExplicitMailbox(..) | GrantMailbox(..) -> {
      let chosen_carrier = option.unwrap(command.carrier, Tor)
      materialize_and_save_config(
        command.state_dir,
        command.setup,
        chosen_carrier,
        command.tor_bin,
      )
    }
  }
}

/// Materializes `<state_dir>/provision.cap` and writes `<state_dir>/config.json` (0600).
fn materialize_and_save_config(
  state_dir: String,
  setup: cli.MailboxSetup,
  chosen_carrier: Carrier,
  tor_bin: Option(String),
) -> Result(cli.DaemonOptions, Outcome) {
  // Materialize or copy the capability into `<state_dir>/provision.cap`.
  use #(mailbox_text, provision_file) <- result.try(case setup {
    ExplicitMailbox(mailbox:, provision_file:) ->
      copy_provision_into_state_dir(state_dir, mailbox, provision_file)
    GrantMailbox(source:) -> {
      use raw <- result.try(read_input(source))
      apply_grant_token(state_dir, raw)
    }
    SavedMailbox -> Error(failure(cli.exit_usage, "missing setup input"))
  })

  use canonical_mailbox <- result.try(admit_mailbox_for_carrier(
    mailbox_text,
    chosen_carrier,
  ))
  use Nil <- result.map(write_config_file(
    state_dir,
    canonical_mailbox,
    chosen_carrier,
    tor_bin,
  ))
  DaemonOptions(
    state_dir:,
    mailbox: canonical_mailbox,
    provision_file:,
    carrier: chosen_carrier,
    tor_bin:,
  )
}

/// Validates a provisioning capability file and stores a self-contained 0600 copy in `state_dir`.
fn copy_provision_into_state_dir(
  state_dir: String,
  mailbox: String,
  source_file: String,
) -> Result(#(String, String), Outcome) {
  use bytes <- result.try(
    simplifile.read_bits(source_file)
    |> result.map_error(fn(_) {
      failure(
        cli.exit_unavailable,
        "the provisioning file is missing or malformed",
      )
    }),
  )
  use _cap <- result.try(
    capability.from_bytes(bytes)
    |> result.map_error(fn(_) {
      failure(
        cli.exit_unavailable,
        "the provisioning file is missing or malformed",
      )
    }),
  )
  use Nil <- result.try(prepare_private_state_dir(state_dir))
  let target_file = state_dir <> "/provision.cap"
  use Nil <- result.map(write_private_state_file(target_file, bytes))
  #(mailbox, target_file)
}

/// Verifies that `mailbox_text` parses and is permitted by `chosen_carrier`.
fn admit_mailbox_for_carrier(
  mailbox_text: String,
  chosen_carrier: Carrier,
) -> Result(String, Outcome) {
  use parsed <- result.try(
    endpoint.parse(mailbox_text)
    |> result.map_error(fn(_) {
      failure(
        cli.exit_refused,
        "--mailbox must be ONION:PORT or 127.0.0.1:PORT",
      )
    }),
  )

  // Map the CLI carrier flag onto the runtime carrier policy.
  let policy = case chosen_carrier {
    Tor -> TorOnly
    Loopback -> TorOrLoopback
  }

  use admitted <- result.map(
    endpoint.admit(parsed, policy)
    |> result.map_error(fn(_) {
      failure(cli.exit_refused, "loopback mailbox requires --carrier loopback")
    }),
  )
  endpoint.to_string(admitted)
}

/// Writes `<state_dir>/config.json` atomically with mode 0600.
fn write_config_file(
  state_dir: String,
  mailbox: String,
  chosen_carrier: Carrier,
  tor_bin: Option(String),
) -> Result(Nil, Outcome) {
  // Store an explicit `--tor-bin` only when supplied, leaving auto-discovery dynamic.
  let tor_json = case tor_bin {
    Some(path) -> json.string(path)
    None -> json.null()
  }

  let payload =
    json.object([
      #("v", json.int(1)),
      #("mailbox", json.string(mailbox)),
      #("carrier", json.string(carrier_name(chosen_carrier))),
      #("tor_bin", tor_json),
    ])
    |> json.to_string
  write_private_state_file(state_dir <> "/config.json", <<payload:utf8, "\n">>)
}

/// Loads `<state_dir>/config.json` and verifies `<state_dir>/provision.cap` exists.
///
/// ## Examples
///
/// ```gleam
/// cli_run.load_daemon_config("/nonexistent")
/// // -> Error(Outcome(6, <<>>, ...))
/// ```
pub fn load_daemon_config(
  state_dir: String,
) -> Result(cli.DaemonOptions, Outcome) {
  let config_path = state_dir <> "/config.json"
  let cap_path = state_dir <> "/provision.cap"
  use text <- result.try(
    simplifile.read(config_path)
    |> result.map_error(fn(_) {
      failure(
        cli.exit_unavailable,
        "no saved config in "
          <> state_dir
          <> "; run pondline init first or pass --mailbox/--provision-file or --grant-stdin",
      )
    }),
  )

  // Decode versioned fields with a total JSON decoder before checking admission.
  let decoder = {
    use version <- decode.field("v", decode.int)
    use mailbox <- decode.field("mailbox", decode.string)
    use carrier_str <- decode.field("carrier", decode.string)
    use tor_bin <- decode.optional_field(
      "tor_bin",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(version, mailbox, carrier_str, tor_bin))
  }
  use #(version, mailbox, carrier_str, tor_bin) <- result.try(
    json.parse(text, decoder)
    |> result.map_error(fn(_) {
      failure(cli.exit_unavailable, "malformed config in " <> config_path)
    }),
  )
  use chosen_carrier <- result.try(parse_saved_carrier(
    version,
    carrier_str,
    config_path,
  ))
  use canonical_mailbox <- result.try(admit_mailbox_for_carrier(
    mailbox,
    chosen_carrier,
  ))
  use _cap <- result.map(
    simplifile.read_bits(cap_path)
    |> result.map_error(fn(_) { Nil })
    |> result.try(capability.from_bytes)
    |> result.map_error(fn(_) {
      failure(cli.exit_unavailable, "missing or malformed " <> cap_path)
    }),
  )
  DaemonOptions(
    state_dir:,
    mailbox: canonical_mailbox,
    provision_file: cap_path,
    carrier: chosen_carrier,
    tor_bin:,
  )
}

/// Validates the schema version and carrier field from `config.json`.
fn parse_saved_carrier(
  version: Int,
  carrier_str: String,
  config_path: String,
) -> Result(Carrier, Outcome) {
  case version, carrier_str {
    1, "tor" -> Ok(Tor)
    1, "loopback" -> Ok(Loopback)
    _, _ ->
      Error(failure(
        cli.exit_unavailable,
        "unsupported version or carrier in " <> config_path,
      ))
  }
}

/// Canonical string name of a `Carrier`.
fn carrier_name(chosen_carrier: Carrier) -> String {
  case chosen_carrier {
    Tor -> "tor"
    Loopback -> "loopback"
  }
}

/// Creates `state_dir` with mode 0700.
fn prepare_private_state_dir(state_dir: String) -> Result(Nil, Outcome) {
  ffi_local_system.make_private_dir(state_dir)
  |> result.map_error(fn(reason) {
    failure(cli.exit_local, "could not prepare " <> state_dir <> ": " <> reason)
  })
}

/// Atomically writes `bytes` to `path` with mode 0600.
fn write_private_state_file(
  path: String,
  bytes: BitArray,
) -> Result(Nil, Outcome) {
  ffi_local_system.write_private_file(path, bytes)
  |> result.map_error(fn(reason) {
    failure(cli.exit_local, "could not write " <> path <> ": " <> reason)
  })
}

/// Decodes a `plg1...` grant token and persists its 32-byte provisioning
/// capability in `<state_dir>/provision.cap` with mode 0600.
///
/// ## Examples
///
/// ```gleam
/// cli_run.apply_grant_token("/tmp/pl", <<"not-a-grant":utf8>>)
/// // -> Error(Outcome(5, <<>>, ...))
/// ```
pub fn apply_grant_token(
  state_dir: String,
  raw: BitArray,
) -> Result(#(String, String), Outcome) {
  use text <- result.try(
    bit_array.to_string(raw)
    |> result.map_error(fn(_) {
      failure(cli.exit_refused, "the grant token is not text")
    }),
  )
  use token <- result.try(
    grant.decode(string.trim(text)) |> result.map_error(grant_decode_outcome),
  )
  use Nil <- result.try(
    ffi_local_system.make_private_dir(state_dir)
    |> result.map_error(fn(reason) {
      failure(
        cli.exit_local,
        "could not prepare " <> state_dir <> ": " <> reason,
      )
    }),
  )
  let provision_file = state_dir <> "/provision.cap"
  use Nil <- result.map(
    ffi_local_system.write_private_file(
      provision_file,
      capability.expose(grant.provision(token)),
    )
    |> result.map_error(fn(reason) {
      failure(
        cli.exit_local,
        "could not write " <> provision_file <> ": " <> reason,
      )
    }),
  )
  #(endpoint.to_string(grant.endpoint(token)), provision_file)
}

/// Maps a `GrantError` to a clean refusal outcome without echoing input text.
fn grant_decode_outcome(error: grant.GrantError) -> Outcome {
  // Translate each decode failure into operator guidance without echoing input.
  let reason = case error {
    grant.NotAGrant -> "the input is not a plg1 grant token"
    grant.BadChecksum -> "the grant token checksum failed; check for typos"
    grant.UnknownFormat -> "the grant token uses an unsupported format"
    grant.BadPayload -> "the grant token payload is malformed"
  }

  failure(cli.exit_refused, reason)
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
  // `$(pondline invite create ... --ticket)` captures the ticket alone.
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
  Outcome(status, <<>>, "pondline: " <> message)
}
