//// The `pondline` command line, parsed (spec §9.2).
////
//// This module is pure: it turns arguments into a `Command` and a `Command`
//// into the request it sends, and touches no file, socket or environment
//// variable. `daemon/cli_run` does the effects and `daemon/cli_render`
//// prints the answers.
////
//// ## Flow
////
//// 1. `parse` and `parse_with_env` dispatch on the leading command words to `parse_init`, `parse_daemon`, `client`, `parse_send`, or `parse_receive`.
//// 2. `read_options` scans `--name value` pairs and flags, rejecting unknown options or stray arguments through `unknown`.
//// 3. `target` resolves the Unix socket and credential path from options and the environment.
//// 4. `request` and `timeout_ms` turn a parsed `Action` and its input bytes into the local API call.
////
//// ## Commands
////
//// - `init (--stdin | --file F | --mailbox HOST:PORT --provision-file F)`
////   `[--state-dir D] [--carrier tor|loopback] [--tor-bin PATH] [--json]`
////   initializes a state directory (`~/.pondline` by default) and writes `config.json`.
//// - `daemon [--state-dir D] [--mailbox HOST:PORT --provision-file F | --grant-file F | --grant-stdin]`
////   `[--carrier tor|loopback] [--tor-bin PATH]` runs the daemon.
//// - `invite create --description TEXT --budget N [--auto-approve]`
////   `[--out FILE] [--ticket]` (at least one of the two) and `invite accept`
////   `[--ticket] (--file FILE | --stdin) [--description TEXT] [--budget N]`.
//// - `contacts list`, `contact approve|decline|close --contact CONTACT` and
////   `contact budget --contact CONTACT --add N`.
//// - `send --contact CONTACT [--content-type T] (--file F | --stdin)`
////   `[--reply-to HEX] [--idempotency-key KEY]`.
//// - `receive [--contact CONTACT] [--max N] [--wait SECONDS] [--raw]`.
//// - `ack --message HEX`, `status --message HEX`, `audit [--contact CONTACT]`
////   `[--limit N]`, `incidents [--limit N]` and `health`.
//// - `--version` prints the build's version and commit.
////
//// Every client command also takes `--state-dir D` or `--socket P` to find
//// the daemon, `--credential-file F` to name the credential (default
//// `D/operator.cred`, or the `PONDLINE_CREDENTIAL_FILE` variable) and
//// `--json` for machine-readable output.
////
//// ## Exit codes
////
//// 0 success; 1 a local failure such as an unreadable file; 2 a usage
//// error; 3 unauthorized or forbidden; 4 not found; 5 refused, invalid or
//// too large; 6 the daemon is unavailable or unreachable.
////
//// ## What argv never carries
////
//// A payload, a credential and a ticket are secrets, and a command line is
//// visible to every process on the machine and kept in shell history. So no
//// option takes one: payloads and tickets come from `--file` or `--stdin`,
//// credentials from a file. An option such as `--payload` or `--credential`
//// is unknown and fails as a usage error, and `--ticket` is a flag, so a
//// ticket typed after it is a stray word. A stray word is refused without
//// being repeated, since it may be exactly the secret that was misplaced.

import core/id.{type Contact, type Id, type Message}
import core/limits
import core/offer.{type Approval, AutoApprove, OperatorApproves}
import daemon/local_api_protocol as protocol
import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string

/// The exit status of a command that succeeded.
pub const exit_ok = 0

/// The exit status of a local failure such as an unreadable file.
pub const exit_local = 1

/// The exit status of a usage error.
pub const exit_usage = 2

/// The exit status when the credential is missing, wrong or too weak.
pub const exit_unauthorized = 3

/// The exit status when a contact or message does not exist.
pub const exit_not_found = 4

/// The exit status when the daemon refused or rejected the request.
pub const exit_refused = 5

/// The exit status when the daemon cannot be reached or cannot serve.
pub const exit_unavailable = 6

/// The text printed for `help` and for a usage error.
pub const usage =
  "usage: pondline <command> [options]

commands:
  init (--stdin | --file F | --mailbox HOST:PORT --provision-file F)
       [--state-dir D] [--carrier tor|loopback] [--tor-bin PATH] [--json]
  daemon [--state-dir D] [--mailbox HOST:PORT --provision-file F | --grant-file F | --grant-stdin]
         [--carrier tor|loopback] [--tor-bin PATH]
  invite create --description TEXT --budget N [--auto-approve]
                [--out FILE] [--ticket]
  invite accept [--ticket] (--file FILE | --stdin) [--description TEXT] [--budget N]
  contacts list
  contact approve|decline|close --contact CONTACT
  contact budget --contact CONTACT --add N
  send --contact CONTACT [--content-type T] (--file F | --stdin) [--reply-to HEX]
       [--idempotency-key KEY]
  receive [--contact CONTACT] [--max N] [--wait SECONDS] [--raw]
  ack --message HEX
  status --message HEX
  audit [--contact CONTACT] [--limit N]
  incidents [--limit N]
  health
  --version

client options: --state-dir D (default ~/.pondline or $PONDLINE_STATE_DIR) | --socket P, --credential-file F, --json
exit codes: 0 ok, 1 local failure, 2 usage, 3 unauthorized or forbidden,
            4 not found, 5 refused or invalid, 6 unavailable"

/// How the daemon reaches mailboxes.
pub type Carrier {
  Tor
  Loopback
}

/// Environment defaults read once by the entry point and passed into `parse_with_env`.
pub type Environment {
  Environment(
    credential_file: Option(String),
    default_state_dir: Option(String),
  )
}

/// Where `pondline init` or `pondline daemon` obtains its mailbox and provisioning capability.
pub type MailboxSetup {
  /// Explicit `--mailbox HOST:PORT --provision-file F`.
  ExplicitMailbox(mailbox: String, provision_file: String)

  /// A `plg1...` grant token read from a file or standard input.
  GrantMailbox(source: Input)

  /// Load `<state_dir>/config.json` and `<state_dir>/provision.cap` written earlier.
  SavedMailbox
}

/// The parsed `pondline init` command.
pub type InitCommand {
  InitCommand(
    state_dir: String,
    setup: MailboxSetup,
    carrier: Carrier,
    tor_bin: Option(String),
    output: Output,
  )
}

/// The parsed `pondline daemon` command before config/grant resolution.
pub type DaemonCommand {
  DaemonCommand(
    state_dir: String,
    setup: MailboxSetup,
    carrier: Option(Carrier),
    tor_bin: Option(String),
  )
}

/// The resolved startup options passed to `local_api_backend.start_node`.
pub type DaemonOptions {
  DaemonOptions(
    state_dir: String,
    /// The mailbox as `HOST:PORT` or `ONION:PORT`.
    mailbox: String,
    provision_file: String,
    carrier: Carrier,
    tor_bin: Option(String),
  )
}

/// How a command prints its answer.
pub type Output {
  HumanOutput
  JsonOutput
}

/// Where a client command finds the daemon and its credential.
pub type Target {
  Target(socket: String, credential_file: String)
}

/// Where a command reads its one input from.
pub type Input {
  NoInput
  InputFile(path: String)
  InputStdin
}

/// What `invite create` hands the operator: the invitation file, a ticket
/// printed on standard output (ADR-009), or both. Asking for neither is a
/// usage error, so there is no variant for it.
pub type InviteOutput {
  /// Write the invitation file.
  InvitationFile(path: String)

  /// Print the ticket.
  TicketOnly

  /// Write the file and print the ticket.
  TicketAndFile(path: String)
}

/// What `invite accept` reads from its input.
pub type AcceptForm {
  /// The bytes of an invitation file.
  FromInvitation

  /// A ticket's text, fetched and opened by the daemon.
  FromTicket
}

/// How `receive` prints a payload.
pub type PayloadView {
  /// Base64 inside the output, with the delivery's metadata.
  Encoded

  /// The one message's bytes alone on standard output.
  Raw
}

/// How `--contact` names a relationship on the CLI: either a full 32-digit hex
/// identifier (sent directly) or a description/petname or >=4-char hex prefix
/// resolved against `contacts` before the command runs.
pub type ContactRef {
  /// Full 32-digit hex contact identifier.
  ExactContact(contact: Id(Contact))

  /// Description/petname or hex prefix resolved against `contacts`.
  LookupContact(query: String)
}

/// One row from `contacts` used to resolve `LookupContact` selectors purely.
pub type ContactEntry {
  ContactEntry(contact: Id(Contact), phase: String, description: String)
}

/// What a client command asks the daemon to do.
pub type Action {
  CreateInvite(
    description: String,
    approval: Approval,
    budget: Int,
    output: InviteOutput,
  )
  AcceptInvite(
    source: Input,
    form: AcceptForm,
    description: String,
    budget: Option(Int),
  )
  ListContacts
  ApproveContact(contact: ContactRef)
  DeclineContact(contact: ContactRef)
  CloseContact(contact: ContactRef)
  RaiseBudget(contact: ContactRef, add: Int)
  SendMessage(
    contact: ContactRef,
    content_type: String,
    source: Input,
    in_reply_to: Option(Id(Message)),
    idempotency_key: Option(String),
  )
  ReceiveMessages(
    contact: Option(ContactRef),
    max: Int,
    wait_seconds: Int,
    view: PayloadView,
  )
  Acknowledge(message: Id(Message))
  MessageStatus(message: Id(Message))
  ShowAudit(contact: Option(ContactRef), limit: Int)
  ShowIncidents(limit: Int)
  ShowHealth
}

/// A parsed command line.
pub type Command {
  InitDaemon(InitCommand)
  RunDaemon(DaemonCommand)
  Client(target: Target, output: Output, action: Action)
  Help

  /// Print the build's version and commit (`daemon/build`) and exit.
  Version
}

/// The options found on a command line.
type Options {
  Options(values: Dict(String, String), flags: List(String))
}

/// Turns arguments into a command, or a one-line usage error.
/// `env_credential_file` is the value of `PONDLINE_CREDENTIAL_FILE`, which
/// the caller reads because this module reads nothing.
///
/// ## Examples
///
/// ```gleam
/// cli.parse(["health", "--state-dir", "/var/lib/pondline"], None)
/// // -> Ok(Client(Target("/var/lib/pondline/api.sock",
/// //      "/var/lib/pondline/operator.cred"), HumanOutput, ShowHealth))
/// cli.parse(["send", "--payload", "hi"], None)
/// // -> Error("unknown option --payload")
/// ```
pub fn parse(
  arguments: List(String),
  env_credential_file: Option(String),
) -> Result(Command, String) {
  parse_with_env(
    arguments,
    Environment(credential_file: env_credential_file, default_state_dir: None),
  )
}

/// Turns arguments and resolved environment defaults (`PONDLINE_CREDENTIAL_FILE`,
/// `PONDLINE_STATE_DIR` / `$HOME/.pondline`) into a `Command`.
///
/// ## Examples
///
/// ```gleam
/// cli.parse_with_env(["health"], cli.Environment(None, Some("/home/a/.pondline")))
/// // -> Ok(Client(Target("/home/a/.pondline/api.sock", "/home/a/.pondline/operator.cred"), ...))
/// ```
pub fn parse_with_env(
  arguments: List(String),
  env: Environment,
) -> Result(Command, String) {
  // The leading words name the command; its options are checked against
  // that command's own list, so an option valid for one is unknown to the
  // rest.
  case arguments {
    ["help"] | ["--help"] -> Ok(Help)

    ["--version"] | ["version"] -> Ok(Version)

    ["init", ..rest] -> parse_init(rest, env)

    ["daemon", ..rest] -> parse_daemon(rest, env)

    ["invite", "create", ..rest] ->
      client(
        rest,
        env,
        ["--description", "--budget", "--out"],
        ["--auto-approve", "--ticket"],
        fn(options) {
          use description <- result.try(required(options, "--description"))
          use budget <- result.try(number(
            options,
            "--budget",
            1,
            limits.max_budget_messages,
          ))
          use output <- result.try(invite_output(options))
          let approval = approval_of(options)

          Ok(CreateInvite(description:, approval:, budget:, output:))
        },
      )

    ["invite", "accept", ..rest] ->
      client(
        rest,
        env,
        ["--file", "--description", "--budget"],
        ["--stdin", "--ticket"],
        fn(options) {
          use source <- result.try(one_source(options))
          use budget <- result.try(optional_present_number(
            options,
            "--budget",
            1,
            limits.max_budget_messages,
          ))
          let description = dict_get(options, "--description", "")

          // `--ticket` says what the input is; it never carries it.
          let form = case has_flag(options, "--ticket") {
            True -> FromTicket
            False -> FromInvitation
          }

          Ok(AcceptInvite(source:, form:, description:, budget:))
        },
      )

    ["contacts", "list", ..rest] ->
      client(rest, env, [], [], fn(_) { Ok(ListContacts) })

    ["contact", "approve", ..rest] ->
      client(rest, env, ["--contact"], [], fn(options) {
        result.map(contact(options), ApproveContact)
      })

    ["contact", "decline", ..rest] ->
      client(rest, env, ["--contact"], [], fn(options) {
        result.map(contact(options), DeclineContact)
      })

    ["contact", "close", ..rest] ->
      client(rest, env, ["--contact"], [], fn(options) {
        result.map(contact(options), CloseContact)
      })

    ["contact", "budget", ..rest] ->
      client(rest, env, ["--contact", "--add"], [], fn(options) {
        use contact <- result.try(contact(options))
        use add <- result.try(number(
          options,
          "--add",
          1,
          limits.max_budget_messages,
        ))

        Ok(RaiseBudget(contact:, add:))
      })

    ["send", ..rest] -> parse_send(rest, env)

    ["receive", ..rest] -> parse_receive(rest, env)

    ["ack", ..rest] ->
      client(rest, env, ["--message"], [], fn(options) {
        result.map(message(options), Acknowledge)
      })

    ["status", ..rest] ->
      client(rest, env, ["--message"], [], fn(options) {
        result.map(message(options), MessageStatus)
      })

    ["audit", ..rest] ->
      client(rest, env, ["--contact", "--limit"], [], fn(options) {
        use contact <- result.try(optional_contact(options))
        use limit <- result.try(optional_number(options, "--limit", 50, 1, 256))

        Ok(ShowAudit(contact:, limit:))
      })

    ["incidents", ..rest] ->
      client(rest, env, ["--limit"], [], fn(options) {
        use limit <- result.try(optional_number(options, "--limit", 50, 1, 256))

        Ok(ShowIncidents(limit:))
      })

    ["health", ..rest] -> client(rest, env, [], [], fn(_) { Ok(ShowHealth) })

    _ -> Error("unknown command")
  }
}

/// The approval mode `--auto-approve` asks for. Without it the operator
/// approves, which is the safe default.
fn approval_of(options: Options) -> Approval {
  // The flag is a presence test, so there are exactly two modes.
  case has_flag(options, "--auto-approve") {
    True -> AutoApprove
    False -> OperatorApproves
  }
}

/// Where `invite create` puts the invitation: a file, a ticket, or both.
fn invite_output(options: Options) -> Result(InviteOutput, String) {
  // The two choices are independent flags; asking for neither is the one
  // combination with nothing to hand out.
  case dict.get(options.values, "--out"), has_flag(options, "--ticket") {
    Ok(path), False -> Ok(InvitationFile(path))
    Ok(path), True -> Ok(TicketAndFile(path))
    Error(Nil), True -> Ok(TicketOnly)
    Error(Nil), False -> Error("give --out FILE, --ticket, or both")
  }
}

/// The one input of a command that reads from exactly one of `--file`
/// and `--stdin`.
fn one_source(options: Options) -> Result(Input, String) {
  // With both the input would be ambiguous, and with neither there is none.
  case dict.get(options.values, "--file"), has_flag(options, "--stdin") {
    Ok(path), False -> Ok(InputFile(path))
    Error(Nil), True -> Ok(InputStdin)
    _, _ -> Error("give exactly one of --file and --stdin")
  }
}

/// Parses `send`. The payload comes from exactly one of `--file` and
/// `--stdin`, never from the command line.
fn parse_send(rest: List(String), env: Environment) -> Result(Command, String) {
  client(
    rest,
    env,
    ["--contact", "--content-type", "--file", "--reply-to", "--idempotency-key"],
    ["--stdin"],
    fn(options) {
      use contact <- result.try(contact(options))
      use in_reply_to <- result.try(optional_message(options, "--reply-to"))

      // A key makes the send safe to retry (ADR-011); the daemon checks it.
      let idempotency_key =
        dict.get(options.values, "--idempotency-key") |> option.from_result

      let content_type =
        dict_get(options, "--content-type", "application/octet-stream")
      let file = dict.get(options.values, "--file")

      // Exactly one source: with both the payload would be ambiguous, and
      // with neither there is none.
      case file, has_flag(options, "--stdin") {
        Ok(path), False ->
          Ok(SendMessage(
            contact:,
            content_type:,
            source: InputFile(path),
            in_reply_to:,
            idempotency_key:,
          ))

        Error(Nil), True ->
          Ok(SendMessage(
            contact:,
            content_type:,
            source: InputStdin,
            in_reply_to:,
            idempotency_key:,
          ))

        _, _ -> Error("give exactly one of --file and --stdin")
      }
    },
  )
}

/// Parses `receive`. `--raw` prints one message alone, so it fixes the
/// count at one and cannot combine with `--json` or `--max`.
fn parse_receive(
  rest: List(String),
  env: Environment,
) -> Result(Command, String) {
  client(rest, env, ["--contact", "--max", "--wait"], ["--raw"], fn(options) {
    use contact <- result.try(optional_contact(options))
    use max <- result.try(optional_number(options, "--max", 16, 1, 64))
    use wait_seconds <- result.try(optional_number(options, "--wait", 0, 0, 30))

    // Raw output has no framing, so it can carry one message and no
    // metadata, and it cannot be JSON.
    case has_flag(options, "--raw") {
      False -> Ok(ReceiveMessages(contact:, max:, wait_seconds:, view: Encoded))

      True ->
        case
          dict.has_key(options.values, "--max"),
          has_flag(options, "--json")
        {
          False, False ->
            Ok(ReceiveMessages(contact:, max: 1, wait_seconds:, view: Raw))

          _, _ ->
            Error("--raw prints one message; it takes neither --json nor --max")
        }
    }
  })
}

/// Parses `init`, which configures a state directory (`~/.pondline` by default)
/// from a `plg1...` grant token or explicit `--mailbox` + `--provision-file`.
fn parse_init(rest: List(String), env: Environment) -> Result(Command, String) {
  use options <- result.try(
    read_options(
      rest,
      [
        "--state-dir", "--mailbox", "--provision-file", "--grant-file", "--file",
        "--carrier", "--tor-bin",
      ],
      ["--grant-stdin", "--stdin", "--json"],
    ),
  )
  use state_dir <- result.try(resolve_state_dir(options, env.default_state_dir))
  use setup <- result.try(init_setup(options))
  use chosen_carrier <- result.try(carrier(options))

  // Select JSON or human confirmation output for `init`.
  let output = case has_flag(options, "--json") {
    True -> JsonOutput
    False -> HumanOutput
  }

  Ok(
    InitDaemon(InitCommand(
      state_dir:,
      setup:,
      carrier: chosen_carrier,
      tor_bin: option.from_result(dict.get(options.values, "--tor-bin")),
      output:,
    )),
  )
}

/// Parses `daemon`, allowing bare `pondline daemon` to load `<state_dir>/config.json`.
fn parse_daemon(
  rest: List(String),
  env: Environment,
) -> Result(Command, String) {
  use options <- result.try(
    read_options(
      rest,
      [
        "--state-dir", "--mailbox", "--provision-file", "--grant-file",
        "--carrier", "--tor-bin",
      ],
      ["--grant-stdin"],
    ),
  )
  use state_dir <- result.try(resolve_state_dir(options, env.default_state_dir))
  use setup <- result.try(daemon_setup(options))
  use explicit_carrier <- result.try(optional_carrier(options))

  Ok(
    RunDaemon(DaemonCommand(
      state_dir:,
      setup:,
      carrier: explicit_carrier,
      tor_bin: option.from_result(dict.get(options.values, "--tor-bin")),
    )),
  )
}

/// Resolves `--state-dir`, falling back to `default_state_dir` (`~/.pondline`).
fn resolve_state_dir(
  options: Options,
  default_dir: Option(String),
) -> Result(String, String) {
  case dict.get(options.values, "--state-dir"), default_dir {
    Ok(dir), _ -> Ok(dir)
    Error(Nil), Some(dir) -> Ok(dir)
    Error(Nil), None -> Error("missing option --state-dir")
  }
}

/// Resolves `init`'s setup source (`ExplicitMailbox` or `GrantMailbox`).
fn init_setup(options: Options) -> Result(MailboxSetup, String) {
  let has_explicit =
    dict.has_key(options.values, "--mailbox")
    || dict.has_key(options.values, "--provision-file")
  let has_grant = has_init_grant_option(options)

  // `init` must be handed either `--mailbox`/`--provision-file` or a grant token input.
  case has_explicit, has_grant {
    True, False -> explicit_mailbox_setup(options)
    False, True -> init_grant_source(options) |> result.map(GrantMailbox)
    True, True ->
      Error(
        "give either --mailbox/--provision-file or a grant token input, not both",
      )
    False, False ->
      Error(
        "give --stdin, --file FILE, or --mailbox HOST:PORT --provision-file FILE",
      )
  }
}

/// Whether any grant-input flag or option was given to `init`.
fn has_init_grant_option(options: Options) -> Bool {
  dict.has_key(options.values, "--grant-file")
  || dict.has_key(options.values, "--file")
  || has_flag(options, "--grant-stdin")
  || has_flag(options, "--stdin")
}

/// Ensures `init` received exactly one grant input source (`--file`, `--grant-file`, `--stdin`, or `--grant-stdin`).
fn init_grant_source(options: Options) -> Result(Input, String) {
  let files =
    list.filter_map(["--grant-file", "--file"], dict.get(options.values, _))
  let stdins = list.filter(["--grant-stdin", "--stdin"], has_flag(options, _))

  // Only a single file or single stdin flag is unambiguous.
  case files, stdins {
    [path], [] -> Ok(InputFile(path))
    [], [_] -> Ok(InputStdin)
    _, _ -> Error("give exactly one grant input (--stdin or --file FILE)")
  }
}

/// Resolves how `daemon` gets its mailbox: explicit flags, a grant token, or `<state_dir>/config.json`.
fn daemon_setup(options: Options) -> Result(MailboxSetup, String) {
  let has_explicit =
    dict.has_key(options.values, "--mailbox")
    || dict.has_key(options.values, "--provision-file")
  let has_grant =
    dict.has_key(options.values, "--grant-file")
    || has_flag(options, "--grant-stdin")

  // With neither flag group present, `daemon` loads `<state_dir>/config.json`.
  case has_explicit, has_grant {
    True, False -> explicit_mailbox_setup(options)
    False, True -> grant_source(options) |> result.map(GrantMailbox)
    False, False -> Ok(SavedMailbox)
    True, True ->
      Error(
        "give either --mailbox/--provision-file or --grant-file/--grant-stdin, not both",
      )
  }
}

/// Validates `--mailbox` and `--provision-file` together.
fn explicit_mailbox_setup(options: Options) -> Result(MailboxSetup, String) {
  use mailbox <- result.try(required(options, "--mailbox"))
  use mailbox <- result.try(check_endpoint(mailbox))
  use provision_file <- result.map(required(options, "--provision-file"))
  ExplicitMailbox(mailbox:, provision_file:)
}

/// Ensures exactly one grant input source (`--grant-file` or `--grant-stdin`).
fn grant_source(options: Options) -> Result(Input, String) {
  case
    dict.get(options.values, "--grant-file"),
    has_flag(options, "--grant-stdin")
  {
    Ok(path), False -> Ok(InputFile(path))
    Error(Nil), True -> Ok(InputStdin)
    _, _ -> Error("give exactly one of --grant-file and --grant-stdin")
  }
}

/// Parses `--carrier` when optional, leaving `None` when omitted so saved config can supply it.
fn optional_carrier(options: Options) -> Result(Option(Carrier), String) {
  case dict.get(options.values, "--carrier") {
    Error(Nil) -> Ok(None)
    Ok("tor") -> Ok(Some(Tor))
    Ok("loopback") -> Ok(Some(Loopback))
    Ok(_) -> Error("--carrier must be tor or loopback")
  }
}

/// The `--carrier` option, defaulting to Tor.
fn carrier(options: Options) -> Result(Carrier, String) {
  case dict.get(options.values, "--carrier") {
    Error(Nil) | Ok("tor") -> Ok(Tor)
    Ok("loopback") -> Ok(Loopback)
    Ok(_) -> Error("--carrier must be tor or loopback")
  }
}

/// Checks that a mailbox endpoint is `HOST:PORT` with a usable port.
fn check_endpoint(text: String) -> Result(String, String) {
  let failure = Error("--mailbox must be HOST:PORT")

  // The port follows the last colon, so an IPv6 literal keeps its own.
  case list.reverse(string.split(text, ":")) {
    [port, host, ..] ->
      case int.parse(port), host {
        Ok(number), host if number >= 1 && number <= 65_535 && host != "" ->
          Ok(text)

        _, _ -> failure
      }

    _ -> failure
  }
}

/// Parses a client command's options, then resolves where to find the
/// daemon and builds the action.
fn client(
  rest: List(String),
  env: Environment,
  values: List(String),
  flags: List(String),
  build: fn(Options) -> Result(Action, String),
) -> Result(Command, String) {
  let common_values = ["--state-dir", "--socket", "--credential-file"]

  use options <- result.try(
    read_options(rest, list.append(common_values, values), ["--json", ..flags]),
  )
  use target <- result.try(target(options, env))
  use action <- result.try(build(options))

  // The output mode is a flag, so it is a branch on presence.
  let output = case has_flag(options, "--json") {
    True -> JsonOutput
    False -> HumanOutput
  }

  Ok(Client(target:, output:, action:))
}

/// Where the daemon's socket and the credential file are. Explicit `--state-dir`
/// or `--socket` wins; when neither is given, `env.default_state_dir` supplies
/// the default `~/.pondline` directory without ever sending its credential to an
/// unrelated explicit `--socket`.
fn target(options: Options, env: Environment) -> Result(Target, String) {
  let explicit_socket = dict.get(options.values, "--socket")

  // Fall back to `env.default_state_dir` (`~/.pondline`) only when neither `--state-dir` nor `--socket` was given.
  let state_dir = case
    dict.get(options.values, "--state-dir"),
    explicit_socket,
    env.default_state_dir
  {
    Ok(dir), _, _ -> Ok(dir)
    Error(Nil), Error(Nil), Some(dir) -> Ok(dir)
    Error(Nil), _, _ -> Error(Nil)
  }

  // The explicit socket wins; otherwise the resolved state directory implies one.
  use socket <- result.try(case explicit_socket, state_dir {
    Ok(path), _ -> Ok(path)
    Error(Nil), Ok(dir) -> Ok(dir <> "/api.sock")
    Error(Nil), Error(Nil) -> Error("give --state-dir or --socket")
  })

  // The explicit file wins, then `PONDLINE_CREDENTIAL_FILE`, then `<state-dir>/operator.cred`.
  use credential_file <- result.try(
    case
      dict.get(options.values, "--credential-file"),
      env.credential_file,
      state_dir
    {
      Ok(path), _, _ -> Ok(path)
      Error(Nil), Some(path), _ -> Ok(path)
      Error(Nil), None, Ok(dir) -> Ok(dir <> "/operator.cred")
      Error(Nil), None, Error(Nil) ->
        Error("give --credential-file or --state-dir")
    },
  )

  Ok(Target(socket:, credential_file:))
}

/// Reads `--name value` pairs and bare flags, rejecting an unknown or
/// repeated name and a name without a value.
fn read_options(
  arguments: List(String),
  values: List(String),
  flags: List(String),
) -> Result(Options, String) {
  read_loop(arguments, values, flags, Options(dict.new(), []))
}

/// The loop of `read_options`, one name at a time.
fn read_loop(
  arguments: List(String),
  values: List(String),
  flags: List(String),
  found: Options,
) -> Result(Options, String) {
  case arguments {
    [] -> Ok(found)

    // A name is a bare flag, an option that takes the next word, or
    // neither, which is an error.
    [name, ..rest] ->
      case list.contains(flags, name), list.contains(values, name) {
        True, _ -> take_flag(name, rest, values, flags, found)
        False, True -> take_value(name, rest, values, flags, found)
        False, False -> Error(unknown(name))
      }
  }
}

/// The refusal of a word no command takes. An option name is repeated so
/// the user can see the typo; a stray word is not, because a stray word
/// is often a secret typed where a flag stood (`--ticket pl1...`).
fn unknown(name: String) -> String {
  // An option written `--name=value` is named without its value, which
  // may be the secret (`--ticket=pl1...`).
  case string.starts_with(name, "-"), string.split_once(name, "=") {
    True, Ok(#(option, _)) -> "unknown option " <> option <> "=..."
    True, Error(Nil) -> "unknown option " <> name
    False, _ ->
      "unexpected argument; secrets are read from a file or standard input"
  }
}

/// Records a bare flag, refusing a repeat, and reads on.
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

/// Records an option with the word that follows it, refusing a repeat and
/// a missing value, and reads on.
fn take_value(
  name: String,
  rest: List(String),
  values: List(String),
  flags: List(String),
  found: Options,
) -> Result(Options, String) {
  case rest, dict.has_key(found.values, name) {
    [], _ -> Error("missing value for " <> name)

    _, True -> Error("repeated option " <> name)

    [value, ..rest], False ->
      read_loop(
        rest,
        values,
        flags,
        Options(..found, values: dict.insert(found.values, name, value)),
      )
  }
}

/// Whether a flag was given.
fn has_flag(options: Options, name: String) -> Bool {
  list.contains(options.flags, name)
}

/// The value of an option, or `default`.
fn dict_get(options: Options, name: String, default: String) -> String {
  dict.get(options.values, name) |> result.unwrap(default)
}

/// The value of a required option.
fn required(options: Options, name: String) -> Result(String, String) {
  dict.get(options.values, name)
  |> result.map_error(fn(_) { "missing option " <> name })
}

/// An integer option from `low` to `high`, which must be present.
fn number(
  options: Options,
  name: String,
  low: Int,
  high: Int,
) -> Result(Int, String) {
  use text <- result.try(required(options, name))
  in_range(text, name, low, high)
}

/// An integer option from `low` to `high`, or `default` when absent.
fn optional_number(
  options: Options,
  name: String,
  default: Int,
  low: Int,
  high: Int,
) -> Result(Int, String) {
  case dict.get(options.values, name) {
    Ok(text) -> in_range(text, name, low, high)
    Error(Nil) -> Ok(default)
  }
}

/// An optional integer option from `low` to `high`, returning `None` when absent.
fn optional_present_number(
  options: Options,
  name: String,
  low: Int,
  high: Int,
) -> Result(Option(Int), String) {
  case dict.get(options.values, name) {
    Ok(text) -> in_range(text, name, low, high) |> result.map(Some)
    Error(Nil) -> Ok(None)
  }
}

/// Parses an integer within bounds.
fn in_range(
  text: String,
  name: String,
  low: Int,
  high: Int,
) -> Result(Int, String) {
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

/// The required `--contact` selector: full 32-digit hex id, hex prefix, or petname.
fn contact(options: Options) -> Result(ContactRef, String) {
  use text <- result.try(required(options, "--contact"))
  parse_contact_ref(text)
}

/// The optional `--contact` selector.
fn optional_contact(options: Options) -> Result(Option(ContactRef), String) {
  case dict.get(options.values, "--contact") {
    Ok(text) -> result.map(parse_contact_ref(text), Some)
    Error(Nil) -> Ok(None)
  }
}

/// Parses `--contact` as `ExactContact` when it is 32-digit hex, else `LookupContact`.
fn parse_contact_ref(text: String) -> Result(ContactRef, String) {
  let trimmed = string.trim(text)
  let looks_secret =
    string.starts_with(trimmed, "pl1") || string.starts_with(trimmed, "plg1")

  // Reject empty, overlong, or misplaced ticket/grant strings without echoing them.
  case
    trimmed == "",
    looks_secret,
    string.byte_size(trimmed) > limits.max_description_bytes
  {
    True, _, _ -> Error("--contact must not be empty")
    False, True, _ ->
      Error(
        "--contact takes a contact id or petname, not a ticket or grant token",
      )
    False, False, True -> Error("--contact exceeds maximum description length")
    False, False, False ->
      case id.from_hex(trimmed) {
        Ok(parsed) -> Ok(ExactContact(parsed))
        Error(Nil) -> Ok(LookupContact(trimmed))
      }
  }
}

/// Whether `action` carries a `LookupContact` that needs a `contacts` lookup first.
///
/// ## Examples
///
/// ```gleam
/// cli.needs_contact_lookup(ApproveContact(LookupContact("bob")))
/// // -> True
/// ```
pub fn needs_contact_lookup(action: Action) -> Bool {
  case action {
    ApproveContact(LookupContact(..))
    | DeclineContact(LookupContact(..))
    | CloseContact(LookupContact(..))
    | RaiseBudget(contact: LookupContact(..), ..)
    | SendMessage(contact: LookupContact(..), ..) -> True
    ReceiveMessages(contact: Some(LookupContact(..)), ..)
    | ShowAudit(contact: Some(LookupContact(..)), ..) -> True
    _ -> False
  }
}

/// Resolves any `LookupContact` inside `action` against `entries`.
///
/// ## Examples
///
/// ```gleam
/// cli.resolve_action_contacts(ShowHealth, [])
/// // -> Ok(ShowHealth)
/// ```
pub fn resolve_action_contacts(
  action: Action,
  entries: List(ContactEntry),
) -> Result(Action, String) {
  // Rewrite only the actions that carry a required or optional `ContactRef`.
  case action {
    ApproveContact(ref) ->
      resolve_ref(ref, entries) |> result.map(ApproveContact)
    DeclineContact(ref) ->
      resolve_ref(ref, entries) |> result.map(DeclineContact)
    CloseContact(ref) -> resolve_ref(ref, entries) |> result.map(CloseContact)
    RaiseBudget(ref, add) ->
      resolve_ref(ref, entries) |> result.map(RaiseBudget(_, add))
    SendMessage(ref, content_type, source, in_reply_to, idempotency_key) -> {
      use resolved <- result.map(resolve_ref(ref, entries))
      SendMessage(resolved, content_type, source, in_reply_to, idempotency_key)
    }
    ReceiveMessages(Some(ref), max, wait_seconds, view) -> {
      use resolved <- result.map(resolve_ref(ref, entries))
      ReceiveMessages(Some(resolved), max, wait_seconds, view)
    }
    ShowAudit(Some(ref), limit) -> {
      use resolved <- result.map(resolve_ref(ref, entries))
      ShowAudit(Some(resolved), limit)
    }
    other -> Ok(other)
  }
}

/// Resolves one `ContactRef` into an `ExactContact`.
fn resolve_ref(
  ref: ContactRef,
  entries: List(ContactEntry),
) -> Result(ContactRef, String) {
  case ref {
    ExactContact(_) -> Ok(ref)
    LookupContact(query) ->
      resolve_contact_ref(entries, query) |> result.map(ExactContact)
  }
}

/// Resolves `query` against `entries`: exact case-insensitive description match first,
/// then >=4-character hex prefix match, preferring non-closed contacts and failing closed on ambiguity.
///
/// ## Examples
///
/// ```gleam
/// cli.resolve_contact_ref([], "bob")
/// // -> Error("no contact matching \"bob\"")
/// ```
pub fn resolve_contact_ref(
  entries: List(ContactEntry),
  query: String,
) -> Result(Id(Contact), String) {
  let lowered = string.lowercase(string.trim(query))
  let by_name =
    list.filter(entries, fn(entry) {
      string.lowercase(string.trim(entry.description)) == lowered
    })

  // Prefer exact description matches before falling back to hex prefixes (>= 4 chars).
  case pick_unique_contact(by_name, query) {
    Ok(found) -> Ok(found)
    Error(AmbiguousMatch(reason)) -> Error(reason)
    Error(NoMatch) -> resolve_hex_prefix(entries, lowered, query)
  }
}

/// Internal outcome of disambiguating candidate contacts.
type LookupMiss {
  NoMatch
  AmbiguousMatch(reason: String)
}

/// Matches `lowered` as a >=4-character hex prefix of `id.to_hex(entry.contact)`.
fn resolve_hex_prefix(
  entries: List(ContactEntry),
  lowered: String,
  original: String,
) -> Result(Id(Contact), String) {
  let is_prefix_candidate =
    string.byte_size(lowered) >= 4 && is_hex_ascii(lowered)

  // Short or non-hex strings cannot match as hex prefixes.
  case is_prefix_candidate {
    False -> Error("no contact matching \"" <> original <> "\"")
    True -> {
      let by_prefix =
        list.filter(entries, fn(entry) {
          string.starts_with(id.to_hex(entry.contact), lowered)
        })

      // Disambiguate prefix hits the same way as description hits.
      case pick_unique_contact(by_prefix, original) {
        Ok(found) -> Ok(found)
        Error(AmbiguousMatch(reason)) -> Error(reason)
        Error(NoMatch) -> Error("no contact matching \"" <> original <> "\"")
      }
    }
  }
}

/// Picks a single contact from `matches`, preferring non-closed contacts over closed ones.
fn pick_unique_contact(
  matches: List(ContactEntry),
  query: String,
) -> Result(Id(Contact), LookupMiss) {
  let live = list.filter(matches, fn(entry) { entry.phase != "closed" })

  // Prefer live relationships when a closed relationship shares the same label.
  let pool = case live {
    [_, ..] -> live
    [] -> matches
  }

  // More than one candidate in the active pool is ambiguous and never guessed.
  case pool {
    [] -> Error(NoMatch)
    [single] -> Ok(single.contact)
    [_, _, ..] ->
      Error(AmbiguousMatch(
        "ambiguous contact \"" <> query <> "\"; pass its full hex id",
      ))
  }
}

/// Checks whether every character in `text` is a lowercase hex digit.
fn is_hex_ascii(text: String) -> Bool {
  list.all(string.to_graphemes(text), fn(ch) {
    string.contains("0123456789abcdef", ch)
  })
}

/// The required `--message` identifier.
fn message(options: Options) -> Result(Id(Message), String) {
  use text <- result.try(required(options, "--message"))
  hex(text, "--message")
}

/// An optional message identifier under `name`.
fn optional_message(
  options: Options,
  name: String,
) -> Result(Option(Id(Message)), String) {
  case dict.get(options.values, name) {
    Ok(text) -> result.map(hex(text, name), Some)
    Error(Nil) -> Ok(None)
  }
}

/// Parses a hex identifier.
fn hex(text: String, name: String) -> Result(Id(kind), String) {
  id.from_hex(text)
  |> result.map_error(fn(_) { name <> " must be a 32-digit hex identifier" })
}

/// Where an action reads its one input from: the invitation or ticket of
/// `invite accept`, or the payload of `send`.
///
/// ## Examples
///
/// ```gleam
/// cli.input_of(AcceptInvite(InputFile("bob.invite"), FromInvitation, "", None))
/// // -> InputFile("bob.invite")
/// ```
pub fn input_of(action: Action) -> Input {
  case action {
    AcceptInvite(source:, ..) -> source
    SendMessage(source:, ..) -> source

    CreateInvite(..)
    | ListContacts
    | ApproveContact(..)
    | DeclineContact(..)
    | CloseContact(..)
    | RaiseBudget(..)
    | ReceiveMessages(..)
    | Acknowledge(..)
    | MessageStatus(..)
    | ShowAudit(..)
    | ShowIncidents(..)
    | ShowHealth -> NoInput
  }
}

/// How long the CLI waits for an invitation to be created or a ticket to be
/// redeemed (130 s). `invite` waits up to `api.invite_wait_ms` for its
/// queue, and a ticket's mailbox call is retried for `api.ticket_wait_ms`
/// with one call of up to `api.ticket_call_ms` still running at the end;
/// giving up sooner would report a failure for an invitation that is then
/// created, or a contact that is then accepted. `cli_test` checks the sum.
pub const invitation_timeout_ms = 130_000

/// How long to wait for the daemon's answer, in milliseconds: the wait the
/// action asks for plus a margin.
///
/// ## Examples
///
/// ```gleam
/// cli.timeout_ms(ReceiveMessages(None, 1, 25, Encoded))
/// // -> 35_000
/// ```
pub fn timeout_ms(action: Action) -> Int {
  case action {
    ReceiveMessages(wait_seconds:, ..) -> wait_seconds * 1000 + 10_000
    CreateInvite(..) | AcceptInvite(form: FromTicket, ..) ->
      invitation_timeout_ms
    _ -> 10_000
  }
}

/// The operation name and arguments an action sends. `input` is the bytes
/// of the action's `input_of` source and is ignored when it has none.
///
/// ## Examples
///
/// ```gleam
/// cli.request(ShowHealth, <<>>)
/// // -> #("health", json.object([]))
/// ```
pub fn request(action: Action, input: BitArray) -> #(String, Json) {
  case action {
    CreateInvite(description:, approval:, budget:, output:) -> #(
      "invite",
      json.object([
        #("description", json.string(description)),
        #("approval", json.string(approval_name(approval))),
        #("budget", json.int(budget)),
        #("ticket", json.bool(wants_ticket(output))),
      ]),
    )

    AcceptInvite(form: FromInvitation, description:, budget:, ..) -> #(
      "accept",
      json.object([
        #("invitation", json.string(bit_array.base64_encode(input, True))),
        #("description", json.string(description)),
        ..budget_args(budget)
      ]),
    )

    // The ticket goes as text; `cli_run` has already refused input that is
    // not, and the daemon drops the newline a paste leaves.
    AcceptInvite(form: FromTicket, description:, budget:, ..) -> #(
      "accept",
      json.object([
        #("ticket", json.string(result.unwrap(bit_array.to_string(input), ""))),
        #("description", json.string(description)),
        ..budget_args(budget)
      ]),
    )

    ListContacts -> #("contacts", json.object([]))
    ApproveContact(contact:) -> #("approve", contact_args(contact))
    DeclineContact(contact:) -> #("decline", contact_args(contact))
    CloseContact(contact:) -> #("close", contact_args(contact))

    RaiseBudget(contact:, add:) -> #(
      "raise_budget",
      json.object([
        #("contact", contact_ref_json(contact)),
        #("by", json.int(add)),
      ]),
    )

    SendMessage(contact:, content_type:, in_reply_to:, idempotency_key:, ..) -> #(
      "send",
      json.object([
        #("contact", contact_ref_json(contact)),
        #("content_type", json.string(content_type)),
        #("payload", json.string(bit_array.base64_encode(input, True))),
        #("in_reply_to", json.nullable(in_reply_to, hex_json)),
        ..key_args(idempotency_key)
      ]),
    )

    ReceiveMessages(contact:, max:, wait_seconds:, ..) -> #(
      "receive",
      json.object([
        #("contact", json.nullable(contact, contact_ref_json)),
        #("max", json.int(max)),
        #("wait_ms", json.int(wait_seconds * 1000)),
      ]),
    )

    Acknowledge(message:) -> #("acknowledge", message_args(message))
    MessageStatus(message:) -> #("status", message_args(message))

    ShowAudit(contact:, limit:) -> #(
      "audit",
      json.object([
        #("contact", json.nullable(contact, contact_ref_json)),
        #("limit", json.int(limit)),
      ]),
    )

    ShowIncidents(limit:) -> #(
      "incidents",
      json.object([#("limit", json.int(limit))]),
    )

    ShowHealth -> #("health", json.object([]))
  }
}

/// Whether an invite output includes a ticket.
fn wants_ticket(output: InviteOutput) -> Bool {
  case output {
    InvitationFile(..) -> False
    TicketOnly | TicketAndFile(..) -> True
  }
}

/// The file an invite output writes, if any.
///
/// ## Examples
///
/// ```gleam
/// cli.invitation_path(TicketAndFile("a.invite"))
/// // -> Some("a.invite")
/// ```
pub fn invitation_path(output: InviteOutput) -> Option(String) {
  case output {
    InvitationFile(path:) | TicketAndFile(path:) -> Some(path)
    TicketOnly -> None
  }
}

/// The `idempotency_key` argument of a send, present only when the operator
/// gave one, so an unkeyed send's request is what it always was.
fn key_args(key: Option(String)) -> List(#(String, Json)) {
  case key {
    Some(key) -> [#("idempotency_key", json.string(key))]
    None -> []
  }
}

/// Optional `budget` field on `accept`, omitted when `None` so wire requests stay minimal.
fn budget_args(budget: Option(Int)) -> List(#(String, Json)) {
  case budget {
    Some(value) -> [#("budget", json.int(value))]
    None -> []
  }
}

/// The wire name of an approval mode.
fn approval_name(approval: Approval) -> String {
  case approval {
    AutoApprove -> "auto"
    OperatorApproves -> "operator"
  }
}

/// An identifier as hex JSON.
fn hex_json(identifier: Id(kind)) -> Json {
  json.string(id.to_hex(identifier))
}

/// Encodes a `ContactRef` to JSON after resolution.
fn contact_ref_json(ref: ContactRef) -> Json {
  case ref {
    ExactContact(contact:) -> hex_json(contact)
    LookupContact(query:) -> json.string(query)
  }
}

/// The arguments of an operation on one contact.
fn contact_args(contact: ContactRef) -> Json {
  json.object([#("contact", contact_ref_json(contact))])
}

/// The arguments of an operation on one message.
fn message_args(message: Id(Message)) -> Json {
  json.object([#("message", hex_json(message))])
}

/// The exit status for a failure category.
///
/// ## Examples
///
/// ```gleam
/// cli.exit_code(protocol.Forbidden)
/// // -> 3
/// ```
pub fn exit_code(category: protocol.Category) -> Int {
  case category {
    protocol.Unauthorized | protocol.Forbidden -> exit_unauthorized
    protocol.NotFound -> exit_not_found
    protocol.Invalid | protocol.Refused | protocol.TooLarge -> exit_refused
    protocol.Unavailable -> exit_unavailable
  }
}
