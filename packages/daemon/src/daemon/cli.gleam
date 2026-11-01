//// The `reedwire` command line, parsed (spec §9.2).
////
//// This module is pure: it turns arguments into a `Command` and a `Command`
//// into the request it sends, and touches no file, socket or environment
//// variable. `daemon/cli_run` does the effects and `daemon/cli_render`
//// prints the answers.
////
//// ## Commands
////
//// - `daemon --state-dir D --mailbox HOST:PORT --provision-file F
////   [--carrier tor|loopback] [--tor-bin PATH]` runs the daemon.
//// - `invite create --description TEXT --budget N [--auto-approve]
////   --out FILE` and `invite accept --file FILE [--description TEXT]`.
//// - `contacts list`, `contact approve|decline|close --contact HEX` and
////   `contact budget --contact HEX --add N`.
//// - `send --contact HEX [--content-type T] (--file F | --stdin)
////   [--reply-to HEX]`.
//// - `receive [--contact HEX] [--max N] [--wait SECONDS] [--raw]`.
//// - `ack --message HEX`, `status --message HEX`, `audit [--contact HEX]
////   [--limit N]` and `health`.
//// - `--version` prints the build's version and commit.
////
//// Every client command also takes `--state-dir D` or `--socket P` to find
//// the daemon, `--credential-file F` to name the credential (default
//// `D/operator.cred`, or the `REEDWIRE_CREDENTIAL_FILE` variable) and
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
//// A payload and a credential are secrets, and a command line is visible to
//// every process on the machine and kept in shell history. So no option
//// takes one: payloads come from `--file` or `--stdin`, credentials from a
//// file. An option such as `--payload` or `--credential` is unknown and
//// fails as a usage error.

import core/id.{type Contact, type Id, type Message}
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
  "usage: reedwire <command> [options]

commands:
  daemon --state-dir D --mailbox HOST:PORT --provision-file F
         [--carrier tor|loopback] [--tor-bin PATH]
  invite create --description TEXT --budget N [--auto-approve] --out FILE
  invite accept --file FILE [--description TEXT]
  contacts list
  contact approve|decline|close --contact HEX
  contact budget --contact HEX --add N
  send --contact HEX [--content-type T] (--file F | --stdin) [--reply-to HEX]
  receive [--contact HEX] [--max N] [--wait SECONDS] [--raw]
  ack --message HEX
  status --message HEX
  audit [--contact HEX] [--limit N]
  health
  --version

client options: --state-dir D | --socket P, --credential-file F, --json
exit codes: 0 ok, 1 local failure, 2 usage, 3 unauthorized or forbidden,
            4 not found, 5 refused or invalid, 6 unavailable"

/// How the daemon reaches mailboxes.
pub type Carrier {
  Tor
  Loopback
}

/// The options of `reedwire daemon`.
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

/// How `receive` prints a payload.
pub type PayloadView {
  /// Base64 inside the output, with the delivery's metadata.
  Encoded

  /// The one message's bytes alone on standard output.
  Raw
}

/// What a client command asks the daemon to do.
pub type Action {
  CreateInvite(
    description: String,
    approval: Approval,
    budget: Int,
    out: String,
  )
  AcceptInvite(file: String, description: String)
  ListContacts
  ApproveContact(contact: Id(Contact))
  DeclineContact(contact: Id(Contact))
  CloseContact(contact: Id(Contact))
  RaiseBudget(contact: Id(Contact), add: Int)
  SendMessage(
    contact: Id(Contact),
    content_type: String,
    source: Input,
    in_reply_to: Option(Id(Message)),
  )
  ReceiveMessages(
    contact: Option(Id(Contact)),
    max: Int,
    wait_seconds: Int,
    view: PayloadView,
  )
  Acknowledge(message: Id(Message))
  MessageStatus(message: Id(Message))
  ShowAudit(contact: Option(Id(Contact)), limit: Int)
  ShowHealth
}

/// A parsed command line.
pub type Command {
  RunDaemon(DaemonOptions)
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
/// `env_credential_file` is the value of `REEDWIRE_CREDENTIAL_FILE`, which
/// the caller reads because this module reads nothing.
///
/// ## Examples
///
/// ```gleam
/// cli.parse(["health", "--state-dir", "/var/lib/reedwire"], None)
/// // -> Ok(Client(Target("/var/lib/reedwire/api.sock",
/// //      "/var/lib/reedwire/operator.cred"), HumanOutput, ShowHealth))
/// cli.parse(["send", "--payload", "hi"], None)
/// // -> Error("unknown option --payload")
/// ```
pub fn parse(
  arguments: List(String),
  env_credential_file: Option(String),
) -> Result(Command, String) {
  // The leading words name the command; its options are checked against
  // that command's own list, so an option valid for one is unknown to the
  // rest.
  case arguments {
    ["help"] | ["--help"] -> Ok(Help)

    ["--version"] | ["version"] -> Ok(Version)

    ["daemon", ..rest] -> parse_daemon(rest)

    ["invite", "create", ..rest] ->
      client(
        rest,
        env_credential_file,
        ["--description", "--budget", "--out"],
        [
          "--auto-approve",
        ],
        fn(options) {
          use description <- result.try(required(options, "--description"))
          use budget <- result.try(number(options, "--budget", 1, 1_000_000))
          use out <- result.try(required(options, "--out"))
          let approval = approval_of(options)

          Ok(CreateInvite(description:, approval:, budget:, out:))
        },
      )

    ["invite", "accept", ..rest] ->
      client(
        rest,
        env_credential_file,
        ["--file", "--description"],
        [],
        fn(options) {
          use file <- result.try(required(options, "--file"))
          let description = dict_get(options, "--description", "")

          Ok(AcceptInvite(file:, description:))
        },
      )

    ["contacts", "list", ..rest] ->
      client(rest, env_credential_file, [], [], fn(_) { Ok(ListContacts) })

    ["contact", "approve", ..rest] ->
      client(rest, env_credential_file, ["--contact"], [], fn(options) {
        result.map(contact(options), ApproveContact)
      })

    ["contact", "decline", ..rest] ->
      client(rest, env_credential_file, ["--contact"], [], fn(options) {
        result.map(contact(options), DeclineContact)
      })

    ["contact", "close", ..rest] ->
      client(rest, env_credential_file, ["--contact"], [], fn(options) {
        result.map(contact(options), CloseContact)
      })

    ["contact", "budget", ..rest] ->
      client(rest, env_credential_file, ["--contact", "--add"], [], fn(options) {
        use contact <- result.try(contact(options))
        use add <- result.try(number(options, "--add", 1, 1_000_000))

        Ok(RaiseBudget(contact:, add:))
      })

    ["send", ..rest] -> parse_send(rest, env_credential_file)

    ["receive", ..rest] -> parse_receive(rest, env_credential_file)

    ["ack", ..rest] ->
      client(rest, env_credential_file, ["--message"], [], fn(options) {
        result.map(message(options), Acknowledge)
      })

    ["status", ..rest] ->
      client(rest, env_credential_file, ["--message"], [], fn(options) {
        result.map(message(options), MessageStatus)
      })

    ["audit", ..rest] ->
      client(
        rest,
        env_credential_file,
        ["--contact", "--limit"],
        [],
        fn(options) {
          use contact <- result.try(optional_contact(options))
          use limit <- result.try(optional_number(
            options,
            "--limit",
            50,
            1,
            256,
          ))

          Ok(ShowAudit(contact:, limit:))
        },
      )

    ["health", ..rest] ->
      client(rest, env_credential_file, [], [], fn(_) { Ok(ShowHealth) })

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

/// Parses `send`. The payload comes from exactly one of `--file` and
/// `--stdin`, never from the command line.
fn parse_send(
  rest: List(String),
  env: Option(String),
) -> Result(Command, String) {
  client(
    rest,
    env,
    ["--contact", "--content-type", "--file", "--reply-to"],
    ["--stdin"],
    fn(options) {
      use contact <- result.try(contact(options))
      use in_reply_to <- result.try(optional_message(options, "--reply-to"))

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
          ))

        Error(Nil), True ->
          Ok(SendMessage(
            contact:,
            content_type:,
            source: InputStdin,
            in_reply_to:,
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
  env: Option(String),
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

/// Parses `daemon`.
fn parse_daemon(rest: List(String)) -> Result(Command, String) {
  use options <- result.try(
    read_options(
      rest,
      ["--state-dir", "--mailbox", "--provision-file", "--carrier", "--tor-bin"],
      [],
    ),
  )
  use state_dir <- result.try(required(options, "--state-dir"))
  use mailbox <- result.try(required(options, "--mailbox"))
  use mailbox <- result.try(check_endpoint(mailbox))
  use provision_file <- result.try(required(options, "--provision-file"))
  use carrier <- result.try(carrier(options))

  Ok(
    RunDaemon(DaemonOptions(
      state_dir:,
      mailbox:,
      provision_file:,
      carrier:,
      tor_bin: option.from_result(dict.get(options.values, "--tor-bin")),
    )),
  )
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
  env_credential_file: Option(String),
  values: List(String),
  flags: List(String),
  build: fn(Options) -> Result(Action, String),
) -> Result(Command, String) {
  let common_values = ["--state-dir", "--socket", "--credential-file"]

  use options <- result.try(
    read_options(rest, list.append(common_values, values), ["--json", ..flags]),
  )
  use target <- result.try(target(options, env_credential_file))
  use action <- result.try(build(options))

  // The output mode is a flag, so it is a branch on presence.
  let output = case has_flag(options, "--json") {
    True -> JsonOutput
    False -> HumanOutput
  }

  Ok(Client(target:, output:, action:))
}

/// Where the daemon's socket and the credential file are. The state
/// directory supplies both defaults, and the environment variable replaces
/// the credential default.
fn target(
  options: Options,
  env_credential_file: Option(String),
) -> Result(Target, String) {
  let state_dir = dict.get(options.values, "--state-dir")

  // The explicit socket wins; otherwise the state directory implies one.
  use socket <- result.try(
    case dict.get(options.values, "--socket"), state_dir {
      Ok(path), _ -> Ok(path)
      Error(Nil), Ok(dir) -> Ok(dir <> "/api.sock")
      Error(Nil), Error(Nil) -> Error("give --state-dir or --socket")
    },
  )

  // The explicit file wins, then the environment, then the state directory's operator credential.
  use credential_file <- result.try(
    case
      dict.get(options.values, "--credential-file"),
      env_credential_file,
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
        False, False -> Error("unknown option " <> name)
      }
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

/// The required `--contact` identifier.
fn contact(options: Options) -> Result(Id(Contact), String) {
  use text <- result.try(required(options, "--contact"))
  hex(text, "--contact")
}

/// The optional `--contact` identifier.
fn optional_contact(options: Options) -> Result(Option(Id(Contact)), String) {
  case dict.get(options.values, "--contact") {
    Ok(text) -> result.map(hex(text, "--contact"), Some)
    Error(Nil) -> Ok(None)
  }
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

/// Where an action reads its one input from: the invitation file of
/// `invite accept` or the payload of `send`.
///
/// ## Examples
///
/// ```gleam
/// cli.input_of(AcceptInvite(file: "bob.invite", description: ""))
/// // -> InputFile("bob.invite")
/// ```
pub fn input_of(action: Action) -> Input {
  case action {
    AcceptInvite(file:, ..) -> InputFile(file)
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
    | ShowHealth -> NoInput
  }
}

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
    CreateInvite(description:, approval:, budget:, ..) -> #(
      "invite",
      json.object([
        #("description", json.string(description)),
        #("approval", json.string(approval_name(approval))),
        #("budget", json.int(budget)),
      ]),
    )

    AcceptInvite(description:, ..) -> #(
      "accept",
      json.object([
        #("invitation", json.string(bit_array.base64_encode(input, True))),
        #("description", json.string(description)),
      ]),
    )

    ListContacts -> #("contacts", json.object([]))
    ApproveContact(contact:) -> #("approve", contact_args(contact))
    DeclineContact(contact:) -> #("decline", contact_args(contact))
    CloseContact(contact:) -> #("close", contact_args(contact))

    RaiseBudget(contact:, add:) -> #(
      "raise_budget",
      json.object([
        #("contact", json.string(id.to_hex(contact))),
        #("by", json.int(add)),
      ]),
    )

    SendMessage(contact:, content_type:, in_reply_to:, ..) -> #(
      "send",
      json.object([
        #("contact", json.string(id.to_hex(contact))),
        #("content_type", json.string(content_type)),
        #("payload", json.string(bit_array.base64_encode(input, True))),
        #("in_reply_to", json.nullable(in_reply_to, hex_json)),
      ]),
    )

    ReceiveMessages(contact:, max:, wait_seconds:, ..) -> #(
      "receive",
      json.object([
        #("contact", json.nullable(contact, hex_json)),
        #("max", json.int(max)),
        #("wait_ms", json.int(wait_seconds * 1000)),
      ]),
    )

    Acknowledge(message:) -> #("acknowledge", message_args(message))
    MessageStatus(message:) -> #("status", message_args(message))

    ShowAudit(contact:, limit:) -> #(
      "audit",
      json.object([
        #("contact", json.nullable(contact, hex_json)),
        #("limit", json.int(limit)),
      ]),
    )

    ShowHealth -> #("health", json.object([]))
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

/// The arguments of an operation on one contact.
fn contact_args(contact: Id(Contact)) -> Json {
  json.object([#("contact", hex_json(contact))])
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
