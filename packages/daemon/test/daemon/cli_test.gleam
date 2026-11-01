import core/id
import core/offer.{AutoApprove, OperatorApproves}
import daemon/api
import daemon/cli.{
  AcceptInvite, Acknowledge, ApproveContact, Client, CloseContact, CreateInvite,
  DaemonOptions, DeclineContact, Encoded, FromInvitation, FromTicket,
  HumanOutput, InputFile, InputStdin, InvitationFile, JsonOutput, ListContacts,
  MessageStatus, RaiseBudget, Raw, ReceiveMessages, RunDaemon, SendMessage,
  ShowAudit, ShowHealth, Target, TicketAndFile, TicketOnly,
}
import daemon/local_api_protocol as protocol
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string

const hex = "000000000000000000000000000000aa"

const hex2 = "000000000000000000000000000000bb"

const common = ["--state-dir", "/s"]

fn parse(arguments: List(String)) {
  cli.parse(arguments, None)
}

fn identifier(text: String) {
  let assert Ok(value) = id.from_hex(text)
  value
}

pub fn invite_create_test() {
  let assert Ok(Client(target:, output:, action:)) =
    parse(list.append(
      [
        "invite", "create", "--description", "for bob", "--budget", "5", "--out",
        "bob.invite",
      ],
      common,
    ))

  assert target == Target("/s/api.sock", "/s/operator.cred")
  assert output == HumanOutput
  assert action
    == CreateInvite(
      "for bob",
      OperatorApproves,
      5,
      InvitationFile("bob.invite"),
    )

  let assert Ok(Client(action:, ..)) =
    parse(list.append(
      [
        "invite", "create", "--description", "d", "--budget", "1", "--out", "o",
        "--auto-approve",
      ],
      common,
    ))
  assert action == CreateInvite("d", AutoApprove, 1, InvitationFile("o"))
}

pub fn invite_create_with_a_ticket_test() {
  let base = ["invite", "create", "--description", "d", "--budget", "1"]

  let assert Ok(Client(action:, ..)) =
    parse(list.flatten([base, ["--ticket"], common]))
  assert action == CreateInvite("d", OperatorApproves, 1, TicketOnly)

  let assert Ok(Client(action:, ..)) =
    parse(list.flatten([base, ["--ticket", "--out", "o"], common]))
  assert action == CreateInvite("d", OperatorApproves, 1, TicketAndFile("o"))

  // With neither there is nothing to hand out.
  assert parse(list.append(base, common))
    == Error("give --out FILE, --ticket, or both")
}

pub fn invite_accept_with_a_ticket_test() {
  let assert Ok(Client(action:, ..)) =
    parse(["invite", "accept", "--ticket", "--stdin", ..common])
  assert action == AcceptInvite(InputStdin, FromTicket, "")

  let assert Ok(Client(action:, ..)) =
    parse(["invite", "accept", "--ticket", "--file", "t.txt", ..common])
  assert action == AcceptInvite(InputFile("t.txt"), FromTicket, "")

  assert parse(["invite", "accept", "--ticket", ..common])
    == Error("give exactly one of --file and --stdin")
}

pub fn invite_accept_test() {
  let assert Ok(Client(action:, ..)) =
    parse(["invite", "accept", "--file", "a.invite", ..common])
  assert action == AcceptInvite(InputFile("a.invite"), FromInvitation, "")

  let assert Ok(Client(action:, ..)) =
    parse([
      "invite",
      "accept",
      "--file",
      "a",
      "--description",
      "alice",
      ..common
    ])
  assert action == AcceptInvite(InputFile("a"), FromInvitation, "alice")
}

pub fn contacts_and_contact_commands_test() {
  let assert Ok(Client(action: ListContacts, ..)) =
    parse(["contacts", "list", ..common])

  let assert Ok(Client(action:, ..)) =
    parse(["contact", "approve", "--contact", hex, ..common])
  assert action == ApproveContact(identifier(hex))

  let assert Ok(Client(action:, ..)) =
    parse(["contact", "decline", "--contact", hex, ..common])
  assert action == DeclineContact(identifier(hex))

  let assert Ok(Client(action:, ..)) =
    parse(["contact", "close", "--contact", hex, ..common])
  assert action == CloseContact(identifier(hex))

  let assert Ok(Client(action:, ..)) =
    parse(["contact", "budget", "--contact", hex, "--add", "9", ..common])
  assert action == RaiseBudget(identifier(hex), 9)
}

pub fn send_takes_its_payload_from_exactly_one_source_test() {
  let assert Ok(Client(action:, ..)) =
    parse(["send", "--contact", hex, "--file", "p.bin", ..common])
  assert action
    == SendMessage(
      identifier(hex),
      "application/octet-stream",
      InputFile("p.bin"),
      None,
    )

  let assert Ok(Client(action:, ..)) =
    parse([
      "send",
      "--contact",
      hex,
      "--stdin",
      "--content-type",
      "text/plain",
      "--reply-to",
      hex2,
      ..common
    ])
  assert action
    == SendMessage(
      identifier(hex),
      "text/plain",
      InputStdin,
      Some(identifier(hex2)),
    )

  assert parse(["send", "--contact", hex, ..common])
    == Error("give exactly one of --file and --stdin")
  assert parse(["send", "--contact", hex, "--file", "p", "--stdin", ..common])
    == Error("give exactly one of --file and --stdin")
}

pub fn receive_test() {
  let assert Ok(Client(action:, ..)) = parse(["receive", ..common])
  assert action == ReceiveMessages(None, 16, 0, Encoded)

  let assert Ok(Client(action:, ..)) =
    parse(["receive", "--contact", hex, "--max", "4", "--wait", "25", ..common])
  assert action == ReceiveMessages(Some(identifier(hex)), 4, 25, Encoded)

  // `--raw` prints one message, so the count is one.
  let assert Ok(Client(action:, ..)) = parse(["receive", "--raw", ..common])
  assert action == ReceiveMessages(None, 1, 0, Raw)

  assert result_is_error(parse(["receive", "--raw", "--json", ..common]))
  assert result_is_error(parse(["receive", "--raw", "--max", "5", ..common]))
  assert result_is_error(parse(["receive", "--raw", "--max", "16", ..common]))
  assert result_is_error(parse(["receive", "--wait", "31", ..common]))
  assert result_is_error(parse(["receive", "--max", "0", ..common]))
  assert result_is_error(parse(["receive", "--max", "x", ..common]))
}

pub fn ack_status_audit_health_test() {
  let assert Ok(Client(action:, ..)) =
    parse(["ack", "--message", hex, ..common])
  assert action == Acknowledge(identifier(hex))

  let assert Ok(Client(action:, ..)) =
    parse(["status", "--message", hex, ..common])
  assert action == MessageStatus(identifier(hex))

  let assert Ok(Client(action:, ..)) = parse(["audit", ..common])
  assert action == ShowAudit(None, 50)

  let assert Ok(Client(action:, ..)) =
    parse(["audit", "--contact", hex, "--limit", "7", ..common])
  assert action == ShowAudit(Some(identifier(hex)), 7)

  let assert Ok(Client(action:, ..)) = parse(["health", ..common])
  assert action == ShowHealth
}

pub fn daemon_test() {
  let assert Ok(RunDaemon(options)) =
    parse([
      "daemon", "--state-dir", "/s", "--mailbox", "abc.onion:80",
      "--provision-file", "/p",
    ])
  assert options == DaemonOptions("/s", "abc.onion:80", "/p", cli.Tor, None)

  let assert Ok(RunDaemon(options)) =
    parse([
      "daemon", "--state-dir", "/s", "--mailbox", "127.0.0.1:8080",
      "--provision-file", "/p", "--carrier", "loopback", "--tor-bin", "/bin/tor",
    ])
  assert options.carrier == cli.Loopback
  assert options.tor_bin == Some("/bin/tor")

  let base = ["daemon", "--state-dir", "/s", "--provision-file", "/p"]
  assert result_is_error(parse(list.append(base, ["--mailbox", "nohost"])))
  assert result_is_error(parse(list.append(base, ["--mailbox", "h:0"])))
  assert result_is_error(parse(list.append(base, ["--mailbox", "h:99999"])))
  assert result_is_error(parse(list.append(base, ["--mailbox", ":80"])))
  assert result_is_error(parse(["daemon", "--state-dir", "/s"]))
  assert result_is_error(
    parse(list.append(base, ["--mailbox", "h:80", "--carrier", "pigeon"])),
  )
}

pub fn the_target_is_resolved_from_options_and_environment_test() {
  let assert Ok(Client(target:, ..)) =
    parse(["health", "--state-dir", "/s", "--credential-file", "/agent.cred"])
  assert target == Target("/s/api.sock", "/agent.cred")

  let assert Ok(Client(target:, ..)) =
    cli.parse(["health", "--state-dir", "/s"], Some("/env.cred"))
  assert target == Target("/s/api.sock", "/env.cred")

  // The option beats the environment, and `--socket` beats the state dir.
  let assert Ok(Client(target:, ..)) =
    cli.parse(
      [
        "health", "--socket", "/x.sock", "--state-dir", "/s",
        "--credential-file", "/opt.cred",
      ],
      Some("/env.cred"),
    )
  assert target == Target("/x.sock", "/opt.cred")

  assert result_is_error(parse(["health"]))
  assert result_is_error(parse(["health", "--socket", "/x.sock"]))

  let assert Ok(Client(target:, ..)) =
    parse(["health", "--socket", "/x.sock", "--credential-file", "/c"])
  assert target == Target("/x.sock", "/c")
}

pub fn json_output_is_a_flag_test() {
  let assert Ok(Client(output:, ..)) = parse(["health", "--json", ..common])
  assert output == JsonOutput
}

pub fn bad_command_lines_are_usage_errors_test() {
  assert parse([]) == Error("unknown command")
  assert parse(["frobnicate"]) == Error("unknown command")
  assert parse(["contact"]) == Error("unknown command")
  assert parse(["health", "stray", ..common])
    == Error(
      "unexpected argument; secrets are read from a file or standard input",
    )
  assert parse(["health", "--state-dir"])
    == Error("missing value for --state-dir")
  assert parse(["health", "--json", "--json", ..common])
    == Error("repeated option --json")
  assert parse(["health", "--state-dir", "/a", "--state-dir", "/b"])
    == Error("repeated option --state-dir")
  assert result_is_error(parse(["ack", "--message", "nothex", ..common]))
  assert result_is_error(parse(["ack", ..common]))
  assert result_is_error(
    parse(["contact", "budget", "--contact", hex, "--add", "0", ..common]),
  )
  assert parse(["help"]) == Ok(cli.Help)
}

/// Every command, written out once with its required options.
fn every_command() -> List(List(String)) {
  [
    ["invite", "create", "--description", "d", "--budget", "1", "--out", "o"],
    ["invite", "accept", "--file", "f"],
    ["contacts", "list"],
    ["contact", "approve", "--contact", hex],
    ["contact", "decline", "--contact", hex],
    ["contact", "close", "--contact", hex],
    ["contact", "budget", "--contact", hex, "--add", "1"],
    ["send", "--contact", hex, "--file", "f"],
    ["receive"],
    ["ack", "--message", hex],
    ["status", "--message", hex],
    ["audit"],
    ["health"],
    ["daemon", "--mailbox", "h:80", "--provision-file", "p"],
  ]
}

pub fn the_baseline_commands_parse_test() {
  list.each(every_command(), fn(command) {
    assert !result_is_error(parse(list.append(command, common)))
  })
}

pub fn no_command_accepts_a_payload_or_a_credential_in_argv_test() {
  // The names a secret could arrive under. `--credential-file` and
  // `--provision-file` name files, so they are not here.
  let secret_options = [
    "--payload", "--data", "--body", "--text", "--message-body", "--content",
    "--credential", "--cred", "--token", "--secret", "--password", "--key",
    "--capability", "--invitation",
  ]

  list.each(every_command(), fn(command) {
    list.each(secret_options, fn(name) {
      let line = list.append(command, [name, "s3cret", ..common])
      let assert Error(message) = parse(line)

      // The refusal names the option and never repeats its value.
      assert message == "unknown option " <> name
      assert !string.contains(message, "s3cret")
    })
  })
}

/// A ticket is a secret, so no command takes one in argv: `--ticket` is a
/// flag, and a ticket typed after it, or anywhere else, is refused without
/// the refusal repeating it (ADR-009).
pub fn no_command_accepts_a_ticket_in_argv_test() {
  let ticket = "rw1qy352euf40x77qfrg4ncn27daufrg4ncn27daufrg4ncn27daufrg"
  let commands = [
    ["invite", "create", "--description", "d", "--budget", "1", "--ticket"],
    ["invite", "accept", "--ticket", "--stdin"],
    ..every_command()
  ]

  list.each(commands, fn(command) {
    list.each(
      [
        [ticket],
        ["--ticket", ticket],
        ["--ticket-text", ticket],
        ["--ticket=" <> ticket],
      ],
      fn(extra) {
        let line = list.flatten([command, extra, common])
        let assert Error(message) = parse(line)

        assert !string.contains(message, ticket)
        assert !string.contains(message, "rw1")
      },
    )
  })
}

/// The CLI waits for an invitation or a ticket's redemption at least as
/// long as the daemon may work on it, so it never reports a failure for an
/// invitation that is then created or a contact that is then accepted.
pub fn the_cli_outwaits_the_daemon_on_invitations_test() {
  let daemon_bound =
    api.invite_wait_ms + api.ticket_wait_ms + api.ticket_call_ms

  assert cli.invitation_timeout_ms >= daemon_bound
  assert cli.timeout_ms(CreateInvite("d", AutoApprove, 1, TicketOnly))
    == cli.invitation_timeout_ms
  assert cli.timeout_ms(AcceptInvite(InputStdin, FromTicket, ""))
    == cli.invitation_timeout_ms
}

pub fn requests_carry_the_wire_shape_test() {
  let assert Ok(Client(action:, ..)) =
    parse([
      "send",
      "--contact",
      hex,
      "--file",
      "p",
      "--reply-to",
      hex2,
      ..common
    ])
  let #(op, args) = cli.request(action, <<"hi":utf8>>)

  assert op == "send"
  assert json.to_string(args)
    == "{\"contact\":\""
    <> hex
    <> "\",\"content_type\":\"application/octet-stream\",\"payload\":\"aGk=\",\"in_reply_to\":\""
    <> hex2
    <> "\"}"

  let #(op, _) = cli.request(ShowHealth, <<>>)
  assert op == "health"
  let #(op, _) = cli.request(Acknowledge(identifier(hex)), <<>>)
  assert op == "acknowledge"
}

pub fn exit_codes_follow_the_documented_table_test() {
  assert cli.exit_code(protocol.Unauthorized) == 3
  assert cli.exit_code(protocol.Forbidden) == 3
  assert cli.exit_code(protocol.NotFound) == 4
  assert cli.exit_code(protocol.Invalid) == 5
  assert cli.exit_code(protocol.Refused) == 5
  assert cli.exit_code(protocol.TooLarge) == 5
  assert cli.exit_code(protocol.Unavailable) == 6
}

fn result_is_error(result: Result(a, b)) -> Bool {
  case result {
    Ok(_) -> False
    Error(_) -> True
  }
}
