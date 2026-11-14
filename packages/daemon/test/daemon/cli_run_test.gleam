import core/id
import daemon/cli
import daemon/cli_run.{type Outcome}
import daemon/internal/ffi_local_system
import daemon/local_api_fixture as fixture
import daemon/local_api_types
import gleam/bit_array
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{None}
import gleam/string
import simplifile

fn run(f: fixture.Fixture, arguments: List(String)) -> Outcome {
  let assert Ok(command) =
    cli.parse(
      list.append(arguments, [
        "--state-dir",
        f.dir,
      ]),
      None,
    )

  cli_run.run(command)
}

fn run_as_agent(f: fixture.Fixture, arguments: List(String)) -> Outcome {
  run(f, list.append(arguments, ["--credential-file", f.dir <> "/agent.cred"]))
}

fn stdout(outcome: Outcome) -> String {
  let assert Ok(text) = bit_array.to_string(outcome.stdout)
  text
}

fn contact_hex() -> String {
  id.to_hex(fixture.contact())
}

fn message_hex() -> String {
  id.to_hex(fixture.message())
}

pub fn health_in_json_prints_the_response_line_test() {
  use f <- fixture.with_server

  let outcome = run(f, ["health", "--json"])

  assert outcome.status == 0
  assert stdout(outcome)
    == "{\"ok\":true,\"result\":{\"mailbox\":\"reachable\"}}\n"
}

pub fn incidents_print_one_line_each_without_a_payload_test() {
  use f <- fixture.with_server

  let outcome = run(f, ["incidents", "--limit", "5"])

  assert outcome.status == 0
  assert stdout(outcome)
    == "1700000002 repeated_message contact="
    <> contact_hex()
    <> " message="
    <> message_hex()
    <> " attempts=-\n"
}

pub fn contacts_list_prints_one_line_per_contact_test() {
  use f <- fixture.with_server

  let outcome = run(f, ["contacts", "list"])

  assert outcome.status == 0
  assert stdout(outcome) == contact_hex() <> " active budget=3/10 held=1 bob\n"
}

pub fn send_reads_its_payload_from_a_file_test() {
  use f <- fixture.with_server

  let path = f.dir <> "/payload.bin"
  let assert Ok(Nil) = simplifile.write_bits(path, <<0, 255, 7>>)

  let outcome =
    run_as_agent(f, ["send", "--contact", contact_hex(), "--file", path])

  assert outcome.status == 0
  assert stdout(outcome) == message_hex() <> "\n"
  assert list.any(fixture.calls(f.fake), string.contains(_, " 00FF07 "))
}

pub fn receive_raw_writes_the_payload_bytes_alone_test() {
  use f <- fixture.with_server

  fixture.deliver(f.fake, fixture.delivery(<<0, 200, 255, 10>>))
  let outcome = run_as_agent(f, ["receive", "--raw", "--wait", "5"])

  assert outcome.status == 0
  assert outcome.stdout == <<0, 200, 255, 10>>
  assert outcome.stderr
    == "message " <> message_hex() <> " contact " <> contact_hex()
}

pub fn receive_prints_headers_and_base64_test() {
  use f <- fixture.with_server

  fixture.deliver(f.fake, fixture.delivery(<<"hi":utf8>>))
  let outcome = run_as_agent(f, ["receive"])

  assert stdout(outcome)
    == message_hex()
    <> " "
    <> contact_hex()
    <> " text/plain bytes=2 at=1700000000\naGk=\n"
}

pub fn invite_create_writes_a_private_file_and_refuses_to_overwrite_test() {
  use f <- fixture.with_server

  let out = f.dir <> "/bob.invite"
  let arguments = [
    "invite", "create", "--description", "bob", "--budget", "3", "--out", out,
  ]

  let first = run(f, arguments)
  assert first.status == 0
  assert stdout(first) == "wrote " <> out <> "\n"
  assert simplifile.read_bits(out) == Ok(<<"INVITATION-BYTES", 255, 0>>)
  assert ffi_local_system.file_mode(out) == Ok(0o600)

  // Neither output mode puts the invitation on the terminal.
  let json = run(f, list.append(arguments, ["--json"]))
  assert json.status == cli.exit_refused

  let second_json_path = f.dir <> "/carol.invite"
  let printed =
    run(f, [
      "invite", "create", "--description", "c", "--budget", "1", "--out",
      second_json_path, "--json",
    ])
  assert printed.status == 0
  assert !string.contains(stdout(printed), "INVITATION")
  assert !string.contains(stdout(printed), "SU5WSVRBVElPTi")

  // The second attempt on the same path was refused before the daemon was
  // asked, so only the two successful creates reached the backend.
  assert list.length(
      list.filter(fixture.calls(f.fake), string.starts_with(_, "invite")),
    )
    == 2
}

pub fn invite_accept_reads_the_file_test() {
  use f <- fixture.with_server

  let path = f.dir <> "/in.invite"
  let assert Ok(Nil) = simplifile.write_bits(path, <<1, 2, 3>>)
  let outcome =
    run(f, ["invite", "accept", "--file", path, "--description", "al"])

  assert outcome.status == 0
  assert stdout(outcome) == contact_hex() <> "\n"
  assert list.contains(fixture.calls(f.fake), "accept 010203 al")
}

/// `--ticket` prints the ticket alone on standard output, so a script can
/// capture it; with `--out` the file is written too and its path goes to
/// standard error. Neither mode prints the invitation file (ADR-009).
pub fn invite_create_with_a_ticket_prints_the_ticket_test() {
  use f <- fixture.with_server

  let base = ["invite", "create", "--description", "t", "--budget", "2"]

  let alone = run(f, list.append(base, ["--ticket"]))
  assert alone.status == 0
  assert stdout(alone) == fixture.fake_ticket <> "\n"
  assert alone.stderr == ""

  let out = f.dir <> "/both.invite"
  let both = run(f, list.append(base, ["--ticket", "--out", out]))
  assert both.status == 0
  assert stdout(both) == fixture.fake_ticket <> "\n"
  assert both.stderr == "wrote " <> out
  assert simplifile.read_bits(out) == Ok(<<"INVITATION-BYTES", 255, 0>>)
  assert ffi_local_system.file_mode(out) == Ok(0o600)

  let json = run(f, list.append(base, ["--ticket", "--json"]))
  assert json.status == 0
  assert stdout(json)
    == "{\"ok\":true,\"result\":{\"ticket\":\""
    <> fixture.fake_ticket
    <> "\",\"out\":null}}\n"
  assert !string.contains(stdout(json), "SU5WSVRBVElPTi")

  assert list.length(
      list.filter(fixture.calls(f.fake), string.starts_with(_, "invite_ticket")),
    )
    == 3
}

/// `invite accept --ticket` reads the ticket from its file and sends it as
/// a ticket, as written; `api.accept_ticket` drops the newline a paste
/// leaves, for every local API client alike.
pub fn invite_accept_with_a_ticket_reads_the_file_test() {
  use f <- fixture.with_server

  let path = f.dir <> "/ticket.txt"
  let assert Ok(Nil) = simplifile.write(path, "pl1abc\n")
  let outcome =
    run(f, [
      "invite",
      "accept",
      "--ticket",
      "--file",
      path,
      "--description",
      "al",
    ])

  assert outcome.status == 0
  assert stdout(outcome) == contact_hex() <> "\n"
  assert list.contains(fixture.calls(f.fake), "accept_ticket pl1abc\n al")
}

/// A ticket input that is not text, such as an invitation file given with
/// `--ticket`, is refused before the daemon is asked.
pub fn a_ticket_that_is_not_text_is_refused_locally_test() {
  use f <- fixture.with_server

  let path = f.dir <> "/binary.invite"
  let assert Ok(Nil) = simplifile.write_bits(path, <<255, 0, 254>>)
  let outcome = run(f, ["invite", "accept", "--ticket", "--file", path])

  assert outcome.status == cli.exit_refused
  assert fixture.calls(f.fake) == []
}

pub fn the_agent_credential_cannot_run_operator_commands_test() {
  use f <- fixture.with_server

  let outcome =
    run_as_agent(f, ["contact", "approve", "--contact", contact_hex()])

  assert outcome.status == cli.exit_unauthorized
  assert string.contains(outcome.stderr, "forbidden")
  assert fixture.calls(f.fake) == []
}

pub fn a_wrong_credential_file_exits_unauthorized_test() {
  use f <- fixture.with_server

  let path = f.dir <> "/wrong.cred"
  let assert Ok(Nil) = simplifile.write_bits(path, <<0:256>>)
  let outcome = run(f, ["health", "--credential-file", path])

  assert outcome.status == cli.exit_unauthorized

  let missing = run(f, ["health", "--credential-file", f.dir <> "/absent"])
  assert missing.status == cli.exit_unauthorized
}

pub fn an_unreachable_daemon_exits_unavailable_test() {
  use f <- fixture.with_server

  let outcome = run(f, ["health", "--socket", f.dir <> "/nobody.sock"])

  assert outcome.status == cli.exit_unavailable
}

pub fn backend_errors_set_the_exit_status_test() {
  let make = fn(fake) {
    local_api_types.Backend(
      ..fixture.backend(fake),
      approve: fn(_) { Error(local_api_types.NotFound) },
      status: fn(_) { Error(local_api_types.Refused("nope")) },
      health: fn() { local_api_types.Health([]) },
    )
  }
  use f <- fixture.with_backend(make)

  let missing = run(f, ["contact", "approve", "--contact", contact_hex()])
  assert missing.status == cli.exit_not_found

  let refused = run(f, ["status", "--message", message_hex(), "--json"])
  assert refused.status == cli.exit_refused
  assert stdout(refused)
    == "{\"ok\":false,\"error\":{\"category\":\"refused\",\"message\":\"nope\"}}\n"
}

pub fn an_unreadable_payload_file_exits_local_test() {
  use f <- fixture.with_server

  let outcome =
    run_as_agent(f, [
      "send",
      "--contact",
      contact_hex(),
      "--file",
      f.dir <> "/absent",
    ])

  assert outcome.status == cli.exit_local
}

// ---------------------------------------------------------- spoken codes

/// Runs a command as `run` does, collecting what it announces before its
/// answer.
fn run_announcing(
  f: fixture.Fixture,
  arguments: List(String),
) -> #(Outcome, List(#(BitArray, String))) {
  let assert Ok(command) =
    cli.parse(list.append(arguments, ["--state-dir", f.dir]), None)
  let announced = process.new_subject()

  let outcome =
    cli_run.run_with(command, fn(stdout, stderr) {
      process.send(announced, #(stdout, stderr))
    })

  #(outcome, drain(announced, []))
}

fn drain(subject: Subject(a), found: List(a)) -> List(a) {
  case process.receive(subject, 0) {
    Ok(value) -> drain(subject, [value, ..found])
    Error(Nil) -> list.reverse(found)
  }
}

/// `invite create --code` prints the code the moment the daemon answers,
/// alone on standard output, then waits for the run with a second request
/// and reports how it ended; the invitation is never printed (ADR-016).
pub fn invite_create_with_a_code_prints_it_then_waits_test() {
  use f <- fixture.with_server

  let base = ["invite", "create", "--description", "t", "--budget", "2"]
  let #(outcome, announced) = run_announcing(f, list.append(base, ["--code"]))

  assert announced
    == [
      #(
        <<fixture.fake_code:utf8, "\n">>,
        "waiting for the joiner to enter the code\n",
      ),
    ]
  assert outcome.status == 0
  assert outcome.stdout == <<>>
  assert string.starts_with(outcome.stderr, "paired:")
  assert fixture.calls(f.fake)
    == [
      "invite_code t OperatorApproves 2",
      "await_code " <> id.to_hex(fixture.run()),
    ]

  // In JSON mode both answers are response lines, the code's first.
  let #(json, announced) =
    run_announcing(f, list.append(base, ["--code", "--json"]))
  let assert [#(first, "")] = announced
  let assert Ok(first) = bit_array.to_string(first)
  assert first
    == "{\"ok\":true,\"result\":{\"run\":\""
    <> id.to_hex(fixture.run())
    <> "\",\"code\":\""
    <> fixture.fake_code
    <> "\",\"expires_at\":1700000600}}\n"
  assert json.status == 0
  assert stdout(json)
    == "{\"ok\":true,\"result\":{\"outcome\":\"paired\",\"contact\":null}}\n"
  assert !string.contains(first <> stdout(json), "SU5WSVRBVElPTi")
}

/// `invite accept --code` trims the code it reads and sends it as text;
/// the paired contact is printed as an accept always printed it.
pub fn invite_accept_with_a_code_trims_and_sends_it_test() {
  use f <- fixture.with_server

  let path = f.dir <> "/code.txt"
  let assert Ok(Nil) =
    simplifile.write(path, "  " <> fixture.fake_code <> " \n")
  let outcome =
    run(f, [
      "invite",
      "accept",
      "--code",
      "--file",
      path,
      "--rendezvous",
      "127.0.0.1:4000",
      "--description",
      "al",
    ])

  assert outcome.status == 0
  assert stdout(outcome) == contact_hex() <> "\n"
  assert fixture.calls(f.fake)
    == ["accept_code " <> fixture.fake_code <> " 127.0.0.1:4000 al"]
}

/// A code that does not decode is refused before the daemon is asked, so
/// it spends nothing; the refusal names the word's position and repeats
/// neither the code nor the word.
pub fn a_mistyped_code_is_refused_locally_test() {
  use f <- fixture.with_server

  let path = f.dir <> "/code.txt"
  let typed = "482719-cradle-nobel-velvet"
  let assert Ok(Nil) = simplifile.write(path, typed <> "\n")
  let outcome = run(f, ["invite", "accept", "--code", "--file", path])

  assert outcome.status == cli.exit_refused
  assert string.contains(outcome.stderr, "word 2 of the code")
  assert !string.contains(outcome.stderr, "nobel")
  assert !string.contains(outcome.stderr, "482719")
  assert fixture.calls(f.fake) == []
}

/// Each ending of a code's run is its own message and a refusal's exit
/// status, on both sides; the joiner's failed confirmation says it may have
/// been an interruption.
pub fn every_code_outcome_is_told_apart_test() {
  let endings = [
    #(local_api_types.NeverClaimed, "expired before anyone used it"),
    #(local_api_types.Stalled, "stopped before the exchange finished"),
    #(local_api_types.ConfirmationFailed, "the code did not match"),
  ]

  list.each(endings, fn(pair) {
    let make = fn(fake) {
      local_api_types.Backend(
        ..fixture.backend(fake),
        await_code: fn(_) { Ok(pair.0) },
        accept_code: fn(_, _, _, _) { Ok(pair.0) },
      )
    }
    use f <- fixture.with_backend(make)

    let #(inviting, _) =
      run_announcing(f, [
        "invite",
        "create",
        "--description",
        "t",
        "--budget",
        "2",
        "--code",
      ])
    let path = f.dir <> "/code.txt"
    let assert Ok(Nil) = simplifile.write(path, fixture.fake_code)
    let joining = run(f, ["invite", "accept", "--code", "--file", path])

    assert inviting.status == cli.exit_refused
    assert joining.status == cli.exit_refused
    assert string.contains(inviting.stderr, pair.1)
    assert string.contains(joining.stderr, pair.1)
    assert inviting.stdout == <<>>
    assert joining.stdout == <<>>
  })

  // Only the joiner's failed confirmation may be an interruption.
  let make = fn(fake) {
    local_api_types.Backend(
      ..fixture.backend(fake),
      accept_code: fn(_, _, _, _) { Ok(local_api_types.ConfirmationFailed) },
    )
  }
  use f <- fixture.with_backend(make)
  let path = f.dir <> "/code.txt"
  let assert Ok(Nil) = simplifile.write(path, fixture.fake_code)
  let joining = run(f, ["invite", "accept", "--code", "--file", path])
  assert string.contains(joining.stderr, "or the exchange was interrupted")
}
