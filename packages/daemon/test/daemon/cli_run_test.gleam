import core/id
import daemon/cli
import daemon/cli_run.{type Outcome}
import daemon/internal/ffi_local_system
import daemon/local_api_fixture as fixture
import daemon/local_api_types
import gleam/bit_array
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
