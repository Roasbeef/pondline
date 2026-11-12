import core/endpoint
import core/grant
import core/id
import core/limits
import core/secret
import daemon/cli
import daemon/cli_run
import daemon/credential
import daemon/internal/ffi_local_system
import daemon/local_api
import daemon/local_api_backend
import daemon/local_api_client
import daemon/local_api_fixture as fixture
import daemon/local_api_protocol as protocol
import daemon/local_api_types
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import simplifile

/// One request over a fresh connection, expecting an answer.
fn ask(
  f: fixture.Fixture,
  credential: BitArray,
  op: String,
  args: List(#(String, json.Json)),
) -> protocol.Response {
  let assert Ok(response) =
    local_api_client.call(f.socket, credential, op, json.object(args), 5000)

  response
}

/// The result of a successful response.
fn succeeded(response: protocol.Response) -> Dynamic {
  let assert protocol.Succeeded(result) = response
  result
}

/// Asserts a failed response and returns its category.
fn category(response: protocol.Response) -> protocol.Category {
  let assert protocol.Failed(category, _) = response
  category
}

fn string_at(result: Dynamic, path: List(String)) -> String {
  let assert Ok(value) = decode.run(result, decode.at(path, decode.string))
  value
}

/// A string field of the first element of a list field.
fn first_string(result: Dynamic, list_field: String, name: String) -> String {
  let assert Ok(items) =
    decode.run(result, decode.at([list_field], decode.list(decode.dynamic)))
  let assert [first, ..] = items

  string_at(first, [name])
}

fn contact_hex() -> String {
  id.to_hex(fixture.contact())
}

fn message_hex() -> String {
  id.to_hex(fixture.message())
}

pub fn every_operator_op_round_trips_test() {
  use f <- fixture.with_server

  let invite =
    ask(f, f.operator, "invite", [
      #("description", json.string("for bob")),
      #("approval", json.string("auto")),
      #("budget", json.int(5)),
    ])
    |> succeeded
  assert string_at(invite, ["invitation"])
    == bit_array.base64_encode(<<"INVITATION-BYTES", 255, 0>>, True)

  let accept =
    ask(f, f.operator, "accept", [
      #("invitation", json.string(bit_array.base64_encode(<<1, 2, 3>>, True))),
      #("description", json.string("alice")),
    ])
    |> succeeded
  assert string_at(accept, ["contact"]) == contact_hex()

  let contacts = ask(f, f.operator, "contacts", []) |> succeeded
  assert first_string(contacts, "contacts", "phase") == "active"

  let who = [#("contact", json.string(contact_hex()))]
  let _ = ask(f, f.operator, "approve", who) |> succeeded
  let _ = ask(f, f.operator, "decline", who) |> succeeded
  let _ = ask(f, f.operator, "close", who) |> succeeded

  let _ =
    ask(f, f.operator, "raise_budget", [
      #("contact", json.string(contact_hex())),
      #("by", json.int(7)),
    ])
    |> succeeded

  let audit =
    ask(f, f.operator, "audit", [#("limit", json.int(10))]) |> succeeded
  assert first_string(audit, "entries", "direction") == "outbound"
  assert first_string(audit, "entries", "payload")
    == bit_array.base64_encode(<<"hello audit":utf8>>, True)

  let incidents =
    ask(f, f.operator, "incidents", [#("limit", json.int(3))]) |> succeeded
  assert first_string(incidents, "incidents", "kind") == "repeated_message"
  assert first_string(incidents, "incidents", "message") == message_hex()

  assert fixture.calls(f.fake)
    == [
      "invite for bob AutoApprove 5",
      "accept 010203 alice",
      "contacts",
      "approve " <> contact_hex(),
      "decline " <> contact_hex(),
      "close " <> contact_hex(),
      "raise_budget " <> contact_hex() <> " 7",
      "audit 10",
      "incidents 3",
    ]
}

pub fn every_agent_op_round_trips_test() {
  use f <- fixture.with_server

  let _ = ask(f, f.agent, "contacts", []) |> succeeded

  let sent =
    ask(f, f.agent, "send", [
      #("contact", json.string(contact_hex())),
      #("content_type", json.string("text/plain")),
      #("payload", json.string(bit_array.base64_encode(<<0, 255, 7>>, True))),
      #("in_reply_to", json.string(message_hex())),
    ])
    |> succeeded
  assert string_at(sent, ["message"]) == message_hex()

  fixture.deliver(f.fake, fixture.delivery(<<0, 200, 1>>))
  let received =
    ask(f, f.agent, "receive", [
      #("contact", json.null()),
      #("max", json.int(4)),
    ])
    |> succeeded
  assert first_string(received, "deliveries", "payload")
    == bit_array.base64_encode(<<0, 200, 1>>, True)
  assert first_string(received, "deliveries", "content_type") == "text/plain"

  let which = [#("message", json.string(message_hex()))]
  let _ = ask(f, f.agent, "acknowledge", which) |> succeeded
  let status = ask(f, f.agent, "status", which) |> succeeded
  assert string_at(status, ["state"]) == "stored_by_mailbox"

  let health = ask(f, f.agent, "health", []) |> succeeded
  assert string_at(health, ["mailbox"]) == "reachable"

  assert fixture.calls(f.fake)
    == [
      "contacts",
      "send "
        <> contact_hex()
        <> " text/plain 00FF07 Some(\""
        <> message_hex()
        <> "\")",
      "receive 4",
      "acknowledge " <> message_hex(),
      "status " <> message_hex(),
      "health",
    ]
}

pub fn the_agent_credential_is_forbidden_on_operator_ops_test() {
  use f <- fixture.with_server

  let who = [#("contact", json.string(contact_hex()))]
  let operator_ops = [
    #("invite", [
      #("description", json.string("x")),
      #("budget", json.int(1)),
    ]),
    #("accept", [#("invitation", json.string("AAAA"))]),
    #("approve", who),
    #("decline", who),
    #("close", who),
    #("raise_budget", [
      #("contact", json.string(contact_hex())),
      #("by", json.int(1)),
    ]),
    #("audit", []),
    #("incidents", []),
  ]

  list.each(operator_ops, fn(op) {
    assert category(ask(f, f.agent, op.0, op.1)) == protocol.Forbidden
  })

  // Not one of them reached the backend.
  assert fixture.calls(f.fake) == []
}

pub fn a_forbidden_op_is_refused_before_its_arguments_are_read_test() {
  use f <- fixture.with_server

  // The arguments are garbage, and the agent still learns only `forbidden`.
  assert category(ask(f, f.agent, "approve", [#("contact", json.int(3))]))
    == protocol.Forbidden
}

pub fn a_wrong_credential_is_unauthorized_test() {
  use f <- fixture.with_server

  assert category(ask(f, <<0:256>>, "health", [])) == protocol.Unauthorized
  assert category(ask(f, <<>>, "health", [])) == protocol.Unauthorized

  // A credential that is not base64 is wrong in the same way.
  let assert Ok(reply) =
    local_api_client.call_line(
      f.socket,
      <<"{\"v\":1,\"credential\":\"!!!\",\"op\":\"health\"}":utf8>>,
      5000,
    )
  assert string.contains(bit_array_text(reply), "unauthorized")
  assert fixture.calls(f.fake) == []
}

pub fn a_response_never_contains_a_credential_test() {
  use f <- fixture.with_server

  let operator_b64 = bit_array.base64_encode(f.operator, True)
  let agent_b64 = bit_array.base64_encode(f.agent, True)

  let bad = [
    #("{not json", Nil),
    #("{\"v\":1,\"credential\":\"" <> agent_b64 <> "\",\"op\":\"nope\"}", Nil),
    #("{\"v\":1,\"credential\":\"" <> agent_b64 <> "\",\"op\":\"audit\"}", Nil),
    #(
      "{\"v\":1,\"credential\":\"" <> operator_b64 <> "x\",\"op\":\"health\"}",
      Nil,
    ),
  ]

  list.each(bad, fn(request) {
    let assert Ok(reply) =
      local_api_client.call_line(f.socket, <<request.0:utf8>>, 5000)
    let text = bit_array_text(reply)

    assert !string.contains(text, operator_b64)
    assert !string.contains(text, agent_b64)
  })
}

fn bit_array_text(bytes: BitArray) -> String {
  let assert Ok(text) = bit_array.to_string(bytes)
  text
}

pub fn malformed_requests_are_invalid_and_leave_the_server_up_test() {
  use f <- fixture.with_server

  let operator = bit_array.base64_encode(f.operator, True)
  let with_credential = fn(rest: String) {
    "{\"v\":1,\"credential\":\"" <> operator <> "\"," <> rest <> "}"
  }

  let lines = [
    "not json at all",
    "[]",
    "{}",
    "{\"v\":1}",
    "{\"v\":2,\"credential\":\"" <> operator <> "\",\"op\":\"health\"}",
    with_credential("\"op\":\"no_such_op\""),
    with_credential("\"op\":7"),
    with_credential("\"op\":\"approve\",\"args\":{}"),
    with_credential("\"op\":\"approve\",\"args\":{\"contact\":\"zz\"}"),
    with_credential("\"op\":\"approve\",\"args\":\"nope\""),
    with_credential(
      "\"op\":\"send\",\"args\":{\"contact\":\""
      <> contact_hex()
      <> "\",\"payload\":\"***\"}",
    ),
    with_credential(
      "\"op\":\"invite\",\"args\":{\"description\":\"d\",\"budget\":0}",
    ),
    with_credential(
      "\"op\":\"invite\",\"args\":{\"description\":\"d\",\"budget\":1,\"approval\":\"maybe\"}",
    ),
  ]

  list.each(lines, fn(line) {
    let assert Ok(reply) =
      local_api_client.call_line(f.socket, <<line:utf8>>, 5000)
    let assert Ok(response) = protocol.parse_response(bit_array_text(reply))

    assert category(response) == protocol.Invalid
  })

  // Bytes that are not UTF-8 are invalid too.
  let assert Ok(reply) =
    local_api_client.call_line(f.socket, <<255, 254, 253>>, 5000)
  assert string.contains(bit_array_text(reply), "invalid")

  // Nothing reached the backend, and the server still answers.
  assert fixture.calls(f.fake) == []
  let _ = ask(f, f.operator, "health", []) |> succeeded
  Nil
}

pub fn an_over_long_line_is_refused_and_the_server_survives_test() {
  use f <- fixture.with_server

  let long =
    bit_array.from_string(string.repeat("a", protocol.max_line_bytes + 1))
  let outcome = local_api_client.call_line(f.socket, long, 5000)

  // The server answers `too_large` and closes. A client still writing when
  // it closes may see the reset instead of the answer, so either is right;
  // what matters is that the line was not served.
  case outcome {
    Ok(reply) -> {
      assert string.contains(bit_array_text(reply), "too_large")
    }

    Error(_) -> Nil
  }

  let _ = ask(f, f.operator, "health", []) |> succeeded
  assert fixture.calls(f.fake) == ["health"]
}

pub fn a_line_at_the_bound_is_still_served_test() {
  use f <- fixture.with_server

  // A line of exactly the bound is not too long. It is garbage, so it is
  // invalid, which proves it was read whole.
  let line = bit_array.from_string(string.repeat("a", protocol.max_line_bytes))
  let assert Ok(reply) = local_api_client.call_line(f.socket, line, 5000)

  assert string.contains(bit_array_text(reply), "invalid")
}

pub fn a_payload_over_the_body_limit_is_too_large_test() {
  use f <- fixture.with_server

  let big = bit_array.from_string(string.repeat("a", limits.max_body_bytes + 1))
  let response =
    ask(f, f.agent, "send", [
      #("contact", json.string(contact_hex())),
      #("payload", json.string(bit_array.base64_encode(big, True))),
    ])
  assert category(response) == protocol.TooLarge

  let fits = bit_array.from_string(string.repeat("a", limits.max_body_bytes))
  let _ =
    ask(f, f.agent, "send", [
      #("contact", json.string(contact_hex())),
      #("payload", json.string(bit_array.base64_encode(fits, True))),
    ])
    |> succeeded
  Nil
}

pub fn backend_errors_map_to_stable_categories_test() {
  let make = fn(fake) {
    local_api_types.Backend(
      ..fixture.backend(fake),
      approve: fn(_) { Error(local_api_types.NotFound) },
      accept: fn(_, _, _) {
        Error(local_api_types.InvalidInvitation("expired"))
      },
      send: fn(_, _, _, _, _) { Error(local_api_types.Refused("budget spent")) },
      status: fn(_) { Error(local_api_types.Unavailable) },
    )
  }
  use f <- fixture.with_backend(make)

  let who = [#("contact", json.string(contact_hex()))]
  assert category(ask(f, f.operator, "approve", who)) == protocol.NotFound

  assert category(
      ask(f, f.operator, "accept", [#("invitation", json.string("AAAA"))]),
    )
    == protocol.Invalid

  let sent =
    ask(f, f.agent, "send", [
      #("contact", json.string(contact_hex())),
      #("payload", json.string("AAAA")),
    ])
  assert category(sent) == protocol.Refused
  let assert protocol.Failed(_, "budget spent") = sent

  assert category(
      ask(f, f.agent, "status", [#("message", json.string(message_hex()))]),
    )
    == protocol.Unavailable
}

pub fn a_waiting_receive_returns_when_messages_become_ready_test() {
  use f <- fixture.with_server

  let _ =
    process.spawn(fn() {
      process.sleep(300)
      fixture.deliver(f.fake, fixture.delivery(<<"wake":utf8>>))
    })

  let started = ffi_local_system.monotonic_ms()
  let result =
    ask(f, f.agent, "receive", [#("wait_ms", json.int(20_000))]) |> succeeded
  let elapsed = ffi_local_system.monotonic_ms() - started

  assert first_string(result, "deliveries", "payload")
    == bit_array.base64_encode(<<"wake":utf8>>, True)

  // It woke on the announcement, not on the deadline.
  assert elapsed >= 250
  assert elapsed < 10_000
}

pub fn a_waiting_receive_times_out_empty_test() {
  use f <- fixture.with_server

  let started = ffi_local_system.monotonic_ms()
  let result =
    ask(f, f.agent, "receive", [#("wait_ms", json.int(400))]) |> succeeded
  let elapsed = ffi_local_system.monotonic_ms() - started

  let assert Ok(deliveries) =
    decode.run(result, decode.at(["deliveries"], decode.list(decode.dynamic)))
  assert deliveries == []
  assert elapsed >= 350
}

pub fn a_receive_without_wait_returns_at_once_test() {
  use f <- fixture.with_server

  let started = ffi_local_system.monotonic_ms()
  let _ = ask(f, f.agent, "receive", []) |> succeeded
  assert ffi_local_system.monotonic_ms() - started < 2000
}

pub fn the_socket_is_owner_only_and_stale_sockets_are_replaced_test() {
  use f <- fixture.with_server

  assert ffi_local_system.file_mode(f.socket) == Ok(0o600)
  assert ffi_local_system.file_mode(f.dir) == Ok(0o700)

  // A second server on the same path replaces the stale file and serves.
  let assert Ok(credentials) = credential.ensure(f.dir)
  let assert Ok(second) =
    local_api.start(fixture.backend(f.fake), credentials, f.socket)
  let _ = ask(f, f.operator, "health", []) |> succeeded
  local_api.stop(second)
}

pub fn the_credential_files_are_private_and_never_in_output_test() {
  use f <- fixture.with_server

  assert ffi_local_system.file_mode(f.dir <> "/" <> credential.operator_file)
    == Ok(0o600)
  assert ffi_local_system.file_mode(f.dir <> "/" <> credential.agent_file)
    == Ok(0o600)
  assert bit_array.byte_size(f.operator) == credential.credential_bytes
  assert f.operator != f.agent

  let assert Ok(entries) = simplifile.read_directory(f.dir)
  assert list.sort(entries, string.compare)
    == ["agent.cred", "api.sock", "operator.cred"]
}

/// `invite` with `"ticket": true` answers the file and the ticket, and
/// `accept` takes a ticket in place of a file (ADR-009). The agent scope
/// can do neither, as for the plain forms.
pub fn invite_and_accept_carry_a_ticket_test() {
  use f <- fixture.with_server

  let invited =
    ask(f, f.operator, "invite", [
      #("description", json.string("t")),
      #("budget", json.int(2)),
      #("ticket", json.bool(True)),
    ])
    |> succeeded
  assert string_at(invited, ["ticket"]) == fixture.fake_ticket
  assert string_at(invited, ["invitation"])
    == bit_array.base64_encode(<<"INVITATION-BYTES", 255, 0>>, True)

  let accepted =
    ask(f, f.operator, "accept", [
      #("ticket", json.string("pl1abc")),
      #("description", json.string("al")),
    ])
    |> succeeded
  assert string_at(accepted, ["contact"]) == contact_hex()

  assert category(
      ask(f, f.agent, "accept", [#("ticket", json.string("pl1abc"))]),
    )
    == protocol.Forbidden

  assert fixture.calls(f.fake)
    == ["invite_ticket t OperatorApproves 2", "accept_ticket pl1abc al"]
}

/// `accept` takes exactly one of an invitation and a ticket, and its
/// refusal does not repeat the ticket.
pub fn accept_takes_exactly_one_source_test() {
  use f <- fixture.with_server

  let both =
    ask(f, f.operator, "accept", [
      #("invitation", json.string("AAAA")),
      #("ticket", json.string("pl1secretticket")),
    ])
  let neither = ask(f, f.operator, "accept", [])

  assert category(both) == protocol.Invalid
  assert category(neither) == protocol.Invalid
  assert !string.contains(string.inspect(both), "pl1secretticket")
  assert fixture.calls(f.fake) == []
}

/// An `idempotency_key` reaches the backend with the send, and its absence
/// (or `null`) is no key at all (ADR-011).
pub fn a_send_carries_its_idempotency_key_test() {
  use f <- fixture.with_server

  let base = [
    #("contact", json.string(contact_hex())),
    #("content_type", json.string("text/plain")),
    #("payload", json.string(bit_array.base64_encode(<<1>>, True))),
  ]
  let _ =
    ask(f, f.agent, "send", [#("idempotency_key", json.string("k-1")), ..base])
    |> succeeded
  let _ =
    ask(f, f.agent, "send", [#("idempotency_key", json.null()), ..base])
    |> succeeded

  assert fixture.calls(f.fake)
    == [
      "send " <> contact_hex() <> " text/plain 01 None key=k-1",
      "send " <> contact_hex() <> " text/plain 01 None",
    ]
}

pub fn daemon_tor_sidecar_resolution_and_fail_fast_test() {
  let none = fn(_) { Error(Nil) }
  let has = fn(expected) { fn(path) { path == expected } }

  assert local_api_backend.resolve_tor_bin(
      Some("/opt/pondline-tor"),
      none,
      none,
      has("/opt/pondline-tor"),
    )
    == Ok("/opt/pondline-tor")
  assert local_api_backend.resolve_tor_bin(
      None,
      fn(_) { Ok("/bundle/bin/pondline-tor") },
      none,
      has("/bundle/bin/pondline-tor"),
    )
    == Ok("/bundle/bin/pondline-tor")
  assert local_api_backend.resolve_tor_bin(None, none, none, fn(_) { False })
    == Error(
      "could not find pondline-tor; pass --tor-bin or set PONDLINE_TOR_BIN",
    )
}

pub fn apply_grant_token_writes_private_capability_and_scrubs_errors_test() {
  let dir =
    "build/grant_token_test_" <> int.to_string(int.random(1_000_000_000))
  let _ = simplifile.delete(dir)
  let assert Ok(ep) = endpoint.parse("127.0.0.1:4199")
  let cap_bytes = <<42:256>>
  let assert Ok(token) = grant.from_parts(ep, cap_bytes)
  let raw = <<{ secret.expose(grant.encode(token)) }:bits, "\n":utf8>>

  let assert Ok(#(mailbox, cap_file)) = cli_run.apply_grant_token(dir, raw)
  assert mailbox == "127.0.0.1:4199"
  assert cap_file == dir <> "/provision.cap"
  assert simplifile.read_bits(cap_file) == Ok(cap_bytes)
  assert ffi_local_system.file_mode(cap_file) == Ok(0o600)

  let bad = <<"plg1secretbadtoken":utf8>>
  let assert Error(outcome) = cli_run.apply_grant_token(dir, bad)
  assert !string.contains(outcome.stderr, "plg1secretbadtoken")
  let _ = simplifile.delete(dir)
}

pub fn init_and_saved_config_round_trip_test() {
  let _ = simplifile.create_directory_all("build")
  let dir = "build/init_cfg_test_" <> int.to_string(int.random(1_000_000_000))
  let _ = simplifile.delete(dir)
  let assert Ok(ep) = endpoint.parse("127.0.0.1:4299")
  let cap_bytes = <<77:256>>
  let assert Ok(token) = grant.from_parts(ep, cap_bytes)
  let grant_file = dir <> "_grant.txt"
  let assert Ok(Nil) =
    simplifile.write_bits(grant_file, secret.expose(grant.encode(token)))

  // Loopback endpoint without `--carrier loopback` is refused by policy.
  let refused =
    cli_run.run(
      cli.InitDaemon(cli.InitCommand(
        dir,
        cli.GrantMailbox(cli.InputFile(grant_file)),
        cli.Tor,
        None,
        cli.HumanOutput,
      )),
    )
  assert refused.status == cli.exit_refused

  // With `--carrier loopback`, `init` saves 0600 `config.json`, `provision.cap`, and credentials.
  let ok =
    cli_run.run(
      cli.InitDaemon(cli.InitCommand(
        dir,
        cli.GrantMailbox(cli.InputFile(grant_file)),
        cli.Loopback,
        None,
        cli.JsonOutput,
      )),
    )
  assert ok.status == cli.exit_ok
  assert ffi_local_system.file_mode(dir <> "/config.json") == Ok(0o600)
  assert ffi_local_system.file_mode(dir <> "/provision.cap") == Ok(0o600)
  assert ffi_local_system.file_mode(dir <> "/operator.cred") == Ok(0o600)

  let assert Ok(loaded) = cli_run.load_daemon_config(dir)
  assert loaded
    == cli.DaemonOptions(
      dir,
      "127.0.0.1:4299",
      dir <> "/provision.cap",
      cli.Loopback,
      None,
    )
  // A refused re-init must leave the existing `provision.cap` and `config.json` intact.
  let assert Ok(other_token) = grant.from_parts(ep, <<99:256>>)
  let other_file = dir <> "_other_grant.txt"
  let assert Ok(Nil) =
    simplifile.write_bits(other_file, secret.expose(grant.encode(other_token)))
  let bad_reinit =
    cli_run.run(
      cli.InitDaemon(cli.InitCommand(
        dir,
        cli.GrantMailbox(cli.InputFile(other_file)),
        cli.Tor,
        None,
        cli.HumanOutput,
      )),
    )
  assert bad_reinit.status == cli.exit_refused
  assert simplifile.read_bits(dir <> "/provision.cap") == Ok(cap_bytes)

  let _ = simplifile.delete(other_file)
  let _ = simplifile.delete(grant_file)
  let _ = simplifile.delete(dir)
}

pub fn cli_resolves_contact_by_petname_and_accept_budget_round_trips_test() {
  use f <- fixture.with_server
  let cred_file = f.dir <> "/agent_test.cred"
  let assert Ok(Nil) = ffi_local_system.write_private_file(cred_file, f.agent)
  let payload_file = f.dir <> "/msg.txt"
  let assert Ok(Nil) = simplifile.write(payload_file, "hello bob")

  // Sending with `--contact bob` resolves `"bob"` via `contacts` using the agent credential.
  let target = cli.Target(socket: f.socket, credential_file: cred_file)
  let send_out =
    cli_run.run(cli.Client(
      target,
      cli.HumanOutput,
      cli.SendMessage(
        cli.LookupContact("bob"),
        "text/plain",
        cli.InputFile(payload_file),
        None,
        None,
      ),
    ))
  assert send_out.status == cli.exit_ok

  // Unknown contact petname returns exit_not_found (4) and JSON error in `--json` mode.
  let miss_out =
    cli_run.run(cli.Client(
      target,
      cli.JsonOutput,
      cli.SendMessage(
        cli.LookupContact("mallory"),
        "text/plain",
        cli.InputFile(payload_file),
        None,
        None,
      ),
    ))
  assert miss_out.status == cli.exit_not_found
  let assert Ok(miss_json) = bit_array.to_string(miss_out.stdout)
  assert string.contains(miss_json, "\"not_found\"")

  // `accept` with explicit `"budget": 25` reaches the backend.
  let _ =
    ask(f, f.operator, "accept", [
      #("ticket", json.string("pl1example")),
      #("description", json.string("peer")),
      #("budget", json.int(25)),
    ])
    |> succeeded
  assert list.contains(
    fixture.calls(f.fake),
    "accept_ticket pl1example peer budget=25",
  )
}
