//// Tests for the human and JSON rendering of `pondline messages`: the inbox
//// grouping and order, decoding, the UTC time, and the escaping of what a
//// peer sent.

import core/id
import daemon/cli.{
  type ContactEntry, ContactEntry, DecodeText, Encoded, KeepEncoded,
  ReceiveMessages, ShowAudit, ShowMessages,
}
import daemon/cli_render
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/option.{None}
import gleam/string

const kevin = "38a2bfd3162d902422d5d3363c3420c4"

const stranger = "aaaaaaaabbbbbbbbccccccccdddddddd"

/// A daemon `audit` result built from `entries`, each a JSON object.
fn result_of(entries: List(String)) -> Dynamic {
  let text = "{\"entries\":[" <> string.join(entries, ",") <> "]}"
  let assert Ok(result) = json.parse(text, decode.dynamic)

  result
}

/// One audit entry for `contact`. `payload` is base64.
fn entry_for(
  contact: String,
  at: Int,
  direction: String,
  content_type: String,
  payload: String,
) -> String {
  "{\"at\":"
  <> int.to_string(at)
  <> ",\"direction\":\""
  <> direction
  <> "\",\"contact\":\""
  <> contact
  <> "\",\"message\":\"7129a71c4fe0968dbe23a68d5ec9f3f5\""
  <> ",\"content_type\":\""
  <> content_type
  <> "\",\"payload\":\""
  <> payload
  <> "\"}"
}

/// One audit entry for the first contact.
fn entry(
  at: Int,
  direction: String,
  content_type: String,
  payload: String,
) -> String {
  entry_for(kevin, at, direction, content_type, payload)
}

/// A contact the daemon lists under `name`.
fn named(hex: String, name: String) -> ContactEntry {
  let assert Ok(contact) = id.from_hex(hex)

  ContactEntry(contact:, phase: "active", description: name)
}

/// What `messages` prints for `entries` with `names`, as text.
fn rendered(entries: List(String), names: List(ContactEntry)) -> String {
  let assert Ok(cli_render.Rendered(stdout:, ..)) =
    cli_render.render(
      ShowMessages(None, 20, DecodeText),
      result_of(entries),
      names,
    )
  let assert Ok(text) = bit_array.to_string(stdout)

  text
}

const header_0 = "  1970-01-01 00:00:00Z  <-  text/plain  7129a71c\n"

pub fn a_contact_is_titled_by_its_name_and_read_oldest_first_test() {
  // The daemon answers newest first; the reader wants the order they were said.
  let text =
    rendered(
      [
        entry(1_795_016_705, "inbound", "text/plain", "b2s="),
        entry(1_795_016_636, "outbound", "text/plain", "b2s="),
      ],
      [named(kevin, "kevin")],
    )

  assert text
    == "kevin  (38a2bfd3)\n"
    <> "  2026-11-18 15:43:56Z  ->  text/plain  7129a71c\n    ok\n\n"
    <> "  2026-11-18 15:45:05Z  <-  text/plain  7129a71c\n    ok\n"
}

pub fn an_unnamed_contact_is_titled_by_its_prefix_test() {
  assert rendered([entry(0, "inbound", "text/plain", "b2s=")], [])
    == "38a2bfd3\n" <> header_0 <> "    ok\n"
}

pub fn contacts_are_sorted_by_latest_activity_with_a_blank_line_between_test() {
  // Newest first: the stranger spoke last, then kevin twice.
  let text =
    rendered(
      [
        entry_for(stranger, 30, "inbound", "text/plain", "b2s="),
        entry(20, "inbound", "text/plain", "b2s="),
        entry(10, "outbound", "text/plain", "b2s="),
      ],
      [named(kevin, "kevin")],
    )

  assert text
    == "aaaaaaaa\n"
    <> "  1970-01-01 00:00:30Z  <-  text/plain  7129a71c\n    ok\n\n"
    <> "kevin  (38a2bfd3)\n"
    <> "  1970-01-01 00:00:10Z  ->  text/plain  7129a71c\n    ok\n\n"
    <> "  1970-01-01 00:00:20Z  <-  text/plain  7129a71c\n    ok\n"
}

pub fn a_multi_line_payload_is_indented_on_every_line_test() {
  let text = rendered([entry(0, "inbound", "text/plain", "aGkKdGhlcmU=")], [])

  assert text == "38a2bfd3\n" <> header_0 <> "    hi\n    there\n"
}

pub fn a_blank_line_in_a_payload_has_no_trailing_spaces_test() {
  // "a", an empty line, "b".
  let text = rendered([entry(0, "inbound", "text/plain", "YQoKYg==")], [])

  assert text == "38a2bfd3\n" <> header_0 <> "    a\n\n    b\n"
}

pub fn no_messages_print_nothing_test() {
  assert rendered([], []) == ""
}

pub fn a_leap_day_and_a_century_boundary_render_correctly_test() {
  let leap = rendered([entry(951_782_400, "inbound", "text/plain", "b2s=")], [])
  let modern =
    rendered([entry(1_709_164_800, "inbound", "text/plain", "b2s=")], [])
  let century =
    rendered([entry(4_102_444_800, "inbound", "text/plain", "b2s=")], [])

  assert string.contains(leap, "2000-02-29 00:00:00Z")
  assert string.contains(modern, "2024-02-29 00:00:00Z")
  assert string.contains(century, "2100-01-01 00:00:00Z")
}

pub fn a_terminal_escape_in_a_payload_is_written_out_test() {
  // ESC [ 31 m would turn the operator's terminal red; it must print as text.
  let text = rendered([entry(0, "inbound", "text/plain", "YRtbMzFtcmVk")], [])

  assert text == "38a2bfd3\n" <> header_0 <> "    a\\x1b[31mred\n"
}

pub fn a_c1_control_in_a_payload_is_written_out_test() {
  // U+0085 is a control some terminals treat as a line break or an escape.
  let text = rendered([entry(0, "inbound", "text/plain", "eMKFeQ==")], [])

  assert text == "38a2bfd3\n" <> header_0 <> "    x\\x85y\n"
}

pub fn a_newline_in_a_content_type_cannot_forge_a_header_test() {
  // The peer's content type tries to start a second, header-looking line.
  let forged = "x\\n2026-11-18 10:00:00Z  <-  text/plain"
  let text = rendered([entry(0, "inbound", forged, "b2s=")], [])

  assert text
    == "38a2bfd3\n"
    <> "  1970-01-01 00:00:00Z  <-  x\\x0a2026-11-18 10:00:00Z  <-  text/plain  7129a71c\n"
    <> "    ok\n"
}

pub fn a_control_character_in_a_name_is_written_out_test() {
  // The name is the operator's own, but it is printed on one line.
  let text =
    rendered([entry(0, "inbound", "text/plain", "b2s=")], [
      named(kevin, "ke\u{1b}vin"),
    ])

  assert string.starts_with(text, "ke\\x1bvin  (38a2bfd3)\n")
}

pub fn a_payload_that_is_not_utf8_prints_as_base64_test() {
  let text =
    rendered([entry(0, "inbound", "application/octet-stream", "//4=")], [])

  assert text
    == "38a2bfd3\n"
    <> "  1970-01-01 00:00:00Z  <-  application/octet-stream  7129a71c\n"
    <> "    base64://4=\n"
}

pub fn no_decode_keeps_the_base64_in_the_human_view_test() {
  let assert Ok(cli_render.Rendered(stdout:, ..)) =
    cli_render.render(
      ShowMessages(None, 20, KeepEncoded),
      result_of([entry(0, "inbound", "text/plain", "b2s=")]),
      [],
    )
  let assert Ok(text) = bit_array.to_string(stdout)

  assert text == "38a2bfd3\n" <> header_0 <> "    base64:b2s=\n"
}

pub fn a_malformed_result_is_an_error_not_a_crash_test() {
  let assert Ok(result) = json.parse("{\"entries\":3}", decode.dynamic)

  assert cli_render.render(ShowMessages(None, 20, DecodeText), result, [])
    == Error("the daemon sent a malformed result")
  assert cli_render.messages_json(result, [], DecodeText)
    == Error("the daemon sent a malformed result")
}

const json_head = "{\"ok\":true,\"result\":{\"contacts\":["

pub fn json_groups_by_contact_and_decodes_text_test() {
  let assert Ok(text) =
    cli_render.messages_json(
      result_of([
        entry(1_795_016_705, "inbound", "text/plain", "b2s="),
        entry(1_795_016_636, "outbound", "text/plain", "b2s="),
      ]),
      [named(kevin, "kevin")],
      DecodeText,
    )

  assert text
    == json_head
    <> "{\"contact\":\"38a2bfd3162d902422d5d3363c3420c4\",\"description\":\"kevin\","
    <> "\"messages\":["
    <> "{\"message\":\"7129a71c4fe0968dbe23a68d5ec9f3f5\",\"direction\":\"outbound\","
    <> "\"at\":1795016636,\"time\":\"2026-11-18 15:43:56Z\","
    <> "\"content_type\":\"text/plain\",\"text\":\"ok\"},"
    <> "{\"message\":\"7129a71c4fe0968dbe23a68d5ec9f3f5\",\"direction\":\"inbound\","
    <> "\"at\":1795016705,\"time\":\"2026-11-18 15:45:05Z\","
    <> "\"content_type\":\"text/plain\",\"text\":\"ok\"}]}]}}"
}

pub fn json_gives_an_unknown_contact_a_null_description_test() {
  let assert Ok(text) =
    cli_render.messages_json(
      result_of([entry_for(stranger, 0, "inbound", "text/plain", "b2s=")]),
      [],
      DecodeText,
    )

  assert string.contains(text, "\"description\":null")
}

pub fn json_no_decode_returns_only_the_base64_payload_test() {
  let assert Ok(text) =
    cli_render.messages_json(
      result_of([entry(0, "inbound", "text/plain", "b2s=")]),
      [],
      KeepEncoded,
    )

  assert string.contains(text, "\"payload\":\"b2s=\"")
  assert !string.contains(text, "\"text\"")
}

pub fn json_returns_base64_for_a_payload_that_is_not_text_test() {
  let assert Ok(text) =
    cli_render.messages_json(
      result_of([entry(0, "inbound", "application/octet-stream", "//4=")]),
      [],
      DecodeText,
    )

  assert string.contains(text, "\"payload\":\"//4=\"")
  assert !string.contains(text, "\"text\"")
}

pub fn json_with_no_messages_is_an_empty_inbox_test() {
  assert cli_render.messages_json(result_of([]), [], DecodeText)
    == Ok(json_head <> "]}}")
}

pub fn audit_escapes_a_content_type_test() {
  // ESC ] 0 ; ... BEL would retitle the terminal if it were printed raw.
  let assert Ok(cli_render.Rendered(stdout:, ..)) =
    cli_render.render(
      ShowAudit(None, 20),
      result_of([entry(0, "inbound", "\\u001b]0;pwned\\u0007", "b2s=")]),
      [],
    )
  let assert Ok(text) = bit_array.to_string(stdout)

  assert string.contains(text, "\\x1b]0;pwned\\x07")
  assert !string.contains(text, "\u{1b}")
}

pub fn receive_escapes_a_content_type_test() {
  let delivery =
    "{\"deliveries\":[{\"message\":\"7129a71c4fe0968dbe23a68d5ec9f3f5\","
    <> "\"contact\":\"38a2bfd3162d902422d5d3363c3420c4\","
    <> "\"content_type\":\"\\u001b[2J\",\"payload\":\"b2s=\","
    <> "\"in_reply_to\":null,\"received_at\":0}]}"
  let assert Ok(result) = json.parse(delivery, decode.dynamic)
  let assert Ok(cli_render.Rendered(stdout:, ..)) =
    cli_render.render(ReceiveMessages(None, 16, 0, Encoded), result, [])
  let assert Ok(text) = bit_array.to_string(stdout)

  assert string.contains(text, " \\x1b[2J ")
  assert !string.contains(text, "\u{1b}")
}
