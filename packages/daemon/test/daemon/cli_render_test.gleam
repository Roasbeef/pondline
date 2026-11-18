//// Tests for the human rendering of `pondline messages`: the order,
//// the UTC time, the indentation, and the escaping of what a peer sent.

import daemon/cli.{Encoded, ReceiveMessages, ShowAudit, ShowMessages}
import daemon/cli_render
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/option.{None}
import gleam/string

/// A daemon `audit` result built from `entries`, each a JSON object.
fn result_of(entries: List(String)) -> Dynamic {
  let text = "{\"entries\":[" <> string.join(entries, ",") <> "]}"
  let assert Ok(result) = json.parse(text, decode.dynamic)

  result
}

fn entry(
  at: Int,
  direction: String,
  content_type: String,
  payload: String,
) -> String {
  "{\"at\":"
  <> int.to_string(at)
  <> ",\"direction\":\""
  <> direction
  <> "\",\"contact\":\"38a2bfd3162d902422d5d3363c3420c4\""
  <> ",\"message\":\"7129a71c4fe0968dbe23a68d5ec9f3f5\""
  <> ",\"content_type\":\""
  <> content_type
  <> "\",\"payload\":\""
  <> payload
  <> "\"}"
}

/// What `messages` prints for `entries`, as text.
fn rendered(entries: List(String)) -> String {
  let assert Ok(cli_render.Rendered(stdout:, ..)) =
    cli_render.render(ShowMessages(None, 20), result_of(entries))
  let assert Ok(text) = bit_array.to_string(stdout)

  text
}

pub fn messages_read_oldest_first_with_a_blank_line_between_test() {
  // The daemon answers newest first; the reader wants the order they were said.
  let text =
    rendered([
      entry(1_795_016_705, "inbound", "text/plain", "b2s="),
      entry(1_795_016_636, "outbound", "text/plain", "b2s="),
    ])

  assert text
    == "2026-11-18 15:43:56Z  ->  38a2bfd3  text/plain\n  ok\n\n"
    <> "2026-11-18 15:45:05Z  <-  38a2bfd3  text/plain\n  ok\n"
}

pub fn a_multi_line_payload_is_indented_on_every_line_test() {
  let text = rendered([entry(0, "inbound", "text/plain", "aGkKdGhlcmU=")])

  assert text
    == "1970-01-01 00:00:00Z  <-  38a2bfd3  text/plain\n  hi\n  there\n"
}

pub fn no_messages_print_nothing_test() {
  assert rendered([]) == ""
}

pub fn a_leap_day_and_a_century_boundary_render_correctly_test() {
  let leap = rendered([entry(951_782_400, "inbound", "text/plain", "b2s=")])
  let modern = rendered([entry(1_709_164_800, "inbound", "text/plain", "b2s=")])
  let century =
    rendered([entry(4_102_444_800, "inbound", "text/plain", "b2s=")])

  assert leap == "2000-02-29 00:00:00Z  <-  38a2bfd3  text/plain\n  ok\n"
  assert modern == "2024-02-29 00:00:00Z  <-  38a2bfd3  text/plain\n  ok\n"
  assert century == "2100-01-01 00:00:00Z  <-  38a2bfd3  text/plain\n  ok\n"
}

pub fn a_terminal_escape_in_a_payload_is_written_out_test() {
  // ESC [ 31 m would turn the operator's terminal red; it must print as text.
  let text = rendered([entry(0, "inbound", "text/plain", "YRtbMzFtcmVk")])

  assert text
    == "1970-01-01 00:00:00Z  <-  38a2bfd3  text/plain\n  a\\x1b[31mred\n"
}

pub fn a_c1_control_in_a_payload_is_written_out_test() {
  // U+0085 is a control some terminals treat as a line break or an escape.
  let text = rendered([entry(0, "inbound", "text/plain", "eMKFeQ==")])

  assert text == "1970-01-01 00:00:00Z  <-  38a2bfd3  text/plain\n  x\\x85y\n"
}

pub fn a_control_character_in_a_content_type_is_written_out_test() {
  let text = rendered([entry(0, "inbound", "text/\\u001bplain", "b2s=")])

  assert text == "1970-01-01 00:00:00Z  <-  38a2bfd3  text/\\x1bplain\n  ok\n"
}

pub fn a_payload_that_is_not_utf8_prints_as_base64_test() {
  let text = rendered([entry(0, "inbound", "application/octet-stream", "//4=")])

  assert text
    == "1970-01-01 00:00:00Z  <-  38a2bfd3  application/octet-stream\n  base64://4=\n"
}

pub fn a_malformed_result_is_an_error_not_a_crash_test() {
  let assert Ok(result) = json.parse("{\"entries\":3}", decode.dynamic)

  assert cli_render.render(ShowMessages(None, 20), result)
    == Error("the daemon sent a malformed result")
}

pub fn a_newline_in_a_content_type_cannot_forge_a_header_test() {
  // The peer's content type tries to start a second, indented-looking header.
  let forged = "x\\n2026-11-18 10:00:00Z  <-  abcd1234  text/plain"
  let text = rendered([entry(0, "inbound", forged, "b2s=")])

  assert text
    == "1970-01-01 00:00:00Z  <-  38a2bfd3  x\\x0a2026-11-18 10:00:00Z  <-  abcd1234  text/plain\n  ok\n"
}

pub fn a_tab_in_a_content_type_is_written_out_test() {
  let text = rendered([entry(0, "inbound", "a\\tb", "b2s=")])

  assert text == "1970-01-01 00:00:00Z  <-  38a2bfd3  a\\x09b\n  ok\n"
}

pub fn audit_escapes_a_content_type_test() {
  // ESC ] 0 ; ... BEL would retitle the terminal if it were printed raw.
  let assert Ok(cli_render.Rendered(stdout:, ..)) =
    cli_render.render(
      ShowAudit(None, 20),
      result_of([entry(0, "inbound", "\\u001b]0;pwned\\u0007", "b2s=")]),
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
    cli_render.render(ReceiveMessages(None, 16, 0, Encoded), result)
  let assert Ok(text) = bit_array.to_string(stdout)

  assert string.contains(text, " \\x1b[2J ")
  assert !string.contains(text, "\u{1b}")
}
