//// The two token rules of a logfmt line, in one place.
////
//// Every line Pondline writes is `key=value` pairs separated by single
//// spaces: logfmt, which a person reads in a terminal and which Loki,
//// Vector and `grep key=value` all parse. Two rules keep it parseable
//// whatever a value holds. A key is one bare word (`word`), and a value
//// that is not a bare token is quoted with its quotes, backslashes and
//// control characters escaped (`quote`), so no value can end a pair early
//// or start a new line. Both our own lines (`telemetry/line`) and the
//// Erlang formatter's rendering of OTP's reports call these two
//// functions, so there is one escaping rule and the tests reach it.

import gleam/int
import gleam/list
import gleam/string

/// `text` with anything outside `[a-z0-9_]` replaced by `_`, so a key is
/// always one bare token. Keys are literals, so this only guards a typo.
///
/// ## Examples
///
/// ```gleam
/// assert logfmt.word("queue id") == "queue_id"
/// ```
pub fn word(text: String) -> String {
  text
  |> string.to_graphemes
  |> list.map(fn(grapheme) {
    case string.contains("abcdefghijklmnopqrstuvwxyz0123456789_", grapheme) {
      True -> grapheme
      False -> "_"
    }
  })
  |> string.concat
}

/// `text` as one logfmt value: bare when it is a non-empty run of
/// printable characters other than space, `"`, `=` and `\`; otherwise
/// quoted, with `"` and `\` escaped and every control character written
/// as `\n`, `\r`, `\t` or `\u{hex}`.
///
/// ## Examples
///
/// ```gleam
/// assert logfmt.quote("busy") == "busy"
/// ```
///
/// ```gleam
/// assert logfmt.quote("two words") == "\"two words\""
/// ```
pub fn quote(text: String) -> String {
  let codepoints = string.to_utf_codepoints(text)

  // A bare token needs no escaping; anything else is quoted whole.
  case text != "" && list.all(codepoints, bare) {
    True -> text
    False -> "\"" <> string.concat(list.map(codepoints, escape)) <> "\""
  }
}

/// Whether a codepoint may appear in a bare value: printable, and none
/// of the four characters that delimit or escape.
fn bare(codepoint: UtfCodepoint) -> Bool {
  let value = string.utf_codepoint_to_int(codepoint)
  value > 0x20
  && value != 0x7f
  && value != 0x22
  && value != 0x3d
  && value != 0x5c
}

/// One codepoint inside a quoted value.
fn escape(codepoint: UtfCodepoint) -> String {
  let value = string.utf_codepoint_to_int(codepoint)

  // The four common escapes by name, any other control character by
  // number, and everything printable as itself.
  case value {
    0x22 -> "\\\""
    0x5c -> "\\\\"
    0x0a -> "\\n"
    0x0d -> "\\r"
    0x09 -> "\\t"
    _ if value < 0x20 || value == 0x7f ->
      "\\u{" <> string.lowercase(int.to_base16(value)) <> "}"
    _ -> string.from_utf_codepoints([codepoint])
  }
}
