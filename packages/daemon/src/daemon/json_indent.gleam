//// Indents compact JSON for a person to read.
////
//// `--json` is the form a program reads, so it stays one compact line: a
//// program takes a response a line at a time. When standard output is a
//// terminal, someone is reading it instead, and `pondline` runs the same text
//// through this module. The text is re-indented, never decoded and encoded
//// again, so no number, key order or escape can change: the only edit is
//// whitespace between tokens, and none of it is added inside a string.
////
//// The scanner has three states: outside a string, inside one, and just after
//// a backslash inside one. The last exists so that an escaped quote, which
//// does not end a string, is not mistaken for one. The input is trusted to be
//// JSON that `pondline` itself produced; anything else is indented as well as
//// the same rules allow and is not otherwise checked.

import gleam/int
import gleam/list
import gleam/string

/// Where the scanner is in the text.
type Scan {
  /// Between tokens, where structure characters mean something.
  Outside

  /// Inside a string, where every character is data.
  InString

  /// The character after a backslash in a string, which is data whatever it is.
  Escaped
}

/// Two spaces for each level of nesting.
const indent_width = 2

/// Re-indents compact JSON: each member and element on its own line, two
/// spaces per level, one space after a colon, and `{}` or `[]` left whole.
///
/// ## Examples
///
/// ```gleam
/// json_indent.indent("{\"ok\":true,\"result\":{\"n\":1}}")
/// // -> "{\n  \"ok\": true,\n  \"result\": {\n    \"n\": 1\n  }\n}"
/// ```
pub fn indent(compact: String) -> String {
  string.to_utf_codepoints(compact)
  |> scan(0, Outside, [])
  |> list.reverse
  |> string.from_utf_codepoints
}

/// Walks the text once. `out` is the output so far, reversed, so that adding
/// to it is a cons.
fn scan(
  rest: List(UtfCodepoint),
  depth: Int,
  state: Scan,
  out: List(UtfCodepoint),
) -> List(UtfCodepoint) {
  // The end of the text ends the walk; otherwise one codepoint is handled and
  // the rest is walked with whatever state it leaves behind.
  case rest {
    [] -> out

    [point, ..tail] -> {
      let code = string.utf_codepoint_to_int(point)

      // What a codepoint means depends on whether it is inside a string, so
      // the scanner state is matched first and the codepoint second.
      case state, code {
        // A backslash hands one character to the string, so `\"` stays inside it.
        Escaped, _ -> scan(tail, depth, InString, [point, ..out])
        InString, 0x5c -> scan(tail, depth, Escaped, [point, ..out])
        InString, 0x22 -> scan(tail, depth, Outside, [point, ..out])
        InString, _ -> scan(tail, depth, InString, [point, ..out])

        Outside, 0x22 -> scan(tail, depth, InString, [point, ..out])
        Outside, 0x7b | Outside, 0x5b -> open(point, code, tail, depth, out)

        Outside, 0x7d | Outside, 0x5d -> {
          let out = line_break(out, int.max(depth - 1, 0))

          scan(tail, int.max(depth - 1, 0), Outside, [point, ..out])
        }

        Outside, 0x2c ->
          scan(tail, depth, Outside, line_break([point, ..out], depth))
        Outside, 0x3a -> scan(tail, depth, Outside, push(" ", [point, ..out]))
        Outside, _ -> scan(tail, depth, Outside, [point, ..out])
      }
    }
  }
}

/// Handles `{` and `[`. An object or array that closes at once is written
/// whole, because a line holding only an opener is noise.
fn open(
  point: UtfCodepoint,
  code: Int,
  tail: List(UtfCodepoint),
  depth: Int,
  out: List(UtfCodepoint),
) -> List(UtfCodepoint) {
  // `{` closes with `}` and `[` with `]`.
  let closer = case code {
    0x7b -> 0x7d
    _ -> 0x5d
  }

  // Only the very next codepoint can make the container empty, because
  // compact JSON has no whitespace to look past.
  case tail {
    [next, ..after] ->
      // A closer straight after the opener is the empty container.
      case string.utf_codepoint_to_int(next) == closer {
        True -> scan(after, depth, Outside, [next, point, ..out])
        False ->
          scan(tail, depth + 1, Outside, line_break([point, ..out], depth + 1))
      }

    [] -> [point, ..out]
  }
}

/// A newline and the indentation for `depth`, added to the reversed output.
fn line_break(out: List(UtfCodepoint), depth: Int) -> List(UtfCodepoint) {
  push("\n" <> string.repeat(" ", depth * indent_width), out)
}

/// Adds `text` to the reversed output.
fn push(text: String, out: List(UtfCodepoint)) -> List(UtfCodepoint) {
  list.fold(string.to_utf_codepoints(text), out, fn(acc, point) {
    [point, ..acc]
  })
}
