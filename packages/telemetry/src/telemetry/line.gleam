//// One of our own log lines, rendered: pure and total.
////
//// A line is `component=<word> event=<word>` followed by its fields, in the
//// order the caller gave them. The handler's formatter puts `time=` and
//// `level=` in front, so every line in the stream, ours and OTP's alike,
//// starts the same way. Rendering here rather than in the formatter keeps
//// it a pure function a test can call and grep, and leaves the formatter
//// nothing to decide about our lines: it prints them as given.
////
//// The line carries no timestamp of its own. The handler stamps `logger`'s
//// time, so a log call reads no clock and changes nothing a test injects.

import gleam/list
import gleam/string
import telemetry/field.{type Field}
import telemetry/logfmt

/// The body of one line: component, event and fields.
///
/// ## Examples
///
/// ```gleam
/// assert line.render("http", "request", [field.count("status", 200)])
///   == "component=http event=request status=200"
/// ```
pub fn render(component: String, event: String, fields: List(Field)) -> String {
  let head = [
    "component=" <> logfmt.word(component),
    "event=" <> logfmt.word(event),
  ]

  list.append(head, list.map(fields, field.render))
  |> string.join(" ")
}
