//// Log levels, and the policy for what goes at which one.
////
//// Four levels, exactly Erlang `logger`'s `debug`, `info`, `warning` and
//// `error`, so a value crosses to `logger:log/3` unchanged. OTP's other
//// four (`notice`, `critical`, `alert`, `emergency`) draw distinctions a
//// single-host daemon has no use for: there is no pager and no fleet. A
//// foreign event at one of them is still printed under its own name.
////
//// The policy, which every call site follows:
////
//// - **`error`**: something could not be done and nothing will retry it.
////   A process crashed (every OTP crash and supervisor report is here), a
////   start was refused, a row was dropped for good. An `error` line is one
////   an operator should read.
//// - **`warning`**: degraded but still progressing. A write lost its
////   version check, a storage operation failed and the caller will try
////   again, the mailbox refused a request the worker will repeat. Read
////   after the fact, not during.
//// - **`info`**: the lifecycle skeleton and the mailbox's access log: a
////   program started, one line per HTTP request. Sized so a whole run at
////   `info`, the default, is readable by a person.
//// - **`debug`**: per-message steps and OTP's progress reports (a child
////   started), which the handler drops at any other threshold.
////
//// No level carries a value that is not one of `telemetry/field`'s typed
//// kinds, so the level chooses how much is said, never what may be said.

import gleam/option.{None, Some}
import gleam/string

/// A log level, ordered by severity.
///
/// Constructor invariant: the four constructors compile to the atoms
/// `debug`, `info`, `warning` and `error`, which are Erlang `logger`'s own
/// level names.
pub type Level {
  /// Per-message steps and OTP progress reports; off by default.
  Debug

  /// The lifecycle skeleton and the access log; the default threshold.
  Info

  /// Degraded but progressing.
  Warning

  /// Nothing will retry it; an operator should read it.
  Error
}

/// The level's name, as it appears on a line and as `logger` spells it.
///
/// ## Examples
///
/// ```gleam
/// assert level.name(level.Warning) == "warning"
/// ```
pub fn name(level: Level) -> String {
  case level {
    Debug -> "debug"
    Info -> "info"
    Warning -> "warning"
    Error -> "error"
  }
}

/// Parses an operator's level name, ignoring case and surrounding space,
/// and taking `warn` and `err` as the abbreviations people type. Anything
/// else is `Error(Nil)`, and the caller keeps its default.
///
/// ## Examples
///
/// ```gleam
/// assert level.parse(" WARN ") == Ok(level.Warning)
/// ```
///
/// ```gleam
/// assert level.parse("loud") == Error(Nil)
/// ```
pub fn parse(text: String) -> Result(Level, Nil) {
  // `Error` is a constructor of this module's type and shadows the
  // prelude's here, so the failure is built through `Option`.
  case string.lowercase(string.trim(text)) {
    "debug" -> Some(Debug)
    "info" -> Some(Info)
    "warn" | "warning" -> Some(Warning)
    "err" | "error" -> Some(Error)
    _ -> None
  }
  |> option.to_result(Nil)
}
