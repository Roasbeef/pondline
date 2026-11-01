//// Installs Reedwire's handler: one logfmt stream on standard error, with
//// OTP's own reports scrubbed.
////
//// An entry point calls `install` (or `install_from_env`) before it starts
//// anything, and nothing else does: a library that reconfigured `logger`
//// would change the VM of whatever embedded it, and the simulation, which
//// silences `logger` around its runs, would be un-silenced by a node start.
////
//// ## What installing does
////
//// It replaces OTP's `default` handler with the stock `logger_std_h` (its
//// overload protection and supervision unchanged) writing to **standard
//// error**, formatted by `telemetry_ffi:format/2`, and sets the primary
//// level. Standard error because standard output is a protocol here: the
//// mailbox prints `listening` and `onion` lines a launcher parses, and
//// `reedwire receive --raw` writes payload bytes there. Below `debug`, a
//// filter drops OTP's progress reports (a child started), which say nothing
//// an operator acts on.
////
//// The formatter prints our own lines as `telemetry/line` rendered them.
//// Everything else, a crash report, a supervisor report, a `gen_server`
//// termination, a library's warning, is rebuilt from its shape: the report
//// kind, the process's registered name, the reason's tag and where it was
//// raised. A process's state, its last message, its mailbox, its
//// dictionary, a stack frame's arguments and a reason's data are never
//// printed, because any of them can be a payload, a key or a capability.
//// `telemetry_ffi.erl` has the rules, one function per report kind.

import telemetry/internal/ffi_logger
import telemetry/level.{type Level}

/// The environment variable an operator sets to choose the threshold:
/// `debug`, `info`, `warning` or `error` (`level.parse`).
pub const level_variable = "REEDWIRE_LOG_LEVEL"

/// Installs the handler at `threshold`. Idempotent: a second call
/// replaces the same configuration, which is what a second test does.
/// `Error(Nil)` means `logger` refused the handler, and an entry point
/// should refuse to start rather than run with OTP's unscrubbed one.
///
/// ## Examples
///
/// ```gleam
/// handler.install(level.Info)
/// // -> Ok(Nil)
/// ```
pub fn install(threshold: Level) -> Result(Nil, Nil) {
  ffi_logger.install(threshold)
}

/// Installs the handler at the threshold `REEDWIRE_LOG_LEVEL` names, or
/// `info`, and returns the threshold it used.
///
/// ## Examples
///
/// ```gleam
/// handler.install_from_env()
/// // -> Ok(level.Info)
/// ```
pub fn install_from_env() -> Result(Level, Nil) {
  let threshold = threshold_named(ffi_logger.getenv(level_variable))

  // The caller learns the threshold only when the handler is in place.
  case install(threshold) {
    Ok(Nil) -> Ok(threshold)
    Error(Nil) -> Error(Nil)
  }
}

/// The threshold an operator asked for, or `info` when they asked for
/// nothing or for something unrecognised. A misspelled level is not worth
/// refusing to start over.
///
/// ## Examples
///
/// ```gleam
/// assert handler.threshold_named(Ok("debug")) == level.Debug
/// ```
///
/// ```gleam
/// assert handler.threshold_named(Error(Nil)) == level.Info
/// ```
pub fn threshold_named(named: Result(String, Nil)) -> Level {
  case named {
    Ok(text) ->
      case level.parse(text) {
        Ok(parsed) -> parsed
        Error(Nil) -> level.Info
      }

    Error(Nil) -> level.Info
  }
}
