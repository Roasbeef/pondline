//// Confined FFI over OTP's `logger` (`docs/gleam-style.md` Part IV §4).
//// The Erlang side is `src/telemetry_ffi.erl`.
////
//// Why FFI: `logger` is where every OTP library, the supervisor and
//// `proc_lib` crash reporters and the emulator itself already write, and
//// neither the standard library nor `gleam_erlang` binds it. A sink of our
//// own would leave every crash report on OTP's unscrubbed stream, which is
//// the leak this package exists to close. A logger formatter is also, by
//// `logger`'s contract, a module exporting `format/2` that receives
//// arbitrary Erlang terms; classifying those terms (is this a tuple whose
//// first element is an atom, is this a stack trace) has no pure Gleam
//// spelling short of decoding every report shape OTP has.
////
//// Nothing here decides what our own lines say: `telemetry/line` renders
//// them and these functions carry the finished text across.

import telemetry/level.{type Level}

/// Replaces OTP's `default` handler with `logger_std_h` on standard error,
/// formatted by `telemetry_ffi:format/2`, and sets the primary level.
///
/// Binds `logger:remove_handler/1`, `logger:add_handler/3`,
/// `logger:update_handler_config/3` and `logger:set_primary_config/2`.
@external(erlang, "telemetry_ffi", "install")
pub fn install(threshold: Level) -> Result(Nil, Nil)

/// Whether `logger` would pass an event at `level` from this package.
///
/// Binds `logger:allow/2`.
@external(erlang, "telemetry_ffi", "enabled")
pub fn enabled(level: Level) -> Bool

/// Logs one rendered line at `level`, as the report `#{reedwire => Line}`
/// the formatter recognises as ours.
///
/// Binds `logger:log/3`.
@external(erlang, "telemetry_ffi", "emit")
pub fn emit(level: Level, line: String) -> Nil

/// The name of a value's constructor: an atom's own name, a tuple's first
/// element when it is an atom, otherwise the value's shape in angle
/// brackets. Never reads anything else from the value.
///
/// Binds `erlang:is_atom/1`, `erlang:element/2` and `atom_to_binary/2`;
/// Gleam has no way to ask a value its constructor without rendering it.
@external(erlang, "telemetry_ffi", "constructor_name")
pub fn constructor_name(value: a) -> String

/// An environment variable, if set.
///
/// Binds `os:getenv/1`; the standard library has no environment access.
@external(erlang, "telemetry_ffi", "getenv")
pub fn getenv(name: String) -> Result(String, Nil)
