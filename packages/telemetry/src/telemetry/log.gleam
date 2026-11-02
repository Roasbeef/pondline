//// The four calls every Pondline log line goes through.
////
//// `debug`, `info`, `warning` and `error` each take a component, an event
//// and a list of `telemetry/field` values. The component (`engine`,
//// `scheduler`, `http`) and the event (`storage_failed`, `request`) are
//// literals at every call site; the fields are the only values, and
//// `telemetry/field` admits no free-form string or bytes. The level is
//// chosen by the policy in `telemetry/level`.
////
//// A call is a global, not an injected logger: Pondline's processes are
//// few, each call site names its own component, and Erlang `logger` is
//// already the process-wide sink every OTP library writes to. A line below
//// the threshold is not rendered at all (`logger:allow/2`). A program that
//// never installed the handler (`telemetry/handler`) still logs, through
//// OTP's default handler and formatter; what it loses is the scrubbing of
//// OTP's own reports, not the typing of ours.
////
//// Nothing here reads a line back, and no line is ever the record of
//// anything: the store is.

import telemetry/field.{type Field}
import telemetry/internal/ffi_logger
import telemetry/level.{type Level}
import telemetry/line

/// A per-message step; off by default.
///
/// ## Examples
///
/// ```gleam
/// log.debug("fetcher", "polled", [field.count("envelopes", 3)])
/// // -> Nil
/// ```
pub fn debug(component: String, event: String, fields: List(Field)) -> Nil {
  emit(level.Debug, component, event, fields)
}

/// A lifecycle step or an access-log line.
///
/// ## Examples
///
/// ```gleam
/// log.info("node", "started", [])
/// // -> Nil
/// ```
pub fn info(component: String, event: String, fields: List(Field)) -> Nil {
  emit(level.Info, component, event, fields)
}

/// Degraded but progressing: something will be tried again.
///
/// ## Examples
///
/// ```gleam
/// log.warning("engine", "storage_failed", [field.tag("reason", error)])
/// // -> Nil
/// ```
pub fn warning(component: String, event: String, fields: List(Field)) -> Nil {
  emit(level.Warning, component, event, fields)
}

/// Nothing will retry it; an operator should read it.
///
/// ## Examples
///
/// ```gleam
/// log.error("node", "start_refused", [field.tag("reason", reason)])
/// // -> Nil
/// ```
pub fn error(component: String, event: String, fields: List(Field)) -> Nil {
  emit(level.Error, component, event, fields)
}

/// Renders and hands the line to `logger`, unless `logger` would drop it
/// at this level anyway, in which case nothing is rendered.
fn emit(
  level: Level,
  component: String,
  event: String,
  fields: List(Field),
) -> Nil {
  // The threshold check is `logger`'s own, so it agrees with the handler.
  case ffi_logger.enabled(level) {
    True -> ffi_logger.emit(level, line.render(component, event, fields))
    False -> Nil
  }
}
