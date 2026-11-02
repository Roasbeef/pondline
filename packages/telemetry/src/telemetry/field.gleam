//// The values a log line may carry, and nothing else.
////
//// Spec §12.4 keeps invitation secrets, capabilities, plaintext and
//// serialized crypto state out of every log. A rule that each call site
//// must remember is a rule that one call site eventually forgets, so this
//// module makes the forbidden values unrepresentable instead: a `Field`
//// holds one of four kinds, and none of them is a free-form string or
//// bytes.
////
//// - **`id`** takes a typed `core/id.Id` and renders the first
////   `id_prefix_chars` hex characters, enough to correlate the lines about
////   one contact, queue, envelope or message in a single daemon's log and
////   too few to be the identifier itself. Identifiers are not secrets
////   (`core/id`), so the prefix is a convenience, not a concession.
//// - **`count`** and **`millis`** take an `Int`: a number of things, a
////   size in bytes, a status code, a duration.
//// - **`tag`** takes a value of any type and renders only the name of its
////   constructor: `Busy` as `busy`, `Refused(reason)` as `refused`. The
////   fields inside are never read, so a reason that carries a payload
////   renders the same as one that does not, and a `String` or `BitArray`
////   passed by mistake renders as `<binary>`.
////
//// The event name and the component are the other two words on a line,
//// and callers pass them as literals (`telemetry/log`).

import core/id.{type Id}
import gleam/int
import gleam/string
import telemetry/internal/ffi_logger
import telemetry/logfmt

/// How many hex characters of an identifier a line carries: four bytes,
/// one in four billion per collision between two live identifiers.
pub const id_prefix_chars = 8

/// One `key=value` pair of a line. Opaque so that the four constructors
/// below are the only way to make one.
pub opaque type Field {
  Field(key: String, value: Value)
}

/// What a field holds. Every variant renders to a token with no spaces.
type Value {
  /// The leading hex characters of an identifier.
  Prefix(hex: String)

  /// A count, size or status.
  Number(value: Int)

  /// A duration in milliseconds, rendered under `<key>_ms`.
  Millis(value: Int)

  /// A constructor's name, read without its fields.
  Tag(name: String)
}

/// A typed identifier, rendered as its first `id_prefix_chars` hex
/// characters.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(queue) = id.from_hex("3fa2c1d0aabbccddeeff001122334455")
/// field.render(field.id("queue", queue))
/// // -> "queue=3fa2c1d0"
/// ```
pub fn id(key: String, id: Id(kind)) -> Field {
  Field(key:, value: Prefix(string.slice(id.to_hex(id), 0, id_prefix_chars)))
}

/// A count, size or status code.
///
/// ## Examples
///
/// ```gleam
/// assert field.render(field.count("status", 200)) == "status=200"
/// ```
pub fn count(key: String, value: Int) -> Field {
  Field(key:, value: Number(value))
}

/// A duration in milliseconds. The unit is in the rendered key, so the
/// value stays a bare number a log tool can compare.
///
/// ## Examples
///
/// ```gleam
/// assert field.render(field.millis("elapsed", 12)) == "elapsed_ms=12"
/// ```
pub fn millis(key: String, value: Int) -> Field {
  Field(key:, value: Millis(value))
}

/// The name of `value`'s constructor, without anything it holds. A value
/// that is not a custom type renders as its shape in angle brackets.
///
/// ## Examples
///
/// ```gleam
/// assert field.render(field.tag("reason", Error(<<"secret">>)))
///   == "reason=error"
/// ```
///
/// ```gleam
/// assert field.render(field.tag("reason", "secret")) == "reason=<binary>"
/// ```
pub fn tag(key: String, value: a) -> Field {
  Field(key:, value: Tag(ffi_logger.constructor_name(value)))
}

/// The field as `key=value`. Identifiers and numbers are bare tokens by
/// construction; a constructor name is quoted if an Erlang atom ever needs
/// it; the key is a caller's literal, still reduced to `[a-z0-9_]` so a
/// typo cannot break the line.
///
/// ## Examples
///
/// ```gleam
/// assert field.render(field.count("bytes", 3)) == "bytes=3"
/// ```
pub fn render(field: Field) -> String {
  let Field(key:, value:) = field

  // A duration says its unit in the key; every other kind keeps the key.
  case value {
    Prefix(hex:) -> logfmt.word(key) <> "=" <> hex
    Number(value:) -> logfmt.word(key) <> "=" <> int.to_string(value)
    Millis(value:) -> logfmt.word(key) <> "_ms=" <> int.to_string(value)
    Tag(name:) -> logfmt.word(key) <> "=" <> logfmt.quote(name)
  }
}
