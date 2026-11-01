//// One log line, on standard error.
////
//// The daemon logs lifecycle and failure kinds, never values. Spec §12.4
//// and `docs/gleam-style.md` Part IV §7 forbid a capability, a plaintext, a
//// ciphertext or serialized crypto state in any log line, and the simplest
//// way to keep that true is a logger whose only input is a fixed phrase
//// and, at most, a count or a typed reason name. Callers pass a literal;
//// none of them holds a secret in a position where it could be formatted
//// into the text, and `test/daemon/secrets_test.gleam` captures the whole
//// of a real exchange to check it.

import gleam/io

/// Writes `text` as one line, prefixed with the component that spoke.
///
/// ## Examples
///
/// ```gleam
/// log.line("scheduler", "append refused: conflict")
/// // -> Nil
/// ```
pub fn line(component: String, text: String) -> Nil {
  io.println_error("daemon " <> component <> ": " <> text)
}
