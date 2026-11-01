//// Secret bytes that cannot be printed by accident.
////
//// Keys, capabilities, plaintext and serialized ratchet state must never
//// reach a log line, an error message or a crash report (`docs/spec.md`
//// §5.4, §12.4; `docs/gleam-style.md` Part IV §7). An opaque type alone
//// does not deliver that on the BEAM: `string.inspect`, `io.debug` and
//// every OTP crash report print a record's fields whatever Gleam's
//// visibility says. So a `Secret` holds its bytes inside a closure. The
//// BEAM renders a closure as `#Fun<module.N.M>` and never prints what it
//// captured, which turns "do not log secrets" from a rule every caller must
//// remember into a property of the value.
////
//// The bytes come out only through `expose`, and every call site of
//// `expose` is a place a reviewer should read.

import gleam/bit_array

/// Bytes that must not be observed. Two secrets compare equal with `==`
/// exactly when their bytes do, because the BEAM compares closures by code
/// and captured environment.
pub opaque type Secret {
  Secret(reveal: fn() -> BitArray)
}

/// Wraps bytes as a secret.
///
/// ## Examples
///
/// ```gleam
/// string.inspect(secret.new(<<1, 2, 3>>))
/// // -> "Secret(//fn() { ... })"
/// ```
pub fn new(bytes: BitArray) -> Secret {
  Secret(reveal: fn() { bytes })
}

/// The secret's bytes. Every caller is handling key material and should
/// say why in a comment.
///
/// ## Examples
///
/// ```gleam
/// secret.expose(secret.new(<<1, 2, 3>>))
/// // -> <<1, 2, 3>>
/// ```
pub fn expose(secret: Secret) -> BitArray {
  secret.reveal()
}

/// The secret's length in bytes, which is never itself secret here.
///
/// ## Examples
///
/// ```gleam
/// secret.byte_size(secret.new(<<1, 2, 3>>))
/// // -> 3
/// ```
pub fn byte_size(secret: Secret) -> Int {
  bit_array.byte_size(secret.reveal())
}
