//// TLV field codecs for the domain's primitive types, shared by every
//// module that puts an identifier, a capability or an instant on the wire
//// or into storage.
////
//// `core/tlv` knows bytes, integers and text; this module is where those
//// become the domain's own types, so that a decoder in `core/message` or
//// `core/snapshot` reads `field.id()` and cannot accept a queue identifier
//// of the wrong length. Every codec is total: a value that does not fit its
//// type is an `InvalidValue`, never a crash and never a clamp, and no error
//// carries value bytes.
////
//// Fresh identifiers and capabilities are drawn here too, from the
//// injected `Suite.random`, so there is exactly one place that decides what
//// a misbehaving randomness source (one returning the wrong number of
//// bytes) means: the draw fails with `Error(Nil)` and the transition that
//// asked refuses.

import core/capability.{type Capability}
import core/crypto/suite.{type Suite}
import core/id.{type Id}
import core/secret.{type Secret}
import core/time.{type Instant, Instant}
import core/tlv.{type Field}
import gleam/bit_array

/// The codec for an identifier of any kind: exactly `id.id_bytes` bytes.
///
/// ## Examples
///
/// ```gleam
/// field.id()(<<0:128>>)
/// // -> Ok(_)
/// ```
pub fn id() -> Field(Id(kind)) {
  tlv.fixed_bytes(id.id_bytes)
  |> tlv.try_map(id.from_bytes)
}

/// The codec for a capability of any authority: exactly
/// `capability.capability_bytes` bytes.
///
/// ## Examples
///
/// ```gleam
/// field.capability()(<<0:256>>)
/// // -> Ok(_)
/// ```
pub fn capability() -> Field(Capability(authority)) {
  tlv.fixed_bytes(capability.capability_bytes)
  |> tlv.try_map(capability.from_bytes)
}

/// The codec for an instant: a u64 of whole seconds.
///
/// ## Examples
///
/// ```gleam
/// field.instant()(<<0:64>>)
/// // -> Ok(Instant(0))
/// ```
pub fn instant() -> Field(Instant) {
  tlv.u64
  |> tlv.map(fn(seconds) { Instant(unix_seconds: seconds) })
}

/// Encodes an instant as a u64.
///
/// ## Examples
///
/// ```gleam
/// field.encode_instant(Instant(5))
/// // -> <<5:64>>
/// ```
pub fn encode_instant(instant: Instant) -> BitArray {
  tlv.encode_u64(instant.unix_seconds)
}

/// The codec for text of at most `max_bytes` bytes. A longer value is an
/// `InvalidValue`, which is how a hostile peer's oversized description is
/// refused before anything else reads it.
///
/// ## Examples
///
/// ```gleam
/// field.bounded_text(3)(<<"abcd":utf8>>)
/// // -> Error(tlv.InvalidValue)
/// ```
pub fn bounded_text(max_bytes: Int) -> Field(String) {
  tlv.try_map(tlv.bytes, fn(raw) {
    case bit_array.byte_size(raw) <= max_bytes {
      True -> bit_array.to_string(raw)
      False -> Error(Nil)
    }
  })
}

/// The codec for bytes of at most `max_bytes` bytes.
///
/// ## Examples
///
/// ```gleam
/// field.bounded_bytes(2)(<<1, 2, 3>>)
/// // -> Error(tlv.InvalidValue)
/// ```
pub fn bounded_bytes(max_bytes: Int) -> Field(BitArray) {
  tlv.try_map(tlv.bytes, fn(raw) {
    case bit_array.byte_size(raw) <= max_bytes {
      True -> Ok(raw)
      False -> Error(Nil)
    }
  })
}

/// The codec for bytes that must not be observed: they decode straight into
/// a `Secret`, so a decoder never holds key material as a bare `BitArray`
/// beyond the one expression that builds it.
///
/// ## Examples
///
/// ```gleam
/// field.secret_bytes(<<1, 2>>)
/// // -> Ok(_)
/// ```
pub fn secret_bytes(raw: BitArray) -> Result(Secret, tlv.TlvError) {
  Ok(secret.new(raw))
}

/// A fresh identifier of any kind from the injected randomness source;
/// `Error(Nil)` when the source returns the wrong number of bytes.
///
/// ## Examples
///
/// ```gleam
/// field.fresh_id(suite)
/// // -> Ok(_)
/// ```
pub fn fresh_id(suite: Suite) -> Result(Id(kind), Nil) {
  id.from_bytes(suite.random(id.id_bytes))
}

/// A fresh capability of any authority from the injected randomness source.
///
/// ## Examples
///
/// ```gleam
/// field.fresh_capability(suite)
/// // -> Ok(_)
/// ```
pub fn fresh_capability(suite: Suite) -> Result(Capability(authority), Nil) {
  capability.from_bytes(suite.random(capability.capability_bytes))
}
