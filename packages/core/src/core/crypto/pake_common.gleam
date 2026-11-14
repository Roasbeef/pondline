//// The pieces every PAKE of `draft-vos-cfrg-pqpake-03` shares: the
//// configuration's domain-separation tag, the two-byte length framing
//// `lv_encode` (§3.1), the public-context encoding `EncodePublicContext`
//// (Appendix C.1) and the transcript hash `TH` (§5).
////
//// Pondline pairs from a spoken code with CPaceOQUAKE (ADR-016), whose two
//// stages, CPace (`core/crypto/cpace`) and OQUAKE, are specified against
//// one interface: each takes a password-related string, a public context
//// and a secret context, and each returns a session key and a transcript
//// hash that binds the public context and every message of the stage.
//// The sequential combiner then feeds the first stage's transcript hash to
//// the second as its public context. Getting one byte of that binding
//// different from the draft's would make a key that no other
//// implementation agrees with, so the encodings live here once, written
//// exactly as the draft writes them, and are pinned by its Appendix E.4
//// vectors through the stage that uses them
//// (`packages/primitives/test/primitives/cpace_test.gleam`).
////
//// Two framings with different widths sit side by side and must not be
//// confused. `lv_encode` frames a KDF input field with a two-byte length,
//// so a field longer than 65 535 bytes cannot be framed and is refused
//// rather than truncated. `encode_public_context` frames each part with a
//// four-byte length, so the bound there is 2^32 - 1 bytes. CPace's own
//// LEB128 framing, `lv_cat`, is a third; it lives in `core/crypto/cpace`
//// because only CPace uses it.
////
//// There is one configuration and no knob: `cpaceoquake-x25519-mlbuaskem1024`
//// (§9.4.1), whose DST "applies throughout, including within the inner
//// protocols", so CPace's transcript hash is keyed by the CPaceOQUAKE DST.

import core/crypto/hkdf
import core/crypto/suite.{type Suite}
import gleam/bit_array
import gleam/list
import gleam/result

/// The DST of `cpaceoquake-x25519-mlbuaskem1024`, `draft-vos-cfrg-pqpake-03`
/// §9.4.1: 32 random bytes the draft fixed, which a later draft that
/// changes the wire would replace. Every `TH` of the run is keyed by it.
pub const dst = <<
  0x44, 0x3e, 0x30, 0x89, 0x98, 0x5f, 0x0f, 0x8d, 0xdd, 0xfb, 0x20, 0xcc, 0x5e,
  0x86, 0x18, 0xf4, 0x47, 0xbd, 0xcf, 0xe6, 0xdd, 0x39, 0xab, 0xb2, 0x39, 0x11,
  0xcd, 0x78, 0x4c, 0x07, 0x51, 0x20,
>>

/// The longest field `lv_encode` can frame: its length prefix is two bytes.
pub const max_field_bytes = 65_535

/// The longest part `encode_public_context` can frame: its length prefixes
/// are four bytes.
pub const max_context_part_bytes = 4_294_967_295

/// `lv_encode` of §3.1: the field behind its length as two big-endian
/// bytes. A field longer than `max_field_bytes` has no encoding and is
/// refused, because truncating its length would let two different fields
/// frame to one KDF input.
///
/// ## Examples
///
/// ```gleam
/// assert pake_common.lv_encode(<<0, 1, 2>>) == Ok(<<0, 3, 0, 1, 2>>)
/// ```
pub fn lv_encode(field: BitArray) -> Result(BitArray, Nil) {
  let length = bit_array.byte_size(field)

  // A length the two-byte prefix cannot hold is refused, never wrapped.
  case length <= max_field_bytes {
    True -> Ok(<<length:size(16), field:bits>>)
    False -> Error(Nil)
  }
}

/// `EncodePublicContext` of Appendix C.1: the session identifier, the
/// client's identifier and the server's identifier, each behind its length
/// as four big-endian bytes, in that order. Any of them may be empty. The
/// draft lets an application prepend or append its own public data to the
/// result, which is how ADR-016 adds its rendezvous label and nameplate.
/// A part longer than `max_context_part_bytes` is refused.
///
/// ## Examples
///
/// ```gleam
/// assert pake_common.encode_public_context(<<1>>, <<"U">>, <<>>)
///   == Ok(<<0, 0, 0, 1, 1, 0, 0, 0, 1, "U", 0, 0, 0, 0>>)
/// ```
pub fn encode_public_context(
  sid: BitArray,
  client: BitArray,
  server: BitArray,
) -> Result(BitArray, Nil) {
  use framed <- result.map(list.try_map(
    [sid, client, server],
    frame_context_part,
  ))

  bit_array.concat(framed)
}

/// One part of the public context behind its four-byte length.
fn frame_context_part(part: BitArray) -> Result(BitArray, Nil) {
  let length = bit_array.byte_size(part)

  // A length the four-byte prefix cannot hold is refused, never wrapped.
  case length <= max_context_part_bytes {
    True -> Ok(<<length:size(32), part:bits>>)
    False -> Error(Nil)
  }
}

/// `TH` of §5: `HKDF-Extract(DST || "TH-" || label, lv_encode(f_1) || ...
/// || lv_encode(f_n))` under HKDF-SHA-256, so a 32-byte hash. Each field is
/// framed, so moving a byte from one field to the next changes the hash. A
/// field `lv_encode` cannot frame is refused before anything is hashed.
///
/// The salt is the public part and the fields are the input keying
/// material, which reads backwards but is the draft's choice: the
/// transcript hash is public, and HKDF-Extract is used here as a keyed
/// hash under a label, not as a key derivation.
///
/// ## Examples
///
/// ```gleam
/// pake_common.transcript_hash(suite, <<"CPace">>, [context, ya, yb])
/// // -> Ok(<<_:256>>)
/// ```
pub fn transcript_hash(
  suite: Suite,
  label: BitArray,
  fields: List(BitArray),
) -> Result(BitArray, Nil) {
  use framed <- result.map(list.try_map(fields, lv_encode))
  let salt = <<dst:bits, "TH-":utf8, label:bits>>

  hkdf.extract(suite, salt, bit_array.concat(framed))
}
