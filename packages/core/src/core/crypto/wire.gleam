//// Fixed-layout byte readers shared by the `core/crypto` encodings.
////
//// Every encoding in `CryptoProfileV1` is a fixed layout of fixed-size
//// fields, with at most a length-prefixed tail. Reading one is a left-to-
//// right walk that either yields a field and the remaining bytes or reports
//// the input malformed. Nothing here can raise, and nothing here allocates
//// from a length it has not already checked against the bytes in hand, so a
//// hostile length prefix costs nothing.

import core/crypto/error.{type Error, Malformed}

/// Splits `size` bytes off the front of `bits`. The label names the field
/// for the error when the input is too short.
///
/// ## Examples
///
/// ```gleam
/// wire.take(<<1, 2, 3>>, 2, "field")
/// // -> Ok(#(<<1, 2>>, <<3>>))
///
/// wire.take(<<1>>, 2, "field")
/// // -> Error(Malformed("field"))
/// ```
pub fn take(
  bits: BitArray,
  size: Int,
  what: String,
) -> Result(#(BitArray, BitArray), Error) {
  case bits {
    <<head:bytes-size(size), rest:bytes>> -> Ok(#(head, rest))
    _ -> Error(Malformed(what))
  }
}

/// Reads a big-endian unsigned 32-bit integer.
///
/// ## Examples
///
/// ```gleam
/// wire.read_u32(<<0, 0, 1, 0, 9>>, "count")
/// // -> Ok(#(256, <<9>>))
/// ```
pub fn read_u32(
  bits: BitArray,
  what: String,
) -> Result(#(Int, BitArray), Error) {
  case bits {
    <<value:size(32), rest:bytes>> -> Ok(#(value, rest))
    _ -> Error(Malformed(what))
  }
}

/// Reads one byte.
///
/// ## Examples
///
/// ```gleam
/// wire.read_u8(<<7, 9>>, "tag")
/// // -> Ok(#(7, <<9>>))
/// ```
pub fn read_u8(
  bits: BitArray,
  what: String,
) -> Result(#(Int, BitArray), Error) {
  case bits {
    <<value:size(8), rest:bytes>> -> Ok(#(value, rest))
    _ -> Error(Malformed(what))
  }
}

/// Succeeds only when no bytes remain, so a trailing byte is an error rather
/// than something ignored.
///
/// ## Examples
///
/// ```gleam
/// wire.end(<<>>, "state")
/// // -> Ok(Nil)
/// ```
pub fn end(bits: BitArray, what: String) -> Result(Nil, Error) {
  case bits {
    <<>> -> Ok(Nil)
    _ -> Error(Malformed(what))
  }
}
