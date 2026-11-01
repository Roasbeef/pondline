//// The padded ciphertext a mailbox stores, and the envelope around it.
////
//// A mailbox sees sizes, so sizes are coarsened to a few buckets (spec
//// §11.1, `core/limits.padding_buckets`). Padding is applied to the sealed
//// ciphertext, outside the encryption: a four-byte length, the ciphertext,
//// then zeros to the bucket. The zeros are not authenticated and need not
//// be; `unpad` reads the length and discards them, and the ciphertext's own
//// AEAD tag covers everything that carries meaning.
////
//// `Padded` can only be built by `pad` or by `from_wire`, and both check
//// that the size is a bucket. So a value of this type is always a size the
//// mailbox will accept, and an unpadded ciphertext cannot reach the
//// network by mistake.

import core/id.{type Envelope, type Id, type Queue}
import core/limits
import core/time.{type Instant}
import gleam/bit_array
import gleam/list

/// A ciphertext padded to one of the buckets.
pub opaque type Padded {
  Padded(bytes: BitArray)
}

/// What the mailbox stores for one envelope (spec §6.3): nothing about the
/// sender, the agent or the content beyond the bucket size.
pub type StoredEnvelope {
  StoredEnvelope(
    queue: Id(Queue),
    envelope: Id(Envelope),
    retention_deadline: Instant,
    ciphertext: Padded,
  )
}

/// Pads a sealed ciphertext to the smallest bucket that holds it and its
/// length prefix; an error when no bucket does.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(padded) = envelope.pad(<<1, 2, 3>>)
/// bit_array.byte_size(envelope.to_wire(padded))
/// // -> 4096
/// ```
pub fn pad(sealed: BitArray) -> Result(Padded, Nil) {
  let length = bit_array.byte_size(sealed)

  // The four-byte length prefix counts toward the bucket, so a ciphertext
  // exactly a bucket's size moves up to the next one.
  case limits.padded_size(length + 4) {
    Ok(bucket) -> {
      let fill = { bucket - length - 4 } * 8
      Ok(Padded(bytes: <<length:size(32), sealed:bits, 0:size(fill)>>))
    }
    Error(Nil) -> Error(Nil)
  }
}

/// The sealed ciphertext inside a padded one; an error when the length
/// prefix points past the end.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(padded) = envelope.pad(<<1, 2, 3>>)
/// envelope.unpad(padded)
/// // -> Ok(<<1, 2, 3>>)
/// ```
pub fn unpad(padded: Padded) -> Result(BitArray, Nil) {
  case padded.bytes {
    <<length:size(32), rest:bits>> ->
      bit_array.slice(from: rest, at: 0, take: length)
    _ -> Error(Nil)
  }
}

/// Accepts bytes from the wire as a padded ciphertext when their size is
/// exactly a bucket.
///
/// ## Examples
///
/// ```gleam
/// envelope.from_wire(<<0:size(32768)>>)
/// // -> Ok(_)
/// envelope.from_wire(<<0:size(8)>>)
/// // -> Error(Nil)
/// ```
pub fn from_wire(bytes: BitArray) -> Result(Padded, Nil) {
  case list.contains(limits.padding_buckets, bit_array.byte_size(bytes)) {
    True -> Ok(Padded(bytes:))
    False -> Error(Nil)
  }
}

/// The padded bytes, for the wire and for storage.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(envelope.to_wire(padded))
/// // -> 4096
/// ```
pub fn to_wire(padded: Padded) -> BitArray {
  padded.bytes
}
