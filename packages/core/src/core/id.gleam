//// Identifiers, typed by what they identify.
////
//// Every identifier in the system is sixteen bytes from a CSPRNG (spec
//// §3), and a bare `BitArray` would let a queue identifier be passed where
//// an envelope identifier belongs. A phantom type parameter rules that
//// out: an `Id(Queue)` and an `Id(Envelope)` are different types with the
//// same representation, so the mistake is a compile error and one codec
//// serves every kind.
////
//// Identifiers are not secrets. They are visible to the mailbox, so they
//// carry no authority; authority is `core/capability`'s job.

import gleam/bit_array
import gleam/string

/// The size of every identifier, in bytes.
pub const id_bytes = 16

/// An identifier of a `kind` of thing. The bytes are always `id_bytes`
/// long; `from_bytes` is the only way in.
pub opaque type Id(kind) {
  Id(bytes: BitArray)
}

/// A local agent principal (spec §3, `AgentId`).
pub type Agent

/// A local handle for a relationship with one remote peer (`ContactId`).
pub type Contact

/// One directional mailbox queue (`QueueId`).
pub type Queue

/// One immutable ciphertext submission and its retries (`EnvelopeId`).
pub type Envelope

/// A sender-generated logical message, authenticated inside the
/// encryption (`MessageId`).
pub type Message

/// A single-use pairing offer (`InvitationId`).
pub type Invitation

/// Builds an identifier from exactly `id_bytes` bytes, which a caller
/// draws from the injected randomness source or decodes from the wire.
///
/// ## Examples
///
/// ```gleam
/// id.from_bytes(<<0:128>>)
/// // -> Ok(_)
/// id.from_bytes(<<0:64>>)
/// // -> Error(Nil)
/// ```
pub fn from_bytes(bytes: BitArray) -> Result(Id(kind), Nil) {
  case bit_array.byte_size(bytes) == id_bytes {
    True -> Ok(Id(bytes:))
    False -> Error(Nil)
  }
}

/// The identifier's sixteen bytes.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(queue) = id.from_bytes(<<7:128>>)
/// id.to_bytes(queue)
/// // -> <<7:128>>
/// ```
pub fn to_bytes(id: Id(kind)) -> BitArray {
  id.bytes
}

/// The identifier as lowercase hex, for storage keys and the CLI.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(queue) = id.from_bytes(<<255, 0:120>>)
/// id.to_hex(queue)
/// // -> "ff000000000000000000000000000000"
/// ```
pub fn to_hex(id: Id(kind)) -> String {
  bit_array.base16_encode(id.bytes)
  |> string.lowercase
}

/// Parses `to_hex`'s output, in either case.
///
/// ## Examples
///
/// ```gleam
/// id.from_hex("ff000000000000000000000000000000")
/// // -> Ok(_)
/// ```
pub fn from_hex(text: String) -> Result(Id(kind), Nil) {
  case bit_array.base16_decode(string.uppercase(text)) {
    Ok(bytes) -> from_bytes(bytes)
    Error(Nil) -> Error(Nil)
  }
}

/// Forgets what an identifier identifies, for a table keyed across kinds.
/// The result is only bytes; it cannot be turned back into a typed `Id`
/// without `from_bytes`, which is where a decoder states the kind again.
///
/// ## Examples
///
/// ```gleam
/// id.erase(queue) == id.to_bytes(queue)
/// // -> True
/// ```
pub fn erase(id: Id(kind)) -> BitArray {
  id.bytes
}
