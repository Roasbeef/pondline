//// What the padded envelope carries (spec §6.3): one tag byte, then a
//// handshake or a ratchet message.
////
//// A mailbox stores opaque padded bytes, and the recipient must decide what
//// they are before it can do anything with them. Exactly two things arrive
//// on a queue: the joiner's PQXDH initial message, which only an open
//// invitation can consume, and a Double Ratchet message, which only an
//// established session can read. The tag byte says which, so the shell
//// routes an `Initial` to the offer that owns the queue and a `Ratchet` to
//// the relationship that owns it, and neither decoder ever sees the
//// other's bytes.
////
//// `seal` pads a frame to a bucket and `open` is its total inverse: every
//// failure (a length prefix pointing past the end, an unknown tag, an
//// initial message whose identity binding does not verify) is a typed
//// error and none carries bytes, so the shell can record "processed and
//// dropped" for hostile input and acknowledge it.

import core/crypto/error
import core/crypto/pqxdh.{type InitialMessage}
import core/crypto/suite.{type Suite}
import core/envelope.{type Padded}
import gleam/result

/// One mailbox payload, after unpadding.
pub type Frame {
  /// The joiner's handshake message, addressed to an invitation's queue.
  Initial(initial: InitialMessage)

  /// A Double Ratchet wire message, from `ratchet.encrypt`.
  Ratchet(message: BitArray)
}

/// Why a padded envelope is not a frame.
pub type FrameError {
  /// The length prefix points past the end of the padded bytes.
  BadPadding

  /// The tag byte is neither of the two this version knows.
  UnknownTag

  /// The initial message did not decode; its error carries no key bytes.
  MalformedInitial(error: error.Error)
}

/// A frame's bytes before padding: its tag, then the body.
///
/// ## Examples
///
/// ```gleam
/// frame.encode(frame.Ratchet(<<9>>))
/// // -> <<2, 9>>
/// ```
pub fn encode(frame: Frame) -> BitArray {
  case frame {
    Initial(initial:) -> <<1, pqxdh.encode_initial(initial):bits>>
    Ratchet(message:) -> <<2, message:bits>>
  }
}

/// Reads a frame's bytes. Total.
///
/// ## Examples
///
/// ```gleam
/// frame.decode(suite, <<2, 9>>)
/// // -> Ok(frame.Ratchet(<<9>>))
/// ```
pub fn decode(suite: Suite, bytes: BitArray) -> Result(Frame, FrameError) {
  case bytes {
    <<1, rest:bytes>> ->
      pqxdh.decode_initial(suite, rest)
      |> result.map(Initial)
      |> result.map_error(MalformedInitial)

    <<2, rest:bytes>> -> Ok(Ratchet(rest))

    _ -> Error(UnknownTag)
  }
}

/// Pads a frame to a bucket; `Error(Nil)` when it is larger than every
/// bucket, which a sender treats as "too large to send".
///
/// ## Examples
///
/// ```gleam
/// frame.seal(frame.Ratchet(<<9>>))
/// // -> Ok(_)
/// ```
pub fn seal(frame: Frame) -> Result(Padded, Nil) {
  envelope.pad(encode(frame))
}

/// Unpads and decodes a stored envelope's payload.
///
/// ## Examples
///
/// ```gleam
/// frame.open(suite, padded) == Ok(frame)
/// // -> True
/// ```
pub fn open(suite: Suite, padded: Padded) -> Result(Frame, FrameError) {
  use bytes <- result.try(
    envelope.unpad(padded)
    |> result.replace_error(BadPadding),
  )

  decode(suite, bytes)
}
