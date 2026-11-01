//// The simulated network's two halves of an HTTP exchange: reading the
//// request a daemon's real client framed, and framing the mailbox's real
//// answer, honestly or as a lie.
////
//// The client side is untouched: `mailbox_client` frames with `core/http1`
//// and parses the response with the same bounded parser it uses against a
//// real onion stream. The server side is what `mailbox/http` does around
//// `node.handle`, without mist: split the head from the body, decode the
//// body with `codec.decode_request` (a decode failure becomes the
//// protocol's own `Malformed`-class refusal, exactly as the real binding
//// answers it), and frame the encoded response with a `Content-Length`.
////
//// A lie is applied here, to the bytes of one response, so a byzantine
//// mailbox needs nothing from production: a truncated body, a flipped
//// byte, a non-200 status, a refusal in place of the real answer, or an
//// answer of the wrong kind.

import core/id
import core/mailbox/codec
import core/mailbox/protocol.{type Request, type Response}
import gleam/bit_array
import gleam/int
import gleam/result
import gleam/string
import sim/seed
import sim/world.{type Wire}

/// What the runner keeps of a request it read.
pub type Read {
  /// A request that decoded.
  Decoded(request: Request)

  /// Bytes that did not decode; the answer is this refusal.
  Undecodable(refusal: protocol.Refusal)
}

/// Reads the request a client wrote: the body after the head, decoded.
///
/// ## Examples
///
/// ```gleam
/// net.read_request(framed)
/// // -> Decoded(protocol.Fetch(..))
/// ```
pub fn read_request(bytes: BitArray) -> Read {
  // The head ends at the first blank line; everything after is the body.
  case split_head(bytes, 0) {
    Ok(body) ->
      case codec.decode_request(body) {
        Ok(request) -> Decoded(request)
        Error(error) -> Undecodable(codec.refusal(error))
      }

    Error(Nil) -> Undecodable(protocol.Malformed)
  }
}

/// The bytes after the first `\r\n\r\n`, scanning from `at`.
fn split_head(bytes: BitArray, at: Int) -> Result(BitArray, Nil) {
  use window <- result.try(bit_array.slice(bytes, at, 4))

  // The blank line ends the head; anything else moves one byte on.
  case window {
    <<"\r\n\r\n":utf8>> -> {
      let start = at + 4
      bit_array.slice(bytes, start, bit_array.byte_size(bytes) - start)
    }

    _ -> split_head(bytes, at + 1)
  }
}

/// A short, value-free description of a request for traces and sort keys:
/// its kind and the queue and envelope it names.
///
/// ## Examples
///
/// ```gleam
/// net.describe(protocol.Fetch(..))
/// // -> "fetch/0a1b.."
/// ```
pub fn describe(request: Request) -> String {
  case request {
    protocol.CreateQueue(queue:, ..) -> "create/" <> hex(queue)
    protocol.Append(queue:, envelope:, ..) ->
      "append/" <> hex(queue) <> "/" <> hex(envelope)
    protocol.Fetch(queue:, wait_seconds:, ..) ->
      "fetch/" <> hex(queue) <> "/" <> int.to_string(wait_seconds)
    protocol.Ack(queue:, envelopes:, ..) ->
      "ack/" <> hex(queue) <> "/" <> int.to_string(count(envelopes, 0))
    protocol.DeleteQueue(queue:, ..) -> "delete/" <> hex(queue)
  }
}

/// The first eight hex digits of an identifier.
fn hex(value: id.Id(kind)) -> String {
  string.slice(id.to_hex(value), 0, 8)
}

/// The length of a list, without the stdlib's warning about counting.
fn count(items: List(a), acc: Int) -> Int {
  case items {
    [] -> acc
    [_, ..rest] -> count(rest, acc + 1)
  }
}

/// The honest framed response.
///
/// ## Examples
///
/// ```gleam
/// net.frame(protocol.Acked)
/// // -> <<"HTTP/1.1 200 OK\r\n...">>
/// ```
pub fn frame(response: Response) -> BitArray {
  frame_status(200, codec.encode_response(response))
}

/// A response head with `status` and `body`, as the real binding writes.
fn frame_status(status: Int, body: BitArray) -> BitArray {
  let head =
    "HTTP/1.1 "
    <> int.to_string(status)
    <> " OK\r\nContent-Type: application/vnd.reedwire.mailbox+tlv\r\nContent-Length: "
    <> int.to_string(bit_array.byte_size(body))
    <> "\r\nConnection: close\r\n\r\n"

  <<head:utf8, body:bits>>
}

/// What the client's reader is handed for `response` under `lie`, in
/// order. `at` picks the byte a corruption flips.
///
/// ## Examples
///
/// ```gleam
/// net.lie(protocol.Acked, seed.BadStatus, 0)
/// // -> [world.Data(<<"HTTP/1.1 500 ...">>)]
/// ```
pub fn lie(response: Response, lie: seed.Lie, at: Int) -> List(Wire) {
  let honest = frame(response)

  // Each lie is one shape of wrong bytes on the wire.
  case lie {
    seed.Truncate -> {
      let half = bit_array.byte_size(honest) / 2
      let prefix =
        bit_array.slice(honest, 0, half) |> result.lazy_unwrap(fn() { <<>> })
      [world.Data(prefix), world.Hangup]
    }

    seed.Corrupt -> [world.Data(flip(honest, response, at))]

    seed.BadStatus -> [world.Data(frame_status(500, <<>>))]

    seed.Refuse(reason:) -> [world.Data(frame(protocol.Refused(reason)))]

    seed.WrongKind -> [world.Data(frame(wrong_kind(response)))]
  }
}

/// Flips every bit of one byte of the body, chosen by `at`. The head is
/// left alone so the parser reaches the body.
fn flip(framed: BitArray, response: Response, at: Int) -> BitArray {
  let size = bit_array.byte_size(framed)
  let body = codec.encode_response(response) |> bit_array.byte_size
  let index = size - body + at % int.max(body, 1)

  // A byte that exists is flipped; an empty body leaves the bytes alone.
  case
    bit_array.slice(framed, 0, index),
    bit_array.slice(framed, index, 1),
    bit_array.slice(framed, index + 1, size - index - 1)
  {
    Ok(before), Ok(<<byte>>), Ok(after) -> <<
      before:bits,
      int.bitwise_exclusive_or(byte, 0xFF),
      after:bits,
    >>
    _, _, _ -> framed
  }
}

/// An answer of a different kind than the request asked for.
fn wrong_kind(response: Response) -> Response {
  // An acknowledgement is the wrong answer to anything but an `Ack`.
  case response {
    protocol.Acked -> protocol.QueueDeleted

    protocol.QueueCreated(..)
    | protocol.Appended(..)
    | protocol.Batch(..)
    | protocol.QueueDeleted
    | protocol.Refused(..) -> protocol.Acked
  }
}
