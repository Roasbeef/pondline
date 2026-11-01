//// An outbound onion stream: a passive-mode socket spliced to an Arti
//// stream by the sidecar.
////
//// Why the stream is a plain socket: when the caller stops calling `recv`,
//// the kernel buffer fills, the sidecar's write waits, the sidecar stops
//// reading from Arti, and Arti's stream window stops granting the far end
//// credit. Backpressure crosses the whole path with no credit protocol in
//// Gleam (spec section 10.4), and the caller decides when to read.
////
//// A stream belongs to the process that opened it: the socket's owner is
//// the opener, and the socket closes when that process exits. Nothing here
//// retries; a stream that reports an error is finished.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import tor/address.{type OnionAddress, type Port}
import tor/internal/ffi_socket.{type Socket}

/// The longest isolation group name, in bytes. The sidecar's handshake
/// line is limited to 256 bytes in all.
pub const max_group_bytes = 128

/// An open, passive-mode onion stream.
pub opaque type Stream {
  Stream(socket: Socket)
}

/// Why a read or write on an open stream failed.
pub type StreamError {
  /// The far end, or the sidecar, closed the stream.
  Closed

  /// The operation did not finish in time. For `send` this means the
  /// reader is not keeping up.
  Timeout

  /// Any other failure, such as a reset because the sidecar died.
  Failed
}

/// Why the sidecar refused to open a stream. The variants are the
/// sidecar's closed set of `ERR` codes.
pub type Refusal {
  /// The target is not a v3 onion address. Unreachable through this
  /// package's types; present because the sidecar enforces it too.
  NotOnion

  /// The handshake line was malformed.
  BadRequest

  /// The sidecar has as many streams open as it allows.
  Busy

  /// The sidecar remembers as many isolation groups as it allows.
  TooManyGroups

  /// The Tor client has not bootstrapped.
  NotBootstrapped

  /// The address has the right shape but a bad checksum or version.
  OnionInvalid

  /// No descriptor was found for the onion service.
  OnionNotFound

  /// The onion service exists but could not be reached.
  OnionUnreachable

  /// Opening the stream took too long.
  ConnectTimedOut

  /// Any other connect failure.
  ConnectFailed

  /// A code this version does not know.
  UnknownRefusal
}

/// Why opening a stream failed.
pub type OpenError {
  /// The isolation group is empty, too long, or has a character other
  /// than printable ASCII without spaces.
  InvalidIsolationGroup

  /// The sidecar's socket could not be reached or the handshake reply
  /// did not arrive.
  SidecarUnreachable(reason: StreamError)

  /// The sidecar refused.
  Refused(reason: Refusal)

  /// The sidecar answered with something that is neither `OK` nor `ERR`.
  HandshakeViolation
}

/// Opens a stream through the sidecar listening on `socket_path`. Streams
/// with the same `isolation_group` may share Tor circuits; streams with
/// different groups never do. `timeout` bounds the whole handshake, which
/// includes Arti's descriptor fetch and rendezvous, so give it minutes
/// rather than seconds for a first connect to an onion service.
///
/// ## Examples
///
/// ```gleam
/// stream.open(sock, onion, port, "queue-7", 120_000)
/// // -> Ok(stream)
/// ```
pub fn open(
  socket_path: String,
  onion: OnionAddress,
  port: Port,
  isolation_group: String,
  timeout: Int,
) -> Result(Stream, OpenError) {
  use Nil <- result.try(validate_group(isolation_group))
  use socket <- result.try(
    ffi_socket.connect_unix(socket_path, timeout)
    |> result.map_error(fn(e) { SidecarUnreachable(stream_error(e)) }),
  )

  let line =
    "CONNECT "
    <> address.onion_host(onion)
    <> ":"
    <> int.to_string(address.port_number(port))
    <> " "
    <> isolation_group
    <> "\n"

  // On any failure the socket is closed here, so a refused or failed
  // handshake never leaves a descriptor behind.
  case handshake(socket, line, timeout) {
    Ok(Nil) -> Ok(Stream(socket))
    Error(error) -> {
      let _ = ffi_socket.close(socket)
      Error(error)
    }
  }
}

/// Sends the request line, reads the one-line reply, and switches the
/// socket to raw mode on `OK`.
fn handshake(
  socket: Socket,
  line: String,
  timeout: Int,
) -> Result(Nil, OpenError) {
  use Nil <- result.try(
    ffi_socket.send(socket, <<line:utf8>>, timeout)
    |> result.map_error(fn(e) { SidecarUnreachable(stream_error(e)) }),
  )
  use reply <- result.try(
    ffi_socket.recv(socket, 512, timeout)
    |> result.map_error(fn(e) { SidecarUnreachable(stream_error(e)) }),
  )

  // Only the first line is the reply; bytes after it, if the far end
  // spoke first, stay in the socket for the first `recv`.
  case bit_array.to_string(reply) {
    Ok("OK\n") ->
      ffi_socket.set_raw(socket)
      |> result.map_error(fn(e) { SidecarUnreachable(stream_error(e)) })

    Ok("ERR " <> code) -> Error(Refused(refusal(string.trim(code))))

    _ -> Error(HandshakeViolation)
  }
}

/// The refusal for an `ERR` code.
fn refusal(code: String) -> Refusal {
  case code {
    "not-onion" -> NotOnion
    "bad-request" -> BadRequest
    "busy" -> Busy
    "too-many-groups" -> TooManyGroups
    "not-bootstrapped" -> NotBootstrapped
    "onion-invalid" -> OnionInvalid
    "onion-not-found" -> OnionNotFound
    "onion-unreachable" -> OnionUnreachable
    "timeout" -> ConnectTimedOut
    "connect-failed" -> ConnectFailed
    _ -> UnknownRefusal
  }
}

/// Checks the isolation group against what the sidecar's line grammar
/// accepts, so a bad group is a typed error here rather than `bad-request`
/// from the sidecar.
fn validate_group(group: String) -> Result(Nil, OpenError) {
  let printable = fn(c: UtfCodepoint) {
    let n = string.utf_codepoint_to_int(c)
    n >= 0x21 && n <= 0x7e
  }
  let ok =
    string.byte_size(group) >= 1
    && string.byte_size(group) <= max_group_bytes
    && list.all(string.to_utf_codepoints(group), printable)

  // Only a group the sidecar's line grammar accepts goes on the wire.
  case ok {
    True -> Ok(Nil)
    False -> Error(InvalidIsolationGroup)
  }
}

/// Maps the socket layer's error to the public one.
fn stream_error(error: ffi_socket.SocketError) -> StreamError {
  case error {
    ffi_socket.Closed -> Closed
    ffi_socket.Timeout -> Timeout
    ffi_socket.SocketFailed -> Failed
  }
}

/// Sends bytes, waiting at most `timeout` milliseconds while the socket is
/// full. A `Timeout` means the reader, or Tor's flow control behind it, is
/// not keeping up: some of the bytes may already be queued, and the caller
/// should treat the stream as stalled rather than resend.
///
/// ## Examples
///
/// ```gleam
/// stream.send(s, <<"hello":utf8>>, 5000)
/// // -> Ok(Nil)
/// ```
pub fn send(
  stream: Stream,
  data: BitArray,
  timeout: Int,
) -> Result(Nil, StreamError) {
  ffi_socket.send(stream.socket, data, timeout)
  |> result.map_error(stream_error)
}

/// Receives between one and `max_bytes` bytes, waiting at most `timeout`
/// milliseconds. The stream is passive, so bytes arrive only when this is
/// called; not calling it is how a reader applies backpressure.
///
/// ## Examples
///
/// ```gleam
/// stream.recv(s, 4096, 5000)
/// // -> Ok(<<"hello":utf8>>)
/// ```
pub fn recv(
  stream: Stream,
  max_bytes: Int,
  timeout: Int,
) -> Result(BitArray, StreamError) {
  ffi_socket.recv(stream.socket, max_bytes, timeout)
  |> result.map_error(stream_error)
}

/// Closes the stream. Closing an already-closed stream is harmless.
///
/// ## Examples
///
/// ```gleam
/// stream.close(s)
/// // -> Nil
/// ```
pub fn close(stream: Stream) -> Nil {
  let _ = ffi_socket.close(stream.socket)
  Nil
}
