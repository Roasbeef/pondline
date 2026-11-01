//// The client side of the local API: one request over the daemon's Unix
//// socket.
////
//// The CLI uses it for every client command, and the tests use it to speak
//// to a real server. A call connects, writes one request line, reads one
//// response line and closes, so a command line never holds a connection
//// between invocations. A failure to reach the daemon is a `ClientError`,
//// distinct from a `Failed` response: the first means no answer came, the
//// second means the daemon answered no.

import daemon/internal/ffi_local_socket
import daemon/local_api_protocol as protocol
import gleam/bit_array
import gleam/json.{type Json}
import gleam/result

/// How long connecting may take, in milliseconds.
const connect_timeout_ms = 5000

/// Why no response arrived.
pub type ClientError {
  /// The socket could not be opened, usually because the daemon is not
  /// running. The reason is the POSIX name, such as `enoent`.
  CannotConnect(reason: String)

  /// The connection broke or timed out after it opened.
  ConnectionFailed(reason: String)

  /// The daemon answered with something that is not a protocol response.
  MalformedReply
}

/// Sends one request and reads its response. `credential` is the raw
/// credential bytes; they are base64-encoded on the wire. `timeout_ms`
/// bounds the wait for the answer, so it must exceed any `wait_ms` in
/// `args`.
///
/// ## Examples
///
/// ```gleam
/// local_api_client.call(socket, credential, "health", json.object([]), 5000)
/// // -> Ok(Succeeded(_))
/// ```
pub fn call(
  socket_path: String,
  credential: BitArray,
  op: String,
  args: Json,
  timeout_ms: Int,
) -> Result(protocol.Response, ClientError) {
  exchange(socket_path, credential, op, args, timeout_ms)
  |> result.map(fn(reply) { reply.1 })
}

/// Like `call`, but also returns the response line as it arrived, for a
/// caller that prints it unchanged.
///
/// ## Examples
///
/// ```gleam
/// local_api_client.exchange(socket, credential, "health", json.object([]), 5000)
/// // -> Ok(#("{\"ok\":true,\"result\":{}}", Succeeded(_)))
/// ```
pub fn exchange(
  socket_path: String,
  credential: BitArray,
  op: String,
  args: Json,
  timeout_ms: Int,
) -> Result(#(String, protocol.Response), ClientError) {
  let line =
    protocol.request_json(bit_array.base64_encode(credential, True), op, args)

  use reply <- result.try(call_line(socket_path, <<line:utf8>>, timeout_ms))
  use text <- result.try(
    bit_array.to_string(reply) |> result.replace_error(MalformedReply),
  )
  use response <- result.try(
    protocol.parse_response(text) |> result.replace_error(MalformedReply),
  )

  Ok(#(text, response))
}

/// Sends raw bytes as one request line and returns the response line. A
/// test uses it to send input a well-behaved client would not.
///
/// ## Examples
///
/// ```gleam
/// local_api_client.call_line(socket, <<"not json">>, 5000)
/// // -> Ok(<<"{\"ok\":false,...}">>)
/// ```
pub fn call_line(
  socket_path: String,
  request: BitArray,
  timeout_ms: Int,
) -> Result(BitArray, ClientError) {
  use connection <- result.try(
    ffi_local_socket.connect(socket_path, connect_timeout_ms)
    |> result.map_error(CannotConnect),
  )

  let outcome = {
    use Nil <- result.try(
      ffi_local_socket.send(connection, <<request:bits, "\n">>),
    )
    use #(line, _rest) <- result.try(ffi_local_socket.recv_line(
      connection,
      <<>>,
      protocol.max_line_bytes,
      timeout_ms,
    ))

    Ok(line)
  }

  ffi_local_socket.close(connection)
  result.map_error(outcome, ConnectionFailed)
}
