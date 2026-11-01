//// The mailbox's HTTP/1.1 binding (spec §6.2).
////
//// The binding is deliberately thin. It frames one request, decodes the TLV
//// body into a `Request`, hands it to `node.handle` and encodes the
//// `Response`; every rule about queues lives behind that call. It exists so
//// that the transport can be replaced (onion messages later) without
//// touching storage or policy.
////
//// ## The contract
////
//// There is one route, `POST /v1/mailbox`. The server answers `200` with a
//// TLV `Response` for everything the protocol can say, including refusals:
//// a body that does not decode is `Refused(Malformed)`, `UnsupportedVersion`
//// or `TooLarge`, not an HTTP error, so a client reads one kind of answer.
//// Statuses other than 200 mean the HTTP layer itself failed: `404` for
//// another path, `405` for another method, `400` for a request that cannot
//// be framed (no usable `Content-Length`, or chunked), and `413` when the
//// declared length exceeds `codec.max_request_bytes()`. Nothing redirects.
//// Every response carries `Connection: close`, because a v1 client sends one
//// request per connection.
////
//// ## Bounded reading
////
//// The declared `Content-Length` is checked before any body byte is read,
//// and the read itself is bounded by the same limit, so an oversize request
//// costs the server no memory and no socket time.
////
//// ## Long polls
////
//// A `Fetch` that waits is served by `node.handle` in the connection's own
//// process, which blocks for at most `limits.long_poll_seconds`. mist's idle
//// timer only runs between requests, and its 15 second receive timeout
//// applies to reading a body, so a parked poll is not cut off. Each
//// connection has its own process, so a poll does not hold up other
//// requests.
////
//// ## Logging
////
//// A request logs method, path, status, response kind and duration, and
//// nothing else (spec §12.4). Capabilities, ciphertext, request bodies and
//// queue identifiers never reach a log line.
////
//// ## Flow
////
//// 1. `start` binds the listener and reports the port it was given.
//// 2. `route` selects the method and path.
//// 3. `serve` checks the declared length, reads the body, decodes it,
////    calls the node and encodes the answer.

import core/mailbox/codec
import core/mailbox/protocol.{type Response as Answer}
import gleam/bytes_tree
import gleam/erlang/process
import gleam/http.{Post}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/int
import gleam/io
import gleam/otp/actor
import gleam/otp/static_supervisor
import gleam/result
import mailbox/internal/ffi_system
import mailbox/node.{type Node}
import mist.{type Connection, type ResponseData}

/// The media type of every request and response body.
pub const media_type = "application/vnd.reedwire.mailbox+tlv"

/// How long `start` waits for the listener to report its port. mist runs
/// `after_start` before `mist.start` returns, so the report is already in
/// this process's mailbox and the wait never blocks; the bound only keeps
/// `start` from hanging if a later mist stops doing that. Setting it to
/// zero fails no test, which is why this is documented rather than tested.
const start_timeout_ms = 5000

/// How the HTTP server is started.
pub type Config {
  Config(
    /// The interface to listen on. The binary passes `127.0.0.1`: the onion
    /// service forwards to it, and the mailbox is never put on a public
    /// interface by this program.
    interface: String,
    /// The port, or 0 to let the operating system choose one.
    port: Int,
  )
}

/// A running HTTP server.
pub type Server {
  Server(
    /// The supervisor owning the listener. It is linked to the process that
    /// called `start`.
    supervisor: actor.Started(static_supervisor.Supervisor),
    /// The port the listener is bound to, never 0.
    port: Int,
  )
}

/// Why the server did not start.
pub type StartError {
  /// mist could not start, for instance because the port is taken.
  ListenFailed(actor.StartError)

  /// The listener started but never reported its port.
  NoPortReported
}

/// Starts the listener for `node` and returns the port it is bound to.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(server) =
///   http.start(node, http.Config(interface: "127.0.0.1", port: 0))
/// server.port
/// ```
pub fn start(node: Node, config: Config) -> Result(Server, StartError) {
  let Config(interface:, port:) = config

  // mist calls this from the listener's process once the socket is bound,
  // which is the only moment the real port of an ephemeral bind is known.
  // It is a message and not a probe, so `process.receive` is the wait and
  // `weft/poll`, which re-probes a synchronous check, has nothing to ask.
  let bound = process.new_subject()

  let started =
    mist.new(fn(req) { serve(node, req) })
    |> mist.bind(interface)
    |> mist.port(port)
    |> mist.after_start(fn(bound_port, _scheme, _address) {
      process.send(bound, bound_port)
    })
    |> mist.start

  use supervisor <- result.try(result.map_error(started, ListenFailed))
  use port <- result.try(
    process.receive(bound, start_timeout_ms)
    |> result.replace_error(NoPortReported),
  )

  Ok(Server(supervisor:, port:))
}

/// Answers one HTTP request, logging its outcome.
fn serve(node: Node, req: Request(Connection)) -> Response(ResponseData) {
  let started = ffi_system.monotonic_ms()
  let #(response, kind) = route(node, req)
  let elapsed = ffi_system.monotonic_ms() - started

  io.println_error(
    http.method_to_string(req.method)
    <> " "
    <> req.path
    <> " "
    <> int.to_string(response.status)
    <> " "
    <> kind
    <> " "
    <> int.to_string(elapsed)
    <> "ms",
  )

  response
}

/// Selects by path and then method, and names the outcome for the log.
fn route(
  node: Node,
  req: Request(Connection),
) -> #(Response(ResponseData), String) {
  // The path decides first, so a wrong method on the route is a 405 and
  // anything else is a 404 whatever its method.
  case req.path, req.method {
    "/v1/mailbox", Post -> exchange(node, req)

    "/v1/mailbox", _ -> #(
      empty(405) |> response.set_header("allow", "POST"),
      "method_not_allowed",
    )

    _, _ -> #(empty(404), "not_found")
  }
}

/// Frames the request, runs it through the node and encodes the answer.
fn exchange(
  node: Node,
  req: Request(Connection),
) -> #(Response(ResponseData), String) {
  let limit = codec.max_request_bytes()

  // A length over the limit is refused before the body is touched; any
  // other usable length is read under the same bound.
  case declared_length(req) {
    Ok(length) if length > limit -> #(empty(413), "too_large")

    Ok(_) ->
      case mist.read_body(req, max_body_limit: limit) {
        Ok(body) -> answer(node, body.body)
        Error(mist.ExcessBody) -> #(empty(413), "too_large")
        Error(mist.MalformedBody) -> #(empty(400), "bad_request")
      }

    Error(Nil) -> #(empty(400), "bad_request")
  }
}

/// The body length the client declared. A request without a plain
/// `Content-Length`, or one that also names a transfer coding, cannot be
/// framed by this server.
fn declared_length(req: Request(Connection)) -> Result(Int, Nil) {
  case request.get_header(req, "transfer-encoding") {
    Ok(_) -> Error(Nil)

    Error(Nil) ->
      request.get_header(req, "content-length")
      |> result.try(int.parse)
      |> result.try(fn(length) {
        case length < 0 {
          True -> Error(Nil)
          False -> Ok(length)
        }
      })
  }
}

/// Decodes the body and answers it. A body that does not decode is a
/// protocol refusal, not an HTTP error.
fn answer(node: Node, body: BitArray) -> #(Response(ResponseData), String) {
  // A decode failure becomes the protocol's own refusal, so the client
  // reads one kind of answer whether or not its bytes were understood.
  let result = case codec.decode_request(body) {
    Ok(request) -> node.handle(node, request)
    Error(error) -> protocol.Refused(codec.refusal(error))
  }

  let body = bytes_tree.from_bit_array(codec.encode_response(result))
  let http_response =
    response.new(200)
    |> response.set_header("content-type", media_type)
    |> response.set_header("connection", "close")
    |> response.set_body(mist.Bytes(body))

  #(http_response, kind(result))
}

/// An answer that is only a status.
fn empty(status: Int) -> Response(ResponseData) {
  response.new(status)
  |> response.set_header("connection", "close")
  |> response.set_body(mist.Bytes(bytes_tree.new()))
}

/// The response's variant name, safe to log because it carries no data.
fn kind(answer: Answer) -> String {
  case answer {
    protocol.QueueCreated(..) -> "queue_created"
    protocol.Appended(..) -> "appended"
    protocol.Batch(..) -> "batch"
    protocol.Acked -> "acked"
    protocol.QueueDeleted -> "queue_deleted"
    protocol.BlobStored(..) -> "blob_stored"
    protocol.SealedBlob(..) -> "sealed_blob"
    protocol.Refused(..) -> "refused"
  }
}
