//// The client side of the mailbox HTTP binding (spec §6.1).
////
//// One call is one request: dial, send a `POST /v1/mailbox` whose body is
//// the TLV-encoded `Request`, read the answer incrementally until the HTTP
//// parser says it is complete, close, and decode the body into a
//// `Response`. A mailbox refusal (`Refused(reason)`) is a `Response`
//// inside a `200`; a non-200 status is an HTTP-level failure and a
//// `ClientError` here, so a caller can tell "the mailbox said no" from
//// "the transport did not work".
////
//// Everything that could make this path unsafe is closed off by what is
//// absent. The client never follows a redirect (a `3xx` is an error), never
//// reads a proxy setting (it dials only through its `Dialer`, so the
//// carrier policy is the only route), and accepts only bounded,
//// `Content-Length`-framed bodies (`core/http1`). It opens one connection
//// per call with `Connection: close`; a keep-alive pool is a later
//// optimisation and would only change this module's dial and close.
////
//// There are no retries here. A failed call is reported and the delivery
//// scheduler decides whether and when to try again, because a retry policy
//// needs state (attempt counts, backoff, circuit rotation) that a call
//// does not own.
////
//// An error never carries a capability, a ciphertext or peer bytes: the
//// variants hold only a status code and the typed parse or codec error,
//// which name what went wrong and not what was said.

import core/endpoint.{type Endpoint}
import core/http1
import core/id
import core/limits
import core/mailbox/codec
import core/mailbox/protocol.{
  type Request, type Response, Ack, Append, CreateQueue, DeleteQueue, Fetch,
  GetBlob, PutBlob,
}
import daemon/internal/ffi_clock
import daemon/transport.{type Dialer, type TransportError}
import gleam/int
import gleam/result

/// The route every mailbox operation uses.
pub const path = "/v1/mailbox"

/// The body's media type.
pub const content_type = "application/vnd.reedwire.mailbox+tlv"

/// How much longer than the long-poll wait a `Fetch` may take to answer: the
/// mailbox's own wait plus time to build and send the batch over Tor.
pub const long_poll_margin_ms = 10_000

/// The most bytes asked of the carrier in one read.
pub const read_chunk_bytes = 65_536

/// Why a call failed.
pub type ClientError {
  /// The daemon's carrier policy refused the endpoint before any connection
  /// was attempted.
  CarrierRefused

  /// The connection could not be opened.
  DialFailed

  /// The deadline passed before a complete response arrived.
  TimedOut

  /// The connection ended, or failed, before a complete response arrived.
  ConnectionClosedEarly

  /// The mailbox answered with a status other than 200. Redirects land here
  /// and are not followed.
  HttpStatus(status: Int)

  /// The response is not acceptable HTTP: chunked, oversized, unframed or
  /// otherwise outside `core/http1`'s subset.
  MalformedHttp(error: http1.HttpError)

  /// The `200` body is not a mailbox response this build understands.
  MalformedBody(error: codec.CodecError)
}

/// Sends one mailbox request and returns the mailbox's answer.
///
/// `isolation_group` is the queue id in hex, so each queue is reached over
/// its own circuit group. `timeout_ms` is the budget for the whole call,
/// dial included. A `Fetch` that long-polls is given at least its own wait
/// plus `long_poll_margin_ms`, whatever the caller passed, since cutting the
/// call off earlier would drop an answer the mailbox is still holding.
///
/// The connection is closed on every path. After an error the request may
/// or may not have been processed; the operations are idempotent by design
/// (spec §6.4), so a caller may repeat one.
///
/// ## Examples
///
/// ```gleam
/// mailbox_client.call(dialer, endpoint, id.to_hex(queue), request, 5000)
/// // -> Ok(protocol.Acked)
/// ```
pub fn call(
  dialer: Dialer,
  endpoint: Endpoint,
  isolation_group: String,
  request: Request,
  timeout_ms: Int,
) -> Result(Response, ClientError) {
  let budget = effective_timeout(request, timeout_ms)
  let deadline = ffi_clock.now_milliseconds() + budget

  use connection <- result.try(
    transport.dial(dialer, endpoint, isolation_group, budget)
    |> result.map_error(from_dial_error),
  )

  // The connection closes whether the exchange succeeded or not, so no
  // path leaves a socket or circuit open.
  let outcome = exchange(connection, endpoint, request, deadline)
  transport.close(connection)
  outcome
}

/// The call's time budget: the caller's, raised to cover a long poll.
///
/// ## Examples
///
/// ```gleam
/// mailbox_client.effective_timeout(fetch_with_wait_25, 1000)
/// // -> 35_000
/// ```
pub fn effective_timeout(request: Request, timeout_ms: Int) -> Int {
  // Only a `Fetch` can be held open by the mailbox, so only it needs more
  // than the caller's budget.
  case request {
    Fetch(wait_seconds:, ..) -> {
      // The mailbox clamps the wait to the protocol limit, so waiting for
      // more than that would only hold the connection open.
      let wait = int.clamp(wait_seconds, 0, limits.long_poll_seconds)
      int.max(timeout_ms, wait * 1000 + long_poll_margin_ms)
    }

    CreateQueue(..)
    | Append(..)
    | Ack(..)
    | DeleteQueue(..)
    | PutBlob(..)
    | GetBlob(..) -> timeout_ms
  }
}

/// Sends the framed request and reads the response, all against one
/// absolute `deadline` on the monotonic clock.
fn exchange(
  connection: transport.Connection,
  endpoint: Endpoint,
  request: Request,
  deadline: Int,
) -> Result(Response, ClientError) {
  let framed =
    http1.encode_request(
      host_header(endpoint),
      path,
      content_type,
      codec.encode_request(request),
    )

  use _ <- result.try(
    transport.send(connection, framed)
    |> result.map_error(from_io_error),
  )
  use response <- result.try(read_response(
    connection,
    http1.new_parser(codec.max_response_bytes()),
    deadline,
  ))

  // Only a 200 carries a mailbox answer; every other status is the HTTP
  // layer failing, and a redirect in particular is never followed.
  case response.status {
    200 ->
      codec.decode_response(response.body)
      |> result.map_error(MalformedBody)

    status -> Error(HttpStatus(status))
  }
}

/// Reads until the parser completes, the peer closes or the deadline
/// passes. Each read is given only the time that remains, so many small
/// reads cannot stretch a call beyond its budget.
fn read_response(
  connection: transport.Connection,
  parser: http1.Parser,
  deadline: Int,
) -> Result(http1.Response, ClientError) {
  let remaining = deadline - ffi_clock.now_milliseconds()

  // An exhausted budget stops the call without another read.
  case remaining > 0 {
    False -> Error(TimedOut)

    True -> {
      use bytes <- result.try(
        transport.receive(connection, read_chunk_bytes, remaining)
        |> result.map_error(from_io_error),
      )
      use progress <- result.try(
        http1.feed(parser, bytes) |> result.map_error(MalformedHttp),
      )

      // The parser decides whether the response is whole.
      case progress {
        http1.Complete(response) -> Ok(response)
        http1.NeedMore(next) -> read_response(connection, next, deadline)
      }
    }
  }
}

/// The `Host` header: the onion hostname, or the loopback literal.
fn host_header(endpoint: Endpoint) -> String {
  case endpoint {
    endpoint.Onion(address:, ..) -> endpoint.onion_host(address)
    endpoint.Loopback(..) -> "127.0.0.1"
  }
}

/// A dial that failed, as the client reports it. A policy refusal is its
/// own variant because the operator can fix it and it was never attempted.
fn from_dial_error(error: TransportError) -> ClientError {
  case error {
    transport.CarrierNotPermitted -> CarrierRefused
    transport.TimedOut -> TimedOut
    transport.ConnectFailed -> DialFailed
    transport.Closed -> DialFailed
    transport.Failed -> DialFailed
  }
}

/// A failure on an established connection, as the client reports it.
fn from_io_error(error: TransportError) -> ClientError {
  case error {
    transport.TimedOut -> TimedOut
    transport.CarrierNotPermitted -> ConnectionClosedEarly
    transport.ConnectFailed -> ConnectionClosedEarly
    transport.Closed -> ConnectionClosedEarly
    transport.Failed -> ConnectionClosedEarly
  }
}

/// The isolation group for a queue: its id in hex. One circuit group per
/// queue means two queues are never linked by sharing a circuit.
///
/// ## Examples
///
/// ```gleam
/// mailbox_client.isolation_group(queue)
/// // -> "00112233445566778899aabbccddeeff"
/// ```
pub fn isolation_group(queue: id.Id(id.Queue)) -> String {
  id.to_hex(queue)
}
