//// A carrier-neutral byte connection, and the dialer that opens one.
////
//// The mailbox client speaks HTTP over "something that moves bytes", and
//// which something it is must not leak into the protocol code: an onion
//// stream from Arti in production, a loopback socket in tests and the
//// offline demo, and later perhaps another carrier (spec §6.2). A
//// `Connection` is three functions over one open stream, so each carrier
//// wraps its own handle once and the client never learns which it holds.
////
//// The `Dialer` is also where spec §13.1's "no silent downgrade" is made
//// true. `dial` asks `endpoint.admit` for the daemon's `CarrierPolicy`
//// before it does anything else, so a loopback endpoint under `TorOnly`
//// never opens a socket, and an endpoint read from an invitation cannot
//// widen the policy. The onion carrier is injected as a function because
//// the Arti bridge lives in `tor`, which this package does not depend on;
//// wiring it later is passing one function to `new_dialer`.
////
//// Isolation: every dial carries an isolation group, which the client sets
//// to the queue id so that each queue gets its own circuit group. The
//// loopback carrier has no circuits and ignores it.

import core/endpoint.{type CarrierPolicy, type Endpoint, Loopback, Onion}
import gleam/result
import mug

/// Why a connection could not be opened or used. None of these carries
/// peer bytes or an address, so each is safe to log.
pub type TransportError {
  /// The daemon's `CarrierPolicy` does not admit this endpoint. Nothing was
  /// opened.
  CarrierNotPermitted

  /// The connection could not be established.
  ConnectFailed

  /// The deadline passed before the operation completed.
  TimedOut

  /// The peer closed the connection.
  Closed

  /// Any other failure on an established connection.
  Failed
}

/// One open byte stream. Each field acts on the same underlying stream.
///
/// `send` writes all of the bytes or fails. `receive(max_bytes, timeout_ms)`
/// returns the next bytes that arrive, at most `max_bytes` for a carrier
/// that can bound a read, waiting up to `timeout_ms`; `Closed` means the
/// peer ended the stream. `close` releases the stream and is safe to call
/// after any failure.
pub type Connection {
  Connection(
    send: fn(BitArray) -> Result(Nil, TransportError),
    receive: fn(Int, Int) -> Result(BitArray, TransportError),
    close: fn() -> Nil,
  )
}

/// Opens connections under a carrier policy.
pub type Dialer {
  Dialer(
    /// Which endpoints may be dialled at all.
    policy: CarrierPolicy,
    /// Opens an onion stream to the address and port in an isolation group,
    /// within a timeout in milliseconds.
    dial_onion: fn(endpoint.OnionAddress, endpoint.Port, String, Int) ->
      Result(Connection, TransportError),
  )
}

/// A dialer that enforces `policy`, reaches loopback endpoints with a TCP
/// socket and reaches onion endpoints with `dial_onion`.
///
/// ## Examples
///
/// ```gleam
/// transport.new_dialer(endpoint.TorOnly, tor_dial)
/// ```
pub fn new_dialer(
  policy: CarrierPolicy,
  dial_onion: fn(endpoint.OnionAddress, endpoint.Port, String, Int) ->
    Result(Connection, TransportError),
) -> Dialer {
  Dialer(policy:, dial_onion:)
}

/// Opens a connection to `endpoint`, or refuses without opening anything.
///
/// The policy check comes first and is the only gate: a refused endpoint
/// costs no socket, no circuit and no DNS. `isolation_group` names the
/// circuit group for an onion stream, and `timeout_ms` bounds the dial.
///
/// ## Examples
///
/// ```gleam
/// transport.dial(dialer, Loopback(port), "queue-hex", 1000)
/// // -> Error(CarrierNotPermitted) under TorOnly
/// ```
pub fn dial(
  dialer: Dialer,
  endpoint: Endpoint,
  isolation_group: String,
  timeout_ms: Int,
) -> Result(Connection, TransportError) {
  use admitted <- result.try(
    endpoint.admit(endpoint, dialer.policy)
    |> result.replace_error(CarrierNotPermitted),
  )

  // Each carrier arm is a different kind of stream behind the same record.
  case admitted {
    Onion(address:, port:) ->
      dialer.dial_onion(address, port, isolation_group, timeout_ms)

    Loopback(port:) -> dial_loopback(endpoint.port_number(port), timeout_ms)
  }
}

/// Sends bytes on a connection.
///
/// ## Examples
///
/// ```gleam
/// transport.send(connection, <<"hello">>)
/// // -> Ok(Nil)
/// ```
pub fn send(
  connection: Connection,
  bytes: BitArray,
) -> Result(Nil, TransportError) {
  connection.send(bytes)
}

/// Waits up to `timeout_ms` for the next bytes, at most `max_bytes` where
/// the carrier can bound a read.
///
/// ## Examples
///
/// ```gleam
/// transport.receive(connection, 4096, 1000)
/// // -> Ok(<<"...">>)
/// ```
pub fn receive(
  connection: Connection,
  max_bytes: Int,
  timeout_ms: Int,
) -> Result(BitArray, TransportError) {
  connection.receive(max_bytes, timeout_ms)
}

/// Closes a connection.
///
/// ## Examples
///
/// ```gleam
/// transport.close(connection)
/// // -> Nil
/// ```
pub fn close(connection: Connection) -> Nil {
  connection.close()
}

/// Opens a TCP socket to `127.0.0.1`. IPv4 only, so the host is exactly the
/// loopback literal and name resolution is never consulted.
fn dial_loopback(
  port: Int,
  timeout_ms: Int,
) -> Result(Connection, TransportError) {
  let options =
    mug.new("127.0.0.1", port:)
    |> mug.ip_version_preference(mug.Ipv4Only)
    |> mug.timeout(timeout_ms)

  use socket <- result.try(
    mug.connect(options) |> result.replace_error(ConnectFailed),
  )

  Ok(Connection(
    send: fn(bytes) {
      mug.send(socket, bytes) |> result.map_error(from_socket_error)
    },
    // The kernel receive buffer bounds one read here; `max_bytes` cannot be
    // passed to a passive `gen_tcp:recv` without waiting for that many
    // bytes. The HTTP parser's bounds are the real limit.
    receive: fn(_max_bytes, timeout_ms) {
      mug.receive(socket, timeout_ms) |> result.map_error(from_socket_error)
    },
    close: fn() {
      let _ = mug.shutdown(socket)
      Nil
    },
  ))
}

/// Sorts a socket error into the three cases a caller acts on differently:
/// the deadline, the peer closing, and everything else.
fn from_socket_error(error: mug.Error) -> TransportError {
  case error {
    mug.Timeout -> TimedOut
    mug.Closed -> Closed
    _ -> Failed
  }
}
