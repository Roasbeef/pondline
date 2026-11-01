//// Passive-mode unix sockets to the sidecar's outbound listener.
////
//// Passive mode is the point. The socket delivers bytes only when the
//// owner calls `recv`, so a slow reader fills the kernel buffer, the
//// sidecar's write waits, and Tor's own flow control reaches the far end.
//// No read-credit protocol is built in Gleam (spec section 10.4).
////
//// Every external lands in `tor_ffi.erl`, which catches every exception
//// and returns the error atoms named by `SocketError`'s variants. No pure
//// alternative exists: Gleam has no socket binding, and a unix-domain
//// address needs `gen_tcp`'s `{local, Path}` form.

/// A connected unix socket, in passive mode.
pub type Socket

/// Why a socket operation failed.
pub type SocketError {
  /// The peer closed the connection.
  Closed

  /// The operation did not finish in time.
  Timeout

  /// Any other failure, such as a missing socket file or a reset.
  SocketFailed
}

/// Connects in passive line mode, ready to read the handshake reply.
///
/// Foreign function: `tor_ffi:connect_unix/2`, which wraps
/// `gen_tcp:connect/4` with `{local, Path}`.
@external(erlang, "tor_ffi", "connect_unix")
pub fn connect_unix(path: String, timeout: Int) -> Result(Socket, SocketError)

/// Sends all of the data, waiting at most `timeout` milliseconds while the
/// socket is full. A timeout means the reader is not keeping up; some of
/// the data may already have been queued.
///
/// Foreign function: `tor_ffi:socket_send/3`, which wraps `gen_tcp:send/2`.
@external(erlang, "tor_ffi", "socket_send")
pub fn send(
  socket: Socket,
  data: BitArray,
  timeout: Int,
) -> Result(Nil, SocketError)

/// Receives one to `max` bytes, or one line in line mode.
///
/// Foreign function: `tor_ffi:socket_recv/3`, which wraps
/// `gen_tcp:recv/3` with the buffer capped at `max`.
@external(erlang, "tor_ffi", "socket_recv")
pub fn recv(
  socket: Socket,
  max: Int,
  timeout: Int,
) -> Result(BitArray, SocketError)

/// Switches to line mode, for the handshake reply.
///
/// Foreign function: `tor_ffi:socket_set_line/2`, which wraps
/// `inet:setopts/2`.
@external(erlang, "tor_ffi", "socket_set_line")
pub fn set_line(socket: Socket, max: Int) -> Result(Nil, SocketError)

/// Switches to raw bytes, once the handshake is done.
///
/// Foreign function: `tor_ffi:socket_set_raw/1`, which wraps
/// `inet:setopts/2`.
@external(erlang, "tor_ffi", "socket_set_raw")
pub fn set_raw(socket: Socket) -> Result(Nil, SocketError)

/// Closes the socket.
///
/// Foreign function: `tor_ffi:socket_close/1`, which wraps
/// `gen_tcp:close/1`.
@external(erlang, "tor_ffi", "socket_close")
pub fn close(socket: Socket) -> Result(Nil, Nil)
