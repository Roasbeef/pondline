//// Unix domain sockets for the local API, over `gen_tcp`.
////
//// The standard library has no socket support and `mug` speaks TCP only,
//// so the local API reaches `gen_tcp` through one small Erlang shim. All
//// reads go through `recv_line`, which does its own newline framing: the
//// built-in line mode truncates a long line instead of refusing it, and
//// refusing is the behavior the API needs.

/// A listening socket or an open connection.
pub type Socket

/// Binds a Unix socket at `path`, replacing a stale socket file, with mode
/// 0600. The error is the POSIX reason, such as `eaddrinuse`.
@external(erlang, "daemon_local_ffi", "listen")
pub fn listen(path: String) -> Result(Socket, String)

/// Waits for the next connection on a listening socket. It fails once the
/// listener is closed.
@external(erlang, "daemon_local_ffi", "accept")
pub fn accept(listener: Socket) -> Result(Socket, String)

/// Opens a connection to a Unix socket within `timeout_ms`.
@external(erlang, "daemon_local_ffi", "connect")
pub fn connect(path: String, timeout_ms: Int) -> Result(Socket, String)

/// Reads one newline-terminated line, without the newline. `buffer` is what
/// an earlier read left over; the second element of the result is what
/// follows this line. The error is `too_large` when the line is longer than
/// `max` bytes, `timeout` when no data arrives in time, or `closed`.
@external(erlang, "daemon_local_ffi", "recv_line")
pub fn recv_line(
  socket: Socket,
  buffer: BitArray,
  max: Int,
  timeout_ms: Int,
) -> Result(#(BitArray, BitArray), String)

/// Writes bytes to a connection.
@external(erlang, "daemon_local_ffi", "send")
pub fn send(socket: Socket, bytes: BitArray) -> Result(Nil, String)

/// Closes a socket.
@external(erlang, "daemon_local_ffi", "close")
pub fn close(socket: Socket) -> Nil
