//// The sidecar port: the externals that start it, send it control frames,
//// close it, and recognise its messages.
////
//// Every external here lands in `tor_ffi.erl`, which catches every
//// exception. `gleam_erlang` supplies the `Port` type but no way to open
//// or write one, and no pure alternative exists: a port is opened with
//// BIFs and an option list that Gleam does not bind.

import gleam/dynamic.{type Dynamic}
import gleam/erlang/port.{type Port}

/// A message the port sent to its owner.
pub type PortMessage {
  /// One whole `{packet, 4}` frame payload.
  PortData(port: Port, data: BitArray)

  /// The sidecar process exited with this status.
  PortExit(port: Port, status: Int)
}

/// Starts the sidecar binary as a `{packet, 4}` port owned by the calling
/// process. The state directory is the only argument.
///
/// Foreign function: `tor_ffi:open_sidecar/2`, which wraps `open_port/2`
/// with `spawn_executable` and catches its exceptions. No pure alternative
/// exists; ports have no Gleam constructor.
@external(erlang, "tor_ffi", "open_sidecar")
pub fn open_sidecar(binary_path: String, state_dir: String) -> Result(Port, Nil)

/// Sends one control frame; the VM adds the length prefix.
///
/// Foreign function: `tor_ffi:send_frame/2`, which wraps `port_command/2`.
/// No pure alternative exists; Gleam has no port write.
@external(erlang, "tor_ffi", "send_frame")
pub fn send_frame(port: Port, frame: BitArray) -> Result(Nil, Nil)

/// Closes the port, which closes the sidecar's stdin and tells it to exit.
///
/// Foreign function: `tor_ffi:close_port/1`, which wraps `port_close/1`.
/// No pure alternative exists; Gleam has no port close.
@external(erlang, "tor_ffi", "close_port")
pub fn close_port(port: Port) -> Result(Nil, Nil)

/// The operating system pid of the sidecar, for tests and diagnostics.
///
/// Foreign function: `tor_ffi:port_os_pid/1`, which wraps
/// `erlang:port_info/2`. No pure alternative exists.
@external(erlang, "tor_ffi", "port_os_pid")
pub fn os_pid(port: Port) -> Result(Int, Nil)

/// Recognises a port message in the machine's mailbox. The `Dynamic` is the
/// raw message handed over by `select_record` for one port; it is
/// classified at once and never kept, and anything that is not a port
/// `data` or `exit_status` message is `Error(Nil)`.
///
/// Foreign function: `tor_ffi:classify_message/1`. No pure alternative
/// exists; the payload of a port message is an Erlang term that Gleam has
/// no decoder for.
@external(erlang, "tor_ffi", "classify_message")
pub fn classify_message(message: Dynamic) -> Result(PortMessage, Nil)
