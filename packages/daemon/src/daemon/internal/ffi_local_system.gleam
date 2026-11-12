//// The operating-system calls the local API and the CLI need.
////
//// Gleam has no way to read the monotonic clock, create a file readable
//// only by its owner, read a file's mode, write raw bytes to standard
//// output or read the environment without a package, and none of those
//// packages is worth a dependency for one call. They live behind this one
//// module so the rest of the package stays free of `@external`.

/// A monotonic millisecond reading. Only differences between two readings
/// mean anything.
@external(erlang, "daemon_local_ffi", "monotonic_ms")
pub fn monotonic_ms() -> Int

/// Creates `path` with mode 0600 and writes `bytes` into it. It refuses an
/// existing file, and the file is restricted before the bytes are written.
/// The error is the POSIX reason, such as `eexist`.
@external(erlang, "daemon_local_ffi", "create_private_file")
pub fn create_private_file(path: String, bytes: BitArray) -> Result(Nil, String)

/// Creates a directory and its parents if missing, then sets the directory
/// itself to mode 0700.
@external(erlang, "daemon_local_ffi", "make_private_dir")
pub fn make_private_dir(path: String) -> Result(Nil, String)

/// The permission bits of a path, such as `0o600`.
@external(erlang, "daemon_local_ffi", "file_mode")
pub fn file_mode(path: String) -> Result(Int, String)

/// Writes raw bytes to standard output, without any re-encoding.
@external(erlang, "daemon_local_ffi", "write_stdout")
pub fn write_stdout(bytes: BitArray) -> Result(Nil, String)

/// Reads standard input to its end. The error is `too_large` when more than
/// `max` bytes arrive.
@external(erlang, "daemon_local_ffi", "read_stdin")
pub fn read_stdin(max: Int) -> Result(BitArray, String)

/// The value of an environment variable.
@external(erlang, "daemon_local_ffi", "getenv")
pub fn getenv(name: String) -> Result(String, Nil)

/// Finds an executable named `name` on `PATH`.
@external(erlang, "daemon_local_ffi", "find_executable")
pub fn find_executable(name: String) -> Result(String, Nil)

/// Stops the VM with `code` after flushing output.
@external(erlang, "erlang", "halt")
pub fn halt(code: Int) -> Nil
