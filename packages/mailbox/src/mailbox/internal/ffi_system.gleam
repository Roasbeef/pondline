//// The few operating-system calls the mailbox binary needs.
////
//// There is no pure Gleam way to read the wall clock without a package, to
//// create a file readable only by its owner, or to read the environment. Both live behind this one
//// module so the rest of the package stays free of `@external`, and so a
//// test can replace the clock by passing a function instead.

/// Whole seconds since the Unix epoch.
@external(erlang, "mailbox_ffi", "unix_seconds")
pub fn unix_seconds() -> Int

/// A monotonic millisecond reading. Only differences between two readings
/// mean anything.
@external(erlang, "mailbox_ffi", "monotonic_ms")
pub fn monotonic_ms() -> Int

/// Creates `path` with mode 0600 and writes `bytes` into it. It refuses an
/// existing file, and the file is restricted before the bytes are written.
/// The error is the POSIX reason, such as `eexist`.
@external(erlang, "mailbox_ffi", "create_private_file")
pub fn create_private_file(path: String, bytes: BitArray) -> Result(Nil, String)

/// The value of an environment variable.
@external(erlang, "mailbox_ffi", "getenv")
pub fn getenv(name: String) -> Result(String, Nil)

/// Finds an executable named `name` on `PATH`.
@external(erlang, "mailbox_ffi", "find_executable")
pub fn find_executable(name: String) -> Result(String, Nil)

/// Stops the VM with `code` after flushing output.
@external(erlang, "erlang", "halt")
pub fn halt(code: Int) -> Nil
