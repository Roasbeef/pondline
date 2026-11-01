//// The VM primitives the runner needs that no pure Gleam module offers.
////
//// Each one is foreign for a reason a Gleam alternative cannot meet:
////
//// - `quiesce` asks the schedulers whether anything but the caller is
////   runnable (`erlang:statistics(total_active_tasks_all)`), then confirms
////   it with every process's status, because the statistics do not count a
////   process while it runs a dirty NIF, and every SQLite call is one. No
////   message protocol can answer "nothing else is running" without being
////   one more thing that runs.
//// - `Cells` are `atomics`: the virtual clock and the per-node skew are
////   read by the daemons' own processes on every `clock()` call, which must
////   not be a message round trip to a runner that is itself waiting for
////   quiescence.
//// - `Table` is a public ETS set: the store and engine fault hooks run in
////   the engine's and coordinator's processes and take an armed fault there,
////   synchronously, with no process of their own to ask.
//// - `supervisor_children` and `registered_role` read the supervisor's
////   child list and a process's registered name, which `gleam_otp` does not
////   expose, so a restart op can find the child to kill and a timer arming
////   can be labelled by the role of the process that made it.
//// - The logger level is OTP's `logger` primary config, which no Gleam
////   package exposes; a quiet run silences the crash reports its faults
////   cause.
//// - The stderr sink replaces the registered `standard_error` device, so
////   the daemons' fixed-phrase log lines land in the run instead of the
////   terminal; `gleam/io` writes to that device by name.

import gleam/erlang/process.{type Pid}

/// A fixed-size array of signed integers shared by every process.
pub type Cells

/// A shared key-value table any process may read and take from.
pub type Table(key, value)

/// The saved `standard_error` device and the sink standing in for it.
pub type Sink

/// A saved OTP logger level.
pub type LogLevel

/// How thoroughly `quiesce` confirms what the scheduler statistics say.
pub type Scan {
  /// Every registered process is waiting: the processes that hold a
  /// SQLite connection, and the code server and loader.
  Registered

  /// Every process is waiting. Half a millisecond, so only after a kill.
  Every
}

/// Waits until nothing but the caller is runnable, across three yields in a
/// row, and the processes `scan` names are all waiting. `Error(Nil)` after
/// `max_spins` yields without that.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.quiesce(1_000_000, ffi_vm.Registered)
/// // -> Ok(spins)
/// ```
@external(erlang, "sim_ffi", "quiesce")
pub fn quiesce(max_spins: Int, scan: Scan) -> Result(Int, Nil)

/// How many processes and ports are runnable or running right now.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.active_tasks()
/// // -> 1
/// ```
@external(erlang, "sim_ffi", "active_tasks")
pub fn active_tasks() -> Int

/// `size` shared integers, all zero. Indices start at 1.
///
/// ## Examples
///
/// ```gleam
/// let cells = ffi_vm.cells_new(4)
/// ```
@external(erlang, "sim_ffi", "cells_new")
pub fn cells_new(size: Int) -> Cells

/// The integer at `index`.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.cells_get(cells, 1)
/// // -> 0
/// ```
@external(erlang, "sim_ffi", "cells_get")
pub fn cells_get(cells: Cells, index: Int) -> Int

/// Sets the integer at `index`.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.cells_put(cells, 1, 42)
/// ```
@external(erlang, "sim_ffi", "cells_put")
pub fn cells_put(cells: Cells, index: Int, value: Int) -> Nil

/// Adds `delta` to the integer at `index` and returns the new value.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.cells_add(cells, 1, 1)
/// // -> 1
/// ```
@external(erlang, "sim_ffi", "cells_add")
pub fn cells_add(cells: Cells, index: Int, delta: Int) -> Int

/// A new, empty shared table owned by the caller.
///
/// ## Examples
///
/// ```gleam
/// let table = ffi_vm.table_new()
/// ```
@external(erlang, "sim_ffi", "table_new")
pub fn table_new() -> Table(key, value)

/// Stores `value` under `key`, replacing any earlier one.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.table_put(table, "a", 1)
/// ```
@external(erlang, "sim_ffi", "table_put")
pub fn table_put(table: Table(key, value), key: key, value: value) -> Nil

/// Removes and returns the value under `key`.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.table_take(table, "a")
/// // -> Ok(1)
/// ```
@external(erlang, "sim_ffi", "table_take")
pub fn table_take(table: Table(key, value), key: key) -> Result(value, Nil)

/// The value under `key`, left in place.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.table_get(table, "a")
/// // -> Ok(1)
/// ```
@external(erlang, "sim_ffi", "table_get")
pub fn table_get(table: Table(key, value), key: key) -> Result(value, Nil)

/// Deletes the table.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.table_delete(table)
/// ```
@external(erlang, "sim_ffi", "table_delete")
pub fn table_delete(table: Table(key, value)) -> Nil

/// Removes every entry of the table.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.table_clear(table)
/// ```
@external(erlang, "sim_ffi", "table_clear")
pub fn table_clear(table: Table(key, value)) -> Nil

/// A positive integer no other call in this VM returns. Used only for names
/// that never reach a snapshot, such as a run's in-memory database names.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.unique()
/// ```
@external(erlang, "sim_ffi", "unique")
pub fn unique() -> Int

/// The operating system's process id of this VM, so two VMs running
/// campaigns side by side use different state directories.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.os_pid()
/// // -> "48213"
/// ```
@external(erlang, "sim_ffi", "os_pid")
pub fn os_pid() -> String

/// Silences the OTP logger and returns the level it had.
///
/// ## Examples
///
/// ```gleam
/// let level = ffi_vm.quiet_logger()
/// ```
@external(erlang, "sim_ffi", "quiet_logger")
pub fn quiet_logger() -> LogLevel

/// Puts the OTP logger back at a saved level.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.restore_logger(level)
/// ```
@external(erlang, "sim_ffi", "restore_logger")
pub fn restore_logger(level: LogLevel) -> Nil

/// The SHA-256 of a term's external format, in lowercase hex: a table row's
/// identity in a snapshot. Foreign because the external term format is the
/// one encoding of an arbitrary decoded row that needs no schema.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.term_digest(row)
/// // -> "9f86d0.."
/// ```
@external(erlang, "sim_ffi", "term_digest")
pub fn term_digest(term: a) -> String

/// The monotonic clock in microseconds, for throughput only. Never read by
/// anything inside the simulation.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.monotonic_us()
/// ```
@external(erlang, "sim_ffi", "monotonic_us")
pub fn monotonic_us() -> Int

/// The registered name of `pid` up to its uniqueness suffix, or `""`.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.registered_role(engine_pid)
/// // -> "daemon_engine"
/// ```
@external(erlang, "sim_ffi", "registered_role")
pub fn registered_role(pid: Pid) -> String

/// The live children of a supervisor.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.supervisor_children(supervisor)
/// // -> [pid, ..]
/// ```
@external(erlang, "sim_ffi", "supervisor_children")
pub fn supervisor_children(supervisor: Pid) -> List(Pid)

/// Replaces `standard_error` with a sink that keeps every line.
///
/// ## Examples
///
/// ```gleam
/// let sink = ffi_vm.install_sink()
/// ```
@external(erlang, "sim_ffi", "install_sink")
pub fn install_sink() -> Sink

/// The lines the sink kept since the last call, oldest first.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.sink_lines(sink)
/// // -> ["daemon engine: a storage operation failed\n"]
/// ```
@external(erlang, "sim_ffi", "sink_lines")
pub fn sink_lines(sink: Sink) -> List(String)

/// Puts the saved `standard_error` back and stops the sink.
///
/// ## Examples
///
/// ```gleam
/// ffi_vm.uninstall_sink(sink)
/// ```
@external(erlang, "sim_ffi", "uninstall_sink")
pub fn uninstall_sink(sink: Sink) -> Nil
