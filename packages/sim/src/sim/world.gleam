//// The simulated world the real trees run in: what every seam is set to,
//// and the one message type all of them report to the runner with.
////
//// Every boundary a daemon or the mailbox has with the outside world is a
//// seam their `Config` exposes (`packages/daemon/CLAUDE.md` and
//// `packages/mailbox/CLAUDE.md`, "Simulation seams"). This module builds
//// the value for each one. None of them acts on its own: each hands what
//// happened to the runner as an `Inbound` message, sent from the process
//// that hit the boundary, and the runner decides when it takes effect.
////
//// | Seam | Built by | What reaches the runner |
//// | --- | --- | --- |
//// | `timer` (every weft loop and run) | `timer_source` | `Armed`: a delay and a wake |
//// | `poll_clock` (invite's wait) | `poll_clock` | `Armed`, from the waiting process |
//// | `clock` (wall time, both sides) | `clock` | nothing: reads the shared virtual time |
//// | `interceptor` (cross-actor mail) | `daemon_interceptor`, `mailbox_interceptor` | `Parked`: a parcel to release |
//// | `dialer` (the network) | `dialer` | `Requested` and `Waiting` per exchange |
//// | `store_faults` | `daemon_store_hook`, `mailbox_store_hook` | nothing: takes an armed fault, counts the transaction |
//// | `engine_faults` | `engine_hook` | nothing: takes an armed fate |
////
//// The clock, the skews, the transaction counter and the mailbox's up or
//// down state live in shared `Cells`, because the processes that read them
//// do so synchronously and the runner only writes them between steps, when
//// nothing else runs. Armed faults live in a shared `Table` for the same
//// reason. Every hook is a production no-op when nothing is armed: the
//// store proceeds, the job applies.

import core/endpoint
import core/mailbox/protocol
import core/time.{type Instant, Instant}
import daemon/engine
import daemon/mail as daemon_mail
import daemon/store as daemon_store
import daemon/transport
import gleam/erlang/process.{type Pid, type Subject}
import mailbox/mail as mailbox_mail
import mailbox/store as mailbox_store
import sim/internal/ffi_vm.{type Cells, type Table}
import sim/seed
import weft/poll
import weft/timer

/// The virtual time in milliseconds since the run began.
pub const now_cell = 1

/// Daemon A's clock skew in milliseconds.
pub const skew_a_cell = 2

/// Daemon B's clock skew in milliseconds.
pub const skew_b_cell = 3

/// The mailbox's clock skew in milliseconds.
pub const skew_mailbox_cell = 4

/// Store transactions begun anywhere, counted by the fault hooks.
pub const transactions_cell = 5

/// 1 while the mailbox refuses connections.
pub const mailbox_down_cell = 6

/// How many cells a world needs.
pub const cell_count = 6

/// The wall-clock instant virtual time zero stands for, in milliseconds.
pub const epoch_ms = 1_800_000_000_000

/// What a connection's reader can be handed.
pub type Wire {
  /// Response bytes.
  Data(bytes: BitArray)

  /// The connection closed.
  Hangup

  /// The reader's own deadline passed.
  Expired
}

/// Everything a seam reports. Each is sent from the process that hit the
/// boundary, so the runner can tell who it was.
pub type Inbound {
  /// An intercepted message, waiting for the runner to deliver it.
  Parked(
    node: String,
    sender: Pid,
    from: String,
    to: String,
    label: String,
    deliver: fn() -> Bool,
  )

  /// A timer armed through an injected source.
  Armed(node: String, sender: Pid, delay: Int, wake: fn() -> Nil)

  /// A daemon wrote a request on a simulated connection.
  Requested(node: String, sender: Pid, wire: Subject(Wire), bytes: BitArray)

  /// A daemon began waiting on that connection, for at most `timeout` ms.
  Waiting(node: String, sender: Pid, wire: Subject(Wire), timeout: Int)

  /// The mailbox answered request `id`.
  Answered(id: Int, response: protocol.Response)

  /// An operator op finished, with what the runner needs to know of it.
  Finished(op: Int, outcome: Outcome)
}

/// What an operator op came to.
pub type Outcome {
  /// An invitation file to hand to the other daemon, after `retried`
  /// answers of `Unavailable`.
  Invited(file: BitArray, retried: Int)

  /// An invitation file was accepted, after `retried` answers of
  /// `Unavailable`.
  Accepted(retried: Int)

  /// Messages committed for sending, by payload tag; `retried` names the
  /// tags whose send answered `Unavailable` at least once first.
  Sent(tags: List(String), retried: List(String))

  /// A call that succeeded and carries nothing the runner keeps.
  Done

  /// A call refused with a fixed reason.
  Refused(reason: String)

  /// A call that answered `Unavailable` after every retry.
  Unavailable

  /// A call that answered something the op did not expect.
  Other(text: String)
}

/// Where a fault is armed.
pub type FaultKey {
  /// The next transactions of a node's store.
  StoreKey(node: String)

  /// The next engine job of one kind on a daemon.
  EngineKey(node: String, kind: String)

  /// The next exchange a daemon starts, request side.
  DropKey(node: String)

  /// The next exchange a daemon starts, response side.
  LoseKey(node: String)

  /// The next response to a daemon.
  LieKey(node: String)
}

/// An armed fault.
pub type FaultArm {
  /// A store fault after `skip` more transactions.
  StoreArm(fault: seed.StoreFault, skip: Int)

  /// An engine job's fate.
  FateArm(fate: engine.JobFate)

  /// A loss: present means armed.
  LossArm

  /// A byzantine response.
  LieArm(lie: seed.Lie)
}

/// The shared state every seam reads and the runner writes.
pub type World {
  World(
    /// Where every seam reports.
    inbox: Subject(Inbound),
    /// The virtual clock, skews, counters and the mailbox state.
    cells: Cells,
    /// The armed faults.
    faults: Table(FaultKey, FaultArm),
  )
}

/// A fresh world reporting to `inbox`, at virtual time zero.
///
/// ## Examples
///
/// ```gleam
/// let world = world.new(process.new_subject())
/// ```
pub fn new(inbox: Subject(Inbound)) -> World {
  World(inbox:, cells: ffi_vm.cells_new(cell_count), faults: ffi_vm.table_new())
}

/// The virtual time in milliseconds.
///
/// ## Examples
///
/// ```gleam
/// world.now(world)
/// // -> 0
/// ```
pub fn now(world: World) -> Int {
  ffi_vm.cells_get(world.cells, now_cell)
}

/// The skew cell of a node.
///
/// ## Examples
///
/// ```gleam
/// world.skew_cell("m")
/// // -> 4
/// ```
pub fn skew_cell(node: String) -> Int {
  case node {
    "a" -> skew_a_cell
    "b" -> skew_b_cell
    _ -> skew_mailbox_cell
  }
}

/// A node's wall clock: virtual time plus its skew, in whole seconds.
///
/// ## Examples
///
/// ```gleam
/// let clock = world.clock(world, "a")
/// clock()
/// // -> Instant(1_800_000_000)
/// ```
pub fn clock(world: World, node: String) -> fn() -> Instant {
  let cells = world.cells
  let skew = skew_cell(node)

  fn() {
    let ms =
      epoch_ms
      + ffi_vm.cells_get(cells, now_cell)
      + ffi_vm.cells_get(cells, skew)
    Instant(unix_seconds: ms / 1000)
  }
}

/// The timer source for a node's weft loops and runs: every arming goes to
/// the runner's wheel.
///
/// ## Examples
///
/// ```gleam
/// world.timer_source(world, "a")
/// // -> timer.Injected(..)
/// ```
pub fn timer_source(world: World, node: String) -> timer.Source {
  let inbox = world.inbox

  timer.Injected(after: fn(delay, wake) {
    process.send(inbox, Armed(node:, sender: process.self(), delay:, wake:))
  })
}

/// The clock `weft/poll` waits on: virtual time, and a sleep that is a
/// timer on the runner's wheel.
///
/// ## Examples
///
/// ```gleam
/// world.poll_clock(world, "a")
/// ```
pub fn poll_clock(world: World, node: String) -> poll.Clock {
  let cells = world.cells
  let inbox = world.inbox

  poll.Clock(now: fn() { ffi_vm.cells_get(cells, now_cell) }, sleep: fn(ms) {
    let woken = process.new_subject()
    let wake = fn() { process.send(woken, Nil) }
    process.send(inbox, Armed(node:, sender: process.self(), delay: ms, wake:))
    process.receive_forever(woken)
  })
}

/// A daemon's mail interceptor: every parcel goes to the runner.
///
/// ## Examples
///
/// ```gleam
/// world.daemon_interceptor(world, "a")
/// ```
pub fn daemon_interceptor(
  world: World,
  node: String,
) -> daemon_mail.Interceptor {
  let inbox = world.inbox

  daemon_mail.Interceptor(park: fn(parcel: daemon_mail.Parcel) {
    let send = parcel.deliver
    let deliver = fn() { send() == daemon_mail.Delivered }
    process.send(
      inbox,
      Parked(
        node:,
        sender: process.self(),
        from: parcel.from,
        to: parcel.to,
        label: parcel.label,
        deliver:,
      ),
    )
  })
}

/// The mailbox's mail interceptor.
///
/// ## Examples
///
/// ```gleam
/// world.mailbox_interceptor(world)
/// ```
pub fn mailbox_interceptor(world: World) -> mailbox_mail.Interceptor {
  let inbox = world.inbox

  mailbox_mail.Interceptor(park: fn(parcel: mailbox_mail.Parcel) {
    let send = parcel.deliver
    let deliver = fn() { send() == mailbox_mail.Delivered }
    process.send(
      inbox,
      Parked(
        node: "m",
        sender: process.self(),
        from: parcel.from,
        to: parcel.to,
        label: parcel.label,
        deliver:,
      ),
    )
  })
}

/// The dialer a daemon's network workers use. Dialling fails while the
/// mailbox is down; otherwise it opens a simulated connection whose request
/// and reader both report to the runner.
///
/// ## Examples
///
/// ```gleam
/// world.dialer(world, "a")
/// ```
pub fn dialer(world: World, node: String) -> transport.Dialer {
  let cells = world.cells
  let inbox = world.inbox

  transport.new_dialer(endpoint.TorOnly, fn(_address, _port, _group, _ms) {
    // A down mailbox refuses the circuit, as an unreachable onion would.
    case ffi_vm.cells_get(cells, mailbox_down_cell) {
      1 -> Error(transport.ConnectFailed)
      _ -> Ok(connection(inbox, node))
    }
  })
}

/// One simulated connection: a request reports to the runner, and the
/// reader waits for what the runner hands it.
fn connection(inbox: Subject(Inbound), node: String) -> transport.Connection {
  let wire = process.new_subject()

  transport.Connection(
    send: fn(bytes) {
      process.send(
        inbox,
        Requested(node:, sender: process.self(), wire:, bytes:),
      )
      Ok(Nil)
    },
    receive: fn(_max_bytes, timeout) { await_wire(inbox, node, wire, timeout) },
    close: fn() { Nil },
  )
}

/// Reads one thing from the connection. Anything already handed over is
/// read at once; otherwise the reader's deadline is armed on the wheel,
/// rounded up to a whole second because the client computes it from the
/// wall-clock monotonic time, which differs by a millisecond between two
/// runs of one seed.
fn await_wire(
  inbox: Subject(Inbound),
  node: String,
  wire: Subject(Wire),
  timeout: Int,
) -> Result(BitArray, transport.TransportError) {
  // Anything already handed over is read without arming a deadline.
  let got = case process.receive(wire, 0) {
    Ok(ready) -> ready

    Error(Nil) -> {
      let rounded = { timeout + 999 } / 1000 * 1000
      process.send(
        inbox,
        Waiting(node:, sender: process.self(), wire:, timeout: rounded),
      )
      process.receive_forever(wire)
    }
  }

  // What the runner handed over decides the read.
  case got {
    Data(bytes) -> Ok(bytes)
    Hangup -> Error(transport.Closed)
    Expired -> Error(transport.TimedOut)
  }
}

/// A daemon store's fault hook: counts the transaction, then applies an
/// armed fault once its skip count runs out.
///
/// ## Examples
///
/// ```gleam
/// world.daemon_store_hook(world, "a")
/// ```
pub fn daemon_store_hook(world: World, node: String) -> daemon_store.Faults {
  let cells = world.cells
  let faults = world.faults

  fn() {
    // An armed fault fires only once its skip count is spent.
    case take_store(cells, faults, node) {
      Ok(seed.StoreDown) -> daemon_store.Down
      Ok(seed.StoreAckLost) -> daemon_store.AckLost
      Error(Nil) -> daemon_store.Proceed
    }
  }
}

/// The mailbox store's fault hook.
///
/// ## Examples
///
/// ```gleam
/// world.mailbox_store_hook(world)
/// ```
pub fn mailbox_store_hook(world: World) -> mailbox_store.Faults {
  let cells = world.cells
  let faults = world.faults

  fn() {
    // The same arming as a daemon's, under the mailbox's own fate type.
    case take_store(cells, faults, "m") {
      Ok(seed.StoreDown) -> mailbox_store.Down
      Ok(seed.StoreAckLost) -> mailbox_store.AckLost
      Error(Nil) -> mailbox_store.Proceed
    }
  }
}

/// Counts one transaction and returns the fault due on it, if any.
fn take_store(
  cells: Cells,
  faults: Table(FaultKey, FaultArm),
  node: String,
) -> Result(seed.StoreFault, Nil) {
  let _ = ffi_vm.cells_add(cells, transactions_cell, 1)
  let key = StoreKey(node)

  // A skip count above zero is spent one transaction at a time.
  case ffi_vm.table_take(faults, key) {
    Ok(StoreArm(fault:, skip: 0)) -> Ok(fault)

    Ok(StoreArm(fault:, skip:)) -> {
      ffi_vm.table_put(faults, key, StoreArm(fault:, skip: skip - 1))
      Error(Nil)
    }

    Ok(FateArm(_)) | Ok(LossArm) | Ok(LieArm(_)) | Error(Nil) -> Error(Nil)
  }
}

/// A daemon engine's fault hook: the armed fate for this job's kind, once.
///
/// ## Examples
///
/// ```gleam
/// world.engine_hook(world, "a")
/// ```
pub fn engine_hook(
  world: World,
  node: String,
) -> fn(engine.JobKind) -> engine.JobFate {
  let faults = world.faults

  fn(kind) {
    let key = EngineKey(node:, kind: engine.kind_label(kind))

    // Only a fate armed for exactly this kind applies.
    case ffi_vm.table_take(faults, key) {
      Ok(FateArm(fate:)) -> fate
      Ok(StoreArm(..)) | Ok(LossArm) | Ok(LieArm(_)) | Error(Nil) ->
        engine.Apply
    }
  }
}
