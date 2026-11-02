//// The state directory's ownership lock (spec §8.4).
////
//// A relationship has one logical writer for its cryptographic state, and
//// two daemons on one directory would each advance the same ratchet from the
//// same committed point. The lock refuses the second daemon instead of
//// relying on the version column to catch it afterwards.
////
//// The lock is an exclusive SQLite write transaction held open on its own
//// file, `lock.db`, for the life of the daemon. SQLite takes it as an
//// operating-system file lock, which the system drops when the holding
//// process dies, so a crashed daemon never leaves a stale lock behind, the
//// failure a lock file created with `O_EXCL` has. Within one VM SQLite
//// enforces it between connections too, which is how the tests exercise it.
//// It is a separate file so the main database stays in ordinary WAL mode,
//// readable by a backup tool.
////
//// The holder is a `weft/actor`: holding the transaction open is a process's
//// whole job, and its lifetime is the lock's. It traps exits, and
//// `on_shutdown` runs `release`, which closes the connection. When its supervisor stops it, the
//// lock is released before the process dies, so a restart on the same
//// directory straight after a stop finds the lock free instead of waiting
//// for garbage collection to close the connection. `on_shutdown` cannot run
//// on a brutal kill, and nothing here defends against one: the operating
//// system drops the file lock when the VM's process dies, which is the case
//// that matters, and `node.stop` waits on `is_free` for the in-VM case.
////
//// This does not protect against copying the directory to another machine
//// and running both copies; independent clones are unsupported (spec §8.4).

import gleam/erlang/process
import gleam/otp/supervision
import gleam/result
import sqlight
import weft/actor

/// The actor's only message: a request to release the lock and stop. The
/// supervisor's stop arrives as a trapped exit, not as this message, so
/// nothing in the tree sends it; it exists because an actor has a message
/// type, and it ends the holder through the same `on_shutdown` path.
pub opaque type Message {
  Release
}

/// Why the lock was not taken.
pub type LockError {
  /// Another process, or another daemon in this VM, holds it.
  Held

  /// The file could not be opened.
  Unopenable
}

/// Starts the holder. Start fails when the lock is held elsewhere, and the
/// supervisor with it, so a second daemon never gets as far as opening the
/// database.
///
/// ## Examples
///
/// ```gleam
/// lock.supervised("/var/lib/pondline/lock.db")
/// ```
pub fn supervised(
  path: String,
) -> supervision.ChildSpecification(process.Subject(Message)) {
  supervision.worker(fn() { start(path) })
}

/// Takes the lock and holds it in a new actor.
fn start(path: String) -> actor.StartResult(process.Subject(Message)) {
  actor.new_with_initialiser(5000, fn(subject) {
    // A lock taken starts the holder; a lock held elsewhere fails the start with the reason.
    case acquire(path) {
      Ok(connection) ->
        actor.initialised(connection)
        |> actor.returning(subject)
        |> Ok

      Error(Held) -> Error("the state directory is locked by another daemon")
      Error(Unopenable) -> Error("the lock file could not be opened")
    }
  })
  |> actor.on_message(handle)
  |> actor.trapping_exits(True)
  |> actor.on_shutdown(release)
  |> actor.start
}

/// Opens the lock file and takes the exclusive transaction, without waiting.
fn acquire(path: String) -> Result(sqlight.Connection, LockError) {
  use connection <- result.try(
    sqlight.open(path) |> result.replace_error(Unopenable),
  )

  // No waiting: a held lock is an answer, not a delay.
  let taken = {
    use _ <- result.try(sqlight.exec("PRAGMA busy_timeout=0", connection))
    sqlight.exec("BEGIN EXCLUSIVE", connection)
  }

  // Taking the exclusive transaction decides whether this process owns the directory.
  case taken {
    Ok(Nil) -> Ok(connection)

    Error(_) -> {
      let _ = sqlight.close(connection)
      Error(Held)
    }
  }
}

/// Whether the lock at `path` is free right now. Takes it and gives it back,
/// so it is a hint: it classifies a failed start and lets a stop wait for the
/// holder to let go.
///
/// ## Examples
///
/// ```gleam
/// lock.is_free("/var/lib/pondline/lock.db")
/// // -> True
/// ```
pub fn is_free(path: String) -> Bool {
  // Whether the lock could be taken decides the answer, and a taken lock is given straight back.
  case acquire(path) {
    Ok(connection) -> {
      let _ = sqlight.close(connection)
      True
    }

    Error(Held) | Error(Unopenable) -> False
  }
}

/// Stops when asked, which releases the lock through `release`.
fn handle(
  _connection: sqlight.Connection,
  message: Message,
) -> actor.Next(sqlight.Connection, Message) {
  // The only message is a request to let go.
  case message {
    Release -> actor.stop()
  }
}

/// Closes the connection, which drops the transaction and the file lock.
/// Runs on every orderly stop: a message, or the supervisor's trapped exit.
fn release(connection: sqlight.Connection, _reason: process.ExitReason) -> Nil {
  let _ = sqlight.close(connection)
  Nil
}
