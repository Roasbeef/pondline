//// The client supervisor tree (spec §10.2): starts every process of a daemon
//// in dependency order and returns the `api.Daemon` handle.
////
//// ```text
//// supervisor (rest_for_one)
//// ├── lock          the state directory's ownership lock
//// ├── status        Tor and mailbox observations
//// ├── events        subscribers for adapter wake
//// ├── carrier       the Tor sidecar and the onion dialer (state machine)
//// ├── engine        the single writer
//// ├── scheduler     sends committed outbox rows (actor, runs of sends)
//// ├── provisioner   creates committed queues at the mailbox (state machine)
//// └── fetch_manager one fetcher per live inbound queue (actor; each fetcher
////                   is a state machine linked to it)
//// ```
////
//// The order is the dependency order and the supervisor is `rest_for_one`:
//// a crash of the engine restarts the three workers that call it, and a
//// crash of a worker touches nothing before it. Every child is addressed by
//// a `Name`, so a restarted process is found again without anyone passing
//// its new address around. Nothing a worker holds needs to survive a
//// restart: each starts by reading committed state from the engine (spec
//// §12.2).
////
//// ## Wiring
////
//// The engine does not know the workers. It is given one `notify` function
//// and calls it after each commit; `route_notice` is that function, and it
//// is the only place that says which effect nudges which worker. A nudge is
//// advisory, because every worker also scans on a timer, so a notice lost to
//// a restart costs latency only.
////
//// ## Starting
////
//// `start` checks what can be checked without a process (the mailbox is
//// admitted by the carrier policy, the provisioning capability file reads),
//// prepares the state directory with its modes (`0700` directory, `0600`
//// files), then starts the tree. A second daemon on the same directory is
//// refused by the lock. `start_offline` is the same tree without the three
//// workers that use the network: commands commit locally and nothing is sent
//// or fetched, which is how a daemon can be inspected or its crash recovery
//// exercised.
////
//// ## Flow
////
//// 1. `start` calls `check_config`, `prepare_directory` and `launch`.
//// 2. `launch` builds the children and starts the supervisor.
//// 3. `route_notice` turns the engine's notices into nudges.
//// 4. `stop` ends the tree and waits for the lock to be released.

import core/capability
import core/endpoint
import core/plan
import daemon/api
import daemon/carrier
import daemon/config.{type Config}
import daemon/engine
import daemon/events
import daemon/fetch_manager
import daemon/lock
import daemon/provisioner
import daemon/scheduler
import daemon/status
import daemon/store
import gleam/erlang/process
import gleam/option.{None, Some}
import gleam/otp/static_supervisor
import gleam/result
import simplifile
import weft/poll

/// The file name of the database inside the state directory.
pub const database_file = "daemon.db"

/// The file name of the ownership lock inside the state directory.
pub const lock_file = "lock.db"

/// How long `stop` waits for the lock to be released.
pub const stop_wait_ms = 10_000

/// Which processes a tree has.
pub type Network {
  /// Everything: commands, delivery, fetching and queue creation.
  Online

  /// No scheduler, provisioner or fetchers. Local commands still commit.
  Offline
}

/// Why a daemon did not start.
pub type StartError {
  /// The state directory could not be created or its modes set.
  StateDirUnusable

  /// Another daemon holds the state directory.
  StateDirLocked

  /// The configured mailbox endpoint is not admitted by the carrier policy.
  MailboxNotPermitted

  /// The provisioning capability file is missing or not 32 bytes.
  BadProvisioning

  /// A process of the tree failed to start: the database, the Tor sidecar or
  /// the supervisor.
  StartupFailed
}

/// The names of the tree's processes.
type Names {
  Names(
    status: process.Name(status.Message),
    events: process.Name(events.Message(api.Event)),
    carrier: process.Name(carrier.Message),
    engine: process.Name(engine.Message),
    scheduler: process.Name(scheduler.Message),
    provisioner: process.Name(provisioner.Message),
    fetch_manager: process.Name(fetch_manager.Message),
  )
}

/// Starts a daemon with the network workers.
///
/// ## Examples
///
/// ```gleam
/// node.start(config.new(dir, mailbox, endpoint.TorOrLoopback))
/// // -> Ok(daemon)
/// ```
pub fn start(config: Config) -> Result(api.Daemon, StartError) {
  start_with(config, Online)
}

/// Starts a daemon without the workers that use the network.
///
/// ## Examples
///
/// ```gleam
/// node.start_offline(config)
/// // -> Ok(daemon)
/// ```
pub fn start_offline(config: Config) -> Result(api.Daemon, StartError) {
  start_with(config, Offline)
}

/// Starts a tree with the chosen processes.
fn start_with(
  config: Config,
  network: Network,
) -> Result(api.Daemon, StartError) {
  use provision <- result.try(check_config(config))
  use Nil <- result.try(prepare_directory(config))
  use Nil <- result.try(probe(config))

  launch(config, network, provision)
}

/// Checks what needs no process: the mailbox against the carrier policy and
/// the provisioning capability file. Returns the capability.
fn check_config(
  config: Config,
) -> Result(capability.Capability(capability.Provision), StartError) {
  use _ <- result.try(
    endpoint.admit(config.mailbox.endpoint, config.carrier)
    |> result.replace_error(MailboxNotPermitted),
  )
  use _ <- result.try(check_sidecar(config))
  use bytes <- result.try(
    simplifile.read_bits(config.mailbox.provisioning_file)
    |> result.replace_error(BadProvisioning),
  )

  capability.from_bytes(bytes) |> result.replace_error(BadProvisioning)
}

/// Refuses to start a tree that is certain to fail. A supervisor that fails
/// to start takes its linked starter down with it, so the two failures an
/// operator can cause are found first, by trying them: a held lock, and a
/// database that cannot be opened or is from a newer build.
fn probe(config: Config) -> Result(Nil, StartError) {
  let directory = config.state_dir

  // A held lock is the one start failure with its own name.
  case lock.is_free(directory <> "/" <> lock_file) {
    False -> Error(StateDirLocked)

    True -> {
      use opened <- result.try(
        store.open(directory <> "/" <> database_file, config.suite)
        |> result.replace_error(StartupFailed),
      )

      store.close(opened) |> result.replace_error(StartupFailed)
    }
  }
}

/// A configured Tor binary must exist, because a sidecar that cannot be
/// spawned fails the whole tree and with it the starter.
fn check_sidecar(config: Config) -> Result(Nil, StartError) {
  case config.tor {
    None -> Ok(Nil)

    Some(path) ->
      case simplifile.is_file(path) {
        Ok(True) -> Ok(Nil)
        Ok(False) | Error(_) -> Error(StartupFailed)
      }
  }
}

/// Creates the state directory `0700` and the two database files `0600`
/// before SQLite touches them, so they never exist with a wider mode (and
/// SQLite gives the `-wal` and `-shm` files the main file's mode).
fn prepare_directory(config: Config) -> Result(Nil, StartError) {
  let directory = config.state_dir

  use _ <- result.try(
    simplifile.create_directory_all(directory)
    |> result.replace_error(StateDirUnusable),
  )
  use _ <- result.try(
    simplifile.set_permissions_octal(directory, 0o700)
    |> result.replace_error(StateDirUnusable),
  )
  use _ <- result.try(private_file(directory <> "/" <> database_file))

  private_file(directory <> "/" <> lock_file)
}

/// Makes sure a file exists with mode `0600`.
fn private_file(path: String) -> Result(Nil, StartError) {
  // An existing file is kept; a new one is created empty. Either way its mode
  // is then narrowed.
  let created = case simplifile.is_file(path) {
    Ok(True) -> Ok(Nil)
    Ok(False) | Error(_) -> simplifile.create_file(path)
  }

  use _ <- result.try(created |> result.replace_error(StateDirUnusable))

  simplifile.set_permissions_octal(path, 0o600)
  |> result.replace_error(StateDirUnusable)
}

/// Builds the children and starts the supervisor.
fn launch(
  config: Config,
  network: Network,
  provision: capability.Capability(capability.Provision),
) -> Result(api.Daemon, StartError) {
  let names =
    Names(
      status: process.new_name("daemon_status"),
      events: process.new_name("daemon_events"),
      carrier: process.new_name("daemon_carrier"),
      engine: process.new_name("daemon_engine"),
      scheduler: process.new_name("daemon_scheduler"),
      provisioner: process.new_name("daemon_provisioner"),
      fetch_manager: process.new_name("daemon_fetch_manager"),
    )
  let directory = config.state_dir
  let dialer = carrier.dialer(names.carrier, config.carrier)

  let base =
    static_supervisor.new(static_supervisor.RestForOne)
    |> static_supervisor.add(lock.supervised(directory <> "/" <> lock_file))
    |> static_supervisor.add(status.supervised(names.status, tor_status(config)))
    |> static_supervisor.add(events.supervised(names.events))
    |> static_supervisor.add(carrier.supervised(
      names.carrier,
      names.status,
      config.tor,
      directory,
    ))
    |> static_supervisor.add(engine.supervised(
      names.engine,
      engine.Config(
        path: directory <> "/" <> database_file,
        suite: config.suite,
        clock: config.clock,
        policy: config.carrier,
        mailbox: config.mailbox.endpoint,
        accept_budget: config.accept_budget,
        notify: fn(notice) { route_notice(names, notice) },
      ),
    ))

  // The supervisor's start result decides whether the tree is up or why it is not.
  let tree = case network {
    Offline -> base

    Online ->
      base
      |> static_supervisor.add(scheduler.supervised(
        names.scheduler,
        scheduler.Config(
          dialer:,
          engine: names.engine,
          status: names.status,
          clock: config.clock,
          sha256: config.suite.sha256,
          send_deadline_ms: scheduler.send_deadline_ms,
        ),
      ))
      |> static_supervisor.add(provisioner.supervised(
        names.provisioner,
        provisioner.Config(
          dialer:,
          engine: names.engine,
          status: names.status,
          provision:,
        ),
      ))
      |> static_supervisor.add(fetch_manager.supervised(
        names.fetch_manager,
        fetch_manager.Config(
          dialer:,
          engine: names.engine,
          status: names.status,
        ),
      ))
  }

  // The supervisor's start result decides whether the tree is up or why it is not.
  case static_supervisor.start(tree) {
    Ok(started) ->
      Ok(api.assemble(
        names.engine,
        names.events,
        names.status,
        config.suite,
        config.carrier,
        started.pid,
        directory,
      ))

    Error(_) -> Error(classify_failure(directory))
  }
}

/// What a failed start was: a held lock if the lock is still held after the
/// failed tree let go of everything it had, otherwise a failed process.
fn classify_failure(directory: String) -> StartError {
  case lock.is_free(directory <> "/" <> lock_file) {
    True -> StartupFailed
    False -> StateDirLocked
  }
}

/// Where Tor stands before the carrier has said anything.
fn tor_status(config: Config) -> status.TorStatus {
  case config.tor {
    Some(_) -> status.TorStarting
    None -> status.TorNotUsed
  }
}

/// Turns one of the engine's notices into the nudge or event it means. This
/// is the whole of the engine-to-worker wiring.
fn route_notice(names: Names, notice: engine.Notice) -> Nil {
  case notice {
    engine.Nudge(plan.Transmit) -> scheduler.nudge(names.scheduler)

    engine.Nudge(plan.CreateQueue(_)) -> provisioner.nudge(names.provisioner)

    engine.Nudge(plan.WakeAdapter(contact:)) ->
      events.publish(names.events, api.MessagesReady(contact))

    engine.Changed(contact:) ->
      events.publish(names.events, api.ContactChanged(contact))

    engine.Topology -> fetch_manager.nudge(names.fetch_manager)
  }
}

/// Ends a daemon abruptly, as a crash would, and waits until the state
/// directory's lock is free so a daemon can start on it again at once. Every
/// process of the tree dies where it stands: committed state survives and
/// nothing else does. Call it from the process that started the daemon.
///
/// ## Examples
///
/// ```gleam
/// node.stop(daemon)
/// // -> Nil
/// ```
pub fn stop(daemon: api.Daemon) -> Nil {
  let supervisor = api.supervisor(daemon)

  // The supervisor is linked to its starter, and killing it would otherwise
  // take the starter down with it.
  process.unlink(supervisor)
  process.kill(supervisor)

  wait_for_lock(api.state_dir(daemon) <> "/" <> lock_file, stop_wait_ms)
}

/// Polls until the lock can be taken or the wait is over. The `Retry` arm is
/// a backstop that no test exercises: the lock's `on_shutdown` frees it
/// before a following `start` probes it, so no test sees the first attempt
/// fail.
fn wait_for_lock(path: String, within_ms: Int) -> Nil {
  // A free lock ends the stop; a spent wait ends it too, and the caller
  // finds out when it starts on the directory again.
  let _ =
    poll.until(within: within_ms, every: 20, attempt: fn() {
      case lock.is_free(path) {
        True -> poll.Done(Nil)
        False -> poll.Retry
      }
    })

  Nil
}
