//// The runner: owns the event loop of a whole simulated world and plays
//// one seed through it.
////
//// Two real daemon trees and one real mailbox tree run as ordinary BEAM
//// processes. Every way they touch each other or the outside world is a
//// seam (`sim/world`), and every seam parks what happened with the runner
//// instead of letting it happen. The runner then releases one parked event
//// at a time, waits until the VM is quiescent (nothing but the runner is
//// runnable, dirty schedulers included), drains what that release caused
//// into the parked set, and chooses the next event with the run's seeded
//// generator. Time moves only when the runner says so.
////
//// ## What is parked, and what is ordered by quiescence
////
//// Parked, and released in an order the seed chooses:
////
//// - every cross-actor `tell` and `ask` in both daemons and the mailbox
////   (the interceptors); one sender's parcels are released in the order it
////   sent them, because a schedule that reorders them is one production
////   cannot have (the long poll's register-then-look depends on it);
//// - every timer arming of every weft actor, state machine and run, the
////   long poll's deadline, `api.invite`'s poll sleep, and each simulated
////   connection reader's deadline (the wheel);
//// - every request a daemon writes and every response the mailbox gives.
////
//// Not parked, and ordered only by quiescence: ask replies, a process's
//// sends to itself, weft-internal wake-ups and run outcomes once their
//// timer fired, the events registry's fan-out, the notifier's wake-ups to
//// waiting long polls, and supervisor traffic. Each of these is caused by
//// exactly one released event, so it runs to completion inside that step.
////
//// ## Choosing
////
//// The ready set is the head of each sender's parcel queue, every timer
//// already due, every parked request and every parked response. Each has a
//// key that does not depend on which process the BEAM ran first: the
//// sender's role (a daemon's actor name, `op<n>` for an operator op,
//// `req<n>` for a mailbox request), the target, the label and a per-role
//// sequence number; a timer's deadline; a request's node and content. The
//// set is sorted by key and one is picked by the generator. With the
//// network-delay class on, a quarter of the choices hold the network back,
//// so a timer can fire while a request or response is in flight.
////
//// When nothing is ready, virtual time jumps to the earliest timer, if the
//// current op allows time to move that far.
////
//// ## Flow
////
//// 1. `run` decodes the seed, calls `setup`, runs every op through `apply`,
////    then `heal`, the liveness check and `teardown`.
//// 2. `apply` arms a fault, moves the world, or spawns the op's process,
////    then `pump`s until nothing is ready at the current instant.
//// 3. `pump` repeats `settle` (quiesce, `drain`, safety), `choose` and
////    `release` until nothing is ready before its deadline.
//// 4. `heal` clears every fault and lets time run in chunks until the
////    liveness check passes or the heal budget is spent.
//// 5. `snapshot` collects the trace and every table for the double run.

import core/capability
import core/crypto/suite as core_suite
import core/endpoint
import core/envelope
import core/id
import core/mailbox/protocol.{type Response}
import daemon/api
import daemon/config
import daemon/engine
import daemon/node as daemon_node
import gleam/dict.{type Dict}
import gleam/erlang/process.{type Pid, type Subject}
import gleam/int
import gleam/io
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/set.{type Set}
import gleam/string
import mailbox/node as mailbox_node
import mailbox/service
import mailbox/store as mailbox_store
import sim/forge
import sim/internal/ffi_vm.{type Table}
import sim/net
import sim/ops
import sim/oracle
import sim/rng.{type Rng}
import sim/seed.{type Op, type Party, type Script}
import sim/suite
import sim/tables
import sim/world.{type Inbound, type Wire, type World}
import simplifile
import sqlight

/// The most events one run may release before it is stopped as runaway.
pub const max_steps = 400_000

/// The most events one virtual instant may hold before it is a livelock.
pub const max_steps_per_instant = 20_000

/// How long the heal phase may run, in virtual milliseconds.
pub const heal_budget_ms = 900_000

/// How far each heal round moves time, in virtual milliseconds.
pub const heal_round_ms = 5000

/// How a run reports itself.
pub type Options {
  Options(
    /// Print each released event and the daemons' log lines as they come.
    verbose: Verbosity,
  )
}

/// Whether a run prints as it goes.
pub type Verbosity {
  Quiet
  Loud
}

/// What a run found.
pub type Report {
  Report(
    /// The seed that was run.
    seed: BitArray,
    /// Every broken property, safety and liveness, in the order found.
    violations: List(oracle.Violation),
    /// Every excuse applied, in the order found.
    excuses: List(oracle.Excuse),
    /// Everything the double run compares.
    snapshot: List(String),
    /// How many events were released.
    steps: Int,
    /// How far virtual time moved, in milliseconds.
    virtual_ms: Int,
  )
}

/// One daemon of the world.
type Daemon {
  Daemon(
    party: Party,
    name: String,
    uri: String,
    keeper: sqlight.Connection,
    config: config.Config,
    handle: api.Daemon,
    kills: Int,
  )
}

/// The mailbox of the world.
type Mailbox {
  Mailbox(
    node: mailbox_node.Node,
    supervisor: Pid,
    keeper: sqlight.Connection,
    holder: mailbox_store.Store,
    kills: Int,
  )
}

/// A parked parcel.
type Mail {
  Mail(key: String, deliver: fn() -> Bool)
}

/// A timer on the wheel.
type Timer {
  Timer(
    deadline: Int,
    key: String,
    wake: fn() -> Nil,
    wire: Option(Subject(Wire)),
  )
}

/// A request a daemon wrote and the runner has not yet released.
type Parked {
  Parked(
    key: String,
    node: String,
    sender: Pid,
    wire: Subject(Wire),
    read: net.Read,
  )
}

/// A released request, by id.
type Request {
  Request(node: String, wire: Subject(Wire), read: net.Read)
}

/// One event the runner may release now.
type Ready {
  FromMail(sender: Pid)
  FromTimer(key: String)
  FromSend(key: String)
  FromAnswer(id: Int)
}

/// An invitation file an `Invite` produced.
type File {
  File(from: Party, bytes: BitArray, state: FileState)
}

/// Whether the network may be held back while timers fire.
type Delay {
  /// The delay class is on: some choices exclude network events.
  Holding

  /// Network events are as ready as anything else.
  Prompt
}

/// Whether an invitation file has been handed to an honest accept.
type FileState {
  Unused
  Redeemed
}

/// What the runner decided after looking at the ready set.
type Choice {
  Release(Ready)
  Jump(Int)
  Rest
}

/// The whole run.
type State {
  State(
    seed: BitArray,
    script: Script,
    options: Options,
    world: World,
    rng: Rng,
    a: Daemon,
    b: Daemon,
    mailbox: Mailbox,
    handles: Table(String, api.Daemon),
    sink: ffi_vm.Sink,
    logger: Option(ffi_vm.LogLevel),
    decoder: core_suite.Suite,
    cache: oracle.Cache,
    mail: Dict(Pid, List(Mail)),
    timers: List(Timer),
    sends: List(Parked),
    answers: Dict(Int, Response),
    requests: Dict(Int, Request),
    wires: Dict(Subject(Wire), String),
    closed_wires: Set(Subject(Wire)),
    who: Dict(Pid, String),
    seqs: Dict(String, Int),
    spawned: List(Pid),
    next_request: Int,
    now: Int,
    step: Int,
    at_instant: Int,
    transactions: Int,
    delay: Delay,
    trace: List(String),
    logs: List(String),
    violations: List(oracle.Violation),
    excuses: List(oracle.Excuse),
    lied: Set(#(String, BitArray)),
    tombstoned: Set(#(BitArray, BitArray)),
    corrupted: Set(BitArray),
    ops: Dict(Int, #(Op, Option(world.Outcome))),
    files: List(File),
    mailbox_kills: Int,
    aborted: Option(String),
  )
}

/// Runs one seed to the end and reports what it found.
///
/// ## Examples
///
/// ```gleam
/// runner.run(<<0, 255, 255, 3, 0, 4, 1>>, runner.Options(verbose: runner.Quiet))
/// // -> Report(violations: [], ..)
/// ```
pub fn run(bytes: BitArray, options: Options) -> Report {
  let script = seed.decode(bytes)
  let state = setup(bytes, script, options)
  let state = pump(state, state.now)

  let state =
    list.index_fold(script.ops, state, fn(state, op, index) {
      apply(state, index, op)
    })

  let state = heal(state)
  let state = final_checks(state)
  let snapshot = snapshot(state)
  let report =
    Report(
      seed: bytes,
      violations: list.reverse(state.violations),
      excuses: list.reverse(state.excuses),
      snapshot:,
      steps: state.step,
      virtual_ms: state.now,
    )

  teardown(state)
  report
}

// ------------------------------------------------------------------- setup

/// Builds the world: stores, the mailbox and its grant, both daemons.
fn setup(bytes: BitArray, script: Script, options: Options) -> State {
  let inbox = process.new_subject()
  let the_world = world.new(inbox)
  let run_id = int.to_string(ffi_vm.unique())
  let root = "build/sim_state/" <> ffi_vm.os_pid()
  let sink = ffi_vm.install_sink()

  // A quiet run silences the logger, and must put its level back.
  let logger = case options.verbose {
    Quiet -> Some(ffi_vm.quiet_logger())
    Loud -> None
  }

  let mailbox_uri = memory_uri(run_id, "m")
  let assert Ok(holder) = mailbox_store.open(mailbox_uri)
    as "the mailbox's in-memory store opens"
  let assert Ok(mailbox_keeper) = sqlight.open(mailbox_uri)
    as "the mailbox keeper connection opens"
  let mailbox_suite = suite.new(bytes, "m")
  let assert Ok(provision) =
    service.create_grant(holder, 1000, mailbox_suite.random)
    as "the provisioning grant is created"

  let mailbox = start_mailbox(the_world, mailbox_uri, holder, mailbox_keeper)
  let a = new_daemon(the_world, bytes, seed.A, run_id, root, provision)
  let b = new_daemon(the_world, bytes, seed.B, run_id, root, provision)
  let handles = ffi_vm.table_new()
  ffi_vm.table_put(handles, a.name, a.handle)
  ffi_vm.table_put(handles, b.name, b.handle)

  State(
    seed: bytes,
    script:,
    options:,
    world: the_world,
    rng: rng.new(seed_number(bytes)),
    a:,
    b:,
    mailbox:,
    handles:,
    sink:,
    logger:,
    decoder: suite.new(<<>>, "decode"),
    cache: oracle.new_cache(),
    mail: dict.new(),
    timers: [],
    sends: [],
    answers: dict.new(),
    requests: dict.new(),
    wires: dict.new(),
    closed_wires: set.new(),
    who: dict.new(),
    seqs: dict.new(),
    spawned: [],
    next_request: 0,
    now: 0,
    step: 0,
    at_instant: 0,
    transactions: 0,
    delay: case list.contains(script.enabled, seed.NetDelay) {
      True -> Holding
      False -> Prompt
    },
    trace: [],
    logs: [],
    violations: [],
    excuses: [],
    lied: set.new(),
    tombstoned: set.new(),
    corrupted: set.new(),
    ops: dict.new(),
    files: [],
    mailbox_kills: 0,
    aborted: None,
  )
}

/// A shared-cache in-memory SQLite URI, unique to this run and node.
fn memory_uri(run_id: String, node: String) -> String {
  "file:sim" <> run_id <> node <> "?mode=memory&cache=shared"
}

/// The generator seed of a run: the first eight bytes of the seed's hash.
fn seed_number(bytes: BitArray) -> Int {
  let digest = suite.new(<<>>, "order").sha256(<<"order":utf8, bytes:bits>>)

  // The digest is 32 bytes, so the first eight always exist.
  case digest {
    <<number:size(64), _:bits>> -> number
    _ -> 0
  }
}

/// Starts the mailbox tree with every seam set.
fn start_mailbox(
  the_world: World,
  uri: String,
  holder: mailbox_store.Store,
  keeper: sqlight.Connection,
) -> Mailbox {
  let assert Ok(#(started, running)) =
    mailbox_node.start(mailbox_node.Config(
      path: uri,
      sweep_period_ms: 60_000,
      clock: world.clock(the_world, "m"),
      names: mailbox_node.new_names(),
      timer: world.timer_source(the_world, "m"),
      interceptor: Some(world.mailbox_interceptor(the_world)),
      store_faults: Some(world.mailbox_store_hook(the_world)),
    ))
    as "the mailbox tree starts"

  // The tree must not take the runner down with it if it dies.
  process.unlink(started.pid)

  Mailbox(node: running, supervisor: started.pid, keeper:, holder:, kills: 0)
}

/// Builds a daemon's configuration and starts it.
fn new_daemon(
  the_world: World,
  bytes: BitArray,
  party: Party,
  run_id: String,
  root: String,
  provision: capability.Capability(capability.Provision),
) -> Daemon {
  let name = seed.party_name(party)
  let uri = memory_uri(run_id, name)
  let directory = root <> "/" <> name
  let provisioning = directory <> "/provision.cap"
  let assert Ok(Nil) = simplifile.create_directory_all(directory)
    as "the state directory can be made"
  let assert Ok(Nil) =
    simplifile.write_bits(provisioning, capability.expose(provision))
    as "the provisioning file can be written"
  let assert Ok(keeper) = sqlight.open(uri) as "the keeper connection opens"

  let assert Ok(address) =
    endpoint.parse_onion(string.repeat("a", 55) <> "d.onion")
    as "the mailbox's onion address parses"
  let assert Ok(port) = endpoint.port(80) as "port 80 is a port"
  let base =
    config.new(
      directory,
      config.Mailbox(
        endpoint: endpoint.Onion(address:, port:),
        provisioning_file: provisioning,
      ),
      endpoint.TorOnly,
    )

  let settings =
    config.Config(
      ..base,
      clock: world.clock(the_world, name),
      suite: suite.new(bytes, name),
      accept_budget: seed.decode(bytes).mode.budget,
      timer: world.timer_source(the_world, name),
      poll_clock: world.poll_clock(the_world, name),
      dialer: Some(world.dialer(the_world, name)),
      database: Some(uri),
      store_faults: Some(world.daemon_store_hook(the_world, name)),
      engine_faults: Some(world.engine_hook(the_world, name)),
      interceptor: Some(world.daemon_interceptor(the_world, name)),
    )

  Daemon(
    party:,
    name:,
    uri:,
    keeper:,
    config: settings,
    handle: start_tree(settings),
    kills: 0,
  )
}

/// Starts a daemon tree and unlinks it from the runner.
fn start_tree(settings: config.Config) -> api.Daemon {
  let assert Ok(handle) = daemon_node.start(settings) as "a daemon tree starts"

  // A tree that dies must not take the runner down with it.
  process.unlink(api.supervisor(handle))
  handle
}

// -------------------------------------------------------------------- ops

/// Runs one op of the script, then lets the instant settle.
fn apply(state: State, index: Int, op: Op) -> State {
  // An aborted run skips the rest of its script.
  case state.aborted {
    Some(_) -> state
    None ->
      pump(
        perform(trace(state, "op " <> int.to_string(index)), index, op),
        state.now,
      )
  }
}

/// Carries out one op.
fn perform(state: State, index: Int, op: Op) -> State {
  let faults = state.world.faults

  // Faults are armed in the shared table; world ops act at once; the rest
  // run in a process of their own.
  case op {
    seed.Advance(ms:) -> pump(state, state.now + ms)

    seed.ArmStore(target:, fault:, skip:) -> {
      let key = world.StoreKey(target_name(target))
      ffi_vm.table_put(faults, key, world.StoreArm(fault:, skip:))
      state
    }

    seed.ArmEngine(party:, kind:, fate:) -> {
      let key = world.EngineKey(seed.party_name(party), engine.kind_label(kind))
      ffi_vm.table_put(faults, key, world.FateArm(fate))
      state
    }

    seed.ArmLoss(party:, loss: seed.DropRequest) -> {
      ffi_vm.table_put(
        faults,
        world.DropKey(seed.party_name(party)),
        world.LossArm,
      )
      state
    }

    seed.ArmLoss(party:, loss: seed.LoseResponse) -> {
      ffi_vm.table_put(
        faults,
        world.LoseKey(seed.party_name(party)),
        world.LossArm,
      )
      state
    }

    seed.ArmLie(party:, lie:) -> {
      ffi_vm.table_put(
        faults,
        world.LieKey(seed.party_name(party)),
        world.LieArm(lie),
      )
      state
    }

    seed.ToggleMailbox -> {
      let cells = state.world.cells
      let down = ffi_vm.cells_get(cells, world.mailbox_down_cell)
      ffi_vm.cells_put(cells, world.mailbox_down_cell, 1 - down)
      state
    }

    seed.SetSkew(target:, seconds:) -> {
      let cell = world.skew_cell(target_name(target))
      ffi_vm.cells_put(state.world.cells, cell, seconds * 1000)
      state
    }

    seed.Forge(party:, forgery:) -> forge_op(state, index, party, forgery)

    seed.Restart(party:) -> restart(state, party)

    seed.Kill(victim:) -> kill(state, victim)

    _ -> spawn_op(state, index, op)
  }
}

/// The node name a fault target stands for.
fn target_name(target: seed.Target) -> String {
  case target {
    seed.Daemon(party:) -> seed.party_name(party)
    seed.Mailbox -> "m"
  }
}

/// Starts an op's process, or lets time pass if the op has nothing to do.
fn spawn_op(state: State, index: Int, op: Op) -> State {
  let #(file, state) = file_for(state, op)
  let inbox = state.world.inbox
  let env =
    ops.Env(
      handles: state.handles,
      sleep: sleeper(state.world, "op"),
      mode: state.script.mode,
    )

  // An op with no body (an accept with no file to redeem) is an honest
  // short wait instead.
  case ops.body(env, index, op, file) {
    Error(Nil) -> pump(state, state.now + 100)

    Ok(body) -> {
      let pid =
        process.spawn_unlinked(fn() {
          process.send(inbox, world.Finished(op: index, outcome: body()))
        })
      State(
        ..state,
        who: dict.insert(state.who, pid, "op" <> int.to_string(index)),
        spawned: [pid, ..state.spawned],
        ops: dict.insert(state.ops, index, #(op, None)),
      )
    }
  }
}

/// A sleep on the wheel, for an op's retries.
fn sleeper(the_world: World, node: String) -> fn(Int) -> Nil {
  let clock = world.poll_clock(the_world, node)
  clock.sleep
}

/// The invitation file an op redeems, taking it out of the pool when the
/// op is an honest accept.
fn file_for(state: State, op: Op) -> #(Result(BitArray, Nil), State) {
  // Only accepts redeem a file; a past-limit accept leaves it in the pool.
  case op {
    seed.Accept(party:, pick:) -> take_file(state, party, pick, Redeemed)
    seed.Exceed(party:, limit: seed.AcceptDescriptionPast) ->
      take_file(state, party, 0, Unused)
    _ -> #(Error(Nil), state)
  }
}

/// The `pick`th unused file the other daemon made, left in the state
/// `after` says: `Redeemed` for an honest accept, `Unused` for one that
/// must be refused.
fn take_file(
  state: State,
  party: Party,
  pick: Int,
  after: FileState,
) -> #(Result(BitArray, Nil), State) {
  let open =
    list.filter(state.files, fn(file) {
      file.from == seed.other(party) && file.state == Unused
    })

  // No open file means nothing to accept.
  case open {
    [] -> #(Error(Nil), state)

    _ -> {
      let index = pick % list.length(open)
      let assert Ok(chosen) = list.drop(open, index) |> list.first
        as "the index is within the list"
      let files =
        list.map(state.files, fn(file) {
          case file == chosen {
            True -> File(..file, state: after)
            False -> file
          }
        })
      #(Ok(chosen.bytes), State(..state, files:))
    }
  }
}

/// Forges a message from `party` and hands it to the mailbox.
fn forge_op(
  state: State,
  index: Int,
  party: Party,
  forgery: seed.Forgery,
) -> State {
  let daemon = daemon_of(state, party)
  let forger = suite.new(state.seed, "forge" <> int.to_string(index))
  let now = world.clock(state.world, daemon.name)()

  // A forgery that found nothing to forge on is an honest short wait.
  case forge.forge(daemon.uri, daemon.keeper, forger, now, forgery) {
    Error(reason) ->
      pump(trace(state, "forge skipped: " <> reason), state.now + 100)

    Ok(request) -> {
      let mailbox = state.mailbox.node
      let pid =
        process.spawn_unlinked(fn() {
          let _ = mailbox_node.handle(mailbox, request)
          Nil
        })
      let tag = "forge" <> int.to_string(index)
      let state = trace(state, "forged " <> net.describe(request))
      State(..state, who: dict.insert(state.who, pid, tag), spawned: [
        pid,
        ..state.spawned
      ])
    }
  }
}

/// The daemon record of a party.
fn daemon_of(state: State, party: Party) -> Daemon {
  case party {
    seed.A -> state.a
    seed.B -> state.b
  }
}

/// Replaces a party's daemon record.
fn with_daemon(state: State, daemon: Daemon) -> State {
  ffi_vm.table_put(state.handles, daemon.name, daemon.handle)

  // The party decides which slot it fills.
  case daemon.party {
    seed.A -> State(..state, a: daemon)
    seed.B -> State(..state, b: daemon)
  }
}

/// Stops a daemon as a crash would and starts it again over its stores.
fn restart(state: State, party: Party) -> State {
  let daemon = daemon_of(state, party)
  process.kill(api.supervisor(daemon.handle))

  // The old tree finishes dying, its lock closing in an unregistered
  // process, before the new one takes the lock.
  let state = settle_with(state, ffi_vm.Every)
  let handle = start_tree(daemon.config)
  let state = trace(state, "restart " <> daemon.name)

  with_daemon(state, Daemon(..daemon, handle:, kills: 0))
}

/// Kills one process; its supervisor restarts it. At most two kills per
/// daemon incarnation and two on the mailbox, so the supervisors' restart
/// intensity (counted on the wall clock) is never what ends a tree.
fn kill(state: State, victim: seed.Victim) -> State {
  // Each victim is found by role among its supervisor's children.
  case victim {
    seed.KillEngine(party:) -> kill_daemon_child(state, party, "daemon_engine")
    seed.KillScheduler(party:) ->
      kill_daemon_child(state, party, "daemon_scheduler")
    seed.KillProvisioner(party:) ->
      kill_daemon_child(state, party, "daemon_provisioner")
    seed.KillFetchManager(party:) ->
      kill_daemon_child(state, party, "daemon_fetch_manager")
    seed.KillCoordinator -> kill_mailbox_child(state, "mailbox_coordinator")
    seed.KillNotifier -> kill_mailbox_child(state, "mailbox_notifier")
  }
}

/// Kills a daemon child by role, within the kill budget.
fn kill_daemon_child(state: State, party: Party, role: String) -> State {
  let daemon = daemon_of(state, party)

  // Past the budget the op is an honest short wait.
  case daemon.kills >= 2 {
    True -> pump(state, state.now + 100)

    False -> {
      kill_role(api.supervisor(daemon.handle), role)
      let state = settle_with(state, ffi_vm.Every)
      let state = trace(state, "kill " <> daemon.name <> " " <> role)
      with_daemon(state, Daemon(..daemon, kills: daemon.kills + 1))
    }
  }
}

/// Kills a mailbox child by role, within the kill budget.
fn kill_mailbox_child(state: State, role: String) -> State {
  // Past the budget the op is an honest short wait.
  case state.mailbox_kills >= 2 {
    True -> pump(state, state.now + 100)

    False -> {
      kill_role(state.mailbox.supervisor, role)
      let state = settle_with(state, ffi_vm.Every)
      let state = trace(state, "kill m " <> role)
      State(..state, mailbox_kills: state.mailbox_kills + 1)
    }
  }
}

/// Kills the child of `supervisor` registered under `role`.
fn kill_role(supervisor: Pid, role: String) -> Nil {
  ffi_vm.supervisor_children(supervisor)
  |> list.filter(fn(pid) { ffi_vm.registered_role(pid) == role })
  |> list.each(process.kill)
}

// ------------------------------------------------------------------- loop

/// Releases events until nothing is ready before `until`, then moves time
/// to `until` if it is later.
fn pump(state: State, until: Int) -> State {
  // An aborted run releases nothing more.
  case state.aborted {
    Some(_) -> state

    None -> {
      let state = settle(state)

      // The ready set decides: release one event, move time, or stop here.
      case choose(state, until) {
        #(Release(ready), state) -> pump(release(state, ready), until)
        #(Jump(deadline), state) -> pump(jump(state, deadline), until)
        #(Rest, state) -> jump(state, int.max(state.now, until))
      }
    }
  }
}

/// Moves virtual time to `to`.
fn jump(state: State, to: Int) -> State {
  // Time only moves forward; a jump to now changes nothing.
  case to > state.now {
    True -> {
      ffi_vm.cells_put(state.world.cells, world.now_cell, to)
      State(..state, now: to, at_instant: 0)
    }

    False -> state
  }
}

/// Waits for quiescence, drains every report, and checks safety if
/// anything was written.
fn settle(state: State) -> State {
  settle_with(state, ffi_vm.Registered)
}

/// `settle`, confirming quiescence over `scan`.
fn settle_with(state: State, scan: ffi_vm.Scan) -> State {
  // A VM that never quiesces is a harness fault; the run stops.
  case ffi_vm.quiesce(50_000_000, scan) {
    Error(Nil) -> abort(state, "the VM never became quiescent")

    Ok(_) -> {
      let state = drain(state)
      let written = ffi_vm.cells_get(state.world.cells, world.transactions_cell)

      // Only a step that wrote something can have broken a safety property.
      case written == state.transactions {
        True -> state
        False -> safety(State(..state, transactions: written))
      }
    }
  }
}

/// Stops the run with a harness-level violation.
fn abort(state: State, reason: String) -> State {
  let violation = oracle.Violation(check: "runner", detail: reason)
  State(..state, aborted: Some(reason), violations: [
    violation,
    ..state.violations
  ])
}

/// Takes every report waiting in the inbox into the parked set.
fn drain(state: State) -> State {
  // An empty inbox ends the drain.
  case process.receive(state.world.inbox, 0) {
    Ok(inbound) -> drain(integrate(state, inbound))
    Error(Nil) -> state
  }
}

/// Files one report.
fn integrate(state: State, inbound: Inbound) -> State {
  // Each report is one kind of parked event, or a finished op.
  case inbound {
    world.Parked(node:, sender:, from:, to:, label:, deliver:) -> {
      let tag = tag_of(state, sender, node <> ":" <> from)
      let stem = string.join([tag, node <> ":" <> to, label], "|")
      let #(seq, state) = next_seq(state, stem)
      let key = stem <> "|" <> pad(seq)
      let queue = dict.get(state.mail, sender) |> result.unwrap([])
      let queued = list.append(queue, [Mail(key:, deliver:)])
      State(..state, mail: dict.insert(state.mail, sender, queued))
    }

    world.Armed(node:, sender:, delay:, wake:) -> {
      let role = node <> ":" <> ffi_vm.registered_role(sender)
      let tag = tag_of(state, sender, role)
      let deadline = state.now + delay
      let stem = string.join([pad(deadline), tag], "|")
      let #(seq, state) = next_seq(state, stem)
      let key = stem <> "|" <> pad(seq)
      let timer = Timer(deadline:, key:, wake:, wire: None)
      State(..state, timers: [timer, ..state.timers])
    }

    world.Requested(node:, sender:, wire:, bytes:) ->
      requested(state, node, sender, wire, net.read_request(bytes))

    world.Waiting(node: _, sender: _, wire:, timeout:) -> {
      let owner = dict.get(state.wires, wire) |> result.unwrap("unknown")
      let deadline = state.now + timeout
      let key = string.join([pad(deadline), "wire", owner], "|")
      let wake = fn() { process.send(wire, world.Expired) }
      let timer = Timer(deadline:, key:, wake:, wire: Some(wire))
      State(..state, timers: [timer, ..state.timers])
    }

    world.Answered(id:, response:) ->
      State(..state, answers: dict.insert(state.answers, id, response))

    world.Finished(op:, outcome:) -> finished(state, op, outcome)
  }
}

/// The ordering role of a process: the runner's own name for it if it
/// spawned it, else the role the seam labelled it with.
fn tag_of(state: State, sender: Pid, fallback: String) -> String {
  dict.get(state.who, sender) |> result.unwrap(fallback)
}

/// The next sequence number for a key stem. A stem is everything about an
/// event but its order: two parcels with one stem from two processes that
/// share a role (a run's tasks all report as their actor) are the same
/// message to the same target, so which one takes which number cannot
/// change what happens.
fn next_seq(state: State, tag: String) -> #(Int, State) {
  let seq = dict.get(state.seqs, tag) |> result.unwrap(0)
  #(seq, State(..state, seqs: dict.insert(state.seqs, tag, seq + 1)))
}

/// A number written with a fixed width, so keys sort numerically: offset
/// by 10^12, which every step, time and id in a run stays below.
fn pad(number: Int) -> String {
  int.to_string(number + 1_000_000_000_000)
}

/// Files a request a daemon wrote, after checking it against the
/// writer's committed state.
fn requested(
  state: State,
  node: String,
  sender: Pid,
  wire: Subject(Wire),
  read: net.Read,
) -> State {
  // The trace names a request by its kind and the ids it carries.
  let text = case read {
    net.Decoded(request) -> net.describe(request)
    net.Undecodable(_) -> "undecodable"
  }

  let content = node <> ":" <> text
  let #(seq, state) = next_seq(state, content)
  let key = content <> "|" <> pad(seq)
  let state = request_checks(state, node, read)
  let parked = Parked(key:, node:, sender:, wire:, read:)

  // A process the runner did not spawn takes its first request's key as
  // its ordering role. Several of a run's tasks share their actor's role
  // (a scheduler's sends all report to the status cell as "scheduler"), and
  // two of them parking in one step would otherwise be ordered by which the
  // BEAM ran first.
  let who = case dict.has_key(state.who, sender) {
    True -> state.who
    False -> dict.insert(state.who, sender, "net:" <> key)
  }

  State(
    ..state,
    who:,
    sends: [parked, ..state.sends],
    wires: dict.insert(state.wires, wire, key),
  )
}

/// The three checks made when a request is written: an `Append` carries a
/// committed outbox row's bytes and is the only one in flight for its
/// envelope; an `Ack` names only committed `Processed` rows.
fn request_checks(state: State, node: String, read: net.Read) -> State {
  // The writer's keeper connection is the store the request must agree with.
  let daemon = case node {
    "a" -> state.a
    _ -> state.b
  }

  // Only appends and acks carry a claim about committed state.
  case read {
    net.Decoded(protocol.Append(queue: _, envelope:, ciphertext:, ..)) -> {
      let envelope_bytes = id.to_bytes(envelope)
      let wire_bytes = envelope.to_wire(ciphertext)
      let committed =
        tables.outbox(daemon.keeper)
        |> list.any(fn(row) {
          row.envelope == envelope_bytes && row.padded == wire_bytes
        })
      let in_flight = in_flight_appends(state, node, envelope_bytes)

      // The bytes on the wire must be a committed row's, byte for byte.
      let uncommitted = case committed {
        True -> []
        False -> [
          oracle.Violation(
            "append_committed",
            node
              <> " appended "
              <> oracle.short(envelope_bytes)
              <> " without a committed row",
          ),
        ]
      }

      // No earlier append of the same envelope may still be in flight.
      let doubled = case in_flight {
        0 -> []
        _ -> [
          oracle.Violation(
            "single_inflight",
            node
              <> " has "
              <> int.to_string(in_flight + 1)
              <> " appends of "
              <> oracle.short(envelope_bytes)
              <> " in flight",
          ),
        ]
      }

      add_violations(state, list.append(uncommitted, doubled))
    }

    net.Decoded(protocol.Ack(queue:, envelopes:, ..)) -> {
      let queue_bytes = id.to_bytes(queue)
      let processed = tables.processed(daemon.keeper)
      let unprocessed =
        list.filter(envelopes, fn(envelope) {
          let bytes = id.to_bytes(envelope)
          !list.any(processed, fn(row) {
            row.queue == queue_bytes && row.envelope == bytes
          })
        })

      // Every acknowledged envelope must have its outcome committed.
      case unprocessed {
        [] -> state
        [_, ..] ->
          add_violations(state, [
            oracle.Violation(
              "ack_processed",
              node <> " acknowledged an envelope with no processed row",
            ),
          ])
      }
    }

    _ -> state
  }
}

/// How many `Append`s of one envelope from one daemon are still in flight:
/// parked or released, the reader alive and not yet answered or expired.
fn in_flight_appends(state: State, node: String, envelope: BitArray) -> Int {
  let parked =
    list.count(state.sends, fn(send) {
      send.node == node
      && appends(send.read, envelope)
      && open(state, send.wire)
      && process.is_alive(send.sender)
    })
  let released =
    dict.values(state.requests)
    |> list.count(fn(request) {
      request.node == node
      && appends(request.read, envelope)
      && open(state, request.wire)
      && wire_alive(request.wire)
    })

  parked + released
}

/// Whether a read request appends this envelope.
fn appends(read: net.Read, envelope: BitArray) -> Bool {
  case read {
    net.Decoded(protocol.Append(envelope: found, ..)) ->
      id.to_bytes(found) == envelope
    _ -> False
  }
}

/// Whether a connection's reader is still waiting for an answer.
fn open(state: State, wire: Subject(Wire)) -> Bool {
  !set.contains(state.closed_wires, wire)
}

/// Whether the process that owns a connection is alive.
fn wire_alive(wire: Subject(Wire)) -> Bool {
  case process.subject_owner(wire) {
    Ok(pid) -> process.is_alive(pid)
    Error(Nil) -> False
  }
}

/// Adds violations found at one instant to the run's list.
fn add_violations(state: State, found: List(oracle.Violation)) -> State {
  State(..state, violations: list.append(list.reverse(found), state.violations))
}

/// Files a finished op, and keeps an invitation file it produced.
fn finished(state: State, index: Int, outcome: world.Outcome) -> State {
  let entry = dict.get(state.ops, index)

  // Only a known op's outcome is filed; an op the runner never spawned has none.
  let ops = case entry {
    Ok(#(op, _)) -> dict.insert(state.ops, index, #(op, Some(outcome)))
    Error(Nil) -> state.ops
  }

  let state = State(..state, ops:)

  // Only an invitation file feeds a later op.
  case outcome, entry {
    world.Invited(file:, ..), Ok(#(op, _)) ->
      case party_of(op) {
        Ok(from) ->
          State(
            ..state,
            files: list.append(state.files, [
              File(from:, bytes: file, state: Unused),
            ]),
          )
        Error(Nil) -> state
      }

    _, _ -> state
  }
}

/// Looks at the ready set and decides what happens next.
fn choose(state: State, until: Int) -> #(Choice, State) {
  let #(local, network) = ready(state)

  // With the delay class on, a quarter of the choices hold the network back.
  let #(hold, rng) = case state.delay == Holding && network != [] {
    True -> {
      let #(roll, rng) = rng.below(state.rng, 4)
      #(roll == 0, rng)
    }
    False -> #(False, state.rng)
  }

  let state = State(..state, rng:)

  // A held network leaves only the local events to choose among.
  let candidates = case hold {
    True -> local
    False -> list.append(local, network)
  }

  let next = earliest(state.timers)

  // A held network with nothing local lets time pass to the next timer
  // instead, if the op allows time to move.
  case candidates, next {
    [], Some(deadline) if deadline <= until -> #(Jump(deadline), state)
    [], _ ->
      case network {
        [] -> #(Rest, state)
        _ -> pick(state, network)
      }
    _, _ -> pick(state, candidates)
  }
}

/// One of `candidates`, sorted by key and chosen by the generator.
fn pick(state: State, candidates: List(#(String, Ready))) -> #(Choice, State) {
  let sorted = list.sort(candidates, fn(x, y) { string.compare(x.0, y.0) })
  let #(index, rng) = rng.below(state.rng, list.length(sorted))
  let assert Ok(#(_, chosen)) = list.drop(sorted, index) |> list.first
    as "the index is within the ready set"

  #(Release(chosen), State(..state, rng:))
}

/// The ready set, split into local events (parcels and due timers) and the
/// network (requests and responses).
fn ready(state: State) -> #(List(#(String, Ready)), List(#(String, Ready))) {
  let mail =
    dict.to_list(state.mail)
    |> list.filter_map(fn(pair) {
      case pair.1 {
        [head, ..] -> Ok(#("1|" <> head.key, FromMail(pair.0)))
        [] -> Error(Nil)
      }
    })
  let timers =
    state.timers
    |> list.filter(fn(timer) { timer.deadline <= state.now })
    |> list.map(fn(timer) { #("2|" <> timer.key, FromTimer(timer.key)) })
  let sends =
    list.map(state.sends, fn(send) { #("3|" <> send.key, FromSend(send.key)) })
  let answers =
    dict.keys(state.answers)
    |> list.map(fn(id) { #("4|" <> pad(id), FromAnswer(id)) })

  #(list.append(mail, timers), list.append(sends, answers))
}

/// The earliest deadline on the wheel.
fn earliest(timers: List(Timer)) -> Option(Int) {
  list.fold(timers, None, fn(acc, timer) {
    case acc {
      None -> Some(timer.deadline)
      Some(best) -> Some(int.min(best, timer.deadline))
    }
  })
}

/// Releases one event.
fn release(state: State, chosen: Ready) -> State {
  let state =
    State(..state, step: state.step + 1, at_instant: state.at_instant + 1)

  // Runaway runs and livelocks stop here; otherwise the event happens.
  case state.step > max_steps, state.at_instant > max_steps_per_instant {
    True, _ -> abort(state, "the run released more than its step budget")
    _, True ->
      abort(
        state,
        "livelock: one virtual instant held more than "
          <> int.to_string(max_steps_per_instant)
          <> " events",
      )
    False, False -> release_one(state, chosen)
  }
}

/// Carries out one released event.
fn release_one(state: State, chosen: Ready) -> State {
  // Each kind of event has its own effect on the world.
  case chosen {
    FromMail(sender:) -> {
      let assert Ok([head, ..rest]) = dict.get(state.mail, sender)
        as "a ready parcel is at the head of its queue"
      let delivered = head.deliver()

      // The parcel leaves its sender's queue; an empty queue is dropped.
      let mail = case rest {
        [] -> dict.delete(state.mail, sender)
        _ -> dict.insert(state.mail, sender, rest)
      }

      // The trace marks a parcel whose target was gone when it was released.
      let mark = case delivered {
        True -> "m "
        False -> "m! "
      }

      trace(State(..state, mail:), mark <> head.key)
    }

    FromTimer(key:) -> fire(state, key)

    FromSend(key:) -> send(state, key)

    FromAnswer(id:) -> answer(state, id)
  }
}

/// Fires one timer.
fn fire(state: State, key: String) -> State {
  let #(found, rest) =
    list.partition(state.timers, fn(timer) { timer.key == key })
  let state = State(..state, timers: rest)

  // Keys are unique, so there is exactly one.
  case found {
    [timer, ..] -> {
      timer.wake()

      // A reader's deadline that fires also closes its connection.
      let closed = case timer.wire {
        Some(wire) -> set.insert(state.closed_wires, wire)
        None -> state.closed_wires
      }

      trace(State(..state, closed_wires: closed), "t " <> key)
    }

    [] -> state
  }
}

/// Releases one request to the mailbox, or drops it.
fn send(state: State, key: String) -> State {
  let #(found, rest) = list.partition(state.sends, fn(send) { send.key == key })
  let assert [parked, ..] = found as "a ready request is parked"
  let id = state.next_request
  let request = Request(node: parked.node, wire: parked.wire, read: parked.read)
  let state =
    State(
      ..state,
      sends: rest,
      next_request: id + 1,
      requests: dict.insert(state.requests, id, request),
    )
  let dropped =
    ffi_vm.table_take(state.world.faults, world.DropKey(parked.node))

  // A dropped request never arrives; an undecodable one is refused by the
  // binding; anything else runs in a process of its own at the mailbox.
  case dropped, parked.read {
    Ok(_), _ -> trace(state, "s drop " <> key)

    Error(Nil), net.Undecodable(refusal) ->
      trace(
        State(
          ..state,
          answers: dict.insert(state.answers, id, protocol.Refused(refusal)),
        ),
        "s refuse " <> key,
      )

    Error(Nil), net.Decoded(decoded) -> {
      let inbox = state.world.inbox
      let mailbox = state.mailbox.node
      let pid =
        process.spawn_unlinked(fn() {
          let response = mailbox_node.handle(mailbox, decoded)
          process.send(inbox, world.Answered(id:, response:))
        })
      let tag = "req" <> int.to_string(id)
      trace(
        State(..state, who: dict.insert(state.who, pid, tag), spawned: [
          pid,
          ..state.spawned
        ]),
        "s " <> tag <> " " <> key,
      )
    }
  }
}

/// Hands the mailbox's answer to the client, lost or lied about if a fault
/// is armed.
fn answer(state: State, id: Int) -> State {
  let assert Ok(response) = dict.get(state.answers, id)
    as "a ready answer is parked"
  let assert Ok(request) = dict.get(state.requests, id)
    as "its request was released"
  let state = State(..state, answers: dict.delete(state.answers, id))
  let faults = state.world.faults
  let label = "a" <> int.to_string(id) <> " " <> response_name(response)

  // A loss leaves the reader to its deadline; a lie hands it wrong bytes;
  // otherwise it gets the real answer.
  case
    ffi_vm.table_take(faults, world.LoseKey(request.node)),
    ffi_vm.table_take(faults, world.LieKey(request.node))
  {
    Ok(_), _ -> trace(state, label <> " lost")

    Error(Nil), Ok(world.LieArm(lie:)) -> {
      let #(at, rng) = rng.below(state.rng, 1_000_000)
      list.each(net.lie(response, lie, at), fn(piece) {
        process.send(request.wire, piece)
      })

      // A lie to an `Append` excuses the row it fails; nothing else is a row.
      let lied = case appended(request.read) {
        Ok(envelope) -> set.insert(state.lied, #(request.node, envelope))
        Error(Nil) -> state.lied
      }

      // Every envelope in a lied-about batch may have been dropped by its reader.
      let corrupted =
        list.fold(batch_envelopes(response), state.corrupted, set.insert)

      let state =
        answered_wire(State(..state, rng:, lied:, corrupted:), request.wire)
      trace(state, label <> " lie " <> string.inspect(lie))
    }

    Error(Nil), _ -> {
      process.send(request.wire, world.Data(net.frame(response)))
      trace(answered_wire(state, request.wire), label)
    }
  }
}

/// The envelope an `Append` request carries.
fn appended(read: net.Read) -> Result(BitArray, Nil) {
  case read {
    net.Decoded(protocol.Append(envelope:, ..)) -> Ok(id.to_bytes(envelope))

    net.Decoded(protocol.CreateQueue(..))
    | net.Decoded(protocol.Fetch(..))
    | net.Decoded(protocol.Ack(..))
    | net.Decoded(protocol.DeleteQueue(..))
    | net.Undecodable(_) -> Error(Nil)
  }
}

/// The envelope ids a fetch response hands its reader.
fn batch_envelopes(response: Response) -> List(BitArray) {
  case response {
    protocol.Batch(envelopes:) ->
      list.map(envelopes, fn(stored) { id.to_bytes(stored.envelope) })

    protocol.QueueCreated(..)
    | protocol.Appended(..)
    | protocol.Acked
    | protocol.QueueDeleted
    | protocol.Refused(..) -> []
  }
}

/// Closes a connection that has its answer, and takes its reader's
/// deadline off the wheel: the simulated network owns that timer, and a
/// reader that was answered never sees it fire, so leaving it armed would
/// only hand a stale `Expired` to whatever the reader's process does next.
fn answered_wire(state: State, wire: Subject(Wire)) -> State {
  State(
    ..state,
    closed_wires: set.insert(state.closed_wires, wire),
    timers: list.filter(state.timers, fn(timer) { timer.wire != Some(wire) }),
  )
}

/// A value-free name for a response, for the trace.
fn response_name(response: Response) -> String {
  case response {
    protocol.QueueCreated(..) -> "created"
    protocol.Appended(..) -> "appended"
    protocol.Batch(envelopes:) ->
      "batch " <> int.to_string(list.length(envelopes))
    protocol.Acked -> "acked"
    protocol.QueueDeleted -> "deleted"
    protocol.Refused(reason:) -> "refused " <> string.inspect(reason)
  }
}

/// Appends a line to the event trace. A loud run prints it, with the log
/// lines the daemons wrote since the last one; a quiet run collects the
/// log lines once, at the end, for the snapshot.
fn trace(state: State, line: String) -> State {
  let entry =
    int.to_string(state.step) <> "@" <> int.to_string(state.now) <> " " <> line

  // Only a loud run pays for reading the sink at every step.
  case state.options.verbose {
    Loud -> {
      let logs = ffi_vm.sink_lines(state.sink)
      io.println(entry)
      list.each(logs, fn(log) { io.println("    " <> string.trim_end(log)) })
      State(
        ..state,
        trace: [entry, ..state.trace],
        logs: list.append(logs, state.logs),
      )
    }

    Quiet -> State(..state, trace: [entry, ..state.trace])
  }
}

// ----------------------------------------------------------------- oracle

/// Reads every node's tables at this instant.
fn view(state: State) -> #(oracle.View, State) {
  let #(a, cache) =
    oracle.read_node("a", state.a.keeper, state.decoder, state.cache)
  let #(b, cache) = oracle.read_node("b", state.b.keeper, state.decoder, cache)
  let current =
    oracle.View(
      a:,
      b:,
      envelopes: tables.envelopes(state.mailbox.keeper),
      tombstones: tables.tombstones(state.mailbox.keeper),
    )

  #(current, State(..state, cache:))
}

/// What the runner did, as the oracle needs it.
fn facts(state: State) -> oracle.Facts {
  let entries = dict.to_list(state.ops)
  let retried_tags =
    list.flat_map(entries, fn(entry) {
      case entry.1.1 {
        Some(world.Sent(retried:, ..)) -> retried
        _ -> []
      }
    })
  let retried_accepts =
    list.fold(entries, dict.new(), fn(acc, entry) {
      let #(op, outcome) = entry.1

      // An accept that answered `Unavailable` may still have committed its relationship.
      let count = case op, outcome {
        seed.Accept(..), Some(world.Accepted(retried:)) -> retried
        seed.Accept(..), Some(world.Unavailable) -> ops.attempts
        _, _ -> 0
      }

      // Only an op on a daemon has a daemon to count against.
      case party_of(op) {
        Ok(party) ->
          dict.upsert(acc, seed.party_name(party), fn(found) {
            option.unwrap(found, 0) + count
          })
        Error(Nil) -> acc
      }
    })

  // An op with no outcome never returned; one with `Other` returned
  // something it should not have.
  let unfinished =
    list.filter_map(entries, fn(entry) {
      case entry.1.1 {
        None -> Ok(entry.0)
        Some(_) -> Error(Nil)
      }
    })
  let unexpected =
    list.filter_map(entries, fn(entry) {
      case entry.1.1 {
        Some(world.Other(text:)) -> Ok(#(entry.0, text))
        _ -> Error(Nil)
      }
    })

  oracle.Facts(
    lied_appends: state.lied,
    retried_tags: set.from_list(retried_tags),
    retried_accepts:,
    unfinished: list.sort(unfinished, int.compare),
    unexpected: list.sort(unexpected, fn(x, y) { int.compare(x.0, y.0) }),
    tombstoned: state.tombstoned,
    corrupted: state.corrupted,
  )
}

/// The daemon an op acts on, for the ops that act on one.
fn party_of(op: Op) -> Result(Party, Nil) {
  case op {
    seed.Send(party:, ..)
    | seed.Burst(party:, ..)
    | seed.Consume(party:)
    | seed.Invite(party:)
    | seed.Accept(party:, ..)
    | seed.Approve(party:)
    | seed.End(party:, ..)
    | seed.Raise(party:, ..)
    | seed.Exceed(party:, ..)
    | seed.ArmEngine(party:, ..)
    | seed.ArmLoss(party:, ..)
    | seed.ArmLie(party:, ..)
    | seed.Forge(party:, ..)
    | seed.Restart(party:) -> Ok(party)

    seed.Advance(..)
    | seed.ArmStore(..)
    | seed.ToggleMailbox
    | seed.SetSkew(..)
    | seed.Kill(..) -> Error(Nil)
  }
}

/// The safety checks, after a step that wrote something.
fn safety(state: State) -> State {
  let #(current, state) = view(state)
  let tombstoned =
    list.fold(current.tombstones, state.tombstoned, fn(acc, row) {
      set.insert(acc, #(row.queue, row.envelope))
    })
  let state = State(..state, tombstoned:)
  let #(violations, excuses) = oracle.safety(current, facts(state))

  record(state, violations, excuses)
}

/// Adds findings to the run, each once.
fn record(
  state: State,
  violations: List(oracle.Violation),
  excuses: List(oracle.Excuse),
) -> State {
  let new_violations =
    list.filter(violations, fn(found) {
      !list.contains(state.violations, found)
    })
  let new_excuses =
    list.filter(excuses, fn(found) { !list.contains(state.excuses, found) })

  State(
    ..state,
    violations: list.append(list.reverse(new_violations), state.violations),
    excuses: list.append(list.reverse(new_excuses), state.excuses),
  )
}

// ------------------------------------------------------------------- heal

/// Turns every fault off and lets time run until the liveness check
/// passes or the budget is spent. Nothing is restarted, reconnected or
/// reset: the world only stops misbehaving.
fn heal(state: State) -> State {
  let cells = state.world.cells
  ffi_vm.table_clear(state.world.faults)
  ffi_vm.cells_put(cells, world.mailbox_down_cell, 0)
  ffi_vm.cells_put(cells, world.skew_a_cell, 0)
  ffi_vm.cells_put(cells, world.skew_b_cell, 0)
  ffi_vm.cells_put(cells, world.skew_mailbox_cell, 0)

  let state = trace(State(..state, delay: Prompt), "heal")
  heal_rounds(state, state.now + heal_budget_ms)
}

/// One heal round at a time, checking liveness every thirty virtual
/// seconds.
fn heal_rounds(state: State, budget_end: Int) -> State {
  let state = pump(state, state.now + heal_round_ms)
  let check = state.now % 30_000 < heal_round_ms

  // The run stops healing once liveness holds or the budget is spent.
  case state.aborted, state.now >= budget_end {
    Some(_), _ -> state
    None, True -> state
    None, False ->
      case check {
        False -> heal_rounds(state, budget_end)
        True ->
          case live(state) {
            #(True, state) -> state
            #(False, state) -> heal_rounds(state, budget_end)
          }
      }
  }
}

/// Whether the liveness check passes now.
fn live(state: State) -> #(Bool, State) {
  let #(current, state) = view(state)
  let #(violations, _) = oracle.liveness(current, facts(state))
  #(violations == [], state)
}

/// The liveness check, and the trees still being alive.
fn final_checks(state: State) -> State {
  let state = settle(state)
  let #(current, state) = view(state)
  let #(violations, excuses) = oracle.liveness(current, facts(state))
  let trees =
    [
      #("a", api.supervisor(state.a.handle)),
      #("b", api.supervisor(state.b.handle)),
      #("m", state.mailbox.supervisor),
    ]
    |> list.filter_map(fn(pair) {
      case process.is_alive(pair.1) {
        True -> Error(Nil)
        False -> Ok(oracle.Violation("trees_alive", pair.0 <> " tree died"))
      }
    })

  record(state, list.append(violations, trees), excuses)
}

// --------------------------------------------------------------- snapshot

/// Everything a double run compares: the event trace, every op's outcome,
/// the daemons' log lines, and every table of every node.
fn snapshot(state: State) -> List(String) {
  let outcomes =
    dict.to_list(state.ops)
    |> list.sort(fn(x, y) { int.compare(x.0, y.0) })
    |> list.map(fn(entry) {
      "op " <> int.to_string(entry.0) <> " " <> string.inspect(entry.1.1)
    })
  let daemon_tables = [
    "relationships", "offers", "outbox", "processed", "deliveries",
    "sent_messages", "audit", "meta",
  ]
  let mailbox_tables = ["grants", "queues", "envelopes", "tombstones"]
  let dumps =
    list.flatten([
      list.flat_map(daemon_tables, fn(table) {
        tables.dump(state.a.keeper, table)
        |> list.map(fn(row) { "a." <> table <> " " <> row })
      }),
      list.flat_map(daemon_tables, fn(table) {
        tables.dump(state.b.keeper, table)
        |> list.map(fn(row) { "b." <> table <> " " <> row })
      }),
      list.flat_map(mailbox_tables, fn(table) {
        tables.dump(state.mailbox.keeper, table)
        |> list.map(fn(row) { "m." <> table <> " " <> row })
      }),
    ])

  let logs = list.append(ffi_vm.sink_lines(state.sink), state.logs)

  list.flatten([
    list.reverse(state.trace),
    outcomes,
    list.sort(logs, string.compare),
    dumps,
  ])
}

/// Stops every process the run started and releases its stores.
fn teardown(state: State) -> Nil {
  process.kill(api.supervisor(state.a.handle))
  process.kill(api.supervisor(state.b.handle))
  process.kill(state.mailbox.supervisor)
  list.each(state.spawned, process.kill)

  let _ = ffi_vm.quiesce(50_000_000, ffi_vm.Every)
  let _ = drain(state)
  let _ = sqlight.close(state.a.keeper)
  let _ = sqlight.close(state.b.keeper)
  let _ = sqlight.close(state.mailbox.keeper)
  let _ = mailbox_store.close(state.mailbox.holder)

  ffi_vm.table_delete(state.world.faults)
  ffi_vm.table_delete(state.handles)
  ffi_vm.uninstall_sink(state.sink)
  option.map(state.logger, ffi_vm.restore_logger)
  |> option.unwrap(Nil)
}
