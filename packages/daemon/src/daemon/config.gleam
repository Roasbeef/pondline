//// How a daemon is configured: where its state lives, which mailbox it uses
//// to create its own queues, which carriers it may use, and the injected
//// clock and cryptography.
////
//// Everything the daemon does not decide for itself arrives here, because
//// `core` is pure and the shell must be testable: the clock is a function
//// (a test passes a counter), the `Suite` is a record of primitives (the
//// production one comes from `primitives`; the fake provider lives under
//// `core`'s `test/` and can never be selected by a release, spec §13.3),
//// and the carrier policy is an explicit operator choice with no default
//// that widens it.
////
//// ## The mailbox
////
//// A daemon creates its own inbound queues at one mailbox, using a
//// provisioning capability the mailbox operator issued (spec §3.2). The
//// capability is read from a file at start rather than carried in the
//// configuration value, so a `Config` that is printed or logged names a
//// path and never the authority behind it. Peers' mailboxes need no
//// configuration: a route read from an invitation carries its own endpoint,
//// and the carrier policy decides whether the daemon will dial it.
////
//// ## Secrets at rest
////
//// Nothing in the state directory is encrypted in this version. The
//// directory is created `0700` and the database `0600`, and the daemon's
//// protection against a reader who can open those files is the operating
//// system's. That matches the design review's ruling that the state
//// directory lives outside the agent's sandbox; encryption at rest is still
//// open (`docs/design-intent.md` §17).
////
//// ## Simulation seams
////
//// The last seven fields exist so a deterministic simulation can run the
//// real tree: where timers are armed (`timer`), what `weft/poll` waits on
//// (`poll_clock`), how mailboxes are dialled (`dialer`), where the database
//// lives (`database`), fault hooks for the store and the engine
//// (`store_faults`, `engine_faults`), and a mail interceptor that orders
//// every cross-actor message (`interceptor`). `new` sets each to what
//// production does: the wall clock, the monotonic clock, the carrier's own
//// dialer, `daemon.db` in the state directory, no faults and direct sends.
//// No production code sets them to anything else; only a test does.

import core/crypto/suite.{type Suite}
import core/endpoint.{type CarrierPolicy, type Endpoint}
import core/time.{type Instant, Instant}
import daemon/engine.{type JobFate, type JobKind}
import daemon/internal/ffi_runtime_clock
import daemon/mail.{type Interceptor}
import daemon/store
import daemon/transport.{type Dialer}
import gleam/option.{type Option, None}
import primitives/suite as primitive_suite
import weft/poll
import weft/timer

/// The inbound messages a relationship granted by `accept` may deliver.
/// `invite` takes its budget as an argument; the joiner's side has no
/// argument for it in the contract, so it is a daemon-wide default until the
/// CLI grows one.
pub const default_accept_budget = 1000

/// The mailbox a daemon creates its own queues at.
pub type Mailbox {
  Mailbox(
    /// Where the mailbox is reached.
    endpoint: Endpoint,
    /// A file holding the 32-byte provisioning capability.
    provisioning_file: String,
  )
}

/// A daemon's whole configuration.
pub type Config {
  Config(
    /// The state directory: the database, the lock and Tor's own state.
    state_dir: String,
    /// The mailbox that hosts this daemon's queues.
    mailbox: Mailbox,
    /// Which carriers the daemon may dial.
    carrier: CarrierPolicy,
    /// The path of the `reedwire-tor` binary, or `None` for no Tor.
    tor: Option(String),
    /// The current time.
    clock: fn() -> Instant,
    /// The cryptographic primitives.
    suite: Suite,
    /// The inbound budget `accept` grants.
    accept_budget: Int,
    /// Where every weft actor, state machine and run of the tree arms its
    /// timers. Production: `timer.WallClock`.
    timer: timer.Source,
    /// The clock `weft/poll` waits on in `api.invite` and `node.stop`.
    /// Production: `poll.monotonic()`.
    poll_clock: poll.Clock,
    /// How the workers reach mailboxes, or `None` for the carrier's dialer
    /// under `carrier`.
    dialer: Option(Dialer),
    /// Where the database is opened, or `None` for `daemon.db` in the state
    /// directory. An override is opened as given (a simulation passes a
    /// shared-cache in-memory URI) and is not created `0600` by the daemon;
    /// the lock stays a file in the state directory either way.
    database: Option(String),
    /// A fault hook for the store's transactions, or `None`.
    store_faults: Option(store.Faults),
    /// A fault hook for the engine's jobs, or `None`.
    engine_faults: Option(fn(JobKind) -> JobFate),
    /// Where cross-actor messages are handed instead of sent, or `None` to
    /// send them directly.
    interceptor: Option(Interceptor),
  )
}

/// A production configuration: the wall clock, the real primitives, no Tor
/// sidecar, the default accept budget, and every simulation seam at its
/// production value. A caller sets `tor` for a Tor carrier.
///
/// ## Examples
///
/// ```gleam
/// config.new("/var/lib/reedwire", mailbox, endpoint.TorOnly)
/// // -> Config(..)
/// ```
pub fn new(
  state_dir: String,
  mailbox: Mailbox,
  carrier: CarrierPolicy,
) -> Config {
  Config(
    state_dir:,
    mailbox:,
    carrier:,
    tor: None,
    clock: system_clock(),
    suite: primitive_suite.suite(),
    accept_budget: default_accept_budget,
    timer: timer.WallClock,
    poll_clock: poll.monotonic(),
    dialer: None,
    database: None,
    store_faults: None,
    engine_faults: None,
    interceptor: None,
  )
}

/// The wall clock as an injectable function, in whole seconds.
///
/// ## Examples
///
/// ```gleam
/// let now = config.system_clock()
/// now().unix_seconds > 1_700_000_000
/// // -> True
/// ```
pub fn system_clock() -> fn() -> Instant {
  fn() { Instant(unix_seconds: ffi_runtime_clock.unix_seconds()) }
}
