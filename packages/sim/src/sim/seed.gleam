//// What a seed means: a mode, a fault mask and a script of operations.
////
//// A seed is a byte string, so a campaign can draw one at random, a failure
//// can be printed in hex, and a regression is one line in the corpus. The
//// layout follows the swarm-testing shape of the neutrino header-sync DST:
////
//// ```text
//// byte 0       mode        byte % 4 picks a production configuration;
////                          the upper nibble is reserved for later modes
//// bytes 1..2   fault mask  one bit per `FaultClass`, little-endian
//// bytes 3..    ops         two bytes each: op byte, argument byte
//// ```
////
//// A seed shorter than three bytes runs with every fault class on. Each
//// seed enables a random subset of fault classes, which finds bugs that
//// need several kinds of fault to stay away. An op whose class is masked
//// off performs an honest action instead (a send, or a short advance of
//// time), so every seed keeps making progress. At most `max_ops` ops are
//// decoded; the rest of a longer seed is ignored.
////
//// ## Flow
////
//// 1. `decode` splits the header from the ops.
//// 2. `decode_ops` reads two bytes at a time through `op_of`.
//// 3. `op_of` picks the op by `byte % op_count` and its arguments from the
////    second byte, or the honest stand-in when the class is masked.

import core/mailbox/protocol
import daemon/engine
import daemon/store
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string

/// The most ops one seed runs.
pub const max_ops = 48

/// How many distinct ops the op byte selects among.
pub const op_count = 20

/// One of the two daemons.
pub type Party {
  A
  B
}

/// A component a fault or a skew can be aimed at.
pub type Target {
  /// One daemon.
  Daemon(party: Party)

  /// The mailbox.
  Mailbox
}

/// A production configuration of the run: how invitations approve their
/// joiner and how large an inbound budget each relationship gets.
pub type Mode {
  Mode(
    /// Whether the inviter's operator must approve each joiner.
    approval: Approval,
    /// The inbound budget each invitation grants.
    budget: Int,
  )
}

/// Whether an invitation activates on a valid `Hello` or waits for
/// `approve`.
pub type Approval {
  Automatic
  ByOperator
}

/// The fault classes, one bit each in the mask.
pub type FaultClass {
  /// Ambiguous commits and failures on a daemon's store.
  StoreDaemon

  /// The same on the mailbox's store.
  StoreMailbox

  /// Engine jobs that fail before or after applying.
  Engine

  /// A request dropped, or a response lost after the mailbox applied it.
  NetLoss

  /// Network events held back while timers fire.
  NetDelay

  /// The mailbox refusing connections, and coming back.
  MailboxDown

  /// A mailbox whose responses lie: truncated, corrupt, refused.
  Byzantine

  /// Per-node clock skew.
  Skew

  /// An authenticated peer sending what an honest one would not.
  Peer

  /// Operator inputs at and past the limits.
  Limits

  /// A daemon stopped and started over the same stores.
  Restarts

  /// One process of a tree killed and restarted by its supervisor.
  Kills
}

/// Every fault class, in bit order.
pub fn classes() -> List(FaultClass) {
  [
    StoreDaemon,
    StoreMailbox,
    Engine,
    NetLoss,
    NetDelay,
    MailboxDown,
    Byzantine,
    Skew,
    Peer,
    Limits,
    Restarts,
    Kills,
  ]
}

/// A fault class's name as the swarm's `--without` flag spells it.
///
/// ## Examples
///
/// ```gleam
/// seed.class_name(seed.Skew)
/// // -> "skew"
/// ```
pub fn class_name(class: FaultClass) -> String {
  case class {
    StoreDaemon -> "store_daemon"
    StoreMailbox -> "store_mailbox"
    Engine -> "engine"
    NetLoss -> "net_loss"
    NetDelay -> "net_delay"
    MailboxDown -> "mailbox_down"
    Byzantine -> "byzantine"
    Skew -> "skew"
    Peer -> "peer"
    Limits -> "limits"
    Restarts -> "restarts"
    Kills -> "kills"
  }
}

/// The seed with the mask bits of `classes` cleared, so a campaign can
/// keep a class whose bug is already known out of its way. Ops of a
/// cleared class become honest ones, as for any masked class.
///
/// ## Examples
///
/// ```gleam
/// seed.mask_off(<<0, 255, 255>>, [seed.Skew])
/// // -> <<0, 127, 255>>
/// ```
pub fn mask_off(bytes: BitArray, cleared: List(FaultClass)) -> BitArray {
  let clear =
    classes()
    |> list.index_fold(0, fn(acc, class, bit) {
      case list.contains(cleared, class) {
        True -> int.bitwise_or(acc, int.bitwise_shift_left(1, bit))
        False -> acc
      }
    })

  // Only a seed with a full header has a mask to clear.
  case bytes {
    <<mode, low, high, rest:bytes>> -> {
      let mask = int.bitwise_and(low + high * 256, int.bitwise_not(clear))
      let low = mask % 256
      let high = mask / 256
      <<mode, low, high, rest:bits>>
    }
    _ -> bytes
  }
}

/// How an armed store fault fails a transaction.
pub type StoreFault {
  /// Before `BEGIN`: nothing written.
  StoreDown

  /// After `COMMIT`: written, and the caller told it failed.
  StoreAckLost
}

/// How a network fault loses an exchange.
pub type Loss {
  /// The request never reaches the mailbox.
  DropRequest

  /// The mailbox applies the request and the response never arrives.
  LoseResponse
}

/// How a byzantine mailbox lies in its next response to a daemon.
pub type Lie {
  /// The response is cut short and the connection closes.
  Truncate

  /// One byte of the body is flipped.
  Corrupt

  /// An HTTP status other than 200.
  BadStatus

  /// The real answer replaced with this refusal.
  Refuse(reason: protocol.Refusal)

  /// The real answer replaced with an answer to a different request.
  WrongKind
}

/// What an authenticated byzantine peer sends.
pub type Forgery {
  /// An application message reusing an id the peer already sent (H2).
  RepeatId

  /// An `Accept` while the relationship is already active.
  StrayAccept

  /// A `Reject` while the relationship is already active.
  StrayReject

  /// A ratchet frame that does not decrypt.
  Garbage
}

/// An operator input at or past one of the limits.
pub type Limit {
  /// An invitation whose description is exactly the limit.
  DescriptionAt

  /// An invitation whose description is one byte past the limit.
  DescriptionPast

  /// An acceptance whose description is one byte past the limit.
  AcceptDescriptionPast

  /// An invitation granting no budget.
  BudgetZero

  /// An invitation granting the largest budget allowed.
  BudgetMax

  /// An invitation granting one more than that.
  BudgetPast

  /// A message whose payload is exactly the limit.
  PayloadAt

  /// A message whose payload is one byte past it.
  PayloadPast

  /// A message whose content type is exactly the limit.
  ContentTypeAt

  /// A message whose content type is one byte past it.
  ContentTypePast

  /// A budget raised by more than the largest budget.
  RaiseHuge
}

/// Which process a kill op ends.
pub type Victim {
  /// A daemon's engine; the supervisor restarts it and every worker.
  KillEngine(party: Party)

  /// A daemon's scheduler.
  KillScheduler(party: Party)

  /// A daemon's provisioner.
  KillProvisioner(party: Party)

  /// A daemon's fetch manager, and with it its fetchers.
  KillFetchManager(party: Party)

  /// The mailbox's coordinator.
  KillCoordinator

  /// The mailbox's notifier, and with it every waiting long poll's wake-up.
  KillNotifier
}

/// How an operator ends a relationship.
pub type Ending {
  Close
  Decline
}

/// One step of the script.
pub type Op {
  /// The agent sends one message of `size` bytes to its `contact`th
  /// relationship.
  Send(party: Party, contact: Int, size: Int)

  /// The agent sends `count` messages at once.
  Burst(party: Party, contact: Int, count: Int)

  /// The agent reads its ready deliveries and acknowledges them.
  Consume(party: Party)

  /// The operator creates an invitation.
  Invite(party: Party)

  /// The operator accepts the other daemon's `pick`th open invitation.
  Accept(party: Party, pick: Int)

  /// The operator approves every pending relationship.
  Approve(party: Party)

  /// The operator closes or declines its `contact`th relationship.
  End(party: Party, contact: Int, how: Ending)

  /// The operator raises the `contact`th relationship's budget.
  Raise(party: Party, contact: Int, by: Int)

  /// Virtual time moves forward `ms`, firing every timer due on the way.
  Advance(ms: Int)

  /// The `skip`th next transaction on `target`'s store fails.
  ArmStore(target: Target, fault: StoreFault, skip: Int)

  /// The next engine job of `kind` on `party` meets `fate`.
  ArmEngine(party: Party, kind: engine.JobKind, fate: engine.JobFate)

  /// The next exchange `party` starts is lost.
  ArmLoss(party: Party, loss: Loss)

  /// The mailbox goes down, or comes back.
  ToggleMailbox

  /// The mailbox's next response to `party` lies.
  ArmLie(party: Party, lie: Lie)

  /// `target`'s clock moves to `seconds` off the true time.
  SetSkew(target: Target, seconds: Int)

  /// `party` acts as a byzantine peer on its first active relationship.
  Forge(party: Party, forgery: Forgery)

  /// `party`'s operator gives an input at or past a limit.
  Exceed(party: Party, limit: Limit)

  /// `party` stops and starts again over the same stores.
  Restart(party: Party)

  /// One process is killed and its supervisor restarts it.
  Kill(victim: Victim)
}

/// A decoded seed.
pub type Script {
  Script(
    /// The production configuration.
    mode: Mode,
    /// The fault classes this seed enables.
    enabled: List(FaultClass),
    /// The operations, in order.
    ops: List(Op),
  )
}

/// Decodes a seed. Total: every byte string is a script.
///
/// ## Examples
///
/// ```gleam
/// seed.decode(<<0, 255, 255, 0, 1>>).mode
/// // -> Mode(approval: Automatic, budget: 100)
/// ```
pub fn decode(bytes: BitArray) -> Script {
  // The header is three bytes; a shorter seed enables every class.
  case bytes {
    <<mode, low, high, ops:bytes>> -> {
      let mask = low + high * 256
      let enabled =
        classes()
        |> list.index_map(fn(class, bit) { #(class, bit) })
        |> list.filter(fn(pair) {
          int.bitwise_and(mask, int.bitwise_shift_left(1, pair.1)) != 0
        })
        |> list.map(fn(pair) { pair.0 })

      Script(
        mode: mode_of(mode),
        enabled:,
        ops: decode_ops(ops, enabled, max_ops, []),
      )
    }

    <<mode, _:bytes>> ->
      Script(mode: mode_of(mode), enabled: classes(), ops: [])

    _ -> Script(mode: mode_of(0), enabled: classes(), ops: [])
  }
}

/// The configuration selected by the low two bits of the mode byte.
fn mode_of(byte: Int) -> Mode {
  // The upper bits are reserved so a later mode can keep old seeds stable.
  case byte % 4 {
    0 -> Mode(approval: Automatic, budget: 100)
    1 -> Mode(approval: ByOperator, budget: 100)
    2 -> Mode(approval: Automatic, budget: 2)
    _ -> Mode(approval: ByOperator, budget: 2)
  }
}

/// Reads ops two bytes at a time, up to `max_ops`.
fn decode_ops(
  bytes: BitArray,
  enabled: List(FaultClass),
  left: Int,
  acc: List(Op),
) -> List(Op) {
  // A trailing odd byte is ignored, like everything past `max_ops`.
  case bytes, left {
    _, 0 -> list.reverse(acc)
    <<op, arg, rest:bytes>>, _ ->
      decode_ops(rest, enabled, left - 1, [op_of(op, arg, enabled), ..acc])
    _, _ -> list.reverse(acc)
  }
}

/// The op an op byte and its argument byte stand for.
fn op_of(op: Int, arg: Int, enabled: List(FaultClass)) -> Op {
  let party = party_of(arg)
  let contact = arg / 2 % 4
  let gated = fn(class, faulty) {
    case list.contains(enabled, class) {
      True -> faulty()
      False -> honest(arg)
    }
  }

  // The op byte picks the kind; the argument byte its details.
  case op % op_count {
    0 -> Send(party:, contact:, size: arg / 8 % 4)
    1 -> Burst(party:, contact:, count: 2 + arg / 8 % 7)
    2 -> Consume(party:)
    3 -> Invite(party:)
    4 -> Accept(party:, pick: arg / 2 % 3)
    5 -> Approve(party:)
    6 -> ending(arg, party, contact)
    7 -> Raise(party:, contact:, by: 1 + arg / 8 % 8)
    8 | 9 -> Advance(ms: advance_ms(arg))
    10 -> gated(store_class(arg), fn() { arm_store(arg) })
    11 -> gated(Engine, fn() { arm_engine(arg) })
    12 -> gated(NetLoss, fn() { arm_loss(arg) })
    13 -> gated(MailboxDown, fn() { ToggleMailbox })
    14 -> gated(Byzantine, fn() { ArmLie(party:, lie: lie_of(arg / 2)) })
    15 -> gated(Skew, fn() { skew_of(arg) })
    16 -> gated(Peer, fn() { Forge(party:, forgery: forgery_of(arg / 2)) })
    17 -> gated(Limits, fn() { Exceed(party:, limit: limit_of(arg / 2)) })
    18 -> gated(Restarts, fn() { Restart(party:) })
    _ -> gated(Kills, fn() { Kill(victim: victim_of(arg)) })
  }
}

/// The honest stand-in for an op whose class is masked off.
fn honest(arg: Int) -> Op {
  // Half send, half let time pass, so a masked seed still makes progress.
  case arg % 2 {
    0 -> Send(party: party_of(arg / 2), contact: arg / 4 % 4, size: 0)
    _ -> Advance(ms: advance_ms(arg))
  }
}

/// The daemon an argument byte names.
fn party_of(arg: Int) -> Party {
  // The low bit picks the daemon.
  case arg % 2 {
    0 -> A
    _ -> B
  }
}

/// A close or a decline, rarely: three arguments in four send instead, so
/// a script does not end most of its relationships.
fn ending(arg: Int, party: Party, contact: Int) -> Op {
  // Only two of the eight argument residues end anything.
  case arg / 8 % 8 {
    0 -> End(party:, contact:, how: Close)
    1 -> End(party:, contact:, how: Decline)
    _ -> Send(party:, contact:, size: 0)
  }
}

/// How far an advance moves time: mostly short, sometimes past a long poll
/// or a backoff.
fn advance_ms(arg: Int) -> Int {
  // The top two bits choose the scale.
  case arg / 64 {
    0 -> 50 + arg % 64 * 10
    1 -> 1000 + arg % 64 * 100
    2 -> 5000 + arg % 64 * 500
    _ -> 30_000 + arg % 64 * 2000
  }
}

/// Which store class a store-fault argument aims at.
fn store_class(arg: Int) -> FaultClass {
  // One argument in three aims at the mailbox.
  case arg % 3 {
    2 -> StoreMailbox
    _ -> StoreDaemon
  }
}

/// A store fault from its argument byte.
fn arm_store(arg: Int) -> Op {
  // One argument in three aims at the mailbox's store.
  let target = case arg % 3 {
    0 -> Daemon(A)
    1 -> Daemon(B)
    _ -> Mailbox
  }

  // The next bit chooses an ambiguous commit or an outright failure.
  let fault = case arg / 3 % 2 {
    0 -> StoreAckLost
    _ -> StoreDown
  }

  ArmStore(target:, fault:, skip: arg / 6 % 4)
}

/// An engine fault from its argument byte.
fn arm_engine(arg: Int) -> Op {
  let kinds = job_kinds()
  let kind =
    list.drop(kinds, arg / 4 % list.length(kinds))
    |> list.first
    |> unwrap_kind

  // The second bit chooses whether the job runs before it fails.
  let fate = case arg / 2 % 2 {
    0 -> engine.ApplyThenFail
    _ -> engine.FailBeforeApply
  }

  ArmEngine(party: party_of(arg), kind:, fate:)
}

/// The kind a non-empty drop found; the list is never shorter than the
/// index taken modulo its length.
fn unwrap_kind(found: Result(engine.JobKind, Nil)) -> engine.JobKind {
  // The modulo keeps the index in range, so `Error` cannot happen.
  case found {
    Ok(kind) -> kind
    Error(Nil) -> engine.Send
  }
}

/// Every engine job kind, in declaration order.
pub fn job_kinds() -> List(engine.JobKind) {
  [
    engine.Invite,
    engine.InvitationFile,
    engine.Accept,
    engine.Provisioned,
    engine.Approve,
    engine.Decline,
    engine.Close,
    engine.RaiseBudget,
    engine.Send,
    engine.Consume,
    engine.ExpireOffers,
    engine.Process,
    engine.Contacts,
    engine.Deliveries,
    engine.MessageState,
    engine.Audit,
    engine.LiveInboxes,
    engine.PendingInboxes,
    engine.DueOutbox,
    engine.RecordSend,
    engine.Unacked,
    engine.MarkAcked,
    engine.OutboxPending,
  ]
}

/// A network loss from its argument byte.
fn arm_loss(arg: Int) -> Op {
  // The second bit picks which half of the exchange is lost.
  case arg / 2 % 2 {
    0 -> ArmLoss(party: party_of(arg), loss: DropRequest)
    _ -> ArmLoss(party: party_of(arg), loss: LoseResponse)
  }
}

/// A byzantine response from an index.
fn lie_of(index: Int) -> Lie {
  // Twelve lies: three framing faults, eight refusals, one wrong answer.
  case index % 12 {
    0 -> Truncate
    1 -> Corrupt
    2 -> BadStatus
    3 -> Refuse(protocol.Unauthorized)
    4 -> Refuse(protocol.Conflict)
    5 -> Refuse(protocol.QuotaExceeded)
    6 -> Refuse(protocol.TooLarge)
    7 -> Refuse(protocol.BadDeadline)
    8 -> Refuse(protocol.Malformed)
    9 -> Refuse(protocol.UnsupportedVersion)
    10 -> Refuse(protocol.Unavailable)
    _ -> WrongKind
  }
}

/// A clock skew from its argument byte: a daemon or the mailbox, ahead or
/// behind, by one second to ten minutes.
fn skew_of(arg: Int) -> Op {
  // A third of the arguments skew the mailbox, the rest a daemon.
  let target = case arg % 3 {
    0 -> Daemon(A)
    1 -> Daemon(B)
    _ -> Mailbox
  }

  // Four scales, from a second to ten minutes.
  let magnitude = case arg / 3 % 4 {
    0 -> 1
    1 -> 5
    2 -> 60
    _ -> 600
  }

  // Ahead or behind the true time.
  let sign = case arg / 12 % 2 {
    0 -> 1
    _ -> -1
  }

  SetSkew(target:, seconds: sign * magnitude)
}

/// A byzantine peer's message from an index.
fn forgery_of(index: Int) -> Forgery {
  // Four forgeries, evenly.
  case index % 4 {
    0 -> RepeatId
    1 -> StrayAccept
    2 -> StrayReject
    _ -> Garbage
  }
}

/// An input at or past a limit, from an index.
fn limit_of(index: Int) -> Limit {
  // Eleven limits, evenly.
  case index % 11 {
    0 -> DescriptionAt
    1 -> DescriptionPast
    2 -> AcceptDescriptionPast
    3 -> BudgetZero
    4 -> BudgetMax
    5 -> BudgetPast
    6 -> PayloadAt
    7 -> PayloadPast
    8 -> ContentTypeAt
    9 -> ContentTypePast
    _ -> RaiseHuge
  }
}

/// A kill target from its argument byte.
fn victim_of(arg: Int) -> Victim {
  let party = party_of(arg)

  // Six victims; the four daemon ones take the daemon from the low bit.
  case arg / 2 % 6 {
    0 -> KillEngine(party:)
    1 -> KillScheduler(party:)
    2 -> KillProvisioner(party:)
    3 -> KillFetchManager(party:)
    4 -> KillCoordinator
    _ -> KillNotifier
  }
}

/// The seed as lowercase hex, the form a failure is printed in.
///
/// ## Examples
///
/// ```gleam
/// seed.to_hex(<<1, 171>>)
/// // -> "01ab"
/// ```
pub fn to_hex(bytes: BitArray) -> String {
  bit_array.base16_encode(bytes) |> string.lowercase
}

/// A seed from hex, upper or lower case.
///
/// ## Examples
///
/// ```gleam
/// seed.from_hex("01ab")
/// // -> Ok(<<1, 171>>)
/// ```
pub fn from_hex(text: String) -> Result(BitArray, Nil) {
  bit_array.base16_decode(string.uppercase(text))
}

/// A short name for a party, used in labels and traces.
///
/// ## Examples
///
/// ```gleam
/// seed.party_name(seed.A)
/// // -> "a"
/// ```
pub fn party_name(party: Party) -> String {
  case party {
    A -> "a"
    B -> "b"
  }
}

/// The other daemon.
///
/// ## Examples
///
/// ```gleam
/// seed.other(seed.A)
/// // -> seed.B
/// ```
pub fn other(party: Party) -> Party {
  case party {
    A -> B
    B -> A
  }
}

/// The store fault as the daemon's and the mailbox's stores spell it.
///
/// ## Examples
///
/// ```gleam
/// seed.daemon_fate(seed.StoreAckLost)
/// // -> store.AckLost
/// ```
pub fn daemon_fate(fault: StoreFault) -> store.Fate {
  case fault {
    StoreDown -> store.Down
    StoreAckLost -> store.AckLost
  }
}
