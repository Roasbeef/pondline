//// The in-process API of a running daemon: what the local socket server and
//// the tests call, and the contract they code against (spec §9).
////
//// This module owns no process. A `Daemon` is a set of names (the engine,
//// the event registry, the status cell) and each function is a typed call to
//// one of them, so a handle is cheap to copy and stays valid across the
//// restart of any process it names. Every function answers with a typed
//// `ApiError` and never a crash: an engine that is restarting is
//// `Unavailable`, and the caller retries.
////
//// ## What the API promises
////
//// A command that returns `Ok` has committed. `send` returns once the
//// ciphertext and the advanced session are durable, not once anything has
//// reached a mailbox; `status` is how the caller learns how far the message
//// got (spec §7.2). `receive` returns only `Ready` deliveries that were not
//// consumed, oldest first, and a delivery stays visible until `acknowledge`
//// marks it consumed, so an adapter that crashes before acknowledging sees it
//// again (spec §8.5). Nothing here gives the agent execution or
//// administration authority: delivery and command permissions are separate,
//// and the socket layer decides which caller may use which function.
////
//// `invite` is the one call that waits. An invitation cannot be handed out
//// until the mailbox has created its queue, since a joiner could append to a
//// queue that does not exist, so `invite` commits the offer and then polls
//// the committed offer with `weft/poll` until it opens, for at most
//// `invite_wait_ms`.
////
//// ## Tickets
////
//// `invite_ticket` and `accept_ticket` are the short-string form of the same
//// pair (ADR-009). They are the only calls here that reach a mailbox
//// themselves, in the caller's process: the inviter stores the sealed
//// invitation at its own mailbox before the ticket is returned, so a ticket
//// that exists always names a stored blob, and the joiner fetches and opens
//// it before anything is committed. Each mailbox call is retried with
//// `weft/poll` for at most `ticket_wait_ms`, because a first onion
//// connection can fail while circuits build. Neither writes durable state of
//// its own; a ticket whose store failed leaves an offer that was never
//// handed out, as a timed-out `invite` does, and the operator asks again.
////
//// ## Spoken codes
////
//// `invite_code`, `await_code` and `accept_code` are ADR-016's pairing by a
//// code read aloud, and their run delivers a ticket. The inviter checks its
//// count of failed confirmations, does everything `invite_ticket` does, so
//// the ticket's blob is stored before any rendezvous message can be read,
//// opens a slot at its own mailbox, and hands the run to the pairing
//// registry (`daemon/pairing`), which owns it past the call and closes its
//// slot however it ends; `await_code` waits for it. The joiner decodes the
//// code strictly, admits the rendezvous under the carrier policy, checks
//// the count, claims, runs its half in the caller's process, and redeems
//// the delivered ticket through `accept_ticket_with_budget`, unchanged. The
//// only durable trace of a run is a failed confirmation, counted per
//// rendezvous endpoint by the engine; the code, its words and the run's
//// messages never reach the store or a log.
////
//// ## Flow
////
//// 1. `assemble` builds the handle, for `daemon/node` alone.
//// 2. Pairing: `invite` (and `await_file`), `accept`; by ticket,
////    `invite_ticket` (`offer_inbox`, `store_blob`) and `accept_ticket`
////    (`fetch_blob`), both through `ticket_call`; by spoken code,
////    `invite_code` (`check_failures`, `open_slot`), `await_code` and
////    `accept_code` (`claim_slot`), both through `rendezvous_call`.
//// 3. Relationships: `contacts`, `approve`, `decline`, `close`,
////    `raise_budget`.
//// 4. Messages: `send` and `send_with_key`, `receive`, `acknowledge`,
////    `status`; the operator's trail: `audit` and `incidents`.
//// 5. `subscribe` and `health` for adapters and monitoring.
////
//// ## Why the types are repeated
////
//// The engine and the store define their own record types and this module
//// defines the contract's, converting between them. The contract's types
//// have to live here so the socket layer can build and match their
//// constructors, and the engine cannot import this module without a cycle
//// (this module calls the engine), so the conversion is the price of the
//// layering.

import core/capability.{type Capability, type Provision}
import core/crypto/identity
import core/crypto/suite.{type Suite}
import core/endpoint.{type CarrierPolicy, type Endpoint}
import core/field
import core/id.{
  type Contact, type Id, type Invitation as InvitationKind,
  type Message as MessageKind, type Queue, type Rendezvous as RendezvousKind,
}
import core/invitation
import core/limits
import core/mailbox/protocol
import core/nameplate.{type Nameplate}
import core/offer.{type Approval}
import core/pairing_code.{type PairingCode}
import core/relationship
import core/rendezvous
import core/route.{type Inbox}
import core/secret.{type Secret}
import core/ticket
import core/time.{type Instant}
import daemon/engine
import daemon/events
import daemon/mail.{type Handle}
import daemon/mailbox_client
import daemon/pairing
import daemon/status
import daemon/store
import daemon/transport.{type Dialer}
import gleam/bit_array
import gleam/bool
import gleam/erlang/process.{type Pid, type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import weft/poll

/// How long `invite` and onion `accept_ticket` wait for a `TorStarting`
/// carrier to reach `TorBootstrapped` before starting their mailbox wait,
/// matching `carrier.bootstrap_timeout_ms` (180 s).
pub const bootstrap_wait_ms = 180_000

/// How long `invite` waits for the mailbox to create the offer's queue,
/// matching `provisioner.create_timeout_ms` so a cold onion rendezvous does
/// not time out in the caller while `CreateQueue` is still connecting.
pub const invite_wait_ms = 120_000

/// How often `invite` looks at the committed offer while it waits.
pub const invite_poll_ms = 50

/// How long `invite_ticket` keeps trying to store the sealed invitation,
/// and `accept_ticket` to fetch it (ADR-009): room for two full cold onion
/// rendezvous attempts.
pub const ticket_wait_ms = 240_000

/// The budget of one mailbox call made for a ticket, dial included. A cold
/// v3 onion connection fetches a descriptor and builds a 6-hop rendezvous
/// circuit, matching `provisioner.create_timeout_ms` (120 s).
pub const ticket_call_ms = 120_000

/// How long a ticket's mailbox call waits before it is tried again.
pub const ticket_retry_ms = 1000

/// How long `await_code` waits for an inviter's run: the longest a slot
/// lives, the registry's own slack past it, and a margin for the answer.
pub const code_wait_ms = 700_000

/// A running daemon, as its callers hold it. Built only by `node`.
pub opaque type Daemon {
  Daemon(
    engine: Handle(engine.Message),
    events: Handle(events.Message(Event)),
    status: Handle(status.Message),
    suite: Suite,
    carrier: CarrierPolicy,
    supervisor: Pid,
    state_dir: String,
    poll_clock: poll.Clock,
    dialer: Dialer,
    pairing: Handle(pairing.Message),
    rendezvous: Rendezvous,
  )
}

/// What the spoken-code calls need beyond the ticket's (ADR-016): the
/// daemon's own mailbox, which is the inviter's rendezvous and the joiner's
/// default one, the provisioning capability an `OpenRendezvous` is charged
/// to, and the wall clock a slot's expiry is read against.
pub type Rendezvous {
  Rendezvous(
    /// The mailbox this daemon creates its queues at.
    mailbox: Endpoint,
    /// The capability the mailbox operator issued for it.
    provision: Capability(Provision),
    /// The daemon's wall clock, the engine's.
    clock: fn() -> Instant,
  )
}

/// What `invite_code` hands back: the run to wait for, the code to read to
/// the joiner's operator, and when the slot expires by the mailbox's clock.
/// The code is a `Secret`: its words are the run's password.
pub type CodeInvite {
  CodeInvite(
    /// The run, named by its rendezvous slot, for `await_code`.
    run: Id(RendezvousKind),
    /// The code's text, `NNNNNN-word-word-word`.
    code: Secret,
    /// When the slot expires, by the mailbox's clock.
    expires_at: Instant,
  )
}

/// How a pairing by spoken code ended (ADR-016). Only `ConfirmationFailed`
/// may be a spent guess at the words, and only it is counted.
pub type PairingOutcome {
  /// The hand-off completed. For the inviter `m4` was stored for the joiner
  /// and `contact` is `None`, since the joiner's `Hello` arrives later; for
  /// the joiner the ticket was redeemed and `contact` is the relationship.
  Paired(contact: Option(Id(Contact)))

  /// The inviter's slot expired or was closed with no joiner's first
  /// message. Never the joiner's.
  NeverClaimed

  /// The peer stopped, or the slot ended or was interfered with, before any
  /// confirmation verdict. Not counted.
  Stalled

  /// The confirmation failed, or for the joiner its confirmation was sent
  /// and no hand-off came: the code did not match, or the exchange was
  /// interrupted. Counted against the rendezvous endpoint.
  ConfirmationFailed
}

/// What `invite_ticket` hands back: the invitation file, for an operator
/// who also wants it, and the ticket's text, a `Secret` because it is the
/// authority to fetch and open the invitation.
pub type IssuedTicket {
  IssuedTicket(file: Secret, ticket: Secret)
}

/// Why a call did not do what was asked.
pub type ApiError {
  /// There is no such contact, message or invitation.
  NotFound

  /// The invitation file is malformed or expired.
  InvalidInvitation(reason: String)

  /// The operation is not valid now. The reason is a fixed phrase.
  Refused(reason: String)

  /// The daemon could not serve the call; nothing changed. Retry.
  Unavailable
}

/// Where a relationship stands, for display.
pub type PhaseName {
  Joining
  AwaitingAccept
  PendingApproval
  Active
  Closed
}

/// One relationship as an operator or agent sees it.
pub type ContactView {
  ContactView(
    /// The local handle.
    contact: Id(Contact),
    /// Where the pairing stands.
    phase: PhaseName,
    /// The operator's label, unverified.
    description: String,
    /// The peer's identity fingerprint in hex, once there is a session, for
    /// out-of-band comparison.
    peer_fingerprint: Option(String),
    /// The inbound messages the pairing may deliver in total.
    budget_granted: Int,
    /// How many it has delivered.
    budget_used: Int,
    /// How many are stored over budget, waiting for `raise_budget`.
    held: Int,
  )
}

/// A message stored for the agent.
pub type Delivery {
  Delivery(
    /// The sender's identifier for it.
    message: Id(MessageKind),
    /// The relationship it arrived on.
    contact: Id(Contact),
    /// The sender's content type.
    content_type: String,
    /// The plaintext, printed as a closure by `string.inspect`.
    payload: Secret,
    /// The message it answers, if any.
    in_reply_to: Option(Id(MessageKind)),
    /// When the daemon processed it.
    received_at: Instant,
  )
}

/// How far an outbound message got (spec §7.2).
pub type MessageState {
  LocallyQueued
  StoredByMailbox
  ReceivedByPeer
  Failed
}

/// Which way an audited message went.
pub type Direction {
  Inbound
  Outbound
}

/// One plaintext audit entry.
pub type AuditEntry {
  AuditEntry(
    contact: Id(Contact),
    direction: Direction,
    message: Id(MessageKind),
    content_type: String,
    payload: Secret,
    at: Instant,
  )
}

/// Why the daemon set an inbound envelope aside (ADR-010).
pub type IncidentKind {
  /// An authenticated peer reused a message identifier; the message was
  /// ignored.
  RepeatedMessageId

  /// An envelope failed to process `limits.max_process_attempts` times and
  /// was dropped and acknowledged; its sender's retransmit may still
  /// deliver it.
  QuarantinedEnvelope
}

/// One envelope the daemon set aside without delivering it, as the operator
/// reads it. It names identifiers and a count, never a payload.
pub type Incident {
  Incident(
    /// What happened.
    kind: IncidentKind,
    /// The relationship whose queue it arrived on, when one owns it.
    contact: Option(Id(Contact)),
    /// The repeated message identifier, for a `RepeatedMessageId`.
    message: Option(Id(MessageKind)),
    /// How many times the envelope was handed to the core, when counted.
    attempts: Option(Int),
    /// When it was recorded.
    at: Instant,
  )
}

/// What subscribers hear. Neither carries data: the subscriber reads the
/// committed store through this API.
pub type Event {
  /// A contact has deliveries the agent may now consume.
  MessagesReady(contact: Id(Contact))

  /// A relationship changed state.
  ContactChanged(contact: Id(Contact))
}

/// The daemon's own account of itself (spec §12.4).
pub type Health {
  Health(
    /// Which carriers it may dial.
    carrier: CarrierPolicy,
    /// The Tor client.
    tor: status.TorStatus,
    /// Whether the last mailbox call got through.
    mailbox: status.MailboxStatus,
    /// Outbox rows still waiting for a mailbox.
    outbox_pending: Int,
    /// Incidents ever recorded (ADR-010); `incidents` lists them.
    incidents: Int,
  )
}

/// Assembles the handle `node.start` returns. Not for other callers: the
/// handles must belong to a running tree. `poll_clock` is what `invite` and
/// `node.stop` wait on; `dialer` is what the ticket calls reach a mailbox
/// through, the same one the tree's workers use. `pairing` is the registry
/// that owns an inviter's spoken-code run, and `rendezvous` what those runs
/// need of the daemon's own configuration.
///
/// ## Examples
///
/// ```gleam
/// api.assemble(engine, events, status, suite, policy, pid, dir, clock,
///   dialer, pairing, rendezvous)
/// ```
pub fn assemble(
  engine: Handle(engine.Message),
  events: Handle(events.Message(Event)),
  status: Handle(status.Message),
  suite: Suite,
  carrier: CarrierPolicy,
  supervisor: Pid,
  state_dir: String,
  poll_clock: poll.Clock,
  dialer: Dialer,
  pairing: Handle(pairing.Message),
  rendezvous: Rendezvous,
) -> Daemon {
  Daemon(
    engine:,
    events:,
    status:,
    suite:,
    carrier:,
    supervisor:,
    state_dir:,
    poll_clock:,
    dialer:,
    pairing:,
    rendezvous:,
  )
}

/// The clock the daemon's waits poll on, for `node.stop`.
///
/// ## Examples
///
/// ```gleam
/// api.poll_clock(daemon)
/// // -> poll.monotonic() in production
/// ```
pub fn poll_clock(daemon: Daemon) -> poll.Clock {
  daemon.poll_clock
}

/// The supervisor process of the tree behind a handle, for `node.stop`.
///
/// ## Examples
///
/// ```gleam
/// api.supervisor(daemon)
/// ```
pub fn supervisor(daemon: Daemon) -> Pid {
  daemon.supervisor
}

/// The state directory behind a handle, for `node.stop`.
///
/// ## Examples
///
/// ```gleam
/// api.state_dir(daemon)
/// // -> "/var/lib/pondline"
/// ```
pub fn state_dir(daemon: Daemon) -> String {
  daemon.state_dir
}

/// The engine's handle, for tests that drive the writer directly.
///
/// ## Examples
///
/// ```gleam
/// engine.live_inboxes(api.engine_handle(daemon))
/// ```
pub fn engine_handle(daemon: Daemon) -> Handle(engine.Message) {
  daemon.engine
}

/// The status cell's handle, for tests that simulate Tor bootstrap transitions.
///
/// ## Examples
///
/// ```gleam
/// status.read(api.status_handle(daemon))
/// ```
pub fn status_handle(daemon: Daemon) -> Handle(status.Message) {
  daemon.status
}

/// Creates an invitation and returns its file bytes once the mailbox has
/// created the queue. The file is a bearer credential: it carries the append
/// capability of the inviter's queue.
///
/// `approval` says whether a valid `Hello` activates the relationship at once
/// or waits for `approve`; `budget` is the inbound messages the new
/// relationship may deliver.
///
/// ## Examples
///
/// ```gleam
/// api.invite(daemon, "vendor support", offer.OperatorApproves, 10)
/// // -> Ok(<<...>>)
/// ```
pub fn invite(
  daemon: Daemon,
  description: String,
  approval: Approval,
  budget: Int,
) -> Result(BitArray, ApiError) {
  use Nil <- result.try(await_tor_for_policy(daemon))
  use invitation <- result.try(
    engine.invite(daemon.engine, description, approval, budget)
    |> result.map_error(from_failure),
  )

  await_file(daemon, invitation)
}

/// Waits for Tor bootstrap when the daemon's carrier policy requires Tor, so
/// an `invite` called immediately after `pondline daemon` starts neither
/// fails early nor burns `invite_wait_ms` while Arti is still bootstrapping.
fn await_tor_for_policy(daemon: Daemon) -> Result(Nil, ApiError) {
  case daemon.carrier {
    endpoint.TorOnly -> await_tor_if_starting(daemon)
    endpoint.TorOrLoopback -> Ok(Nil)
  }
}

/// Waits for Tor bootstrap when a ticket names an `.onion` mailbox.
fn await_tor_for_endpoint(
  daemon: Daemon,
  mailbox: Endpoint,
) -> Result(Nil, ApiError) {
  case mailbox {
    endpoint.Onion(..) -> await_tor_if_starting(daemon)
    endpoint.Loopback(..) -> Ok(Nil)
  }
}

/// Polls the status cell while Tor is `TorStarting` up to `bootstrap_wait_ms`.
/// `TorBootstrapped` and `TorNotUsed` return immediately on the first read;
/// `TorUnavailable` fails fast as `Unavailable`.
fn await_tor_if_starting(daemon: Daemon) -> Result(Nil, ApiError) {
  let waited =
    poll.until_on(
      clock: daemon.poll_clock,
      within: bootstrap_wait_ms,
      every: poll.Fixed(invite_poll_ms),
      attempt: fn() {
        case status.read(daemon.status).tor {
          status.TorBootstrapped | status.TorNotUsed -> poll.Done(Nil)
          status.TorStarting -> poll.Retry
          status.TorUnavailable -> poll.Fail(Unavailable)
        }
      },
    )

  // A spent or failed bootstrap wait leaves nothing committed.
  case waited {
    poll.Answered(Nil) -> Ok(Nil)
    poll.Failed(error) -> Error(error)
    poll.Expired -> Error(Unavailable)
  }
}

/// Polls the committed offer until its queue exists or the wait runs out.
///
/// The wait is a poll and not an event because the thing awaited is a durable
/// row landing, written by the provisioner after a network call, and the
/// caller is a foreground request that has nothing else to do. The engine
/// does not announce the transition to a waiter, and a subscription would
/// need a registry slot per invitation to save a probe every
/// `invite_poll_ms`. `weft/poll` is the loop with its three corners decided:
/// the first read is immediate, a last read is made at the deadline, and a
/// read that fails for good (the offer expired, the engine is restarting)
/// ends the wait with that failure instead of burning the budget.
fn await_file(
  daemon: Daemon,
  invitation: Id(InvitationKind),
) -> Result(BitArray, ApiError) {
  let waited =
    poll.until_on(
      clock: daemon.poll_clock,
      within: invite_wait_ms,
      every: poll.Fixed(invite_poll_ms),
      attempt: fn() {
        case engine.invitation_file(daemon.engine, invitation) {
          Ok(Some(file)) -> poll.Done(file)

          // Until the queue exists the offer is not exportable.
          Ok(None) -> poll.Retry

          Error(failure) -> poll.Fail(from_failure(failure))
        }
      },
    )

  // A wait that runs out is the engine being too slow, which the caller retries.
  case waited {
    poll.Answered(file) -> Ok(secret.expose(file))
    poll.Failed(error) -> Error(error)
    poll.Expired -> Error(Unavailable)
  }
}

/// Imports an invitation file. The relationship starts `Joining`; its queue
/// is created and its first message sent in the background. Accepting an
/// invitation this daemon already accepted returns that first relationship
/// and starts nothing new (ADR-011), so a retry after `Unavailable` is
/// safe.
///
/// ## Examples
///
/// ```gleam
/// api.accept(daemon, file_bytes, "vendor support")
/// // -> Ok(contact)
/// ```
pub fn accept(
  daemon: Daemon,
  invitation: BitArray,
  description: String,
) -> Result(Id(Contact), ApiError) {
  accept_with_budget(daemon, invitation, description, None)
}

/// `accept` with an optional inbound message budget override.
///
/// ## Examples
///
/// ```gleam
/// api.accept_with_budget(daemon, file, "vendor", Some(25))
/// // -> Ok(contact)
/// ```
pub fn accept_with_budget(
  daemon: Daemon,
  invitation: BitArray,
  description: String,
  budget: Option(Int),
) -> Result(Id(Contact), ApiError) {
  engine.accept_with_budget(daemon.engine, invitation, description, budget)
  |> result.map_error(from_failure)
}

/// Creates an invitation, stores it sealed at the inviter's mailbox and
/// returns its ticket (ADR-009). The ticket is returned only once the
/// mailbox has stored the blob, so a ticket always names a stored
/// invitation; the blob's deadline is the invitation's own.
///
/// ## Examples
///
/// ```gleam
/// api.invite_ticket(daemon, "vendor support", offer.OperatorApproves, 10)
/// // -> Ok(IssuedTicket(file: file, ticket: secret))
/// ```
pub fn invite_ticket(
  daemon: Daemon,
  description: String,
  approval: Approval,
  budget: Int,
) -> Result(IssuedTicket, ApiError) {
  use file <- result.try(invite(daemon, description, approval, budget))

  // The file came from this daemon a moment ago, so a decode failure is
  // the engine misbehaving, not the caller.
  use offered <- result.try(
    invitation.decode(daemon.suite, file) |> result.replace_error(Unavailable),
  )
  use inbox <- result.try(offer_inbox(daemon, offered.route.queue))
  use made <- result.try(
    ticket.generate(daemon.suite, offered.route.endpoint)
    |> result.replace_error(Refused("the ticket could not be created")),
  )
  use keys <- result.try(
    ticket.keys(daemon.suite, made)
    |> result.replace_error(Refused("the ticket could not be created")),
  )
  use sealed <- result.try(
    ticket.seal(daemon.suite, keys, file)
    |> result.replace_error(Refused("the invitation could not be sealed")),
  )

  let request =
    protocol.PutBlob(
      queue: inbox.queue,
      admin: inbox.admin,
      blob: keys.locator,
      retrieve: keys.retrieve,
      retention_deadline: offered.expires_at,
      sealed:,
    )
  use Nil <- result.try(store_blob(daemon, inbox, request))

  Ok(IssuedTicket(file: secret.new(file), ticket: ticket.encode(made)))
}

/// Redeems a ticket: fetches the sealed invitation from the mailbox it
/// names, opens it (the AEAD, then the commitment), checks that the
/// invitation names the ticket's own mailbox, and then imports it exactly
/// as `accept` does. Surrounding whitespace is ignored; the ticket itself
/// must be exact.
///
/// ## Examples
///
/// ```gleam
/// api.accept_ticket(daemon, ticket_text, "vendor support")
/// // -> Ok(contact)
/// ```
pub fn accept_ticket(
  daemon: Daemon,
  text: Secret,
  description: String,
) -> Result(Id(Contact), ApiError) {
  accept_ticket_with_budget(daemon, text, description, None)
}

/// `accept_ticket` with an optional inbound message budget override.
///
/// ## Examples
///
/// ```gleam
/// api.accept_ticket_with_budget(daemon, ticket_text, "vendor", Some(25))
/// // -> Ok(contact)
/// ```
pub fn accept_ticket_with_budget(
  daemon: Daemon,
  text: Secret,
  description: String,
  budget: Option(Int),
) -> Result(Id(Contact), ApiError) {
  let invalid = InvalidInvitation("the ticket is not valid")

  // The ticket is exposed only to be decoded; no error repeats it.
  use spelled <- result.try(
    bit_array.to_string(secret.expose(text)) |> result.replace_error(invalid),
  )
  use made <- result.try(
    ticket.decode(string.trim(spelled)) |> result.replace_error(invalid),
  )
  use mailbox <- result.try(
    endpoint.admit(ticket.endpoint(made), daemon.carrier)
    |> result.replace_error(Refused(
      "the carrier policy does not permit the ticket's mailbox",
    )),
  )
  use Nil <- result.try(await_tor_for_endpoint(daemon, mailbox))
  use keys <- result.try(
    ticket.keys(daemon.suite, made) |> result.replace_error(Unavailable),
  )
  use sealed <- result.try(fetch_blob(daemon, mailbox, keys))
  use file <- result.try(
    ticket.open(daemon.suite, keys, sealed)
    |> result.replace_error(InvalidInvitation(
      "the mailbox returned an invitation this ticket does not open",
    )),
  )
  use offered <- result.try(
    invitation.decode(daemon.suite, file)
    |> result.replace_error(InvalidInvitation(
      "the file is not a valid invitation",
    )),
  )

  // The invitation's route and the ticket name the same mailbox; one that
  // does not is not the invitation this ticket was issued for.
  use <- bool.guard(
    offered.route.endpoint != mailbox,
    Error(InvalidInvitation(
      "the invitation names a different mailbox than its ticket",
    )),
  )

  accept_with_budget(daemon, file, description, budget)
}

/// Creates an invitation and its ticket as `invite_ticket` does, opens a
/// rendezvous slot at this daemon's own mailbox, and returns a spoken code
/// for it (ADR-016). The run that follows belongs to the daemon's pairing
/// registry, not to the caller: it waits for the joiner, answers, checks
/// the joiner's confirmation and only then releases the ticket, and it
/// closes the slot however it ends. `await_code` reports how it ended.
///
/// The order is the ADR's. The failure count at the mailbox is checked
/// first, so a refused code mints no offer; the ticket is minted and its
/// blob stored before the slot exists, so it exists before any message can
/// be read; and the code is built from the nameplate the mailbox drew.
///
/// ## Examples
///
/// ```gleam
/// api.invite_code(daemon, "vendor support", offer.OperatorApproves, 10)
/// // -> Ok(CodeInvite(run:, code:, expires_at:))
/// ```
pub fn invite_code(
  daemon: Daemon,
  description: String,
  approval: Approval,
  budget: Int,
) -> Result(CodeInvite, ApiError) {
  let mailbox = daemon.rendezvous.mailbox
  let counted = endpoint.to_string(mailbox)

  use Nil <- result.try(check_failures(daemon, counted))
  use issued <- result.try(invite_ticket(daemon, description, approval, budget))
  use slot <- result.try(draw_slot(daemon))

  let link = rendezvous_link(daemon, mailbox, id.to_hex(slot.rendezvous))
  use #(plate, expires_at) <- result.try(open_slot(daemon, link, slot))
  let code = pairing_code.generate(daemon.suite, plate)

  // From here the slot exists, so a step that fails closes it before the
  // caller hears why.
  use waiting <- or_close_slot(
    rendezvous.invite(code, slot.rendezvous, issued.ticket),
    link,
    slot,
    Refused("the ticket does not fit a pairing code"),
  )

  let lifetime = lifetime_ms(daemon, expires_at, limits.rendezvous_seconds)
  let record = record_failure(daemon, counted)
  let suite = daemon.suite
  let work = fn() {
    pairing.run_inviter(suite, link, slot, waiting, lifetime, record)
  }
  let abandon = fn() { pairing.close(link, slot) }

  use Nil <- or_close_slot(
    pairing.begin(
      daemon.pairing,
      slot.rendezvous,
      work,
      lifetime + pairing.run_slack_ms,
      abandon,
    ),
    link,
    slot,
    Unavailable,
  )

  Ok(CodeInvite(
    run: slot.rendezvous,
    code: pairing_code.encode(code),
    expires_at:,
  ))
}

/// Waits for an inviter's run, started by `invite_code`, to end, for at
/// most `code_wait_ms`. A run this daemon does not know, because it never
/// started here or the daemon restarted since, is `NotFound`. Waiting
/// changes nothing: a caller that goes away leaves the run to finish and
/// close its slot.
///
/// ## Examples
///
/// ```gleam
/// api.await_code(daemon, invited.run)
/// // -> Ok(Paired(contact: None))
/// ```
pub fn await_code(
  daemon: Daemon,
  run: Id(RendezvousKind),
) -> Result(PairingOutcome, ApiError) {
  // The registry's answer decides; no answer in time leaves the run going.
  case pairing.await(daemon.pairing, run, code_wait_ms) {
    Ok(pairing.Ended(Ok(Nil))) -> Ok(Paired(contact: None))
    Ok(pairing.Ended(Error(ending))) -> Ok(from_ending(ending))
    Ok(pairing.Unknown) -> Error(NotFound)
    Error(Nil) -> Error(Unavailable)
  }
}

/// Pairs by a spoken code as the joiner (ADR-016): claims the slot the
/// code's nameplate names at the rendezvous, runs the PAKE, and redeems
/// the ticket it delivers exactly as `accept_ticket_with_budget` does. The
/// code must be exact; a caller reading a terminal trims it first. The
/// rendezvous is `rendezvous` as `HOST:PORT` when given, else this daemon's
/// own mailbox, and it is admitted under the carrier policy before any
/// connection. A refused claim is a plain `Refused` and costs nothing; a
/// run that does not pair is `Ok` with its ending.
///
/// ## Examples
///
/// ```gleam
/// api.accept_code(daemon, code_text, None, "vendor", None)
/// // -> Ok(Paired(contact: Some(contact)))
/// ```
pub fn accept_code(
  daemon: Daemon,
  code: Secret,
  rendezvous: Option(String),
  description: String,
  budget: Option(Int),
) -> Result(PairingOutcome, ApiError) {
  use parsed <- result.try(decode_code(code))
  use at <- result.try(rendezvous_endpoint(daemon, rendezvous))
  use Nil <- result.try(await_tor_for_endpoint(daemon, at))

  let counted = endpoint.to_string(at)
  use Nil <- result.try(check_failures(daemon, counted))
  use #(read, append) <- result.try(draw_capabilities(daemon))

  let plate = pairing_code.nameplate(parsed)
  let link = rendezvous_link(daemon, at, nameplate.to_string(plate))
  use #(run, expires_at) <- result.try(claim_slot(
    daemon,
    link,
    plate,
    read,
    append,
  ))

  let slot = pairing.Slot(rendezvous: run, read:, append:)
  let lifetime =
    lifetime_ms(daemon, expires_at, limits.rendezvous_claimed_seconds)
  let record = record_failure(daemon, counted)

  // A delivered ticket continues on the ticket's own path, unchanged; any
  // other ending is the answer.
  case pairing.run_joiner(daemon.suite, link, slot, parsed, lifetime, record) {
    Ok(ticket) ->
      accept_ticket_with_budget(daemon, ticket, description, budget)
      |> result.map(fn(contact) { Paired(contact: Some(contact)) })

    Error(ending) -> Ok(from_ending(ending))
  }
}

/// Refuses a pairing code at an endpoint where `limits.max_rendezvous_failures`
/// confirmations already failed inside the window (ADR-016). Each failure
/// may be a spent guess, and the rendezvous gets two per run, so past the
/// cap the operator is sent to a ticket and a fingerprint check.
fn check_failures(daemon: Daemon, counted: String) -> Result(Nil, ApiError) {
  use failures <- result.try(
    engine.rendezvous_failures(daemon.engine, counted)
    |> result.map_error(from_failure),
  )

  use <- bool.guard(
    failures >= limits.max_rendezvous_failures,
    Error(Refused(
      "too many pairing codes failed at this rendezvous recently; pair with a ticket instead (invite create --ticket) and compare fingerprints",
    )),
  )

  Ok(Nil)
}

/// The function a run calls when it ends with a failed confirmation. A
/// record the engine cannot make is lost: the run has ended either way, and
/// a count that missed one only lets one more code through.
fn record_failure(daemon: Daemon, counted: String) -> fn() -> Nil {
  let engine = daemon.engine

  fn() {
    let _ = engine.record_rendezvous_failure(engine, counted)
    Nil
  }
}

/// A fresh slot for the inviter: an identifier and its two capabilities,
/// drawn from the daemon's suite.
fn draw_slot(daemon: Daemon) -> Result(pairing.Slot, ApiError) {
  use rendezvous <- result.try(
    field.fresh_id(daemon.suite) |> result.replace_error(Unavailable),
  )
  use #(read, append) <- result.map(draw_capabilities(daemon))

  pairing.Slot(rendezvous:, read:, append:)
}

/// One side's two fresh capabilities for a slot.
fn draw_capabilities(
  daemon: Daemon,
) -> Result(
  #(Capability(capability.Read), Capability(capability.Append)),
  ApiError,
) {
  use read <- result.try(
    field.fresh_capability(daemon.suite) |> result.replace_error(Unavailable),
  )
  use append <- result.map(
    field.fresh_capability(daemon.suite) |> result.replace_error(Unavailable),
  )

  #(read, append)
}

/// How a run reaches a rendezvous: the daemon's dialer to `at`, one onion
/// circuit group per run, and the daemon's poll clock.
fn rendezvous_link(
  daemon: Daemon,
  at: Endpoint,
  group: String,
) -> pairing.Link {
  let dialer = daemon.dialer

  pairing.Link(
    call: fn(request, timeout) {
      mailbox_client.call(dialer, at, group, request, timeout)
      |> result.replace_error(Nil)
    },
    clock: daemon.poll_clock,
  )
}

/// Opens the inviter's slot under the daemon's provisioning capability.
/// The identical request answers the same nameplate, so a retry after a
/// lost answer is safe.
fn open_slot(
  daemon: Daemon,
  link: pairing.Link,
  slot: pairing.Slot,
) -> Result(#(Nameplate, Instant), ApiError) {
  let request =
    protocol.OpenRendezvous(
      provision: daemon.rendezvous.provision,
      rendezvous: slot.rendezvous,
      read: slot.read,
      append: slot.append,
      lifetime_seconds: limits.rendezvous_seconds,
    )

  rendezvous_call(daemon, link, request, fn(response) {
    // A nameplate ends the wait; a refusal the mailbox will repeat ends it
    // with that refusal, and a busy mailbox is tried again.
    case response {
      protocol.RendezvousOpened(nameplate:, expires_at:) ->
        poll.Done(#(nameplate, expires_at))

      protocol.Refused(protocol.QuotaExceeded) ->
        poll.Fail(Refused(
          "the mailbox holds as many open codes as it allows; try again later",
        ))

      protocol.Refused(protocol.Unauthorized) ->
        poll.Fail(Refused("the mailbox refused this daemon's provisioning"))

      protocol.Refused(protocol.Unavailable) -> poll.Retry

      protocol.Refused(_)
      | protocol.QueueCreated(_)
      | protocol.Appended(_)
      | protocol.Batch(_)
      | protocol.Acked
      | protocol.QueueDeleted
      | protocol.BlobStored(_)
      | protocol.SealedBlob(_)
      | protocol.RendezvousClaimed(..)
      | protocol.RendezvousSent
      | protocol.RendezvousMessages(_)
      | protocol.RendezvousClosed ->
        poll.Fail(Refused("the mailbox did not open a rendezvous"))
    }
  })
}

/// Claims the slot a nameplate names. An unknown, expired or already
/// claimed nameplate gets one answer from the mailbox, and it is final; the
/// identical claim is answered the same, so a retry is safe.
fn claim_slot(
  daemon: Daemon,
  link: pairing.Link,
  plate: Nameplate,
  read: Capability(capability.Read),
  append: Capability(capability.Append),
) -> Result(#(Id(RendezvousKind), Instant), ApiError) {
  let request = protocol.ClaimRendezvous(nameplate: plate, read:, append:)

  rendezvous_call(daemon, link, request, fn(response) {
    // A bound claim ends the wait; a refused one is final and costs no
    // guess; a busy mailbox is tried again.
    case response {
      protocol.RendezvousClaimed(rendezvous:, expires_at:) ->
        poll.Done(#(rendezvous, expires_at))

      protocol.Refused(protocol.Unauthorized) ->
        poll.Fail(Refused(
          "no code is open under that nameplate at the rendezvous; it may have expired or been used",
        ))

      protocol.Refused(protocol.Unavailable) -> poll.Retry

      protocol.Refused(_)
      | protocol.QueueCreated(_)
      | protocol.Appended(_)
      | protocol.Batch(_)
      | protocol.Acked
      | protocol.QueueDeleted
      | protocol.BlobStored(_)
      | protocol.SealedBlob(_)
      | protocol.RendezvousOpened(..)
      | protocol.RendezvousSent
      | protocol.RendezvousMessages(_)
      | protocol.RendezvousClosed ->
        poll.Fail(Refused("the rendezvous did not accept the claim"))
    }
  })
}

/// One request made before a run starts, retried with `weft/poll` on the
/// daemon's clock for at most `ticket_wait_ms`, as a ticket's calls are. A
/// call that did not reach the mailbox is always tried again.
fn rendezvous_call(
  daemon: Daemon,
  link: pairing.Link,
  request: protocol.Request,
  judge: fn(protocol.Response) -> poll.Attempt(a, ApiError),
) -> Result(a, ApiError) {
  let waited =
    poll.until_on(
      clock: daemon.poll_clock,
      within: ticket_wait_ms,
      every: poll.Fixed(ticket_retry_ms),
      attempt: fn() {
        // The answer decides; a transport failure is always worth a retry.
        case link.call(request, ticket_call_ms) {
          Ok(response) -> judge(response)
          Error(Nil) -> poll.Retry
        }
      },
    )

  // A wait that runs out is a mailbox that could not be reached.
  case waited {
    poll.Answered(value) -> Ok(value)
    poll.Failed(error) -> Error(error)
    poll.Expired -> Error(Unavailable)
  }
}

/// How long a run may last: what remains of its slot by the expiry the
/// mailbox returned, read against this daemon's clock, at most `cap`
/// seconds. The two clocks may disagree (ADR-008), so a remainder outside
/// one second to `cap` is read as skew and `cap` is used; the mailbox's own
/// expiry still ends the slot, which a run sees as the slot going away.
fn lifetime_ms(daemon: Daemon, expires_at: Instant, cap: Int) -> Int {
  let remaining =
    expires_at.unix_seconds - { daemon.rendezvous.clock() }.unix_seconds

  // Only a plausible remainder narrows the cap.
  case remaining >= 1 && remaining <= cap {
    True -> remaining * 1000
    False -> cap * 1000
  }
}

/// A spoken code from its text, strictly: a refusal here has spent nothing,
/// and its reason names a word's position, never a word.
fn decode_code(code: Secret) -> Result(PairingCode, ApiError) {
  // The code is exposed only to be decoded; no error repeats it.
  use text <- result.try(
    bit_array.to_string(secret.expose(code))
    |> result.replace_error(InvalidInvitation("the pairing code is not text")),
  )

  pairing_code.decode(text)
  |> result.map_error(fn(error) {
    InvalidInvitation(pairing.describe_code_error(error))
  })
}

/// The joiner's rendezvous: `HOST:PORT` when the operator named one, else
/// this daemon's own mailbox, admitted under the carrier policy before
/// anything dials it.
fn rendezvous_endpoint(
  daemon: Daemon,
  rendezvous: Option(String),
) -> Result(Endpoint, ApiError) {
  // A named rendezvous is parsed; without one the daemon's own is used.
  use at <- result.try(case rendezvous {
    None -> Ok(daemon.rendezvous.mailbox)

    Some(text) ->
      endpoint.parse(text)
      |> result.replace_error(Refused(
        "the rendezvous must be ONION:PORT or 127.0.0.1:PORT",
      ))
  })

  endpoint.admit(at, daemon.carrier)
  |> result.replace_error(Refused(
    "the carrier policy does not permit the rendezvous",
  ))
}

/// A run's ending as the contract names it.
fn from_ending(ending: pairing.Ending) -> PairingOutcome {
  case ending {
    pairing.NeverClaimed -> NeverClaimed
    pairing.Stalled -> Stalled
    pairing.ConfirmationFailed -> ConfirmationFailed
  }
}

/// Continues with the value of a step taken while a slot is open, or closes
/// the slot and fails with `refusal`, so no path out of `invite_code` after
/// the open leaves the slot behind.
///
/// ```gleam
/// // use waiting <- or_close_slot(rendezvous.invite(..), link, slot, Unavailable)
/// ```
fn or_close_slot(
  outcome: Result(a, e),
  link: pairing.Link,
  slot: pairing.Slot,
  refusal: ApiError,
  then: fn(a) -> Result(b, ApiError),
) -> Result(b, ApiError) {
  // A failed step owes the open slot its close before the caller hears.
  case outcome {
    Ok(value) -> then(value)

    Error(_) -> {
      pairing.close(link, slot)
      Error(refusal)
    }
  }
}

/// The inbox behind an offer's queue, whose admin capability pays for the
/// sealed invitation.
fn offer_inbox(daemon: Daemon, queue: Id(Queue)) -> Result(Inbox, ApiError) {
  use inboxes <- result.try(
    engine.live_inboxes(daemon.engine) |> result.map_error(from_failure),
  )

  list.find(inboxes, fn(inbox) { inbox.queue == queue })
  |> result.replace_error(NotFound)
}

/// Stores the sealed invitation at the offer's mailbox, retrying what may
/// pass on a second try. The request is the same bytes every time, so a
/// retry after a lost answer is answered `BlobStored` by the mailbox.
fn store_blob(
  daemon: Daemon,
  inbox: Inbox,
  request: protocol.Request,
) -> Result(Nil, ApiError) {
  ticket_call(
    daemon,
    inbox.endpoint,
    mailbox_client.isolation_group(inbox.queue),
    request,
    fn(response) {
      // Only a stored blob ends the wait; a refusal the mailbox will repeat
      // ends it with that refusal, and everything else is tried again.
      case response {
        protocol.BlobStored(_) -> poll.Done(Nil)

        protocol.Refused(protocol.BadDeadline) ->
          poll.Fail(Refused(
            "the mailbox refused the invitation's deadline; check the clock",
          ))

        protocol.Refused(protocol.QuotaExceeded) ->
          poll.Fail(Refused("the mailbox queue's quota is exhausted"))

        protocol.Refused(protocol.Unavailable) -> poll.Retry

        protocol.Refused(_)
        | protocol.QueueCreated(_)
        | protocol.Appended(_)
        | protocol.Batch(_)
        | protocol.Acked
        | protocol.QueueDeleted
        | protocol.SealedBlob(_)
        | protocol.RendezvousOpened(..)
        | protocol.RendezvousClaimed(..)
        | protocol.RendezvousSent
        | protocol.RendezvousMessages(_)
        | protocol.RendezvousClosed ->
          poll.Fail(Refused("the mailbox did not store the invitation"))
      }
    },
  )
}

/// Fetches a ticket's sealed invitation. `Unauthorized` is final: the
/// mailbox has no live blob for this ticket, because it expired, was never
/// stored, or the ticket was mistyped in a way the checksum could not see.
fn fetch_blob(
  daemon: Daemon,
  mailbox: Endpoint,
  keys: ticket.Keys,
) -> Result(BitArray, ApiError) {
  ticket_call(
    daemon,
    mailbox,
    id.to_hex(keys.locator),
    protocol.GetBlob(blob: keys.locator, retrieve: keys.retrieve),
    fn(response) {
      // A sealed blob ends the wait; a missing one is final, and a busy
      // mailbox is tried again.
      case response {
        protocol.SealedBlob(sealed:) -> poll.Done(sealed)

        protocol.Refused(protocol.Unauthorized) ->
          poll.Fail(InvalidInvitation(
            "the mailbox holds no invitation for this ticket; it may have expired",
          ))

        protocol.Refused(protocol.Unavailable) -> poll.Retry

        protocol.Refused(_)
        | protocol.QueueCreated(_)
        | protocol.Appended(_)
        | protocol.Batch(_)
        | protocol.Acked
        | protocol.QueueDeleted
        | protocol.BlobStored(_)
        | protocol.RendezvousOpened(..)
        | protocol.RendezvousClaimed(..)
        | protocol.RendezvousSent
        | protocol.RendezvousMessages(_)
        | protocol.RendezvousClosed ->
          poll.Fail(Refused("the mailbox did not return the invitation"))
      }
    },
  )
}

/// One ticket request, retried with `weft/poll` on the daemon's clock until
/// `judge` settles it or `ticket_wait_ms` runs out. A call that did not
/// reach the mailbox is always tried again.
fn ticket_call(
  daemon: Daemon,
  mailbox: Endpoint,
  isolation_group: String,
  request: protocol.Request,
  judge: fn(protocol.Response) -> poll.Attempt(a, ApiError),
) -> Result(a, ApiError) {
  let waited =
    poll.until_on(
      clock: daemon.poll_clock,
      within: ticket_wait_ms,
      every: poll.Fixed(ticket_retry_ms),
      attempt: fn() {
        // The answer decides; a transport failure is always worth a retry.
        case
          mailbox_client.call(
            daemon.dialer,
            mailbox,
            isolation_group,
            request,
            ticket_call_ms,
          )
        {
          Ok(response) -> judge(response)
          Error(_) -> poll.Retry
        }
      },
    )

  // A wait that runs out is a mailbox that could not be reached.
  case waited {
    poll.Answered(value) -> Ok(value)
    poll.Failed(error) -> Error(error)
    poll.Expired -> Error(Unavailable)
  }
}

/// Every relationship, oldest first.
///
/// ## Examples
///
/// ```gleam
/// api.contacts(daemon)
/// // -> Ok([ContactView(..)])
/// ```
pub fn contacts(daemon: Daemon) -> Result(List(ContactView), ApiError) {
  use records <- result.try(
    engine.contacts(daemon.engine) |> result.map_error(from_failure),
  )

  Ok(list.map(records, fn(record) { contact_view(daemon.suite, record) }))
}

/// Approves a pending relationship.
///
/// ## Examples
///
/// ```gleam
/// api.approve(daemon, contact)
/// // -> Ok(Nil)
/// ```
pub fn approve(daemon: Daemon, contact: Id(Contact)) -> Result(Nil, ApiError) {
  engine.approve(daemon.engine, contact) |> result.map_error(from_failure)
}

/// Declines a pending relationship.
///
/// ## Examples
///
/// ```gleam
/// api.decline(daemon, contact)
/// // -> Ok(Nil)
/// ```
pub fn decline(daemon: Daemon, contact: Id(Contact)) -> Result(Nil, ApiError) {
  engine.decline(daemon.engine, contact) |> result.map_error(from_failure)
}

/// Closes a relationship, telling the peer on a best-effort basis.
///
/// ## Examples
///
/// ```gleam
/// api.close(daemon, contact)
/// // -> Ok(Nil)
/// ```
pub fn close(daemon: Daemon, contact: Id(Contact)) -> Result(Nil, ApiError) {
  engine.close(daemon.engine, contact) |> result.map_error(from_failure)
}

/// Raises a relationship's inbound budget by `by` messages and releases the
/// held messages it now admits.
///
/// ## Examples
///
/// ```gleam
/// api.raise_budget(daemon, contact, 5)
/// // -> Ok(Nil)
/// ```
pub fn raise_budget(
  daemon: Daemon,
  contact: Id(Contact),
  by: Int,
) -> Result(Nil, ApiError) {
  engine.raise_budget(daemon.engine, contact, by)
  |> result.map_error(from_failure)
}

/// Queues a message for a contact and returns its identifier. It has been
/// committed, not delivered; read `status` for how far it got.
///
/// ## Examples
///
/// ```gleam
/// api.send(daemon, contact, "text/plain", <<"hi">>, None)
/// // -> Ok(message)
/// ```
pub fn send(
  daemon: Daemon,
  contact: Id(Contact),
  content_type: String,
  payload: Secret,
  in_reply_to: Option(Id(MessageKind)),
) -> Result(Id(MessageKind), ApiError) {
  engine.send(daemon.engine, contact, None, content_type, payload, in_reply_to)
  |> result.map_error(from_failure)
}

/// `send` under a caller's idempotency key, so a retry after an answer the
/// caller never saw (`Unavailable` after the commit landed) cannot queue
/// the message twice (ADR-011). The key is scoped to the contact and
/// remembered for `limits.send_key_seconds`; it is 1 to
/// `limits.max_send_key_bytes` bytes. The same key with the same content
/// type, payload and reply target answers with the first message's
/// identifier and queues nothing; with anything else it is `Refused`.
///
/// ## Examples
///
/// ```gleam
/// api.send_with_key(daemon, contact, "order-17", "text/plain", <<"hi">>, None)
/// // -> Ok(message)
/// ```
pub fn send_with_key(
  daemon: Daemon,
  contact: Id(Contact),
  key: String,
  content_type: String,
  payload: Secret,
  in_reply_to: Option(Id(MessageKind)),
) -> Result(Id(MessageKind), ApiError) {
  engine.send(
    daemon.engine,
    contact,
    Some(key),
    content_type,
    payload,
    in_reply_to,
  )
  |> result.map_error(from_failure)
}

/// Ready deliveries not yet consumed, oldest first, for one contact or all.
///
/// ## Examples
///
/// ```gleam
/// api.receive(daemon, None, 10)
/// // -> Ok([Delivery(..)])
/// ```
pub fn receive(
  daemon: Daemon,
  contact: Option(Id(Contact)),
  max: Int,
) -> Result(List(Delivery), ApiError) {
  use records <- result.try(
    engine.deliveries(daemon.engine, contact, max)
    |> result.map_error(from_failure),
  )

  Ok(list.map(records, delivery))
}

/// Marks a delivery consumed. The adapter calls it after it has persisted
/// its own processing outcome (spec §8.5).
///
/// ## Examples
///
/// ```gleam
/// api.acknowledge(daemon, message)
/// // -> Ok(Nil)
/// ```
pub fn acknowledge(
  daemon: Daemon,
  message: Id(MessageKind),
) -> Result(Nil, ApiError) {
  engine.consume(daemon.engine, message) |> result.map_error(from_failure)
}

/// How far an outbound message got.
///
/// ## Examples
///
/// ```gleam
/// api.status(daemon, message)
/// // -> Ok(StoredByMailbox)
/// ```
pub fn status(
  daemon: Daemon,
  message: Id(MessageKind),
) -> Result(MessageState, ApiError) {
  use state <- result.try(
    engine.message_state(daemon.engine, message)
    |> result.map_error(from_failure),
  )

  Ok(message_state(state))
}

/// The most recent audit entries, newest first, for one contact or all.
///
/// ## Examples
///
/// ```gleam
/// api.audit(daemon, None, 20)
/// // -> Ok([AuditEntry(..)])
/// ```
pub fn audit(
  daemon: Daemon,
  contact: Option(Id(Contact)),
  limit: Int,
) -> Result(List(AuditEntry), ApiError) {
  use records <- result.try(
    engine.audit(daemon.engine, contact, limit)
    |> result.map_error(from_failure),
  )

  Ok(list.map(records, audit_entry))
}

/// The most recent incidents, newest first: inbound envelopes the daemon
/// set aside without delivering them (ADR-010). For the operator only.
///
/// ## Examples
///
/// ```gleam
/// api.incidents(daemon, 20)
/// // -> Ok([Incident(..)])
/// ```
pub fn incidents(
  daemon: Daemon,
  limit: Int,
) -> Result(List(Incident), ApiError) {
  use records <- result.try(
    engine.incidents(daemon.engine, limit) |> result.map_error(from_failure),
  )

  Ok(list.map(records, incident))
}

/// Subscribes a subject to `Event`s. Nothing is replayed.
///
/// ## Examples
///
/// ```gleam
/// api.subscribe(daemon, process.new_subject())
/// // -> Nil
/// ```
pub fn subscribe(daemon: Daemon, subscriber: Subject(Event)) -> Nil {
  events.subscribe(daemon.events, subscriber)
}

/// The daemon's account of itself. An engine that does not answer reads as
/// zero pending and zero incidents.
///
/// ## Examples
///
/// ```gleam
/// api.health(daemon).outbox_pending
/// // -> 0
/// ```
pub fn health(daemon: Daemon) -> Health {
  let seen = status.read(daemon.status)

  // The engine's answer decides the count; one that is not running reads as no pending work.
  let pending = case engine.outbox_pending(daemon.engine) {
    Ok(count) -> count
    Error(_) -> 0
  }

  // The same goes for the incident count.
  let incidents = case engine.incident_count(daemon.engine) {
    Ok(count) -> count
    Error(_) -> 0
  }

  Health(
    carrier: daemon.carrier,
    tor: seen.tor,
    mailbox: seen.mailbox,
    outbox_pending: pending,
    incidents:,
  )
}

/// The engine's failure in the contract's words.
fn from_failure(failure: engine.Failure) -> ApiError {
  case failure {
    engine.NotFound -> NotFound
    engine.InvalidInvitation(reason:) -> InvalidInvitation(reason)
    engine.Refused(reason:) -> Refused(reason)
    engine.Unavailable -> Unavailable
  }
}

/// A stored relationship as the contract's view of it.
fn contact_view(suite: Suite, record: store.ContactRecord) -> ContactView {
  let current = record.relationship
  let budget = current.budget

  ContactView(
    contact: current.contact,
    phase: phase_name(current.phase),
    description: record.description,
    peer_fingerprint: fingerprint(suite, current.phase),
    budget_granted: budget.granted,
    budget_used: budget.used,
    held: list.length(budget.held),
  )
}

/// The relationship's phase as the contract names it, without the session.
fn phase_name(phase: relationship.Phase) -> PhaseName {
  case phase {
    relationship.Joining(..) -> Joining
    relationship.AwaitingAccept(_) -> AwaitingAccept
    relationship.PendingApproval(_) -> PendingApproval
    relationship.Active(_) -> Active
    relationship.Closed(_) -> Closed
  }
}

/// The peer's fingerprint, for the phases that have a verified peer.
fn fingerprint(suite: Suite, phase: relationship.Phase) -> Option(String) {
  case phase {
    relationship.AwaitingAccept(link)
    | relationship.PendingApproval(link)
    | relationship.Active(link) ->
      Some(
        identity.fingerprint(suite, link.peer)
        |> bit_array.base16_encode
        |> string.lowercase,
      )

    relationship.Joining(..) | relationship.Closed(_) -> None
  }
}

/// A stored delivery as the contract's `Delivery`, payload still a `Secret`.
fn delivery(record: store.DeliveryRecord) -> Delivery {
  Delivery(
    message: record.message,
    contact: record.contact,
    content_type: record.content_type,
    payload: record.payload,
    in_reply_to: record.in_reply_to,
    received_at: record.received_at,
  )
}

/// A stored send state as the contract's `MessageState`.
fn message_state(state: store.SentState) -> MessageState {
  case state {
    store.LocallyQueued -> LocallyQueued
    store.StoredByMailbox -> StoredByMailbox
    store.ReceivedByPeer -> ReceivedByPeer
    store.Failed -> Failed
  }
}

/// A stored incident as the contract's `Incident`.
fn incident(record: store.IncidentRecord) -> Incident {
  Incident(
    kind: case record.kind {
      store.RepeatedMessageId -> RepeatedMessageId
      store.QuarantinedEnvelope -> QuarantinedEnvelope
    },
    contact: record.contact,
    message: record.message,
    attempts: record.attempts,
    at: record.at,
  )
}

/// A stored audit row as the contract's `AuditEntry`.
fn audit_entry(record: store.AuditRecord) -> AuditEntry {
  AuditEntry(
    contact: record.contact,
    direction: case record.direction {
      store.Inbound -> Inbound
      store.Outbound -> Outbound
    },
    message: record.message,
    content_type: record.content_type,
    payload: record.payload,
    at: record.at,
  )
}
