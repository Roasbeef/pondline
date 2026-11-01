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
//// ## Flow
////
//// 1. `assemble` builds the handle, for `daemon/node` alone.
//// 2. Pairing: `invite` (and `await_file`), `accept`; by ticket,
////    `invite_ticket` (`offer_inbox`, `store_blob`) and `accept_ticket`
////    (`fetch_blob`), both through `ticket_call`.
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

import core/crypto/identity
import core/crypto/suite.{type Suite}
import core/endpoint.{type CarrierPolicy, type Endpoint}
import core/id.{
  type Contact, type Id, type Invitation as InvitationKind,
  type Message as MessageKind, type Queue,
}
import core/invitation
import core/mailbox/protocol
import core/offer.{type Approval}
import core/relationship
import core/route.{type Inbox}
import core/secret.{type Secret}
import core/ticket
import core/time.{type Instant}
import daemon/engine
import daemon/events
import daemon/mail.{type Handle}
import daemon/mailbox_client
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

/// How long `invite` waits for the mailbox to create the offer's queue.
pub const invite_wait_ms = 30_000

/// How often `invite` looks at the committed offer while it waits.
pub const invite_poll_ms = 50

/// How long `invite_ticket` keeps trying to store the sealed invitation,
/// and `accept_ticket` to fetch it (ADR-009).
pub const ticket_wait_ms = 60_000

/// The budget of one mailbox call made for a ticket, dial included. A
/// first onion connection builds a rendezvous circuit, which takes seconds.
pub const ticket_call_ms = 30_000

/// How long a ticket's mailbox call waits before it is tried again.
pub const ticket_retry_ms = 1000

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
  )
}

/// What `invite_ticket` hands back: the invitation file, for an operator
/// who also wants it, and the ticket's text, a `Secret` because it is the
/// authority to fetch and open the invitation.
pub type IssuedTicket {
  IssuedTicket(file: BitArray, ticket: Secret)
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
/// through, the same one the tree's workers use.
///
/// ## Examples
///
/// ```gleam
/// api.assemble(engine, events, status, suite, policy, pid, dir, clock, dialer)
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
/// // -> "/var/lib/reedwire"
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
  use invitation <- result.try(
    engine.invite(daemon.engine, description, approval, budget)
    |> result.map_error(from_failure),
  )

  await_file(daemon, invitation)
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
          Ok(Some(bytes)) -> poll.Done(bytes)

          // Until the queue exists the offer is not exportable.
          Ok(None) -> poll.Retry

          Error(failure) -> poll.Fail(from_failure(failure))
        }
      },
    )

  // A wait that runs out is the engine being too slow, which the caller retries.
  case waited {
    poll.Answered(bytes) -> Ok(bytes)
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
  engine.accept(daemon.engine, invitation, description)
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
/// // -> Ok(IssuedTicket(file: <<...>>, ticket: secret))
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

  Ok(IssuedTicket(file:, ticket: ticket.encode(made)))
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

  accept(daemon, file, description)
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
        | protocol.SealedBlob(_) ->
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
        | protocol.BlobStored(_) ->
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
  payload: BitArray,
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
  payload: BitArray,
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
