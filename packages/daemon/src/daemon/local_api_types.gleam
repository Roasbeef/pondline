//// The vocabulary the local API server shares with the daemon runtime.
////
//// The server does not call the runtime directly. It calls a `Backend`, a
//// record of one function per operation, so a test can serve the same
//// protocol over a fake and the real wiring is one function in
//// `daemon/local_api_backend`. The types here mirror the runtime's own API
//// types (`daemon/api`) field for field; when the runtime's shapes change,
//// the mapping in that one module changes with them and the server does
//// not.

import core/id.{type Contact, type Id, type Message}
import core/offer.{type Approval}
import core/secret.{type Secret}
import core/time.{type Instant}
import gleam/erlang/process.{type Subject}
import gleam/option.{type Option}

/// Why an operation failed, in terms an API client can act on.
pub type ApiError {
  /// The contact or message does not exist.
  NotFound

  /// The invitation file could not be redeemed.
  InvalidInvitation(reason: String)

  /// The operation is valid but not allowed now, such as sending past the
  /// budget. The reason is safe to show.
  Refused(reason: String)

  /// The runtime cannot serve the call right now.
  Unavailable
}

/// Where a relationship is in its life.
pub type PhaseName {
  Joining
  AwaitingAccept
  PendingApproval
  Active
  Closed
}

/// What the operator or an agent sees of one contact.
pub type ContactView {
  ContactView(
    contact: Id(Contact),
    phase: PhaseName,
    description: String,
    peer_fingerprint: Option(String),
    /// Messages the peer may send in all, ever.
    budget_granted: Int,
    /// Messages already spent from that grant.
    budget_used: Int,
    /// Messages received and not yet acknowledged.
    held: Int,
  )
}

/// A received message waiting to be acknowledged.
pub type Delivery {
  Delivery(
    message: Id(Message),
    contact: Id(Contact),
    content_type: String,
    payload: Secret,
    in_reply_to: Option(Id(Message)),
    received_at: Instant,
  )
}

/// How far an outbound message has got.
pub type MessageState {
  LocallyQueued
  StoredByMailbox
  ReceivedByPeer
  Failed
}

/// Which way a message went.
pub type Direction {
  Inbound
  Outbound
}

/// One line of the operator's plaintext audit log.
pub type AuditEntry {
  AuditEntry(
    contact: Id(Contact),
    direction: Direction,
    message: Id(Message),
    content_type: String,
    payload: Secret,
    at: Instant,
  )
}

/// Why the daemon set an inbound envelope aside (ADR-010).
pub type IncidentKind {
  /// An authenticated peer reused a message identifier; it was ignored.
  RepeatedMessageId

  /// An envelope that failed to process too often was dropped and
  /// acknowledged.
  QuarantinedEnvelope
}

/// One inbound envelope the daemon set aside without delivering it. It
/// carries identifiers and a count, never a payload.
pub type Incident {
  Incident(
    kind: IncidentKind,
    contact: Option(Id(Contact)),
    message: Option(Id(Message)),
    attempts: Option(Int),
    at: Instant,
  )
}

/// What the runtime tells subscribers.
pub type Event {
  /// A delivery for this contact is ready to receive.
  MessagesReady(contact: Id(Contact))

  /// The contact's phase or budget changed.
  ContactChanged(contact: Id(Contact))
}

/// A summary of the runtime's state as named fields, such as
/// `#("mailbox", "reachable")`. Every value is safe to print.
pub type Health {
  Health(fields: List(#(String, String)))
}

/// One function per API operation.
pub type Backend {
  Backend(
    invite: fn(String, Approval, Int) -> Result(BitArray, ApiError),
    accept: fn(BitArray, String) -> Result(Id(Contact), ApiError),
    contacts: fn() -> Result(List(ContactView), ApiError),
    approve: fn(Id(Contact)) -> Result(Nil, ApiError),
    decline: fn(Id(Contact)) -> Result(Nil, ApiError),
    close: fn(Id(Contact)) -> Result(Nil, ApiError),
    raise_budget: fn(Id(Contact), Int) -> Result(Nil, ApiError),
    send: fn(Id(Contact), Option(String), String, BitArray, Option(Id(Message))) ->
      Result(Id(Message), ApiError),
    receive: fn(Option(Id(Contact)), Int) -> Result(List(Delivery), ApiError),
    acknowledge: fn(Id(Message)) -> Result(Nil, ApiError),
    status: fn(Id(Message)) -> Result(MessageState, ApiError),
    audit: fn(Option(Id(Contact)), Int) -> Result(List(AuditEntry), ApiError),
    incidents: fn(Int) -> Result(List(Incident), ApiError),
    subscribe: fn(Subject(Event)) -> Nil,
    health: fn() -> Health,
  )
}
