//// What a transition hands back: the new durable state, the records to
//// write in the same transaction, and nudges for the shell.
////
//// This is where "no send before commit" and "no ack before commit" stop
//// being rules about call order and become properties of where bytes come
//// from (spec §8.2, §8.3, §13.1). A transition never produces bytes for the
//// network. Ciphertext exists in exactly one place, an `Outbound` record,
//// which the shell commits together with the new state. A separate delivery
//// scheduler transmits only outbox rows it reads back from the committed
//// store, and acknowledges to the mailbox only envelopes the committed store
//// holds a `Processed` record for. Nothing in a `Plan` is something the
//// shell could send or acknowledge directly, so a shell that skips the
//// commit has nothing to send, and a crash at any point before the commit
//// leaves the old state and no trace of the new.
////
//// ## Records and effects
////
//// A `Record` is data to persist. An `Effect` is a nudge that carries no
//// data: wake the scheduler, wake the adapter, or create a queue. Losing
//// an effect is harmless, because the scheduler and the adapter work from
//// the store, and the shell creates a queue again on restart from the
//// persisted state. That is why effects are derived from the records and
//// never the reverse.
////
//// One refusal deserves saying plainly. `relationship.HeldFull` makes the
//// shell drop and acknowledge a legitimate message, because the held queue
//// is bounded and the message cannot be stored. The sender gets no receipt
//// for it, which is accurate: a receipt means durably stored.
////
//// A `Processed` record names an envelope by identifier and digest, and the
//// shell skips an envelope only when both match, so a corrupted copy that
//// was dropped cannot cause a good retransmit under the same identifier to
//// be dropped as a duplicate.
////
//// A transition that refuses returns an error and no plan, which is how
//// "a refusal changes nothing" is typed: there is no state to commit. For
//// an envelope the core refused to process, the shell writes the `Processed`
//// record itself with `dropped`, because the mailbox must still be
//// acknowledged once the drop is durable.

import core/envelope.{type Padded}
import core/id.{
  type Contact, type Envelope, type Id, type Message as MessageKind, type Queue,
}
import core/route.{type Inbox, type Route}
import core/secret.{type Secret}
import core/time.{type Instant}
import gleam/list
import gleam/option.{type Option}

/// A new state with the records and nudges that go with it.
pub type Plan(state) {
  Plan(
    /// The state to store, replacing the one the transition read.
    state: state,
    /// Written in the same transaction as `state`, in order.
    records: List(Record),
    /// Nudges to send after the commit. Carry no ciphertext.
    effects: List(Effect),
  )
}

/// The envelope being processed: which queue it came from, its identifier,
/// and the digest of its stored bytes, so a `Processed` record names the
/// exact ciphertext it covers.
pub type EnvelopeRef {
  EnvelopeRef(
    /// The queue it was fetched from.
    queue: Id(Queue),
    /// Its identifier within that queue.
    envelope: Id(Envelope),
    /// SHA-256 of the stored padded bytes, computed by the shell.
    digest: BitArray,
  )
}

/// Data to write in the plan's transaction.
pub type Record {
  /// An immutable ciphertext for the outbox. The scheduler retries these
  /// exact bytes and never re-encrypts (spec §8.2).
  Outbound(
    /// The identifier the mailbox deduplicates retries by.
    envelope: Id(Envelope),
    /// Where to send it.
    route: Route,
    /// The padded ciphertext.
    padded: Padded,
    /// The mailbox may discard it after this instant.
    retention_deadline: Instant,
    /// What it is, so the store can update the right message state.
    kind: OutboundKind,
  )

  /// An inbound envelope has been fully handled. The scheduler may
  /// acknowledge it to the mailbox once this is committed, and the shell
  /// answers a redelivery of it by acknowledging without calling the core.
  Processed(
    /// The queue it came from.
    queue: Id(Queue),
    /// Its identifier.
    envelope: Id(Envelope),
    /// The digest of the bytes handled.
    digest: BitArray,
    /// Whether it changed state.
    outcome: ProcessedOutcome,
  )

  /// An application message stored for the agent, with the state it is in.
  Delivered(
    /// The sender's identifier for it.
    message: Id(MessageKind),
    /// The relationship it arrived on.
    contact: Id(Contact),
    /// The sender's content type.
    content_type: String,
    /// The plaintext, held as a `Secret` so a rendered record never prints
    /// it.
    payload: Secret,
    /// The message it answers, if any.
    in_reply_to: Option(Id(MessageKind)),
    /// Whether the agent may see it.
    status: DeliveryStatus,
    /// When it was processed.
    at: Instant,
  )

  /// Held messages the operator's raised budget now admits, oldest first.
  Released(
    /// The relationship.
    contact: Id(Contact),
    /// The messages that become `Ready`.
    messages: List(Id(MessageKind)),
  )

  /// The peer's receipt: these outbound messages are `ReceivedByPeer`
  /// (spec §7.2).
  PeerReceived(
    /// The relationship.
    contact: Id(Contact),
    /// The outbound messages the peer says it stored.
    messages: List(Id(MessageKind)),
  )

  /// An entry in the plaintext audit log the operator reads. Written for
  /// every application message in or out.
  Audit(
    /// Which way the message went.
    direction: Direction,
    /// The relationship.
    contact: Id(Contact),
    /// The message.
    message: Id(MessageKind),
    /// Its content type.
    content_type: String,
    /// Its plaintext, as a `Secret`.
    payload: Secret,
    /// When it was processed or sent.
    at: Instant,
  )
}

/// What an outbox row is.
pub type OutboundKind {
  /// The `Initial` frame that opens a relationship.
  Handshake

  /// An application message.
  ApplicationOut(message: Id(MessageKind))

  /// A receipt. Receipts never request receipts.
  ReceiptOut(message: Id(MessageKind))

  /// An `Accept`, `Reject` or `Close`.
  ControlOut(message: Id(MessageKind))
}

/// Whether handling an envelope changed state.
pub type ProcessedOutcome {
  /// It advanced the session or consumed an offer.
  Applied

  /// It was refused or ignored and changed nothing, but is done with: the
  /// mailbox must still be acknowledged.
  Dropped
}

/// Whether the agent may see a stored application message.
pub type DeliveryStatus {
  /// Within the budget: the agent may consume it.
  Ready

  /// Over the budget: stored, not shown, released only by an operator
  /// raising the budget.
  Held

  /// Past its `expires_at`: recorded for audit, never actionable.
  Expired
}

/// The direction of an audit entry.
pub type Direction {
  /// Received from the peer.
  In

  /// Sent to the peer.
  Out
}

/// A nudge for the shell after the commit. Only `CreateQueue` carries data:
/// the inbox the shell must create. None carries ciphertext.
pub type Effect {
  /// There is committed outbox work: wake the delivery scheduler.
  Transmit

  /// There is something new for the local adapter.
  WakeAdapter(contact: Id(Contact))

  /// Create this queue at its mailbox. Carries the inbox, with its
  /// capabilities, because creating a queue registers them. The shell re-derives the need from
  /// the persisted state after a restart, so the nudge may be lost.
  CreateQueue(inbox: Inbox)
}

/// A plan whose effects are derived from its records: `Transmit` when it
/// writes outbox rows, `WakeAdapter` when something becomes visible to the
/// agent.
///
/// ## Examples
///
/// ```gleam
/// plan.build(state, contact, [])
/// // -> Plan(state, [], [])
/// ```
pub fn build(
  state: state,
  contact: Id(Contact),
  records: List(Record),
) -> Plan(state) {
  // Outbox rows need the scheduler; anything the agent may now see needs
  // the adapter. Neither nudge carries data.
  let transmit = case list.any(records, is_outbound) {
    True -> [Transmit]
    False -> []
  }

  // The adapter is nudged only for what is actionable, never for held or
  // expired messages.
  let wake = case list.any(records, is_visible) {
    True -> [WakeAdapter(contact)]
    False -> []
  }

  Plan(state:, records:, effects: list.append(transmit, wake))
}

/// Whether a record is an outbox row.
fn is_outbound(record: Record) -> Bool {
  case record {
    Outbound(..) -> True
    Processed(..)
    | Delivered(..)
    | Released(..)
    | PeerReceived(..)
    | Audit(..) -> False
  }
}

/// Whether a record makes something newly visible to the agent: a message
/// the agent may consume now.
fn is_visible(record: Record) -> Bool {
  case record {
    Delivered(status: Ready, ..) | Released(..) -> True
    Delivered(status: Held, ..)
    | Delivered(status: Expired, ..)
    | Outbound(..)
    | Processed(..)
    | PeerReceived(..)
    | Audit(..) -> False
  }
}

/// The record a shell writes for an envelope the core refused or ignored:
/// the drop is durable, then the mailbox is acknowledged.
///
/// ## Examples
///
/// ```gleam
/// plan.dropped(EnvelopeRef(queue, envelope, digest))
/// // -> Processed(queue, envelope, digest, Dropped)
/// ```
pub fn dropped(ref: EnvelopeRef) -> Record {
  Processed(
    queue: ref.queue,
    envelope: ref.envelope,
    digest: ref.digest,
    outcome: Dropped,
  )
}

/// The record for an envelope that was handled and changed state.
///
/// ## Examples
///
/// ```gleam
/// plan.applied(EnvelopeRef(queue, envelope, digest))
/// // -> Processed(queue, envelope, digest, Applied)
/// ```
pub fn applied(ref: EnvelopeRef) -> Record {
  Processed(
    queue: ref.queue,
    envelope: ref.envelope,
    digest: ref.digest,
    outcome: Applied,
  )
}
