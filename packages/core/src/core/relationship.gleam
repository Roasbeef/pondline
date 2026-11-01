//// The relationship state machine: one pairing's life from "invitation
//// imported" to "closed", as pure transitions over a value.
////
//// A relationship is the unit the protocol is about (spec §3, §12.1): two
//// pairwise identities, one ratchet session, one route each way, and the
//// local policy that bounds what the peer can do to us. This module is the
//// only place those change. Every transition takes the current value and
//// returns either a `Plan` (the new value, the records to commit with it,
//// and nudges) or a `Refusal` that changes nothing. Time and randomness
//// arrive as arguments (`now`, `Suite.random`), never from the environment,
//// so a test can replay any interleaving and crash point.
////
//// ## Why a transition returns a plan and never bytes
////
//// The ratchet state is a value (`core/crypto/ratchet`), so encrypting a
//// message returns a new state and the ciphertext and touches nothing else
//// (spec §5.3). The plan puts the ciphertext in an `Outbound` record that
//// commits with that state. The scheduler sends only what the committed
//// store holds, so a ciphertext the committed state does not account for can
//// never reach the network, and a crash before the commit loses nothing
//// because the old state was never replaced. The same holds on the way in:
//// the plan carries a `Processed` record, and the scheduler acknowledges an
//// envelope only once that record is committed (`core/plan`).
////
//// ## The phases
////
//// A session exists in exactly three phases, and a peer identity exists
//// exactly where a session does, so both live in a `Link`. `Joining` has no
//// session yet because our own queue is still being created; `Closed` has
//// none because closing drops the keys, so a closed relationship cannot be
//// sent on or received on, by construction rather than by a flag.
////
//// <!-- transitions: relationship.Phase -->
////
//// | state | joined | approve or decline | send | receive | close | raise_budget |
//// | --- | --- | --- | --- | --- | --- | --- |
//// | `Joining` | opens the session: queues the `Initial` frame, becomes `AwaitingAccept` | refused | refused | refused (no session) | `Closed(ClosedLocally)`, nothing to send | refused |
//// | `AwaitingAccept` | refused | refused | refused | `Accept` makes it `Active`; `Reject` and `Close` close it; application messages and receipts are ignored | queues a `Close`, `Closed(ClosedLocally)` | refused |
//// | `PendingApproval` | refused | approve queues `Accept` and becomes `Active`; decline queues `Reject` and becomes `Closed(Declined)` | refused | `Close` closes it; everything else is ignored | queues a `Close`, `Closed(ClosedLocally)` | refused |
//// | `Active` | refused | refused | queues the message | application messages are delivered, held or recorded expired; receipts mark messages received; `Close` closes it; `Accept` and `Reject` are ignored | queues a `Close`, `Closed(ClosedLocally)` | releases held messages the new budget admits |
//// | `Closed` | refused | refused | refused | refused (no session) | refused | refused |
////
//// "Ignored" means the session advanced and the envelope is recorded as
//// processed, but nothing reached the agent: application messages must not
//// reach the host before the relationship is authorized (spec §4.3).
////
//// ## The inbound budget
////
//// Pairing grants a bounded number of inbound application messages, so a
//// pairing is not an unlimited prompt-injection channel (design review,
//// rulings). A message within the budget is `Ready`; one beyond it is
//// `Held`, stored but not shown, until an operator raises the budget with
//// `raise_budget`. The held queue is itself bounded; a message past
//// `max_held_messages` is refused without advancing the ratchet, so the
//// sender never gets a receipt for it, which is accurate.
////
//// ## What the shell does with the result
////
//// On `Ok(plan)`, commit `plan.state` and `plan.records` in one transaction,
//// then act on `plan.effects`. On `Error(refusal)`, commit nothing from the
//// core; for an inbound envelope, write `plan.dropped` so the mailbox can be
//// acknowledged. Receipts are one per stored message in this version;
//// batching them is a later optimization.

import core/crypto/error
import core/crypto/identity.{type Identity, type PublicIdentity}
import core/crypto/pqxdh
import core/crypto/ratchet
import core/crypto/suite.{type Suite}
import core/endpoint.{type CarrierPolicy}
import core/field
import core/frame
import core/id.{type Contact, type Id, type Message as MessageKind}
import core/invitation.{type Invitation}
import core/limits
import core/message.{
  type Message, Accept, Application, Close, Hello, Receipt, Reject,
}
import core/plan.{
  type EnvelopeRef, type Plan, type Record, Audit, ControlOut, CreateQueue,
  Delivered, Expired, Held, In, Out, Outbound, PeerReceived, Plan, Ready,
  ReceiptOut, Released,
}
import core/route.{type Inbox, type Route}
import core/secret
import core/time.{type Instant}
import core/tlv
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

/// The most application messages held over budget at once. New limit,
/// flagged for §11.3.
pub const max_held_messages = 256

/// One pairing, from our side.
pub type Relationship {
  Relationship(
    /// Our local handle for the peer.
    contact: Id(Contact),
    /// Our pairwise identity for this relationship, secrets included.
    us: Identity,
    /// Our own queue: the peer appends to it, we read it.
    inbox: Inbox,
    /// Where the pairing stands. Holds the session, when there is one.
    phase: Phase,
    /// How many inbound application messages the peer may still deliver.
    budget: Budget,
    /// When the relationship was created locally.
    created_at: Instant,
  )
}

/// Where a pairing stands. A session exists exactly in the three middle
/// phases.
pub type Phase {
  /// The joiner has imported an invitation and is creating its own queue.
  /// There is no session: PQXDH needs the reply route this queue provides.
  Joining(
    /// The invitation being redeemed.
    invitation: Invitation,
    /// How we describe ourselves in the `Hello`.
    description: String,
  )

  /// The joiner sent its `Initial` frame and waits for `Accept` or `Reject`.
  AwaitingAccept(link: Link)

  /// The inviter received a valid `Hello`; the operator decides.
  PendingApproval(link: Link)

  /// Both sides have agreed; application messages flow.
  Active(link: Link)

  /// Over. The session is gone and cannot be recovered from this value.
  Closed(reason: CloseReason)
}

/// What a live session needs: the ratchet, where to send, and who the peer
/// is. It exists only inside the phases that have a session.
pub type Link {
  Link(
    /// The Double Ratchet state; an ordinary value.
    session: ratchet.State,
    /// The peer's queue.
    outbound: Route,
    /// The peer's verified identity.
    peer: PublicIdentity,
  )
}

/// The inbound message allowance and the messages waiting on it.
pub type Budget {
  Budget(
    /// The total `Ready` deliveries the pairing may ever make.
    granted: Int,
    /// How many have been made. Never exceeds `granted`.
    used: Int,
    /// Messages stored over budget, oldest first. Non-empty only while
    /// `used == granted`.
    held: List(Id(MessageKind)),
  )
}

/// Why a relationship ended.
pub type CloseReason {
  /// We declined it as the inviter.
  Declined

  /// The inviter declined it and told us.
  RejectedByPeer

  /// The peer closed it.
  ClosedByPeer

  /// We closed it.
  ClosedLocally
}

/// What a party brings to a pairing: its own queue, how it describes itself
/// and the inbound budget it grants.
pub type Terms {
  Terms(
    /// Our queue, created or about to be.
    inbox: Inbox,
    /// Informational, unverified.
    description: String,
    /// The inbound application messages the peer may deliver.
    budget: Int,
  )
}

/// Why a transition did nothing.
pub type Refusal {
  /// The operation is not valid in this phase.
  WrongPhase

  /// `send` outside `Active`.
  NotActive

  /// An inbound frame for a relationship with no session.
  NoSession

  /// The ratchet refused the message: tampering, a replay, or a message that
  /// was never for this session.
  Undecryptable(error: error.Error)

  /// The message authenticated but is not a well-formed message.
  MalformedMessage(error: tlv.TlvError)

  /// A cryptographic step failed on well-formed input.
  CryptoFailed(error: error.Error)

  /// The injected randomness source returned the wrong number of bytes.
  NoRandomness

  /// The invitation's deadline has passed.
  InvitationExpired

  /// The invitation's endpoint is not permitted by the carrier policy.
  Carrier(error: endpoint.EndpointError)

  /// The padded message would exceed the largest bucket.
  TooLarge

  /// The payload exceeds `message.max_payload_bytes`.
  PayloadTooLarge

  /// The content type exceeds `message.max_content_type_bytes`.
  ContentTypeTooLong

  /// A lifetime or budget increase that is not positive.
  NotPositive

  /// Over budget with `max_held_messages` already held.
  HeldFull
}

/// A budget granting `granted` messages, none used. A negative grant is
/// zero.
///
/// ## Examples
///
/// ```gleam
/// relationship.budget(3)
/// // -> Budget(3, 0, [])
/// ```
pub fn budget(granted: Int) -> Budget {
  Budget(granted: int.max(granted, 0), used: 0, held: [])
}

/// Starts a relationship from an invitation: refuses an expired invitation
/// or an endpoint the policy does not permit, makes a fresh pairwise
/// identity, and asks the shell to create our queue. No session exists
/// until `joined`.
///
/// ## Examples
///
/// ```gleam
/// relationship.join(suite, invitation, endpoint.TorOnly, terms, now)
/// // -> Ok(Plan(Relationship(phase: Joining(..)), [], [CreateQueue(..)]))
/// ```
pub fn join(
  suite: Suite,
  invitation: Invitation,
  policy: CarrierPolicy,
  terms: Terms,
  now: Instant,
) -> Result(Plan(Relationship), Refusal) {
  use Nil <- result.try(check_unexpired(invitation.expires_at, now))
  use _admitted <- result.try(
    endpoint.admit(invitation.route.endpoint, policy)
    |> result.map_error(Carrier),
  )
  use us <- result.try(
    identity.generate(suite)
    |> result.map_error(CryptoFailed),
  )
  use contact <- result.try(fresh(suite))

  let phase = Joining(invitation:, description: terms.description)
  let relationship =
    Relationship(
      contact:,
      us:,
      inbox: terms.inbox,
      phase:,
      budget: budget(terms.budget),
      created_at: now,
    )

  Ok(
    Plan(state: relationship, records: [], effects: [CreateQueue(terms.inbox)]),
  )
}

/// Our queue exists: run PQXDH against the invitation's bundle, with a
/// `Hello` naming the invitation and our reply route as the first ratchet
/// message, and queue the `Initial` frame for the invitation's route. The
/// frame's retention deadline is the invitation's own.
///
/// ## Examples
///
/// ```gleam
/// relationship.joined(suite, joining, now)
/// // -> Ok(Plan(Relationship(phase: AwaitingAccept(..)), [Outbound(..)], [Transmit]))
/// ```
pub fn joined(
  suite: Suite,
  relationship: Relationship,
  now: Instant,
) -> Result(Plan(Relationship), Refusal) {
  case relationship.phase {
    Joining(invitation:, description:) ->
      open_session(suite, relationship, invitation, description, now)

    AwaitingAccept(_) | PendingApproval(_) | Active(_) | Closed(_) ->
      Error(WrongPhase)
  }
}

/// Runs the handshake and builds the plan: the session, the `Initial`
/// frame, and the outbox row that carries it.
fn open_session(
  suite: Suite,
  relationship: Relationship,
  invitation: Invitation,
  description: String,
  now: Instant,
) -> Result(Plan(Relationship), Refusal) {
  use Nil <- result.try(check_unexpired(invitation.expires_at, now))
  use envelope_id <- result.try(fresh(suite))

  let hello =
    Hello(
      invitation: invitation.id,
      reply: route.route(relationship.inbox),
      description:,
    )

  // The Hello's plaintext is the first ratchet message of the handshake, so
  // this is the one place it leaves its `Secret`.
  use #(session, initial) <- result.try(
    pqxdh.initiate(
      suite,
      relationship.us,
      invitation.bundle,
      secret.expose(message.encode_hello(hello)),
    )
    |> result.map_error(CryptoFailed),
  )
  use padded <- result.try(
    frame.seal(frame.Initial(initial))
    |> result.replace_error(TooLarge),
  )

  let link =
    Link(
      session:,
      outbound: invitation.route,
      peer: pqxdh.bundle_identity(invitation.bundle),
    )
  let row =
    Outbound(
      envelope: envelope_id,
      route: invitation.route,
      padded:,
      retention_deadline: invitation.expires_at,
      kind: plan.Handshake,
    )

  Ok(
    plan.build(
      Relationship(..relationship, phase: AwaitingAccept(link)),
      relationship.contact,
      [row],
    ),
  )
}

/// The operator approves a pending relationship: queue `Accept` and become
/// `Active`. The ciphertext is produced from the pending session, so the
/// outbox row and the new phase commit together.
///
/// ## Examples
///
/// ```gleam
/// relationship.approve(suite, pending, now)
/// // -> Ok(Plan(Relationship(phase: Active(..)), [Outbound(..)], [Transmit]))
/// ```
pub fn approve(
  suite: Suite,
  relationship: Relationship,
  now: Instant,
) -> Result(Plan(Relationship), Refusal) {
  // Only a pending relationship has an approval to give.
  case relationship.phase {
    PendingApproval(link) -> {
      use #(link, row, _) <- result.try(queue_control(suite, link, Accept, now))

      Ok(
        plan.build(
          Relationship(..relationship, phase: Active(link)),
          relationship.contact,
          [row],
        ),
      )
    }

    Joining(..) | AwaitingAccept(_) | Active(_) | Closed(_) -> Error(WrongPhase)
  }
}

/// The operator declines a pending relationship: queue `Reject`, then drop
/// the session. The `Reject` is encrypted from the session before the phase
/// becomes `Closed`, so its row exists in the plan even though the keys do
/// not exist in the new state.
///
/// ## Examples
///
/// ```gleam
/// relationship.decline(suite, pending, now)
/// // -> Ok(Plan(Relationship(phase: Closed(Declined)), [Outbound(..)], [Transmit]))
/// ```
pub fn decline(
  suite: Suite,
  relationship: Relationship,
  now: Instant,
) -> Result(Plan(Relationship), Refusal) {
  // Only a pending relationship has a decision to refuse.
  case relationship.phase {
    PendingApproval(link) -> {
      use #(_, row, _) <- result.try(queue_control(suite, link, Reject, now))

      Ok(
        plan.build(
          Relationship(..relationship, phase: Closed(Declined)),
          relationship.contact,
          [row],
        ),
      )
    }

    Joining(..) | AwaitingAccept(_) | Active(_) | Closed(_) -> Error(WrongPhase)
  }
}

/// Closes the relationship from our side: queue a `Close` to the peer
/// (best effort; the row is written before the session is dropped), then
/// become `Closed(ClosedLocally)`. A relationship still `Joining` has no
/// peer to tell and closes with no record.
///
/// ## Examples
///
/// ```gleam
/// relationship.close(suite, active, now)
/// // -> Ok(Plan(Relationship(phase: Closed(ClosedLocally)), [Outbound(..)], [Transmit]))
/// ```
pub fn close(
  suite: Suite,
  relationship: Relationship,
  now: Instant,
) -> Result(Plan(Relationship), Refusal) {
  let closed = Relationship(..relationship, phase: Closed(ClosedLocally))

  // A live session says goodbye first; the others have nothing to say.
  case relationship.phase {
    Joining(..) -> Ok(plan.build(closed, relationship.contact, []))

    AwaitingAccept(link) | PendingApproval(link) | Active(link) -> {
      use #(_, row, _) <- result.try(queue_control(suite, link, Close, now))

      Ok(plan.build(closed, relationship.contact, [row]))
    }

    Closed(_) -> Error(WrongPhase)
  }
}

/// Sends an application message, from `Active` only. The payload and
/// content type are bounded, the lifetime defaults to the retention limit
/// and may be narrowed (never widened), and the plan carries the outbox row
/// and an audit entry holding the plaintext.
///
/// ## Examples
///
/// ```gleam
/// relationship.send(suite, active, now, "text/plain", <<"hi">>, None, None)
/// // -> Ok(Plan(_, [Outbound(..), Audit(..)], [Transmit]))
/// ```
pub fn send(
  suite: Suite,
  relationship: Relationship,
  now: Instant,
  content_type: String,
  payload: BitArray,
  in_reply_to: Option(Id(MessageKind)),
  lifetime: Option(Int),
) -> Result(Plan(Relationship), Refusal) {
  use link <- result.try(active_link(relationship))
  use Nil <- result.try(check_sendable(content_type, payload))
  use seconds <- result.try(lifetime_seconds(lifetime))

  let secret_payload = secret.new(payload)
  use #(link, row, sent) <- result.try(seal_message(
    suite,
    link,
    Application(content_type:, payload: secret_payload, in_reply_to:),
    now,
    seconds,
  ))

  let audit =
    Audit(
      direction: Out,
      contact: relationship.contact,
      message: sent,
      content_type:,
      payload: secret_payload,
      at: now,
    )

  Ok(
    plan.build(
      Relationship(..relationship, phase: Active(link)),
      relationship.contact,
      [row, audit],
    ),
  )
}

/// Everything about one inbound envelope that the phase handlers share.
type Arrival {
  Arrival(
    suite: Suite,
    now: Instant,
    relationship: Relationship,
    link: Link,
    records: List(Record),
  )
}

/// Processes one inbound ratchet message for a relationship.
///
/// A failure to decrypt, or a plaintext that is not a message, is a refusal
/// that changes nothing: the caller still holds the old session, so a forged
/// or corrupted envelope cannot burn a message key (spec §8.3). The shell
/// then records the envelope as processed and dropped, and acknowledges it.
/// On success the plan carries a `Processed` record, and what else it
/// carries depends on the phase and the body (the table above).
///
/// ## Examples
///
/// ```gleam
/// relationship.receive(suite, active, now, envelope_ref, ratchet_bytes)
/// // -> Ok(Plan(_, [Processed(..), Delivered(..), Audit(..), Outbound(..)], _))
/// ```
pub fn receive(
  suite: Suite,
  relationship: Relationship,
  now: Instant,
  envelope: EnvelopeRef,
  ratchet_bytes: BitArray,
) -> Result(Plan(Relationship), Refusal) {
  use link <- result.try(session_link(relationship))
  use #(session, plaintext) <- result.try(
    ratchet.decrypt(suite, link.session, ratchet_bytes)
    |> result.map_error(Undecryptable),
  )
  use incoming <- result.try(
    message.decode(plaintext)
    |> result.map_error(MalformedMessage),
  )

  let arrival =
    Arrival(suite:, now:, relationship:, link: Link(..link, session:), records: [
      plan.applied(envelope),
    ])

  // The phase decides what a body means; the session has already advanced.
  case relationship.phase {
    Active(_) -> in_active(arrival, incoming)
    AwaitingAccept(_) -> in_awaiting(arrival, incoming)
    PendingApproval(_) -> in_pending(arrival, incoming)
    Joining(..) | Closed(_) -> Error(NoSession)
  }
}

/// What each body means to an active relationship.
fn in_active(
  arrival: Arrival,
  incoming: Message,
) -> Result(Plan(Relationship), Refusal) {
  case incoming.body {
    Application(content_type:, payload:, in_reply_to:) ->
      store_application(arrival, incoming, content_type, payload, in_reply_to)

    Receipt(of:) ->
      Ok(
        stay(arrival, Active, [
          PeerReceived(arrival.relationship.contact, of),
        ]),
      )

    Accept | Reject -> Ok(stay(arrival, Active, []))

    Close -> Ok(finish(arrival, ClosedByPeer))
  }
}

/// What each body means to a joiner waiting for the inviter's answer.
fn in_awaiting(
  arrival: Arrival,
  incoming: Message,
) -> Result(Plan(Relationship), Refusal) {
  case incoming.body {
    Accept -> Ok(stay(arrival, Active, []))

    Reject -> Ok(finish(arrival, RejectedByPeer))

    Close -> Ok(finish(arrival, ClosedByPeer))

    Application(..) | Receipt(_) -> Ok(stay(arrival, AwaitingAccept, []))
  }
}

/// What each body means to an inviter whose operator has not decided.
/// Application messages MUST NOT reach the host before the relationship is
/// authorized (spec §4.3), so they advance the session and nothing more.
fn in_pending(
  arrival: Arrival,
  incoming: Message,
) -> Result(Plan(Relationship), Refusal) {
  case incoming.body {
    Close -> Ok(finish(arrival, ClosedByPeer))

    Application(..) | Receipt(_) | Accept | Reject ->
      Ok(stay(arrival, PendingApproval, []))
  }
}

/// Stores an application message that arrived in `Active`. An expired one
/// is recorded and never delivered, and earns no receipt, since a receipt
/// tells the sender the message will be acted on. A live one is `Ready`
/// within the budget and `Held` beyond it, and either way is durably stored
/// by this plan, so a receipt is queued in the same transaction.
fn store_application(
  arrival: Arrival,
  incoming: Message,
  content_type: String,
  payload: secret.Secret,
  in_reply_to: Option(Id(MessageKind)),
) -> Result(Plan(Relationship), Refusal) {
  let contact = arrival.relationship.contact
  let audit =
    Audit(
      direction: In,
      contact:,
      message: incoming.id,
      content_type:,
      payload:,
      at: arrival.now,
    )
  let message_id = incoming.id
  let now = arrival.now
  let stored = fn(status) {
    Delivered(
      message: message_id,
      contact:,
      content_type:,
      payload:,
      in_reply_to:,
      status:,
      at: now,
    )
  }

  // Expiry is judged after decryption, because only an authenticated
  // message may advance the session, and it never changes the ratchet.
  case time.is_past(arrival.now, incoming.expires_at) {
    True -> Ok(stay(arrival, Active, [stored(Expired), audit]))

    False -> {
      use #(budget, status) <- result.try(admit(
        arrival.relationship.budget,
        incoming.id,
      ))
      use #(link, receipt, _) <- result.try(seal_message(
        arrival.suite,
        arrival.link,
        Receipt([incoming.id]),
        arrival.now,
        limits.message_retention_seconds,
      ))

      let relationship = Relationship(..arrival.relationship, budget:)
      let arrival = Arrival(..arrival, relationship:, link:)

      Ok(stay(arrival, Active, [stored(status), audit, receipt]))
    }
  }
}

/// Counts one live application message against the budget: `Ready` while
/// there is room, `Held` while the held queue has room, else a refusal.
fn admit(
  budget: Budget,
  message: Id(MessageKind),
) -> Result(#(Budget, plan.DeliveryStatus), Refusal) {
  // Room in the budget delivers; otherwise the message waits if the held
  // queue has room, and is refused if it does not.
  case budget.used < budget.granted {
    True -> Ok(#(Budget(..budget, used: budget.used + 1), Ready))

    False ->
      case list.drop(budget.held, max_held_messages - 1) == [] {
        True ->
          Ok(#(
            Budget(..budget, held: list.append(budget.held, [message])),
            Held,
          ))

        False -> Error(HeldFull)
      }
  }
}

/// An operator raises the inbound budget by `by` messages and the held
/// messages it now admits are released, oldest first. Only an `Active`
/// relationship has anything to release, so any other phase refuses.
///
/// ## Examples
///
/// ```gleam
/// relationship.raise_budget(active, 5)
/// // -> Ok(Plan(_, [Released(contact, held_ids)], [WakeAdapter(contact)]))
/// ```
pub fn raise_budget(
  relationship: Relationship,
  by: Int,
) -> Result(Plan(Relationship), Refusal) {
  use _link <- result.try(active_link(relationship))
  use Nil <- result.try(check_positive(by))

  let current = relationship.budget
  let granted = current.granted + by
  let #(released, still_held) = list.split(current.held, granted - current.used)
  let raised =
    Budget(
      granted:,
      used: current.used + list.length(released),
      held: still_held,
    )

  // Nothing held means nothing to announce.
  let records = case released {
    [] -> []
    [_, ..] -> [Released(relationship.contact, released)]
  }

  Ok(plan.build(
    Relationship(..relationship, budget: raised),
    relationship.contact,
    records,
  ))
}

/// The session as it stays: same phase, new session, extra records after
/// the `Processed` one.
fn stay(
  arrival: Arrival,
  phase: fn(Link) -> Phase,
  extra: List(Record),
) -> Plan(Relationship) {
  plan.build(
    Relationship(..arrival.relationship, phase: phase(arrival.link)),
    arrival.relationship.contact,
    list.append(arrival.records, extra),
  )
}

/// The relationship ends: the advanced session is dropped with the phase.
fn finish(arrival: Arrival, reason: CloseReason) -> Plan(Relationship) {
  plan.build(
    Relationship(..arrival.relationship, phase: Closed(reason)),
    arrival.relationship.contact,
    arrival.records,
  )
}

/// Encrypts one control message under the retention limit.
fn queue_control(
  suite: Suite,
  link: Link,
  body: message.Body,
  now: Instant,
) -> Result(#(Link, Record, Id(MessageKind)), Refusal) {
  seal_message(suite, link, body, now, limits.message_retention_seconds)
}

/// Encrypts one message and builds its outbox row: a fresh message and
/// envelope identifier, the plaintext encoded, ratchet-encrypted, framed and
/// padded. The returned link holds the advanced session, and the row holds
/// the only copy of the ciphertext, so the pair must be committed together.
/// The row's retention deadline is the message's own `expires_at`.
fn seal_message(
  suite: Suite,
  link: Link,
  body: message.Body,
  now: Instant,
  lifetime: Int,
) -> Result(#(Link, Record, Id(MessageKind)), Refusal) {
  use message_id <- result.try(fresh(suite))
  use envelope_id <- result.try(fresh(suite))

  let expires_at = time.add(now, lifetime)
  let plaintext =
    message.encode(message.Message(id: message_id, expires_at:, body:))

  // Encoding the plaintext is the one place the message leaves its `Secret`
  // on the way out, and the ratchet is the only thing that sees it.
  use #(session, ciphertext) <- result.try(
    ratchet.encrypt(suite, link.session, secret.expose(plaintext))
    |> result.map_error(CryptoFailed),
  )
  use padded <- result.try(
    frame.seal(frame.Ratchet(ciphertext))
    |> result.replace_error(TooLarge),
  )

  let row =
    Outbound(
      envelope: envelope_id,
      route: link.outbound,
      padded:,
      retention_deadline: expires_at,
      kind: outbound_kind(body, message_id),
    )

  Ok(#(Link(..link, session:), row, message_id))
}

/// Which outbox kind a body is, so the store updates the right state when
/// the mailbox acknowledges storage.
fn outbound_kind(
  body: message.Body,
  message_id: Id(MessageKind),
) -> plan.OutboundKind {
  case body {
    Application(..) -> plan.ApplicationOut(message_id)
    Receipt(_) -> ReceiptOut(message_id)
    Accept | Reject | Close -> ControlOut(message_id)
  }
}

/// The session of a phase that has one.
fn session_link(relationship: Relationship) -> Result(Link, Refusal) {
  case relationship.phase {
    AwaitingAccept(link) | PendingApproval(link) | Active(link) -> Ok(link)
    Joining(..) | Closed(_) -> Error(NoSession)
  }
}

/// The session of an active relationship, or `NotActive`.
fn active_link(relationship: Relationship) -> Result(Link, Refusal) {
  case relationship.phase {
    Active(link) -> Ok(link)

    Joining(..) | AwaitingAccept(_) | PendingApproval(_) | Closed(_) ->
      Error(NotActive)
  }
}

fn fresh(suite: Suite) -> Result(Id(kind), Refusal) {
  field.fresh_id(suite)
  |> result.replace_error(NoRandomness)
}

fn check_unexpired(deadline: Instant, now: Instant) -> Result(Nil, Refusal) {
  case time.is_past(now, deadline) {
    True -> Error(InvitationExpired)
    False -> Ok(Nil)
  }
}

/// Refuses a content type or payload over its bound.
fn check_sendable(
  content_type: String,
  payload: BitArray,
) -> Result(Nil, Refusal) {
  case message.content_type_fits(content_type), message.payload_fits(payload) {
    True, True -> Ok(Nil)
    False, _ -> Error(ContentTypeTooLong)
    True, False -> Error(PayloadTooLarge)
  }
}

fn check_positive(amount: Int) -> Result(Nil, Refusal) {
  case amount >= 1 {
    True -> Ok(Nil)
    False -> Error(NotPositive)
  }
}

/// A message's lifetime: the retention limit unless the caller narrows it.
fn lifetime_seconds(lifetime: Option(Int)) -> Result(Int, Refusal) {
  case lifetime {
    None -> Ok(limits.message_retention_seconds)

    Some(seconds) ->
      check_positive(seconds)
      |> result.map(fn(_) { int.min(seconds, limits.message_retention_seconds) })
  }
}
