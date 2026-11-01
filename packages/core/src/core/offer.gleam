//// The inviter's side of an invitation: the stored offer that holds the
//// prekey secrets and decides, exactly once, who consumes it.
////
//// An invitation file is a bearer credential, so anyone holding it can try
//// to redeem it, and two of them can race. The offer is the single
//// serialization point (spec §4.4, §13.1 "no invitation double
//// consumption"): the first valid `Hello` turns it from `Open` into
//// `Consumed` and produces the only relationship, in one transition that the
//// shell commits atomically. After that the prekey secrets are gone, and not
//// merely unused: `Consumed` has no field that could hold them, so a second
//// claimant cannot succeed by any code path, only be refused.
////
//// ## Life of an offer
////
//// <!-- transitions: offer.OfferPhase -->
////
//// | state | provisioned | redeem | expire |
//// | --- | --- | --- | --- |
//// | `Provisioning` | becomes `Open` | refused: the invitation has not been exported yet | becomes `Expired` once the deadline passes |
//// | `Open` | unchanged | a valid, authenticated `Hello` for this invitation consumes it; anything else is refused and changes nothing | becomes `Expired` once the deadline passes |
//// | `Consumed` | unchanged | the same initial message again is a `Duplicate`; any other is refused | unchanged |
//// | `Expired` | unchanged | refused | unchanged |
////
//// ## What a redemption checks
////
//// The initial message must name this offer's bundle (`pqxdh.respond`
//// checks the commitment), authenticate under the keys derived from the
//// prekey secrets, and decrypt to a `Hello` that names this invitation. The
//// `Hello`'s reply route must be an endpoint the carrier policy admits, so a
//// joiner cannot make the daemon connect to a loopback port or any carrier
//// the operator did not allow. A refusal of any kind changes nothing, so a
//// hostile or corrupted initial message cannot spend the invitation.
////
//// A retry after a lost acknowledgment arrives with the same bytes. The
//// consumed offer remembers the initiator's fingerprint and the digest of the
//// initial message, so that retry is recognised and answered with
//// `Duplicate`; the shell only acknowledges. A different initial message,
//// even from the same initiator, is refused.

import core/crypto/error
import core/crypto/identity.{type Identity}
import core/crypto/keys.{type KemSecret, type X25519Secret}
import core/crypto/pqxdh.{type InitialMessage, Prekeys, Response}
import core/crypto/suite.{type Suite}
import core/endpoint.{type CarrierPolicy}
import core/field
import core/id.{type Contact, type Id, type Invitation as InvitationKind}
import core/invitation.{type Invitation, Invitation}
import core/limits
import core/message
import core/plan.{type EnvelopeRef, type Plan, CreateQueue, Plan}
import core/relationship.{
  type Relationship, type Terms, Link, PendingApproval, Relationship,
}
import core/route
import core/time.{type Instant}
import core/tlv
import gleam/result

/// A stored invitation, from the inviter's side. The identifier is kept in
/// every phase so the store can key on it after the secrets are gone.
pub type Offer {
  Offer(
    /// The invitation's identifier.
    id: Id(InvitationKind),
    /// Where the offer stands.
    phase: OfferPhase,
  )
}

/// Where an offer stands. Secrets exist exactly in the first two phases.
pub type OfferPhase {
  /// Prekeys exist and our queue is being created. The invitation must not
  /// be handed out yet: a joiner could append to a queue that is not there.
  Provisioning(stock: Stock)

  /// The queue exists and the invitation may be exported and redeemed.
  Open(stock: Stock)

  /// A valid `Hello` consumed it. The prekey secrets are gone; what remains
  /// recognises a retry of the same initial message.
  Consumed(
    /// The relationship it produced.
    contact: Id(Contact),
    /// SHA-256 of the initiator's encoded public identity.
    initiator: BitArray,
    /// SHA-256 of the encoded initial message that consumed it.
    initial_digest: BitArray,
  )

  /// Its deadline passed unused. The prekey secrets are gone.
  Expired
}

/// What an open offer holds, secrets included.
pub type Stock {
  Stock(
    /// Our pairwise identity for the relationship this offer creates.
    identity: Identity,
    /// The signed prekey's secret half.
    spk_secret: X25519Secret,
    /// The post-quantum prekey's secret half.
    pqspk_secret: KemSecret,
    /// The file we export; holds the public bundle and our route.
    invitation: Invitation,
    /// Our queue, the one the invitation's route points at.
    inbox: route.Inbox,
    /// Whether redemption needs an operator.
    approval: Approval,
    /// The inbound budget the new relationship starts with.
    budget: Int,
  )
}

/// Whether a valid `Hello` makes the relationship `Active` at once or waits
/// for an operator (design review §3: import creates a pending
/// relationship, activation is a deliberate act).
pub type Approval {
  /// Accept without asking: a preapproved invitation.
  AutoApprove

  /// Wait in `PendingApproval` until `relationship.approve` or `decline`.
  OperatorApproves
}

/// What redeeming an initial message produced.
pub type Redemption {
  /// The offer is consumed and a relationship exists. The shell commits the
  /// consumed offer and the plan in one transaction.
  Redeemed(
    /// The consumed offer to store in place of the open one.
    offer: Offer,
    /// The new relationship, with the `Processed` record for the envelope
    /// and, for `AutoApprove`, the queued `Accept`.
    plan: Plan(Relationship),
  )

  /// The same initial message was already consumed: nothing to do but
  /// acknowledge.
  Duplicate
}

/// Why an offer did not change.
pub type Rejection {
  /// The offer is still `Provisioning`.
  NotOpen

  /// The deadline has passed, or the offer is `Expired`.
  OfferExpired

  /// A different claimant, or a different initial message, already
  /// consumed it.
  AlreadyConsumed

  /// The initial message failed a cryptographic check: the wrong bundle, a
  /// forged ciphertext, a bad signature. The error carries no key bytes.
  Crypto(error: error.Error)

  /// The first ratchet message is not a well-formed `Hello`.
  BadHello(error: tlv.TlvError)

  /// The `Hello` names a different invitation.
  WrongInvitation

  /// The `Hello`'s reply endpoint is not permitted by the carrier policy.
  Carrier(error: endpoint.EndpointError)

  /// The `Hello`'s reply route is this offer's own inbox route: a joiner
  /// asking us to reply to ourselves.
  ReplyIsOwnInbox

  /// The description exceeds `message.max_description_bytes`.
  DescriptionTooLong

  /// The relationship transition that follows redemption refused.
  Refused(refusal: relationship.Refusal)

  /// The injected randomness source returned the wrong number of bytes.
  NoRandomness
}

/// Creates an offer: a fresh pairwise identity, fresh prekeys, a fresh
/// invitation identifier and an invitation file valid for
/// `limits.invitation_window_seconds`. The offer is `Provisioning`; the plan
/// asks the shell to create the queue, and `provisioned` opens the offer.
///
/// ## Examples
///
/// ```gleam
/// offer.create(suite, terms, offer.OperatorApproves, now)
/// // -> Ok(Plan(Offer(_, Provisioning(..)), [], [CreateQueue(..)]))
/// ```
pub fn create(
  suite: Suite,
  terms: Terms,
  approval: Approval,
  now: Instant,
) -> Result(Plan(Offer), Rejection) {
  use Nil <- result.try(check_description(terms.description))
  use identity <- result.try(
    identity.generate(suite)
    |> result.map_error(Crypto),
  )
  use prekeys <- result.try(
    pqxdh.generate_prekeys(suite, identity)
    |> result.map_error(Crypto),
  )
  use invitation_id <- result.try(
    field.fresh_id(suite)
    |> result.replace_error(NoRandomness),
  )

  let file =
    Invitation(
      id: invitation_id,
      bundle: prekeys.bundle,
      route: route.route(terms.inbox),
      expires_at: time.add(now, limits.invitation_window_seconds),
      description: terms.description,
    )
  let stock =
    Stock(
      identity:,
      spk_secret: prekeys.spk_secret,
      pqspk_secret: prekeys.pqspk_secret,
      invitation: file,
      inbox: terms.inbox,
      approval:,
      budget: relationship.budget(terms.budget).granted,
    )

  Ok(
    Plan(
      state: Offer(id: invitation_id, phase: Provisioning(stock)),
      records: [],
      effects: [CreateQueue(terms.inbox)],
    ),
  )
}

/// Our queue exists: the offer opens and its invitation may be exported.
/// Idempotent on an offer that is already open or past it.
///
/// ## Examples
///
/// ```gleam
/// offer.provisioned(provisioning)
/// // -> Offer(_, Open(..))
/// ```
pub fn provisioned(offer: Offer) -> Offer {
  case offer.phase {
    Provisioning(stock) -> Offer(..offer, phase: Open(stock))
    Open(_) | Consumed(..) | Expired -> offer
  }
}

/// The invitation file to hand out, once the offer is open.
///
/// ## Examples
///
/// ```gleam
/// offer.invitation(open)
/// // -> Ok(Invitation(..))
/// ```
pub fn invitation(offer: Offer) -> Result(Invitation, Nil) {
  case offer.phase {
    Open(stock) -> Ok(stock.invitation)
    Provisioning(_) | Consumed(..) | Expired -> Error(Nil)
  }
}

/// Retires an unused offer whose deadline has passed, dropping the prekey
/// secrets with it. A consumed or expired offer is unchanged.
///
/// ## Examples
///
/// ```gleam
/// offer.expire(open, later)
/// // -> Offer(_, Expired)
/// ```
pub fn expire(offer: Offer, now: Instant) -> Offer {
  case offer.phase {
    Provisioning(stock) | Open(stock) ->
      case time.is_past(now, stock.invitation.expires_at) {
        True -> Offer(..offer, phase: Expired)
        False -> offer
      }

    Consumed(..) | Expired -> offer
  }
}

/// Redeems an initial message against an offer.
///
/// On success the consumed offer and the new relationship are one result, so
/// the shell commits them together: there is no state in which the offer is
/// consumed and no relationship exists, or the reverse. The relationship is
/// `PendingApproval`, or `Active` with `Accept` queued under `AutoApprove`.
/// Every failure returns a `Rejection` and leaves the offer as it was.
///
/// ## Examples
///
/// ```gleam
/// offer.redeem(suite, open, TorOnly, envelope_ref, initial, now)
/// // -> Ok(Redeemed(consumed, plan))
/// ```
pub fn redeem(
  suite: Suite,
  offer: Offer,
  policy: CarrierPolicy,
  envelope: EnvelopeRef,
  initial: InitialMessage,
  now: Instant,
) -> Result(Redemption, Rejection) {
  case offer.phase {
    Open(stock) ->
      case time.is_past(now, stock.invitation.expires_at) {
        True -> Error(OfferExpired)
        False -> consume(suite, offer, stock, policy, envelope, initial, now)
      }

    Consumed(initiator:, initial_digest:, ..) ->
      recognise_retry(suite, initiator, initial_digest, initial)

    Provisioning(_) -> Error(NotOpen)

    Expired -> Error(OfferExpired)
  }
}

/// Runs the handshake, checks the `Hello` and builds the relationship.
fn consume(
  suite: Suite,
  offer: Offer,
  stock: Stock,
  policy: CarrierPolicy,
  envelope: EnvelopeRef,
  initial: InitialMessage,
  now: Instant,
) -> Result(Redemption, Rejection) {
  let prekeys =
    Prekeys(
      bundle: stock.invitation.bundle,
      spk_secret: stock.spk_secret,
      pqspk_secret: stock.pqspk_secret,
    )

  use Response(state:, plaintext:, ..) <- result.try(
    pqxdh.respond(suite, stock.identity, prekeys, initial)
    |> result.map_error(Crypto),
  )
  use hello <- result.try(
    message.decode_hello(plaintext)
    |> result.map_error(BadHello),
  )
  use Nil <- result.try(check_names(hello.invitation, stock.invitation.id))
  use Nil <- result.try(check_not_ours(hello.reply, stock))
  use _admitted <- result.try(
    endpoint.admit(hello.reply.endpoint, policy)
    |> result.map_error(Carrier),
  )
  use contact <- result.try(
    field.fresh_id(suite)
    |> result.replace_error(NoRandomness),
  )

  let pending =
    Relationship(
      contact:,
      us: stock.identity,
      inbox: stock.inbox,
      phase: PendingApproval(Link(
        session: state,
        outbound: hello.reply,
        peer: initial.identity,
      )),
      budget: relationship.budget(stock.budget),
      created_at: now,
    )

  use settled <- result.try(approve_as_agreed(suite, stock, pending, now))

  let consumed =
    Offer(
      ..offer,
      phase: Consumed(
        contact:,
        initiator: fingerprint(suite, initial),
        initial_digest: digest(suite, initial),
      ),
    )
  let processed = plan.applied(envelope)

  Ok(Redeemed(
    offer: consumed,
    plan: Plan(..settled, records: [processed, ..settled.records]),
  ))
}

/// Applies the offer's approval policy to the pending relationship.
fn approve_as_agreed(
  suite: Suite,
  stock: Stock,
  pending: Relationship,
  now: Instant,
) -> Result(Plan(Relationship), Rejection) {
  case stock.approval {
    AutoApprove ->
      relationship.approve(suite, pending, now)
      |> result.map_error(Refused)

    OperatorApproves -> Ok(plan.build(pending, pending.contact, []))
  }
}

/// A consumed offer answers the same initial message again with
/// `Duplicate` and every other with a refusal.
fn recognise_retry(
  suite: Suite,
  initiator: BitArray,
  initial_digest: BitArray,
  initial: InitialMessage,
) -> Result(Redemption, Rejection) {
  case
    suite.constant_time_equal(initiator, fingerprint(suite, initial))
    && suite.constant_time_equal(initial_digest, digest(suite, initial))
  {
    True -> Ok(Duplicate)
    False -> Error(AlreadyConsumed)
  }
}

/// Refuses a `Hello` that asks us to reply to our own inbox.
fn check_not_ours(reply: route.Route, stock: Stock) -> Result(Nil, Rejection) {
  case reply == route.route(stock.inbox) {
    True -> Error(ReplyIsOwnInbox)
    False -> Ok(Nil)
  }
}

/// Refuses a description the decoders would refuse.
fn check_description(description: String) -> Result(Nil, Rejection) {
  case message.description_fits(description) {
    True -> Ok(Nil)
    False -> Error(DescriptionTooLong)
  }
}

/// Refuses a `Hello` that names some other invitation.
fn check_names(
  named: Id(InvitationKind),
  ours: Id(InvitationKind),
) -> Result(Nil, Rejection) {
  case named == ours {
    True -> Ok(Nil)
    False -> Error(WrongInvitation)
  }
}

fn fingerprint(suite: Suite, initial: InitialMessage) -> BitArray {
  identity.fingerprint(suite, initial.identity)
}

fn digest(suite: Suite, initial: InitialMessage) -> BitArray {
  suite.sha256(pqxdh.encode_initial(initial))
}
