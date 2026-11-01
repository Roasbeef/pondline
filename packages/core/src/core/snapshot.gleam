//// The durable form of a relationship and of an offer: total TLV codecs,
//// so the daemon's store can keep each as one blob.
////
//// What the store holds is what the next transition reads, so these
//// encodings are the boundary where a corrupted or tampered row must be
//// refused rather than half-read (`docs/gleam-style.md` Part IV §2). Every
//// decoder is total and canonical: a bounded input, strictly ordered
//// records, an unknown even type refused, and every nested secret, key,
//// identity and ratchet state rebuilt through its own smart constructor, so
//// a stored value that decodes is one the type system would have accepted
//// fresh. A decoder also re-checks the invariants a transition relies on
//// (`used <= granted`, held messages only at the limit), so a snapshot that
//// could never have been written is not trusted.
////
//// ## Secrets
////
//// A snapshot holds identity secret keys, prekey secrets, queue
//// capabilities and the ratchet state. The encoders return a `Secret`, so
//// the bytes cannot be printed by accident, and the only `secret.expose`
//// calls are the ones that put key material into the record being built.
//// Decoding takes plain bytes (the store hands them over) and rebuilds
//// every secret straight into its wrapper.
////
//// ## Layout
////
//// Both are TLV streams. A relationship: 0 version (1), 2 contact, 4
//// identity, 6 inbox, 8 phase, 10 budget, 12 creation time. An offer: 0
//// version, 2 invitation identifier, 4 phase. A phase record starts with a
//// kind in type 0 and carries only the records its kind owns.

import core/crypto/error
import core/crypto/identity.{type Identity, type PublicIdentity, Identity}
import core/crypto/keys
import core/crypto/ratchet
import core/crypto/suite.{type Suite}
import core/field
import core/id
import core/invitation.{type Invitation}
import core/message
import core/offer.{
  type Approval, type Offer, type OfferPhase, type Stock, AutoApprove, Consumed,
  Expired, Offer, Open, OperatorApproves, Provisioning, Stock,
}
import core/relationship.{
  type Budget, type Link, type Phase, type Relationship, Active, AwaitingAccept,
  Budget, Closed, Joining, Link, PendingApproval, Relationship,
}
import core/route
import core/secret.{type Secret}
import core/tlv
import gleam/list
import gleam/result

/// The format version this module writes and the only one it reads.
pub const format_version = 1

/// The largest snapshot: a ratchet state holding a full skipped-key store,
/// with room for the rest. New limit, flagged for §11.3.
pub const max_snapshot_bytes = 1_048_576

/// The size of a SHA-256 digest, which both consumed-offer fingerprints are.
const digest_bytes = 32

/// Which phase record a relationship's phase is.
type PhaseKind {
  JoiningKind
  AwaitingKind
  PendingKind
  ActiveKind
  ClosedKind
}

/// Which phase record an offer's phase is.
type OfferKind {
  ProvisioningKind
  OpenKind
  ConsumedKind
  ExpiredKind
}

/// A relationship as a secret blob.
///
/// ## Examples
///
/// ```gleam
/// snapshot.decode_relationship(suite, secret.expose(snapshot.encode_relationship(rel)))
/// // -> Ok(rel)
/// ```
pub fn encode_relationship(relationship: Relationship) -> Secret {
  tlv.new()
  |> tlv.put(0, tlv.encode_u8(format_version))
  |> tlv.put(2, id.to_bytes(relationship.contact))
  |> tlv.put(4, encode_identity(relationship.us))
  |> tlv.put(6, route.encode_inbox(relationship.inbox))
  |> tlv.put(8, encode_phase(relationship.phase))
  |> tlv.put(10, encode_budget(relationship.budget))
  |> tlv.put(12, field.encode_instant(relationship.created_at))
  |> tlv.encode
  |> secret.new
}

/// Reads a relationship snapshot. Total.
///
/// ## Examples
///
/// ```gleam
/// snapshot.decode_relationship(suite, <<>>)
/// // -> Error(tlv.MissingRequired(0))
/// ```
pub fn decode_relationship(
  suite: Suite,
  bytes: BitArray,
) -> Result(Relationship, tlv.TlvError) {
  tlv.decode(bytes, max_bytes: max_snapshot_bytes, with: {
    use _version <- tlv.required(0, version_field())
    use contact <- tlv.required(2, field.id())
    use us <- tlv.required(4, tlv.nested(identity_decoder(suite)))
    use inbox <- tlv.required(6, tlv.nested(route.inbox_decoder()))
    use phase <- tlv.required(8, tlv.nested(phase_decoder(suite)))
    use budget <- tlv.required(10, tlv.nested(budget_decoder()))
    use created_at <- tlv.required(12, field.instant())

    tlv.success(Relationship(
      contact:,
      us:,
      inbox:,
      phase:,
      budget:,
      created_at:,
    ))
  })
}

/// An offer as a secret blob.
///
/// ## Examples
///
/// ```gleam
/// snapshot.decode_offer(suite, secret.expose(snapshot.encode_offer(offer)))
/// // -> Ok(offer)
/// ```
pub fn encode_offer(offer: Offer) -> Secret {
  tlv.new()
  |> tlv.put(0, tlv.encode_u8(format_version))
  |> tlv.put(2, id.to_bytes(offer.id))
  |> tlv.put(4, encode_offer_phase(offer.phase))
  |> tlv.encode
  |> secret.new
}

/// Reads an offer snapshot. Total.
///
/// ## Examples
///
/// ```gleam
/// snapshot.decode_offer(suite, <<>>)
/// // -> Error(tlv.MissingRequired(0))
/// ```
pub fn decode_offer(
  suite: Suite,
  bytes: BitArray,
) -> Result(Offer, tlv.TlvError) {
  tlv.decode(bytes, max_bytes: max_snapshot_bytes, with: {
    use _version <- tlv.required(0, version_field())
    use id <- tlv.required(2, field.id())
    use phase <- tlv.required(4, tlv.nested(offer_phase_decoder(suite)))

    tlv.success(Offer(id:, phase:))
  })
}

/// Accepts only `format_version`.
fn version_field() -> tlv.Field(Int) {
  tlv.try_map(tlv.u8, fn(version) {
    case version == format_version {
      True -> Ok(version)
      False -> Error(Nil)
    }
  })
}

// ------------------------------------------------------------- identity

/// Both secret keys and the public identity, each in its own record.
fn encode_identity(owner: Identity) -> BitArray {
  tlv.new()
  |> tlv.put(0, keys.expose_ed25519_secret(owner.signing))
  |> tlv.put(2, keys.expose_x25519_secret(owner.agreement))
  |> tlv.put(4, identity.encode_public(owner.public))
  |> tlv.encode
}

/// The two secret keys and the verified public identity.
fn identity_decoder(suite: Suite) -> tlv.Decoder(Identity) {
  use signing <- tlv.required(0, key_field(keys.ed25519_secret))
  use agreement <- tlv.required(2, key_field(keys.x25519_secret))
  use public <- tlv.required(4, public_identity_field(suite))

  tlv.success(Identity(signing:, agreement:, public:))
}

/// A key rebuilt through its smart constructor, which checks the size and
/// wraps it in a `Secret`.
fn key_field(make: fn(BitArray) -> Result(key, error.Error)) -> tlv.Field(key) {
  tlv.try_map(tlv.bytes, fn(raw) { result.replace_error(make(raw), Nil) })
}

/// A public identity whose binding signature verifies.
fn public_identity_field(suite: Suite) -> tlv.Field(PublicIdentity) {
  tlv.fixed_bytes(identity.public_identity_bytes)
  |> tlv.try_map(fn(raw) {
    identity.decode_public(suite, raw)
    |> result.replace_error(Nil)
  })
}

// --------------------------------------------------------- relationship

/// A relationship phase as a kind record plus the records its kind owns.
fn encode_phase(phase: Phase) -> BitArray {
  case phase {
    Joining(invitation:, description:) ->
      tlv.new()
      |> tlv.put(0, tlv.encode_u8(0))
      |> tlv.put(2, secret.expose(invitation.encode(invitation)))
      |> tlv.put(4, tlv.encode_text(description))
      |> tlv.encode

    AwaitingAccept(link) -> encode_link(tlv.encode_u8(1), link)

    PendingApproval(link) -> encode_link(tlv.encode_u8(2), link)

    Active(link) -> encode_link(tlv.encode_u8(3), link)

    Closed(reason) ->
      tlv.new()
      |> tlv.put(0, tlv.encode_u8(4))
      |> tlv.put(2, tlv.encode_u8(close_reason_code(reason)))
      |> tlv.encode
  }
}

/// A session-holding phase: its kind, then the link's three records. The
/// ratchet state is the one place a state's bytes leave their `Secret`.
fn encode_link(kind: BitArray, link: Link) -> BitArray {
  tlv.new()
  |> tlv.put(0, kind)
  |> tlv.put(2, secret.expose(ratchet.encode_state(link.session)))
  |> tlv.put(4, route.encode(link.outbound))
  |> tlv.put(6, identity.encode_public(link.peer))
  |> tlv.encode
}

/// The stored number of a close reason.
fn close_reason_code(reason: relationship.CloseReason) -> Int {
  case reason {
    relationship.Declined -> 0
    relationship.RejectedByPeer -> 1
    relationship.ClosedByPeer -> 2
    relationship.ClosedLocally -> 3
  }
}

fn phase_decoder(suite: Suite) -> tlv.Decoder(Phase) {
  use kind <- tlv.required(0, phase_kind())
  use phase <- phase_body(suite, kind)

  tlv.success(phase)
}

/// Reads the records that belong to a phase kind and no others, so a record
/// of another kind is an unknown type and an even one fails closed.
fn phase_body(
  suite: Suite,
  kind: PhaseKind,
  next: fn(Phase) -> tlv.Decoder(a),
) -> tlv.Decoder(a) {
  // The kind names which records follow.
  case kind {
    JoiningKind -> {
      use invitation <- tlv.required(2, invitation_field(suite))
      use description <- tlv.required(
        4,
        field.bounded_text(message.max_description_bytes),
      )

      next(Joining(invitation:, description:))
    }

    AwaitingKind -> {
      use link <- link_records(suite)

      next(AwaitingAccept(link))
    }

    PendingKind -> {
      use link <- link_records(suite)

      next(PendingApproval(link))
    }

    ActiveKind -> {
      use link <- link_records(suite)

      next(Active(link))
    }

    ClosedKind -> {
      use reason <- tlv.required(2, close_reason_field())

      next(Closed(reason))
    }
  }
}

/// The three records every session-holding phase carries.
fn link_records(
  suite: Suite,
  next: fn(Link) -> tlv.Decoder(a),
) -> tlv.Decoder(a) {
  use session <- tlv.required(2, session_field())
  use outbound <- tlv.required(4, tlv.nested(route.decoder()))
  use peer <- tlv.required(6, public_identity_field(suite))

  next(Link(session:, outbound:, peer:))
}

fn session_field() -> tlv.Field(ratchet.State) {
  tlv.try_map(tlv.bytes, fn(raw) {
    ratchet.decode_state(raw)
    |> result.replace_error(Nil)
  })
}

fn invitation_field(suite: Suite) -> tlv.Field(Invitation) {
  tlv.try_map(tlv.bytes, fn(raw) {
    invitation.decode(suite, raw)
    |> result.replace_error(Nil)
  })
}

/// The phase discriminator; an unassigned number is refused.
fn phase_kind() -> tlv.Field(PhaseKind) {
  tlv.try_map(tlv.u8, fn(number) {
    case number {
      0 -> Ok(JoiningKind)
      1 -> Ok(AwaitingKind)
      2 -> Ok(PendingKind)
      3 -> Ok(ActiveKind)
      4 -> Ok(ClosedKind)
      _ -> Error(Nil)
    }
  })
}

/// The close reason's stored number; an unassigned one is refused.
fn close_reason_field() -> tlv.Field(relationship.CloseReason) {
  tlv.try_map(tlv.u8, fn(number) {
    case number {
      0 -> Ok(relationship.Declined)
      1 -> Ok(relationship.RejectedByPeer)
      2 -> Ok(relationship.ClosedByPeer)
      3 -> Ok(relationship.ClosedLocally)
      _ -> Error(Nil)
    }
  })
}

// --------------------------------------------------------------- budget

/// A budget as granted, used and the held identifiers.
fn encode_budget(budget: Budget) -> BitArray {
  tlv.new()
  |> tlv.put(0, tlv.encode_u64(budget.granted))
  |> tlv.put(2, tlv.encode_u64(budget.used))
  |> tlv.put(4, tlv.encode_items(list.map(budget.held, id.to_bytes)))
  |> tlv.encode
}

/// Reads a budget and refuses one the transitions could not have produced:
/// more used than granted, or messages held while there is still room.
fn budget_decoder() -> tlv.Decoder(Budget) {
  use granted <- tlv.required(0, tlv.u64)
  use used <- tlv.required(2, tlv.u64)
  use held <- tlv.required(4, held_field())

  // The invariants the transitions maintain, re-checked on the way in.
  case used <= granted && { held == [] || used == granted } {
    True -> tlv.success(Budget(granted:, used:, held:))
    False -> tlv.fail(tlv.InvalidField(2))
  }
}

/// At most `max_held_messages` held identifiers.
fn held_field() -> tlv.Field(List(id.Id(id.Message))) {
  tlv.items(id.id_bytes, field.id())
  |> tlv.try_map(fn(held) {
    case list.drop(held, relationship.max_held_messages) == [] {
      True -> Ok(held)
      False -> Error(Nil)
    }
  })
}

// ---------------------------------------------------------------- offer

/// An offer phase as a kind record plus the records its kind owns.
fn encode_offer_phase(phase: OfferPhase) -> BitArray {
  case phase {
    Provisioning(stock) -> encode_stock(tlv.encode_u8(0), stock)

    Open(stock) -> encode_stock(tlv.encode_u8(1), stock)

    Consumed(contact:, initiator:, initial_digest:) ->
      tlv.new()
      |> tlv.put(0, tlv.encode_u8(2))
      |> tlv.put(2, id.to_bytes(contact))
      |> tlv.put(4, initiator)
      |> tlv.put(6, initial_digest)
      |> tlv.encode

    Expired ->
      tlv.new()
      |> tlv.put(0, tlv.encode_u8(3))
      |> tlv.encode
  }
}

/// A secret-holding offer phase: its kind, then everything the offer needs
/// to answer a redemption.
fn encode_stock(kind: BitArray, stock: Stock) -> BitArray {
  tlv.new()
  |> tlv.put(0, kind)
  |> tlv.put(2, encode_identity(stock.identity))
  |> tlv.put(4, keys.expose_x25519_secret(stock.spk_secret))
  |> tlv.put(6, keys.expose_kem_secret(stock.pqspk_secret))
  |> tlv.put(8, secret.expose(invitation.encode(stock.invitation)))
  |> tlv.put(10, route.encode_inbox(stock.inbox))
  |> tlv.put(12, tlv.encode_u8(approval_code(stock.approval)))
  |> tlv.put(14, tlv.encode_u64(stock.budget))
  |> tlv.encode
}

fn approval_code(approval: Approval) -> Int {
  case approval {
    AutoApprove -> 0
    OperatorApproves -> 1
  }
}

fn offer_phase_decoder(suite: Suite) -> tlv.Decoder(OfferPhase) {
  use kind <- tlv.required(0, offer_kind())
  use phase <- offer_body(suite, kind)

  tlv.success(phase)
}

/// Reads the records that belong to an offer phase kind and no others.
fn offer_body(
  suite: Suite,
  kind: OfferKind,
  next: fn(OfferPhase) -> tlv.Decoder(a),
) -> tlv.Decoder(a) {
  // The kind names which records follow; secrets exist only in the first two.
  case kind {
    ProvisioningKind -> {
      use stock <- stock_records(suite)

      next(Provisioning(stock))
    }

    OpenKind -> {
      use stock <- stock_records(suite)

      next(Open(stock))
    }

    ConsumedKind -> {
      use contact <- tlv.required(2, field.id())
      use initiator <- tlv.required(4, tlv.fixed_bytes(digest_bytes))
      use initial_digest <- tlv.required(6, tlv.fixed_bytes(digest_bytes))

      next(Consumed(contact:, initiator:, initial_digest:))
    }

    ExpiredKind -> next(Expired)
  }
}

/// Reads a stock and refuses one whose invitation does not point at its own
/// inbox, which no `offer.create` could have written.
fn stock_records(
  suite: Suite,
  next: fn(Stock) -> tlv.Decoder(a),
) -> tlv.Decoder(a) {
  use owner <- tlv.required(2, tlv.nested(identity_decoder(suite)))
  use spk_secret <- tlv.required(4, key_field(keys.x25519_secret))
  use pqspk_secret <- tlv.required(6, key_field(keys.kem_secret))
  use file <- tlv.required(8, invitation_field(suite))
  use inbox <- tlv.required(10, tlv.nested(route.inbox_decoder()))
  use approval <- tlv.required(12, approval_field())
  use budget <- tlv.required(14, tlv.u64)

  // The invitation's route must be the one this inbox hands out.
  case route.route(inbox) == file.route {
    True ->
      next(Stock(
        identity: owner,
        spk_secret:,
        pqspk_secret:,
        invitation: file,
        inbox:,
        approval:,
        budget:,
      ))

    False -> tlv.fail(tlv.InvalidField(10))
  }
}

/// The approval policy's stored number.
fn approval_field() -> tlv.Field(Approval) {
  tlv.try_map(tlv.u8, fn(number) {
    case number {
      0 -> Ok(AutoApprove)
      1 -> Ok(OperatorApproves)
      _ -> Error(Nil)
    }
  })
}

/// The offer phase discriminator; an unassigned number is refused.
fn offer_kind() -> tlv.Field(OfferKind) {
  tlv.try_map(tlv.u8, fn(number) {
    case number {
      0 -> Ok(ProvisioningKind)
      1 -> Ok(OpenKind)
      2 -> Ok(ConsumedKind)
      3 -> Ok(ExpiredKind)
      _ -> Error(Nil)
    }
  })
}
