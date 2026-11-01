//// The invitation file: everything a joiner needs to start a relationship,
//// and nothing a mailbox needs to know.
////
//// The inviter's public prekey bundle is embedded (design review §3.3). So
//// there is no `PublishBundle`, no `ClaimBundle` and no join secret: the
//// bundle-substitution attack cannot happen because no mailbox carries the
//// bundle, and the invitation's own authenticity is the PQXDH handshake's.
//// `decode` verifies the bundle (its identity binding and both prekey
//// signatures), so an `Invitation` value always holds a bundle that
//// verified under its own identity key. An invitation is a bearer
//// credential: it carries the append capability of the inviter's queue.
////
//// The inviter's side of an invitation, the stored offer that holds the
//// prekey secrets and decides who may consume it, is `core/offer`; this
//// module is only the file.
////
//// ## Layout
////
//// A TLV stream: 0 the format version (1), 2 the invitation identifier, 4
//// the bundle (`pqxdh.encode_bundle`, 1857 bytes), 6 the inviter's route, 8
//// the acceptance deadline, 10 the description. A different version is an
//// unknown value in tag 0 and the file is refused whole.

import core/crypto/pqxdh.{type Bundle}
import core/crypto/suite.{type Suite}
import core/field
import core/id.{type Id, type Invitation as InvitationKind}
import core/limits
import core/message
import core/route.{type Route}
import core/secret.{type Secret}
import core/time.{type Instant}
import core/tlv
import gleam/result

/// The format version this module writes and the only one it reads.
pub const format_version = 1

/// The largest invitation file: the bundle, a route and a description, with
/// framing, rounded up. New limit, flagged for §11.3.
pub const max_invitation_bytes = limits.max_invitation_bytes

/// A pairing offer as the joiner receives it.
pub type Invitation {
  Invitation(
    /// Names the offer; the joiner repeats it in its `Hello`.
    id: Id(InvitationKind),
    /// The inviter's verified public prekey bundle.
    bundle: Bundle,
    /// Where the joiner appends its first message: the inviter's queue.
    route: Route,
    /// After this instant the inviter will not redeem the invitation.
    expires_at: Instant,
    /// How the inviter describes the offer. Informational, unverified.
    description: String,
  )
}

/// The canonical bytes of an invitation file, as a `Secret` because the
/// route inside is bearer authority to append to the inviter's queue.
///
/// ## Examples
///
/// ```gleam
/// invitation.decode(suite, secret.expose(invitation.encode(invite)))
/// // -> Ok(invite)
/// ```
pub fn encode(invitation: Invitation) -> Secret {
  tlv.new()
  |> tlv.put(0, tlv.encode_u8(format_version))
  |> tlv.put(2, id.to_bytes(invitation.id))
  |> tlv.put(4, pqxdh.encode_bundle(invitation.bundle))
  |> tlv.put(6, route.encode(invitation.route))
  |> tlv.put(8, field.encode_instant(invitation.expires_at))
  |> tlv.put(10, tlv.encode_text(invitation.description))
  |> tlv.encode
  |> secret.new
}

/// Reads an invitation file and verifies its bundle. Total: a wrong
/// version, a bad bundle signature, an oversized description and every
/// truncation are `TlvError`s that carry no bytes.
///
/// ## Examples
///
/// ```gleam
/// invitation.decode(suite, <<>>)
/// // -> Error(tlv.MissingRequired(0))
/// ```
pub fn decode(
  suite: Suite,
  bytes: BitArray,
) -> Result(Invitation, tlv.TlvError) {
  tlv.decode(bytes, max_bytes: max_invitation_bytes, with: {
    use _version <- tlv.required(0, version_field())
    use id <- tlv.required(2, field.id())
    use bundle <- tlv.required(4, bundle_field(suite))
    use route <- tlv.required(6, tlv.nested(route.decoder()))
    use expires_at <- tlv.required(8, field.instant())
    use description <- tlv.required(
      10,
      field.bounded_text(message.max_description_bytes),
    )

    tlv.success(Invitation(id:, bundle:, route:, expires_at:, description:))
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

/// Decodes the embedded bundle, which verifies its signatures.
fn bundle_field(suite: Suite) -> tlv.Field(Bundle) {
  tlv.fixed_bytes(pqxdh.bundle_bytes)
  |> tlv.try_map(fn(raw) {
    pqxdh.decode_bundle(suite, raw)
    |> result.replace_error(Nil)
  })
}
