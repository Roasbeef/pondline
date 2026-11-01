//// A relationship's identity: an Ed25519 signing key bound to an X25519
//// agreement key.
////
//// Signal's X3DH uses one Curve25519 key for both agreement and signing
//// through XEdDSA. Reedwire keeps two keys instead (`docs/review/
//// 2026-10-31-design-review.md`, rulings): the Ed25519 key signs, the X25519
//// key agrees, and a binding signature by the first over the second ties
//// them together. The pair is generated fresh per relationship, so an
//// identity says nothing about any other relationship.
////
//// A `PublicIdentity` is opaque and only ever built by `generate` or by
//// `decode_public`, and `decode_public` verifies the binding. A value of the
//// type therefore always carries a valid binding, and the handshake never
//// has to remember to check one.

import core/crypto/error.{type Error, BadSignature}
import core/crypto/keys.{
  type Ed25519Public, type Ed25519Secret, type Signature, type X25519Public,
  type X25519Secret,
}
import core/crypto/suite.{type Suite}
import core/crypto/wire
import gleam/result

/// The size of an encoded public identity: 32 + 32 + 64 bytes.
pub const public_identity_bytes = 128

/// The domain-separation label of the binding signature, which signs this
/// label followed by the 32 bytes of the X25519 public key.
pub const binding_label = <<"Reedwire_IdentityBinding_v1":utf8>>

/// The public half of an identity, with a binding signature that has been
/// verified: either it came from `generate`, or `decode_public` checked it.
pub opaque type PublicIdentity {
  PublicIdentity(
    signing: Ed25519Public,
    agreement: X25519Public,
    binding: Signature,
  )
}

/// A full identity: both secret keys and the public identity they belong to.
/// The constructor is public so a caller can restore a persisted identity;
/// nothing checks that the secrets match `public`, and a mismatch shows up
/// as signatures and agreements that no peer accepts.
pub type Identity {
  Identity(
    signing: Ed25519Secret,
    agreement: X25519Secret,
    public: PublicIdentity,
  )
}

/// A fresh identity: new Ed25519 and X25519 keys and the binding between
/// them.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(identity) = identity.generate(suite)
/// ```
pub fn generate(suite: Suite) -> Result(Identity, Error) {
  use #(signing_secret, signing_public) <- result.try(keys.generate_ed25519(
    suite,
  ))
  use #(agreement_secret, agreement_public) <- result.try(keys.generate_x25519(
    suite,
  ))
  use binding <- result.try(keys.sign(
    suite,
    signing_secret,
    binding_message(agreement_public),
  ))

  Ok(Identity(
    signing: signing_secret,
    agreement: agreement_secret,
    public: PublicIdentity(
      signing: signing_public,
      agreement: agreement_public,
      binding: binding,
    ),
  ))
}

fn binding_message(agreement: X25519Public) -> BitArray {
  <<binding_label:bits, keys.x25519_public_bytes(agreement):bits>>
}

/// The Ed25519 key that verifies this identity's signatures.
///
/// ## Examples
///
/// ```gleam
/// identity.signing_key(public)
/// ```
pub fn signing_key(public: PublicIdentity) -> Ed25519Public {
  public.signing
}

/// The X25519 key peers agree against.
///
/// ## Examples
///
/// ```gleam
/// identity.agreement_key(public)
/// ```
pub fn agreement_key(public: PublicIdentity) -> X25519Public {
  public.agreement
}

/// The canonical encoding of a public identity: the Ed25519 public key, the
/// X25519 public key and the binding signature, 128 bytes with no framing.
/// This is the encoding that is fingerprinted and that goes into the
/// handshake's associated data.
///
/// ## Examples
///
/// ```gleam
/// identity.encode_public(public)
/// // -> <<_:1024>>
/// ```
pub fn encode_public(public: PublicIdentity) -> BitArray {
  <<
    keys.ed25519_public_bytes(public.signing):bits,
    keys.x25519_public_bytes(public.agreement):bits,
    keys.signature_bytes(public.binding):bits,
  >>
}

/// Decodes and verifies a public identity. Wrong length is `Malformed`; a
/// binding that does not verify is `BadSignature("identity binding")`.
///
/// ## Examples
///
/// ```gleam
/// identity.decode_public(suite, identity.encode_public(public))
/// // -> Ok(public)
/// ```
pub fn decode_public(
  suite: Suite,
  bytes: BitArray,
) -> Result(PublicIdentity, Error) {
  use #(public, rest) <- result.try(read_public(suite, bytes))
  use Nil <- result.try(wire.end(rest, "public identity"))

  Ok(public)
}

/// Reads one public identity off the front of `bytes`, verifying it, and
/// returns what follows. The handshake messages embed identities this way.
///
/// ## Examples
///
/// ```gleam
/// identity.read_public(suite, <<encoded:bits, 9>>)
/// // -> Ok(#(public, <<9>>))
/// ```
pub fn read_public(
  suite: Suite,
  bytes: BitArray,
) -> Result(#(PublicIdentity, BitArray), Error) {
  use #(signing, rest) <- result.try(wire.take(
    bytes,
    keys.ed25519_key_bytes,
    "public identity",
  ))
  use #(agreement, rest) <- result.try(wire.take(
    rest,
    keys.x25519_bytes,
    "public identity",
  ))
  use #(binding, rest) <- result.try(wire.take(
    rest,
    keys.ed25519_signature_bytes,
    "public identity",
  ))
  use signing <- result.try(keys.ed25519_public(signing))
  use agreement <- result.try(keys.x25519_public(agreement))
  use binding <- result.try(keys.signature(binding))

  // The binding is verified here, so no public identity exists with a bad one.
  case keys.verify(suite, signing, binding_message(agreement), binding) {
    True ->
      Ok(#(
        PublicIdentity(signing: signing, agreement: agreement, binding: binding),
        rest,
      ))

    False -> Error(BadSignature("identity binding"))
  }
}

/// The fingerprint of a public identity: SHA-256 of its canonical encoding.
/// Two parties compare fingerprints out of band to confirm they hold the
/// same identity.
///
/// ## Examples
///
/// ```gleam
/// identity.fingerprint(suite, public)
/// // -> <<_:256>>
/// ```
pub fn fingerprint(suite: Suite, public: PublicIdentity) -> BitArray {
  suite.sha256(encode_public(public))
}
