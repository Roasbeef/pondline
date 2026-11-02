//// A relationship's identity: two signing keys, Ed25519 and ML-DSA-65,
//// bound to an X25519 agreement key.
////
//// Signal's X3DH uses one Curve25519 key for both agreement and signing
//// through XEdDSA. Reedwire keeps separate keys instead (`docs/review/
//// 2026-10-31-design-review.md`, rulings): the signing keys sign, the
//// X25519 key agrees, and a binding signature ties them together. The keys
//// are generated fresh per relationship, so an identity says nothing about
//// any other relationship.
////
//// Authentication is hybrid (`docs/adr/005-hybrid-authentication.md`).
//// Every signature an identity makes is a `keys.HybridSignature`, Ed25519
//// and ML-DSA-65 over the same bytes, and a verifier requires both. The
//// binding is such a pair over the label and all three public keys, so it
//// ties the two signing keys to each other as well as to the agreement
//// key: an attacker cannot splice its own ML-DSA key beside someone else's
//// Ed25519 key, because the Ed25519 half signs the ML-DSA key too.
////
//// A `PublicIdentity` is opaque and only ever built by `generate` or by
//// `decode_public`, and `decode_public` verifies the binding. A value of the
//// type therefore always carries a valid binding, and the handshake never
//// has to remember to check one.

import core/crypto/error.{type Error, BadSignature}
import core/crypto/keys.{
  type Ed25519Public, type Ed25519Secret, type HybridSignature, type MldsaPublic,
  type MldsaSecret, type X25519Public, type X25519Secret,
}
import core/crypto/suite.{type Suite}
import core/crypto/wire
import gleam/result

/// The size of an encoded public identity: the Ed25519 key (32), the
/// ML-DSA-65 key (1952), the X25519 key (32) and the hybrid binding
/// signature (3373), 5389 bytes.
pub const public_identity_bytes = 5389

/// The domain-separation label of the binding signature, which signs this
/// label followed by the Ed25519, ML-DSA-65 and X25519 public keys.
pub const binding_label = <<"Pondline_IdentityBinding_v1":utf8>>

/// The public half of an identity, with a binding signature that has been
/// verified: either it came from `generate`, or `decode_public` checked it.
pub opaque type PublicIdentity {
  PublicIdentity(
    signing: Ed25519Public,
    pq_signing: MldsaPublic,
    agreement: X25519Public,
    binding: HybridSignature,
  )
}

/// A full identity: the secret keys and the public identity they belong to.
/// The constructor is public so a caller can restore a persisted identity;
/// nothing checks that the secrets match `public`, and a mismatch shows up
/// as signatures and agreements that no peer accepts.
pub type Identity {
  Identity(
    /// The Ed25519 signing key, the classical half of every signature.
    signing: Ed25519Secret,
    /// The ML-DSA-65 signing key, the post-quantum half.
    pq_signing: MldsaSecret,
    /// The X25519 key the handshake agrees with.
    agreement: X25519Secret,
    /// The public identity these secrets answer.
    public: PublicIdentity,
  )
}

/// A fresh identity: new Ed25519, ML-DSA-65 and X25519 keys and the hybrid
/// binding over them.
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
  use #(pq_secret, pq_public) <- result.try(keys.generate_mldsa(suite))
  use #(agreement_secret, agreement_public) <- result.try(keys.generate_x25519(
    suite,
  ))
  use binding <- result.try(keys.hybrid_sign(
    suite,
    signing_secret,
    pq_secret,
    binding_message(signing_public, pq_public, agreement_public),
  ))

  Ok(Identity(
    signing: signing_secret,
    pq_signing: pq_secret,
    agreement: agreement_secret,
    public: PublicIdentity(
      signing: signing_public,
      pq_signing: pq_public,
      agreement: agreement_public,
      binding: binding,
    ),
  ))
}

/// The bytes both halves of the binding sign: the label, then every public
/// key in encoding order. All three are covered, so neither signing key can
/// be paired with a key its owner did not choose. Public so a test can play
/// an attacker who signs it; `generate` and `read_public` are its callers.
///
/// ## Examples
///
/// ```gleam
/// identity.binding_message(ed25519_public, mldsa_public, x25519_public)
/// // -> <<"Pondline_IdentityBinding_v1", ..>>
/// ```
pub fn binding_message(
  signing: Ed25519Public,
  pq_signing: MldsaPublic,
  agreement: X25519Public,
) -> BitArray {
  <<
    binding_label:bits,
    keys.ed25519_public_bytes(signing):bits,
    keys.mldsa_public_bytes(pq_signing):bits,
    keys.x25519_public_bytes(agreement):bits,
  >>
}

/// Signs `message` with both of an identity's signing keys. Every
/// signature the protocol asks of an identity goes through here, so none
/// can be made with one key alone.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(signature) = identity.sign(suite, owner, <<"label", data:bits>>)
/// ```
pub fn sign(
  suite: Suite,
  owner: Identity,
  message: BitArray,
) -> Result(HybridSignature, Error) {
  keys.hybrid_sign(suite, owner.signing, owner.pq_signing, message)
}

/// Whether `signature` is a valid hybrid signature over `message` by this
/// identity: both the Ed25519 and the ML-DSA-65 halves must verify.
///
/// ## Examples
///
/// ```gleam
/// identity.verify(suite, public, message, signature)
/// // -> True
/// ```
pub fn verify(
  suite: Suite,
  public: PublicIdentity,
  message: BitArray,
  signature: HybridSignature,
) -> Bool {
  keys.hybrid_verify(
    suite,
    public.signing,
    public.pq_signing,
    message,
    signature,
  )
}

/// The Ed25519 key that verifies the classical half of this identity's
/// signatures. Verifying a signature takes both halves: use `verify`.
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

/// The ML-DSA-65 key that verifies the post-quantum half of this
/// identity's signatures.
///
/// ## Examples
///
/// ```gleam
/// identity.pq_signing_key(public)
/// ```
pub fn pq_signing_key(public: PublicIdentity) -> MldsaPublic {
  public.pq_signing
}

/// The canonical encoding of a public identity, 5389 bytes with no framing:
/// the Ed25519 public key (32), the ML-DSA-65 public key (1952), the X25519
/// public key (32), then the hybrid binding signature (64 + 3309). This is
/// the encoding that is fingerprinted (the session's associated data holds
/// the two fingerprints) and that the initiator's transcript signs.
///
/// ## Examples
///
/// ```gleam
/// identity.encode_public(public)
/// // -> <<_:43_112>>
/// ```
pub fn encode_public(public: PublicIdentity) -> BitArray {
  <<
    keys.ed25519_public_bytes(public.signing):bits,
    keys.mldsa_public_bytes(public.pq_signing):bits,
    keys.x25519_public_bytes(public.agreement):bits,
    keys.hybrid_signature_bytes(public.binding):bits,
  >>
}

/// Decodes and verifies a public identity. Wrong length is `Malformed`; a
/// binding whose Ed25519 or ML-DSA-65 half does not verify is
/// `BadSignature("identity binding")`.
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
  use #(pq_signing, rest) <- result.try(wire.take(
    rest,
    keys.mldsa_public_size,
    "public identity",
  ))
  use #(agreement, rest) <- result.try(wire.take(
    rest,
    keys.x25519_bytes,
    "public identity",
  ))
  use #(binding, rest) <- result.try(wire.take(
    rest,
    keys.hybrid_signature_size,
    "public identity",
  ))
  use signing <- result.try(keys.ed25519_public(signing))
  use pq_signing <- result.try(keys.mldsa_public(pq_signing))
  use agreement <- result.try(keys.x25519_public(agreement))
  use binding <- result.try(keys.hybrid_signature(binding))

  let public =
    PublicIdentity(
      signing: signing,
      pq_signing: pq_signing,
      agreement: agreement,
      binding: binding,
    )

  // The binding is verified here, both halves, so no public identity exists
  // with a bad one or with one whose post-quantum half was never checked.
  case
    verify(
      suite,
      public,
      binding_message(signing, pq_signing, agreement),
      binding,
    )
  {
    True -> Ok(#(public, rest))

    False -> Error(BadSignature("identity binding"))
  }
}

/// The fingerprint of a public identity: SHA-256 of its canonical encoding,
/// which covers all three public keys and the binding. Two parties compare
/// fingerprints out of band to confirm they hold the same identity.
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
