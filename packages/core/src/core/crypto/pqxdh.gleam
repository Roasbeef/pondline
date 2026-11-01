//// PQXDH, the post-quantum extended triple Diffie-Hellman handshake
//// (Signal's specification), specialised to Reedwire's invitation flow, and
//// the hand-off into the Double Ratchet.
////
//// ## Roles
////
//// The inviter is the responder and the joiner is the initiator. The
//// inviter generates a `Prekeys` value, whose public `Bundle` travels
//// inside the invitation file; no server publishes or claims it, and there
//// are no one-time prekeys, because an invitation's bundle is already
//// single-use. The joiner verifies the bundle, runs the agreement and
//// sends one `InitialMessage`, which carries its identity, the ephemeral
//// key, the KEM ciphertext, a commitment naming the bundle, a hybrid
//// signature over the handshake transcript, and the first ratchet message.
////
//// ## The agreement
////
//// ```text
//// DH1 = DH(IK_init, SPK)   DH2 = DH(EK, IK_resp)   DH3 = DH(EK, SPK)
//// (SS, CT) = ML-KEM-1024.Encaps(PQSPK)
//// SK = HKDF(salt = 0^32, ikm = 0xFF^32 || DH1 || DH2 || DH3 || SS,
////           info = "Reedwire_PQXDH_X25519_SHA-256_ML-KEM-1024_v1", L = 32)
//// AD = encode(IK_init) || encode(IK_resp)
//// ```
////
//// The ratchet starts from `SK` and `AD`, and the responder's first ratchet
//// key pair is the signed prekey, as in Signal's hand-off from X3DH.
////
//// ## What authenticates what
////
//// Every signature here is hybrid, Ed25519 and ML-DSA-65 over the same
//// bytes, and every check requires both halves
//// (`docs/adr/005-hybrid-authentication.md`). Both identities carry a
//// verified binding, and the bundle's signed prekeys verify under the
//// bundle's identity, so a bundle whose prekeys were swapped (mailbox
//// substitution) is rejected when it is decoded.
////
//// The joiner authenticates explicitly: it signs the transcript
//// (`initial_transcript`) with both of its signing keys, and `respond`
//// verifies both signatures before any agreement. Classical PQXDH
//// authenticates the joiner only through DH1, an X25519 agreement a
//// quantum adversary could forge; the signature makes the joiner's
//// authentication need ML-DSA-65 broken as well. The inviter stays
//// implicitly authenticated, as in PQXDH: only the holder of the SPK and
//// PQSPK secrets, both signed under the inviter's hybrid identity, can
//// derive the key the first reply is encrypted under.
////
//// The KEM is implicitly rejecting: a ciphertext the joiner itself mangled
//// decapsulates to an unrelated secret, so the responder detects it as a
//// failed authentication of the first ratchet message, not as a KEM error.
//// A ciphertext anyone else changed fails the transcript signature first.
//// The commitment is the SHA-256 of the bundle's encoding; a responder
//// holding a different bundle refuses the message as `UnknownBundle`
//// without doing any agreement.
////
//// ## After the handshake
////
//// `respond` reports the commitment it consumed. The caller retires that
//// bundle's secrets once it has durably stored the new ratchet state; until
//// then, a retry of the same initial message works.

import core/crypto/error.{
  type Error, BadSignature, IdentityMismatch, Malformed, UnknownBundle,
}
import core/crypto/hkdf
import core/crypto/identity.{type Identity, type PublicIdentity}
import core/crypto/keys.{
  type HybridSignature, type KemCiphertext, type KemPublic, type KemSecret,
  type X25519Public, type X25519Secret,
}
import core/crypto/ratchet
import core/crypto/suite.{type Suite}
import core/crypto/wire
import core/secret
import gleam/result

/// The version byte of a bundle and of an initial message. It reserves room
/// for a handshake that adds post-quantum ratchet material.
pub const wire_version = 1

/// The HKDF `info` of the shared-secret derivation.
pub const kdf_info = <<"Reedwire_PQXDH_X25519_SHA-256_ML-KEM-1024_v1":utf8>>

/// The label the signed X25519 prekey's signature covers, followed by the
/// 32-byte public key.
pub const spk_label = <<"Reedwire_SignedPrekey_v1":utf8>>

/// The label the signed ML-KEM prekey's signature covers, followed by the
/// 1568-byte public key.
pub const pqspk_label = <<"Reedwire_PQSignedPrekey_v1":utf8>>

/// The label the initiator's transcript signature covers, followed by the
/// transcript fields (`initial_transcript`).
pub const transcript_label = <<"Reedwire_InitiatorTranscript_v1":utf8>>

/// The size of an encoded bundle: the version (1), the inviter's public
/// identity (5389), the SPK (32) and its hybrid signature (3373), the PQSPK
/// (1568) and its hybrid signature (3373), 13736 bytes.
pub const bundle_bytes = 13_736

/// The size of the bundle commitment: a SHA-256 digest.
pub const commitment_bytes = 32

/// The size of an initial message before its ratchet message: the version
/// (1), the initiator's public identity (5389), EK (32), CT (1568), the
/// bundle commitment (32) and the hybrid transcript signature (3373),
/// 10395 bytes.
pub const initial_fixed_bytes = 10_395

/// The inviter's public prekey bundle. Opaque: it is built only by
/// `generate_prekeys` or by `decode_bundle`, and both guarantee that the
/// identity binding and both hybrid prekey signatures verified.
pub opaque type Bundle {
  Bundle(
    identity: PublicIdentity,
    spk: X25519Public,
    spk_signature: HybridSignature,
    pqspk: KemPublic,
    pqspk_signature: HybridSignature,
  )
}

/// The inviter's prekeys: the public bundle and the two secrets that answer
/// it. The caller persists this until it either completes a handshake
/// against it or the invitation expires, and retires it after the ratchet
/// state is stored (`docs/spec.md` §5.4).
///
/// The constructor is public so a caller can restore persisted prekeys.
/// Nothing checks that the secrets answer the bundle's public keys; a
/// mismatch shows up as `AuthenticationFailed` from `respond`.
pub type Prekeys {
  Prekeys(bundle: Bundle, spk_secret: X25519Secret, pqspk_secret: KemSecret)
}

/// What the joiner sends first. The identity inside has a verified
/// binding, because `decode_initial` checks it; the transcript signature is
/// checked by `respond`, which alone knows the responder's half of the
/// transcript.
pub type InitialMessage {
  InitialMessage(
    /// The joiner's public identity.
    identity: PublicIdentity,
    /// The joiner's ephemeral X25519 key, EK.
    ephemeral: X25519Public,
    /// The ML-KEM-1024 ciphertext to the bundle's PQSPK.
    kem_ciphertext: KemCiphertext,
    /// SHA-256 of the bundle the joiner answered.
    bundle_commitment: BitArray,
    /// The joiner's hybrid signature over `initial_transcript`.
    transcript_signature: HybridSignature,
    /// The first ratchet message, from `ratchet.encrypt`.
    message: BitArray,
  )
}

/// What `respond` hands back: the ratchet state after the first message, the
/// first message's plaintext, and the commitment of the bundle it consumed,
/// which tells the caller which prekey secrets to retire.
pub type Response {
  Response(state: ratchet.State, plaintext: BitArray, consumed_bundle: BitArray)
}

/// Fresh prekeys signed by `identity`: a signed X25519 prekey and a signed
/// ML-KEM-1024 prekey, with their secrets.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(prekeys) = pqxdh.generate_prekeys(suite, identity)
/// ```
pub fn generate_prekeys(
  suite: Suite,
  owner: Identity,
) -> Result(Prekeys, Error) {
  use #(spk_secret, spk) <- result.try(keys.generate_x25519(suite))
  use #(pqspk_secret, pqspk) <- result.try(keys.generate_kem(suite))
  use spk_signature <- result.try(identity.sign(suite, owner, spk_message(spk)))
  use pqspk_signature <- result.try(identity.sign(
    suite,
    owner,
    pqspk_message(pqspk),
  ))

  Ok(Prekeys(
    bundle: Bundle(
      identity: owner.public,
      spk: spk,
      spk_signature: spk_signature,
      pqspk: pqspk,
      pqspk_signature: pqspk_signature,
    ),
    spk_secret: spk_secret,
    pqspk_secret: pqspk_secret,
  ))
}

fn spk_message(spk: X25519Public) -> BitArray {
  <<spk_label:bits, keys.x25519_public_bytes(spk):bits>>
}

fn pqspk_message(pqspk: KemPublic) -> BitArray {
  <<pqspk_label:bits, keys.kem_public_bytes(pqspk):bits>>
}

/// The bundle's inviter identity.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.bundle_identity(prekeys.bundle)
/// ```
pub fn bundle_identity(bundle: Bundle) -> PublicIdentity {
  bundle.identity
}

/// The canonical encoding of a bundle: the version byte, the inviter's
/// public identity (5389 bytes), the signed prekey (32) and its hybrid
/// signature (3373), the ML-KEM prekey (1568) and its hybrid signature
/// (3373), 13736 bytes in all.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.encode_bundle(prekeys.bundle)
/// // -> <<_:109_888>>
/// ```
pub fn encode_bundle(bundle: Bundle) -> BitArray {
  <<
    wire_version:size(8),
    identity.encode_public(bundle.identity):bits,
    keys.x25519_public_bytes(bundle.spk):bits,
    keys.hybrid_signature_bytes(bundle.spk_signature):bits,
    keys.kem_public_bytes(bundle.pqspk):bits,
    keys.hybrid_signature_bytes(bundle.pqspk_signature):bits,
  >>
}

/// Decodes a bundle and verifies everything in it: the identity binding and
/// both prekey signatures, each of which needs its Ed25519 and its
/// ML-DSA-65 half to verify under the identity's two signing keys. A bundle
/// whose prekey was replaced by anyone but the identity's owner fails here,
/// which is what makes mailbox substitution detectable.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.decode_bundle(suite, pqxdh.encode_bundle(prekeys.bundle))
/// // -> Ok(prekeys.bundle)
/// ```
pub fn decode_bundle(suite: Suite, bytes: BitArray) -> Result(Bundle, Error) {
  use #(version, rest) <- result.try(wire.read_u8(bytes, "bundle"))
  use Nil <- result.try(check_version(version, "bundle"))
  use #(owner, rest) <- result.try(identity.read_public(suite, rest))
  use #(spk, rest) <- result.try(read_x25519_public(rest))
  use #(spk_signature, rest) <- result.try(read_signature(rest, "bundle"))
  use #(pqspk, rest) <- result.try(read_kem_public(rest))
  use #(pqspk_signature, rest) <- result.try(read_signature(rest, "bundle"))
  use Nil <- result.try(wire.end(rest, "bundle"))
  use Nil <- result.try(verify_prekey(
    suite,
    owner,
    spk_message(spk),
    spk_signature,
    "signed prekey",
  ))
  use Nil <- result.try(verify_prekey(
    suite,
    owner,
    pqspk_message(pqspk),
    pqspk_signature,
    "post-quantum prekey",
  ))

  Ok(Bundle(owner, spk, spk_signature, pqspk, pqspk_signature))
}

/// Checks one hybrid prekey signature under the identity's two signing
/// keys, naming the prekey in the error.
fn verify_prekey(
  suite: Suite,
  owner: PublicIdentity,
  message: BitArray,
  signature: HybridSignature,
  which: String,
) -> Result(Nil, Error) {
  case identity.verify(suite, owner, message, signature) {
    True -> Ok(Nil)
    False -> Error(BadSignature(which))
  }
}

fn check_version(version: Int, what: String) -> Result(Nil, Error) {
  case version == wire_version {
    True -> Ok(Nil)
    False -> Error(Malformed(what <> " version"))
  }
}

/// Reads a 32-byte X25519 public key off the front of a bundle.
fn read_x25519_public(
  bytes: BitArray,
) -> Result(#(X25519Public, BitArray), Error) {
  use #(raw, rest) <- result.try(wire.take(bytes, keys.x25519_bytes, "bundle"))
  use key <- result.try(keys.x25519_public(raw))

  Ok(#(key, rest))
}

/// Reads a 3373-byte hybrid signature off the front of `bytes`, naming the
/// enclosing encoding in the error.
fn read_signature(
  bytes: BitArray,
  what: String,
) -> Result(#(HybridSignature, BitArray), Error) {
  use #(raw, rest) <- result.try(wire.take(
    bytes,
    keys.hybrid_signature_size,
    what,
  ))
  use signature <- result.try(keys.hybrid_signature(raw))

  Ok(#(signature, rest))
}

/// Reads a 1568-byte ML-KEM public key off the front of a bundle.
fn read_kem_public(bytes: BitArray) -> Result(#(KemPublic, BitArray), Error) {
  use #(raw, rest) <- result.try(wire.take(
    bytes,
    keys.kem_public_size,
    "bundle",
  ))
  use key <- result.try(keys.kem_public(raw))

  Ok(#(key, rest))
}

/// The commitment that identifies a bundle: SHA-256 of its encoding.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.commitment(suite, prekeys.bundle)
/// // -> <<_:256>>
/// ```
pub fn commitment(suite: Suite, bundle: Bundle) -> BitArray {
  suite.sha256(encode_bundle(bundle))
}

/// The initiator's side: verify nothing further (a `Bundle` is already
/// verified), agree on a secret, start the ratchet as sender, encrypt
/// `plaintext` as the first ratchet message, and sign the transcript with
/// both of the initiator's signing keys.
///
/// Returns the initiator's ratchet state, which the caller persists, and the
/// message to send.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(state, initial)) =
///   pqxdh.initiate(suite, joiner, bundle, <<"hello">>)
/// ```
pub fn initiate(
  suite: Suite,
  initiator: Identity,
  bundle: Bundle,
  plaintext: BitArray,
) -> Result(#(ratchet.State, InitialMessage), Error) {
  let responder_agreement = identity.agreement_key(bundle.identity)

  use #(ek_secret, ek_public) <- result.try(keys.generate_x25519(suite))
  use dh1 <- result.try(keys.dh(suite, initiator.agreement, bundle.spk))
  use dh2 <- result.try(keys.dh(suite, ek_secret, responder_agreement))
  use dh3 <- result.try(keys.dh(suite, ek_secret, bundle.spk))
  use #(kem_secret, kem_ciphertext) <- result.try(keys.kem_encapsulate(
    suite,
    bundle.pqspk,
  ))
  use shared <- result.try(derive_shared(suite, dh1, dh2, dh3, kem_secret))

  let ad = associated_data(initiator.public, bundle.identity)

  use state <- result.try(ratchet.init_sender(suite, shared, ad, bundle.spk))
  use #(state, message) <- result.try(ratchet.encrypt(suite, state, plaintext))

  // The signature comes last because it covers the ratchet message too, so
  // every byte the responder acts on is bound to the initiator's keys.
  let bundle_commitment = commitment(suite, bundle)

  use transcript_signature <- result.try(identity.sign(
    suite,
    initiator,
    transcript(ad, bundle_commitment, ek_public, kem_ciphertext, message),
  ))

  Ok(#(
    state,
    InitialMessage(
      identity: initiator.public,
      ephemeral: ek_public,
      kem_ciphertext: kem_ciphertext,
      bundle_commitment: bundle_commitment,
      transcript_signature: transcript_signature,
      message: message,
    ),
  ))
}

/// The bytes the initiator's transcript signature covers, for a responder
/// whose public identity is `responder`:
///
/// ```text
/// transcript_label || version (1)
///   || AD = encode(IK_init) || encode(IK_resp)
///   || bundle_commitment (32) || EK (32) || CT (1568) || ratchet_message
/// ```
///
/// That is every field of the initial message except the signature itself,
/// plus the responder's identity, so a signature made for one bundle, one
/// ephemeral key or one ciphertext verifies for no other. Every field
/// before the ratchet message has a fixed size, so the concatenation is
/// unambiguous without length prefixes. Public so tests can sign a
/// transcript of their own; protocol code reaches it only through
/// `initiate` and `respond`.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.initial_transcript(initial, inviter.public)
/// ```
pub fn initial_transcript(
  initial: InitialMessage,
  responder: PublicIdentity,
) -> BitArray {
  transcript(
    associated_data(initial.identity, responder),
    initial.bundle_commitment,
    initial.ephemeral,
    initial.kem_ciphertext,
    initial.message,
  )
}

/// The transcript from its parts, shared by `initiate` (which signs it
/// before the `InitialMessage` exists) and `initial_transcript` (which
/// rebuilds it from one), so the two can never lay it out differently.
fn transcript(
  ad: BitArray,
  bundle_commitment: BitArray,
  ephemeral: X25519Public,
  kem_ciphertext: KemCiphertext,
  message: BitArray,
) -> BitArray {
  <<
    transcript_label:bits,
    wire_version:size(8),
    ad:bits,
    bundle_commitment:bits,
    keys.x25519_public_bytes(ephemeral):bits,
    keys.kem_ciphertext_bytes(kem_ciphertext):bits,
    message:bits,
  >>
}

/// The responder's side: check the commitment, verify the initiator's
/// hybrid transcript signature, recompute the agreement, start the ratchet
/// with the signed prekey as its first key pair, and decrypt the first
/// message.
///
/// Any failure leaves the caller's `Prekeys` untouched: nothing is consumed
/// until the caller stores the returned state and retires the bundle named
/// by `consumed_bundle`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(response) = pqxdh.respond(suite, inviter, prekeys, initial)
/// ```
pub fn respond(
  suite: Suite,
  responder: Identity,
  prekeys: Prekeys,
  initial: InitialMessage,
) -> Result(Response, Error) {
  let commitment = commitment(suite, prekeys.bundle)

  // The bundle names the inviter's identity, so a responder holding a
  // different identity can say so precisely, before any agreement.
  use Nil <- result.try(check_identity(responder, prekeys.bundle))
  use Nil <- result.try(check_commitment(
    suite,
    commitment,
    initial.bundle_commitment,
  ))

  // Explicit initiator authentication, both halves, before any agreement:
  // without it the joiner is authenticated only through DH1, which is
  // X25519 alone.
  use Nil <- result.try(check_transcript(suite, responder, initial))
  use dh1 <- result.try(keys.dh(
    suite,
    prekeys.spk_secret,
    identity.agreement_key(initial.identity),
  ))
  use dh2 <- result.try(keys.dh(suite, responder.agreement, initial.ephemeral))
  use dh3 <- result.try(keys.dh(suite, prekeys.spk_secret, initial.ephemeral))
  use kem_secret <- result.try(keys.kem_decapsulate(
    suite,
    prekeys.pqspk_secret,
    initial.kem_ciphertext,
  ))
  use shared <- result.try(derive_shared(suite, dh1, dh2, dh3, kem_secret))

  let ad = associated_data(initial.identity, responder.public)
  let state =
    ratchet.init_receiver(shared, ad, prekeys.spk_secret, prekeys.bundle.spk)

  use #(state, plaintext) <- result.try(ratchet.decrypt(
    suite,
    state,
    initial.message,
  ))

  Ok(Response(state: state, plaintext: plaintext, consumed_bundle: commitment))
}

/// The responder must be the identity the bundle was signed by.
fn check_identity(responder: Identity, bundle: Bundle) -> Result(Nil, Error) {
  case responder.public == bundle.identity {
    True -> Ok(Nil)
    False -> Error(IdentityMismatch)
  }
}

/// The initiator's transcript signature must verify, Ed25519 and ML-DSA-65
/// both, under the identity the message names.
fn check_transcript(
  suite: Suite,
  responder: Identity,
  initial: InitialMessage,
) -> Result(Nil, Error) {
  case
    identity.verify(
      suite,
      initial.identity,
      initial_transcript(initial, responder.public),
      initial.transcript_signature,
    )
  {
    True -> Ok(Nil)
    False -> Error(BadSignature("initiator transcript"))
  }
}

/// Compares the bundle commitment the message names with the one the responder holds, in constant time.
fn check_commitment(
  suite: Suite,
  held: BitArray,
  named: BitArray,
) -> Result(Nil, Error) {
  case suite.constant_time_equal(held, named) {
    True -> Ok(Nil)
    False -> Error(UnknownBundle)
  }
}

/// The 32 bytes of 0xFF that begin the key-derivation input, Signal's `F`.
/// It separates this input from any Curve25519 value an XEdDSA-era handshake
/// could have fed the same KDF.
pub const kdf_prefix = <<
  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:size(256),
>>

/// The handshake's shared secret:
/// `HKDF(salt = 0^32, ikm = 0xFF^32 || DH1 || DH2 || DH3 || SS)`, 32 bytes.
/// It is public so a known-answer test can pin the exact bytes the profile
/// specifies; protocol code reaches it only through `initiate` and `respond`.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.derive_shared(suite, dh1, dh2, dh3, kem_shared)
/// // -> Ok(secret)
/// ```
pub fn derive_shared(
  suite: Suite,
  dh1: BitArray,
  dh2: BitArray,
  dh3: BitArray,
  kem_secret: BitArray,
) -> Result(secret.Secret, Error) {
  let ikm = <<
    kdf_prefix:bits,
    dh1:bits,
    dh2:bits,
    dh3:bits,
    kem_secret:bits,
  >>

  hkdf.extract_expand(suite, <<0:256>>, ikm, kdf_info, 32)
  |> result.map(secret.new)
}

/// The session's associated data: the initiator's identity encoding followed
/// by the responder's, so every message is bound to both parties.
fn associated_data(
  initiator: PublicIdentity,
  responder: PublicIdentity,
) -> BitArray {
  <<
    identity.encode_public(initiator):bits,
    identity.encode_public(responder):bits,
  >>
}

/// The wire form of an initial message: the version byte, the initiator's
/// public identity (5389 bytes), the ephemeral key (32), the KEM
/// ciphertext (1568), the bundle commitment (32), the hybrid transcript
/// signature (3373), then the ratchet message to the end. The fixed part
/// is `initial_fixed_bytes`.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.encode_initial(initial)
/// ```
pub fn encode_initial(initial: InitialMessage) -> BitArray {
  <<
    wire_version:size(8),
    identity.encode_public(initial.identity):bits,
    keys.x25519_public_bytes(initial.ephemeral):bits,
    keys.kem_ciphertext_bytes(initial.kem_ciphertext):bits,
    initial.bundle_commitment:bits,
    keys.hybrid_signature_bytes(initial.transcript_signature):bits,
    initial.message:bits,
  >>
}

/// Decodes an initial message, verifying the initiator's identity binding.
/// The transcript signature is only checked for shape here: verifying it
/// needs the responder's identity, which `respond` has. The ratchet message
/// at the end is kept as bytes and only parsed when `respond` decrypts it.
///
/// ## Examples
///
/// ```gleam
/// pqxdh.decode_initial(suite, pqxdh.encode_initial(initial))
/// // -> Ok(initial)
/// ```
pub fn decode_initial(
  suite: Suite,
  bytes: BitArray,
) -> Result(InitialMessage, Error) {
  use #(version, rest) <- result.try(wire.read_u8(bytes, "initial message"))
  use Nil <- result.try(check_version(version, "initial message"))
  use #(initiator, rest) <- result.try(identity.read_public(suite, rest))
  use #(ephemeral, rest) <- result.try(wire.take(
    rest,
    keys.x25519_bytes,
    "initial message",
  ))
  use #(ciphertext, rest) <- result.try(wire.take(
    rest,
    keys.kem_ciphertext_size,
    "initial message",
  ))
  use #(commitment, rest) <- result.try(wire.take(
    rest,
    commitment_bytes,
    "initial message",
  ))
  use #(signature, message) <- result.try(read_signature(
    rest,
    "initial message",
  ))
  use ephemeral <- result.try(keys.x25519_public(ephemeral))
  use ciphertext <- result.try(keys.kem_ciphertext(ciphertext))

  Ok(InitialMessage(
    identity: initiator,
    ephemeral: ephemeral,
    kem_ciphertext: ciphertext,
    bundle_commitment: commitment,
    transcript_signature: signature,
    message: message,
  ))
}
