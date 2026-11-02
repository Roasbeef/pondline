//// Hybrid authentication over the real primitives
//// (`docs/adr/005-hybrid-authentication.md`).
////
//// Every signature in the handshake is a pair, Ed25519 and ML-DSA-65 over
//// the same bytes, and every check must require both. The tests here are
//// the ones that would pass if a check quietly verified only the classical
//// half: for the identity binding, each bundle signature and the joiner's
//// transcript signature, a pair with exactly one valid half is refused, in
//// both directions. They also pin what the transcript covers, the sizes
//// the hybrid encodings grew to, the padding bucket the initial frame
//// lands in, and that the snapshot and invitation codecs carry the larger
//// identities.

import core/crypto/error.{BadSignature, Malformed}
import core/crypto/identity
import core/crypto/keys
import core/crypto/pqxdh
import core/crypto/ratchet
import core/endpoint
import core/envelope
import core/frame
import core/id as core_id
import core/invitation
import core/limits
import core/offer
import core/plan
import core/relationship
import core/route
import core/secret
import core/snapshot
import core/time.{Instant}
import gleam/bit_array
import gleam/int
import gleam/string
import primitives
import primitives/suite

// ------------------------------------------------------------- helpers

fn fresh_identity() -> identity.Identity {
  let assert Ok(id) = identity.generate(suite.suite())
    as "key generation succeeds"
  id
}

fn flip_byte(bytes: BitArray, index: Int) -> BitArray {
  let assert Ok(head) = bit_array.slice(bytes, 0, index)
  let assert Ok(<<byte>>) = bit_array.slice(bytes, index, 1)
  let assert Ok(tail) =
    bit_array.slice(bytes, index + 1, bit_array.byte_size(bytes) - index - 1)

  <<head:bits, int.bitwise_exclusive_or(byte, 1), tail:bits>>
}

/// `bytes` with `size` bytes at `at` replaced by `replacement`.
fn splice(bytes: BitArray, at: Int, replacement: BitArray) -> BitArray {
  let size = bit_array.byte_size(replacement)
  let assert Ok(head) = bit_array.slice(bytes, 0, at)
  let assert Ok(tail) =
    bit_array.slice(bytes, at + size, bit_array.byte_size(bytes) - at - size)

  <<head:bits, replacement:bits, tail:bits>>
}

fn slice(bytes: BitArray, at: Int, size: Int) -> BitArray {
  let assert Ok(part) = bit_array.slice(bytes, at, size)
  part
}

/// An inviter, its prekeys, a joiner and the joiner's initial message.
type Handshake {
  Handshake(
    inviter: identity.Identity,
    joiner: identity.Identity,
    prekeys: pqxdh.Prekeys,
    initial: pqxdh.InitialMessage,
  )
}

fn start(inviter: identity.Identity, joiner: identity.Identity) -> Handshake {
  let s = suite.suite()
  let assert Ok(prekeys) = pqxdh.generate_prekeys(s, inviter)
  let assert Ok(#(_, initial)) =
    pqxdh.initiate(s, joiner, prekeys.bundle, <<"hello inviter">>)

  Handshake(inviter:, joiner:, prekeys:, initial:)
}

fn respond(handshake: Handshake, initial: pqxdh.InitialMessage) {
  pqxdh.respond(suite.suite(), handshake.inviter, handshake.prekeys, initial)
}

// Offsets inside an encoded public identity: the Ed25519 key, the ML-DSA-65
// key, the X25519 key, then the binding's Ed25519 and ML-DSA-65 halves.
const identity_mldsa_at = 32

const binding_at = 2016

const binding_mldsa_at = 2080

// Offsets inside an encoded bundle (see `protocol_test`).
const spk_signature_at = 5422

const pqspk_signature_at = 10_363

// The transcript signature's offset inside an encoded initial message:
// version, identity, EK, CT and commitment come first.
const transcript_signature_at = 7022

pub fn the_offsets_used_here_hold_test() {
  assert identity_mldsa_at == keys.ed25519_key_bytes
  assert binding_at
    == keys.ed25519_key_bytes + keys.mldsa_public_size + keys.x25519_bytes
  assert binding_mldsa_at == binding_at + keys.ed25519_signature_bytes
  assert identity.public_identity_bytes
    == binding_at + keys.hybrid_signature_size
  assert spk_signature_at == 1 + identity.public_identity_bytes + 32
  assert pqspk_signature_at
    == spk_signature_at + keys.hybrid_signature_size + keys.kem_public_size
  assert transcript_signature_at
    == 1
    + identity.public_identity_bytes
    + keys.x25519_bytes
    + keys.kem_ciphertext_size
    + pqxdh.commitment_bytes
  assert pqxdh.initial_fixed_bytes
    == transcript_signature_at + keys.hybrid_signature_size
}

// ------------------------------------------------------------ identity

pub fn an_identity_binding_with_one_valid_half_is_refused_test() {
  let s = suite.suite()
  let encoded = identity.encode_public(fresh_identity().public)

  // The Ed25519 half broken, the ML-DSA-65 half intact.
  assert identity.decode_public(s, flip_byte(encoded, binding_at))
    == Error(BadSignature("identity binding"))

  // The ML-DSA-65 half broken, the Ed25519 half intact: the first byte, and
  // the last byte of the whole encoding.
  assert identity.decode_public(s, flip_byte(encoded, binding_mldsa_at))
    == Error(BadSignature("identity binding"))
  assert identity.decode_public(
      s,
      flip_byte(encoded, identity.public_identity_bytes - 1),
    )
    == Error(BadSignature("identity binding"))
}

/// The ML-DSA half of one identity's binding grafted onto another, whose
/// Ed25519 half stays valid: each half is a genuine signature by its
/// identity's key, but not over this identity's keys.
pub fn an_identity_binding_with_a_foreign_post_quantum_half_is_refused_test() {
  let s = suite.suite()
  let honest = identity.encode_public(fresh_identity().public)
  let other = identity.encode_public(fresh_identity().public)
  let foreign = slice(other, binding_mldsa_at, keys.mldsa_signature_size)

  assert identity.decode_public(s, splice(honest, binding_mldsa_at, foreign))
    == Error(BadSignature("identity binding"))
}

/// An attacker keeps someone's Ed25519 key and binding half, swaps in its
/// own ML-DSA-65 key, and signs the binding message for the new key set
/// with that key. The ML-DSA half verifies; the Ed25519 half, which signed
/// the honest ML-DSA key as part of its message, does not.
pub fn a_spliced_post_quantum_key_is_refused_test() {
  let s = suite.suite()
  let honest = fresh_identity().public
  let encoded = identity.encode_public(honest)
  let #(attacker_secret, attacker_bytes) = primitives.mldsa65_keypair()
  let assert Ok(attacker_public) = keys.mldsa_public(attacker_bytes)
  let message =
    identity.binding_message(
      identity.signing_key(honest),
      attacker_public,
      identity.agreement_key(honest),
    )
  let assert Ok(attacker_half) =
    primitives.mldsa65_sign(attacker_secret, message)
  let spliced =
    encoded
    |> splice(identity_mldsa_at, attacker_bytes)
    |> splice(binding_mldsa_at, attacker_half)

  assert primitives.mldsa65_verify(attacker_bytes, message, attacker_half)
  assert identity.decode_public(s, spliced)
    == Error(BadSignature("identity binding"))
}

pub fn the_fingerprint_covers_all_three_keys_test() {
  let s = suite.suite()
  let public = fresh_identity().public
  let encoded = identity.encode_public(public)

  assert bit_array.byte_size(encoded) == identity.public_identity_bytes
  assert slice(encoded, 0, 32)
    == keys.ed25519_public_bytes(identity.signing_key(public))
  assert slice(encoded, identity_mldsa_at, keys.mldsa_public_size)
    == keys.mldsa_public_bytes(identity.pq_signing_key(public))
  assert slice(encoded, binding_at - 32, 32)
    == keys.x25519_public_bytes(identity.agreement_key(public))
  assert identity.fingerprint(s, public) == primitives.sha256(encoded)
}

// -------------------------------------------------------------- bundle

pub fn a_signed_prekey_signature_with_one_valid_half_is_refused_test() {
  let s = suite.suite()
  let encoded =
    pqxdh.encode_bundle(
      start(fresh_identity(), fresh_identity()).prekeys.bundle,
    )
  let mldsa_half = spk_signature_at + keys.ed25519_signature_bytes

  assert pqxdh.decode_bundle(s, flip_byte(encoded, spk_signature_at + 5))
    == Error(BadSignature("signed prekey"))
  assert pqxdh.decode_bundle(s, flip_byte(encoded, mldsa_half + 5))
    == Error(BadSignature("signed prekey"))
}

pub fn a_post_quantum_prekey_signature_with_one_valid_half_is_refused_test() {
  let s = suite.suite()
  let encoded =
    pqxdh.encode_bundle(
      start(fresh_identity(), fresh_identity()).prekeys.bundle,
    )
  let mldsa_half = pqspk_signature_at + keys.ed25519_signature_bytes

  assert pqxdh.decode_bundle(s, flip_byte(encoded, pqspk_signature_at + 5))
    == Error(BadSignature("post-quantum prekey"))
  assert pqxdh.decode_bundle(s, flip_byte(encoded, mldsa_half + 5))
    == Error(BadSignature("post-quantum prekey"))
}

/// The two prekey signatures are by the same keys, so their halves are
/// genuine signatures by the right identity. Swapping the ML-DSA halves
/// between them is refused because the labels differ: neither half signs
/// the other prekey's message.
pub fn prekey_signature_halves_do_not_transfer_between_prekeys_test() {
  let s = suite.suite()
  let encoded =
    pqxdh.encode_bundle(
      start(fresh_identity(), fresh_identity()).prekeys.bundle,
    )
  let spk_half = spk_signature_at + keys.ed25519_signature_bytes
  let pqspk_half = pqspk_signature_at + keys.ed25519_signature_bytes
  let from_spk = slice(encoded, spk_half, keys.mldsa_signature_size)
  let from_pqspk = slice(encoded, pqspk_half, keys.mldsa_signature_size)
  let swapped =
    encoded
    |> splice(spk_half, from_pqspk)
    |> splice(pqspk_half, from_spk)

  assert pqxdh.decode_bundle(s, swapped) == Error(BadSignature("signed prekey"))
}

// ----------------------------------------------------- the transcript

pub fn an_honest_transcript_signature_verifies_test() {
  let s = suite.suite()
  let handshake = start(fresh_identity(), fresh_identity())
  let wire = pqxdh.encode_initial(handshake.initial)
  let assert Ok(decoded) = pqxdh.decode_initial(s, wire)
  let assert Ok(response) = respond(handshake, decoded)

  assert response.plaintext == <<"hello inviter">>
  assert identity.verify(
    s,
    handshake.joiner.public,
    pqxdh.initial_transcript(decoded, handshake.inviter.public),
    decoded.transcript_signature,
  )
}

/// The transcript, byte for byte: the label, the version, both identities,
/// the commitment, EK, CT and the ratchet message, in that order.
pub fn the_transcript_layout_test() {
  let s = suite.suite()
  let handshake = start(fresh_identity(), fresh_identity())
  let initial = handshake.initial

  assert pqxdh.initial_transcript(initial, handshake.inviter.public)
    == <<
      "Pondline_InitiatorTranscript_v1":utf8,
      1,
      identity.encode_public(handshake.joiner.public):bits,
      identity.encode_public(handshake.inviter.public):bits,
      pqxdh.commitment(s, handshake.prekeys.bundle):bits,
      keys.x25519_public_bytes(initial.ephemeral):bits,
      keys.kem_ciphertext_bytes(initial.kem_ciphertext):bits,
      initial.message:bits,
    >>
}

/// The session's associated data is the two identity fingerprints, the
/// initiator's first, 64 bytes, and both ends store exactly that in their
/// ratchet state: the version byte, a 32-bit length, then `AD`.
pub fn the_session_associated_data_is_the_two_fingerprints_test() {
  let s = suite.suite()
  let inviter = fresh_identity()
  let joiner = fresh_identity()
  let assert Ok(prekeys) = pqxdh.generate_prekeys(s, inviter)
  let assert Ok(#(joiner_state, initial)) =
    pqxdh.initiate(s, joiner, prekeys.bundle, <<"hello inviter">>)
  let assert Ok(response) = pqxdh.respond(s, inviter, prekeys, initial)
  let expected = <<
    identity.fingerprint(s, joiner.public):bits,
    identity.fingerprint(s, inviter.public):bits,
  >>

  assert pqxdh.associated_data(s, joiner.public, inviter.public) == expected
  assert bit_array.byte_size(expected) == 64

  let stored = fn(state) {
    let assert <<1, size:size(32), ad:bytes-size(size), _:bytes>> =
      secret.expose(ratchet.encode_state(state))
    ad
  }

  assert stored(joiner_state) == expected
  assert stored(response.state) == expected
}

pub fn a_transcript_signature_with_one_valid_half_is_refused_test() {
  let s = suite.suite()
  let handshake = start(fresh_identity(), fresh_identity())
  let wire = pqxdh.encode_initial(handshake.initial)
  let mldsa_half = transcript_signature_at + keys.ed25519_signature_bytes

  // Ed25519 half broken, ML-DSA-65 half intact.
  let assert Ok(classical_broken) =
    pqxdh.decode_initial(s, flip_byte(wire, transcript_signature_at + 3))

  assert respond(handshake, classical_broken)
    == Error(BadSignature("initiator transcript"))

  // ML-DSA-65 half broken, Ed25519 half intact.
  let assert Ok(post_quantum_broken) =
    pqxdh.decode_initial(s, flip_byte(wire, mldsa_half + 3))

  assert respond(handshake, post_quantum_broken)
    == Error(BadSignature("initiator transcript"))
}

/// Each half genuine and by the joiner's key, but the ML-DSA-65 half from a
/// second handshake: it signs another transcript.
pub fn a_transcript_signature_with_a_foreign_post_quantum_half_is_refused_test() {
  let s = suite.suite()
  let joiner = fresh_identity()
  let handshake = start(fresh_identity(), joiner)
  let assert Ok(#(_, other)) =
    pqxdh.initiate(s, joiner, handshake.prekeys.bundle, <<"hello inviter">>)
  let mldsa_half = transcript_signature_at + keys.ed25519_signature_bytes
  let foreign =
    slice(pqxdh.encode_initial(other), mldsa_half, keys.mldsa_signature_size)
  let wire =
    splice(pqxdh.encode_initial(handshake.initial), mldsa_half, foreign)
  let assert Ok(mixed) = pqxdh.decode_initial(s, wire)

  assert respond(handshake, mixed)
    == Error(BadSignature("initiator transcript"))
}

pub fn a_missing_or_truncated_transcript_signature_is_refused_test() {
  let s = suite.suite()
  let handshake = start(fresh_identity(), fresh_identity())
  let wire = pqxdh.encode_initial(handshake.initial)
  let size = bit_array.byte_size(wire)
  let before = slice(wire, 0, transcript_signature_at)
  let after =
    slice(wire, pqxdh.initial_fixed_bytes, size - pqxdh.initial_fixed_bytes)

  // Without the signature the ratchet message is too short to be read as
  // one, so the message does not decode at all.
  assert pqxdh.decode_initial(s, <<before:bits, after:bits>>)
    == Error(Malformed("initial message"))

  // One byte short: the decoder takes the signature's last byte from the
  // ratchet message, and the signature no longer verifies.
  let short =
    slice(wire, transcript_signature_at, keys.hybrid_signature_size - 1)
  let assert Ok(truncated) =
    pqxdh.decode_initial(s, <<before:bits, short:bits, after:bits>>)

  assert respond(handshake, truncated)
    == Error(BadSignature("initiator transcript"))
}

/// A genuine joiner signature, carried over a different bundle commitment:
/// the joiner's first handshake against another bundle of the same
/// inviter, re-pointed at this one.
pub fn a_signature_over_another_bundle_commitment_is_refused_test() {
  let inviter = fresh_identity()
  let joiner = fresh_identity()
  let handshake = start(inviter, joiner)
  let elsewhere = start(inviter, joiner)
  let repointed =
    pqxdh.InitialMessage(
      ..elsewhere.initial,
      bundle_commitment: handshake.initial.bundle_commitment,
    )

  assert respond(handshake, repointed)
    == Error(BadSignature("initiator transcript"))

  // And the honest message's signature moved onto a message naming the
  // other bundle commitment, answered by the holder of that bundle.
  let moved =
    pqxdh.InitialMessage(
      ..handshake.initial,
      bundle_commitment: elsewhere.initial.bundle_commitment,
    )

  assert respond(elsewhere, moved)
    == Error(BadSignature("initiator transcript"))
}

pub fn a_signature_over_another_ephemeral_key_is_refused_test() {
  let s = suite.suite()
  let joiner = fresh_identity()
  let handshake = start(fresh_identity(), joiner)
  let assert Ok(#(_, other)) =
    pqxdh.initiate(s, joiner, handshake.prekeys.bundle, <<"hello inviter">>)

  // The other handshake's ephemeral key under this one's signature, and
  // this one's signature on the other handshake.
  let swapped_key =
    pqxdh.InitialMessage(..handshake.initial, ephemeral: other.ephemeral)
  let swapped_signature =
    pqxdh.InitialMessage(
      ..handshake.initial,
      transcript_signature: other.transcript_signature,
    )

  assert respond(handshake, swapped_key)
    == Error(BadSignature("initiator transcript"))
  assert respond(handshake, swapped_signature)
    == Error(BadSignature("initiator transcript"))
}

pub fn a_signature_over_another_ratchet_message_is_refused_test() {
  let handshake = start(fresh_identity(), fresh_identity())
  let message = flip_byte(handshake.initial.message, 0)
  let changed = pqxdh.InitialMessage(..handshake.initial, message:)

  assert respond(handshake, changed)
    == Error(BadSignature("initiator transcript"))
}

/// The transcript names the responder, so the joiner's signature verifies
/// for the inviter it was made for and for no other identity.
pub fn the_transcript_names_the_responder_test() {
  let s = suite.suite()
  let handshake = start(fresh_identity(), fresh_identity())

  assert !identity.verify(
    s,
    handshake.joiner.public,
    pqxdh.initial_transcript(handshake.initial, fresh_identity().public),
    handshake.initial.transcript_signature,
  )
}

// ------------------------------------------------------ sizes and codecs

pub fn the_hybrid_encodings_have_their_documented_sizes_test() {
  let handshake = start(fresh_identity(), fresh_identity())
  let wire = pqxdh.encode_initial(handshake.initial)

  assert identity.public_identity_bytes == 5389
  assert pqxdh.bundle_bytes == 13_736
  assert pqxdh.initial_fixed_bytes == 10_395
  assert bit_array.byte_size(pqxdh.encode_bundle(handshake.prekeys.bundle))
    == pqxdh.bundle_bytes
  assert bit_array.byte_size(wire)
    == pqxdh.initial_fixed_bytes
    + bit_array.byte_size(handshake.initial.message)
}

/// The initial frame always pads to the 16 KiB bucket: the smallest
/// possible one (an empty ratchet plaintext) is past the 4 KiB bucket, and
/// the largest (a `Hello` at its bound) fits 16 KiB. So its padded size says
/// nothing about the `Hello` inside it.
pub fn the_initial_frame_lands_in_the_16_kib_bucket_test() {
  // Length prefix, frame tag, the fixed part, a ratchet header, the AEAD tag.
  let overhead = 4 + 1 + pqxdh.initial_fixed_bytes + ratchet.header_bytes + 16

  assert limits.padded_size(overhead) == Ok(16_384)
  assert limits.padded_size(overhead + limits.max_hello_bytes) == Ok(16_384)

  // And a real one.
  let handshake = start(fresh_identity(), fresh_identity())
  let assert Ok(padded) = frame.seal(frame.Initial(handshake.initial))

  assert bit_array.byte_size(envelope.to_wire(padded)) == 16_384
}

fn terms(description: String) -> relationship.Terms {
  let s = suite.suite()
  let assert Ok(port) = endpoint.port(7000)
  let assert Ok(inbox) = route.new_inbox(s, endpoint.Loopback(port))

  relationship.Terms(inbox:, description:, budget: 3)
}

/// The full pairing over the real suite, through every codec that carries
/// an identity: the invitation file, the offer snapshot, the joining and
/// awaiting relationship snapshots, the initial frame, and the redeemed
/// relationship snapshot. Each round-trips byte for byte.
pub fn pairing_round_trips_the_larger_identities_test() {
  let s = suite.suite()
  let now = Instant(1000)
  let description = string.repeat("d", limits.max_description_bytes)
  let assert Ok(made) =
    offer.create(s, terms(description), offer.AutoApprove, now)
  let opened = offer.provisioned(made.state)
  let assert Ok(invite) = offer.invitation(opened)

  // The invitation file, at the largest description, inside its bound.
  let file = secret.expose(invitation.encode(invite))
  let assert Ok(read_back) = invitation.decode(s, file)

  assert read_back == invite
  assert bit_array.byte_size(file) <= limits.max_invitation_bytes
  assert bit_array.byte_size(file) > pqxdh.bundle_bytes

  // The open offer, holding the inviter's identity and prekey secrets.
  let offer_blob = secret.expose(snapshot.encode_offer(opened))
  let assert Ok(offer_back) = snapshot.decode_offer(s, offer_blob)

  assert secret.expose(snapshot.encode_offer(offer_back)) == offer_blob

  // The joiner's side, before and after the handshake.
  let assert Ok(joining) =
    relationship.join(s, invite, endpoint.TorOrLoopback, terms("j"), now)
  let joining_blob = secret.expose(snapshot.encode_relationship(joining.state))
  let assert Ok(joining_back) = snapshot.decode_relationship(s, joining_blob)

  assert secret.expose(snapshot.encode_relationship(joining_back))
    == joining_blob

  let assert Ok(started) = relationship.joined(s, joining.state, now)
  let awaiting_blob = secret.expose(snapshot.encode_relationship(started.state))
  let assert Ok(_) = snapshot.decode_relationship(s, awaiting_blob)

  // The inviter redeems the initial frame and the relationship it makes
  // round-trips too.
  let assert [plan.Outbound(padded:, ..)] = started.records
  let assert Ok(frame.Initial(initial)) = frame.open(s, padded)
  let assert offer.Open(stock) = opened.phase
  let assert Ok(envelope_id) = id_from(2)
  let ref =
    plan.EnvelopeRef(
      queue: stock.inbox.queue,
      envelope: envelope_id,
      digest: <<>>,
    )
  let assert Ok(offer.Redeemed(plan: redeemed, ..)) =
    offer.redeem(s, opened, endpoint.TorOrLoopback, ref, initial, now)
  let inviter_blob = secret.expose(snapshot.encode_relationship(redeemed.state))
  let assert Ok(inviter_back) = snapshot.decode_relationship(s, inviter_blob)

  assert secret.expose(snapshot.encode_relationship(inviter_back))
    == inviter_blob
  assert bit_array.byte_size(inviter_blob) < limits.max_snapshot_bytes
}

fn id_from(number: Int) {
  core_id.from_bytes(<<number:128>>)
}
