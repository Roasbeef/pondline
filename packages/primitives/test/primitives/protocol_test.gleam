//// PQXDH and the Double Ratchet over the real primitives: a handshake, then
//// conversations that exercise ordering, replay, tampering, the skip bounds
//// and state persistence.
////
//// There are no external vectors for PQXDH, so what these tests establish is
//// that the two sides agree, that every authentication check rejects what it
//// should, and that the prepare/commit contract holds: a failed or
//// uncommitted decrypt leaves the old state able to decrypt again.

import core/crypto/error.{
  AuthenticationFailed, BadSignature, MessageKeyUnavailable, SkipLimitExceeded,
  UnknownBundle,
}
import core/crypto/identity
import core/crypto/keys
import core/crypto/pqxdh
import core/crypto/ratchet
import core/secret
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import primitives
import primitives/suite

/// The two ends of an established conversation: the joiner (initiator) and
/// the inviter (responder).
type Pair {
  Pair(
    joiner: ratchet.State,
    inviter: ratchet.State,
    joiner_identity: identity.Identity,
    inviter_identity: identity.Identity,
    prekeys: pqxdh.Prekeys,
    initial: pqxdh.InitialMessage,
  )
}

fn fresh_identity() -> identity.Identity {
  let assert Ok(id) = identity.generate(suite.suite())
    as "key generation succeeds"
  id
}

fn handshake() -> Pair {
  let s = suite.suite()
  let inviter_identity = fresh_identity()
  let joiner_identity = fresh_identity()

  let assert Ok(prekeys) = pqxdh.generate_prekeys(s, inviter_identity)
    as "prekeys generate"

  // The bundle travels as bytes inside the invitation file.
  let assert Ok(bundle) =
    pqxdh.decode_bundle(s, pqxdh.encode_bundle(prekeys.bundle))
    as "an honest bundle verifies"
  let assert Ok(#(joiner, initial)) =
    pqxdh.initiate(s, joiner_identity, bundle, <<"hello inviter">>)
    as "the joiner initiates"

  // The initial message also travels as bytes.
  let assert Ok(initial) =
    pqxdh.decode_initial(s, pqxdh.encode_initial(initial))
    as "an honest initial message decodes"
  let assert Ok(response) = pqxdh.respond(s, inviter_identity, prekeys, initial)
    as "the inviter responds"

  assert response.plaintext == <<"hello inviter">>
  assert response.consumed_bundle == pqxdh.commitment(s, prekeys.bundle)

  Pair(
    joiner: joiner,
    inviter: response.state,
    joiner_identity: joiner_identity,
    inviter_identity: inviter_identity,
    prekeys: prekeys,
    initial: initial,
  )
}

fn send(state: ratchet.State, text: String) -> #(ratchet.State, BitArray) {
  let assert Ok(sent) = ratchet.encrypt(suite.suite(), state, <<text:utf8>>)
    as "encrypt succeeds"
  sent
}

fn receive(state: ratchet.State, message: BitArray, text: String) {
  let assert Ok(#(next, plaintext)) =
    ratchet.decrypt(suite.suite(), state, message)
    as "decrypt succeeds"
  assert plaintext == <<text:utf8>>
  next
}

fn decrypt_error(state: ratchet.State, message: BitArray) {
  case ratchet.decrypt(suite.suite(), state, message) {
    Ok(_) -> panic as "decrypt should have failed"
    Error(reason) -> reason
  }
}

pub fn in_order_both_directions_test() {
  let pair = handshake()

  let #(joiner, m1) = send(pair.joiner, "one")
  let #(joiner, m2) = send(joiner, "two")
  let inviter = receive(pair.inviter, m1, "one")
  let inviter = receive(inviter, m2, "two")

  // The inviter can send only after receiving, and its reply starts a new
  // chain, which the joiner's next message answers in turn.
  let #(inviter, r1) = send(inviter, "reply one")
  let joiner = receive(joiner, r1, "reply one")
  let #(joiner, m3) = send(joiner, "three")
  let inviter = receive(inviter, m3, "three")
  let #(inviter, r2) = send(inviter, "reply two")
  let #(inviter, r3) = send(inviter, "reply three")
  let joiner = receive(joiner, r2, "reply two")
  let _ = receive(joiner, r3, "reply three")
  let _ = inviter
}

pub fn a_responder_cannot_send_before_receiving_test() {
  let assert Ok(#(dh_secret, dh_public)) = keys.generate_x25519(suite.suite())
  let state =
    ratchet.init_receiver(secret.new(<<0:256>>), <<>>, dh_secret, dh_public)

  assert ratchet.encrypt(suite.suite(), state, <<"too early">>)
    == Error(error.NoSendingChain)
}

pub fn out_of_order_within_the_bound_test() {
  let pair = handshake()
  let #(joiner, m1) = send(pair.joiner, "m1")
  let #(joiner, m2) = send(joiner, "m2")
  let #(joiner, m3) = send(joiner, "m3")
  let #(joiner, m4) = send(joiner, "m4")

  // Delivered as 3, 1, 4, 2 on the inviter's side.
  let inviter = receive(pair.inviter, m3, "m3")
  let inviter = receive(inviter, m1, "m1")
  let inviter = receive(inviter, m4, "m4")
  let inviter = receive(inviter, m2, "m2")

  // The old chain's leftovers survive a DH step: the inviter replies, the
  // joiner answers on a new chain, and a late message from the old chain
  // still decrypts after that.
  let #(joiner, m5) = send(joiner, "m5")
  let #(inviter, r1) = send(inviter, "r1")
  let joiner = receive(joiner, r1, "r1")
  let #(joiner, m6) = send(joiner, "m6")
  let inviter = receive(inviter, m6, "m6")
  let _ = receive(inviter, m5, "m5")
  let _ = joiner
}

pub fn a_replay_fails_on_the_state_that_consumed_it_test() {
  let pair = handshake()
  let #(_, m1) = send(pair.joiner, "m1")
  let consumed = receive(pair.inviter, m1, "m1")

  assert decrypt_error(consumed, m1) == MessageKeyUnavailable
}

pub fn a_replayed_skipped_message_fails_the_second_time_test() {
  let pair = handshake()
  let #(joiner, m1) = send(pair.joiner, "m1")
  let #(_, m2) = send(joiner, "m2")

  // m2 first, so m1's key is stored; m1 then consumes it.
  let inviter = receive(pair.inviter, m2, "m2")
  let inviter = receive(inviter, m1, "m1")

  assert decrypt_error(inviter, m1) == MessageKeyUnavailable
}

pub fn the_old_state_still_decrypts_after_a_new_one_is_returned_test() {
  let pair = handshake()
  let #(_, m1) = send(pair.joiner, "m1")
  let _committed = receive(pair.inviter, m1, "m1")

  // The caller's transaction failed and it kept `pair.inviter`: the same
  // message decrypts again, and the encrypt side behaves the same way.
  let _again = receive(pair.inviter, m1, "m1")

  let #(_, first) = send(pair.joiner, "same state")
  let #(_, second) = send(pair.joiner, "same state")

  assert first == second
}

pub fn a_failed_decrypt_does_not_change_what_the_state_can_do_test() {
  let pair = handshake()
  let #(_, m1) = send(pair.joiner, "m1")

  assert result.is_error(ratchet.decrypt(
    suite.suite(),
    pair.inviter,
    flip_byte(m1, 50),
  ))

  let _ = receive(pair.inviter, m1, "m1")
}

fn flip_byte(message: BitArray, index: Int) -> BitArray {
  let assert Ok(head) = bit_array.slice(message, 0, index)
  let assert Ok(<<byte>>) = bit_array.slice(message, index, 1)
  let assert Ok(tail) =
    bit_array.slice(
      message,
      index + 1,
      bit_array.byte_size(message) - index - 1,
    )

  let changed = int.bitwise_exclusive_or(byte, 1)

  <<head:bits, changed, tail:bits>>
}

pub fn any_tampered_byte_fails_test() {
  let pair = handshake()
  let #(_, m1) = send(pair.joiner, "tamper with me")
  let size = bit_array.byte_size(m1)

  int.range(from: 0, to: size, with: Nil, run: fn(_, index) {
    assert result.is_error(ratchet.decrypt(
      suite.suite(),
      pair.inviter,
      flip_byte(m1, index),
    ))
  })
}

pub fn a_truncated_message_fails_test() {
  let pair = handshake()
  let #(_, m1) = send(pair.joiner, "m1")
  let assert Ok(short) = bit_array.slice(m1, 0, 20)

  assert result.is_error(ratchet.decrypt(suite.suite(), pair.inviter, short))
  assert result.is_error(ratchet.decrypt(suite.suite(), pair.inviter, <<>>))
}

fn send_many(
  state: ratchet.State,
  count: Int,
) -> #(ratchet.State, List(BitArray)) {
  int.range(from: 0, to: count, with: #(state, []), run: fn(acc, _) {
    let #(state, messages) = acc
    let #(state, message) = send(state, "filler")
    #(state, [message, ..messages])
  })
}

pub fn the_per_message_skip_bound_is_enforced_test() {
  let pair = handshake()
  let #(_, messages) = send_many(pair.joiner, 1002)

  // The newest message is number 1002 and the inviter expects number 1, so
  // 1001 keys would have to be skipped.
  let assert [newest, ..] = messages

  assert decrypt_error(pair.inviter, newest) == SkipLimitExceeded

  // A gap of exactly the bound is accepted: number 1001 skips 1000.
  let assert [_, at_bound, ..] = messages
  let assert Ok(_) = ratchet.decrypt(suite.suite(), pair.inviter, at_bound)
}

pub fn the_oldest_stored_key_is_evicted_at_the_bound_test() {
  let pair = handshake()

  // Chain one: deliver number 1001 so 1000 keys are stored.
  let #(joiner, first) = send_many(pair.joiner, 1001)
  let assert [newest, ..] = first
  let inviter = receive_any(pair.inviter, newest)
  let #(inviter, reply) = send(inviter, "r")
  let joiner = receive(joiner, reply, "r")

  // Chain two, from the other direction's turn: another 1000.
  let #(joiner, second) = send_many(joiner, 1001)
  let assert [newest, ..] = second
  let inviter = receive_any(inviter, newest)
  let #(inviter, reply) = send(inviter, "r")
  let joiner = receive(joiner, reply, "r")

  // Chain three skips one more key, the 2001st, so the oldest is evicted
  // and the session carries on.
  let #(joiner, _) = send(joiner, "skipped")
  let #(_, third) = send(joiner, "arrives")
  let inviter = receive(inviter, third, "arrives")

  // The oldest stored key was chain one's number 1; its neighbour survives.
  let assert [oldest, next_oldest, ..] = list.reverse(first)

  assert decrypt_error(inviter, oldest) == AuthenticationFailed

  let _ = receive_any(inviter, next_oldest)
}

fn receive_any(state: ratchet.State, message: BitArray) -> ratchet.State {
  let assert Ok(#(next, _)) = ratchet.decrypt(suite.suite(), state, message)
    as "decrypt succeeds"
  next
}

pub fn state_round_trips_mid_conversation_test() {
  let pair = handshake()
  let #(joiner, m1) = send(pair.joiner, "m1")
  let #(joiner, m2) = send(joiner, "m2")
  let inviter = receive(pair.inviter, m2, "m2")

  // Persist and restore both sides while a message is outstanding.
  let assert Ok(joiner) =
    ratchet.decode_state(secret.expose(ratchet.encode_state(joiner)))
  let assert Ok(inviter) =
    ratchet.decode_state(secret.expose(ratchet.encode_state(inviter)))

  let inviter = receive(inviter, m1, "m1")
  let #(inviter, r1) = send(inviter, "r1")
  let joiner = receive(joiner, r1, "r1")
  let #(_, m3) = send(joiner, "m3")
  let _ = receive(inviter, m3, "m3")
}

pub fn encoding_is_deterministic_and_decoding_is_total_test() {
  let pair = handshake()
  let encoded = secret.expose(ratchet.encode_state(pair.joiner))

  assert encoded == secret.expose(ratchet.encode_state(pair.joiner))
  assert result.is_error(ratchet.decode_state(<<>>))
  assert result.is_error(ratchet.decode_state(<<9, encoded:bits>>))
  assert result.is_error(ratchet.decode_state(<<encoded:bits, 0>>))

  let size = bit_array.byte_size(encoded)
  let assert Ok(truncated) = bit_array.slice(encoded, 0, size - 1)

  assert result.is_error(ratchet.decode_state(truncated))
}

pub fn a_state_claiming_too_many_skipped_keys_is_refused_test() {
  let pair = handshake()
  let encoded = secret.expose(ratchet.encode_state(pair.joiner))
  let size = bit_array.byte_size(encoded)

  // The skipped-key count is the last four bytes of a state with none.
  let assert Ok(body) = bit_array.slice(encoded, 0, size - 4)
  let hostile = <<body:bits, 0xFFFFFFFF:size(32)>>

  assert ratchet.decode_state(hostile) == Error(error.SkippedKeyStoreFull)
}

pub fn a_bad_signed_prekey_signature_is_rejected_test() {
  let s = suite.suite()
  let prekeys = handshake().prekeys
  let encoded = pqxdh.encode_bundle(prekeys.bundle)

  // Layout: version, identity (128), SPK (32), SPK signature (64), PQSPK.
  assert pqxdh.decode_bundle(s, flip_byte(encoded, 129))
    == Error(BadSignature("signed prekey"))
  assert pqxdh.decode_bundle(s, flip_byte(encoded, 161))
    == Error(BadSignature("signed prekey"))
}

pub fn a_bad_post_quantum_prekey_signature_is_rejected_test() {
  let s = suite.suite()
  let prekeys = handshake().prekeys
  let encoded = pqxdh.encode_bundle(prekeys.bundle)

  assert pqxdh.decode_bundle(s, flip_byte(encoded, 225))
    == Error(BadSignature("post-quantum prekey"))
  assert pqxdh.decode_bundle(s, flip_byte(encoded, 1856))
    == Error(BadSignature("post-quantum prekey"))
}

pub fn a_broken_identity_binding_is_rejected_test() {
  let s = suite.suite()
  let encoded = pqxdh.encode_bundle(handshake().prekeys.bundle)

  assert pqxdh.decode_bundle(s, flip_byte(encoded, 100))
    == Error(BadSignature("identity binding"))
}

pub fn a_bundle_with_a_substituted_prekey_is_rejected_test() {
  let s = suite.suite()
  let honest = pqxdh.encode_bundle(handshake().prekeys.bundle)
  let attacker = pqxdh.encode_bundle(handshake().prekeys.bundle)

  // The attacker's prekeys grafted under the honest identity: everything
  // from the SPK on comes from another inviter.
  let assert Ok(identity_part) = bit_array.slice(honest, 0, 129)
  let assert Ok(prekey_part) = bit_array.slice(attacker, 129, 1857 - 129)

  assert result.is_error(
    pqxdh.decode_bundle(s, <<identity_part:bits, prekey_part:bits>>),
  )

  // And the attacker's whole identity swapped in under the honest prekeys.
  let assert Ok(attacker_identity) = bit_array.slice(attacker, 0, 129)
  let assert Ok(honest_prekeys) = bit_array.slice(honest, 129, 1857 - 129)

  assert result.is_error(
    pqxdh.decode_bundle(s, <<attacker_identity:bits, honest_prekeys:bits>>),
  )
}

pub fn a_swapped_initiator_identity_fails_test() {
  let s = suite.suite()
  let pair = handshake()
  let mallory = fresh_identity()
  let swapped = pqxdh.InitialMessage(..pair.initial, identity: mallory.public)

  // The responder's agreement and associated data both use the identity the
  // message names, so the first message no longer authenticates.
  assert pqxdh.respond(s, pair.inviter_identity, pair.prekeys, swapped)
    == Error(AuthenticationFailed)
}

pub fn a_forged_kem_ciphertext_fails_test() {
  let s = suite.suite()
  let pair = handshake()
  let ciphertext = keys.kem_ciphertext_bytes(pair.initial.kem_ciphertext)
  let assert Ok(forged) = keys.kem_ciphertext(flip_byte(ciphertext, 7))
  let initial = pqxdh.InitialMessage(..pair.initial, kem_ciphertext: forged)

  // ML-KEM rejects implicitly, so this surfaces as a failed authentication.
  assert pqxdh.respond(s, pair.inviter_identity, pair.prekeys, initial)
    == Error(AuthenticationFailed)
}

pub fn a_different_bundles_commitment_is_refused_test() {
  let s = suite.suite()
  let pair = handshake()
  let assert Ok(other) = pqxdh.generate_prekeys(s, pair.inviter_identity)

  assert pqxdh.respond(s, pair.inviter_identity, other, pair.initial)
    == Error(UnknownBundle)
}

pub fn the_wrong_responder_identity_is_named_test() {
  let s = suite.suite()
  let pair = handshake()

  assert pqxdh.respond(s, fresh_identity(), pair.prekeys, pair.initial)
    == Error(error.IdentityMismatch)
}

pub fn a_retried_initial_message_gives_the_same_session_test() {
  let s = suite.suite()
  let pair = handshake()

  // The prekeys are untouched by `respond`, so a crash before the caller
  // stored the state can retry the same initial message.
  let assert Ok(again) =
    pqxdh.respond(s, pair.inviter_identity, pair.prekeys, pair.initial)

  assert again.plaintext == <<"hello inviter">>
}

pub fn identity_encoding_and_fingerprint_test() {
  let s = suite.suite()
  let id = fresh_identity()
  let encoded = identity.encode_public(id.public)

  assert bit_array.byte_size(encoded) == identity.public_identity_bytes
  assert identity.decode_public(s, encoded) == Ok(id.public)
  assert identity.fingerprint(s, id.public) == primitives.sha256(encoded)
  assert result.is_error(identity.decode_public(s, flip_byte(encoded, 3)))
  assert pqxdh.bundle_bytes
    == bit_array.byte_size(pqxdh.encode_bundle(handshake().prekeys.bundle))
}

pub fn key_sizes_match_the_primitives_test() {
  assert keys.x25519_bytes == primitives.x25519_bytes
  assert keys.ed25519_key_bytes == primitives.ed25519_key_bytes
  assert keys.ed25519_signature_bytes == primitives.ed25519_signature_bytes
  assert keys.kem_public_size == primitives.mlkem1024_public_bytes
  assert keys.kem_secret_size == primitives.mlkem1024_secret_bytes
  assert keys.kem_ciphertext_size == primitives.mlkem1024_ciphertext_bytes
  assert keys.kem_shared_secret_bytes == primitives.mlkem_shared_secret_bytes
}

fn state_with_skipped_count(count: Int) -> BitArray {
  let encoded = secret.expose(ratchet.encode_state(handshake().joiner))
  let size = bit_array.byte_size(encoded)
  let assert Ok(body) = bit_array.slice(encoded, 0, size - 4)
  let entries = <<0:size(68 * 8)>>

  int.range(
    from: 0,
    to: count,
    with: <<body:bits, count:size(32)>>,
    run: fn(acc, _) { <<acc:bits, entries:bits>> },
  )
}

pub fn the_stored_key_count_is_bounded_when_decoding_test() {
  assert result.is_ok(ratchet.decode_state(state_with_skipped_count(2000)))
  assert ratchet.decode_state(state_with_skipped_count(2001))
    == Error(error.SkippedKeyStoreFull)
}

/// A message numbered at the sender's limit is refused before any key is
/// derived, so a receiver's next number can never reach 2^32.
pub fn a_message_number_at_the_limit_is_refused_test() {
  let pair = handshake()
  let #(_, m1) = send(pair.joiner, "m1")
  let assert Ok(prefix) = bit_array.slice(m1, 0, 36)
  let assert Ok(rest) = bit_array.slice(m1, 40, bit_array.byte_size(m1) - 40)
  let forged = <<prefix:bits, 0xFFFFFFFF:size(32), rest:bits>>

  assert decrypt_error(pair.inviter, forged) == error.CounterExhausted
}

/// Known answer for the handshake's key derivation, computed independently
/// (Python hmac/hashlib) for DH1..DH3 = 0x01.., 0x02.., 0x03.. and SS = 0x04..
/// in 32-byte runs, with 32 bytes of 0xFF as the prefix. A prefix of 31 zero
/// bytes and one 0xFF, which an earlier revision produced, gives another value.
pub fn pqxdh_shared_secret_known_answer_test() {
  let assert Ok(shared) =
    pqxdh.derive_shared(
      suite.suite(),
      <<
        0x0101010101010101010101010101010101010101010101010101010101010101:size(256),
      >>,
      <<
        0x0202020202020202020202020202020202020202020202020202020202020202:size(256),
      >>,
      <<
        0x0303030303030303030303030303030303030303030303030303030303030303:size(256),
      >>,
      <<
        0x0404040404040404040404040404040404040404040404040404040404040404:size(256),
      >>,
    )
  assert secret.expose(shared)
    == <<
      0x6fba3e33d9b8711d0c4d6c4cd0a02a835617f0313bfe5f74992c5fb903b75473:size(256),
    >>
}
