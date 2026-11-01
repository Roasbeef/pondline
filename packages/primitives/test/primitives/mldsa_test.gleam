//// ML-DSA-65 (FIPS 204) through OTP's `crypto`.
////
//// There is no fixed-output known-answer test here, for two reasons found
//// on OTP 29 over OpenSSL 3.6. OpenSSL signs in FIPS 204's hedged mode, so
//// a signature mixes in fresh randomness and no two are alike. And
//// `crypto:generate_key(mldsa65, [], {seed, Seed})` raises rather than
//// deriving the key pair from a seed, so a seed-to-public-key vector cannot
//// be reached either (`crypto:sign` does accept `{seed, Seed}` as a key,
//// but nothing returns the public key that answers it). The binding is
//// therefore checked by sizes, round trips, and the rejections a verifier
//// must make: a changed message, a changed signature, the wrong key, and
//// inputs of the wrong size.

import gleam/bit_array
import gleam/int
import primitives

fn flip_byte(bytes: BitArray, index: Int) -> BitArray {
  let assert Ok(head) = bit_array.slice(bytes, 0, index)
  let assert Ok(<<byte>>) = bit_array.slice(bytes, index, 1)
  let assert Ok(tail) =
    bit_array.slice(bytes, index + 1, bit_array.byte_size(bytes) - index - 1)

  <<head:bits, int.bitwise_exclusive_or(byte, 1), tail:bits>>
}

pub fn mldsa65_sizes_and_round_trip_test() {
  let #(secret, public) = primitives.mldsa65_keypair()
  let assert Ok(signature) = primitives.mldsa65_sign(secret, <<"message">>)

  assert bit_array.byte_size(public) == primitives.mldsa65_public_bytes
  assert bit_array.byte_size(secret) == primitives.mldsa65_secret_bytes
  assert bit_array.byte_size(signature) == primitives.mldsa65_signature_bytes
  assert primitives.mldsa65_verify(public, <<"message">>, signature)
}

/// Hedged signing: the same message signs differently each time, and every
/// signature verifies. A protocol must not rely on a signature being
/// reproducible, which is why a retried initial message is resent from its
/// committed bytes rather than signed again.
pub fn mldsa65_signing_is_hedged_test() {
  let #(secret, public) = primitives.mldsa65_keypair()
  let assert Ok(first) = primitives.mldsa65_sign(secret, <<"same">>)
  let assert Ok(second) = primitives.mldsa65_sign(secret, <<"same">>)

  assert first != second
  assert primitives.mldsa65_verify(public, <<"same">>, first)
  assert primitives.mldsa65_verify(public, <<"same">>, second)
}

pub fn mldsa65_rejects_a_changed_message_test() {
  let #(secret, public) = primitives.mldsa65_keypair()
  let assert Ok(signature) = primitives.mldsa65_sign(secret, <<"message">>)

  assert !primitives.mldsa65_verify(public, <<"messagf">>, signature)
  assert !primitives.mldsa65_verify(public, <<"message", 0>>, signature)
  assert !primitives.mldsa65_verify(public, <<>>, signature)
}

pub fn mldsa65_rejects_a_changed_signature_test() {
  let #(secret, public) = primitives.mldsa65_keypair()
  let assert Ok(signature) = primitives.mldsa65_sign(secret, <<"message">>)

  // The first byte, one in the middle, and the last.
  assert !primitives.mldsa65_verify(
    public,
    <<"message">>,
    flip_byte(signature, 0),
  )
  assert !primitives.mldsa65_verify(
    public,
    <<"message">>,
    flip_byte(signature, 1654),
  )
  assert !primitives.mldsa65_verify(
    public,
    <<"message">>,
    flip_byte(signature, primitives.mldsa65_signature_bytes - 1),
  )
}

pub fn mldsa65_rejects_the_wrong_key_test() {
  let #(secret, _) = primitives.mldsa65_keypair()
  let #(_, other) = primitives.mldsa65_keypair()
  let assert Ok(signature) = primitives.mldsa65_sign(secret, <<"message">>)

  assert !primitives.mldsa65_verify(other, <<"message">>, signature)
}

/// Wrong sizes are refused without raising. A short public key is the case
/// that matters most: OTP raises on it, with the key in the error, and the
/// shim turns that into `False`.
pub fn mldsa65_refuses_wrong_sizes_test() {
  let #(secret, public) = primitives.mldsa65_keypair()
  let assert Ok(signature) = primitives.mldsa65_sign(secret, <<"m">>)
  let assert Ok(short_public) = bit_array.slice(public, 0, 1951)
  let assert Ok(short_signature) = bit_array.slice(signature, 0, 3308)
  let assert Ok(short_secret) = bit_array.slice(secret, 0, 4031)

  assert primitives.mldsa65_sign(short_secret, <<"m">>) == Error(Nil)
  assert primitives.mldsa65_sign(<<>>, <<"m">>) == Error(Nil)
  assert !primitives.mldsa65_verify(short_public, <<"m">>, signature)
  assert !primitives.mldsa65_verify(<<public:bits, 0>>, <<"m">>, signature)
  assert !primitives.mldsa65_verify(public, <<"m">>, short_signature)
  assert !primitives.mldsa65_verify(public, <<"m">>, <<signature:bits, 0>>)
  assert !primitives.mldsa65_verify(public, <<"m">>, <<>>)
}

/// A public key of the right size but the wrong content (all zeros, and a
/// key's own secret prefix) verifies nothing rather than raising.
pub fn mldsa65_refuses_a_garbage_public_key_test() {
  let #(secret, _) = primitives.mldsa65_keypair()
  let assert Ok(signature) = primitives.mldsa65_sign(secret, <<"m">>)
  let assert Ok(prefix) = bit_array.slice(secret, 0, 1952)

  assert !primitives.mldsa65_verify(<<0:size(15_616)>>, <<"m">>, signature)
  assert !primitives.mldsa65_verify(prefix, <<"m">>, signature)
}

/// A secret of the right size but the wrong content either signs nothing
/// that verifies or is refused, and never raises.
pub fn mldsa65_garbage_secret_never_raises_test() {
  let #(_, public) = primitives.mldsa65_keypair()

  case primitives.mldsa65_sign(<<0:size(32_256)>>, <<"m">>) {
    Ok(signature) -> {
      assert !primitives.mldsa65_verify(public, <<"m">>, signature)
    }

    Error(Nil) -> Nil
  }
}
