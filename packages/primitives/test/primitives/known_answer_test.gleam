//// Known-answer tests: each primitive against its standard's published
//// vectors, so the bindings are shown to call the algorithm the name says
//// with the byte order the protocol code assumes. ML-KEM has no
//// deterministic key generation through OTP, so it is checked by round
//// trip, size and implicit rejection instead.

import gleam/bit_array
import gleam/string
import primitives

fn hex(text: String) -> BitArray {
  let assert Ok(bytes) =
    text
    |> string.replace(" ", "")
    |> string.uppercase
    |> bit_array.base16_decode
    as "test vectors are well-formed hex"
  bytes
}

pub fn sha256_abc_test() {
  assert primitives.sha256(<<"abc">>)
    == hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
}

pub fn hmac_rfc4231_case_1_test() {
  let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")

  assert primitives.hmac_sha256(key, <<"Hi There">>)
    == hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
}

pub fn hmac_rfc4231_case_2_test() {
  assert primitives.hmac_sha256(<<"Jefe">>, <<"what do ya want for nothing?">>)
    == hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
}

pub fn x25519_rfc7748_scalar_mult_test() {
  let scalar =
    hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
  let point =
    hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")

  assert primitives.x25519(scalar, point)
    == Ok(hex(
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ))
}

pub fn x25519_rfc7748_diffie_hellman_test() {
  let alice =
    hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
  let bob =
    hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
  let alice_public =
    hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
  let bob_public =
    hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
  let shared =
    hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

  assert primitives.x25519_public(alice) == Ok(alice_public)
  assert primitives.x25519_public(bob) == Ok(bob_public)
  assert primitives.x25519(alice, bob_public) == Ok(shared)
  assert primitives.x25519(bob, alice_public) == Ok(shared)
}

pub fn x25519_refuses_a_low_order_point_test() {
  let #(secret, _public) = primitives.x25519_keypair()

  assert primitives.x25519(secret, <<0:256>>) == Error(Nil)
}

/// The order-8 point of RFC 7748 §6.1's low-order list, and the order-4 point
/// u = 1: a clamped scalar sends each to the identity, so the shared secret
/// is all zeros and must be refused.
pub fn x25519_refuses_small_order_points_test() {
  let #(secret, _public) = primitives.x25519_keypair()
  let order_8 =
    hex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157")

  assert primitives.x25519(secret, order_8) == Error(Nil)
  assert primitives.x25519(secret, <<1, 0:248>>) == Error(Nil)
}

pub fn x25519_refuses_wrong_sizes_test() {
  let #(secret, public) = primitives.x25519_keypair()

  assert primitives.x25519(<<secret:bits, 0>>, public) == Error(Nil)
  assert primitives.x25519(secret, <<1, 2, 3>>) == Error(Nil)
}

pub fn ed25519_rfc8032_test_1_test() {
  let secret =
    hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  let public =
    hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
  let signature =
    hex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )

  assert primitives.ed25519_public(secret) == Ok(public)
  assert primitives.ed25519_sign(secret, <<>>) == Ok(signature)
  assert primitives.ed25519_verify(public, <<>>, signature)
}

pub fn ed25519_rejects_a_changed_message_test() {
  let #(secret, public) = primitives.ed25519_keypair()
  let assert Ok(signature) = primitives.ed25519_sign(secret, <<"hello">>)

  assert !primitives.ed25519_verify(public, <<"hellp">>, signature)
  assert !primitives.ed25519_verify(public, <<"hello">>, <<1, 2, 3>>)
}

pub fn chacha20_poly1305_rfc8439_test() {
  let key =
    hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
  let nonce = hex("070000004041424344454647")
  let aad = hex("50515253c0c1c2c3c4c5c6c7")
  let plaintext = <<
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
  >>
  let sealed =
    hex(
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
      <> "1ae10b594f09e26a7e902ecbd0600691",
    )

  assert primitives.aead_seal(key:, nonce:, aad:, plaintext:) == Ok(sealed)
  assert primitives.aead_open(key:, nonce:, aad:, sealed:) == Ok(plaintext)
}

pub fn chacha20_poly1305_rejects_tampering_test() {
  let key = primitives.random_bytes(32)
  let nonce = primitives.random_bytes(12)
  let assert Ok(sealed) =
    primitives.aead_seal(key:, nonce:, aad: <<"ad">>, plaintext: <<"secret">>)
  let assert <<first, rest:bits>> = sealed
  let flipped = <<{ { first + 1 } % 256 }, rest:bits>>

  assert primitives.aead_open(key:, nonce:, aad: <<"ad">>, sealed: flipped)
    == Error(Nil)
  assert primitives.aead_open(key:, nonce:, aad: <<"AD">>, sealed:)
    == Error(Nil)
  assert primitives.aead_open(key:, nonce:, aad: <<"ad">>, sealed: <<1, 2>>)
    == Error(Nil)
}

pub fn mlkem1024_round_trip_test() {
  let #(secret, public) = primitives.mlkem1024_keypair()
  let assert Ok(#(shared, ciphertext)) =
    primitives.mlkem1024_encapsulate(public)

  assert bit_array.byte_size(public) == primitives.mlkem1024_public_bytes
  assert bit_array.byte_size(secret) == primitives.mlkem1024_secret_bytes
  assert bit_array.byte_size(ciphertext)
    == primitives.mlkem1024_ciphertext_bytes
  assert bit_array.byte_size(shared) == primitives.mlkem_shared_secret_bytes
  assert primitives.mlkem1024_decapsulate(secret, ciphertext) == Ok(shared)
}

pub fn mlkem1024_implicit_rejection_test() {
  let #(secret, public) = primitives.mlkem1024_keypair()
  let assert Ok(#(shared, ciphertext)) =
    primitives.mlkem1024_encapsulate(public)
  let assert <<first, rest:bits>> = ciphertext
  let forged = <<{ { first + 1 } % 256 }, rest:bits>>

  let assert Ok(other) = primitives.mlkem1024_decapsulate(secret, forged)
  assert other != shared
  assert primitives.mlkem1024_decapsulate(secret, <<1, 2, 3>>) == Error(Nil)
}

pub fn constant_time_equal_test() {
  assert primitives.constant_time_equal(<<1, 2, 3>>, <<1, 2, 3>>)
  assert !primitives.constant_time_equal(<<1, 2, 3>>, <<1, 2, 4>>)
  assert !primitives.constant_time_equal(<<1, 2, 3>>, <<1, 2>>)
}

pub fn openssl_supports_mlkem_test() {
  assert string.starts_with(primitives.openssl_version(), "OpenSSL 3.")
}
