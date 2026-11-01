//// The production `core/crypto/suite.Suite`, built from `primitives`.
////
//// `core` is pure and receives its cryptography as a record of functions
//// (`docs/gleam-style.md` Part IV §5). This is the one place that record is
//// filled with the real implementations. The test suite that stands in for
//// it lives under `core`'s `test/` directory and nowhere that a release
//// build compiles, so the fake can never be selected in production
//// (`docs/spec.md` §13.3).

import core/crypto/suite.{type Suite, Suite}
import primitives

/// The suite backed by OTP's `crypto` over OpenSSL.
///
/// ## Examples
///
/// ```gleam
/// let suite = suite.suite()
/// bit_array.byte_size(suite.random(32))
/// // -> 32
/// ```
pub fn suite() -> Suite {
  Suite(
    random: primitives.random_bytes,
    sha256: primitives.sha256,
    hmac_sha256: primitives.hmac_sha256,
    constant_time_equal: primitives.constant_time_equal,
    x25519_keypair: primitives.x25519_keypair,
    x25519: primitives.x25519,
    ed25519_keypair: primitives.ed25519_keypair,
    ed25519_sign: primitives.ed25519_sign,
    ed25519_verify: primitives.ed25519_verify,
    kem_keypair: primitives.mlkem1024_keypair,
    kem_encapsulate: primitives.mlkem1024_encapsulate,
    kem_decapsulate: primitives.mlkem1024_decapsulate,
    aead_seal: fn(key, nonce, aad, plaintext) {
      primitives.aead_seal(key, nonce, aad, plaintext)
    },
    aead_open: fn(key, nonce, aad, sealed) {
      primitives.aead_open(key, nonce, aad, sealed)
    },
  )
}
