//// The foreign bindings behind `primitives`, confined here by the FFI rule
//// (`docs/gleam-style.md` Part IV §4).
////
//// No pure alternative exists for any of these: X25519, Ed25519, ML-KEM,
//// ChaCha20-Poly1305 and HMAC must come from a reviewed constant-time
//// implementation, and on the BEAM that is OTP's `crypto` application over
//// OpenSSL. Each binding goes through `primitives_ffi`, which catches every
//// exception so that no OpenSSL error, and with it no key material, reaches
//// a crash report.

/// `crypto:strong_rand_bytes/1`, the OS CSPRNG.
@external(erlang, "primitives_ffi", "random_bytes")
pub fn random_bytes(count: Int) -> BitArray

/// `crypto:hash(sha256, _)`.
@external(erlang, "primitives_ffi", "sha256")
pub fn sha256(data: BitArray) -> BitArray

/// `crypto:mac(hmac, sha256, _, _)`.
@external(erlang, "primitives_ffi", "hmac_sha256")
pub fn hmac_sha256(key: BitArray, data: BitArray) -> BitArray

/// `crypto:hash_equals/2`, false on a length mismatch.
@external(erlang, "primitives_ffi", "equal")
pub fn equal(left: BitArray, right: BitArray) -> Bool

/// `crypto:generate_key(ecdh, x25519)`, returned secret first.
@external(erlang, "primitives_ffi", "x25519_keypair")
pub fn x25519_keypair() -> #(BitArray, BitArray)

/// `crypto:generate_key(ecdh, x25519, Secret)`.
@external(erlang, "primitives_ffi", "x25519_public")
pub fn x25519_public(secret: BitArray) -> Result(BitArray, Nil)

/// `crypto:compute_key(ecdh, Public, Secret, x25519)`.
@external(erlang, "primitives_ffi", "x25519")
pub fn x25519(secret: BitArray, public: BitArray) -> Result(BitArray, Nil)

/// `crypto:generate_key(eddsa, ed25519)`, returned secret first.
@external(erlang, "primitives_ffi", "ed25519_keypair")
pub fn ed25519_keypair() -> #(BitArray, BitArray)

/// `crypto:generate_key(eddsa, ed25519, Secret)`.
@external(erlang, "primitives_ffi", "ed25519_public")
pub fn ed25519_public(secret: BitArray) -> Result(BitArray, Nil)

/// `crypto:sign(eddsa, none, Message, [Secret, ed25519])`.
@external(erlang, "primitives_ffi", "ed25519_sign")
pub fn ed25519_sign(
  secret: BitArray,
  message: BitArray,
) -> Result(BitArray, Nil)

/// `crypto:verify(eddsa, none, Message, Signature, [Public, ed25519])`.
@external(erlang, "primitives_ffi", "ed25519_verify")
pub fn ed25519_verify(
  public: BitArray,
  message: BitArray,
  signature: BitArray,
) -> Bool

/// `crypto:generate_key(mlkem1024, [])`, returned secret first.
@external(erlang, "primitives_ffi", "mlkem1024_keypair")
pub fn mlkem1024_keypair() -> #(BitArray, BitArray)

/// `crypto:encapsulate_key(mlkem1024, Public)`: `#(secret, ciphertext)`.
@external(erlang, "primitives_ffi", "mlkem1024_encapsulate")
pub fn mlkem1024_encapsulate(
  public: BitArray,
) -> Result(#(BitArray, BitArray), Nil)

/// `crypto:decapsulate_key(mlkem1024, Secret, Ciphertext)`.
@external(erlang, "primitives_ffi", "mlkem1024_decapsulate")
pub fn mlkem1024_decapsulate(
  secret: BitArray,
  ciphertext: BitArray,
) -> Result(BitArray, Nil)

/// `crypto:crypto_one_time_aead(chacha20_poly1305, ..., true)`, tag appended.
@external(erlang, "primitives_ffi", "aead_seal")
pub fn aead_seal(
  key: BitArray,
  nonce: BitArray,
  aad: BitArray,
  plaintext: BitArray,
) -> Result(BitArray, Nil)

/// `crypto:crypto_one_time_aead(chacha20_poly1305, ..., false)`.
@external(erlang, "primitives_ffi", "aead_open")
pub fn aead_open(
  key: BitArray,
  nonce: BitArray,
  aad: BitArray,
  sealed: BitArray,
) -> Result(BitArray, Nil)

/// `crypto:info_lib/0`'s first entry, the linked OpenSSL version string.
@external(erlang, "primitives_ffi", "openssl_version")
pub fn openssl_version() -> String
