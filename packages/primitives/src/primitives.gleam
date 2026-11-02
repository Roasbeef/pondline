//// The cryptographic primitives Pondline builds its protocols from, taken
//// from OTP's `crypto` application rather than written here or pulled in
//// through a native library (`docs/adr/002-pq-crypto-over-otp.md`).
////
//// This module is deliberately byte-level: keys, nonces and outputs are
//// `BitArray`s with the sizes each function documents. The typed layer
//// (keys that cannot be confused, secrets that cannot be printed) lives in
//// `core/crypto`, which receives these functions as a record so that the
//// protocol logic stays pure and a test can substitute a deterministic
//// suite. Nothing outside `core/crypto`'s suite adapter should call this
//// module directly.
////
//// Every fallible function returns `Error(Nil)` rather than raising: OTP's
//// errors carry their arguments, and those arguments are keys.

import primitives/internal/ffi_crypto

/// The size of an X25519 public or secret key, and of its shared secret.
pub const x25519_bytes = 32

/// The size of an Ed25519 public or secret key.
pub const ed25519_key_bytes = 32

/// The size of an Ed25519 signature.
pub const ed25519_signature_bytes = 64

/// The size of an ML-KEM-1024 encapsulation (public) key.
pub const mlkem1024_public_bytes = 1568

/// The size of an ML-KEM-1024 decapsulation (secret) key, in OpenSSL's
/// expanded form.
pub const mlkem1024_secret_bytes = 3168

/// The size of an ML-KEM-1024 ciphertext.
pub const mlkem1024_ciphertext_bytes = 1568

/// The size of the shared secret ML-KEM produces.
pub const mlkem_shared_secret_bytes = 32

/// The size of an ML-DSA-65 public key (FIPS 204).
pub const mldsa65_public_bytes = 1952

/// The size of an ML-DSA-65 secret key, in OpenSSL's expanded form.
pub const mldsa65_secret_bytes = 4032

/// The size of an ML-DSA-65 signature.
pub const mldsa65_signature_bytes = 3309

/// The ChaCha20-Poly1305 key size.
pub const aead_key_bytes = 32

/// The ChaCha20-Poly1305 nonce size.
pub const aead_nonce_bytes = 12

/// The Poly1305 tag size, appended to every sealed message.
pub const aead_tag_bytes = 16

/// Bytes from the operating system's CSPRNG.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(random_bytes(32))
/// // -> 32
/// ```
pub fn random_bytes(count: Int) -> BitArray {
  ffi_crypto.random_bytes(count)
}

/// SHA-256.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(sha256(<<"abc">>))
/// // -> 32
/// ```
pub fn sha256(data: BitArray) -> BitArray {
  ffi_crypto.sha256(data)
}

/// HMAC-SHA-256 (RFC 2104 over FIPS 180-4).
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(hmac_sha256(<<"key">>, <<"data">>))
/// // -> 32
/// ```
pub fn hmac_sha256(key: BitArray, data: BitArray) -> BitArray {
  ffi_crypto.hmac_sha256(key, data)
}

/// Compares two byte strings in time independent of where they differ.
/// Strings of different lengths compare unequal at once, since length is
/// never the secret.
///
/// ## Examples
///
/// ```gleam
/// constant_time_equal(<<1, 2>>, <<1, 2>>)
/// // -> True
/// ```
pub fn constant_time_equal(left: BitArray, right: BitArray) -> Bool {
  ffi_crypto.equal(left, right)
}

/// A fresh X25519 key pair, as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let #(secret, public) = x25519_keypair()
/// x25519_public(secret)
/// // -> Ok(public)
/// ```
pub fn x25519_keypair() -> #(BitArray, BitArray) {
  ffi_crypto.x25519_keypair()
}

/// The public key of an X25519 secret key; an error for a secret of the
/// wrong size.
///
/// ## Examples
///
/// ```gleam
/// x25519_public(<<1, 2, 3>>)
/// // -> Error(Nil)
/// ```
pub fn x25519_public(secret: BitArray) -> Result(BitArray, Nil) {
  ffi_crypto.x25519_public(secret)
}

/// The X25519 shared secret (RFC 7748). An error for a wrong-sized input
/// or a low-order public key whose output would be all zeros.
///
/// ## Examples
///
/// ```gleam
/// x25519(secret, <<0:256>>)
/// // -> Error(Nil)
/// ```
pub fn x25519(secret: BitArray, public: BitArray) -> Result(BitArray, Nil) {
  ffi_crypto.x25519(secret, public)
}

/// A fresh Ed25519 key pair, as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let #(secret, public) = ed25519_keypair()
/// ed25519_public(secret)
/// // -> Ok(public)
/// ```
pub fn ed25519_keypair() -> #(BitArray, BitArray) {
  ffi_crypto.ed25519_keypair()
}

/// The public key of an Ed25519 secret key (RFC 8032 §5.1.5).
///
/// ## Examples
///
/// ```gleam
/// ed25519_public(<<>>)
/// // -> Error(Nil)
/// ```
pub fn ed25519_public(secret: BitArray) -> Result(BitArray, Nil) {
  ffi_crypto.ed25519_public(secret)
}

/// An Ed25519 signature over `message` (RFC 8032, pure Ed25519).
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(signature) = ed25519_sign(secret, <<"m">>)
/// ed25519_verify(public, <<"m">>, signature)
/// // -> True
/// ```
pub fn ed25519_sign(
  secret: BitArray,
  message: BitArray,
) -> Result(BitArray, Nil) {
  ffi_crypto.ed25519_sign(secret, message)
}

/// Whether `signature` is a valid Ed25519 signature over `message` by
/// `public`. Malformed inputs verify as false.
///
/// ## Examples
///
/// ```gleam
/// ed25519_verify(public, <<"m">>, <<0:512>>)
/// // -> False
/// ```
pub fn ed25519_verify(
  public: BitArray,
  message: BitArray,
  signature: BitArray,
) -> Bool {
  ffi_crypto.ed25519_verify(public, message, signature)
}

/// A fresh ML-KEM-1024 key pair (FIPS 203), as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let #(_secret, public) = mlkem1024_keypair()
/// bit_array.byte_size(public)
/// // -> 1568
/// ```
pub fn mlkem1024_keypair() -> #(BitArray, BitArray) {
  ffi_crypto.mlkem1024_keypair()
}

/// Encapsulates a fresh shared secret to `public`, returning
/// `#(shared_secret, ciphertext)`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(shared, ciphertext)) = mlkem1024_encapsulate(public)
/// mlkem1024_decapsulate(secret, ciphertext)
/// // -> Ok(shared)
/// ```
pub fn mlkem1024_encapsulate(
  public: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  ffi_crypto.mlkem1024_encapsulate(public)
}

/// Recovers the shared secret from a ciphertext. ML-KEM uses implicit
/// rejection: a forged ciphertext of the right size yields an unrelated
/// secret, not an error, so authentication must come from what the secret
/// later keys.
///
/// ## Examples
///
/// ```gleam
/// mlkem1024_decapsulate(secret, <<1, 2, 3>>)
/// // -> Error(Nil)
/// ```
pub fn mlkem1024_decapsulate(
  secret: BitArray,
  ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  ffi_crypto.mlkem1024_decapsulate(secret, ciphertext)
}

/// A fresh ML-DSA-65 key pair (FIPS 204), as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let #(_secret, public) = mldsa65_keypair()
/// bit_array.byte_size(public)
/// // -> 1952
/// ```
pub fn mldsa65_keypair() -> #(BitArray, BitArray) {
  ffi_crypto.mldsa65_keypair()
}

/// An ML-DSA-65 signature over `message`, with an empty context string.
/// OpenSSL signs in FIPS 204's hedged mode, so two signatures of the same
/// message differ; both verify. An error for a secret of the wrong size.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(signature) = mldsa65_sign(secret, <<"m">>)
/// mldsa65_verify(public, <<"m">>, signature)
/// // -> True
/// ```
pub fn mldsa65_sign(
  secret: BitArray,
  message: BitArray,
) -> Result(BitArray, Nil) {
  ffi_crypto.mldsa65_sign(secret, message)
}

/// Whether `signature` is a valid ML-DSA-65 signature over `message` by
/// `public`, with an empty context string. Malformed inputs verify as false.
///
/// ## Examples
///
/// ```gleam
/// mldsa65_verify(public, <<"m">>, <<0:26_472>>)
/// // -> False
/// ```
pub fn mldsa65_verify(
  public: BitArray,
  message: BitArray,
  signature: BitArray,
) -> Bool {
  ffi_crypto.mldsa65_verify(public, message, signature)
}

/// ChaCha20-Poly1305 encryption (RFC 8439): the ciphertext with its
/// 16-byte tag appended.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(sealed) = aead_seal(key, nonce, <<>>, <<"hi">>)
/// bit_array.byte_size(sealed)
/// // -> 18
/// ```
pub fn aead_seal(
  key key: BitArray,
  nonce nonce: BitArray,
  aad aad: BitArray,
  plaintext plaintext: BitArray,
) -> Result(BitArray, Nil) {
  ffi_crypto.aead_seal(key, nonce, aad, plaintext)
}

/// ChaCha20-Poly1305 decryption and authentication; an error for any
/// forgery, truncation or wrong key.
///
/// ## Examples
///
/// ```gleam
/// aead_open(key, nonce, <<>>, <<0:128>>)
/// // -> Error(Nil)
/// ```
pub fn aead_open(
  key key: BitArray,
  nonce nonce: BitArray,
  aad aad: BitArray,
  sealed sealed: BitArray,
) -> Result(BitArray, Nil) {
  ffi_crypto.aead_open(key, nonce, aad, sealed)
}

/// The OpenSSL version OTP's `crypto` is linked against. ML-KEM needs 3.5
/// or newer, so a release checks this at startup.
///
/// ## Examples
///
/// ```gleam
/// openssl_version()
/// // -> "OpenSSL 3.6.3 9 Jun 2026"
/// ```
pub fn openssl_version() -> String {
  ffi_crypto.openssl_version()
}
