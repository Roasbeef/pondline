//// Typed keys: the layer that stops an X25519 key being passed as an Ed25519
//// key and a secret key being printed.
////
//// `suite` is byte-level on purpose, so that a test can substitute a
//// deterministic one. This module wraps its bytes in distinct opaque types,
//// each constructed only through a function that checks the size, so a value
//// of type `X25519Public` is always 32 bytes and never an ML-KEM key. Every
//// secret key is held as a `core/secret.Secret`, which keeps it out of logs
//// and crash reports; the bytes come out only through the `expose_*`
//// functions, and each call site of those is a place a reviewer should read.
////
//// The operations here (agreement, signing, encapsulation) are thin: they
//// call the suite and translate its `Error(Nil)` into the shared `Error`,
//// which carries no key material.
////
//// ## Hybrid signatures
////
//// Every authentication step in `CryptoProfileV1` is hybrid
//// (`docs/adr/005-hybrid-authentication.md`): an Ed25519 signature and an
//// ML-DSA-65 signature over the same message, by the two signing keys of
//// one identity. `HybridSignature` holds the pair, and `hybrid_verify`
//// accepts it only when both halves verify, so forging one needs both
//// Ed25519 and ML-DSA-65 broken. There is deliberately no function that
//// verifies one half alone: a caller cannot fall back to the classical
//// signature by choosing the wrong verifier.

import core/crypto/error.{
  type Error, KeyAgreementFailed, Malformed, PrimitiveFailed,
}
import core/crypto/suite.{type Suite}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/result

/// The size of an X25519 key and of its shared secret.
pub const x25519_bytes = 32

/// The size of an Ed25519 key.
pub const ed25519_key_bytes = 32

/// The size of an Ed25519 signature.
pub const ed25519_signature_bytes = 64

/// The size of an ML-KEM-1024 encapsulation key.
pub const kem_public_size = 1568

/// The size of an ML-KEM-1024 decapsulation key.
pub const kem_secret_size = 3168

/// The size of an ML-KEM-1024 ciphertext.
pub const kem_ciphertext_size = 1568

/// The size of the shared secret ML-KEM produces.
pub const kem_shared_secret_bytes = 32

/// The size of an ML-DSA-65 public key.
pub const mldsa_public_size = 1952

/// The size of an ML-DSA-65 secret key, in OpenSSL's expanded form.
pub const mldsa_secret_size = 4032

/// The size of an ML-DSA-65 signature.
pub const mldsa_signature_size = 3309

/// The size of a hybrid signature: the Ed25519 signature (64) followed by
/// the ML-DSA-65 signature (3309).
pub const hybrid_signature_size = 3373

/// An X25519 public key: exactly 32 bytes.
pub opaque type X25519Public {
  X25519Public(bytes: BitArray)
}

/// An X25519 secret key: exactly 32 bytes, held as a `Secret`.
pub opaque type X25519Secret {
  X25519Secret(secret: Secret)
}

/// An Ed25519 public key: exactly 32 bytes.
pub opaque type Ed25519Public {
  Ed25519Public(bytes: BitArray)
}

/// An Ed25519 secret key: exactly 32 bytes, held as a `Secret`.
pub opaque type Ed25519Secret {
  Ed25519Secret(secret: Secret)
}

/// An Ed25519 signature: exactly 64 bytes.
pub opaque type Signature {
  Signature(bytes: BitArray)
}

/// An ML-KEM-1024 encapsulation key: exactly 1568 bytes.
pub opaque type KemPublic {
  KemPublic(bytes: BitArray)
}

/// An ML-KEM-1024 decapsulation key: exactly 3168 bytes, held as a `Secret`.
pub opaque type KemSecret {
  KemSecret(secret: Secret)
}

/// An ML-KEM-1024 ciphertext: exactly 1568 bytes.
pub opaque type KemCiphertext {
  KemCiphertext(bytes: BitArray)
}

/// An ML-DSA-65 public key: exactly 1952 bytes.
pub opaque type MldsaPublic {
  MldsaPublic(bytes: BitArray)
}

/// An ML-DSA-65 secret key: exactly 4032 bytes, held as a `Secret`.
pub opaque type MldsaSecret {
  MldsaSecret(secret: Secret)
}

/// A hybrid signature: an Ed25519 signature and an ML-DSA-65 signature over
/// one message. Built only by `hybrid_sign` or by `hybrid_signature`, which
/// checks both sizes; neither half is reachable alone, so no caller can
/// verify one and skip the other.
pub opaque type HybridSignature {
  HybridSignature(classical: Signature, post_quantum: BitArray)
}

fn sized(bytes: BitArray, size: Int, what: String) -> Result(BitArray, Error) {
  case bit_array.byte_size(bytes) == size {
    True -> Ok(bytes)
    False -> Error(Malformed(what))
  }
}

/// An X25519 public key from 32 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.x25519_public(<<1, 2>>)
/// // -> Error(Malformed("x25519 public key"))
/// ```
pub fn x25519_public(bytes: BitArray) -> Result(X25519Public, Error) {
  sized(bytes, x25519_bytes, "x25519 public key")
  |> result.map(X25519Public)
}

/// The bytes of an X25519 public key.
///
/// ## Examples
///
/// ```gleam
/// keys.x25519_public_bytes(public)
/// // -> <<_:256>>
/// ```
pub fn x25519_public_bytes(key: X25519Public) -> BitArray {
  key.bytes
}

/// An X25519 secret key from 32 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.x25519_secret(<<1, 2>>)
/// // -> Error(Malformed("x25519 secret key"))
/// ```
pub fn x25519_secret(bytes: BitArray) -> Result(X25519Secret, Error) {
  sized(bytes, x25519_bytes, "x25519 secret key")
  |> result.map(fn(valid) { X25519Secret(secret.new(valid)) })
}

/// The bytes of an X25519 secret key. The caller is handling key material
/// and should say why.
///
/// ## Examples
///
/// ```gleam
/// keys.expose_x25519_secret(key)
/// // -> <<_:256>>
/// ```
pub fn expose_x25519_secret(key: X25519Secret) -> BitArray {
  secret.expose(key.secret)
}

/// An Ed25519 public key from 32 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.ed25519_public(<<1, 2>>)
/// // -> Error(Malformed("ed25519 public key"))
/// ```
pub fn ed25519_public(bytes: BitArray) -> Result(Ed25519Public, Error) {
  sized(bytes, ed25519_key_bytes, "ed25519 public key")
  |> result.map(Ed25519Public)
}

/// The bytes of an Ed25519 public key.
///
/// ## Examples
///
/// ```gleam
/// keys.ed25519_public_bytes(public)
/// // -> <<_:256>>
/// ```
pub fn ed25519_public_bytes(key: Ed25519Public) -> BitArray {
  key.bytes
}

/// An Ed25519 secret key from 32 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.ed25519_secret(<<1, 2>>)
/// // -> Error(Malformed("ed25519 secret key"))
/// ```
pub fn ed25519_secret(bytes: BitArray) -> Result(Ed25519Secret, Error) {
  sized(bytes, ed25519_key_bytes, "ed25519 secret key")
  |> result.map(fn(valid) { Ed25519Secret(secret.new(valid)) })
}

/// The bytes of an Ed25519 secret key. The caller is handling key material
/// and should say why.
///
/// ## Examples
///
/// ```gleam
/// keys.expose_ed25519_secret(key)
/// // -> <<_:256>>
/// ```
pub fn expose_ed25519_secret(key: Ed25519Secret) -> BitArray {
  secret.expose(key.secret)
}

/// A signature from 64 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.signature(<<1, 2>>)
/// // -> Error(Malformed("signature"))
/// ```
pub fn signature(bytes: BitArray) -> Result(Signature, Error) {
  sized(bytes, ed25519_signature_bytes, "signature")
  |> result.map(Signature)
}

/// The bytes of a signature.
///
/// ## Examples
///
/// ```gleam
/// keys.signature_bytes(signature)
/// // -> <<_:512>>
/// ```
pub fn signature_bytes(signature: Signature) -> BitArray {
  signature.bytes
}

/// An ML-KEM-1024 encapsulation key from 1568 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.kem_public(<<1, 2>>)
/// // -> Error(Malformed("ml-kem public key"))
/// ```
pub fn kem_public(bytes: BitArray) -> Result(KemPublic, Error) {
  sized(bytes, kem_public_size, "ml-kem public key")
  |> result.map(KemPublic)
}

/// The bytes of an ML-KEM-1024 encapsulation key.
///
/// ## Examples
///
/// ```gleam
/// keys.kem_public_bytes(public)
/// // -> <<_:12544>>
/// ```
pub fn kem_public_bytes(key: KemPublic) -> BitArray {
  key.bytes
}

/// An ML-KEM-1024 decapsulation key from 3168 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.kem_secret(<<1, 2>>)
/// // -> Error(Malformed("ml-kem secret key"))
/// ```
pub fn kem_secret(bytes: BitArray) -> Result(KemSecret, Error) {
  sized(bytes, kem_secret_size, "ml-kem secret key")
  |> result.map(fn(valid) { KemSecret(secret.new(valid)) })
}

/// The bytes of an ML-KEM-1024 decapsulation key. The caller is handling
/// key material and should say why.
///
/// ## Examples
///
/// ```gleam
/// keys.expose_kem_secret(key)
/// // -> <<_:25344>>
/// ```
pub fn expose_kem_secret(key: KemSecret) -> BitArray {
  secret.expose(key.secret)
}

/// An ML-KEM-1024 ciphertext from 1568 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.kem_ciphertext(<<1, 2>>)
/// // -> Error(Malformed("ml-kem ciphertext"))
/// ```
pub fn kem_ciphertext(bytes: BitArray) -> Result(KemCiphertext, Error) {
  sized(bytes, kem_ciphertext_size, "ml-kem ciphertext")
  |> result.map(KemCiphertext)
}

/// The bytes of an ML-KEM-1024 ciphertext.
///
/// ## Examples
///
/// ```gleam
/// keys.kem_ciphertext_bytes(ciphertext)
/// // -> <<_:12544>>
/// ```
pub fn kem_ciphertext_bytes(ciphertext: KemCiphertext) -> BitArray {
  ciphertext.bytes
}

/// An ML-DSA-65 public key from 1952 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.mldsa_public(<<1, 2>>)
/// // -> Error(Malformed("ml-dsa public key"))
/// ```
pub fn mldsa_public(bytes: BitArray) -> Result(MldsaPublic, Error) {
  sized(bytes, mldsa_public_size, "ml-dsa public key")
  |> result.map(MldsaPublic)
}

/// The bytes of an ML-DSA-65 public key.
///
/// ## Examples
///
/// ```gleam
/// keys.mldsa_public_bytes(public)
/// // -> <<_:15_616>>
/// ```
pub fn mldsa_public_bytes(key: MldsaPublic) -> BitArray {
  key.bytes
}

/// An ML-DSA-65 secret key from 4032 bytes.
///
/// ## Examples
///
/// ```gleam
/// keys.mldsa_secret(<<1, 2>>)
/// // -> Error(Malformed("ml-dsa secret key"))
/// ```
pub fn mldsa_secret(bytes: BitArray) -> Result(MldsaSecret, Error) {
  sized(bytes, mldsa_secret_size, "ml-dsa secret key")
  |> result.map(fn(valid) { MldsaSecret(secret.new(valid)) })
}

/// The bytes of an ML-DSA-65 secret key. The caller is handling key
/// material and should say why.
///
/// ## Examples
///
/// ```gleam
/// keys.expose_mldsa_secret(key)
/// // -> <<_:32_256>>
/// ```
pub fn expose_mldsa_secret(key: MldsaSecret) -> BitArray {
  secret.expose(key.secret)
}

/// A hybrid signature from its 3373-byte encoding: the Ed25519 signature,
/// then the ML-DSA-65 signature.
///
/// ## Examples
///
/// ```gleam
/// keys.hybrid_signature(<<1, 2>>)
/// // -> Error(Malformed("hybrid signature"))
/// ```
pub fn hybrid_signature(bytes: BitArray) -> Result(HybridSignature, Error) {
  case bytes {
    <<
      classical:bytes-size(ed25519_signature_bytes),
      post_quantum:bytes-size(mldsa_signature_size),
    >> -> Ok(HybridSignature(Signature(classical), post_quantum))

    _ -> Error(Malformed("hybrid signature"))
  }
}

/// The encoding of a hybrid signature: the Ed25519 signature (64 bytes)
/// followed by the ML-DSA-65 signature (3309 bytes).
///
/// ## Examples
///
/// ```gleam
/// keys.hybrid_signature_bytes(signature)
/// // -> <<_:26_984>>
/// ```
pub fn hybrid_signature_bytes(signature: HybridSignature) -> BitArray {
  <<signature.classical.bytes:bits, signature.post_quantum:bits>>
}

/// A fresh X25519 key pair from the suite, as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(secret, public)) = keys.generate_x25519(suite)
/// ```
pub fn generate_x25519(
  suite: Suite,
) -> Result(#(X25519Secret, X25519Public), Error) {
  let #(secret_bytes, public_bytes) = suite.x25519_keypair()
  use secret <- result.try(x25519_secret(secret_bytes))
  use public <- result.try(x25519_public(public_bytes))
  Ok(#(secret, public))
}

/// A fresh Ed25519 key pair from the suite, as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(secret, public)) = keys.generate_ed25519(suite)
/// ```
pub fn generate_ed25519(
  suite: Suite,
) -> Result(#(Ed25519Secret, Ed25519Public), Error) {
  let #(secret_bytes, public_bytes) = suite.ed25519_keypair()
  use secret <- result.try(ed25519_secret(secret_bytes))
  use public <- result.try(ed25519_public(public_bytes))
  Ok(#(secret, public))
}

/// A fresh ML-KEM-1024 key pair from the suite, as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(secret, public)) = keys.generate_kem(suite)
/// ```
pub fn generate_kem(suite: Suite) -> Result(#(KemSecret, KemPublic), Error) {
  let #(secret_bytes, public_bytes) = suite.kem_keypair()
  use secret <- result.try(kem_secret(secret_bytes))
  use public <- result.try(kem_public(public_bytes))
  Ok(#(secret, public))
}

/// A fresh ML-DSA-65 key pair from the suite, as `#(secret, public)`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(secret, public)) = keys.generate_mldsa(suite)
/// ```
pub fn generate_mldsa(
  suite: Suite,
) -> Result(#(MldsaSecret, MldsaPublic), Error) {
  let #(secret_bytes, public_bytes) = suite.mldsa_keypair()
  use secret <- result.try(mldsa_secret(secret_bytes))
  use public <- result.try(mldsa_public(public_bytes))

  Ok(#(secret, public))
}

/// The X25519 shared secret of `secret` and `public`. A low-order public key
/// is `KeyAgreementFailed`.
///
/// ## Examples
///
/// ```gleam
/// keys.dh(suite, alice_secret, bob_public)
/// // == keys.dh(suite, bob_secret, alice_public)
/// ```
pub fn dh(
  suite: Suite,
  secret: X25519Secret,
  public: X25519Public,
) -> Result(BitArray, Error) {
  // The secret key is the input of the agreement and goes no further.
  suite.x25519(expose_x25519_secret(secret), public.bytes)
  |> result.replace_error(KeyAgreementFailed)
}

/// An Ed25519 signature over `message`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(sig) = keys.sign(suite, secret, <<"m">>)
/// ```
pub fn sign(
  suite: Suite,
  secret: Ed25519Secret,
  message: BitArray,
) -> Result(Signature, Error) {
  // The secret key is the input of the signature and goes no further.
  use bytes <- result.try(
    suite.ed25519_sign(expose_ed25519_secret(secret), message)
    |> result.replace_error(PrimitiveFailed),
  )

  signature(bytes)
}

/// Whether `signature` is a valid signature over `message` by `public`.
///
/// ## Examples
///
/// ```gleam
/// keys.verify(suite, public, <<"m">>, sig)
/// // -> True
/// ```
pub fn verify(
  suite: Suite,
  public: Ed25519Public,
  message: BitArray,
  signature: Signature,
) -> Bool {
  suite.ed25519_verify(public.bytes, message, signature.bytes)
}

/// A hybrid signature over `message`: Ed25519 under `classical` and
/// ML-DSA-65 under `post_quantum`, both over the same bytes. The message
/// is expected to begin with a domain-separation label, which is what
/// keeps a signature made for one purpose from verifying for another.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(signature) =
///   keys.hybrid_sign(suite, ed25519_secret, mldsa_secret, <<"m">>)
/// ```
pub fn hybrid_sign(
  suite: Suite,
  classical: Ed25519Secret,
  post_quantum: MldsaSecret,
  message: BitArray,
) -> Result(HybridSignature, Error) {
  use classical_signature <- result.try(sign(suite, classical, message))

  // The secret key is the input of the signature and goes no further.
  use post_quantum_signature <- result.try(
    suite.mldsa_sign(expose_mldsa_secret(post_quantum), message)
    |> result.replace_error(PrimitiveFailed),
  )
  use post_quantum_signature <- result.try(sized(
    post_quantum_signature,
    mldsa_signature_size,
    "ml-dsa signature",
  ))

  Ok(HybridSignature(classical_signature, post_quantum_signature))
}

/// Whether `signature` is a valid hybrid signature over `message` by the
/// two public keys: true only when the Ed25519 half verifies under
/// `classical` and the ML-DSA-65 half under `post_quantum`. A signature
/// whose classical half alone is valid is refused, which is the whole
/// point of the pair.
///
/// ## Examples
///
/// ```gleam
/// keys.hybrid_verify(suite, ed25519_public, mldsa_public, <<"m">>, sig)
/// // -> True
/// ```
pub fn hybrid_verify(
  suite: Suite,
  classical: Ed25519Public,
  post_quantum: MldsaPublic,
  message: BitArray,
  signature: HybridSignature,
) -> Bool {
  verify(suite, classical, message, signature.classical)
  && suite.mldsa_verify(post_quantum.bytes, message, signature.post_quantum)
}

/// Encapsulates a fresh shared secret to `public`, returning
/// `#(shared_secret, ciphertext)`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(shared, ciphertext)) = keys.kem_encapsulate(suite, public)
/// ```
pub fn kem_encapsulate(
  suite: Suite,
  public: KemPublic,
) -> Result(#(BitArray, KemCiphertext), Error) {
  use #(shared, ciphertext_bytes) <- result.try(
    suite.kem_encapsulate(public.bytes)
    |> result.replace_error(PrimitiveFailed),
  )
  use shared <- result.try(sized(
    shared,
    kem_shared_secret_bytes,
    "ml-kem shared secret",
  ))
  use ciphertext <- result.try(kem_ciphertext(ciphertext_bytes))

  Ok(#(shared, ciphertext))
}

/// Recovers the shared secret from a ciphertext. ML-KEM rejects implicitly,
/// so a forged ciphertext yields an unrelated secret rather than an error;
/// whatever the secret keys must therefore fail to authenticate.
///
/// ## Examples
///
/// ```gleam
/// keys.kem_decapsulate(suite, secret, ciphertext)
/// // -> Ok(shared)
/// ```
pub fn kem_decapsulate(
  suite: Suite,
  secret: KemSecret,
  ciphertext: KemCiphertext,
) -> Result(BitArray, Error) {
  // The secret key is the input of the decapsulation and goes no further.
  use shared <- result.try(
    suite.kem_decapsulate(expose_kem_secret(secret), ciphertext.bytes)
    |> result.replace_error(PrimitiveFailed),
  )

  sized(shared, kem_shared_secret_bytes, "ml-kem shared secret")
}
