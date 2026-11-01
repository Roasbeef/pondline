//// The cryptographic primitives the protocols in `core/crypto` need,
//// received as a record of functions.
////
//// `core` cannot call OpenSSL: it is pure (`docs/gleam-style.md` Part IV
//// §5), so that a property test can run a handshake or a ratchet without a
//// process or a foreign call. The shell builds a `Suite` from the
//// `primitives` package and hands it in; a test can build a deterministic
//// one. Randomness arrives the same way, through `random` and the key
//// generators, which is the injection Part IV §6 asks for.
////
//// The fields are byte-level and mirror `primitives` exactly, with its
//// sizes. The typed keys built on top of them live beside the protocols
//// that use them.

/// The primitive operations, as `primitives` defines them. Key pairs are
/// returned secret first. The `mldsa_*` fields are ML-DSA-65, the
/// post-quantum half of every hybrid signature.
pub type Suite {
  Suite(
    random: fn(Int) -> BitArray,
    sha256: fn(BitArray) -> BitArray,
    hmac_sha256: fn(BitArray, BitArray) -> BitArray,
    constant_time_equal: fn(BitArray, BitArray) -> Bool,
    x25519_keypair: fn() -> #(BitArray, BitArray),
    x25519: fn(BitArray, BitArray) -> Result(BitArray, Nil),
    ed25519_keypair: fn() -> #(BitArray, BitArray),
    ed25519_sign: fn(BitArray, BitArray) -> Result(BitArray, Nil),
    ed25519_verify: fn(BitArray, BitArray, BitArray) -> Bool,
    kem_keypair: fn() -> #(BitArray, BitArray),
    kem_encapsulate: fn(BitArray) -> Result(#(BitArray, BitArray), Nil),
    kem_decapsulate: fn(BitArray, BitArray) -> Result(BitArray, Nil),
    mldsa_keypair: fn() -> #(BitArray, BitArray),
    mldsa_sign: fn(BitArray, BitArray) -> Result(BitArray, Nil),
    mldsa_verify: fn(BitArray, BitArray, BitArray) -> Bool,
    aead_seal: fn(BitArray, BitArray, BitArray, BitArray) ->
      Result(BitArray, Nil),
    aead_open: fn(BitArray, BitArray, BitArray, BitArray) ->
      Result(BitArray, Nil),
  )
}
