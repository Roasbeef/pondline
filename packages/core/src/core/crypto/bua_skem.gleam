//// ML-BUA-sKEM-1024: ML-KEM-1024 whose public keys are any byte string of
//// the right length, look uniformly random, and split into a part that
//// depends on the secret key and a part that does not.
////
//// OQUAKE (`core/crypto/oquake`) needs a KEM with three properties that
//// ML-KEM lacks as FIPS 203 encodes it (`draft-vos-cfrg-pqpake-03` §4.2):
//// every byte string of length Npk must be a public key a peer can
//// encapsulate to (binary), public keys must be indistinguishable from
//// random bytes (uniform), and a key must split into `ut`, which depends on
//// the secret key, and `rho`, which does not and can be handled in the
//// clear. ML-BUA-sKEM gets all three without touching ML-KEM's internals
//// (§4.2.1): key generation re-encodes the FIPS 203 key with Kemeleon
//// (`core/crypto/kemeleon`), encapsulation decodes it again before calling
//// ML-KEM, and decapsulation is ML-KEM's own. Kemeleon leaves the 32-byte
//// seed rho at the end untouched, so `split` is a cut at byte Nt and
//// `combine` is concatenation.
////
//// The splitting is what defeats the timing attack of pqpake §11.6. ML-KEM
//// expands rho into its matrix by rejection sampling, which takes variable
//// time. OQUAKE masks only `ut` with the password and sends rho in the
//// clear, so the variable-time step never runs on a password-dependent
//// value.
////
//// ```text
//// KeyGen():        (ek, dk) = ML-KEM.KeyGen(); upk = Kemeleon.EncodeEk(ek)
//// Split(upk):      ut = upk[0 : 1564], rho = upk[1564 : 1596]
//// Combine(ut,rho): ut || rho
//// Encaps(upk):     ML-KEM.Encaps(Kemeleon.DecodeEk(upk))
//// Decaps(ct, dk):  ML-KEM.Decaps(ct, dk)
//// ```
////
//// The ML-KEM operations are the suite's (`kem_keypair`, `kem_encapsulate`,
//// `kem_decapsulate`), FIPS 203 encodings with the decapsulation key in
//// OpenSSL's expanded form. Because `Kemeleon.DecodeEk` is total, an
//// encapsulation to a key of the right length does not fail for a correct
//// suite; `PrimitiveFailed` is what a broken one would produce.
////
//// Neither the encoding randomness nor the decapsulation key may leak. The
//// decapsulation key is held as a `Secret`; the randomness is drawn,
//// consumed by `kemeleon.encode` and dropped. Kemeleon's arithmetic is not
//// constant time, which `core/crypto/kemeleon` explains.

import core/crypto/error.{type Error, Malformed, PrimitiveFailed}
import core/crypto/kemeleon
import core/crypto/suite.{type Suite}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/bool
import gleam/result

/// The size of a uniform public key, Npk in pqpake Table 1.
pub const public_key_bytes = 1596

/// The size of `ut`, the part of a public key that depends on the secret
/// key: Nt in pqpake Table 1.
pub const dependent_bytes = 1564

/// The size of `rho`, the part of a public key that does not depend on the
/// secret key: N-rho in pqpake Table 1.
pub const seed_bytes = 32

/// The size of a ciphertext, Nct in pqpake Table 1: ML-KEM-1024's own.
pub const ciphertext_bytes = 1568

/// The size of the shared secret an encapsulation produces.
pub const shared_secret_bytes = 32

/// A key pair: ML-KEM's decapsulation key, held as a secret, and the uniform
/// public key that Kemeleon made of its encapsulation key.
pub type KeyPair {
  KeyPair(
    /// The FIPS 203 decapsulation key, in the suite's form.
    decapsulation_key: Secret,
    /// The `public_key_bytes` uniform public key, `upk` in the draft.
    public_key: BitArray,
  )
}

/// A uniform public key cut in two.
pub type SplitKey {
  SplitKey(
    /// `ut`: the `dependent_bytes` that depend on the secret key, and which
    /// OQUAKE masks with the password.
    ut: BitArray,
    /// `rho`: the `seed_bytes` matrix seed, independent of the secret key
    /// and sent in the clear.
    rho: BitArray,
  )
}

/// What encapsulation produces.
pub type Encapsulation {
  Encapsulation(
    /// The shared secret, `k` in the draft.
    shared_secret: Secret,
    /// The ciphertext, `ct` in the draft, for the key's holder.
    ciphertext: BitArray,
  )
}

/// `ML-BUA-sKEM.KeyGen`: a fresh ML-KEM-1024 key pair from the suite, its
/// encapsulation key Kemeleon-encoded under fresh secret randomness from
/// the suite.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(pair) = bua_skem.keygen(suite)
/// bit_array.byte_size(pair.public_key)
/// // -> 1596
/// ```
pub fn keygen(suite: Suite) -> Result(KeyPair, Error) {
  let #(decapsulation_key, encapsulation_key) = suite.kem_keypair()

  // The encoding randomness is drawn here and never stored: once the key is
  // encoded it has no further use, and the drafts require it stay secret.
  use randomness <- result.try(
    kemeleon.randomness(secret.new(suite.random(kemeleon.randomness_bytes))),
  )

  key_pair_from(secret.new(decapsulation_key), encapsulation_key, randomness)
}

/// The key pair for an ML-KEM key pair already in hand, encoded under the
/// given randomness. `keygen` is this with everything drawn from the suite;
/// a test calls it directly to pin the draft's `kemeleon_m` values. An
/// encapsulation key that fails FIPS 203's modulus check is refused.
///
/// ## Examples
///
/// ```gleam
/// bua_skem.key_pair_from(decapsulation_key, encapsulation_key, randomness)
/// // -> Ok(KeyPair(decapsulation_key:, public_key: upk))
/// ```
pub fn key_pair_from(
  decapsulation_key: Secret,
  encapsulation_key: BitArray,
  randomness: kemeleon.Randomness,
) -> Result(KeyPair, Error) {
  use public_key <- result.map(kemeleon.encode(encapsulation_key, randomness))

  KeyPair(decapsulation_key:, public_key:)
}

/// `ML-BUA-sKEM.Split`: `ut` and `rho` of a uniform public key. Only a
/// wrong length is refused; every string of `public_key_bytes` splits.
///
/// ## Examples
///
/// ```gleam
/// bua_skem.split(<<0:size(12_768)>>)
/// // -> Ok(SplitKey(ut: <<0:size(12_512)>>, rho: <<0:size(256)>>))
/// ```
pub fn split(public_key: BitArray) -> Result(SplitKey, Error) {
  case public_key {
    <<ut:bytes-size(dependent_bytes), rho:bytes-size(seed_bytes)>> ->
      Ok(SplitKey(ut:, rho:))

    _ -> Error(Malformed("bua-skem public key"))
  }
}

/// `ML-BUA-sKEM.Combine`, the inverse of `split`: `ut || rho`. Parts of the
/// wrong length are refused, so the result is always a whole key.
///
/// ## Examples
///
/// ```gleam
/// bua_skem.combine(<<0:size(12_512)>>, <<0:size(256)>>)
/// // -> Ok(<<0:size(12_768)>>)
/// ```
pub fn combine(ut: BitArray, rho: BitArray) -> Result(BitArray, Error) {
  use <- bool.guard(
    when: bit_array.byte_size(ut) != dependent_bytes
      || bit_array.byte_size(rho) != seed_bytes,
    return: Error(Malformed("bua-skem public key part")),
  )

  Ok(<<ut:bits, rho:bits>>)
}

/// `ML-BUA-sKEM.Encaps`: a fresh shared secret and its ciphertext for the
/// holder of `public_key`. Any `public_key_bytes` string is accepted, since
/// Kemeleon decodes every one of them to a valid ML-KEM key; that is the
/// binary property OQUAKE needs when it encapsulates to a key unmasked
/// under a guessed password.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(Encapsulation(shared_secret:, ciphertext:)) =
///   bua_skem.encapsulate(suite, pair.public_key)
/// bua_skem.decapsulate(suite, pair.decapsulation_key, ciphertext)
/// // -> Ok(shared_secret)
/// ```
pub fn encapsulate(
  suite: Suite,
  public_key: BitArray,
) -> Result(Encapsulation, Error) {
  use encapsulation_key <- result.try(kemeleon.decode(public_key))
  use #(shared_secret, ciphertext) <- result.map(
    suite.kem_encapsulate(encapsulation_key)
    |> result.replace_error(PrimitiveFailed),
  )

  Encapsulation(shared_secret: secret.new(shared_secret), ciphertext:)
}

/// `ML-BUA-sKEM.Decaps`, which is ML-KEM's: the shared secret a ciphertext
/// carries. ML-KEM rejects implicitly, so a forged ciphertext of the right
/// length yields an unrelated secret, not an error; an error means a
/// malformed key or ciphertext.
///
/// ## Examples
///
/// ```gleam
/// bua_skem.decapsulate(suite, pair.decapsulation_key, <<1, 2, 3>>)
/// // -> Error(PrimitiveFailed)
/// ```
pub fn decapsulate(
  suite: Suite,
  decapsulation_key: Secret,
  ciphertext: BitArray,
) -> Result(Secret, Error) {
  // The decapsulation key leaves its closure only to enter the suite.
  suite.kem_decapsulate(secret.expose(decapsulation_key), ciphertext)
  |> result.map(secret.new)
  |> result.replace_error(PrimitiveFailed)
}
