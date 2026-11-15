//// The test-only ML-KEM-1024 reference (`primitives/mlkem_reference`)
//// held to NIST and to OpenSSL, and then used to reproduce the ML-KEM
//// values of `draft-vos-cfrg-pqpake-03` from their seeds.
////
//// The order is the order of trust. The reference counts for nothing until
//// it reproduces every NIST ACVP keyGen case (`d`, `z` to `ek`, `dk`) and
//// every encapsulation case (`ek`, `m` to `c`, `k`) in the trimmed fixture
//// byte for byte, and until OpenSSL, through the `primitives` binding,
//// agrees with it on fresh seeds: OpenSSL encapsulates to the reference's
//// `ek`, and decapsulates both its own ciphertext and the reference's with
//// the reference's `dk` to the right secret. Only then are the draft's
//// vectors checked: E.1.2's key from `keygen_seed`, re-encoded by Kemeleon
//// under `kemeleon_m`, must be the vector's `upk`, and `encaps_m` must give
//// its `ct` and `k`; the same holds for the ML-KEM steps inside E.2 and
//// E.4. OpenSSL then decapsulates each draft ciphertext with the derived
//// `dk`, so every draft value meets both implementations.

import core/crypto/kemeleon
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import primitives
import primitives/mlkem_reference
import primitives/vectors

/// The ACVP cases of one function.
fn acvp(function: String) -> List(vectors.Vector) {
  vectors.where(vectors.load("acvp_mlkem1024"), "function", function)
}

/// Every NIST keyGen case: `KeyGen_internal(d, z)` is the listed `ek` and
/// `dk`, byte for byte. This pins `G(d || k)`, `SampleNTT`, the CBD, the
/// NTT and its zetas, the base-case products and `ByteEncode_12`, and the
/// `dk` layout with its `H(ek)` and `z`.
pub fn acvp_key_generation_test() {
  let cases = acvp("keyGen")

  assert list.length(cases) == 3
  assert vectors.failing(cases, fn(v) {
      mlkem_reference.keygen_internal(vectors.hex(v, "d"), vectors.hex(v, "z"))
      == #(vectors.hex(v, "ek"), vectors.hex(v, "dk"))
    })
    == []
}

/// Every NIST encapsulation case: `Encaps_internal(ek, m)` is the listed
/// `k` and `c`. This adds the inverse NTT, the transpose, both error
/// distributions, `Compress` at `du` and `dv`, and `G(m || H(ek))`.
pub fn acvp_encapsulation_test() {
  let cases = acvp("encapsulation")

  assert list.length(cases) == 3
  assert vectors.failing(cases, fn(v) {
      mlkem_reference.encaps_internal(vectors.hex(v, "ek"), vectors.hex(v, "m"))
      == #(vectors.hex(v, "k"), vectors.hex(v, "c"))
    })
    == []
}

/// The reference and the production binding are the same KEM, on fresh
/// seeds: OpenSSL accepts the reference's `ek`, and with the reference's
/// `dk` opens both its own ciphertext and the reference's to the secret
/// each side computed. Ten key pairs cost well under a second (one
/// reference key generation and encapsulation together take about 25 ms);
/// ACVP carries the byte-exact coverage.
pub fn openssl_agrees_with_the_reference_on_fresh_seeds_test() {
  assert list.all(list.repeat(Nil, 10), fn(_) {
    let #(ek, dk) =
      mlkem_reference.keygen_internal(
        primitives.random_bytes(32),
        primitives.random_bytes(32),
      )
    let #(reference_secret, reference_ciphertext) =
      mlkem_reference.encaps_internal(ek, primitives.random_bytes(32))
    let assert Ok(#(openssl_secret, openssl_ciphertext)) =
      primitives.mlkem1024_encapsulate(ek)
      as "OpenSSL accepts the reference's encapsulation key"

    primitives.mlkem1024_decapsulate(dk, openssl_ciphertext)
    == Ok(openssl_secret)
    && primitives.mlkem1024_decapsulate(dk, reference_ciphertext)
    == Ok(reference_secret)
  })
}

/// One draft vector's ML-KEM step: where its seeds are, and where its
/// pinned key, ciphertext and secret are.
type DraftStep {
  DraftStep(
    vector: vectors.Vector,
    /// The field holding the Kemeleon-encoded public key.
    upk: String,
    /// The pinned ciphertext, `ct` itself or cut from a message.
    ciphertext: BitArray,
    /// The field holding the pinned shared secret.
    shared_secret: String,
  )
}

/// The only case of a draft fixture.
fn single(name: String) -> vectors.Vector {
  let assert [vector] = vectors.load(name) as "the fixture has one case"
  vector
}

/// The first Nct bytes of a message field, which is where E.2's `resp_msg`
/// and E.4's `msg3` carry the ciphertext.
fn leading_ciphertext(vector: vectors.Vector, key: String) -> BitArray {
  let assert Ok(ciphertext) = bit_array.slice(vectors.hex(vector, key), 0, 1568)
    as "the message starts with a ciphertext"
  ciphertext
}

/// The vector's `kemeleon_m`.
fn multiples(vector: vectors.Vector) -> kemeleon.Randomness {
  let assert Ok(numbers) =
    vectors.text(vector, "kemeleon_m")
    |> string.split(" ")
    |> list.try_map(int.parse)
    as "four decimal numbers"
  let assert Ok(randomness) = kemeleon.randomness_from_multiples(numbers)
    as "four non-negative multiples"
  randomness
}

/// Reproduces one draft step from its seeds and checks each pinned value
/// on its own, so a failure names the value that moved: the key from
/// `keygen_seed` encodes to the pinned `upk`, `encaps_m` gives the pinned
/// ciphertext and secret, and OpenSSL with the derived `dk` opens the
/// pinned ciphertext to the pinned secret.
fn check_draft_step(step: DraftStep) -> Nil {
  let v = step.vector
  let #(ek, dk) = mlkem_reference.derive_key_pair(vectors.hex(v, "keygen_seed"))
  let #(shared_secret, ciphertext) =
    mlkem_reference.encaps_internal(ek, vectors.hex(v, "encaps_m"))

  assert kemeleon.encode(ek, multiples(v)) == Ok(vectors.hex(v, step.upk))
  assert ciphertext == step.ciphertext
  assert shared_secret == vectors.hex(v, step.shared_secret)
  assert primitives.mlkem1024_decapsulate(dk, step.ciphertext)
    == Ok(vectors.hex(v, step.shared_secret))
}

/// E.1.2, ML-BUA-sKEM-1024: `upk`, `ct` and `k` from the seeds.
pub fn draft_e1_2_ml_kem_from_seeds_test() {
  let v = single("bua_skem_mlbuaskem1024")

  check_draft_step(DraftStep(
    vector: v,
    upk: "upk",
    ciphertext: vectors.hex(v, "ct"),
    shared_secret: "k",
  ))
}

/// E.2, OQUAKE: `oquake_upk`, the ciphertext at the head of `resp_msg`,
/// and `oquake_k`, from the seeds.
pub fn draft_e2_ml_kem_from_seeds_test() {
  let v = single("oquake_mlbuaskem1024")

  check_draft_step(DraftStep(
    vector: v,
    upk: "oquake_upk",
    ciphertext: leading_ciphertext(v, "resp_msg"),
    shared_secret: "oquake_k",
  ))
}

/// E.4, CPaceOQUAKE: `oquake_upk`, the ciphertext at the head of `msg3`,
/// and `oquake_k`, from the seeds.
pub fn draft_e4_ml_kem_from_seeds_test() {
  let v = single("oquake_cpaceoquake_stage")

  check_draft_step(DraftStep(
    vector: v,
    upk: "oquake_upk",
    ciphertext: leading_ciphertext(v, "msg3"),
    shared_secret: "oquake_k",
  ))
}
