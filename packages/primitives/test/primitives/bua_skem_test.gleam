//// ML-BUA-sKEM-1024 (`core/crypto/bua_skem`) over the real ML-KEM-1024,
//// and Kemeleon against the vectors of `draft-vos-cfrg-pqpake-03`.
////
//// Appendix E.1.2 gives the randomness of one key generation and one
//// encapsulation (`keygen_seed`, `kemeleon_m`, `encaps_m`) and their outputs
//// (`upk`, `ct`, `k`). OTP has no seeded ML-KEM key generation or
//// encapsulation, and the vector lists no decapsulation key, so the ML-KEM
//// steps come from the test-only FIPS 203 reference
//// (`primitives/mlkem_reference`, held to NIST ACVP and to OpenSSL in
//// `mlkem_reference_test`): `vector_reproduced_from_its_seeds_test` runs
//// `bua_skem`'s own key-pair, encapsulation and decapsulation over the
//// key pair `keygen_seed` derives and an encapsulation seeded with
//// `encaps_m`, and gets `upk`, `ct` and `k` byte for byte, with OpenSSL
//// decapsulating. Kemeleon is also checked on its own: decoding the
//// vector's `upk` and re-encoding it under the vector's four multiples
//// must give `upk` back byte for byte, which pins the base-3329 reading,
//// the multiple of 3329^256, the 391-byte little-endian width and the
//// seed's place, all at once. The same holds for the `oquake_upk` of E.2
//// and E.4, checked in `oquake_test`. The rest is checked by round trip
//// and by the binary property: every string of the right length is a key
//// OpenSSL accepts.

import core/crypto/bua_skem.{Encapsulation, KeyPair, SplitKey}
import core/crypto/error.{Malformed}
import core/crypto/kemeleon
import core/crypto/suite as core_suite
import core/secret
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import primitives/mlkem_reference
import primitives/suite
import primitives/vectors

fn vector() -> vectors.Vector {
  let assert [vector] = vectors.load("bua_skem_mlbuaskem1024")
    as "the fixture has one case"
  vector
}

/// The vector's `kemeleon_m`: four decimal multiples, space separated.
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

/// E.1.2: the encapsulation key `upk` stands for, re-encoded under the
/// vector's multiples, is `upk`. A key pair built from it carries exactly
/// that public key.
pub fn vector_public_key_reencodes_exactly_test() {
  let vector = vector()
  let upk = vectors.hex(vector, "upk")
  let assert Ok(encapsulation_key) = kemeleon.decode(upk)
  let assert Ok(KeyPair(public_key:, ..)) =
    bua_skem.key_pair_from(
      secret.new(<<0:size(25_344)>>),
      encapsulation_key,
      multiples(vector),
    )

  assert bit_array.byte_size(encapsulation_key) == 1568
  assert public_key == upk
}

/// E.1.2: the decoded key is one OpenSSL accepts, and OpenSSL's own
/// (unseeded) encapsulation to it gives a ciphertext and secret of the
/// sizes the vector's `ct` and `k` have. The values themselves are
/// reproduced from the seeds in `vector_reproduced_from_its_seeds_test`.
pub fn vector_public_key_is_an_ml_kem_key_test() {
  let vector = vector()
  let assert Ok(Encapsulation(shared_secret:, ciphertext:)) =
    bua_skem.encapsulate(suite.suite(), vectors.hex(vector, "upk"))

  assert bit_array.byte_size(ciphertext)
    == bit_array.byte_size(vectors.hex(vector, "ct"))
  assert secret.byte_size(shared_secret)
    == bit_array.byte_size(vectors.hex(vector, "k"))
}

/// E.1.2 from its seeds: the key pair `keygen_seed` derives, encoded by
/// `bua_skem.key_pair_from` under `kemeleon_m`, is `upk`; `bua_skem`'s
/// encapsulation to `upk`, with the suite's ML-KEM encapsulation seeded by
/// `encaps_m` through the reference, gives `ct` and `k`; and
/// `bua_skem.decapsulate` over OpenSSL, with the derived decapsulation
/// key, opens `ct` to `k`.
pub fn vector_reproduced_from_its_seeds_test() {
  let vector = vector()
  let #(encapsulation_key, decapsulation_key) =
    mlkem_reference.derive_key_pair(vectors.hex(vector, "keygen_seed"))
  let assert Ok(KeyPair(public_key:, ..)) =
    bua_skem.key_pair_from(
      secret.new(decapsulation_key),
      encapsulation_key,
      multiples(vector),
    )

  assert public_key == vectors.hex(vector, "upk")

  // Only the encapsulation is seeded, and only for the derived key; the
  // decapsulation below is the production binding's.
  let seeded =
    core_suite.Suite(..suite.suite(), kem_encapsulate: fn(key) {
      case key == encapsulation_key {
        True ->
          Ok(mlkem_reference.encaps_internal(
            key,
            vectors.hex(vector, "encaps_m"),
          ))
        False -> Error(Nil)
      }
    })
  let assert Ok(Encapsulation(shared_secret:, ciphertext:)) =
    bua_skem.encapsulate(seeded, public_key)

  assert ciphertext == vectors.hex(vector, "ct")
  assert secret.expose(shared_secret) == vectors.hex(vector, "k")
  assert bua_skem.decapsulate(
      suite.suite(),
      secret.new(decapsulation_key),
      vectors.hex(vector, "ct"),
    )
    |> result.map(secret.expose)
    == Ok(vectors.hex(vector, "k"))
}

/// A multiple is part of the encoding: re-encoding the vector's key under
/// one changed multiple does not give `upk`.
pub fn a_changed_multiple_changes_the_encoding_test() {
  let vector = vector()
  let upk = vectors.hex(vector, "upk")
  let assert Ok(encapsulation_key) = kemeleon.decode(upk)
  let assert Ok(changed) = kemeleon.randomness_from_multiples([0, 0, 0, 0])
  let assert Ok(encoded) = kemeleon.encode(encapsulation_key, changed)

  assert encoded != upk
  assert kemeleon.decode(encoded) == Ok(encapsulation_key)
}

/// Split cuts at Nt, Combine undoes it, and both refuse wrong lengths.
pub fn split_and_combine_are_inverse_test() {
  let upk = vectors.hex(vector(), "upk")
  let assert Ok(SplitKey(ut:, rho:)) = bua_skem.split(upk)
  let assert Ok(tail) = bit_array.slice(upk, 1564, 32)

  assert bit_array.byte_size(ut) == bua_skem.dependent_bytes
  assert rho == tail
  assert bua_skem.combine(ut, rho) == Ok(upk)
  assert bua_skem.split(<<upk:bits, 0>>)
    == Error(Malformed("bua-skem public key"))
  assert bua_skem.combine(rho, ut)
    == Error(Malformed("bua-skem public key part"))
}

/// A fresh key pair is honest: what is encapsulated to its public key, its
/// decapsulation key opens.
pub fn fresh_key_pairs_round_trip_test() {
  let suite = suite.suite()

  assert list.all(list.repeat(Nil, 5), fn(_) {
    let assert Ok(KeyPair(decapsulation_key:, public_key:)) =
      bua_skem.keygen(suite)
    let assert Ok(Encapsulation(shared_secret:, ciphertext:)) =
      bua_skem.encapsulate(suite, public_key)

    bit_array.byte_size(public_key) == bua_skem.public_key_bytes
    && bua_skem.decapsulate(suite, decapsulation_key, ciphertext)
    == Ok(shared_secret)
  })
}

/// Two key generations of one ML-KEM key give different public keys,
/// because the encoding randomness is fresh each time.
pub fn the_encoding_randomness_is_fresh_test() {
  let suite = suite.suite()
  let assert Ok(first) = bua_skem.keygen(suite)
  let assert Ok(second) = bua_skem.keygen(suite)

  assert first.public_key != second.public_key
}

/// The binary property, against the real ML-KEM: every random string of
/// Npk bytes is a public key OpenSSL encapsulates to, including the
/// extremes. OpenSSL applies FIPS 203's modulus check, so this is also an
/// outside check that `kemeleon.decode` never yields a coefficient of 3329
/// or more.
pub fn every_string_of_the_right_length_is_a_public_key_test() {
  let suite = suite.suite()
  let strings = [
    <<0:size(12_768)>>,
    <<-1:size(12_768)>>,
    ..list.map(list.repeat(Nil, 50), fn(_) { suite.random(1596) })
  ]

  assert list.filter(strings, fn(upk) {
      case bua_skem.encapsulate(suite, upk) {
        Ok(_) -> False
        Error(_) -> True
      }
    })
    == []
}

/// Decapsulation refuses a malformed ciphertext and opens a forged one of
/// the right length to an unrelated secret, as ML-KEM's implicit rejection
/// does.
pub fn decapsulation_rejects_implicitly_test() {
  let suite = suite.suite()
  let assert Ok(KeyPair(decapsulation_key:, public_key:)) =
    bua_skem.keygen(suite)
  let assert Ok(Encapsulation(shared_secret:, ..)) =
    bua_skem.encapsulate(suite, public_key)
  let assert Ok(forged) =
    bua_skem.decapsulate(suite, decapsulation_key, suite.random(1568))

  assert forged != shared_secret
  assert bua_skem.decapsulate(suite, decapsulation_key, <<1, 2, 3>>)
    == Error(error.PrimitiveFailed)
}
