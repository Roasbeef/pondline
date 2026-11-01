//// NIST ACVP ML-KEM-1024 vectors (FIPS 203) through
//// `primitives.mlkem1024_encapsulate` and `primitives.mlkem1024_decapsulate`.
////
//// OTP exposes no seeded key generation or encapsulation, so the `d`, `z`
//// and `m` inputs cannot be replayed. What can be checked is everything
//// the decapsulation side of the protocol depends on: that a NIST key pair
//// in FIPS 203's encoding is the encoding OpenSSL stores, that
//// decapsulation of a NIST ciphertext gives the NIST shared secret, and,
//// the case that matters most, that a modified ciphertext decapsulates to
//// exactly the implicit-rejection secret `J(z || c)` the standard
//// prescribes rather than to an error. The responder sees a mangled `CT`
//// as a failed AEAD on the first ratchet message because that secret is
//// unrelated to the sender's, and nothing in the binding turns it into
//// anything else.
////
//// The key-check groups say what the binding does with a malformed key:
//// an encapsulation key with a coefficient outside the modulus is refused
//// (FIPS 203 section 7.2), and a decapsulation key whose embedded hash of
//// the encapsulation key is wrong is refused too (section 7.3).

import gleam/list
import primitives
import primitives/vectors

fn by_function(function: String) -> List(vectors.Vector) {
  vectors.where(vectors.load("acvp_mlkem1024"), "function", function)
}

pub fn mlkem1024_acvp_count_test() {
  assert list.length(vectors.load("acvp_mlkem1024")) == 24
}

/// A NIST key pair works through the binding: the encapsulation key is
/// accepted, and the decapsulation key opens what was sealed to it.
pub fn mlkem1024_nist_key_pairs_round_trip_test() {
  let keygen = by_function("keyGen")

  assert list.length(keygen) == 3
  assert vectors.failing(keygen, fn(v) {
      case primitives.mlkem1024_encapsulate(vectors.hex(v, "ek")) {
        Ok(#(shared, ciphertext)) ->
          primitives.mlkem1024_decapsulate(vectors.hex(v, "dk"), ciphertext)
          == Ok(shared)
        Error(Nil) -> False
      }
    })
    == []
}

/// The encapsulation cases carry NIST's ciphertext and shared secret for
/// the key pair; decapsulation must reproduce the secret.
pub fn mlkem1024_nist_ciphertexts_decapsulate_to_the_nist_secret_test() {
  let encapsulation = by_function("encapsulation")

  assert list.length(encapsulation) == 3
  assert vectors.failing(encapsulation, fn(v) {
      primitives.mlkem1024_decapsulate(
        vectors.hex(v, "dk"),
        vectors.hex(v, "c"),
      )
      == Ok(vectors.hex(v, "k"))
    })
    == []
}

/// Every decapsulation case, valid or with a modified ciphertext, returns
/// `Ok` with exactly the secret NIST lists. For the modified ones that is
/// the implicit-rejection value.
pub fn mlkem1024_decapsulation_matches_nist_including_implicit_rejection_test() {
  let decapsulation = by_function("decapsulation")
  let modified =
    list.filter(decapsulation, fn(v) {
      vectors.text(v, "reason") == "modified ciphertext"
    })

  assert list.length(decapsulation) == 10
  assert list.length(modified) == 5
  assert vectors.failing(decapsulation, fn(v) {
      primitives.mlkem1024_decapsulate(
        vectors.hex(v, "dk"),
        vectors.hex(v, "c"),
      )
      == Ok(vectors.hex(v, "k"))
    })
    == []
}

pub fn mlkem1024_encapsulation_key_modulus_check_test() {
  let checks = by_function("encapsulationKeyCheck")

  assert list.length(checks) == 4
  assert vectors.failing(checks, fn(v) {
      let accepted = case
        primitives.mlkem1024_encapsulate(vectors.hex(v, "ek"))
      {
        Ok(_) -> True
        Error(Nil) -> False
      }
      accepted == vectors.bool(v, "testPassed")
    })
    == []
}

/// A decapsulation key with a wrong embedded hash is refused before any
/// ciphertext is considered, so the probe ciphertext here is the key's own
/// encapsulation key bytes, which are the right size and nothing else.
pub fn mlkem1024_decapsulation_key_hash_check_test() {
  let checks = by_function("decapsulationKeyCheck")

  assert list.length(checks) == 4
  assert vectors.failing(checks, fn(v) {
      let accepted = case
        primitives.mlkem1024_decapsulate(
          vectors.hex(v, "dk"),
          vectors.hex(v, "ek"),
        )
      {
        Ok(_) -> True
        Error(Nil) -> False
      }
      accepted == vectors.bool(v, "testPassed")
    })
    == []
}
