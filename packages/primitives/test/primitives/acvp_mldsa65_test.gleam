//// NIST ACVP ML-DSA-65 vectors (FIPS 204) through `primitives.mldsa65_sign`
//// and `primitives.mldsa65_verify`.
////
//// The binding signs and verifies the pure (not pre-hashed) external
//// interface with an empty context string, hedged. Three things in the
//// NIST files reach that surface. The keyGen cases give a key pair in FIPS
//// 204's encoding, and a signature made with the NIST secret key must
//// verify under the NIST public key, which shows that OpenSSL's "expanded"
//// secret key is the standard's own encoding. The sigGen cases with an
//// empty context give signatures (deterministic and hedged) that must
//// verify; the ones with a non-empty context must not, because the context
//// is bound into the signed message by FIPS 204's domain separator and the
//// binding always supplies the empty one. The one sigVer case with an
//// empty context is a modified message and must be refused.
////
//// Nothing here reproduces a NIST signature byte for byte: OTP signs in
//// hedged mode only, and does not derive a key pair from a seed.

import gleam/list
import primitives
import primitives/vectors

fn by_function(function: String) -> List(vectors.Vector) {
  vectors.where(vectors.load("acvp_mldsa65"), "function", function)
}

fn verifies(v: vectors.Vector) -> Bool {
  primitives.mldsa65_verify(
    vectors.hex(v, "pk"),
    vectors.hex(v, "message"),
    vectors.hex(v, "signature"),
  )
}

fn context_is_empty(v: vectors.Vector) -> Bool {
  vectors.hex(v, "context") == <<>>
}

pub fn mldsa65_acvp_count_test() {
  assert list.length(vectors.load("acvp_mldsa65")) == 10
}

pub fn mldsa65_nist_key_pairs_sign_and_verify_through_the_binding_test() {
  let keygen = by_function("keyGen")

  assert list.length(keygen) == 3
  assert vectors.failing(keygen, fn(v) {
      case primitives.mldsa65_sign(vectors.hex(v, "sk"), <<"acvp keyGen">>) {
        Ok(signature) ->
          primitives.mldsa65_verify(
            vectors.hex(v, "pk"),
            <<"acvp keyGen">>,
            signature,
          )
        Error(Nil) -> False
      }
    })
    == []
}

pub fn mldsa65_nist_signatures_with_an_empty_context_verify_test() {
  let empty = list.filter(by_function("sigGen"), context_is_empty)

  assert list.length(empty) == 2
  assert vectors.failing(empty, verifies) == []
}

pub fn mldsa65_nist_signatures_under_another_context_are_refused_test() {
  let nonempty =
    list.filter(by_function("sigGen"), fn(v) { !context_is_empty(v) })

  assert list.length(nonempty) == 4
  assert vectors.failing(nonempty, fn(v) { !verifies(v) }) == []
}

pub fn mldsa65_nist_modified_message_is_refused_test() {
  let sigver = by_function("sigVer")

  assert list.length(sigver) == 1
  assert vectors.failing(sigver, fn(v) {
      context_is_empty(v) && !vectors.bool(v, "testPassed") && !verifies(v)
    })
    == []
}
