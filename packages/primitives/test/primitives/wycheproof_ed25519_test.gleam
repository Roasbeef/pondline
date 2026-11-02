//// Wycheproof Ed25519 vectors through `primitives.ed25519_verify`.
////
//// The invalid cases are the ones that matter to the protocol. A verifier
//// that accepted a malleated signature (`SignatureMalleability`, the S
//// component not reduced) would let a mailbox rewrite the bytes of an
//// identity binding without the owner's keys, and the fingerprint hashes
//// those bytes. Truncated signatures, signatures with trailing garbage and
//// invalid encodings must all verify as false rather than raise, since the
//// shim turns a raise into false and the protocol relies on that.

import gleam/list
import primitives
import primitives/vectors

fn verifies(v: vectors.Vector) -> Bool {
  primitives.ed25519_verify(
    vectors.hex(v, "pk"),
    vectors.hex(v, "msg"),
    vectors.hex(v, "sig"),
  )
}

pub fn ed25519_wycheproof_count_test() {
  assert list.length(vectors.load("wycheproof_ed25519")) == 210
}

pub fn ed25519_every_valid_signature_verifies_test() {
  let valid =
    vectors.where(vectors.load("wycheproof_ed25519"), "result", "valid")

  assert list.length(valid) == 117
  assert vectors.failing(valid, verifies) == []
}

pub fn ed25519_every_invalid_signature_is_refused_test() {
  let invalid =
    vectors.where(vectors.load("wycheproof_ed25519"), "result", "invalid")

  assert list.length(invalid) == 64
  assert vectors.failing(invalid, fn(v) { !verifies(v) }) == []
}

/// Malleated signatures are listed on their own because they are the case
/// the identity encoding depends on.
pub fn ed25519_malleated_signatures_are_refused_test() {
  let malleated =
    vectors.load("wycheproof_ed25519")
    |> list.filter(fn(v) { vectors.flagged(v, "SignatureMalleability") })

  assert list.length(malleated) == 8
  assert vectors.failing(malleated, fn(v) { !verifies(v) }) == []
}

/// Small-order and mixed-order public keys are `acceptable` upstream: a
/// verifier may accept or refuse them. OpenSSL checks the RFC 8032 equation
/// without a cofactor or an order check on the key, so every one of these
/// cases verifies, and the test pins that. No honest identity has such a
/// key, and the protocol derives no trust from a public key alone (every
/// identity is also bound to an ML-DSA-65 key and reached through an
/// authenticated bundle or a signed transcript), so accepting them is safe
/// here; a future use that compared Ed25519 keys on their own would have to
/// revisit it.
pub fn ed25519_acceptable_cases_are_pinned_test() {
  let acceptable =
    vectors.where(vectors.load("wycheproof_ed25519"), "result", "acceptable")

  assert list.length(acceptable) == 29
  assert vectors.failing(acceptable, verifies) == []
}
