//// Wycheproof X25519 vectors through `primitives.x25519`.
////
//// The binding owes the protocol one thing beyond RFC 7748 arithmetic: an
//// agreement whose output is all zeros (a small-order or low-order public
//// key, Wycheproof's `ZeroSharedSecret`) must be refused, because PQXDH
//// mixes the agreement into the session key and a zero contribution is
//// one the attacker chose. Every other case the upstream file marks
//// `acceptable` (twist points, non-canonical encodings, edge-case scalars)
//// is computed as the RFC says, and the test pins that so a change in
//// OpenSSL's behaviour is noticed rather than silently absorbed.

import gleam/list
import primitives
import primitives/vectors

const zero_shared = <<0:256>>

pub fn x25519_wycheproof_count_test() {
  assert list.length(vectors.load("wycheproof_x25519")) == 518
}

pub fn x25519_zero_shared_secret_is_refused_test() {
  let tests = vectors.load("wycheproof_x25519")
  let zero =
    list.filter(tests, fn(v) { vectors.hex(v, "shared") == zero_shared })

  assert list.length(zero) == 31
  assert vectors.failing(zero, fn(v) {
      primitives.x25519(vectors.hex(v, "private"), vectors.hex(v, "public"))
      == Error(Nil)
    })
    == []
}

pub fn x25519_every_valid_case_agrees_test() {
  let tests = vectors.load("wycheproof_x25519")
  let valid = vectors.where(tests, "result", "valid")

  assert list.length(valid) == 264
  assert vectors.failing(valid, fn(v) {
      primitives.x25519(vectors.hex(v, "private"), vectors.hex(v, "public"))
      == Ok(vectors.hex(v, "shared"))
    })
    == []
}

/// The acceptable cases with a non-zero result: twist points, non-canonical
/// public keys (the top bit set, or a value at or above the field prime)
/// and edge-case multiplications. RFC 7748 defines the output for all of
/// them and OpenSSL computes it, so the binding returns it.
pub fn x25519_acceptable_nonzero_cases_compute_the_rfc_output_test() {
  let tests = vectors.load("wycheproof_x25519")
  let acceptable =
    vectors.where(tests, "result", "acceptable")
    |> list.filter(fn(v) { vectors.hex(v, "shared") != zero_shared })

  assert list.length(acceptable) == 223
  assert vectors.failing(acceptable, fn(v) {
      primitives.x25519(vectors.hex(v, "private"), vectors.hex(v, "public"))
      == Ok(vectors.hex(v, "shared"))
    })
    == []
}

/// The public key of a private key is also pinned where the file gives
/// both, which checks the base-point multiplication path.
pub fn x25519_public_key_derivation_test() {
  let tests = vectors.load("wycheproof_x25519")
  let ktv = list.filter(tests, fn(v) { vectors.flagged(v, "Ktv") })

  assert list.length(ktv) == 3
  assert vectors.failing(ktv, fn(v) {
      case primitives.x25519_public(vectors.hex(v, "private")) {
        Ok(public) ->
          primitives.x25519(vectors.hex(v, "private"), public) != Error(Nil)
        Error(Nil) -> False
      }
    })
    == []
}
