//// Wycheproof HKDF-SHA-256 vectors through `core/crypto/hkdf` over the
//// real HMAC, the path PQXDH and the ratchet take.
////
//// The cases cover an empty salt (which HKDF treats as a zero key of the
//// hash length, and which the handshake's zero salt relies on), the
//// maximal output size of 255 blocks, and sizes past it, which must be
//// refused: `hkdf.expand` checks the bound before any work.

import core/crypto/hkdf
import gleam/list
import primitives/suite
import primitives/vectors

fn expand(v: vectors.Vector) -> Result(BitArray, Nil) {
  hkdf.extract_expand(
    suite.suite(),
    vectors.hex(v, "salt"),
    vectors.hex(v, "ikm"),
    vectors.hex(v, "info"),
    vectors.int(v, "size"),
  )
  |> result_nil
}

fn result_nil(result: Result(a, b)) -> Result(a, Nil) {
  case result {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Nil)
  }
}

pub fn hkdf_sha256_wycheproof_count_test() {
  assert list.length(vectors.load("wycheproof_hkdf_sha256")) == 86
}

pub fn hkdf_sha256_every_valid_case_derives_the_okm_test() {
  let valid =
    vectors.where(vectors.load("wycheproof_hkdf_sha256"), "result", "valid")

  assert list.length(valid) == 83
  assert vectors.failing(valid, fn(v) { expand(v) == Ok(vectors.hex(v, "okm")) })
    == []
}

pub fn hkdf_sha256_oversized_outputs_are_refused_test() {
  let invalid =
    vectors.where(vectors.load("wycheproof_hkdf_sha256"), "result", "invalid")

  assert list.length(invalid) == 3
  assert vectors.failing(invalid, fn(v) { expand(v) == Error(Nil) }) == []
}
