//// Wycheproof HMAC-SHA-256 vectors through `primitives.hmac_sha256`.
////
//// The binding returns the full 32-byte tag; the upstream groups with a
//// 128-bit `tagSize` compare its prefix. Keys of 16, 32 and 65 bytes cover
//// a key shorter than, equal to and longer than the hash block, which is
//// where an HMAC implementation can get the padding wrong. The ratchet's
//// chain keys are 32 bytes, the KDF_CK inputs are single bytes, and HKDF
//// feeds HMAC keys of every length between.

import gleam/bit_array
import gleam/list
import primitives
import primitives/vectors

fn computed_prefix(v: vectors.Vector) -> BitArray {
  let tag = primitives.hmac_sha256(vectors.hex(v, "key"), vectors.hex(v, "msg"))
  let assert Ok(prefix) = bit_array.slice(tag, 0, vectors.int(v, "tagSize") / 8)
    as "the tag size is at most 256 bits"
  prefix
}

pub fn hmac_sha256_wycheproof_count_test() {
  assert list.length(vectors.load("wycheproof_hmac_sha256")) == 174
}

pub fn hmac_sha256_every_valid_tag_matches_test() {
  let valid =
    vectors.where(vectors.load("wycheproof_hmac_sha256"), "result", "valid")

  assert list.length(valid) == 66
  assert vectors.failing(valid, fn(v) {
      computed_prefix(v) == vectors.hex(v, "tag")
    })
    == []
}

pub fn hmac_sha256_every_modified_tag_differs_test() {
  let invalid =
    vectors.where(vectors.load("wycheproof_hmac_sha256"), "result", "invalid")

  assert list.length(invalid) == 108
  assert vectors.failing(invalid, fn(v) {
      computed_prefix(v) != vectors.hex(v, "tag")
    })
    == []
}
