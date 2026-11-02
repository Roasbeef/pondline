//// Wycheproof ChaCha20-Poly1305 vectors through `primitives.aead_seal`
//// and `primitives.aead_open`.
////
//// The ratchet derives a 12-byte nonce for every message, so the binding
//// must refuse every other nonce size (`InvalidNonceSize`) rather than
//// let OpenSSL interpret it, and must refuse every modified tag. The
//// upstream file encodes the ciphertext and the tag separately; the
//// binding's sealed form is their concatenation.

import gleam/bit_array
import gleam/list
import primitives
import primitives/vectors

fn sealed(v: vectors.Vector) -> BitArray {
  bit_array.append(vectors.hex(v, "ct"), vectors.hex(v, "tag"))
}

fn seal(v: vectors.Vector) -> Result(BitArray, Nil) {
  primitives.aead_seal(
    key: vectors.hex(v, "key"),
    nonce: vectors.hex(v, "iv"),
    aad: vectors.hex(v, "aad"),
    plaintext: vectors.hex(v, "msg"),
  )
}

fn open(v: vectors.Vector) -> Result(BitArray, Nil) {
  primitives.aead_open(
    key: vectors.hex(v, "key"),
    nonce: vectors.hex(v, "iv"),
    aad: vectors.hex(v, "aad"),
    sealed: sealed(v),
  )
}

pub fn chacha20_poly1305_wycheproof_count_test() {
  assert list.length(vectors.load("wycheproof_chacha20_poly1305")) == 325
}

pub fn chacha20_poly1305_every_valid_case_round_trips_test() {
  let valid =
    vectors.where(
      vectors.load("wycheproof_chacha20_poly1305"),
      "result",
      "valid",
    )

  assert list.length(valid) == 256
  assert vectors.failing(valid, fn(v) {
      seal(v) == Ok(sealed(v)) && open(v) == Ok(vectors.hex(v, "msg"))
    })
    == []
}

pub fn chacha20_poly1305_every_modified_tag_is_refused_test() {
  let modified =
    vectors.load("wycheproof_chacha20_poly1305")
    |> list.filter(fn(v) { vectors.flagged(v, "ModifiedTag") })

  assert list.length(modified) == 60
  assert vectors.failing(modified, fn(v) { open(v) == Error(Nil) }) == []
}

pub fn chacha20_poly1305_every_other_nonce_size_is_refused_test() {
  let wrong_nonce =
    vectors.load("wycheproof_chacha20_poly1305")
    |> list.filter(fn(v) { vectors.flagged(v, "InvalidNonceSize") })

  assert list.length(wrong_nonce) == 9
  assert vectors.failing(wrong_nonce, fn(v) {
      seal(v) == Error(Nil) && open(v) == Error(Nil)
    })
    == []
}
