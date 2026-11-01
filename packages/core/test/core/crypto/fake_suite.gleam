//// A deterministic stand-in for the real primitives, for tests only.
////
//// This lives under `test/` and nowhere else on purpose: `docs/spec.md`
//// §13.3 forbids a test crypto provider that a release could select, and a
//// module outside `src/` is not compiled into a release at all. Nothing
//// here is secure and nothing is meant to be. The point is to run the whole
//// handshake and ratchet as pure Gleam, so that properties can be checked
//// over many random interleavings without OpenSSL.
////
//// The fakes are chosen to keep the properties the protocol relies on:
////
//// - Agreement is commutative (XOR of two 32-byte values), and a public key
////   equals its secret, so `x25519(a, b) == x25519(b, a)`.
//// - Every hash lane multiplies by an odd constant modulo 2^64, so changing
////   any single input byte changes every lane of the output. That is what
////   makes "any single corrupted byte is rejected" a deterministic property
////   of the fake AEAD rather than a probabilistic one.
//// - Signatures are keyed hashes, verified by recomputing; the KEM masks a
////   fresh shared secret with a seed carried in the keys.
////
//// Fresh keys and shared secrets need a source of distinct values, and a
//// pure function has none, so the one impurity is `unique_integer`, used as
//// the entropy that the real suite takes from the operating system.

import core/crypto/suite.{type Suite, Suite}
import gleam/bit_array
import gleam/int
import gleam/result

@external(erlang, "erlang", "unique_integer")
fn unique_integer() -> Int

const mask = 0xFFFFFFFFFFFFFFFF

/// The fake suite.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(fake_suite.suite().sha256(<<"x">>))
/// // -> 32
/// ```
pub fn suite() -> Suite {
  Suite(
    random: fresh,
    sha256: hash,
    hmac_sha256: hmac,
    constant_time_equal: fn(left, right) { left == right },
    x25519_keypair: fn() {
      let secret = fresh(32)
      #(secret, secret)
    },
    x25519: agree,
    ed25519_keypair: fn() {
      let secret = fresh(32)
      #(secret, secret)
    },
    ed25519_sign: fn(secret, message) { Ok(sign(secret, message)) },
    ed25519_verify: fn(public, message, signature) {
      sign(public, message) == signature
    },
    kem_keypair: fn() {
      let seed = fresh(32)
      #(repeat(seed, 99), repeat(seed, 49))
    },
    kem_encapsulate: encapsulate,
    kem_decapsulate: decapsulate,
    aead_seal: seal,
    aead_open: open,
  )
}

/// `count` bytes that differ on every call.
///
/// ## Examples
///
/// ```gleam
/// fake_suite.fresh(4) != fake_suite.fresh(4)
/// ```
pub fn fresh(count: Int) -> BitArray {
  stretch(<<"fresh":utf8, unique_integer():size(64)>>, count)
}

// Hash output repeated and truncated to exactly `count` bytes.
fn stretch(seed: BitArray, count: Int) -> BitArray {
  let assert Ok(bytes) =
    bit_array.slice(repeat(hash(seed), count / 32 + 1), 0, count)
    as "the repeated hash is at least `count` bytes"
  bytes
}

fn repeat(chunk: BitArray, times: Int) -> BitArray {
  case times <= 0 {
    True -> <<>>
    False -> <<chunk:bits, repeat(chunk, times - 1):bits>>
  }
}

fn lane(data: BitArray, multiplier: Int, accumulator: Int) -> Int {
  case data {
    <<byte, rest:bytes>> ->
      lane(
        rest,
        multiplier,
        int.bitwise_and(accumulator * multiplier + byte + 1, mask),
      )
    _ -> accumulator
  }
}

fn hash(data: BitArray) -> BitArray {
  <<
    lane(data, 1_099_511_628_211, 1):size(64),
    lane(data, 6_364_136_223_846_793_005, 2):size(64),
    lane(data, 1_442_695_040_888_963_407, 3):size(64),
    lane(data, 0x9E3779B97F4A7C15, 4):size(64),
  >>
}

fn hmac(key: BitArray, data: BitArray) -> BitArray {
  hash(<<"hmac":utf8, bit_array.byte_size(key):size(32), key:bits, data:bits>>)
}

fn xor(left: BitArray, right: BitArray) -> BitArray {
  case left, right {
    <<a, rest_left:bytes>>, <<b, rest_right:bytes>> -> <<
      int.bitwise_exclusive_or(a, b),
      xor(rest_left, rest_right):bits,
    >>
    _, _ -> <<>>
  }
}

fn is_zero(bytes: BitArray) -> Bool {
  case bytes {
    <<0, rest:bytes>> -> is_zero(rest)
    <<>> -> True
    _ -> False
  }
}

fn agree(secret: BitArray, public: BitArray) -> Result(BitArray, Nil) {
  case bit_array.byte_size(secret) == 32 && bit_array.byte_size(public) == 32 {
    False -> Error(Nil)
    True ->
      case is_zero(xor(secret, public)) {
        True -> Error(Nil)
        False -> Ok(xor(secret, public))
      }
  }
}

fn sign(key: BitArray, message: BitArray) -> BitArray {
  <<
    hmac(key, <<"sig-a":utf8, message:bits>>):bits,
    hmac(key, <<"sig-b":utf8, message:bits>>):bits,
  >>
}

fn seed_of(key: BitArray) -> Result(BitArray, Nil) {
  bit_array.slice(key, 0, 32)
}

fn encapsulate(public: BitArray) -> Result(#(BitArray, BitArray), Nil) {
  use seed <- result.try(seed_of(public))
  let shared = fresh(32)

  Ok(#(shared, repeat(xor(shared, seed), 49)))
}

fn decapsulate(
  secret: BitArray,
  ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  use seed <- result.try(seed_of(secret))
  use masked <- result.try(seed_of(ciphertext))

  Ok(xor(masked, seed))
}

fn keystream(key: BitArray, nonce: BitArray, length: Int) -> BitArray {
  stretch(<<"ks":utf8, key:bits, nonce:bits>>, length)
}

fn tag(
  key: BitArray,
  nonce: BitArray,
  aad: BitArray,
  body: BitArray,
) -> BitArray {
  let assert Ok(short) =
    bit_array.slice(
      hash(<<
        "tag":utf8,
        key:bits,
        nonce:bits,
        bit_array.byte_size(aad):size(64),
        aad:bits,
        body:bits,
      >>),
      0,
      16,
    )
    as "a digest is 32 bytes"
  short
}

fn seal(
  key: BitArray,
  nonce: BitArray,
  aad: BitArray,
  plaintext: BitArray,
) -> Result(BitArray, Nil) {
  let body =
    xor(plaintext, keystream(key, nonce, bit_array.byte_size(plaintext)))

  Ok(<<body:bits, tag(key, nonce, aad, body):bits>>)
}

fn open(
  key: BitArray,
  nonce: BitArray,
  aad: BitArray,
  sealed: BitArray,
) -> Result(BitArray, Nil) {
  let body_size = bit_array.byte_size(sealed) - 16

  use body <- result.try(bit_array.slice(sealed, 0, body_size))
  use received <- result.try(bit_array.slice(sealed, body_size, 16))

  case received == tag(key, nonce, aad, body) {
    True -> Ok(xor(body, keystream(key, nonce, body_size)))
    False -> Error(Nil)
  }
}
