//// A cryptographic suite whose every output is a function of a seed and a
//// draw counter, for the simulation only.
////
//// The real suite takes its entropy from OpenSSL (`crypto:strong_rand_bytes`
//// and the key generators), so two runs of one seed would mint different
//// identities, ids and capabilities, and nothing after the first draw would
//// replay. This suite keeps every real primitive that is already a pure
//// function (SHA-256, HMAC, the AEAD, X25519 and Ed25519 from a given
//// secret, Ed25519 signing, which is deterministic) and replaces only the
//// entropy:
////
//// - `random(n)` is SHA-256 of the seed, a label and the next value of a
////   shared counter, stretched to `n` bytes;
//// - X25519 and Ed25519 key pairs derive the public key from a drawn secret
////   with the real curve arithmetic;
//// - the KEM is the core fake's construction (no seeded ML-KEM exists in
////   OTP; `crypto:generate_key(mlkem1024, [], Seed)` is refused), with the
////   real key and ciphertext sizes: the secret key repeats a 32-byte seed to
////   3168 bytes, the public key to 1568, and encapsulation masks a drawn
////   shared secret with the seed.
////
//// - ML-DSA-65 is faked the same way and for a second reason: OpenSSL's
////   ML-DSA signing is hedged, so even a seeded key would sign differently
////   in two runs. The secret key carries a 32-byte seed and is stretched
////   to the real 4032 bytes, the public key is a hash of the seed stretched
////   to 1952, and a signature is an HMAC under the public key stretched to
////   3309. Anyone holding the public key can forge one, which a simulation
////   of honest and byzantine daemons does not mind.
////
//// The counter is an `atomics` cell shared by every process holding the
//// suite, so a restarted engine keeps drawing new values instead of
//// replaying the first ones. Draws are deterministic because the engine is
//// the only process that draws during a run, and the runner orders its
//// jobs. Nothing here is secure, and this package is never a dependency of
//// a release (`docs/spec.md` §13.3).

import core/crypto/suite.{type Suite, Suite}
import gleam/bit_array
import gleam/int
import gleam/result
import primitives
import sim/internal/ffi_vm

/// A deterministic suite for the party named `label` in the run seeded by
/// `seed`. Two suites with the same seed and label draw the same values.
///
/// ## Examples
///
/// ```gleam
/// let a = suite.new(<<1, 2, 3>>, "a")
/// bit_array.byte_size(a.random(16))
/// // -> 16
/// ```
pub fn new(seed: BitArray, label: String) -> Suite {
  let counter = ffi_vm.cells_new(1)
  let draw = fn(count) { draw(seed, label, counter, count) }

  Suite(
    random: draw,
    sha256: primitives.sha256,
    hmac_sha256: primitives.hmac_sha256,
    constant_time_equal: primitives.constant_time_equal,
    x25519_keypair: fn() { curve_pair(draw(32), primitives.x25519_public) },
    x25519: primitives.x25519,
    ed25519_keypair: fn() { curve_pair(draw(32), primitives.ed25519_public) },
    ed25519_sign: primitives.ed25519_sign,
    ed25519_verify: primitives.ed25519_verify,
    kem_keypair: fn() {
      let kem_seed = draw(32)
      #(repeat(kem_seed, 99), repeat(kem_seed, 49))
    },
    kem_encapsulate: fn(public) { encapsulate(public, draw(32)) },
    kem_decapsulate: decapsulate,
    mldsa_keypair: fn() { signing_pair(draw(32)) },
    mldsa_sign: sign,
    mldsa_verify: verify,
    aead_seal: primitives.aead_seal,
    aead_open: primitives.aead_open,
  )
}

/// `count` bytes from the next counter value.
fn draw(
  seed: BitArray,
  label: String,
  counter: ffi_vm.Cells,
  count: Int,
) -> BitArray {
  let n = ffi_vm.cells_add(counter, 1, 1)
  let block =
    primitives.sha256(<<
      "sim-draw":utf8,
      seed:bits,
      label:utf8,
      n:size(64),
    >>)

  stretch(block, count)
}

/// The block repeated until there are `count` bytes. Repetition rather
/// than a hash per 32 bytes: the fake ML-DSA keys and signatures are
/// thousands of bytes, and only their first block has to differ between
/// draws.
fn stretch(block: BitArray, count: Int) -> BitArray {
  let joined = repeat(block, count / 32 + 1)

  bit_array.slice(joined, 0, count) |> result.lazy_unwrap(fn() { <<>> })
}

/// A secret and the public key the real curve derives from it, as the
/// primitives return them: `#(secret, public)`.
fn curve_pair(
  secret: BitArray,
  public_of: fn(BitArray) -> Result(BitArray, Nil),
) -> #(BitArray, BitArray) {
  // A 32-byte secret always derives; an empty public key would only make
  // every later agreement fail, which the oracle would report.
  case public_of(secret) {
    Ok(public) -> #(secret, public)
    Error(Nil) -> #(secret, <<>>)
  }
}

/// A fake ML-DSA-65 key pair from a seed, as `#(secret, public)`.
fn signing_pair(signing_seed: BitArray) -> #(BitArray, BitArray) {
  let secret = <<
    signing_seed:bits,
    stretch(signing_seed, secret_signing_bytes - 32):bits,
  >>

  #(secret, signing_public(signing_seed))
}

/// The fake ML-DSA-65 public key of a seed.
fn signing_public(signing_seed: BitArray) -> BitArray {
  stretch(primitives.sha256(<<"mldsa-pk":utf8, signing_seed:bits>>), 1952)
}

/// The size of a fake ML-DSA-65 secret key, the real one's.
const secret_signing_bytes = 4032

/// Signs with a fake ML-DSA-65 secret key.
fn sign(secret: BitArray, message: BitArray) -> Result(BitArray, Nil) {
  use Nil <- result.try(sized(secret, secret_signing_bytes))
  use signing_seed <- result.try(bit_array.slice(secret, 0, 32))

  Ok(tag(signing_public(signing_seed), message))
}

/// Checks a fake ML-DSA-65 signature by recomputing it.
fn verify(public: BitArray, message: BitArray, signature: BitArray) -> Bool {
  bit_array.byte_size(public) == 1952 && tag(public, message) == signature
}

/// The fake signature: an HMAC under the public key, at the real size.
fn tag(public: BitArray, message: BitArray) -> BitArray {
  stretch(primitives.hmac_sha256(public, message), 3309)
}

/// `chunk` written `times` times.
fn repeat(chunk: BitArray, times: Int) -> BitArray {
  int.range(from: 0, to: times, with: <<>>, run: fn(acc, _) {
    <<acc:bits, chunk:bits>>
  })
}

/// The fake KEM's encapsulation: the shared secret masked with the seed the
/// public key carries, repeated to the real ciphertext size.
fn encapsulate(
  public: BitArray,
  shared: BitArray,
) -> Result(#(BitArray, BitArray), Nil) {
  use kem_seed <- result.try(bit_array.slice(public, 0, 32))
  use Nil <- result.try(sized(public, 1568))

  Ok(#(shared, repeat(xor(shared, kem_seed), 49)))
}

/// The fake KEM's decapsulation: unmask with the seed the secret key
/// carries.
fn decapsulate(
  secret: BitArray,
  ciphertext: BitArray,
) -> Result(BitArray, Nil) {
  use Nil <- result.try(sized(secret, 3168))
  use Nil <- result.try(sized(ciphertext, 1568))
  use kem_seed <- result.try(bit_array.slice(secret, 0, 32))
  use masked <- result.try(bit_array.slice(ciphertext, 0, 32))

  Ok(xor(masked, kem_seed))
}

/// `Ok` when `bytes` is exactly `size` bytes, as the real KEM requires.
fn sized(bytes: BitArray, size: Int) -> Result(Nil, Nil) {
  // The real primitives refuse any other length.
  case bit_array.byte_size(bytes) == size {
    True -> Ok(Nil)
    False -> Error(Nil)
  }
}

/// Byte-wise exclusive or over the shorter of the two.
fn xor(left: BitArray, right: BitArray) -> BitArray {
  // Either side running out ends the result.
  case left, right {
    <<a, rest_left:bytes>>, <<b, rest_right:bytes>> -> <<
      int.bitwise_exclusive_or(a, b),
      xor(rest_left, rest_right):bits,
    >>
    _, _ -> <<>>
  }
}
