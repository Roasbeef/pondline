//// HKDF (RFC 5869) over HMAC-SHA-256.
////
//// Every key in the handshake and the ratchet comes out of this one
//// construction. It is written over `suite.hmac_sha256` rather than a
//// native HKDF so that the same code runs under the test suite, and it is
//// checked against RFC 5869's test cases 1 to 3 in
//// `packages/primitives/test/primitives/hkdf_test.gleam`.

import core/crypto/error.{type Error, Malformed}
import core/crypto/suite.{type Suite}
import gleam/bit_array
import gleam/result

/// The SHA-256 output size, which is the size of each HKDF block.
pub const hash_bytes = 32

/// The most output HKDF-SHA-256 can produce: 255 blocks.
pub const max_output_bytes = 8160

/// HKDF-Extract: the pseudorandom key for `ikm` under `salt`. An empty salt
/// behaves as the RFC's string of zero bytes, because HMAC pads its key with
/// zeros.
///
/// ## Examples
///
/// ```gleam
/// hkdf.extract(suite, <<>>, <<1, 2, 3>>)
/// // -> <<_:256>>
/// ```
pub fn extract(suite: Suite, salt: BitArray, ikm: BitArray) -> BitArray {
  suite.hmac_sha256(salt, ikm)
}

/// HKDF-Expand: `length` bytes of output keying material from `prk`,
/// separated by `info`. A length over `max_output_bytes` or below zero is
/// refused.
///
/// ## Examples
///
/// ```gleam
/// hkdf.expand(suite, prk, <<"info">>, 42)
/// // -> Ok(<<_:336>>)
/// ```
pub fn expand(
  suite: Suite,
  prk: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Error) {
  // Lengths past 255 blocks cannot be produced, so they are refused before any work.
  case length >= 0 && length <= max_output_bytes {
    True -> {
      let blocks = { length + hash_bytes - 1 } / hash_bytes
      let okm = expand_blocks(suite, prk, info, <<>>, 1, blocks, <<>>)

      bit_array.slice(okm, 0, length)
      |> result.replace_error(Malformed("hkdf output"))
    }

    False -> Error(Malformed("hkdf length"))
  }
}

/// Each block is HMAC(prk, previous block || info || counter), with the empty
/// string standing in for the block before the first.
fn expand_blocks(
  suite: Suite,
  prk: BitArray,
  info: BitArray,
  previous: BitArray,
  counter: Int,
  blocks: Int,
  acc: BitArray,
) -> BitArray {
  // The recursion ends once every block has been produced.
  case counter > blocks {
    True -> acc

    False -> {
      let block = suite.hmac_sha256(prk, <<previous:bits, info:bits, counter>>)

      expand_blocks(suite, prk, info, block, counter + 1, blocks, <<
        acc:bits,
        block:bits,
      >>)
    }
  }
}

/// Extract then expand, the form every caller in Pondline uses.
///
/// ## Examples
///
/// ```gleam
/// hkdf.extract_expand(suite, salt, ikm, <<"info">>, 64)
/// // -> Ok(<<_:512>>)
/// ```
pub fn extract_expand(
  suite: Suite,
  salt: BitArray,
  ikm: BitArray,
  info: BitArray,
  length: Int,
) -> Result(BitArray, Error) {
  expand(suite, extract(suite, salt, ikm), info, length)
}
