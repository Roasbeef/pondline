//// SHA3-256, SHA3-512, SHAKE128 and SHAKE256 for the test-only ML-KEM
//// reference (`primitives/mlkem_reference`), taken straight from OTP's
//// `crypto`.
////
//// FIPS 203 builds every one of its hash steps from these four Keccak
//// instances, and the `primitives` API has none of them: the production
//// code never needs SHA-3, so adding them to `src/` would grow the audited
//// surface for the sake of a test. Writing Keccak in Gleam would add a
//// second unverified primitive under the one being verified. So these are
//// direct `@external`s to `crypto:hash/2` and `crypto:hash_xof/3`, as
//// `core`'s test support reaches `erlang` and `counters` directly. The
//// confinement rule binds `src/`, but the module is still named and
//// placed as an `internal/ffi_*` module, so the externals stay in one
//// place a reader can find; it lives under `test/` and is never compiled
//// into a release.
////
//// `crypto` names its hash algorithms by atom, and `sha3_256` is not a
//// name a Gleam constructor can spell, so each algorithm is made from a
//// constant string here. The four strings are fixed in this file; no
//// input ever becomes an atom.

/// An algorithm atom as `crypto` names it, opaque to Gleam.
type Algorithm

@external(erlang, "erlang", "binary_to_atom")
fn algorithm(name: String) -> Algorithm

@external(erlang, "crypto", "hash")
fn hash(algorithm: Algorithm, data: BitArray) -> BitArray

/// `crypto:hash_xof/3` takes the output length in bits, not bytes.
@external(erlang, "crypto", "hash_xof")
fn hash_xof(algorithm: Algorithm, data: BitArray, bits: Int) -> BitArray

/// SHA3-256, FIPS 202: ML-KEM's `H`.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(ffi_sha3.sha3_256(<<>>))
/// // -> 32
/// ```
pub fn sha3_256(data: BitArray) -> BitArray {
  hash(algorithm("sha3_256"), data)
}

/// SHA3-512, FIPS 202: ML-KEM's `G`.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(ffi_sha3.sha3_512(<<>>))
/// // -> 64
/// ```
pub fn sha3_512(data: BitArray) -> BitArray {
  hash(algorithm("sha3_512"), data)
}

/// The first `bytes` bytes of SHAKE128 over `data`: ML-KEM's XOF.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(ffi_sha3.shake128(<<>>, 840))
/// // -> 840
/// ```
pub fn shake128(data: BitArray, bytes: Int) -> BitArray {
  hash_xof(algorithm("shake128"), data, bytes * 8)
}

/// The first `bytes` bytes of SHAKE256 over `data`: ML-KEM's `PRF` and `J`.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(ffi_sha3.shake256(<<>>, 128))
/// // -> 128
/// ```
pub fn shake256(data: BitArray, bytes: Int) -> BitArray {
  hash_xof(algorithm("shake256"), data, bytes * 8)
}
