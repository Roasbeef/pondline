//// A FIPS 203 reference for ML-KEM-1024's two deterministic algorithms,
//// `ML-KEM.KeyGen_internal(d, z)` (Algorithm 16) and
//// `ML-KEM.Encaps_internal(ek, m)` (Algorithm 17), in pure Gleam, for
//// tests only.
////
//// It exists because OTP's `crypto` takes neither a key-generation seed
//// nor encapsulation randomness, while the vectors of
//// `draft-vos-cfrg-pqpake-03` (ADR-016) fix both: `keygen_seed` is
//// `d || z` and `encaps_m` is `m`. With this module the tests derive the
//// draft's ML-KEM key, ciphertext and shared secret from those seeds
//// instead of taking them on trust. It is trusted only because
//// `mlkem_reference_test` holds it to NIST's ACVP keyGen and
//// encapsulation cases byte for byte, and checks that OpenSSL, through
//// `primitives`, decapsulates what it produces with the keys it produces.
////
//// This is a test reference and must never be reachable from a production
//// build. It is written for clarity, not speed, and is not constant time:
//// rejection sampling, the NTT and every encoding branch and allocate on
//// secret values. It lives under `test/`, which a release never compiles,
//// so it can no more be selected than the fake suite `docs/spec.md` §13.3
//// forbids a release to carry.
////
//// ## Flow
////
//// `derive_key_pair` cuts the draft's 64-byte seed into the two FIPS 203
//// seeds for `keygen_internal`, which runs K-PKE.KeyGen (Algorithm 13):
//// `g` over the first seed and the rank gives the matrix seed and the
//// noise seed; `generate_matrix` expands the matrix seed into the
//// NTT-domain matrix with `sample_ntt`; `sample_cbd` over `prf` draws the
//// secret and error vectors; `ntt` moves them to the NTT domain, where
//// `dot`, `multiply_ntts` and `add` make the public vector; `encode_vector` and
//// `byte_encode` serialise the keys, and `h` hashes the encapsulation key
//// into the decapsulation key. `encaps_internal` derives the shared
//// secret and the coins from `g` over the message and `h` of the key, and
//// runs K-PKE.Encrypt (Algorithm 14) through `encrypt`, which reads the
//// key back with `decode_vector`, turns the message into a polynomial
//// with `byte_decode` and `decompress`, and adds the inverse transform
//// `inverse_ntt` and `compress`.
////
//// Polynomials are lists of 256 coefficients in `[0, q)`, in coefficient
//// order or NTT order as the name says; vectors are lists of four of them.

import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import primitives/internal/ffi_sha3

/// The ML-KEM modulus.
const q = 3329

/// ML-KEM-1024's module rank.
const k = 4

/// The CBD parameter of the secret and of `y`.
const eta1 = 2

/// The CBD parameter of the encryption errors `e1` and `e2`.
const eta2 = 2

/// The bits per coefficient of the ciphertext's `u` part.
const du = 11

/// The bits per coefficient of the ciphertext's `v` part.
const dv = 5

/// `128^-1 mod q`, the scale the inverse NTT owes for its seven layers.
const inverse_of_128 = 3303

/// The ζ of FIPS 203: a primitive 256th root of unity modulo `q`.
const zeta_root = 17

/// `ML-KEM.KeyGen_internal(d, z)`: the encapsulation key and the
/// decapsulation key FIPS 203 derives from the 32-byte seeds `d` and `z`.
/// The decapsulation key is `dk_pke || ek || H(ek) || z`, the layout
/// OpenSSL stores and decapsulates with.
///
/// # Panics
///
/// When `d` or `z` is not 32 bytes: a broken test, not an input to handle.
///
/// ## Examples
///
/// ```gleam
/// let #(ek, dk) = mlkem_reference.keygen_internal(d, z)
/// #(bit_array.byte_size(ek), bit_array.byte_size(dk))
/// // -> #(1568, 3168)
/// ```
pub fn keygen_internal(d: BitArray, z: BitArray) -> #(BitArray, BitArray) {
  let assert 32 = bit_array.byte_size(d) as "d is 32 bytes"
  let assert 32 = bit_array.byte_size(z) as "z is 32 bytes"

  // FIPS 203 (final) appends the rank to `d` before G, which the draft
  // standard did not; this byte is the domain separation between
  // parameter sets that share a seed.
  let #(rho, sigma) = g(<<d:bits, k>>)
  let matrix = generate_matrix(rho)

  // The secret draws PRF counters 0 to k - 1 and the error k to 2k - 1,
  // in that order, from the same `sigma`.
  let secret =
    list.map(counters(0, k), fn(n) { sample_cbd(eta1, prf(eta1, sigma, n)) })
  let error =
    list.map(counters(k, k), fn(n) { sample_cbd(eta1, prf(eta1, sigma, n)) })
  let secret_hat = list.map(secret, ntt)
  let error_hat = list.map(error, ntt)

  // Row `i` of the matrix against the secret: `t_hat[i] = Σ_j A[i][j] ∘
  // s_hat[j] + e_hat[i]`, all in the NTT domain.
  let t_hat =
    list.map2(matrix, error_hat, fn(row, noise) {
      add(dot(row, secret_hat), noise)
    })

  let ek = <<encode_vector(12, t_hat):bits, rho:bits>>
  let dk = <<
    encode_vector(12, secret_hat):bits,
    ek:bits,
    h(ek):bits,
    z:bits,
  >>
  #(ek, dk)
}

/// `KEM.DeriveKeyPair(seed)` for ML-KEM as `draft-vos-cfrg-pqpake-03`
/// §4.1 and the head of its Appendix E define it: `KeyGen_internal(seed[0:32],
/// seed[32:64])`, so the vectors' 64-byte `keygen_seed` is `d || z`. The
/// draft forbids the HPKE-style derivation that hashes the seed first.
///
/// # Panics
///
/// When `seed` is not 64 bytes: a broken fixture.
///
/// ## Examples
///
/// ```gleam
/// mlkem_reference.derive_key_pair(vectors.hex(v, "keygen_seed"))
/// // -> #(ek, dk)
/// ```
pub fn derive_key_pair(seed: BitArray) -> #(BitArray, BitArray) {
  let assert <<d:bytes-size(32), z:bytes-size(32)>> = seed
    as "a keygen seed is d || z, 64 bytes"
  keygen_internal(d, z)
}

/// `ML-KEM.Encaps_internal(ek, m)`: the shared secret `K` and ciphertext
/// FIPS 203 derives from the encapsulation key and the 32-byte message
/// `m`. `K` and the encryption coins come from `G(m || H(ek))`, so the key
/// is bound into both.
///
/// # Panics
///
/// When `ek` is not 1568 bytes or `m` not 32: a broken test.
///
/// ## Examples
///
/// ```gleam
/// let #(shared_secret, ciphertext) = mlkem_reference.encaps_internal(ek, m)
/// #(bit_array.byte_size(shared_secret), bit_array.byte_size(ciphertext))
/// // -> #(32, 1568)
/// ```
pub fn encaps_internal(ek: BitArray, m: BitArray) -> #(BitArray, BitArray) {
  let assert 32 = bit_array.byte_size(m) as "m is 32 bytes"
  let #(shared_secret, coins) = g(<<m:bits, h(ek):bits>>)

  #(shared_secret, encrypt(ek, m, coins))
}

/// K-PKE.Encrypt (Algorithm 14): the ciphertext `c1 || c2` of the 32-byte
/// message `m` under `ek`, with all randomness drawn from `coins` by the
/// PRF.
fn encrypt(ek: BitArray, m: BitArray, coins: BitArray) -> BitArray {
  let assert <<t_bytes:bytes-size(1536), rho:bytes-size(32)>> = ek
    as "ek is 1568 bytes"
  let t_hat = decode_vector(12, t_bytes)
  let matrix = generate_matrix(rho)

  // PRF counters run 0 to k - 1 for `y`, k to 2k - 1 for `e1`, and 2k for
  // `e2`; `y` takes eta1 and both errors eta2.
  let y =
    list.map(counters(0, k), fn(n) { sample_cbd(eta1, prf(eta1, coins, n)) })
  let e1 =
    list.map(counters(k, k), fn(n) { sample_cbd(eta2, prf(eta2, coins, n)) })
  let e2 = sample_cbd(eta2, prf(eta2, coins, 2 * k))
  let y_hat = list.map(y, ntt)

  // `u` multiplies by the transpose: entry `i` takes column `i` of the
  // matrix, `Σ_j A[j][i] ∘ y_hat[j]`.
  let u =
    list.map2(list.transpose(matrix), e1, fn(column, noise) {
      add(inverse_ntt(dot(column, y_hat)), noise)
    })

  // The message rides in `v` as `Decompress_1` of its bits, each 0 or
  // round(q / 2).
  let mu = list.map(byte_decode(1, m), fn(bit) { decompress(1, bit) })
  let v = add(add(inverse_ntt(dot(t_hat, y_hat)), e2), mu)

  let c1 =
    u
    |> list.map(fn(poly) { byte_encode(du, list.map(poly, compress(du, _))) })
    |> bit_array.concat
  let c2 = byte_encode(dv, list.map(v, compress(dv, _)))
  <<c1:bits, c2:bits>>
}

// ------------------------------------------------------------ hashing

/// `G` is SHA3-512, split into its two 32-byte halves.
fn g(data: BitArray) -> #(BitArray, BitArray) {
  let assert <<first:bytes-size(32), second:bytes-size(32)>> =
    ffi_sha3.sha3_512(data)
    as "SHA3-512 gives 64 bytes"
  #(first, second)
}

/// `H` is SHA3-256.
fn h(data: BitArray) -> BitArray {
  ffi_sha3.sha3_256(data)
}

/// `PRF_eta(s, n)` is SHAKE256 over `s || n`, `64 * eta` bytes of it.
fn prf(eta: Int, seed: BitArray, counter: Int) -> BitArray {
  ffi_sha3.shake256(<<seed:bits, counter>>, 64 * eta)
}

/// The `count` PRF counters from `first`, in order.
fn counters(first: Int, count: Int) -> List(Int) {
  list.index_map(list.repeat(Nil, count), fn(_, index) { first + index })
}

// ----------------------------------------------------------- sampling

/// The NTT-domain matrix `A`, as rows: `A[i][j] = SampleNTT(rho || j || i)`,
/// column index first in the seed, as Algorithm 13 writes it.
fn generate_matrix(rho: BitArray) -> List(List(List(Int))) {
  list.map(counters(0, k), fn(i) {
    list.map(counters(0, k), fn(j) { sample_ntt(<<rho:bits, j, i>>) })
  })
}

/// `SampleNTT` (Algorithm 7): 256 coefficients below `q` read by rejection
/// from SHAKE128 over the 34-byte seed. Five SHAKE128 blocks (840 bytes)
/// almost always suffice; when they do not, the stream is asked for again
/// at twice the length, and since a longer SHAKE output starts with the
/// shorter one the result is the same as reading an endless stream.
fn sample_ntt(seed: BitArray) -> List(Int) {
  sample_ntt_reading(seed, 840)
}

/// One attempt at `SampleNTT` over `length` bytes of the stream.
fn sample_ntt_reading(seed: BitArray, length: Int) -> List(Int) {
  case take_uniform(ffi_sha3.shake128(seed, length), [], 0) {
    Ok(coefficients) -> coefficients

    // The stream ran out before 256 coefficients were accepted.
    Error(Nil) -> sample_ntt_reading(seed, length * 2)
  }
}

/// The rejection loop of `SampleNTT`: each three bytes give two 12-bit
/// candidates, and each below `q` is kept while fewer than 256 are held.
/// `Error(Nil)` means the stream ended first.
fn take_uniform(
  stream: BitArray,
  accepted: List(Int),
  count: Int,
) -> Result(List(Int), Nil) {
  use <- bool.lazy_guard(when: count == 256, return: fn() {
    Ok(list.reverse(accepted))
  })

  // Three more bytes are two more candidates; fewer than three is the end
  // of what was requested, and the caller asks for a longer stream.
  case stream {
    <<c0, c1, c2, rest:bytes>> -> {
      let d1 = c0 + 256 * { c1 % 16 }
      let d2 = c1 / 16 + 16 * c2
      let #(accepted, count) = accept(accepted, count, d1)
      let #(accepted, count) = accept(accepted, count, d2)
      take_uniform(rest, accepted, count)
    }

    _ -> Error(Nil)
  }
}

/// Keeps one candidate if it is below `q` and the polynomial is not full.
fn accept(
  accepted: List(Int),
  count: Int,
  candidate: Int,
) -> #(List(Int), Int) {
  case candidate < q && count < 256 {
    True -> #([candidate, ..accepted], count + 1)
    False -> #(accepted, count)
  }
}

/// `SamplePolyCBD_eta` (Algorithm 8): each coefficient is the sum of
/// `eta` bits minus the sum of the next `eta`, the bits read
/// least-significant first within each byte.
fn sample_cbd(eta: Int, bytes: BitArray) -> List(Int) {
  bytes
  |> bits_lsb_first
  |> list.sized_chunk(2 * eta)
  |> list.map(fn(chunk) {
    let #(x, y) = list.split(chunk, eta)
    reduce(int.sum(x) - int.sum(y))
  })
}

/// Every bit of `bytes`, least-significant bit of each byte first, which
/// is FIPS 203's `BytesToBits` order.
fn bits_lsb_first(bytes: BitArray) -> List(Int) {
  // One byte at a time until none is left; the inputs are whole bytes.
  case bytes {
    <<byte, rest:bytes>> -> {
      let bits =
        list.map(counters(0, 8), fn(i) { { byte / power_of_two(i) } % 2 })
      list.append(bits, bits_lsb_first(rest))
    }

    _ -> []
  }
}

// ---------------------------------------------------- the transform

/// `ζ^BitRev7(i) mod q`, entry `i` of the NTT's zeta table.
fn zeta(index: Int) -> Int {
  power_mod(zeta_root, bit_reverse_7(index))
}

/// `NTT` (Algorithm 9). Each of the seven layers halves the butterfly
/// span `len` from 128 to 2; the polynomial is cut into blocks of `2 *
/// len`, and block `c` of layer `i` uses zeta `2^i + c`, which is the
/// running counter `i` of the algorithm read off by position.
fn ntt(poly: List(Int)) -> List(Int) {
  list.fold(counters(0, 7), poly, fn(f, layer) {
    let span = 128 / power_of_two(layer)

    f
    |> list.sized_chunk(2 * span)
    |> list.index_map(fn(block, c) {
      let #(low, high) = list.split(block, span)
      let z = zeta(power_of_two(layer) + c)
      let t = list.map(high, fn(x) { reduce(z * x) })
      list.append(
        list.map2(low, t, fn(a, b) { reduce(a + b) }),
        list.map2(low, t, fn(a, b) { reduce(a - b) }),
      )
    })
    |> list.flatten
  })
}

/// `NTT^-1` (Algorithm 10): the layers in reverse, span 2 up to 128, the
/// zeta counter running down from 127, so block `c` of a layer with `n`
/// blocks uses zeta `2n - 1 - c`; then every coefficient times `128^-1`.
fn inverse_ntt(poly: List(Int)) -> List(Int) {
  list.fold(counters(1, 7), poly, fn(f, layer) {
    let span = power_of_two(layer)
    let blocks = 128 / span

    f
    |> list.sized_chunk(2 * span)
    |> list.index_map(fn(block, c) {
      let #(low, high) = list.split(block, span)
      let z = zeta(2 * blocks - 1 - c)
      list.append(
        list.map2(low, high, fn(a, b) { reduce(a + b) }),
        list.map2(low, high, fn(a, b) { reduce(z * { b - a }) }),
      )
    })
    |> list.flatten
  })
  |> list.map(fn(x) { reduce(x * inverse_of_128) })
}

/// `MultiplyNTTs` (Algorithms 11 and 12): 128 products of degree-one
/// polynomials modulo `X^2 - γ_i`, with `γ_i = ζ^(2·BitRev7(i) + 1)`.
fn multiply_ntts(f: List(Int), g: List(Int)) -> List(Int) {
  list.map2(list.sized_chunk(f, 2), list.sized_chunk(g, 2), fn(a, b) { #(a, b) })
  |> list.index_map(fn(pair, i) {
    let assert #([a0, a1], [b0, b1]) = pair as "coefficient pairs"
    let gamma = power_mod(zeta_root, 2 * bit_reverse_7(i) + 1)
    [reduce(a0 * b0 + a1 * b1 * gamma), reduce(a0 * b1 + a1 * b0)]
  })
  |> list.flatten
}

/// The NTT-domain inner product `Σ_j left[j] ∘ right[j]`.
fn dot(left: List(List(Int)), right: List(List(Int))) -> List(Int) {
  let assert [first, ..rest] = list.map2(left, right, multiply_ntts)
    as "a vector of rank k"
  list.fold(rest, first, add)
}

/// Coefficient-wise sum modulo `q`.
fn add(left: List(Int), right: List(Int)) -> List(Int) {
  list.map2(left, right, fn(a, b) { reduce(a + b) })
}

// --------------------------------------------------------- encodings

/// `ByteEncode_d` (Algorithm 5): 256 `d`-bit integers packed little-endian,
/// coefficient 0 in the lowest bits, into `32 * d` bytes. The packing is
/// one big integer, which is the definition read as arithmetic.
fn byte_encode(d: Int, poly: List(Int)) -> BitArray {
  let width = power_of_two(d)
  let value = list.fold_right(poly, 0, fn(acc, x) { acc * width + x })
  let bits = 256 * d
  <<value:little-size(bits)>>
}

/// `ByteDecode_d` (Algorithm 6), the inverse of `byte_encode`; for
/// `d = 12` each coefficient is taken modulo `q`, as FIPS 203 says.
fn byte_decode(d: Int, bytes: BitArray) -> List(Int) {
  let bits = 256 * d
  let assert <<value:little-size(bits)>> = bytes as "32 * d bytes"
  let width = power_of_two(d)

  // Only the 12-bit decoding reduces: a 12-bit field can hold values from
  // `q` to 4095, which FIPS 203 maps back into the field. Narrower fields
  // are compressed values and are taken as they are.
  let modulus = case d {
    12 -> q
    _ -> width
  }

  list.map(counters(0, 256), fn(i) {
    { value / power_of_two(d * i) } % width % modulus
  })
}

/// The `k` polynomials of a vector, each `byte_encode`d, concatenated.
fn encode_vector(d: Int, vector: List(List(Int))) -> BitArray {
  bit_array.concat(list.map(vector, byte_encode(d, _)))
}

/// The inverse of `encode_vector` for `k` polynomials of `32 * d` bytes.
fn decode_vector(d: Int, bytes: BitArray) -> List(List(Int)) {
  list.map(counters(0, k), fn(i) {
    let assert Ok(slice) = bit_array.slice(bytes, i * 32 * d, 32 * d)
      as "the vector holds k polynomials"
    byte_decode(d, slice)
  })
}

/// `Compress_d(x) = round(2^d / q · x) mod 2^d`, rounding half up, in
/// integers: `floor((2^(d+1) · x + q) / 2q)`.
fn compress(d: Int, x: Int) -> Int {
  { power_of_two(d + 1) * x + q } / { 2 * q } % power_of_two(d)
}

/// `Decompress_d(y) = round(q / 2^d · y)`, rounding half up.
fn decompress(d: Int, y: Int) -> Int {
  { 2 * q * y + power_of_two(d) } / power_of_two(d + 1)
}

// ------------------------------------------------------- arithmetic

/// `x mod q` in `[0, q)`; Gleam's `%` keeps the dividend's sign.
fn reduce(x: Int) -> Int {
  let r = x % q

  // A negative remainder is lifted into the field.
  case r < 0 {
    True -> r + q
    False -> r
  }
}

/// `base^exponent mod q`.
fn power_mod(base: Int, exponent: Int) -> Int {
  list.fold(list.repeat(base, exponent), 1, fn(acc, b) { reduce(acc * b) })
}

/// `2^n`.
fn power_of_two(n: Int) -> Int {
  int.bitwise_shift_left(1, n)
}

/// The seven-bit reversal `BitRev7`.
fn bit_reverse_7(index: Int) -> Int {
  list.fold(counters(0, 7), 0, fn(acc, bit) {
    acc * 2 + { index / power_of_two(bit) } % 2
  })
}
