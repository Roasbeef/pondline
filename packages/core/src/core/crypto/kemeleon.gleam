//// Kemeleon: an ML-KEM-1024 encapsulation key re-encoded so that it looks
//// like uniformly random bytes, and decoded back.
////
//// OQUAKE (`core/crypto/oquake`) masks a public key with a pad derived from
//// the password. That is only safe if every guess at the password unmasks to
//// something that looks like a key: a FIPS 203 encapsulation key does not,
//// because each of its 12-bit coefficients is below 3329, so a wrong guess
//// would show itself by a coefficient of 3329 or more. Kemeleon removes that
//// tell. Each polynomial's 256 coefficients are read as the digits of one
//// integer in base 3329, and a random multiple of 3329^256 is added so that
//// the integer fills a whole number of bytes nearly uniformly. Decoding
//// reduces modulo 3329^256 and reads the digits back, which works for every
//// byte string of the right length: `decode` is total, and whatever it is
//// given it returns a well-formed encapsulation key. That totality is the
//// property the PAKE rests on, and `test/core/crypto/kemeleon_test` checks it
//// over arbitrary input.
////
//// ## Which Kemeleon
////
//// This is `Kemeleon.EncodeEk` and `DecodeEk` of `draft-irtf-cfrg-kemeleon-02`
//// §4.2, the rejection-free variant, at the width `draft-vos-cfrg-pqpake-03`
//// §4.2.1 fixes for ML-BUA-sKEM-1024: statistical distance parameter
//// `t = 132`, so each polynomial's integer is written as 391 little-endian
//// bytes (b + t = 2996 + 132 = 3128 bits). The Kemeleon draft's own default
//// is `t = 76`, 384 bytes per polynomial and big-endian by omission; where
//// the two disagree the pqpake draft is the one implemented, because its
//// test vectors are the ones this encoding must reproduce. The 32-byte seed
//// rho, already uniform, passes through untouched at the end, which is what
//// keeps the encoded key splittable (`core/crypto/bua_skem`).
////
//// ```text
//// encapsulation key  = t_1 (384) || t_2 (384) || t_3 (384) || t_4 (384) || rho (32)
//// encoded key        = r_1 (391) || r_2 (391) || r_3 (391) || r_4 (391) || rho (32)
//// r_i                = sum_j t_i[j] * 3329^j  +  m_i * 3329^256,   little-endian
//// m_i                in [0, floor((2^3128 - sum_j t_i[j] * 3329^j) / 3329^256)]
//// ```
////
//// ## Randomness
////
//// The multiples `m_i` are the encoding's randomness, and the drafts say it
//// MUST stay secret: anyone who knows them can decode a value, re-encode it
//// and see whether it comes back, which tells an encoded key from noise. So
//// `Randomness` holds its numbers inside a closure, as `core/secret` does,
//// and it is an explicit argument of `encode` so that a test can pin the
//// draft's vector values. The range of `m_i` depends on the key, so the
//// randomness is drawn first, as a 48-byte number per polynomial, and reduced
//// modulo the size of the range once the key is known. A 384-bit draw
//// reduced into a range of about 2^133 values is within 2^-251 of uniform,
//// far inside the 2^-128 per key that pqpake Appendix A.2 asks of the whole
//// encoding, and needs no loop that runs a data-dependent number of times. A
//// multiple that is already in range, as the draft's vectors are, is
//// unchanged by the reduction.
////
//// ## Not constant time
////
//// The pqpake draft calls it "crucial" that this encoding run in constant
//// time, and the Kemeleon draft (§6.3) warns that large-integer arithmetic
//// may leak through timing. This module is not constant time. It is pure
//// Gleam over the BEAM's arbitrary-precision integers, whose multiplication,
//// division and remainder take time that depends on the size of their
//// operands, and the encoded key is derived from a secret decapsulation key
//// and secret randomness. ADR-002 and ADR-016 accept that and say why: the
//// timing vantage it would need is a process on the same host, a pairing
//// code is used once, and across Tor the jitter is far above the signal. The
//// one thing chosen here to narrow it is the rejection-free encoding, so
//// that no loop repeats a data-dependent number of times. A native,
//// constant-time implementation is the remedy if review asks for one.

import core/crypto/error.{type Error, Malformed}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/result

/// ML-KEM's modulus q: every coefficient of a valid key is below it.
pub const modulus = 3329

/// The coefficients in one polynomial, n in FIPS 203.
pub const coefficients_per_polynomial = 256

/// The polynomials in an ML-KEM-1024 encapsulation key, k in FIPS 203.
pub const polynomial_count = 4

/// Kemeleon's statistical distance parameter t, as pqpake §4.2.1 fixes it
/// for ML-BUA-sKEM-1024.
pub const statistical_distance = 132

/// The bits one polynomial's integer can need before the random multiple is
/// added: b = ceil(256 * log2(3329)) in the Kemeleon draft.
pub const vector_bits = 2996

/// The bytes one encoded polynomial occupies: (b + t) / 8.
pub const encoded_polynomial_bytes = 391

/// The bytes of the seed rho that ends both encodings.
pub const seed_bytes = 32

/// The size of a FIPS 203 ML-KEM-1024 encapsulation key.
pub const encapsulation_key_bytes = 1568

/// The size of a Kemeleon-encoded ML-KEM-1024 encapsulation key at t = 132,
/// which is ML-BUA-sKEM-1024's Npk.
pub const encoded_key_bytes = 1596

/// The bytes of randomness drawn for one polynomial's multiple.
pub const draw_bytes = 48

/// The bytes of randomness one encoding consumes: one draw per polynomial.
pub const randomness_bytes = 192

/// The bytes of one polynomial in FIPS 203's ByteEncode_12 form.
const polynomial_bytes = 384

/// The secret randomness of one encoding: one non-negative number per
/// polynomial, from which that polynomial's multiple is reduced. The numbers
/// live inside a closure, so `string.inspect` and a crash report print
/// `#Fun<..>` rather than them.
pub opaque type Randomness {
  Randomness(draws: fn() -> List(Int))
}

/// Randomness from `randomness_bytes` secret bytes, read as four 48-byte
/// big-endian numbers. This is how a caller turns its CSPRNG output into
/// encoding randomness; any other length is refused.
///
/// ## Examples
///
/// ```gleam
/// kemeleon.randomness(secret.new(suite.random(kemeleon.randomness_bytes)))
/// // -> Ok(randomness)
/// ```
///
/// ```gleam
/// kemeleon.randomness(secret.new(<<1, 2, 3>>))
/// // -> Error(Malformed("kemeleon randomness"))
/// ```
pub fn randomness(bytes: Secret) -> Result(Randomness, Error) {
  // Exposed only to be split into the four draws, which go straight back
  // into a closure.
  case secret.expose(bytes) {
    <<first:size(384), second:size(384), third:size(384), fourth:size(384)>> ->
      Ok(Randomness(draws: fn() { [first, second, third, fourth] }))

    _ -> Error(Malformed("kemeleon randomness"))
  }
}

/// Randomness given as the four multiples themselves, one per polynomial in
/// key order. This is how a test pins the `kemeleon_m` values of the
/// pqpake draft's vectors: a multiple inside its polynomial's range is used
/// exactly as given. Anything but four non-negative numbers is refused.
///
/// ## Examples
///
/// ```gleam
/// kemeleon.randomness_from_multiples([1, 2, 3, 4])
/// // -> Ok(randomness)
/// ```
///
/// ```gleam
/// kemeleon.randomness_from_multiples([1, 2, 3])
/// // -> Error(Malformed("kemeleon multiples"))
/// ```
pub fn randomness_from_multiples(
  multiples: List(Int),
) -> Result(Randomness, Error) {
  case multiples {
    [first, second, third, fourth]
      if first >= 0 && second >= 0 && third >= 0 && fourth >= 0
    -> Ok(Randomness(draws: fn() { multiples }))

    _ -> Error(Malformed("kemeleon multiples"))
  }
}

/// `Kemeleon.EncodeEk`: a FIPS 203 ML-KEM-1024 encapsulation key as
/// `encoded_key_bytes` bytes that are within 2^-128 of uniform for a key
/// ML-KEM generated. The key must be `encapsulation_key_bytes` long with
/// every coefficient below `modulus`, which is FIPS 203's own modulus check;
/// anything else is refused, since it has no encoding `decode` would invert.
/// The randomness is secret, and so is the result until it is masked, so
/// see the module doc on timing.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(encoded) = kemeleon.encode(encapsulation_key, randomness)
/// kemeleon.decode(encoded)
/// // -> Ok(encapsulation_key)
/// ```
pub fn encode(
  encapsulation_key: BitArray,
  randomness: Randomness,
) -> Result(BitArray, Error) {
  use <- bool.guard(
    when: bit_array.byte_size(encapsulation_key) != encapsulation_key_bytes,
    return: Error(Malformed("ml-kem encapsulation key")),
  )

  // The draws leave their closure here and are consumed one per polynomial.
  encode_polynomials(encapsulation_key, randomness.draws(), <<>>)
}

/// Encodes the key's polynomials in order, one draw each, and appends the
/// seed once all four are written. The length was checked by `encode`, so
/// the last arm is reached only by a key whose shape the guard missed.
fn encode_polynomials(
  key: BitArray,
  draws: List(Int),
  encoded: BitArray,
) -> Result(BitArray, Error) {
  case key, draws {
    <<polynomial:bytes-size(polynomial_bytes), rest:bytes>>, [draw, ..draws] -> {
      use value <- result.try(accumulate(polynomial))
      let chunk = vector_encode(value, draw)

      encode_polynomials(rest, draws, <<encoded:bits, chunk:bits>>)
    }

    // Every polynomial is written: what remains is rho, which already looks
    // uniform and is what `bua_skem.split` will cut off again.
    <<seed:bytes-size(seed_bytes)>>, [] -> Ok(<<encoded:bits, seed:bits>>)

    _, _ -> Error(Malformed("ml-kem encapsulation key"))
  }
}

/// One polynomial's coefficients as the integer sum of `a[j] * 3329^j`,
/// refusing a coefficient that is not below the modulus. The digits are
/// read lowest first and folded highest first, which is Horner's rule.
fn accumulate(polynomial: BitArray) -> Result(Int, Error) {
  use reversed <- result.try(read_coefficients(polynomial, []))

  Ok(
    list.fold(reversed, 0, fn(value, coefficient) {
      value * modulus + coefficient
    }),
  )
}

/// FIPS 203's ByteDecode_12: every three bytes hold two 12-bit coefficients,
/// the first in the low byte and the low nibble of the middle one. The
/// result is in reverse order, highest index first, for `accumulate`.
fn read_coefficients(
  bytes: BitArray,
  reversed: List(Int),
) -> Result(List(Int), Error) {
  // Three more bytes are two more coefficients; none left is the whole
  // polynomial read, and a stray one or two bytes is not a polynomial.
  case bytes {
    <<low, middle, high, rest:bytes>> -> {
      let first = low + 256 * { middle % 16 }
      let second = middle / 16 + 16 * high

      // The modulus check: a coefficient of 3329 or more is not an ML-KEM
      // key, and it would not survive the round trip through base 3329.
      case first < modulus && second < modulus {
        True -> read_coefficients(rest, [second, first, ..reversed])
        False -> Error(Malformed("ml-kem encapsulation key"))
      }
    }

    <<>> -> Ok(reversed)

    _ -> Error(Malformed("ml-kem encapsulation key"))
  }
}

/// `VectorEncode` at t = 132: the polynomial's integer plus its multiple of
/// 3329^256, as 391 little-endian bytes. The draw is reduced into the
/// range the draft gives for the multiple, so the sum never reaches 2^3128.
fn vector_encode(value: Int, draw: Int) -> BitArray {
  let span = polynomial_span()
  let ceiling = int.bitwise_shift_left(1, vector_bits + statistical_distance)
  let range = { ceiling - value } / span + 1
  let encoded = value + draw % range * span

  <<encoded:little-size(3128)>>
}

/// `Kemeleon.DecodeEk`: the FIPS 203 encapsulation key an encoded key
/// stands for. Total over every `encoded_key_bytes`-byte string: each
/// coefficient is a remainder modulo 3329, so every one is below the
/// modulus and the result always passes FIPS 203's modulus check, whatever
/// the input. Only a wrong length is refused.
///
/// ## Examples
///
/// ```gleam
/// kemeleon.decode(<<0:size(12_768)>>)
/// // -> Ok(<<0:size(12_544)>>)
/// ```
///
/// ```gleam
/// kemeleon.decode(<<1, 2, 3>>)
/// // -> Error(Malformed("kemeleon encoded key"))
/// ```
pub fn decode(encoded: BitArray) -> Result(BitArray, Error) {
  use <- bool.guard(
    when: bit_array.byte_size(encoded) != encoded_key_bytes,
    return: Error(Malformed("kemeleon encoded key")),
  )

  decode_polynomials(encoded, polynomial_count, <<>>)
}

/// Decodes `remaining` more polynomials, then passes the seed through. The
/// length was checked by `decode`, so the last arm is unreachable for input
/// that passed the guard.
fn decode_polynomials(
  encoded: BitArray,
  remaining: Int,
  key: BitArray,
) -> Result(BitArray, Error) {
  // While polynomials remain, the next 391 bytes are one; after the last,
  // exactly the seed must remain.
  case remaining > 0, encoded {
    True, <<value:little-size(3128), rest:bytes>> -> {
      let polynomial = vector_decode(value)

      decode_polynomials(rest, remaining - 1, <<key:bits, polynomial:bits>>)
    }

    False, <<seed:bytes-size(seed_bytes)>> -> Ok(<<key:bits, seed:bits>>)

    _, _ -> Error(Malformed("kemeleon encoded key"))
  }
}

/// `VectorDecode`: the 256 base-3329 digits of the integer modulo 3329^256,
/// lowest first, written back as ByteEncode_12. Each digit is a remainder
/// modulo 3329, which is what makes decoding total. The reduction modulo
/// 3329^256 is the draft's first step and is kept to follow it, but it
/// changes nothing: the lowest 256 digits never see the multiple, or
/// anything else an arbitrary string put above 3329^256. (Removing it is
/// an equivalent mutant; mutation testing confirmed no test can tell.)
fn vector_decode(value: Int) -> BitArray {
  write_coefficients(
    value % polynomial_span(),
    coefficients_per_polynomial / 2,
    <<>>,
  )
}

/// Writes `pairs` more pairs of coefficients, peeled off `value` two base-3329
/// digits at a time, three bytes per pair.
fn write_coefficients(value: Int, pairs: Int, bytes: BitArray) -> BitArray {
  // Each step writes the next two digits; the 128th pair ends the polynomial.
  case pairs > 0 {
    True -> {
      let first = value % modulus
      let second = value / modulus % modulus
      let low = first % 256
      let middle = first / 256 + 16 * { second % 16 }
      let high = second / 16
      let rest = value / modulus / modulus

      write_coefficients(rest, pairs - 1, <<bytes:bits, low, middle, high>>)
    }

    False -> bytes
  }
}

/// 3329^256, the size of the space one polynomial's coefficients span and
/// the step between the encodings of one polynomial.
fn polynomial_span() -> Int {
  power(modulus, coefficients_per_polynomial)
}

/// `base` to the non-negative `exponent`, by squaring, in exact integers.
/// `int.power` answers in floats, which would lose all but 53 bits.
fn power(base: Int, exponent: Int) -> Int {
  // A zero exponent ends the halving.
  case exponent {
    0 -> 1
    _ -> {
      let half = power(base * base, exponent / 2)

      // An odd exponent owes one more factor of the base.
      case exponent % 2 {
        1 -> half * base
        _ -> half
      }
    }
  }
}
