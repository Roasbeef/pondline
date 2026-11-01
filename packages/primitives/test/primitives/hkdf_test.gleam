//// RFC 5869 appendix A test cases 1 to 3 (SHA-256), run through
//// `core/crypto/hkdf` over the real HMAC.

import core/crypto/hkdf
import gleam/bit_array
import gleam/result
import gleam/string
import primitives/suite

fn hex(text: String) -> BitArray {
  let assert Ok(bytes) =
    text
    |> string.replace(" ", "")
    |> string.uppercase
    |> bit_array.base16_decode
    as "test vectors are well-formed hex"
  bytes
}

pub fn rfc5869_case_1_test() {
  let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let salt = hex("000102030405060708090a0b0c")
  let info = hex("f0f1f2f3f4f5f6f7f8f9")

  assert hkdf.extract(suite.suite(), salt, ikm)
    == hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")

  assert hkdf.expand(
      suite.suite(),
      hkdf.extract(suite.suite(), salt, ikm),
      info,
      42,
    )
    == Ok(hex(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    ))
}

pub fn rfc5869_case_2_test() {
  let ikm =
    hex(
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    )
  let salt =
    hex(
      "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    )
  let info =
    hex(
      "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    )

  assert hkdf.extract(suite.suite(), salt, ikm)
    == hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")

  assert hkdf.extract_expand(suite.suite(), salt, ikm, info, 82)
    == Ok(hex(
      "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    ))
}

pub fn rfc5869_case_3_test() {
  let ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")

  assert hkdf.extract(suite.suite(), <<>>, ikm)
    == hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")

  assert hkdf.extract_expand(suite.suite(), <<>>, ikm, <<>>, 42)
    == Ok(hex(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    ))
}

pub fn expand_refuses_out_of_range_lengths_test() {
  let expand = hkdf.expand(suite.suite(), <<0:256>>, <<>>, _)

  assert result.is_error(expand(hkdf.max_output_bytes + 1))
  assert result.is_error(expand(-1))
  assert result.map(expand(hkdf.max_output_bytes), bit_array.byte_size)
    == Ok(hkdf.max_output_bytes)
}
