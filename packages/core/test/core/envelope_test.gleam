import core/envelope
import core/limits
import gleam/bit_array
import gleam/list
import qcheck

const property_count = 100

const property_seed = 13

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

// Ciphertext sizes up to the largest bucket's capacity, with the sizes
// around each bucket edge weighted in.
fn sealed_sizes() -> qcheck.Generator(Int) {
  let top = limits.max_ciphertext_bytes - 4

  qcheck.from_generators(qcheck.bounded_int(0, top), [
    qcheck.bounded_int(0, 64),
    qcheck.bounded_int(4080, 4100),
    qcheck.bounded_int(16_370, 16_390),
    qcheck.bounded_int(65_520, 65_540),
    qcheck.bounded_int(top - 4, top),
  ])
}

// A ciphertext of `size` bytes, all `fill`. Contents are uniform so that
// building a quarter-megabyte value is cheap; the codec never inspects
// them.
fn sealed(size: Int, fill: Int) -> BitArray {
  let assert Ok(bits) = bit_array.slice(buffer(fill), 0, size)
  bits
}

// One mebibyte of `fill`, larger than any size the tests ask for.
fn buffer(fill: Int) -> BitArray {
  double(<<fill, fill, fill, fill>>, 18)
}

fn double(bits: BitArray, times: Int) -> BitArray {
  case times {
    0 -> bits
    _ -> double(<<bits:bits, bits:bits>>, times - 1)
  }
}

/// Padding then unpadding returns the ciphertext, and the padded size is
/// the smallest bucket that holds the ciphertext and its length prefix.
pub fn pad_unpad_round_trip_property_test() {
  use #(size, fill) <- property(qcheck.tuple2(
    sealed_sizes(),
    qcheck.bounded_int(0, 255),
  ))

  let ciphertext = sealed(size, fill)
  let assert Ok(padded) = envelope.pad(ciphertext)
  let wire = envelope.to_wire(padded)

  assert envelope.unpad(padded) == Ok(ciphertext)
  assert envelope.from_wire(wire) == Ok(padded)
  assert limits.padded_size(size + 4) == Ok(bit_array.byte_size(wire))
}

/// A ciphertext exactly one bucket long, with its prefix, moves up.
pub fn pad_picks_the_smallest_bucket_test() {
  let size_of = fn(size) {
    let assert Ok(padded) = envelope.pad(sealed(size, 1))
    bit_array.byte_size(envelope.to_wire(padded))
  }

  assert size_of(0) == 4096
  assert size_of(4092) == 4096
  assert size_of(4093) == 16_384
  assert size_of(16_380) == 16_384
  assert size_of(16_381) == 65_536
  assert size_of(65_532) == 65_536
  assert size_of(65_533) == 262_144
  assert size_of(262_140) == 262_144
}

/// A ciphertext that cannot fit the largest bucket with its prefix is
/// refused.
pub fn oversize_ciphertext_is_refused_test() {
  assert envelope.pad(sealed(262_141, 1)) == Error(Nil)
  assert envelope.pad(sealed(300_000, 1)) == Error(Nil)
}

/// `from_wire` accepts exactly the bucket sizes.
pub fn from_wire_accepts_only_bucket_sizes_test() {
  list.each(limits.padding_buckets, fn(size) {
    assert envelope.from_wire(sealed(size, 0)) != Error(Nil)
    assert envelope.from_wire(sealed(size - 1, 0)) == Error(Nil)
    assert envelope.from_wire(sealed(size + 1, 0)) == Error(Nil)
  })

  assert envelope.from_wire(<<>>) == Error(Nil)
}

/// A length prefix pointing past the end is refused by `unpad`, rather
/// than returning a short slice.
pub fn unpad_rejects_a_lying_length_test() {
  let lying = <<0xffff_ffff:size(32), 0:size(32_736)>>
  let assert Ok(padded) = envelope.from_wire(lying)

  assert envelope.unpad(padded) == Error(Nil)
}
