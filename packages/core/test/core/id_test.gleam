import core/id.{type Id, type Queue}
import gleam/bit_array
import gleam/string
import qcheck

const property_count = 300

const property_seed = 17

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

/// Bytes and hex round trip for every sixteen-byte value, and hex is
/// lowercase, thirty-two characters, and accepted in either case.
pub fn hex_round_trip_property_test() {
  use bytes <- property(qcheck.fixed_size_byte_aligned_bit_array(id.id_bytes))

  let assert Ok(queue) = id.from_bytes(bytes)
  let queue: Id(Queue) = queue
  let hex = id.to_hex(queue)

  assert id.to_bytes(queue) == bytes
  assert id.erase(queue) == bytes
  assert string.length(hex) == 32
  assert hex == string.lowercase(hex)
  assert id.from_hex(hex) == Ok(queue)
  assert id.from_hex(string.uppercase(hex)) == Ok(queue)
}

/// Only exactly sixteen bytes make an identifier.
pub fn wrong_sizes_are_refused_test() {
  assert id.from_bytes(<<>>) == Error(Nil)
  assert id.from_bytes(<<0:120>>) == Error(Nil)
  assert id.from_bytes(<<0:136>>) == Error(Nil)
  assert id.from_bytes(<<0:128>>) != Error(Nil)
}

/// Hex of the wrong length, odd length or with non-hex characters is
/// refused.
pub fn bad_hex_is_refused_test() {
  let hex = string.repeat("a", 32)

  assert id.from_hex(hex) != Error(Nil)
  assert id.from_hex("") == Error(Nil)
  assert id.from_hex(string.repeat("a", 31)) == Error(Nil)
  assert id.from_hex(string.repeat("a", 34)) == Error(Nil)
  assert id.from_hex(string.repeat("g", 32)) == Error(Nil)
  assert id.from_hex(" " <> string.repeat("a", 31)) == Error(Nil)
}

/// The hex of a known value, to pin the format.
pub fn known_hex_test() {
  let assert Ok(queue) = id.from_bytes(<<255, 0:120>>)
  let queue: Id(Queue) = queue

  assert id.to_hex(queue) == "ff000000000000000000000000000000"
  assert bit_array.byte_size(id.to_bytes(queue)) == 16
}
