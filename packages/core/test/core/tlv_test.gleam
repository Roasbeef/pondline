import core/tlv
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import qcheck

const property_count = 500

const property_seed = 11

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

const max_u64 = 0xffff_ffff_ffff_ffff

// Integers across every BigSize width, weighted toward the boundaries.
fn big_size_values() -> qcheck.Generator(Int) {
  qcheck.from_generators(qcheck.bounded_int(0, 300), [
    qcheck.bounded_int(0xf0, 0x110),
    qcheck.bounded_int(0xfff0, 0x1_0010),
    qcheck.bounded_int(0xffff_fff0, 0x1_0000_0010),
    qcheck.bounded_int(0, 70_000),
    qcheck.bounded_int(0, 5_000_000_000),
    qcheck.bounded_int(max_u64 - 16, max_u64),
  ])
}

fn value_bytes() -> qcheck.Generator(BitArray) {
  qcheck.generic_byte_aligned_bit_array(
    values_from: qcheck.bounded_int(0, 255),
    byte_size_from: qcheck.from_generators(qcheck.bounded_int(0, 12), [
      qcheck.bounded_int(250, 260),
    ]),
  )
}

// Records with strictly increasing types, built from gaps so the stream is
// always legal. Both one-byte and wider type numbers occur.
fn record_lists() -> qcheck.Generator(List(#(Int, BitArray))) {
  let gap =
    qcheck.from_generators(qcheck.bounded_int(1, 5), [
      qcheck.bounded_int(1, 300),
      qcheck.bounded_int(1, 70_000),
    ])

  qcheck.generic_list(
    elements_from: qcheck.tuple2(gap, value_bytes()),
    length_from: qcheck.bounded_int(0, 6),
  )
  |> qcheck.map(fn(pairs) {
    list.map_fold(pairs, -1, fn(previous, pair) {
      let tag = previous + pair.0
      #(tag, #(tag, pair.1))
    }).1
  })
}

fn build(records: List(#(Int, BitArray))) -> BitArray {
  list.fold(records, tlv.new(), fn(builder, record) {
    tlv.put(builder, record.0, record.1)
  })
  |> tlv.encode
}

fn parse(bytes: BitArray) -> Result(tlv.Stream, tlv.TlvError) {
  tlv.parse(bytes, max_bytes: 1_000_000)
}

// ---------------------------------------------------------------- BigSize

/// The BOLT #1 BigSize test vectors, in both directions.
pub fn big_size_vectors_test() {
  let vectors = [
    #(0, <<0x00>>),
    #(252, <<0xfc>>),
    #(253, <<0xfd, 0x00, 0xfd>>),
    #(65_535, <<0xfd, 0xff, 0xff>>),
    #(65_536, <<0xfe, 0x00, 0x01, 0x00, 0x00>>),
    #(4_294_967_295, <<0xfe, 0xff, 0xff, 0xff, 0xff>>),
    #(4_294_967_296, <<0xff, 0, 0, 0, 1, 0, 0, 0, 0>>),
    #(max_u64, <<0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff>>),
  ]

  list.each(vectors, fn(vector) {
    assert tlv.encode_big_size(vector.0) == vector.1
    assert tlv.decode_big_size(<<vector.1:bits, 99>>) == Ok(#(vector.0, <<99>>))
  })
}

/// Every BigSize round trips and uses the minimal width for its range.
pub fn big_size_round_trip_property_test() {
  use value <- property(big_size_values())

  let encoded = tlv.encode_big_size(value)
  assert tlv.decode_big_size(encoded) == Ok(#(value, <<>>))

  let width = bit_array.byte_size(encoded)
  assert width
    == case value {
      _ if value < 0xfd -> 1
      _ if value <= 0xffff -> 3
      _ if value <= 0xffff_ffff -> 5
      _ -> 9
    }
}

/// A value written in a wider form than it needs is rejected, including at
/// each boundary where the narrower form just stops fitting.
pub fn non_minimal_big_size_is_rejected_test() {
  let rejected = [
    <<0xfd, 0x00, 0x00>>,
    <<0xfd, 0x00, 0xfc>>,
    <<0xfe, 0x00, 0x00, 0x00, 0x00>>,
    <<0xfe, 0x00, 0x00, 0xff, 0xff>>,
    <<0xff, 0, 0, 0, 0, 0, 0, 0, 0>>,
    <<0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff>>,
  ]

  list.each(rejected, fn(bits) {
    assert tlv.decode_big_size(bits) == Error(tlv.NonMinimalBigSize)
  })
}

/// Every non-minimal widening of any value is rejected.
pub fn non_minimal_widening_property_test() {
  use value <- property(qcheck.bounded_int(0, 0xfc))

  assert tlv.decode_big_size(<<0xfd, value:size(16)>>)
    == Error(tlv.NonMinimalBigSize)
  assert tlv.decode_big_size(<<0xfe, value:size(32)>>)
    == Error(tlv.NonMinimalBigSize)
  assert tlv.decode_big_size(<<0xff, value:size(64)>>)
    == Error(tlv.NonMinimalBigSize)
}

/// A BigSize cut short is truncated, never a wrong number.
pub fn truncated_big_size_is_rejected_test() {
  let rejected = [
    <<>>,
    <<0xfd>>,
    <<0xfd, 0x01>>,
    <<0xfe, 0, 1, 0>>,
    <<0xff, 0, 0, 0, 1, 0, 0, 0>>,
  ]

  list.each(rejected, fn(bits) {
    assert tlv.decode_big_size(bits) == Error(tlv.Truncated)
  })
}

// ---------------------------------------------------------------- streams

/// The canonical property: whatever `parse` accepts, `encode_stream`
/// reproduces byte for byte, and the records are the ones put in.
pub fn canonical_round_trip_property_test() {
  use records <- property(record_lists())

  let bytes = build(records)
  let assert Ok(stream) = parse(bytes)

  assert tlv.records(stream) == records
  assert tlv.encode_stream(stream) == bytes
}

/// The totality property: random bytes, truncations and single-byte
/// changes of valid streams never crash, and whatever is accepted
/// re-encodes to the same bytes.
pub fn parse_is_total_and_canonical_property_test() {
  use #(records, noise, position, replacement) <- property(qcheck.tuple4(
    record_lists(),
    qcheck.bit_array(),
    qcheck.bounded_int(0, 400),
    qcheck.bounded_int(0, 255),
  ))

  let valid = build(records)
  let size = bit_array.byte_size(valid)
  let cut = int.min(position, size)
  let assert Ok(truncated) = bit_array.slice(valid, 0, cut)
  let flipped = case bit_array.slice(valid, 0, int.min(position, size)) {
    Ok(head) ->
      case bit_array.slice(valid, cut + 1, int.max(size - cut - 1, 0)) {
        Ok(tail) -> <<head:bits, replacement:size(8), tail:bits>>
        Error(Nil) -> valid
      }
    Error(Nil) -> valid
  }

  list.each([noise, truncated, flipped], fn(candidate) {
    case parse(candidate) {
      Ok(stream) -> {
        assert tlv.encode_stream(stream) == candidate
      }
      Error(_) -> Nil
    }
  })
}

/// Types must strictly increase: equal or smaller types are refused.
pub fn out_of_order_and_duplicate_types_are_rejected_test() {
  assert parse(<<2, 0, 1, 0>>) == Error(tlv.OutOfOrder(1))
  assert parse(<<2, 0, 2, 0>>) == Error(tlv.OutOfOrder(2))
  assert parse(<<0, 0, 0, 0>>) == Error(tlv.OutOfOrder(0))
  assert parse(<<1, 0, 2, 0>>) |> result_is_ok
}

fn result_is_ok(result: Result(a, b)) -> Bool {
  case result {
    Ok(_) -> True
    Error(_) -> False
  }
}

/// A length that runs past the end is refused, including a huge u64.
pub fn length_past_the_end_is_rejected_test() {
  assert parse(<<1, 2, 9>>) == Error(tlv.Truncated)
  assert parse(<<1, 0xfd, 0x01, 0x00>>) == Error(tlv.Truncated)
  assert parse(<<1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff>>)
    == Error(tlv.Truncated)
  assert parse(<<1>>) == Error(tlv.Truncated)
}

/// A non-minimal type or length inside a stream is refused.
pub fn non_minimal_stream_fields_are_rejected_test() {
  assert parse(<<0xfd, 0x00, 0x01, 0>>) == Error(tlv.NonMinimalBigSize)
  assert parse(<<1, 0xfd, 0x00, 0x01, 9>>) == Error(tlv.NonMinimalBigSize)
}

/// Input over the caller's limit is refused before it is read.
pub fn oversize_input_is_rejected_test() {
  assert tlv.parse(<<1, 1, 9>>, max_bytes: 3) |> result_is_ok
  assert tlv.parse(<<1, 1, 9>>, max_bytes: 2) == Error(tlv.InputTooLarge)
}

/// Input that is not a whole number of bytes is truncated.
pub fn unaligned_input_is_rejected_test() {
  assert parse(<<1:size(4)>>) == Error(tlv.Truncated)
  assert parse(<<1, 0, 1:size(3)>>) == Error(tlv.Truncated)
}

// ---------------------------------------------------------------- decoders

/// An unknown odd type is skipped and cannot be read as any known field;
/// an unknown even type fails closed, wherever it sits.
pub fn unknown_odd_is_skipped_and_unknown_even_rejected_test() {
  let decoder = {
    use n <- tlv.required(2, tlv.u8)
    use extra <- tlv.optional(7, tlv.u8)
    tlv.success(#(n, extra))
  }

  assert tlv.decode(<<2, 1, 9, 5, 2, 1, 1>>, max_bytes: 64, with: decoder)
    == Ok(#(9, None))
  assert tlv.decode(<<2, 1, 9, 7, 1, 4>>, max_bytes: 64, with: decoder)
    == Ok(#(9, Some(4)))
  assert tlv.decode(<<2, 1, 9, 4, 0>>, max_bytes: 64, with: decoder)
    == Error(tlv.UnknownRequired(4))
  assert tlv.decode(<<0, 0, 2, 1, 9>>, max_bytes: 64, with: decoder)
    == Error(tlv.UnknownRequired(0))
  assert tlv.decode(<<2, 1, 9, 6, 0, 8, 0>>, max_bytes: 64, with: decoder)
    == Error(tlv.UnknownRequired(6))
}

/// A required type that is absent, and a field of the wrong size, are
/// errors that name the type and nothing else.
pub fn missing_and_invalid_fields_are_rejected_test() {
  let decoder = {
    use n <- tlv.required(2, tlv.u16)
    tlv.success(n)
  }

  assert tlv.decode(<<>>, max_bytes: 64, with: decoder)
    == Error(tlv.MissingRequired(2))
  assert tlv.decode(<<2, 1, 9>>, max_bytes: 64, with: decoder)
    == Error(tlv.InvalidField(2))
  assert tlv.decode(<<2, 2, 1, 0>>, max_bytes: 64, with: decoder) == Ok(256)
}

/// Each fixed-width integer reads exactly its width, big-endian.
pub fn integer_fields_test() {
  assert tlv.u8(<<7>>) == Ok(7)
  assert tlv.u8(<<>>) == Error(tlv.InvalidValue)
  assert tlv.u16(<<1, 2>>) == Ok(258)
  assert tlv.u16(<<1>>) == Error(tlv.InvalidValue)
  assert tlv.u32(<<1, 2, 3, 4>>) == Ok(16_909_060)
  assert tlv.u32(<<1, 2, 3>>) == Error(tlv.InvalidValue)
  assert tlv.u64(<<0, 0, 0, 0, 0, 0, 1, 0>>) == Ok(256)
  assert tlv.u64(<<0xff:size(64)>>) == Ok(255)
  assert tlv.u64(<<1, 2, 3, 4, 5, 6, 7>>) == Error(tlv.InvalidValue)
}

/// Integer encoders round trip across the width and clamp outside it
/// instead of wrapping.
pub fn integer_encoders_round_trip_and_clamp_test() {
  assert tlv.u8(tlv.encode_u8(200)) == Ok(200)
  assert tlv.u16(tlv.encode_u16(65_535)) == Ok(65_535)
  assert tlv.u32(tlv.encode_u32(4_294_967_295)) == Ok(4_294_967_295)
  assert tlv.u64(tlv.encode_u64(max_u64)) == Ok(max_u64)
  assert tlv.u8(tlv.encode_u8(256)) == Ok(255)
  assert tlv.u8(tlv.encode_u8(-1)) == Ok(0)
  assert tlv.u64(tlv.encode_u64(max_u64 + 1)) == Ok(max_u64)
}

/// Fixed bytes, variable bytes and text.
pub fn bytes_and_text_fields_test() {
  assert tlv.fixed_bytes(2)(<<1, 2>>) == Ok(<<1, 2>>)
  assert tlv.fixed_bytes(2)(<<1>>) == Error(tlv.InvalidValue)
  assert tlv.bytes(<<>>) == Ok(<<>>)
  assert tlv.text(<<"héllo":utf8>>) == Ok("héllo")
  assert tlv.text(<<0xff, 0xfe>>) == Error(tlv.InvalidValue)
  assert tlv.text(<<0xc0, 0x80>>) == Error(tlv.InvalidValue)
}

/// Nested streams follow the same rules as the outer one.
pub fn nested_streams_test() {
  let inner = {
    use n <- tlv.required(2, tlv.u8)
    tlv.success(n)
  }
  let decoder = {
    use n <- tlv.required(4, tlv.nested(inner))
    tlv.success(n)
  }

  assert tlv.decode(<<4, 3, 2, 1, 9>>, max_bytes: 64, with: decoder) == Ok(9)
  assert tlv.decode(<<4, 5, 2, 1, 9, 4, 0>>, max_bytes: 64, with: decoder)
    == Error(tlv.UnknownRequired(4))
  assert tlv.decode(<<4, 4, 2, 1, 9, 9>>, max_bytes: 64, with: decoder)
    == Error(tlv.Truncated)
  assert tlv.decode(<<4, 6, 4, 0, 2, 0, 2, 0>>, max_bytes: 64, with: decoder)
    == Error(tlv.OutOfOrder(2))
}

/// A list of fixed-size items must divide evenly.
pub fn fixed_item_lists_test() {
  assert tlv.items(2, tlv.u16)(<<1, 0, 0, 2>>) == Ok([256, 2])
  assert tlv.items(2, tlv.u16)(<<>>) == Ok([])
  assert tlv.items(2, tlv.u16)(<<1, 0, 0>>) == Error(tlv.InvalidValue)
  assert tlv.items(0, tlv.u16)(<<>>) == Error(tlv.InvalidValue)
}

/// A sequence of length-prefixed items is bounded in count and in size.
pub fn sequences_test() {
  let field = tlv.sequence(tlv.bytes, max_items: 2)

  assert field(<<>>) == Ok([])
  assert field(<<1, 7, 0>>) == Ok([<<7>>, <<>>])
  assert field(<<1, 7, 0, 0>>) == Error(tlv.TooManyItems)
  assert field(<<2, 7>>) == Error(tlv.Truncated)
  assert field(<<0xfd, 0, 1, 7>>) == Error(tlv.NonMinimalBigSize)
}

/// `peek` reads without consuming.
pub fn peek_test() {
  let assert Ok(stream) = parse(<<0, 1, 7>>)

  assert tlv.peek(stream, 0, tlv.u8) == Ok(7)
  assert tlv.peek(stream, 0, tlv.u16) == Error(tlv.InvalidField(0))
  assert tlv.peek(stream, 2, tlv.u8) == Error(tlv.MissingRequired(2))
}

// ---------------------------------------------------------------- builder

/// A builder replaces rather than duplicates, and sorts on encode, so its
/// output always parses.
pub fn builder_cannot_emit_duplicates_or_disorder_test() {
  let bytes =
    tlv.new()
    |> tlv.put(300, <<3>>)
    |> tlv.put(4, <<>>)
    |> tlv.put(2, <<1>>)
    |> tlv.put(4, <<9, 9>>)
    |> tlv.encode

  assert bytes == <<2, 1, 1, 4, 2, 9, 9, 0xfd, 0x01, 0x2c, 1, 3>>
  assert parse(bytes) |> result_is_ok
}

/// Builder output is a stream whose records are what was put in, for any
/// sequence of puts in any order.
pub fn builder_output_always_parses_property_test() {
  use #(records, seed) <- property(qcheck.tuple2(
    record_lists(),
    qcheck.bounded_int(0, 1000),
  ))

  // Reverse half the time so insertion order is not the sorted order.
  let ordered = case seed % 2 {
    0 -> records
    _ -> list.reverse(records)
  }
  let assert Ok(stream) = parse(build(ordered))

  assert tlv.records(stream) == records
}

/// A value long enough to need a four-byte length round trips; generating
/// one at random is too slow, so it is fixed.
pub fn wide_length_round_trips_test() {
  let value = <<0:size(524_288)>>
  let bytes = build([#(2, value)])

  assert bit_array.slice(bytes, 0, 7) == Ok(<<2, 0xfe, 0, 1, 0, 0, 0>>)
  let assert Ok(stream) = parse(bytes)
  assert tlv.records(stream) == [#(2, value)]
  assert tlv.encode_stream(stream) == bytes
}
