//// A BOLT #1-style TLV codec: the one encoding for every byte string the
//// system signs, hashes, or sends (design review §3.1).
////
//// A protobuf decoder accepts many byte strings for one message, so a
//// signature or an AEAD associated-data check over "the message" has no
//// single thing to cover. A TLV stream with canonical rules has exactly one
//// encoding per set of records, which is the property this module exists to
//// provide and the property its tests state: **every byte string `parse`
//// accepts, `encode_stream` reproduces exactly**.
////
//// The wire format is BOLT #1's. A stream is a sequence of records
//// `(type, length, value)` where `type` and `length` are BigSize varints:
//// below `0xfd` one byte; `0xfd` then a big-endian u16; `0xfe` then a u32;
//// `0xff` then a u64. A decoder rejects any BigSize that could have been
//// written shorter, any record whose type does not strictly exceed the
//// previous one (which also forbids duplicates), any length past the end of
//// the input, and any input larger than a caller-supplied limit.
////
//// ## Required and optional types
////
//// By the "it's okay to be odd" rule, an unknown **even** type is one the
//// decoder must understand, so it fails closed (`UnknownRequired`); an
//// unknown **odd** type is skipped. A skipped record is never readable as a
//// known field, because a field is only ever read by naming its type, and
//// the decoder never names a type it does not know.
////
//// ## Shape of the decoding API
////
//// `parse` checks the stream's structure and yields a `Stream`. A
//// `Decoder(a)` then reads known fields out of it in the `use` style, and
//// `run` ends by failing if an even type was present but never read:
////
//// ```gleam
//// tlv.decode(bytes, max_bytes: 1024, with: {
////   use version <- tlv.required(0, tlv.u16)
////   use note <- tlv.optional(1, tlv.text)
////   tlv.success(#(version, note))
//// })
//// ```
////
//// Decoders are total: no input crashes them, and every failure is a
//// `TlvError` carrying type numbers and never value bytes, so an error
//// built from a secret-bearing record cannot leak the secret.
////
//// ## Encoding
////
//// A `Builder` holds at most one value per type and sorts on `encode`, so
//// the encoder cannot emit a duplicate, an out-of-order record, or a
//// non-minimal BigSize. Encoders are total: a number outside the width it
//// is written at is clamped to the nearest representable value, so callers
//// hold values already bounded by `core/limits` and the codec never
//// silently wraps around.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result

const max_u8 = 0xff

const max_u16 = 0xffff

const max_u32 = 0xffff_ffff

const max_u64 = 0xffff_ffff_ffff_ffff

/// Why a byte string is not a valid stream or not the stream a decoder
/// expects. No variant holds value bytes.
pub type TlvError {
  /// The input ended inside a BigSize, or a record's length runs past the
  /// end of the input, or the input is not a whole number of bytes.
  Truncated

  /// A BigSize used more bytes than its value needs.
  NonMinimalBigSize

  /// A record's type did not strictly exceed the record before it.
  OutOfOrder(tag: Int)

  /// The input is longer than the caller's limit.
  InputTooLarge

  /// An even type nobody asked for was present, so the stream is asking
  /// for something this decoder does not understand.
  UnknownRequired(tag: Int)

  /// A required type was absent.
  MissingRequired(tag: Int)

  /// The record for `tag` was present but its value did not decode.
  InvalidField(tag: Int)

  /// A sequence held more items than the decoder allows.
  TooManyItems

  /// A field codec rejected a value. `required` and `optional` rewrite it
  /// to `InvalidField` once the type is known, so callers see this only
  /// from a field codec used on its own.
  InvalidValue
}

/// A structurally valid stream: records in strictly increasing type order,
/// at most one per type, every length in bounds. Nothing here has been
/// interpreted yet.
pub opaque type Stream {
  Stream(records: Dict(Int, BitArray))
}

/// A value codec: reads one record's value bytes. `u8` through `u64`,
/// `fixed_bytes`, `bytes`, `text`, `nested`, `items` and `sequence` build
/// them.
pub type Field(a) =
  fn(BitArray) -> Result(a, TlvError)

/// A plan for reading known fields out of a stream. Fields are consumed as
/// they are read, so whatever is left when the plan finishes is exactly
/// what the plan did not understand.
pub opaque type Decoder(a) {
  Decoder(
    run: fn(Dict(Int, BitArray)) -> Result(#(a, Dict(Int, BitArray)), TlvError),
  )
}

/// A set of records to encode, at most one per type.
pub opaque type Builder {
  Builder(records: Dict(Int, BitArray))
}

// -------------------------------------------------------------- BigSize

/// Writes `value` as a BOLT #1 BigSize in its minimal form. A value below
/// zero is written as zero and one above the u64 range as the u64 maximum.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_big_size(252)
/// // -> <<0xfc>>
///
/// tlv.encode_big_size(253)
/// // -> <<0xfd, 0x00, 0xfd>>
/// ```
pub fn encode_big_size(value: Int) -> BitArray {
  let value = int.clamp(value, 0, max_u64)

  // The value's magnitude picks the narrowest of the four BigSize forms.
  case value {
    _ if value < 0xfd -> <<value:size(8)>>
    _ if value <= max_u16 -> <<0xfd, value:size(16)>>
    _ if value <= max_u32 -> <<0xfe, value:size(32)>>
    _ -> <<0xff, value:size(64)>>
  }
}

/// Reads one BigSize from the front of `bits`, returning it and the bytes
/// after it. Rejects a truncated or non-minimal encoding.
///
/// ## Examples
///
/// ```gleam
/// tlv.decode_big_size(<<0xfd, 0x00, 0xfd, 7>>)
/// // -> Ok(#(253, <<7>>))
///
/// tlv.decode_big_size(<<0xfd, 0x00, 0xfc>>)
/// // -> Error(NonMinimalBigSize)
/// ```
pub fn decode_big_size(bits: BitArray) -> Result(#(Int, BitArray), TlvError) {
  // Each wide form must carry a value the next-narrower form could not,
  // which is what makes the encoding of a given number unique.
  case bits {
    <<0xff, value:size(64), rest:bits>> ->
      minimal(value, above: max_u32, rest: rest)

    <<0xfe, value:size(32), rest:bits>> ->
      minimal(value, above: max_u16, rest: rest)

    <<0xfd, value:size(16), rest:bits>> ->
      minimal(value, above: 0xfc, rest: rest)

    // A marker byte without its full payload.
    <<0xff, _:bits>> | <<0xfe, _:bits>> | <<0xfd, _:bits>> -> Error(Truncated)

    <<value:size(8), rest:bits>> -> Ok(#(value, rest))

    // Empty, or not a whole number of bytes.
    _ -> Error(Truncated)
  }
}

/// Accepts a decoded BigSize only when it exceeds what the next-narrower form can hold,
/// which is the rule that makes every number have exactly one encoding.
fn minimal(
  value: Int,
  above floor: Int,
  rest rest: BitArray,
) -> Result(#(Int, BitArray), TlvError) {
  case value > floor {
    True -> Ok(#(value, rest))
    False -> Error(NonMinimalBigSize)
  }
}

// -------------------------------------------------------------- parsing

/// Checks `bytes` against the stream rules and returns the records. Rejects
/// input longer than `max_bytes` before reading any of it.
///
/// ## Examples
///
/// ```gleam
/// tlv.parse(<<1, 1, 9>>, max_bytes: 16)
/// // -> Ok(_)
///
/// tlv.parse(<<2, 0, 1, 0>>, max_bytes: 16)
/// // -> Error(OutOfOrder(1))
/// ```
pub fn parse(
  bytes: BitArray,
  max_bytes max_bytes: Int,
) -> Result(Stream, TlvError) {
  // The limit is checked before any byte is read, so an oversize input costs one comparison.
  case bit_array.byte_size(bytes) > max_bytes {
    True -> Error(InputTooLarge)
    False -> {
      use records <- result.try(parse_records(bytes, -1, dict.new()))
      Ok(Stream(records:))
    }
  }
}

/// Reads records until the input is empty. `previous` is the last type
/// seen, starting below every legal type, so "strictly increasing" is one
/// comparison and duplicates fall out of it.
fn parse_records(
  bits: BitArray,
  previous: Int,
  records: Dict(Int, BitArray),
) -> Result(Dict(Int, BitArray), TlvError) {
  // An empty remainder ends the stream; anything else must start a whole record.
  case bit_array.byte_size(bits) {
    0 -> Ok(records)

    _ -> {
      use #(tag, rest) <- result.try(decode_big_size(bits))
      use #(length, rest) <- result.try(decode_big_size(rest))
      use Nil <- result.try(ascending(tag, previous))
      use #(value, rest) <- result.try(take(rest, length))
      parse_records(rest, tag, dict.insert(records, tag, value))
    }
  }
}

fn ascending(tag: Int, previous: Int) -> Result(Nil, TlvError) {
  case tag > previous {
    True -> Ok(Nil)
    False -> Error(OutOfOrder(tag))
  }
}

/// Splits `length` bytes off the front. The length is compared first, so a
/// hostile u64 length never reaches the bit-array primitives.
fn take(
  bits: BitArray,
  length: Int,
) -> Result(#(BitArray, BitArray), TlvError) {
  let available = bit_array.byte_size(bits)

  // A length past the end is refused before it reaches the bit-array pattern below.
  case length > available {
    True -> Error(Truncated)
    False ->
      case bits {
        <<value:bytes-size(length), rest:bits>> -> Ok(#(value, rest))
        _ -> Error(Truncated)
      }
  }
}

/// Re-encodes a parsed stream. For every stream `parse` accepts, this
/// returns the bytes `parse` was given; that equality is the module's
/// canonical-encoding property.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(stream) = tlv.parse(<<1, 1, 9>>, max_bytes: 16)
/// tlv.encode_stream(stream)
/// // -> <<1, 1, 9>>
/// ```
pub fn encode_stream(stream: Stream) -> BitArray {
  encode(Builder(records: stream.records))
}

/// The records of a stream as `#(type, value)` pairs in increasing type
/// order, for tests and diagnostics that inspect structure.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(stream) = tlv.parse(<<1, 1, 9>>, max_bytes: 16)
/// tlv.records(stream)
/// // -> [#(1, <<9>>)]
/// ```
pub fn records(stream: Stream) -> List(#(Int, BitArray)) {
  stream.records
  |> dict.to_list
  |> list.sort(by: fn(left, right) { int.compare(left.0, right.0) })
}

// ------------------------------------------------------------- decoding

/// A decoder that reads nothing and produces `value`: the last line of a
/// `use` chain.
///
/// ## Examples
///
/// ```gleam
/// tlv.decode(<<>>, max_bytes: 0, with: tlv.success(7))
/// // -> Ok(7)
/// ```
pub fn success(value: a) -> Decoder(a) {
  Decoder(run: fn(remaining) { Ok(#(value, remaining)) })
}

/// A decoder that always fails with `error`, for a value that parsed but
/// names something this decoder does not support.
///
/// ## Examples
///
/// ```gleam
/// tlv.decode(<<>>, max_bytes: 0, with: tlv.fail(InvalidField(2)))
/// // -> Error(InvalidField(2))
/// ```
pub fn fail(error: TlvError) -> Decoder(a) {
  Decoder(run: fn(_) { Error(error) })
}

/// Reads the value of type `tag` with `field`, then continues with `next`.
/// Fails with `MissingRequired` when the type is absent.
///
/// ## Examples
///
/// ```gleam
/// tlv.decode(<<2, 1, 9>>, max_bytes: 8, with: {
///   use n <- tlv.required(2, tlv.u8)
///   tlv.success(n)
/// })
/// // -> Ok(9)
/// ```
pub fn required(
  tag: Int,
  field: Field(a),
  next: fn(a) -> Decoder(b),
) -> Decoder(b) {
  Decoder(run: fn(remaining) {
    case dict.get(remaining, tag) {
      Ok(raw) -> continue(remaining, tag, field(raw), next)
      Error(Nil) -> Error(MissingRequired(tag))
    }
  })
}

/// Reads the value of type `tag` if present, then continues with `next`.
/// A present value that does not decode is still an error: only absence is
/// optional.
///
/// ## Examples
///
/// ```gleam
/// tlv.decode(<<>>, max_bytes: 0, with: {
///   use n <- tlv.optional(1, tlv.u8)
///   tlv.success(n)
/// })
/// // -> Ok(None)
/// ```
pub fn optional(
  tag: Int,
  field: Field(a),
  next: fn(Option(a)) -> Decoder(b),
) -> Decoder(b) {
  Decoder(run: fn(remaining) {
    case dict.get(remaining, tag) {
      Ok(raw) -> continue(remaining, tag, result.map(field(raw), Some), next)

      Error(Nil) -> run_decoder(next(None), remaining)
    }
  })
}

/// Consumes `tag` from what remains, so an even type that was read is not
/// reported as unknown at the end, then runs the rest of the plan.
fn continue(
  remaining: Dict(Int, BitArray),
  tag: Int,
  decoded: Result(a, TlvError),
  next: fn(a) -> Decoder(b),
) -> Result(#(b, Dict(Int, BitArray)), TlvError) {
  use value <- result.try(result.map_error(decoded, locate(_, tag)))
  run_decoder(next(value), dict.delete(remaining, tag))
}

/// Unwraps a `Decoder` and runs it on the records not yet read.
fn run_decoder(
  decoder: Decoder(a),
  remaining: Dict(Int, BitArray),
) -> Result(#(a, Dict(Int, BitArray)), TlvError) {
  let Decoder(run:) = decoder
  run(remaining)
}

/// Attaches the type number to a field codec's anonymous failure.
fn locate(error: TlvError, tag: Int) -> TlvError {
  case error {
    InvalidValue -> InvalidField(tag)

    Truncated
    | NonMinimalBigSize
    | OutOfOrder(_)
    | InputTooLarge
    | UnknownRequired(_)
    | MissingRequired(_)
    | InvalidField(_)
    | TooManyItems -> error
  }
}

/// Reads one stream with a decoder, and fails when an even type remains
/// that the decoder never read.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(stream) = tlv.parse(<<2, 1, 9>>, max_bytes: 8)
/// tlv.run(stream, tlv.success(Nil))
/// // -> Error(UnknownRequired(2))
/// ```
pub fn run(stream: Stream, decoder: Decoder(a)) -> Result(a, TlvError) {
  use #(value, remaining) <- result.try(run_decoder(decoder, stream.records))

  // Odd leftovers are optional extensions this decoder skips; an even one
  // is a demand it cannot meet. The smallest is reported so the error does
  // not depend on dictionary order.
  let required_left =
    remaining
    |> dict.keys
    |> list.filter(int.is_even)
    |> list.sort(by: int.compare)

  // An even leftover is a demand this decoder cannot meet; none left means the stream was fully understood.
  case required_left {
    [] -> Ok(value)
    [tag, ..] -> Error(UnknownRequired(tag))
  }
}

/// `parse` then `run`: decodes `bytes` of at most `max_bytes` with `with`.
///
/// ## Examples
///
/// ```gleam
/// tlv.decode(<<2, 1, 9>>, max_bytes: 8, with: {
///   use n <- tlv.required(2, tlv.u8)
///   tlv.success(n)
/// })
/// // -> Ok(9)
/// ```
pub fn decode(
  bytes: BitArray,
  max_bytes max_bytes: Int,
  with decoder: Decoder(a),
) -> Result(a, TlvError) {
  use stream <- result.try(parse(bytes, max_bytes:))
  run(stream, decoder)
}

/// Reads one field of a stream without consuming it, so a caller can look
/// at a version before choosing how to decode the rest.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(stream) = tlv.parse(<<0, 1, 7>>, max_bytes: 8)
/// tlv.peek(stream, 0, tlv.u8)
/// // -> Ok(7)
/// ```
pub fn peek(stream: Stream, tag: Int, field: Field(a)) -> Result(a, TlvError) {
  case dict.get(stream.records, tag) {
    Ok(raw) -> result.map_error(field(raw), locate(_, tag))
    Error(Nil) -> Error(MissingRequired(tag))
  }
}

// --------------------------------------------------------- field codecs

/// An unsigned 8-bit integer: exactly one byte.
///
/// ## Examples
///
/// ```gleam
/// tlv.u8(<<7>>)
/// // -> Ok(7)
/// ```
pub fn u8(raw: BitArray) -> Result(Int, TlvError) {
  case raw {
    <<value:size(8)>> -> Ok(value)
    _ -> Error(InvalidValue)
  }
}

/// An unsigned big-endian 16-bit integer: exactly two bytes.
///
/// ## Examples
///
/// ```gleam
/// tlv.u16(<<1, 0>>)
/// // -> Ok(256)
/// ```
pub fn u16(raw: BitArray) -> Result(Int, TlvError) {
  case raw {
    <<value:size(16)>> -> Ok(value)
    _ -> Error(InvalidValue)
  }
}

/// An unsigned big-endian 32-bit integer: exactly four bytes.
///
/// ## Examples
///
/// ```gleam
/// tlv.u32(<<0, 0, 1, 0>>)
/// // -> Ok(256)
/// ```
pub fn u32(raw: BitArray) -> Result(Int, TlvError) {
  case raw {
    <<value:size(32)>> -> Ok(value)
    _ -> Error(InvalidValue)
  }
}

/// An unsigned big-endian 64-bit integer: exactly eight bytes.
///
/// ## Examples
///
/// ```gleam
/// tlv.u64(<<0, 0, 0, 0, 0, 0, 1, 0>>)
/// // -> Ok(256)
/// ```
pub fn u64(raw: BitArray) -> Result(Int, TlvError) {
  case raw {
    <<value:size(64)>> -> Ok(value)
    _ -> Error(InvalidValue)
  }
}

/// A byte string of exactly `size` bytes.
///
/// ## Examples
///
/// ```gleam
/// tlv.fixed_bytes(2)(<<1, 2>>)
/// // -> Ok(<<1, 2>>)
/// ```
pub fn fixed_bytes(size: Int) -> Field(BitArray) {
  fn(raw) {
    case bit_array.byte_size(raw) == size {
      True -> Ok(raw)
      False -> Error(InvalidValue)
    }
  }
}

/// A byte string of any length: the record's length is the size.
///
/// ## Examples
///
/// ```gleam
/// tlv.bytes(<<1, 2, 3>>)
/// // -> Ok(<<1, 2, 3>>)
/// ```
pub fn bytes(raw: BitArray) -> Result(BitArray, TlvError) {
  Ok(raw)
}

/// UTF-8 text. Invalid UTF-8 is rejected, so a decoded string always
/// re-encodes to the bytes it came from.
///
/// ## Examples
///
/// ```gleam
/// tlv.text(<<"hi":utf8>>)
/// // -> Ok("hi")
/// ```
pub fn text(raw: BitArray) -> Result(String, TlvError) {
  case bit_array.to_string(raw) {
    Ok(text) -> Ok(text)
    Error(Nil) -> Error(InvalidValue)
  }
}

/// A nested stream, decoded by `decoder` under the same rules as the
/// outer one. The input limit is the value's own size, which the outer
/// stream already bounded.
///
/// ## Examples
///
/// ```gleam
/// tlv.decode(<<3, 3, 2, 1, 9>>, max_bytes: 8, with: {
///   use n <- tlv.required(3, tlv.nested({
///     use n <- tlv.required(2, tlv.u8)
///     tlv.success(n)
///   }))
///   tlv.success(n)
/// })
/// // -> Ok(9)
/// ```
pub fn nested(decoder: Decoder(a)) -> Field(a) {
  fn(raw) { decode(raw, max_bytes: bit_array.byte_size(raw), with: decoder) }
}

/// A concatenation of fixed-size items, each read by `item`. The length
/// must be a whole number of items.
///
/// ## Examples
///
/// ```gleam
/// tlv.items(1, tlv.u8)(<<1, 2>>)
/// // -> Ok([1, 2])
/// ```
pub fn items(size: Int, item: Field(a)) -> Field(List(a)) {
  fn(raw) {
    case size > 0 && bit_array.byte_size(raw) % size == 0 {
      True -> items_loop(raw, size, item, [])
      False -> Error(InvalidValue)
    }
  }
}

/// Reads `size`-byte items off the front of `raw` until it is empty.
fn items_loop(
  raw: BitArray,
  size: Int,
  item: Field(a),
  acc: List(a),
) -> Result(List(a), TlvError) {
  // An empty remainder ends the list; anything else is one more item.
  case bit_array.byte_size(raw) {
    0 -> Ok(list.reverse(acc))

    _ -> {
      use #(head, rest) <- result.try(take(raw, size))
      use value <- result.try(item(head))
      items_loop(rest, size, item, [value, ..acc])
    }
  }
}

/// A sequence of variable-size items, each prefixed by its BigSize length
/// and read by `item`, at most `max_items` of them. Use it where `items`
/// cannot, because the elements differ in size.
///
/// ## Examples
///
/// ```gleam
/// tlv.sequence(tlv.bytes, max_items: 4)(<<1, 7, 0>>)
/// // -> Ok([<<7>>, <<>>])
/// ```
pub fn sequence(item: Field(a), max_items max_items: Int) -> Field(List(a)) {
  fn(raw) { sequence_loop(raw, item, max_items, []) }
}

/// Reads length-prefixed items off the front of `raw`, counting down from the allowed number.
fn sequence_loop(
  raw: BitArray,
  item: Field(a),
  remaining_items: Int,
  acc: List(a),
) -> Result(List(a), TlvError) {
  // An empty remainder ends the sequence; otherwise the count allowed is checked before reading an item.
  case bit_array.byte_size(raw) {
    0 -> Ok(list.reverse(acc))

    _ if remaining_items <= 0 -> Error(TooManyItems)

    _ -> {
      use #(length, rest) <- result.try(decode_big_size(raw))
      use #(head, rest) <- result.try(take(rest, length))
      use value <- result.try(item(head))
      sequence_loop(rest, item, remaining_items - 1, [value, ..acc])
    }
  }
}

/// Post-processes a field's value with a total function.
///
/// ## Examples
///
/// ```gleam
/// tlv.map(tlv.u8, fn(n) { n + 1 })(<<1>>)
/// // -> Ok(2)
/// ```
pub fn map(field: Field(a), with change: fn(a) -> b) -> Field(b) {
  fn(raw) { result.map(field(raw), change) }
}

/// Post-processes a field's value with a function that can refuse it, as
/// a smart constructor does. A refusal is an `InvalidValue`.
///
/// ## Examples
///
/// ```gleam
/// tlv.try_map(tlv.u8, fn(n) { Error(Nil) })(<<1>>)
/// // -> Error(InvalidValue)
/// ```
pub fn try_map(
  field: Field(a),
  with change: fn(a) -> Result(b, Nil),
) -> Field(b) {
  fn(raw) {
    use value <- result.try(field(raw))

    // A refusal by the smart constructor is a bad value, whatever the constructor's reason.
    case change(value) {
      Ok(changed) -> Ok(changed)
      Error(Nil) -> Error(InvalidValue)
    }
  }
}

// ------------------------------------------------------------- encoding

/// An empty builder.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode(tlv.new())
/// // -> <<>>
/// ```
pub fn new() -> Builder {
  Builder(records: dict.new())
}

/// Sets the value of type `tag`, replacing any earlier value for it. A
/// builder holds one value per type, so a duplicate cannot be emitted.
///
/// ## Examples
///
/// ```gleam
/// tlv.new()
/// |> tlv.put(1, <<7>>)
/// |> tlv.put(1, <<8>>)
/// |> tlv.encode
/// // -> <<1, 1, 8>>
/// ```
pub fn put(builder: Builder, tag: Int, value: BitArray) -> Builder {
  Builder(records: dict.insert(builder.records, int.max(tag, 0), value))
}

/// The canonical bytes: records sorted by type, each with a minimal BigSize
/// type and length.
///
/// ## Examples
///
/// ```gleam
/// tlv.new()
/// |> tlv.put(4, <<>>)
/// |> tlv.put(2, <<1>>)
/// |> tlv.encode
/// // -> <<2, 1, 1, 4, 0>>
/// ```
pub fn encode(builder: Builder) -> BitArray {
  builder.records
  |> dict.to_list
  |> list.sort(by: fn(left, right) { int.compare(left.0, right.0) })
  |> list.map(fn(record) {
    bit_array.concat([
      encode_big_size(record.0),
      encode_big_size(bit_array.byte_size(record.1)),
      record.1,
    ])
  })
  |> bit_array.concat
}

/// A value for `u8`, clamped to 0 through 255.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_u8(300)
/// // -> <<255>>
/// ```
pub fn encode_u8(value: Int) -> BitArray {
  let value = int.clamp(value, 0, max_u8)
  <<value:size(8)>>
}

/// A value for `u16`, clamped to 0 through 65535.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_u16(1)
/// // -> <<0, 1>>
/// ```
pub fn encode_u16(value: Int) -> BitArray {
  let value = int.clamp(value, 0, max_u16)
  <<value:size(16)>>
}

/// A value for `u32`, clamped to the u32 range.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_u32(1)
/// // -> <<0, 0, 0, 1>>
/// ```
pub fn encode_u32(value: Int) -> BitArray {
  let value = int.clamp(value, 0, max_u32)
  <<value:size(32)>>
}

/// A value for `u64`, clamped to the u64 range.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_u64(1)
/// // -> <<0, 0, 0, 0, 0, 0, 0, 1>>
/// ```
pub fn encode_u64(value: Int) -> BitArray {
  let value = int.clamp(value, 0, max_u64)
  <<value:size(64)>>
}

/// A value for `text`.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_text("hi")
/// // -> <<"hi":utf8>>
/// ```
pub fn encode_text(value: String) -> BitArray {
  bit_array.from_string(value)
}

/// A value for `items`: the items concatenated.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_items([<<1>>, <<2>>])
/// // -> <<1, 2>>
/// ```
pub fn encode_items(items: List(BitArray)) -> BitArray {
  bit_array.concat(items)
}

/// A value for `sequence`: each item behind its BigSize length.
///
/// ## Examples
///
/// ```gleam
/// tlv.encode_sequence([<<7>>, <<>>])
/// // -> <<1, 7, 0>>
/// ```
pub fn encode_sequence(items: List(BitArray)) -> BitArray {
  items
  |> list.map(fn(item) {
    bit_array.concat([encode_big_size(bit_array.byte_size(item)), item])
  })
  |> bit_array.concat
}
