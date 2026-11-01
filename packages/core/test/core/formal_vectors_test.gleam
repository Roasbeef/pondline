//// Differential conformance between the Gleam functions and their Lean
//// transcriptions (`formal/lean`, `docs/formal/lean.md`).
////
//// The Lean side proves theorems about its own definitions of the TLV
//// codec, the padding buckets, the retention offers and the retransmit
//// schedule. Those theorems say nothing about this package unless the two
//// definitions agree, so the Lean build also writes
//// `test/core/formal_vectors.txt`: thousands of inputs, exhaustive over
//// small domains and adversarial at every boundary, each with the output
//// the Lean definition gives. Each test here runs the real Gleam function on
//// every input of one operation, renders its output in the same notation,
//// and requires the line it renders to be the line it read (`conform`). A
//// Gleam change that makes the proofs describe a different function fails
//// here; a deliberate change updates the Lean transcription and regenerates
//// the vectors with `formal/lean/check.sh --write`.
////
//// The notation is described in `formal/lean/GenVectors.lean`: byte strings
//// in hex (`hex`), long ones as runs (`rle`), TLV records, decoder steps
//// read through the real `required` and `optional` (`spec_decoder`, with
//// `field` choosing the codec), and errors by name. `runs` folds a byte
//// string into runs, each closed by `render_run`. A vector the test
//// cannot parse is a broken file and fails its `let assert`.
////
//// Reading the file is the only I/O here, through OTP's `file:read_file/1`,
//// the same way `swarm_test` reads the environment through `os:getenv/2`.

import core/envelope
import core/id
import core/limits
import core/plan
import core/retention
import core/retransmit
import core/time.{type Instant, Instant}
import core/tlv
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/string

/// Where the generated vectors live, relative to the package root `gleam
/// test` runs in.
const vectors_path = "test/core/formal_vectors.txt"

// --------------------------------------------------------------- BigSize

pub fn big_size_encode_test() {
  use fields <- conform("bs.enc", 500)
  let assert [value, _] = fields as "bs.enc: value, encoding"

  value <> " " <> hex(tlv.encode_big_size(number(value)))
}

pub fn big_size_decode_test() {
  use fields <- conform("bs.dec", 2500)
  let assert [input, _] = fields as "bs.dec: input, result"

  // Success renders the value and what is left; failure its error.
  let rendered = case tlv.decode_big_size(bytes(input)) {
    Ok(#(value, rest)) -> "ok:" <> int.to_string(value) <> ":" <> hex(rest)
    Error(error) -> "err:" <> render_error(error)
  }

  input <> " " <> rendered
}

// --------------------------------------------------------------- streams

pub fn parse_test() {
  use fields <- conform("parse", 3000)
  let assert [limit, input, _] = fields as "parse: limit, input, result"

  limit <> " " <> input <> " " <> render_parse(bytes(input), number(limit))
}

pub fn decode_test() {
  use fields <- conform("decode", 1500)
  let assert [limit, input, spec, _] = fields
    as "decode: limit, input, spec, result"
  let steps = list.map(split_commas(spec), parse_step)

  // `decode` is `parse` then `run`, so this reaches every error either
  // raises.
  let rendered = case
    tlv.decode(
      bytes(input),
      max_bytes: number(limit),
      with: spec_decoder(steps, []),
    )
  {
    Ok(values) -> "ok:" <> values
    Error(error) -> "err:" <> render_error(error)
  }

  string.join([limit, input, spec, rendered], " ")
}

pub fn build_test() {
  use fields <- conform("build", 150)
  let assert [puts, _] = fields as "build: puts, encoding"

  let builder =
    list.fold(split_commas(puts), tlv.new(), fn(builder, put) {
      let assert Ok(#(tag, value)) = string.split_once(put, ":")
        as "a put is tag:hex"
      tlv.put(builder, number(tag), bytes(value))
    })

  puts <> " " <> hex(tlv.encode(builder))
}

// --------------------------------------------------------------- padding

pub fn padded_size_test() {
  use fields <- conform("psize", 100)
  let assert [size, _] = fields as "psize: size, bucket"

  // A size past every bucket has no padded size.
  let rendered = case limits.padded_size(number(size)) {
    Ok(bucket) -> int.to_string(bucket)
    Error(Nil) -> "none"
  }

  size <> " " <> rendered
}

pub fn pad_test() {
  use fields <- conform("pad", 30)
  let assert [sealed, _] = fields as "pad: sealed, padded"

  // A ciphertext no bucket holds is refused.
  let rendered = case envelope.pad(runs_to_bytes(sealed)) {
    Ok(padded) -> rle(envelope.to_wire(padded))
    Error(Nil) -> "none"
  }

  sealed <> " " <> rendered
}

pub fn from_wire_unpad_test() {
  use fields <- conform("unwire", 30)
  let assert [wire, _] = fields as "unwire: wire, sealed"
  let input = runs_to_bytes(wire)

  // `from_wire` keeps the bytes as they came, which `to_wire` must give
  // back; `unpad` then reads the length prefix.
  let rendered = case envelope.from_wire(input) {
    Error(Nil) -> "wire-refused"
    Ok(padded) ->
      case envelope.to_wire(padded) == input, envelope.unpad(padded) {
        False, _ -> "rewritten"
        True, Ok(sealed) -> rle(sealed)
        True, Error(Nil) -> "unpad-refused"
      }
  }

  wire <> " " <> rendered
}

// ------------------------------------------------------------- schedules

pub fn retention_offers_test() {
  use fields <- conform("offers", 1000)
  let assert [expires_at, now, _, _] = fields
    as "offers: expires_at, now, first, shorter"

  let #(first, shorter) =
    retention.offers(
      expires_at: Instant(number(expires_at)),
      now: Instant(number(now)),
    )

  [expires_at, now, render_instant(first)]
  |> list.append([commas(list.map(shorter, render_instant))])
  |> string.join(" ")
}

pub fn retransmit_due_at_test() {
  use fields <- conform("due", 900)
  let assert [window, kind, stored_at, retransmits, deadline, _] = fields
    as "due: window, kind, stored_at, retransmits, deadline, due"

  let due =
    retransmit.due_at(
      number(window),
      parse_kind(kind),
      Instant(number(stored_at)),
      number(retransmits),
      Instant(number(deadline)),
    )

  // No copy is scheduled for a kind that is never retransmitted, past the
  // bound, or past the deadline.
  let rendered = case due {
    Some(instant) -> render_instant(instant)
    None -> "none"
  }

  string.join([window, kind, stored_at, retransmits, deadline, rendered], " ")
}

// ----------------------------------------------------------- the harness

/// Runs `render` over every vector for `op` and requires each rendered line
/// to equal the vector's own text. `at_least` guards against a file that
/// silently lost a group: a check over zero vectors passes nothing.
fn conform(op: String, at_least: Int, render: fn(List(String)) -> String) {
  let all = vectors(op)
  assert list.drop(all, at_least - 1) != []

  let mismatches =
    list.filter_map(all, fn(vector) {
      let #(line, fields, expected) = vector
      let actual = op <> " " <> render(fields)

      // A line the Gleam side renders differently is a disagreement
      // between the function and the definition the proofs are about.
      case actual == expected {
        True -> Error(Nil)
        False -> Ok(#(line, expected, actual))
      }
    })

  assert list.take(mismatches, 5) == []
}

/// Every vector line for `op`: its line number, its fields after the
/// operation name, and its full text.
fn vectors(op: String) -> List(#(Int, List(String), String)) {
  let assert Ok(contents) = read_file(vectors_path)
    as "formal_vectors.txt is readable from the package root"
  let assert Ok(text) = bit_array.to_string(contents)
    as "formal_vectors.txt is UTF-8"

  text
  |> string.split("\n")
  |> list.index_map(fn(line, index) { #(index + 1, line) })
  |> list.filter_map(fn(numbered) {
    let #(line, text) = numbered

    // A comment or a blank line is not a vector; every other line starts
    // with its operation.
    case string.split(text, " ") {
      [name, ..fields] if name == op -> Ok(#(line, fields, text))
      _ -> Error(Nil)
    }
  })
}

@external(erlang, "file", "read_file")
fn read_file(path: String) -> Result(BitArray, Dynamic)

// ------------------------------------------------------------- notation

/// The integer a field holds.
fn number(token: String) -> Int {
  let assert Ok(value) = int.parse(token) as "a vector integer parses"
  value
}

/// The byte string a hex field holds.
fn bytes(token: String) -> BitArray {
  // `-` is the empty byte string; anything else is lowercase hex.
  case token {
    "-" -> <<>>
    _ -> {
      let assert Ok(value) = bit_array.base16_decode(token)
        as "a vector byte string is hex"
      value
    }
  }
}

/// A byte string as a field: lowercase hex.
fn hex(value: BitArray) -> String {
  // The empty byte string is written `-`, so no field is ever empty.
  case bit_array.byte_size(value) {
    0 -> "-"
    _ -> string.lowercase(bit_array.base16_encode(value))
  }
}

/// The items of a comma-separated field.
fn split_commas(token: String) -> List(String) {
  // `-` is the empty list.
  case token {
    "-" -> []
    _ -> string.split(token, ",")
  }
}

/// Items as a comma-separated field.
fn commas(items: List(String)) -> String {
  // The empty list is written `-`.
  case items {
    [] -> "-"
    _ -> string.join(items, ",")
  }
}

/// A byte string written as `<byte>*<count>` runs.
fn runs_to_bytes(token: String) -> BitArray {
  split_commas(token)
  |> list.map(fn(run) {
    let assert [byte, count] = string.split(run, "*") as "a run is byte*count"
    let assert Ok(byte) = int.base_parse(byte, 16) as "a run's byte is hex"
    bit_array.concat(list.repeat(<<byte>>, number(count)))
  })
  |> bit_array.concat
}

/// A byte string as `<byte>*<count>` runs, the form a 256 KiB padded
/// ciphertext fits on one line in.
fn rle(value: BitArray) -> String {
  commas(runs(value, None, []))
}

/// Folds a byte string into runs, front to back; `current` is the run being
/// extended and `done` the runs already closed, newest first.
fn runs(
  value: BitArray,
  current: Option(#(Int, Int)),
  done: List(String),
) -> List(String) {
  case value, current {
    // The next byte extends the current run.
    <<byte, rest:bytes>>, Some(#(run, count)) if run == byte ->
      runs(rest, Some(#(run, count + 1)), done)

    // A different byte closes the current run and opens another.
    <<byte, rest:bytes>>, Some(#(run, count)) ->
      runs(rest, Some(#(byte, 1)), [render_run(run, count), ..done])

    <<byte, rest:bytes>>, None -> runs(rest, Some(#(byte, 1)), done)

    // The end of the input closes the last run.
    _, Some(#(run, count)) -> list.reverse([render_run(run, count), ..done])

    _, None -> list.reverse(done)
  }
}

fn render_run(byte: Int, count: Int) -> String {
  let digits =
    int.to_base16(byte) |> string.lowercase |> string.pad_start(2, "0")
  digits <> "*" <> int.to_string(count)
}

/// A decode error by name, with its type number where it carries one.
fn render_error(error: tlv.TlvError) -> String {
  case error {
    tlv.Truncated -> "truncated"
    tlv.NonMinimalBigSize -> "nonminimal"
    tlv.OutOfOrder(tag) -> "outoforder." <> int.to_string(tag)
    tlv.InputTooLarge -> "toolarge"
    tlv.UnknownRequired(tag) -> "unknownreq." <> int.to_string(tag)
    tlv.MissingRequired(tag) -> "missingreq." <> int.to_string(tag)
    tlv.InvalidField(tag) -> "invalidfield." <> int.to_string(tag)
    tlv.InvalidValue -> "invalidvalue"
    tlv.TooManyItems -> "toomanyitems"
  }
}

/// An accepted stream renders as its records, and must also re-encode to
/// its input, the canonical property the Lean side proves; one that does
/// not renders as what it re-encoded to, which no vector expects.
fn render_parse(input: BitArray, max_bytes: Int) -> String {
  case tlv.parse(input, max_bytes:) {
    Ok(stream) ->
      case tlv.encode_stream(stream) == input {
        True ->
          tlv.records(stream)
          |> list.map(fn(record) {
            int.to_string(record.0) <> ":" <> hex(record.1)
          })
          |> commas
          |> string.append("ok:", _)
        False -> "reencoded:" <> hex(tlv.encode_stream(stream))
      }
    Error(error) -> "err:" <> render_error(error)
  }
}

/// An instant as its Unix seconds.
fn render_instant(instant: Instant) -> String {
  int.to_string(instant.unix_seconds)
}

/// The outbound kind a field names, carrying a fixed message identifier.
fn parse_kind(token: String) -> plan.OutboundKind {
  let assert Ok(message) = id.from_bytes(<<0:size(128)>>)
    as "sixteen bytes are a message identifier"

  // The message a kind carries plays no part in the schedule.
  case token {
    "application" -> plan.ApplicationOut(message)
    "control" -> plan.ControlOut(message)
    "receipt" -> plan.ReceiptOut(message)
    _ -> {
      let assert "handshake" = token as "a kind is one of the four"
      plan.Handshake
    }
  }
}

// -------------------------------------------------------------- decoders

/// A value read by a decoder step.
type Read {
  Raw(BitArray)
  Number(Int)
}

/// Whether a step's absence is an error.
type Want {
  Required
  Optional
}

/// The field codec a step reads with.
type Codec {
  BytesCodec
  U8Codec
}

/// One `required` or `optional` step.
type Step {
  Step(tag: Int, want: Want, codec: Codec)
}

/// A step written `r<tag>:<codec>` (required) or `o<tag>:<codec>`
/// (optional), the codec `b` or `u8`.
fn parse_step(token: String) -> Step {
  let assert Ok(#(head, codec)) = string.split_once(token, ":")
    as "a step is want-and-tag:codec"
  let assert Ok(#(want, tag)) = string.pop_grapheme(head)
    as "a step names its want"

  // `b` reads the raw value; `u8` exactly one byte.
  let codec = case codec {
    "b" -> BytesCodec
    _ -> U8Codec
  }

  // The first character says whether the type is required.
  case want {
    "r" -> Step(number(tag), Required, codec)
    _ -> Step(number(tag), Optional, codec)
  }
}

/// The decoder a list of steps describes, built from the real `required`,
/// `optional` and `success`, rendering each value as it is read.
fn spec_decoder(steps: List(Step), read: List(String)) -> tlv.Decoder(String) {
  case steps {
    // Every step read: the values, in step order.
    [] -> tlv.success(commas(list.reverse(read)))

    [Step(tag:, want: Required, codec:), ..rest] -> {
      use value <- tlv.required(tag, field(codec))
      spec_decoder(rest, [render_read(tag, Some(value)), ..read])
    }

    [Step(tag:, want: Optional, codec:), ..rest] -> {
      use value <- tlv.optional(tag, field(codec))
      spec_decoder(rest, [render_read(tag, value), ..read])
    }
  }
}

/// The real field codec a step names.
fn field(codec: Codec) -> tlv.Field(Read) {
  case codec {
    BytesCodec -> tlv.map(tlv.bytes, Raw)
    U8Codec -> tlv.map(tlv.u8, Number)
  }
}

/// One decoded value as `tag=n`, `tag=x<hex>` or `tag=i<int>`.
fn render_read(tag: Int, read: Option(Read)) -> String {
  // An absent optional type is `n`; a value is its bytes or its number.
  let value = case read {
    None -> "n"
    Some(Raw(raw)) -> "x" <> hex(raw)
    Some(Number(value)) -> "i" <> int.to_string(value)
  }

  int.to_string(tag) <> "=" <> value
}
