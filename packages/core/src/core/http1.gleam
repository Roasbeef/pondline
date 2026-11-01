//// Pure HTTP/1.1 framing for the mailbox binding (spec §6.1).
////
//// The mailbox binding is one `POST` with a bounded binary body and one
//// bounded binary answer, carried over an onion stream or a loopback
//// socket. This module owns the bytes of that exchange and nothing else:
//// it builds the request and parses the response incrementally, so the
//// daemon (which owns the socket, the clock and the deadline) can feed it
//// whatever each read returns. There is no I/O here, which keeps `core`
//// portable and lets a property test split a response at every offset.
////
//// The parser is deliberately a small subset of HTTP/1.1. The peer is
//// untrusted and reached through Tor, so everything that makes HTTP hard
//// to parse safely is refused rather than supported: chunked or any other
//// `Transfer-Encoding`, a missing, duplicated or non-numeric
//// `Content-Length`, folded or malformed headers, and bytes after the
//// body. Every bound is enforced as bytes arrive. A peer sending an
//// endless header line is cut off at `max_header_bytes`, and a declared
//// body larger than the caller's `max_body_bytes` is refused on the
//// strength of the header, before any of the body is read.
////
//// The client sends `Connection: close` on every request, so the response
//// is exactly the head plus `Content-Length` bytes and nothing follows it.
//// A keep-alive connection pool is a later optimisation; it would change
//// the "bytes after the body" rule into "the start of the next response"
//// and is deliberately not modelled here.

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/order
import gleam/result
import gleam/string

/// The most bytes a response head may occupy, from the first byte of the
/// status line through the blank line that ends the header block.
pub const max_header_bytes = 8192

/// The most header lines a response may carry, not counting the status
/// line.
pub const max_header_lines = 64

/// Header fields as `#(name, value)`. Names are lowercased by the parser
/// and values are trimmed of surrounding spaces and tabs.
pub type Headers =
  List(#(String, String))

/// Why a response was refused. None of these carries bytes from the peer,
/// so an error is always safe to log.
pub type HttpError {
  /// The first line is not `HTTP/1.1 NNN` optionally followed by a reason
  /// phrase, or the head is not valid UTF-8 text.
  StatusLineMalformed

  /// The head exceeds `max_header_bytes`.
  HeaderBlockTooLarge

  /// The head has more than `max_header_lines` header lines.
  TooManyHeaderLines

  /// A header line has no colon, an empty or illegal name, a bare CR or LF,
  /// or is an obsolete folded continuation.
  HeaderMalformed

  /// The response carries a `Transfer-Encoding` header, whatever its value.
  TransferEncodingRefused

  /// There is no `Content-Length` header.
  ContentLengthMissing

  /// There is more than one `Content-Length` header, even if they agree.
  ContentLengthDuplicated

  /// The `Content-Length` value is not a plain decimal number.
  ContentLengthInvalid

  /// The declared body is larger than the caller allowed.
  BodyTooLarge

  /// More bytes arrived than `Content-Length` declared.
  TrailingBytes
}

/// A complete response.
pub type Response {
  Response(
    /// The status code, 100 to 599.
    status: Int,
    /// Header fields, lowercased names, in arrival order.
    headers: Headers,
    /// Exactly `Content-Length` bytes.
    body: BitArray,
  )
}

/// What `feed` made of the bytes so far.
pub type Progress {
  /// The response is incomplete; feed more bytes to the new parser.
  NeedMore(parser: Parser)

  /// The response is complete and nothing followed it.
  Complete(response: Response)
}

/// The parser's state: the head bytes seen so far, or, once the head is
/// parsed, the body chunks collected so far. Opaque so the only way to
/// advance it is `feed`, which applies the bounds.
pub opaque type Parser {
  Parser(max_body_bytes: Int, phase: Phase)
}

type Phase {
  /// Still reading the head. `seen` is every byte received, and it never
  /// holds more than `max_header_bytes` plus the one chunk being examined.
  ReadingHead(seen: BitArray)

  /// The head is parsed and `remaining` body bytes are still owed.
  ReadingBody(
    status: Int,
    headers: Headers,
    declared: Int,
    chunks: List(BitArray),
    received: Int,
  )
}

/// Frames a `POST` request with `Connection: close`.
///
/// `host`, `path` and `content_type` are written into the head verbatim.
/// They come from the daemon's own code (the host from a validated
/// `OnionAddress` or the loopback literal), never from the peer or an
/// invitation, so there is nothing to escape; a caller must not pass text
/// containing a CR or LF.
///
/// ## Examples
///
/// ```gleam
/// http1.encode_request("127.0.0.1", "/v1/mailbox", "text/plain", <<"hi">>)
/// // -> <<"POST /v1/mailbox HTTP/1.1\r\nHost: 127.0.0.1\r\n...\r\n\r\nhi">>
/// ```
pub fn encode_request(
  host: String,
  path: String,
  content_type: String,
  body: BitArray,
) -> BitArray {
  let head =
    "POST "
    <> path
    <> " HTTP/1.1\r\nHost: "
    <> host
    <> "\r\nContent-Type: "
    <> content_type
    <> "\r\nContent-Length: "
    <> int.to_string(bit_array.byte_size(body))
    <> "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"

  bit_array.append(<<head:utf8>>, body)
}

/// A parser for one response whose body may be at most `max_body_bytes`.
///
/// ## Examples
///
/// ```gleam
/// let parser = http1.new_parser(1024)
/// let assert Ok(http1.NeedMore(_)) = http1.feed(parser, <<"HTTP/1.1 ">>)
/// ```
pub fn new_parser(max_body_bytes: Int) -> Parser {
  Parser(max_body_bytes:, phase: ReadingHead(seen: <<>>))
}

/// Gives the parser the next bytes from the peer.
///
/// Chunk boundaries are invisible: any split of the same bytes reaches the
/// same result, and an empty chunk changes nothing. An error is final; the
/// caller drops the connection and the parser. After `Complete` the parser
/// must not be fed again.
///
/// ## Examples
///
/// ```gleam
/// let parser = http1.new_parser(1024)
/// http1.feed(parser, <<"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok">>)
/// // -> Ok(Complete(Response(200, [#("content-length", "2")], <<"ok">>)))
/// ```
pub fn feed(parser: Parser, bytes: BitArray) -> Result(Progress, HttpError) {
  case parser.phase {
    ReadingHead(seen:) ->
      read_head(parser.max_body_bytes, bit_array.append(seen, bytes))

    ReadingBody(status:, headers:, declared:, chunks:, received:) ->
      read_body(
        parser.max_body_bytes,
        status,
        headers,
        declared,
        [bytes, ..chunks],
        received + bit_array.byte_size(bytes),
      )
  }
}

/// The value of the first header named `name`, which must be lowercase.
///
/// ## Examples
///
/// ```gleam
/// http1.header([#("location", "/x")], "location")
/// // -> Ok("/x")
/// ```
pub fn header(headers: Headers, name: String) -> Result(String, Nil) {
  list.key_find(headers, name)
}

/// Advances a parser that is still reading the head.
///
/// The head is complete once the first blank line has arrived. Until then
/// the only question is whether the head can still fit: a terminator found
/// beyond the bound, or no terminator with the bound already reached, means
/// it cannot, and the peer is cut off without buffering any more.
fn read_head(
  max_body_bytes: Int,
  seen: BitArray,
) -> Result(Progress, HttpError) {
  // Whether the blank line has arrived decides between parsing the head and
  // waiting for more of it.
  case find_terminator(seen, 0) {
    Ok(offset) -> {
      use _ <- result.try(check_head_size(offset + 4))
      use #(status, headers) <- result.try(parse_head(seen, offset))
      use declared <- result.try(declared_length(headers, max_body_bytes))

      // Whatever followed the blank line in this chunk is body bytes. They
      // are measured against the declared length like any later chunk, so
      // a peer cannot smuggle extra bytes in with the head.
      let rest = tail_after(seen, offset + 4)
      let received = bit_array.byte_size(rest)
      read_body(max_body_bytes, status, headers, declared, [rest], received)
    }

    Error(Nil) -> {
      use _ <- result.try(check_head_size(bit_array.byte_size(seen) + 1))
      Ok(NeedMore(Parser(max_body_bytes:, phase: ReadingHead(seen:))))
    }
  }
}

/// Refuses a head longer than `max_header_bytes`. A head still missing its
/// terminator is judged with one byte added, because the terminator has not
/// fully arrived and the head cannot end up shorter than what is here.
fn check_head_size(size: Int) -> Result(Nil, HttpError) {
  case size > max_header_bytes {
    True -> Error(HeaderBlockTooLarge)
    False -> Ok(Nil)
  }
}

/// Settles a parser whose head is parsed. Body bytes are exactly `declared`
/// long: fewer is "keep reading", more is an error, because with
/// `Connection: close` nothing may follow the body.
fn read_body(
  max_body_bytes: Int,
  status: Int,
  headers: Headers,
  declared: Int,
  chunks: List(BitArray),
  received: Int,
) -> Result(Progress, HttpError) {
  case int.compare(received, declared) {
    order.Gt -> Error(TrailingBytes)

    order.Eq ->
      Ok(
        Complete(Response(
          status:,
          headers:,
          body: bit_array.concat(list.reverse(chunks)),
        )),
      )

    order.Lt ->
      Ok(
        NeedMore(Parser(
          max_body_bytes:,
          phase: ReadingBody(status:, headers:, declared:, chunks:, received:),
        )),
      )
  }
}

/// Finds the first CRLF CRLF and returns the offset of its first byte.
fn find_terminator(bytes: BitArray, offset: Int) -> Result(Int, Nil) {
  case bytes {
    <<13, 10, 13, 10, _:bits>> -> Ok(offset)
    <<_, rest:bits>> -> find_terminator(rest, offset + 1)
    _ -> Error(Nil)
  }
}

/// Everything from `offset` on. The offset is within the array by
/// construction, so the fallback arm is unreachable.
fn tail_after(bytes: BitArray, offset: Int) -> BitArray {
  case bytes {
    <<_:bytes-size(offset), rest:bits>> -> rest
    _ -> <<>>
  }
}

/// Parses the head, the first `length` bytes of `seen`: a status line and
/// header lines separated by CRLF.
fn parse_head(
  seen: BitArray,
  length: Int,
) -> Result(#(Int, Headers), HttpError) {
  use head <- result.try(
    bit_array.slice(seen, 0, length)
    |> result.try(bit_array.to_string)
    |> result.replace_error(StatusLineMalformed),
  )

  // The status line comes first and every later line is a header.
  case string.split(head, "\r\n") {
    [status_line, ..lines] -> {
      use status <- result.try(parse_status_line(status_line))
      use _ <- result.try(check_line_count(lines))
      use headers <- result.try(list.try_map(lines, parse_header_line))
      Ok(#(status, headers))
    }

    // `string.split` always yields at least one element.
    [] -> Error(StatusLineMalformed)
  }
}

/// Refuses more than `max_header_lines` header lines. The walk stops one
/// element past the bound rather than counting the whole list.
fn check_line_count(lines: List(String)) -> Result(Nil, HttpError) {
  case list.drop(lines, max_header_lines) {
    [] -> Ok(Nil)
    [_, ..] -> Error(TooManyHeaderLines)
  }
}

/// `HTTP/1.1 NNN`, then either the end of the line or a space and a reason
/// phrase. A bare CR or LF inside the phrase is refused: it would mean the
/// peer's idea of the line break differs from ours.
fn parse_status_line(line: String) -> Result(Int, HttpError) {
  case line {
    "HTTP/1.1 " <> rest -> parse_status_code(rest)
    _ -> Error(StatusLineMalformed)
  }
}

/// The text after `HTTP/1.1 `: a three-digit code in 100 to 599 and an
/// optional reason phrase.
fn parse_status_code(rest: String) -> Result(Int, HttpError) {
  let #(code, reason) =
    string.split_once(rest, " ") |> result.unwrap(#(rest, ""))

  use _ <- result.try(check_single_line(reason, StatusLineMalformed))
  use status <- result.try(parse_digits(code, ThreeDigits, StatusLineMalformed))

  // Three digits can still fall outside the status classes HTTP defines.
  case status >= 100 && status <= 599 {
    True -> Ok(status)
    False -> Error(StatusLineMalformed)
  }
}

/// `name: value`. The name is a nonempty RFC 9110 token, so it has no space
/// before the colon (a request-smuggling vector) and nothing exotic. The
/// value is trimmed of spaces and tabs.
fn parse_header_line(line: String) -> Result(#(String, String), HttpError) {
  use #(name, value) <- result.try(
    string.split_once(line, ":") |> result.replace_error(HeaderMalformed),
  )
  use _ <- result.try(check_single_line(value, HeaderMalformed))

  // A name that is not a token is refused rather than normalised.
  case is_token(name) {
    True -> Ok(#(string.lowercase(name), trim_blanks(value)))
    False -> Error(HeaderMalformed)
  }
}

/// Refuses text holding a CR or LF. A line was split on CRLF, so any other
/// line-break byte left inside it is a peer disagreeing about framing.
fn check_single_line(text: String, error: HttpError) -> Result(Nil, HttpError) {
  case string.contains(text, "\r") || string.contains(text, "\n") {
    True -> Error(error)
    False -> Ok(Nil)
  }
}

/// Whether `name` is a nonempty run of RFC 9110 token characters.
fn is_token(name: String) -> Bool {
  name != ""
  && list.all(string.to_utf_codepoints(name), fn(codepoint) {
    is_token_character(string.utf_codepoint_to_int(codepoint))
  })
}

/// RFC 9110 `tchar`: letters, digits and the punctuation in
/// `token_punctuation`.
fn is_token_character(code: Int) -> Bool {
  { code >= 0x30 && code <= 0x39 }
  || { code >= 0x41 && code <= 0x5a }
  || { code >= 0x61 && code <= 0x7a }
  || list.contains(token_punctuation, code)
}

/// The code points of `!#$%&'*+-.^_`|~`.
const token_punctuation = [
  0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2a, 0x2b, 0x2d, 0x2e, 0x5e, 0x5f, 0x60,
  0x7c, 0x7e,
]

fn trim_blanks(value: String) -> String {
  value |> string.trim_start |> string.trim_end
}

/// How many digits a number must have.
type Width {
  /// Exactly three, as a status code.
  ThreeDigits

  /// One or more, as a content length.
  AnyDigits
}

/// Parses plain ASCII decimal digits and nothing else: no sign, no space,
/// no hex prefix. `int.parse` alone would accept a leading sign.
fn parse_digits(
  text: String,
  width: Width,
  error: HttpError,
) -> Result(Int, HttpError) {
  let codes =
    list.map(string.to_utf_codepoints(text), string.utf_codepoint_to_int)
  let all_digits = list.all(codes, fn(code) { code >= 0x30 && code <= 0x39 })

  // Every code point is one byte once they are all digits, so the byte
  // size is the digit count.
  let right_width = case width {
    AnyDigits -> text != ""
    ThreeDigits -> string.byte_size(text) == 3
  }

  // Anything but plain digits of the right width is refused, not repaired.
  case all_digits && right_width {
    True -> int.parse(text) |> result.replace_error(error)
    False -> Error(error)
  }
}

/// The one body-framing rule: no `Transfer-Encoding`, and exactly one
/// `Content-Length` holding a plain number no larger than the caller's
/// bound. Refusing on the header means an oversized body is never read.
fn declared_length(
  headers: Headers,
  max_body_bytes: Int,
) -> Result(Int, HttpError) {
  // Any `Transfer-Encoding` at all means the body is not framed by a
  // length, whatever the value says.
  use _ <- result.try(case header(headers, "transfer-encoding") {
    Ok(_) -> Error(TransferEncodingRefused)
    Error(Nil) -> Ok(Nil)
  })

  // Zero, one or several `Content-Length` headers: only one is valid.
  case list.filter(headers, fn(pair) { pair.0 == "content-length" }) {
    [] -> Error(ContentLengthMissing)
    [#(_, text)] -> check_declared(text, max_body_bytes)
    [_, _, ..] -> Error(ContentLengthDuplicated)
  }
}

/// A `Content-Length` value, which must be a number within the caller's
/// body bound.
fn check_declared(text: String, max_body_bytes: Int) -> Result(Int, HttpError) {
  use declared <- result.try(parse_digits(text, AnyDigits, ContentLengthInvalid))

  // A body over the caller's bound is refused from the header alone.
  case declared > max_body_bytes {
    True -> Error(BodyTooLarge)
    False -> Ok(declared)
  }
}
