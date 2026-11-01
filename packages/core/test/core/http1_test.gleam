import core/http1.{type Response, Complete, NeedMore, Response}
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import qcheck

const property_count = 300

/// The qcheck seed every property in this module draws from, fixed so the
/// gate is deterministic.
const property_seed = 29

const body_limit = 4096

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

// Feeds the chunks in order and returns the first terminal result. A
// parser still waiting after the last chunk is reported as `Ok(NeedMore)`.
fn run(
  chunks: List(BitArray),
  max_body: Int,
) -> Result(http1.Progress, http1.HttpError) {
  run_loop(http1.new_parser(max_body), chunks)
}

fn run_loop(
  parser: http1.Parser,
  chunks: List(BitArray),
) -> Result(http1.Progress, http1.HttpError) {
  case chunks {
    [] -> Ok(NeedMore(parser))
    [chunk, ..rest] ->
      case http1.feed(parser, chunk) {
        Ok(NeedMore(next)) -> run_loop(next, rest)
        other -> other
      }
  }
}

fn parse(bytes: BitArray) -> Result(Response, http1.HttpError) {
  case run([bytes], body_limit) {
    Ok(Complete(response)) -> Ok(response)
    Ok(NeedMore(_)) -> panic as "the response was incomplete"
    Error(error) -> Error(error)
  }
}

fn raw(text: String) -> BitArray {
  <<text:utf8>>
}

fn ok_with(headers: String, body: String) -> BitArray {
  raw(
    "HTTP/1.1 200 OK\r\n"
    <> headers
    <> "Content-Length: "
    <> int.to_string(string.byte_size(body))
    <> "\r\n\r\n"
    <> body,
  )
}

// A split of `bytes` into chunks at the given sizes; the final chunk takes
// whatever is left, and sizes of zero yield empty chunks.
fn split(bytes: BitArray, sizes: List(Int)) -> List(BitArray) {
  case sizes {
    [] -> [bytes]
    [size, ..rest] ->
      case bytes {
        <<head:bytes-size(size), tail:bits>> -> [head, ..split(tail, rest)]
        _ -> [bytes]
      }
  }
}

// ------------------------------------------------------------ examples

pub fn encode_request_frames_a_post_test() {
  let bytes =
    http1.encode_request("host.onion", "/v1/mailbox", "x/y", <<1, 2, 3>>)

  let head =
    "POST /v1/mailbox HTTP/1.1\r\nHost: host.onion\r\nContent-Type: x/y\r\n"
    <> "Content-Length: 3\r\nAccept-Encoding: identity\r\n"
    <> "Connection: close\r\n\r\n"

  assert bytes == bit_array.append(raw(head), <<1, 2, 3>>)
}

pub fn parses_a_simple_response_test() {
  assert parse(ok_with("X-Thing:  a b \r\n", "hello"))
    == Ok(
      Response(200, [#("x-thing", "a b"), #("content-length", "5")], <<
        "hello":utf8,
      >>),
    )
}

pub fn header_names_are_case_insensitive_test() {
  let assert Ok(response) =
    parse(raw("HTTP/1.1 200 OK\r\nCONTENT-length: 0\r\nLoCaTiOn: /x\r\n\r\n"))

  assert http1.header(response.headers, "location") == Ok("/x")
  assert response.body == <<>>
}

pub fn reason_phrase_is_optional_test() {
  let assert Ok(response) =
    parse(raw("HTTP/1.1 503\r\nContent-Length: 0\r\n\r\n"))

  assert response.status == 503
}

pub fn a_zero_length_body_completes_with_the_head_test() {
  assert run([raw("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")], 10)
    == Ok(Complete(Response(200, [#("content-length", "0")], <<>>)))
}

pub fn an_incomplete_response_needs_more_test() {
  let assert Ok(NeedMore(_)) = run([raw("HTTP/1.1 200 OK\r\nCont")], 10)
  let assert Ok(NeedMore(_)) =
    run([raw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe")], 10)
}

pub fn malformed_status_lines_are_refused_test() {
  let bad = [
    "HTTP/1.0 200 OK",
    "HTTP/2 200 OK",
    "http/1.1 200 OK",
    "HTTP/1.1 20 OK",
    "HTTP/1.1 2000 OK",
    "HTTP/1.1 abc OK",
    "HTTP/1.1 099 No",
    "HTTP/1.1 600 No",
    "HTTP/1.1  200 OK",
    "HTTP/1.1",
    "",
  ]

  list.each(bad, fn(line) {
    assert parse(raw(line <> "\r\nContent-Length: 0\r\n\r\n"))
      == Error(http1.StatusLineMalformed)
  })
}

pub fn transfer_encoding_is_refused_test() {
  assert parse(raw(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    ))
    == Error(http1.TransferEncodingRefused)

  assert parse(raw(
      "HTTP/1.1 200 OK\r\ntransfer-encoding: identity\r\nContent-Length: 0\r\n\r\n",
    ))
    == Error(http1.TransferEncodingRefused)
}

pub fn content_length_rules_test() {
  assert parse(raw("HTTP/1.1 200 OK\r\n\r\n"))
    == Error(http1.ContentLengthMissing)

  assert parse(raw(
      "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
    ))
    == Error(http1.ContentLengthDuplicated)

  list.each(["", "abc", "-1", "+1", "1,1", "1 1", "0x10", "1.0"], fn(value) {
    assert parse(raw(
        "HTTP/1.1 200 OK\r\nContent-Length: " <> value <> "\r\n\r\n",
      ))
      == Error(http1.ContentLengthInvalid)
  })
}

pub fn malformed_headers_are_refused_test() {
  let bad = [
    "NoColon",
    ": empty-name",
    "Bad Name: x",
    "Name : x",
    " folded: continuation",
    "Bad\rName: x",
    "Name: a\rb",
  ]

  list.each(bad, fn(line) {
    assert parse(raw(
        "HTTP/1.1 200 OK\r\n" <> line <> "\r\nContent-Length: 0\r\n\r\n",
      ))
      == Error(http1.HeaderMalformed)
  })
}

pub fn a_head_that_is_not_text_is_refused_test() {
  assert parse(<<"HTTP/1.1 200 OK\r\nX: ":utf8, 255, "\r\n\r\n":utf8>>)
    == Error(http1.StatusLineMalformed)
}

pub fn bytes_after_the_body_are_refused_test() {
  assert parse(ok_with("", "abc") |> bit_array.append(<<"x":utf8>>))
    == Error(http1.TrailingBytes)
}

pub fn extra_bytes_in_a_later_chunk_are_refused_test() {
  let head = raw("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab")

  assert run([head, raw("cd")], 10) == Error(http1.TrailingBytes)
}

// ------------------------------------------------------------ bounds

pub fn the_header_block_bound_is_exact_test() {
  // A head of exactly `max_header_bytes` is accepted and one byte more is
  // refused. The padding header's value sets the total.
  let prefix = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX: "
  let suffix = "\r\n\r\n"
  let fixed = string.byte_size(prefix) + string.byte_size(suffix)
  let at_bound =
    prefix <> string.repeat("a", http1.max_header_bytes - fixed) <> suffix
  let over =
    prefix <> string.repeat("a", http1.max_header_bytes - fixed + 1) <> suffix

  assert string.byte_size(at_bound) == http1.max_header_bytes
  let assert Ok(_) = parse(raw(at_bound))
  assert parse(raw(over)) == Error(http1.HeaderBlockTooLarge)
}

pub fn the_header_line_bound_is_exact_test() {
  let lines = fn(count) {
    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
    <> string.repeat("A: b\r\n", count - 1)
    <> "\r\n"
  }

  let assert Ok(_) = parse(raw(lines(http1.max_header_lines)))
  assert parse(raw(lines(http1.max_header_lines + 1)))
    == Error(http1.TooManyHeaderLines)
}

pub fn the_body_bound_is_exact_test() {
  let framed = fn(length) {
    raw(
      "HTTP/1.1 200 OK\r\nContent-Length: "
      <> int.to_string(length)
      <> "\r\n\r\n",
    )
  }

  let assert Ok(NeedMore(_)) = run([framed(10)], 10)
  assert run([framed(11)], 10) == Error(http1.BodyTooLarge)
}

pub fn an_endless_header_line_is_cut_off_at_the_bound_test() {
  // The peer never sends a terminator. The parser must fail on the chunk
  // that reaches the bound, not keep accepting kilobytes.
  let chunk = raw(string.repeat("a", 1024))
  let start = raw("HTTP/1.1 200 OK\r\nX: ")
  let chunks = [start, ..list.repeat(chunk, 16)]

  assert run(chunks, 10) == Error(http1.HeaderBlockTooLarge)

  // Seven kilobytes of it is still within the bound, so still waiting.
  let assert Ok(NeedMore(_)) = run([start, ..list.repeat(chunk, 7)], 10)
}

pub fn a_declared_oversized_body_is_refused_before_it_arrives_test() {
  let head = raw("HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n")

  assert run([head], body_limit) == Error(http1.BodyTooLarge)
}

// ------------------------------------------------------------ properties

fn header_names() -> qcheck.Generator(String) {
  qcheck.from_generators(qcheck.return("x-a"), [
    qcheck.return("X-Other-Header"),
    qcheck.return("Location"),
    qcheck.return("Server"),
  ])
}

fn header_values() -> qcheck.Generator(String) {
  qcheck.string_from(qcheck.bounded_codepoint(0x61, 0x7a))
}

// A valid response: a status, some extra headers, a body.
fn valid_responses() -> qcheck.Generator(
  #(Int, List(#(String, String)), BitArray),
) {
  qcheck.tuple3(
    qcheck.bounded_int(200, 599),
    qcheck.generic_list(
      elements_from: qcheck.tuple2(header_names(), header_values()),
      length_from: qcheck.bounded_int(0, 5),
    ),
    qcheck.generic_byte_aligned_bit_array(
      values_from: qcheck.bounded_int(0, 255),
      byte_size_from: qcheck.from_generators(qcheck.bounded_int(0, 40), [
        qcheck.bounded_int(0, 600),
      ]),
    ),
  )
}

fn render(
  status: Int,
  headers: List(#(String, String)),
  body: BitArray,
) -> BitArray {
  let head =
    "HTTP/1.1 "
    <> int.to_string(status)
    <> " Reason\r\n"
    <> string.concat(
      list.map(headers, fn(pair) { pair.0 <> ": " <> pair.1 <> "\r\n" }),
    )
    <> "Content-Length: "
    <> int.to_string(bit_array.byte_size(body))
    <> "\r\n\r\n"

  bit_array.append(raw(head), body)
}

fn chunk_sizes() -> qcheck.Generator(List(Int)) {
  qcheck.generic_list(
    elements_from: qcheck.bounded_int(0, 30),
    length_from: qcheck.bounded_int(0, 40),
  )
}

pub fn any_split_of_a_valid_response_parses_identically_test() {
  property(qcheck.tuple2(valid_responses(), chunk_sizes()), fn(input) {
    let #(#(status, headers, body), sizes) = input
    let bytes = render(status, headers, body)

    let whole = run([bytes], body_limit)
    let chunked = run(split(bytes, sizes), body_limit)

    // The whole response is also what the generator meant to build.
    let expected_headers =
      list.append(
        list.map(headers, fn(pair) { #(string.lowercase(pair.0), pair.1) }),
        [#("content-length", int.to_string(bit_array.byte_size(body)))],
      )
    let expected = Ok(Complete(Response(status, expected_headers, body)))

    assert whole == expected
    assert chunked == expected
  })
}

pub fn one_byte_at_a_time_parses_identically_test() {
  property(valid_responses(), fn(input) {
    let #(status, headers, body) = input
    let bytes = render(status, headers, body)
    let single = split(bytes, list.repeat(1, bit_array.byte_size(bytes)))

    assert run(single, body_limit) == run([bytes], body_limit)
  })
}

pub fn random_bytes_never_crash_test() {
  let noise =
    qcheck.generic_byte_aligned_bit_array(
      values_from: qcheck.from_generators(qcheck.bounded_int(0, 255), [
        qcheck.bounded_int(9, 13),
        qcheck.bounded_int(0x20, 0x7e),
      ]),
      byte_size_from: qcheck.bounded_int(0, 300),
    )

  property(qcheck.tuple2(noise, chunk_sizes()), fn(input) {
    let #(bytes, sizes) = input

    // Noise alone, and noise behind a plausible status line, so the head
    // parser sees header-shaped garbage as well as non-text.
    let framed = bit_array.append(raw("HTTP/1.1 200 OK\r\n"), bytes)

    let _ = run(split(bytes, sizes), body_limit)
    let _ = run(split(framed, sizes), body_limit)
    Nil
  })
}

pub fn the_body_bound_is_enforced_at_bound_plus_one_test() {
  property(qcheck.bounded_int(0, 200), fn(bound) {
    let framed = fn(length) {
      raw(
        "HTTP/1.1 200 OK\r\nContent-Length: "
        <> int.to_string(length)
        <> "\r\n\r\n",
      )
    }
    let body = fn(length) {
      bit_array.append(framed(length), <<0:size(length * 8)>>)
    }

    let assert Ok(Complete(_)) = run([body(bound)], bound)
    assert run([framed(bound + 1)], bound) == Error(http1.BodyTooLarge)
  })
}
