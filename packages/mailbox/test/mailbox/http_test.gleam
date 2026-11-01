import core/mailbox/codec
import core/mailbox/protocol
import core/time.{Instant}
import gleam/bit_array
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/string
import mailbox.{grant}
import mailbox/http
import mailbox/node
import mailbox/service
import mailbox/store
import mailbox/support.{cap, eid, now, padded, qid}
import simplifile

type Reply =
  Result(#(Int, List(#(String, String)), BitArray), Nil)

@external(erlang, "support_ffi", "http_exchange")
fn exchange(port: Int, raw: BitArray, timeout_ms: Int) -> Reply

@external(erlang, "support_ffi", "file_mode")
fn file_mode(path: String) -> Int

/// Starts a node with a fixed clock and one grant on a fresh database, and
/// an HTTP server on an ephemeral port. Returns the port and the grant.
fn start() {
  let path = support.fresh_path()
  let assert Ok(db) = store.open(path)
  let assert Ok(provision) = service.create_grant(db, 5, support.random(77))
  let assert Ok(Nil) = store.close(db)

  let config =
    node.Config(
      path:,
      sweep_period_ms: 60_000,
      clock: fn() { Instant(now.unix_seconds) },
      names: node.new_names(),
    )
  let assert Ok(#(_, running)) = node.start(config)
  let assert Ok(server) =
    http.start(running, http.Config(interface: "127.0.0.1", port: 0))

  #(server.port, provision)
}

fn raw(method: String, path: String, length: Int, body: BitArray) -> BitArray {
  let head =
    method
    <> " "
    <> path
    <> " HTTP/1.1\r\nHost: localhost\r\nContent-Type: "
    <> http.media_type
    <> "\r\nContent-Length: "
    <> int.to_string(length)
    <> "\r\n\r\n"

  <<head:utf8, body:bits>>
}

/// POSTs a body and returns the decoded protocol response, after checking
/// the headers every answer must carry.
fn call(port: Int, body: BitArray) -> protocol.Response {
  let assert Ok(#(200, headers, reply)) =
    exchange(
      port,
      raw("POST", "/v1/mailbox", bit_array.byte_size(body), body),
      5000,
    )

  assert list.key_find(headers, "content-type") == Ok(http.media_type)
  assert list.key_find(headers, "connection") == Ok("close")
  assert list.key_find(headers, "content-length")
    == Ok(int.to_string(bit_array.byte_size(reply)))

  let assert Ok(response) = codec.decode_response(reply)
  response
}

fn send(port: Int, request: protocol.Request) -> protocol.Response {
  call(port, codec.encode_request(request))
}

fn create(provision) -> protocol.Request {
  protocol.CreateQueue(
    provision:,
    queue: qid(1),
    read: cap(11),
    append: cap(12),
    admin: cap(13),
  )
}

fn append_request(n: Int) -> protocol.Request {
  protocol.Append(
    queue: qid(1),
    append: cap(12),
    envelope: eid(n),
    retention_deadline: time.add(now, 3600),
    ciphertext: padded(n),
  )
}

fn fetch_request(wait: Int) -> protocol.Request {
  protocol.Fetch(
    queue: qid(1),
    read: cap(11),
    wait_seconds: wait,
    max_envelopes: 10,
  )
}

pub fn every_request_kind_round_trips_over_http_test() {
  let #(port, provision) = start()

  assert send(port, create(provision)) == protocol.QueueCreated(qid(1))

  let assert protocol.Appended(_) = send(port, append_request(1))
  assert support.batch_ids(send(port, fetch_request(0))) == [1]

  assert send(
      port,
      protocol.Ack(queue: qid(1), read: cap(11), envelopes: [eid(1)]),
    )
    == protocol.Acked
  assert support.batch_ids(send(port, fetch_request(0))) == []

  assert send(port, protocol.DeleteQueue(queue: qid(1), admin: cap(13)))
    == protocol.QueueDeleted
}

pub fn a_wrong_capability_is_a_refusal_not_an_http_error_test() {
  let #(port, provision) = start()
  let assert protocol.QueueCreated(_) = send(port, create(provision))

  let wrong =
    protocol.Fetch(
      queue: qid(1),
      read: cap(99),
      wait_seconds: 0,
      max_envelopes: 10,
    )

  assert send(port, wrong) == protocol.Refused(protocol.Unauthorized)
}

pub fn an_undecodable_body_is_refused_malformed_test() {
  let #(port, _) = start()

  assert call(port, <<255, 255, 255>>) == protocol.Refused(protocol.Malformed)
}

pub fn a_truncated_request_is_refused_malformed_test() {
  let #(port, _) = start()
  let whole = codec.encode_request(fetch_request(0))
  let assert Ok(truncated) =
    bit_array.slice(whole, 0, bit_array.byte_size(whole) - 3)

  assert call(port, truncated) == protocol.Refused(protocol.Malformed)
}

pub fn a_future_version_is_refused_unsupported_test() {
  let #(port, _) = start()
  let assert <<0, 2, 0, 1, rest:bytes>> = codec.encode_request(fetch_request(0))

  assert call(port, <<0, 2, 0, 2, rest:bits>>)
    == protocol.Refused(protocol.UnsupportedVersion)
}

pub fn an_oversize_content_length_is_413_without_reading_the_body_test() {
  let #(port, _) = start()
  let length = codec.max_request_bytes() + 1

  // Only the head is sent. A server that waited for the body would hit the
  // client's timeout instead of answering.
  let assert Ok(#(413, headers, _)) =
    exchange(port, raw("POST", "/v1/mailbox", length, <<>>), 2000)

  assert list.key_find(headers, "connection") == Ok("close")
}

pub fn another_path_is_404_test() {
  let #(port, _) = start()

  let assert Ok(#(404, _, _)) =
    exchange(port, raw("POST", "/v1/other", 0, <<>>), 2000)
  let assert Ok(#(404, _, _)) =
    exchange(port, raw("GET", "/elsewhere", 0, <<>>), 2000)
}

pub fn another_method_on_the_route_is_405_test() {
  let #(port, _) = start()

  let assert Ok(#(405, headers, _)) =
    exchange(port, raw("GET", "/v1/mailbox", 0, <<>>), 2000)

  assert list.key_find(headers, "allow") == Ok("POST")
}

pub fn a_post_without_content_length_is_400_test() {
  let #(port, _) = start()
  let bare = <<"POST /v1/mailbox HTTP/1.1\r\nHost: localhost\r\n\r\n":utf8>>

  let assert Ok(#(400, _, _)) = exchange(port, bare, 2000)
}

pub fn a_long_poll_is_answered_by_an_append_on_another_connection_test() {
  let #(port, provision) = start()
  let assert protocol.QueueCreated(_) = send(port, create(provision))

  let answer = process.new_subject()
  let started = support.monotonic_ms()
  let _ =
    process.spawn(fn() { process.send(answer, send(port, fetch_request(10))) })

  // The poll is parked while this connection is served.
  process.sleep(500)
  let assert protocol.Appended(_) = send(port, append_request(7))

  let assert Ok(response) = process.receive(answer, 4000)
  assert support.batch_ids(response) == [7]
  assert support.monotonic_ms() - started < 4000
}

pub fn grant_writes_a_private_32_byte_file_and_never_overwrites_test() {
  let db = support.fresh_path()
  let out = db <> ".cap"
  let _ = simplifile.delete(out)

  assert grant(db, 3, out) == Ok(Nil)
  assert file_mode(out) == 0o600
  let assert Ok(bytes) = simplifile.read_bits(out)
  assert bit_array.byte_size(bytes) == 32

  let assert Error(message) = grant(db, 3, out)
  assert string.contains(message, "refusing to overwrite")
  assert simplifile.read_bits(out) == Ok(bytes)

  support.remove_files(db)
  let _ = simplifile.delete(out)
}
