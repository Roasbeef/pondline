import core/capability.{type Capability}
import core/endpoint.{type Endpoint, Loopback, Onion, TorOnly, TorOrLoopback}
import core/envelope
import core/http1
import core/id.{type Id}
import core/limits
import core/mailbox/codec
import core/mailbox/protocol.{
  type Request, type Response, Ack, Acked, Append, AppendReceipt, Appended,
  Batch, CreateQueue, DeleteQueue, Fetch, QueueCreated, QueueDeleted, Refused,
  Unauthorized,
}
import core/time
import daemon/fake_server.{type Server}
import daemon/mailbox_client.{
  CarrierRefused, ConnectionClosedEarly, DialFailed, HttpStatus, MalformedBody,
  MalformedHttp, TimedOut,
}
import daemon/transport.{type Connection, Connection}
import gleam/bit_array
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/string

fn queue_id() -> Id(id.Queue) {
  let assert Ok(value) = id.from_bytes(<<7:128>>)
  value
}

fn envelope_id() -> Id(id.Envelope) {
  let assert Ok(value) = id.from_bytes(<<9:128>>)
  value
}

fn cap() -> Capability(authority) {
  let assert Ok(value) = capability.from_bytes(<<5:size(256)>>)
  value
}

fn loopback(server: Server) -> Endpoint {
  let assert Ok(port) = endpoint.port(server.port)
  Loopback(port)
}

fn dialer(policy: endpoint.CarrierPolicy) -> transport.Dialer {
  transport.new_dialer(policy, fn(_address, _port, _group, _timeout) {
    Error(transport.ConnectFailed)
  })
}

fn call(
  server: Server,
  request: Request,
  timeout_ms: Int,
) -> Result(Response, mailbox_client.ClientError) {
  mailbox_client.call(
    dialer(TorOrLoopback),
    loopback(server),
    mailbox_client.isolation_group(queue_id()),
    request,
    timeout_ms,
  )
}

fn one_of_each() -> List(#(Request, Response)) {
  let assert Ok(padded) = envelope.pad(<<"sealed":utf8>>)
  let receipt =
    AppendReceipt(
      queue: queue_id(),
      envelope: envelope_id(),
      digest: <<1:256>>,
      retention_deadline: time.Instant(unix_seconds: 1000),
    )

  [
    #(
      CreateQueue(
        provision: cap(),
        queue: queue_id(),
        read: cap(),
        append: cap(),
        admin: cap(),
      ),
      QueueCreated(queue_id()),
    ),
    #(
      Append(
        queue: queue_id(),
        append: cap(),
        envelope: envelope_id(),
        retention_deadline: time.Instant(unix_seconds: 1000),
        ciphertext: padded,
      ),
      Appended(receipt),
    ),
    #(
      Fetch(queue: queue_id(), read: cap(), wait_seconds: 0, max_envelopes: 4),
      Batch([]),
    ),
    #(Ack(queue: queue_id(), read: cap(), envelopes: [envelope_id()]), Acked),
    #(DeleteQueue(queue: queue_id(), admin: cap()), QueueDeleted),
    #(
      DeleteQueue(queue: queue_id(), admin: cap()),
      Refused(reason: Unauthorized),
    ),
  ]
}

// ------------------------------------------------------------ round trips

pub fn every_request_kind_round_trips_test() {
  list.each(one_of_each(), fn(pair) {
    let #(request, response) = pair
    let server = fake_server.start(fn(_) { fake_server.mailbox_ok(response) })

    assert call(server, request, 3000) == Ok(response)

    // The server decoded exactly the request that was sent.
    let assert Ok(seen) = fake_server.next_seen(server)
    assert seen.request == Ok(request)
  })
}

pub fn the_request_is_framed_as_the_binding_says_test() {
  let server = fake_server.start(fn(_) { fake_server.mailbox_ok(Acked) })
  let request = Ack(queue: queue_id(), read: cap(), envelopes: [])

  let assert Ok(Acked) = call(server, request, 3000)
  let assert Ok(seen) = fake_server.next_seen(server)

  assert string.starts_with(seen.head, "POST /v1/mailbox HTTP/1.1\r\n")
  assert string.contains(seen.head, "\r\nHost: 127.0.0.1\r\n")
  assert string.contains(
    seen.head,
    "\r\nContent-Type: application/vnd.pondline.mailbox+tlv\r\n",
  )
  assert string.contains(seen.head, "\r\nConnection: close")
}

// ------------------------------------------------------------ failures

pub fn a_redirect_is_an_error_and_is_not_followed_test() {
  let server =
    fake_server.start(fn(_) {
      fake_server.Send(<<
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/elsewhere\r\n":utf8,
        "Content-Length: 0\r\n\r\n":utf8,
      >>)
    })
  let request = DeleteQueue(queue: queue_id(), admin: cap())

  assert call(server, request, 3000) == Error(HttpStatus(302))

  // One connection was made and no second request followed the redirect.
  assert fake_server.connection_count(server) == 1
}

pub fn other_statuses_are_errors_test() {
  let server =
    fake_server.start(fn(_) {
      fake_server.Send(<<
        "HTTP/1.1 503 Busy\r\nContent-Length: 0\r\n\r\n":utf8,
      >>)
    })

  assert call(server, DeleteQueue(queue: queue_id(), admin: cap()), 3000)
    == Error(HttpStatus(503))
}

pub fn an_oversized_response_is_cut_off_test() {
  // The head declares one byte more than the codec's response bound, so the
  // client refuses on the header and never waits for the body.
  let declared = codec.max_response_bytes() + 1
  let server =
    fake_server.start(fn(_) {
      fake_server.Send(<<
        "HTTP/1.1 200 OK\r\nContent-Length: ":utf8,
        int.to_string(declared):utf8,
        "\r\n\r\n":utf8,
      >>)
    })

  assert call(server, DeleteQueue(queue: queue_id(), admin: cap()), 3000)
    == Error(MalformedHttp(http1.BodyTooLarge))
}

pub fn a_server_that_never_answers_times_out_test() {
  let server = fake_server.start(fn(_) { fake_server.Hang })

  assert call(server, DeleteQueue(queue: queue_id(), admin: cap()), 300)
    == Error(TimedOut)
}

pub fn a_chunked_response_is_refused_test() {
  let server =
    fake_server.start(fn(_) {
      fake_server.Send(<<
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n":utf8,
      >>)
    })

  assert call(server, DeleteQueue(queue: queue_id(), admin: cap()), 3000)
    == Error(MalformedHttp(http1.TransferEncodingRefused))
}

pub fn closing_before_a_response_is_reported_test() {
  let server = fake_server.start(fn(_) { fake_server.Hangup })

  assert call(server, DeleteQueue(queue: queue_id(), admin: cap()), 3000)
    == Error(ConnectionClosedEarly)
}

pub fn a_truncated_body_is_reported_test() {
  let server =
    fake_server.start(fn(_) {
      fake_server.Send(<<
        "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nabc":utf8,
      >>)
    })

  assert call(server, DeleteQueue(queue: queue_id(), admin: cap()), 3000)
    == Error(ConnectionClosedEarly)
}

pub fn a_body_that_is_not_a_response_is_reported_test() {
  let server =
    fake_server.start(fn(_) {
      fake_server.Send(fake_server.http_ok(<<1, 2, 3>>))
    })

  let assert Error(MalformedBody(_)) =
    call(server, DeleteQueue(queue: queue_id(), admin: cap()), 3000)
}

pub fn nothing_listening_is_a_dial_failure_test() {
  // Port 1 is privileged and nothing in a test listens on it, so the dial is
  // refused; the started server only supplies a value to override.
  let server = fake_server.start(fn(_) { fake_server.Hangup })
  let closed = fake_server.Server(..server, port: 1)

  assert call(closed, DeleteQueue(queue: queue_id(), admin: cap()), 3000)
    == Error(DialFailed)
}

// ------------------------------------------------------------ the policy

pub fn loopback_under_tor_only_never_connects_test() {
  let server = fake_server.start(fn(_) { fake_server.mailbox_ok(Acked) })

  let result =
    mailbox_client.call(
      dialer(TorOnly),
      loopback(server),
      "group",
      DeleteQueue(queue: queue_id(), admin: cap()),
      3000,
    )

  assert result == Error(CarrierRefused)

  // The listener never saw a connection: the refusal came before any socket.
  assert fake_server.connection_count(server) == 0
}

// ------------------------------------------------------------ the carrier

fn onion() -> Endpoint {
  let assert Ok(address) =
    endpoint.parse_onion(string.repeat("a", 55) <> "d.onion")
  let assert Ok(port) = endpoint.port(80)
  Onion(address, port)
}

// An in-memory connection that answers every request with `reply`, chunked
// into `size`-byte reads, so the client is exercised without any socket.
fn memory_connection(reply: BitArray, size: Int) -> Connection {
  let inbox = process.new_subject()
  feed(inbox, reply, size)

  Connection(
    send: fn(_) { Ok(Nil) },
    receive: fn(_max, timeout) {
      case process.receive(inbox, timeout) {
        Ok(bytes) -> Ok(bytes)
        Error(Nil) -> Error(transport.TimedOut)
      }
    },
    close: fn() { Nil },
  )
}

fn feed(inbox: process.Subject(BitArray), rest: BitArray, size: Int) -> Nil {
  case bit_array.byte_size(rest) <= size {
    True -> process.send(inbox, rest)
    False -> {
      let assert <<head:bytes-size(size), tail:bits>> = rest
      process.send(inbox, head)
      feed(inbox, tail, size)
    }
  }
}

pub fn an_injected_onion_carrier_gets_the_isolation_group_test() {
  let seen = process.new_subject()
  let reply = fake_server.http_ok(codec.encode_response(Acked))

  let dialer =
    transport.new_dialer(TorOnly, fn(address, port, group, _timeout) {
      process.send(seen, #(
        endpoint.onion_host(address),
        endpoint.port_number(port),
        group,
      ))
      Ok(memory_connection(reply, 7))
    })

  let result =
    mailbox_client.call(
      dialer,
      onion(),
      mailbox_client.isolation_group(queue_id()),
      Ack(queue: queue_id(), read: cap(), envelopes: []),
      3000,
    )

  assert result == Ok(Acked)
  assert process.receive(seen, 0)
    == Ok(#(string.repeat("a", 55) <> "d.onion", 80, id.to_hex(queue_id())))
}

// ------------------------------------------------------------ deadlines

pub fn a_long_poll_gets_its_wait_plus_a_margin_test() {
  let fetch = fn(wait) {
    Fetch(queue: queue_id(), read: cap(), wait_seconds: wait, max_envelopes: 1)
  }

  assert mailbox_client.effective_timeout(fetch(20), 1000)
    == 20_000 + mailbox_client.long_poll_margin_ms

  // A caller's longer budget is kept.
  assert mailbox_client.effective_timeout(fetch(1), 60_000) == 60_000

  // A wait beyond the protocol limit is clamped, as the mailbox clamps it.
  assert mailbox_client.effective_timeout(fetch(1_000_000), 1000)
    == limits.long_poll_seconds * 1000 + mailbox_client.long_poll_margin_ms

  // Other operations use the caller's budget as given.
  assert mailbox_client.effective_timeout(
      DeleteQueue(queue: queue_id(), admin: cap()),
      1234,
    )
    == 1234
}
