//// A loopback mailbox server for tests, and only for tests.
////
//// It listens on an OS-chosen port, accepts connections one after another,
//// reads one HTTP request from each, decodes the body with the real codec,
//// and lets the test script decide what to send back. Every accepted
//// connection is announced on a subject so a test can assert that a call
//// did, or did not, reach the network.

import core/mailbox/codec
import core/mailbox/protocol.{type Request, type Response}
import gleam/bit_array
import gleam/bytes_tree
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/string
import glisten/socket.{type Socket}
import glisten/socket/options
import glisten/tcp

/// What the server does after reading a request.
pub type Reply {
  /// Send these bytes and close the connection.
  Send(BitArray)

  /// Read the request and then say nothing, holding the connection open.
  Hang

  /// Close without sending anything.
  Hangup
}

/// What a test learns about one request.
pub type Seen {
  Seen(head: String, request: Result(Request, codec.CodecError))
}

/// A running server.
pub type Server {
  Server(port: Int, connections: Subject(Nil), requests: Subject(Seen))
}

/// Starts a server whose reply to each request is `script(seen)`.
pub fn start(script: fn(Seen) -> Reply) -> Server {
  let assert Ok(listener) = tcp.listen(0, [options.ActiveMode(options.Passive)])
    as "the loopback listen socket opens"
  let assert Ok(#(_, port)) = tcp.sockname(listener)
    as "a listening socket has a name"

  let connections = process.new_subject()
  let requests = process.new_subject()

  process.spawn(fn() { accept_loop(listener, script, connections, requests) })
  Server(port:, connections:, requests:)
}

/// Counts the connections announced so far, without waiting.
pub fn connection_count(server: Server) -> Int {
  drain(server.connections, 0)
}

/// The next request seen, waiting briefly for it.
pub fn next_seen(server: Server) -> Result(Seen, Nil) {
  process.receive(server.requests, 1000)
}

/// A complete `200` response around a body.
pub fn http_ok(body: BitArray) -> BitArray {
  bit_array.append(
    <<
      "HTTP/1.1 200 OK\r\nContent-Length: ":utf8,
      int.to_string(bit_array.byte_size(body)):utf8,
      "\r\n\r\n":utf8,
    >>,
    body,
  )
}

/// A `200` carrying an encoded mailbox response.
pub fn mailbox_ok(response: Response) -> Reply {
  Send(http_ok(codec.encode_response(response)))
}

fn drain(subject: Subject(Nil), count: Int) -> Int {
  // A short wait lets a connection that is in flight announce itself, so a
  // zero really means that nothing connected.
  case process.receive(subject, 200) {
    Ok(Nil) -> drain(subject, count + 1)
    Error(Nil) -> count
  }
}

fn accept_loop(
  listener: socket.ListenSocket,
  script: fn(Seen) -> Reply,
  connections: Subject(Nil),
  requests: Subject(Seen),
) -> Nil {
  case tcp.accept(listener) {
    Ok(connection) -> {
      process.send(connections, Nil)

      // One connection at a time is enough: each test makes one call.
      serve(connection, script, requests)
      accept_loop(listener, script, connections, requests)
    }

    Error(_) -> Nil
  }
}

fn serve(
  connection: Socket,
  script: fn(Seen) -> Reply,
  requests: Subject(Seen),
) -> Nil {
  case read_request(connection, <<>>) {
    Ok(seen) -> {
      process.send(requests, seen)

      // Each reply decides how the connection ends.
      case script(seen) {
        Send(bytes) -> {
          let _ = tcp.send(connection, bytes_tree.from_bit_array(bytes))
          let _ = tcp.close(connection)
          Nil
        }

        Hang -> {
          process.sleep(10_000)
          let _ = tcp.close(connection)
          Nil
        }

        Hangup -> {
          let _ = tcp.close(connection)
          Nil
        }
      }
    }

    Error(Nil) -> {
      let _ = tcp.close(connection)
      Nil
    }
  }
}

// Reads until the head and the declared body are both here.
fn read_request(connection: Socket, seen: BitArray) -> Result(Seen, Nil) {
  case split_head(seen) {
    Ok(#(head, body)) -> {
      let length = content_length(head)

      case bit_array.byte_size(body) >= length {
        True -> {
          let assert Ok(exact) = bit_array.slice(body, 0, length)
            as "the body holds at least `length` bytes"
          Ok(Seen(head:, request: codec.decode_request(exact)))
        }

        False -> read_more(connection, seen)
      }
    }

    Error(Nil) -> read_more(connection, seen)
  }
}

fn read_more(connection: Socket, seen: BitArray) -> Result(Seen, Nil) {
  case tcp.receive_timeout(connection, 0, 2000) {
    Ok(bytes) -> read_request(connection, bit_array.append(seen, bytes))
    Error(_) -> Error(Nil)
  }
}

fn split_head(bytes: BitArray) -> Result(#(String, BitArray), Nil) {
  split_loop(bytes, 0)
}

fn split_loop(
  bytes: BitArray,
  offset: Int,
) -> Result(#(String, BitArray), Nil) {
  case bytes {
    <<_:bytes-size(offset), 13, 10, 13, 10, rest:bits>> -> {
      let assert Ok(head) = bit_array.slice(bytes, 0, offset)
        as "the head precedes the terminator"
      let assert Ok(text) = bit_array.to_string(head)
        as "the client writes an ASCII head"
      Ok(#(text, rest))
    }

    _ ->
      case bit_array.byte_size(bytes) > offset + 4 {
        True -> split_loop(bytes, offset + 1)
        False -> Error(Nil)
      }
  }
}

fn content_length(head: String) -> Int {
  let lines = string.split(string.lowercase(head), "\r\n")
  let values =
    list.filter_map(lines, fn(line) {
      case line {
        "content-length: " <> value -> int.parse(value)
        _ -> Error(Nil)
      }
    })

  case values {
    [value] -> value
    _ -> 0
  }
}
