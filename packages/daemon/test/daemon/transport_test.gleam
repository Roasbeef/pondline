import core/endpoint.{Loopback, TorOnly, TorOrLoopback}
import daemon/fake_server
import daemon/transport

fn refuse_onion(_address, _port, _group, _timeout) {
  Error(transport.ConnectFailed)
}

fn loopback_to(server: fake_server.Server) -> endpoint.Endpoint {
  let assert Ok(port) = endpoint.port(server.port)
  Loopback(port)
}

pub fn tor_only_refuses_loopback_before_dialling_test() {
  let server = fake_server.start(fn(_) { fake_server.Hangup })
  let dialer = transport.new_dialer(TorOnly, refuse_onion)

  let assert Error(transport.CarrierNotPermitted) =
    transport.dial(dialer, loopback_to(server), "group", 1000)

  assert fake_server.connection_count(server) == 0
}

pub fn a_permitted_loopback_endpoint_connects_and_moves_bytes_test() {
  let server =
    fake_server.start(fn(_) {
      fake_server.Send(<<"HTTP/1.1 204\r\nContent-Length: 0\r\n\r\n":utf8>>)
    })
  let dialer = transport.new_dialer(TorOrLoopback, refuse_onion)

  let assert Ok(connection) =
    transport.dial(dialer, loopback_to(server), "group", 1000)
  let assert Ok(Nil) =
    transport.send(connection, <<
      "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n":utf8,
    >>)
  let assert Ok(reply) = transport.receive(connection, 1024, 2000)
  let assert Error(transport.Closed) = transport.receive(connection, 1024, 2000)
  transport.close(connection)

  assert reply == <<"HTTP/1.1 204\r\nContent-Length: 0\r\n\r\n":utf8>>
}

pub fn a_silent_peer_times_out_a_receive_test() {
  let server = fake_server.start(fn(_) { fake_server.Hang })
  let dialer = transport.new_dialer(TorOrLoopback, refuse_onion)

  let assert Ok(connection) =
    transport.dial(dialer, loopback_to(server), "group", 1000)
  let assert Ok(Nil) =
    transport.send(connection, <<
      "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n":utf8,
    >>)
  let assert Error(transport.TimedOut) =
    transport.receive(connection, 1024, 150)
  transport.close(connection)
}
