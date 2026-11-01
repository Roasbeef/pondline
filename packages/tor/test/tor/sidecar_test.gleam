import gleam/bit_array
import gleam/erlang/process
import tor
import tor/address
import tor/internal/ffi_socket
import tor/stream
import tor/support

pub fn missing_binary_fails_to_start_test() {
  let cfg = tor.config("/nonexistent/reedwire-tor", "/tmp/rwtor-none")
  assert tor.start(cfg) == Error(tor.StartFailed(tor.SpawnFailed))
}

pub fn bad_nickname_is_refused_before_the_sidecar_test() {
  use t, _ <- support.with_sidecar
  assert tor.host_onion(t, "", 8080, 1000) == Error(tor.BadNickname)
}

/// The sidecar refuses a clearnet target on the wire, before any Tor
/// work, even though this package's types cannot express one: the second
/// wall of spec section 13.1.
pub fn sidecar_refuses_clearnet_test() {
  use _, dir <- support.with_sidecar
  let assert Ok(sock) = ffi_socket.connect_unix(dir <> "/connect.sock", 2000)
  let assert Ok(Nil) =
    ffi_socket.send(sock, <<"CONNECT example.com:80 g\n":utf8>>, 2000)
  let assert Ok(reply) = ffi_socket.recv(sock, 512, 2000)
  assert bit_array.to_string(reply) == Ok("ERR not-onion\n")
  let _ = ffi_socket.close(sock)
  Nil
}

pub fn sidecar_refuses_garbage_lines_test() {
  use _, dir <- support.with_sidecar
  let assert Ok(sock) = ffi_socket.connect_unix(dir <> "/connect.sock", 2000)
  let assert Ok(Nil) = ffi_socket.send(sock, <<"hello\n":utf8>>, 2000)
  let assert Ok(reply) = ffi_socket.recv(sock, 512, 2000)
  assert bit_array.to_string(reply) == Ok("ERR bad-request\n")
  let _ = ffi_socket.close(sock)
  Nil
}

/// An onion target before bootstrap is refused with a typed error rather
/// than starting a bootstrap as a side effect.
pub fn connect_before_bootstrap_is_refused_test() {
  use t, _ <- support.with_sidecar
  let assert Ok(onion) =
    address.parse_onion(
      "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    )
  let assert Ok(port) = address.port(80)
  assert tor.connect(t, onion, port, "g", 5000)
    == Error(tor.OpenFailed(stream.Refused(stream.NotBootstrapped)))
}

pub fn invalid_isolation_group_is_refused_test() {
  use t, _ <- support.with_sidecar
  let assert Ok(onion) =
    address.parse_onion(
      "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    )
  let assert Ok(port) = address.port(80)
  assert tor.connect(t, onion, port, "has space", 1000)
    == Error(tor.OpenFailed(stream.InvalidIsolationGroup))
  assert tor.connect(t, onion, port, "", 1000)
    == Error(tor.OpenFailed(stream.InvalidIsolationGroup))
}

pub fn shutdown_stops_the_sidecar_test() {
  let dir = support.make_scratch_dir()
  let assert Ok(t) = tor.start(tor.config(support.binary_path(), dir))
  let assert Ok(pid) = tor.sidecar_pid(t)
  assert support.pid_alive(pid)
  tor.shutdown(t)
  assert support.wait_until(fn() { !support.pid_alive(pid) }, 5000)
  support.remove_dir(dir)
}

/// The owner dying, with no `Shutdown` frame sent, closes the port and so
/// the sidecar's stdin; the sidecar must exit on that end of file alone.
pub fn sidecar_exits_when_its_port_closes_test() {
  let dir = support.make_scratch_dir()
  let report = process.new_subject()
  let owner =
    process.spawn_unlinked(fn() {
      let assert Ok(t) = tor.start(tor.config(support.binary_path(), dir))
      let assert Ok(pid) = tor.sidecar_pid(t)
      process.send(report, pid)
      process.sleep_forever()
    })
  let assert Ok(pid) = process.receive(report, 10_000)
  assert support.pid_alive(pid)

  // Killing the owner takes its linked actor, which owns the port.
  process.kill(owner)
  assert support.wait_until(fn() { !support.pid_alive(pid) }, 5000)
  support.remove_dir(dir)
}

/// `kill -9` on the sidecar must leave this VM running; the actor notices,
/// restarts it, and tells subscribers.
pub fn actor_restarts_a_killed_sidecar_test() {
  use t, _ <- support.with_sidecar
  let events = process.new_subject()
  tor.subscribe(t, events)
  let assert Ok(pid) = tor.sidecar_pid(t)

  support.kill_nine(pid)

  let died = fn(e) {
    case e {
      tor.SidecarDied(_) -> True
      _ -> False
    }
  }
  let restarted = fn(e) { e == tor.SidecarRestarted }
  assert support.wait_event(events, died, 10_000) != Error(Nil)
  assert support.wait_event(events, restarted, 20_000)
    == Ok(tor.SidecarRestarted)
  let assert Ok(new_pid) = tor.sidecar_pid(t)
  assert new_pid != pid
  assert support.pid_alive(new_pid)
}
