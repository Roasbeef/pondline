//// The phase-0 spike: two sidecars on the real Tor network, one hosting an
//// onion service in front of a local echo server and the other connecting
//// to it, then a crash and a slow reader.
////
//// It runs only with `PONDLINE_TOR_NETWORK=1`. `tor_slow_test.erl` calls
//// `run_spike`, because EUnit's default timeout is shorter than a
//// bootstrap plus an onion service publication. Measurements go to
//// stderr as `SPIKE` lines, which is where the ADR's numbers come from.

import gleam/bit_array
import gleam/erlang/process
import gleam/int
import gleam/io
import tor
import tor/address
import tor/stream
import tor/support
import weft/poll

pub fn run_spike() -> Nil {
  case support.network_enabled() {
    True -> spike()
    False -> support.skip("network_spike")
  }
}

fn report(line: String) -> Nil {
  io.println_error("SPIKE " <> line)
}

fn seconds_since(started: Int) -> String {
  let ms = support.monotonic_ms() - started
  int.to_string(ms / 1000) <> "." <> int.to_string({ ms % 1000 } / 100) <> "s"
}

/// Connects with backoff until the onion service is reachable, which can
/// take a minute or more after its descriptor is published. `within` is the
/// whole budget in milliseconds.
fn connect_when_reachable(
  t: tor.Tor,
  onion: address.OnionAddress,
  port: address.Port,
  group: String,
  within: Int,
) -> stream.Stream {
  let attempt = fn() {
    case tor.connect(t, onion, port, group, 30_000) {
      Ok(s) -> poll.Done(s)
      Error(error) -> {
        report("connect retry: " <> string_of(error))
        poll.Retry
      }
    }
  }

  case poll.until(within:, every: 5000, attempt:) {
    poll.Answered(s) -> s
    poll.Failed(Nil) | poll.Expired ->
      panic as "onion service never became reachable"
  }
}

/// Prints every event the subscriber has received so far.
fn drain_events(events: process.Subject(tor.Event)) -> Nil {
  case process.receive(events, 0) {
    Ok(event) -> {
      report("host event: " <> string_of(event))
      drain_events(events)
    }
    Error(Nil) -> Nil
  }
}

@external(erlang, "gleam@string", "inspect")
fn string_of(value: a) -> String

fn spike() -> Nil {
  let dir1 = support.make_scratch_dir()
  let dir2 = support.make_scratch_dir()
  report(
    "binary bytes: " <> int.to_string(support.file_size(support.binary_path())),
  )

  let assert Ok(host_side) = tor.start(tor.config(support.binary_path(), dir1))
  let assert Ok(client_side) =
    tor.start(tor.config(support.binary_path(), dir2))
  let host_events = process.new_subject()
  let client_events = process.new_subject()
  tor.subscribe(host_side, host_events)
  tor.subscribe(client_side, client_events)

  // Both sidecars bootstrap; the times are cold starts on empty state.
  let t0 = support.monotonic_ms()
  let assert Ok(Nil) = tor.bootstrap(host_side, 300_000)
  report("bootstrap host (cold): " <> seconds_since(t0))
  let t1 = support.monotonic_ms()
  let assert Ok(Nil) = tor.bootstrap(client_side, 300_000)
  report("bootstrap client (cold): " <> seconds_since(t1))

  // The onion service forwards to a local echo server.
  let echo_port = support.start_echo()
  let t2 = support.monotonic_ms()
  let assert Ok(hosted) = tor.host_onion(host_side, "spike", echo_port, 60_000)
  report("host_onion returned: " <> seconds_since(t2))
  // The first connect, polled until the descriptor is fetchable.
  let assert Ok(port80) = address.port(80)
  let t3 = support.monotonic_ms()
  let s =
    connect_when_reachable(
      client_side,
      hosted.address,
      port80,
      "spike",
      300_000,
    )
  report("reachable (host_onion to first stream): " <> seconds_since(t2))
  report("last connect call: " <> seconds_since(t3))
  drain_events(host_events)

  // Bytes round-trip through two sidecars and the Tor network.
  let assert Ok(Nil) = stream.send(s, <<"hello pondline":utf8>>, 10_000)
  let assert Ok(echoed) = stream.recv(s, 1024, 60_000)
  assert bit_array.to_string(echoed) == Ok("hello pondline")
  report("round trip: ok")

  let assert Ok(host_pid) = tor.sidecar_pid(host_side)
  let assert Ok(client_pid) = tor.sidecar_pid(client_side)
  report("rss host kB: " <> int.to_string(support.rss_kb(host_pid)))
  report("rss client kB: " <> int.to_string(support.rss_kb(client_pid)))

  // Crash test: kill the client sidecar with the stream open. This VM
  // must survive, the stream must fail rather than hang, and the actor
  // must restart the sidecar.
  support.kill_nine(client_pid)
  let outcome = stream.recv(s, 1024, 10_000)
  report("recv after kill -9: " <> string_of(outcome))
  assert outcome != Error(stream.Timeout)
  assert outcome != Ok(<<>>)
  let restarted = fn(e) { e == tor.SidecarRestarted }
  assert support.wait_event(client_events, restarted, 30_000)
    == Ok(tor.SidecarRestarted)
  let assert Ok(new_pid) = tor.sidecar_pid(client_side)
  assert new_pid != client_pid
  report("restart after kill: ok, vm alive")

  // The restarted sidecar keeps its state directory, so a warm bootstrap
  // is fast and the same onion address is reachable again.
  let t4 = support.monotonic_ms()
  let assert Ok(Nil) = tor.bootstrap(client_side, 300_000)
  report("bootstrap client (warm, after restart): " <> seconds_since(t4))
  let t5 = support.monotonic_ms()
  let s2 =
    connect_when_reachable(
      client_side,
      hosted.address,
      port80,
      "spike",
      300_000,
    )
  report("first connect after restart: " <> seconds_since(t5))
  let assert Ok(Nil) = stream.send(s2, <<"again":utf8>>, 10_000)
  let assert Ok(again) = stream.recv(s2, 1024, 60_000)
  assert bit_array.to_string(again) == Ok("again")
  stream.close(s2)

  backpressure(host_side, client_side)

  tor.shutdown(host_side)
  tor.shutdown(client_side)
  support.remove_dir(dir1)
  support.remove_dir(dir2)
}

/// A reader that stops reading must stop the sender through the socket,
/// with no credit protocol: the send times out after a bounded number of
/// bytes, and resumes once the reader reads again.
fn backpressure(host_side: tor.Tor, client_side: tor.Tor) -> Nil {
  let #(sink_port, sink) = support.start_sink()
  let assert Ok(hosted) = tor.host_onion(host_side, "sink", sink_port, 60_000)
  let assert Ok(port80) = address.port(80)
  let s =
    connect_when_reachable(client_side, hosted.address, port80, "sink", 300_000)

  let chunk = <<0:size(65_536 * 8)>>
  let sent = send_until_stalled(s, chunk, 0)
  report("backpressure: sender stalled after bytes: " <> int.to_string(sent))
  assert sent < 64 * 1024 * 1024

  // Once the reader drains, the stalled path moves again.
  support.drain_sink(sink)
  let assert Ok(Nil) = stream.send(s, <<"resume":utf8>>, 60_000)
  report("backpressure: sender resumed after the reader drained")
  stream.close(s)
}

/// Sends chunks until a send times out, returning the bytes accepted.
fn send_until_stalled(s: stream.Stream, chunk: BitArray, total: Int) -> Int {
  case stream.send(s, chunk, 5000) {
    Ok(Nil) -> send_until_stalled(s, chunk, total + 65_536)
    Error(stream.Timeout) -> total
    Error(_) -> {
      panic as "stream failed instead of stalling"
    }
  }
}
