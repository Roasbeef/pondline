import gleam/int
import tor/internal/codec.{
  AlreadyHosting, BadUtf8, BootstrapFailed, Bootstrapped, EmptyPayload, Failed,
  Malformed, OnionReady, Ready, ServiceRunning, ServiceStatus, ServiceUnknown,
  UnknownFailure, UnknownTag,
}

// These vectors are the same bytes that `native/pondline-tor/src/frame.rs`
// decodes and encodes in its own tests; if one side changes, both fail.

pub fn encode_bootstrap_test() {
  assert codec.encode_bootstrap(7) == <<1, 0, 0, 0, 7>>
}

pub fn encode_host_onion_test() {
  assert codec.encode_host_onion(7, "mbx", 8080)
    == <<2, 0, 0, 0, 7, 0, 3, "mbx":utf8, 31, 144>>
}

pub fn encode_shutdown_test() {
  assert codec.encode_shutdown() == <<3>>
}

pub fn decode_ready_test() {
  assert codec.decode_event(<<0x90, 1>>) == Ok(Ready(1))
}

pub fn decode_bootstrapped_test() {
  assert codec.decode_event(<<0x81, 0, 0, 1, 0>>) == Ok(Bootstrapped(256))
}

pub fn decode_onion_ready_test() {
  assert codec.decode_event(<<
      0x82,
      0,
      0,
      0,
      9,
      0,
      3,
      "mbx":utf8,
      0,
      5,
      "a.xyz":utf8,
    >>)
    == Ok(OnionReady(9, "mbx", "a.xyz"))
}

pub fn decode_failed_test() {
  assert codec.decode_event(<<0x83, 0, 0, 0, 2, 0, 1, 0, 2, "no":utf8>>)
    == Ok(Failed(2, BootstrapFailed, "no"))
  assert codec.decode_event(<<0x83, 0, 0, 0, 2, 0, 3, 0, 0>>)
    == Ok(Failed(2, AlreadyHosting, ""))
  assert codec.decode_event(<<0x83, 0, 0, 0, 2, 1, 0, 0, 0>>)
    == Ok(Failed(2, UnknownFailure(256), ""))
}

pub fn decode_service_status_test() {
  assert codec.decode_event(<<0x91, 0, 1, "m":utf8, 4>>)
    == Ok(ServiceStatus("m", ServiceRunning))
  assert codec.decode_event(<<0x91, 0, 1, "m":utf8, 99>>)
    == Ok(ServiceStatus("m", ServiceUnknown))
}

pub fn decode_rejects_bad_shapes_test() {
  assert codec.decode_event(<<>>) == Error(EmptyPayload)
  assert codec.decode_event(<<0x7f, 1>>) == Error(UnknownTag(0x7f))
  assert codec.decode_event(<<0x7f>>) == Error(UnknownTag(0x7f))
  // Truncated, and with trailing bytes.
  assert codec.decode_event(<<0x81, 0, 0>>) == Error(Malformed(0x81))
  assert codec.decode_event(<<0x90, 1, 2>>) == Error(Malformed(0x90))
  assert codec.decode_event(<<0x90>>) == Error(Malformed(0x90))
  // A length that runs past the end.
  assert codec.decode_event(<<0x91, 0xff, 0xff, "m":utf8, 4>>)
    == Error(Malformed(0x91))
  assert codec.decode_event(<<0x82, 0, 0, 0, 1, 0, 1, "a":utf8>>)
    == Error(Malformed(0x82))
  // A string that is not UTF-8.
  assert codec.decode_event(<<0x91, 0, 1, 0xff, 4>>) == Error(BadUtf8(0x91))
}

/// A deterministic byte generator, so the test replays.
fn bytes(seed: Int, length: Int) -> BitArray {
  int.range(0, length, <<>>, fn(acc, i) {
    let byte = { seed * 1_103_515_245 + i * 12_345 + 7 } % 256
    <<acc:bits, byte:size(8)>>
  })
}

pub fn decode_is_total_over_garbage_test() {
  // Every input is either an event or a typed error; the test passes if
  // none of them crashes the decoder. Tags are forced onto the known
  // values so the field parsers, not just the tag check, are exercised.
  int.range(0, 600, Nil, fn(_, seed) {
    let tag = case seed % 6 {
      0 -> 0x81
      1 -> 0x82
      2 -> 0x83
      3 -> 0x90
      4 -> 0x91
      _ -> seed % 256
    }
    let _ = codec.decode_event(<<tag:size(8), bytes(seed, seed % 40):bits>>)
    Nil
  })
}
