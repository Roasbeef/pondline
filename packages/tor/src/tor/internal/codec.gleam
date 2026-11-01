//// The control protocol between this package and the `reedwire-tor`
//// sidecar: requests out, events back.
////
//// Why a hand-written binary encoding: the channel carries five event
//// shapes and two request shapes, each with a few small fields, and both
//// ends must decode *totally*. Every byte string yields a value or a typed
//// `DecodeError`, never a crash and never a partial result. The Rust side
//// (`native/reedwire-tor/src/frame.rs`) holds the matching decoder and
//// carries the same golden vectors as `test/tor/codec_test.gleam`.
////
//// The Erlang port is opened with `{packet, 4}`, so the 4-byte big-endian
//// length prefix is added and stripped by the VM. What this module sees is
//// the payload: one tag byte followed by that message's fields in order.
//// All integers are big-endian. A `str` is a `u16` byte length and that
//// many bytes of UTF-8. Trailing bytes after the last field are malformed.
////
//// ```text
//// requests (this package to the sidecar)
////   0x01 Bootstrap   id:u32
////   0x02 HostOnion   id:u32 nickname:str local_port:u16
////   0x03 Shutdown
////
//// events (the sidecar to this package)
////   0x81 Bootstrapped  id:u32
////   0x82 OnionReady    id:u32 nickname:str hostname:str
////   0x83 Failed        id:u32 code:u16 text:str
////   0x90 Ready         version:u8
////   0x91 ServiceStatus nickname:str state:u8
//// ```
////
//// The `id` is chosen by this package and echoed by the reply, so a reply
//// to a request whose caller gave up is recognised and dropped.

import gleam/bit_array

/// Why the sidecar failed a request. The numbers are wire format.
pub type FailCode {
  /// Arti could not bootstrap. Wire code 1.
  BootstrapFailed

  /// The nickname is not a valid onion service nickname. Wire code 2.
  InvalidNickname

  /// A service with this nickname is already running. Wire code 3.
  AlreadyHosting

  /// The sidecar already hosts as many services as it allows. Wire code 4.
  TooManyServices

  /// Arti refused to launch the service. Wire code 5.
  LaunchFailed

  /// The local forwarding port is zero. Wire code 6.
  InvalidPort

  /// The service has no onion address in its keystore. Wire code 7.
  NoAddress

  /// A code this version does not know. A newer sidecar may send one; it
  /// still means "failed", never "succeeded".
  UnknownFailure(code: Int)
}

/// An onion service state, flattened from Arti's by the sidecar. The
/// numbers are wire format.
pub type ServiceState {
  /// The service is bootstrapping. Wire code 1.
  ServiceBootstrapping

  /// Degraded, but reachable. Wire code 2.
  ServiceDegradedReachable

  /// Degraded and unlikely to be reachable. Wire code 3.
  ServiceDegradedUnreachable

  /// Running and believed fully reachable. Wire code 4.
  ServiceRunning

  /// Recovering from an interruption. Wire code 5.
  ServiceRecovering

  /// Broken. Wire code 6.
  ServiceBroken

  /// Shut down. Wire code 7.
  ServiceShutdown

  /// A state this version does not know, which must not look reachable.
  ServiceUnknown
}

/// A message from the sidecar.
pub type Event {
  /// The sidecar is listening for outbound connections. Sent once.
  Ready(version: Int)

  /// The Tor client finished bootstrapping.
  Bootstrapped(id: Int)

  /// An onion service is launched and has this address.
  OnionReady(id: Int, nickname: String, hostname: String)

  /// A request failed.
  Failed(id: Int, code: FailCode, text: String)

  /// An onion service changed state.
  ServiceStatus(nickname: String, state: ServiceState)
}

/// Why a payload did not decode.
pub type DecodeError {
  /// The payload has no bytes at all.
  EmptyPayload

  /// The tag byte names no event.
  UnknownTag(tag: Int)

  /// The tag is known but the fields are truncated or followed by extra
  /// bytes.
  Malformed(tag: Int)

  /// A string field is not UTF-8.
  BadUtf8(tag: Int)
}

/// Encodes a `Bootstrap` request.
///
/// ## Examples
///
/// ```gleam
/// assert codec.encode_bootstrap(7) == <<1, 0, 0, 0, 7>>
/// ```
pub fn encode_bootstrap(id: Int) -> BitArray {
  <<0x01, id:size(32)>>
}

/// Encodes a `HostOnion` request. The caller has already bounded the
/// nickname to a few bytes, so its length fits the `u16` prefix.
///
/// ## Examples
///
/// ```gleam
/// assert codec.encode_host_onion(7, "mbx", 8080)
///   == <<2, 0, 0, 0, 7, 0, 3, "mbx":utf8, 31, 144>>
/// ```
pub fn encode_host_onion(
  id: Int,
  nickname: String,
  local_port: Int,
) -> BitArray {
  let name = <<nickname:utf8>>
  let length = bit_array.byte_size(name)

  <<0x02, id:size(32), length:size(16), name:bits, local_port:size(16)>>
}

/// Encodes a `Shutdown` request.
///
/// ## Examples
///
/// ```gleam
/// assert codec.encode_shutdown() == <<3>>
/// ```
pub fn encode_shutdown() -> BitArray {
  <<0x03>>
}

/// Decodes one event payload. Total: every byte string is an `Event` or a
/// `DecodeError`.
///
/// ## Examples
///
/// ```gleam
/// assert codec.decode_event(<<0x90, 1>>) == Ok(codec.Ready(1))
/// ```
///
/// ```gleam
/// assert codec.decode_event(<<>>) == Error(codec.EmptyPayload)
/// ```
pub fn decode_event(payload: BitArray) -> Result(Event, DecodeError) {
  case payload {
    <<0x90, version:size(8)>> -> Ok(Ready(version))

    <<0x81, id:size(32)>> -> Ok(Bootstrapped(id))

    <<0x91, name_length:size(16), name:bytes-size(name_length), state:size(8)>> ->
      case bit_array.to_string(name) {
        Ok(nickname) -> Ok(ServiceStatus(nickname, service_state(state)))
        Error(Nil) -> Error(BadUtf8(0x91))
      }

    <<0x82, id:size(32), rest:bytes>> -> decode_onion_ready(id, rest)

    <<0x83, id:size(32), code:size(16), rest:bytes>> ->
      decode_failed(id, code, rest)

    <<tag, _:bytes>> -> Error(classify(tag))

    _ -> Error(EmptyPayload)
  }
}

/// The error for a payload whose tag did not match a complete pattern:
/// unknown if no event has the tag, malformed if one does.
fn classify(tag: Int) -> DecodeError {
  case tag {
    0x81 | 0x82 | 0x83 | 0x90 | 0x91 -> Malformed(tag)
    _ -> UnknownTag(tag)
  }
}

/// The two strings of an `OnionReady`, which must consume the rest of the
/// payload exactly.
fn decode_onion_ready(id: Int, rest: BitArray) -> Result(Event, DecodeError) {
  case rest {
    <<
      name_length:size(16),
      name:bytes-size(name_length),
      host_length:size(16),
      host:bytes-size(host_length),
    >> ->
      case bit_array.to_string(name), bit_array.to_string(host) {
        Ok(nickname), Ok(hostname) -> Ok(OnionReady(id, nickname, hostname))
        _, _ -> Error(BadUtf8(0x82))
      }
    _ -> Error(Malformed(0x82))
  }
}

/// The text of a `Failed`, which must consume the rest of the payload.
fn decode_failed(
  id: Int,
  code: Int,
  rest: BitArray,
) -> Result(Event, DecodeError) {
  case rest {
    <<text_length:size(16), text:bytes-size(text_length)>> ->
      case bit_array.to_string(text) {
        Ok(text) -> Ok(Failed(id, fail_code(code), text))
        Error(Nil) -> Error(BadUtf8(0x83))
      }
    _ -> Error(Malformed(0x83))
  }
}

/// The failure code for a wire number.
fn fail_code(code: Int) -> FailCode {
  case code {
    1 -> BootstrapFailed
    2 -> InvalidNickname
    3 -> AlreadyHosting
    4 -> TooManyServices
    5 -> LaunchFailed
    6 -> InvalidPort
    7 -> NoAddress
    other -> UnknownFailure(other)
  }
}

/// The service state for a wire number.
fn service_state(state: Int) -> ServiceState {
  case state {
    1 -> ServiceBootstrapping
    2 -> ServiceDegradedReachable
    3 -> ServiceDegradedUnreachable
    4 -> ServiceRunning
    5 -> ServiceRecovering
    6 -> ServiceBroken
    7 -> ServiceShutdown
    _ -> ServiceUnknown
  }
}
