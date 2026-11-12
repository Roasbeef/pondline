//// Where a mailbox is reached, and which carriers a daemon may use.
////
//// Tor is the carrier (`docs/next.md`, "Rulings already made"), and spec
//// §13.1 requires that core traffic never silently fall back to a public
//// one. The type makes the fallback unrepresentable rather than forbidden:
//// an `Endpoint` is a v3 onion address or a loopback port, and there is
//// no constructor for a public host at all. A loopback endpoint exists so
//// that tests and the offline demo can run without the Tor network, and a
//// daemon accepts one only when its `CarrierPolicy` says so; the policy is
//// configuration an operator sets, never something an invitation can turn
//// on.
////
//// Another carrier, Lightning onion messages first, is a new variant here
//// and a new transport behind the mailbox command boundary (spec §6.2).

import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string

/// A syntactically valid v3 onion service hostname, lowercase, with the
/// `.onion` suffix. Arti verifies the embedded checksum when it connects;
/// this type guarantees the shape, which is all `core` can check without
/// SHA3. `bytes` is the label decoded: the 32-byte service key, the two
/// checksum bytes and the version byte, the form a ticket carries
/// (ADR-009). It is a function of `host`, so equality is unchanged.
pub opaque type OnionAddress {
  OnionAddress(host: String, bytes: BitArray)
}

/// The size of a v3 onion address's decoded label: key, checksum, version.
pub const onion_address_bytes = 35

/// A TCP port, 1 to 65535.
pub opaque type Port {
  Port(number: Int)
}

/// A mailbox location.
pub type Endpoint {
  /// A mailbox reached over Tor at a v3 onion service.
  Onion(address: OnionAddress, port: Port)

  /// A mailbox on this host's loopback interface, for tests and the
  /// offline demo. Never accepted under `TorOnly`.
  Loopback(port: Port)
}

/// Which carriers a daemon will use.
pub type CarrierPolicy {
  /// Only onion endpoints. The production setting.
  TorOnly

  /// Onion and loopback endpoints. An explicit operator choice for tests
  /// and demonstrations on one machine.
  TorOrLoopback
}

/// Why an endpoint was refused.
pub type EndpointError {
  /// The text is not a v3 onion hostname.
  NotAnOnionAddress

  /// The port is outside 1 to 65535.
  InvalidPort

  /// The endpoint is loopback and the policy is `TorOnly`.
  CarrierNotPermitted
}

const base32_alphabet = "abcdefghijklmnopqrstuvwxyz234567"

/// Parses a v3 onion hostname: fifty-six base32 characters ending in the
/// version character `d`, then `.onion`. Case is folded.
///
/// ## Examples
///
/// ```gleam
/// endpoint.parse_onion("example.com")
/// // -> Error(NotAnOnionAddress)
/// ```
pub fn parse_onion(text: String) -> Result(OnionAddress, EndpointError) {
  let host = string.lowercase(text)

  // The label is 56 characters of base32 over 35 bytes (key, checksum,
  // version); version 3 always encodes to a trailing "d". Every base32
  // character is one byte, so the byte size is the character count.
  case string.split(host, ".") {
    [label, "onion"] -> {
      let shaped = string.byte_size(label) == 56 && string.ends_with(label, "d")

      // The characters decode only if every one is in the alphabet, and
      // 56 of them are exactly 280 bits, so no padding is involved.
      case shaped, list.try_map(string.to_graphemes(label), base32_value) {
        True, Ok(values) ->
          Ok(OnionAddress(
            host:,
            bytes: list.fold(values, <<>>, fn(acc, value) {
              <<acc:bits, value:size(5)>>
            }),
          ))

        _, _ -> Error(NotAnOnionAddress)
      }
    }

    _ -> Error(NotAnOnionAddress)
  }
}

/// The decoded label: the service's 32-byte key, the two checksum bytes
/// and the version byte, `onion_address_bytes` in all.
///
/// ## Examples
///
/// ```gleam
/// bit_array.byte_size(endpoint.onion_bytes(address))
/// // -> 35
/// ```
pub fn onion_bytes(address: OnionAddress) -> BitArray {
  address.bytes
}

/// The address whose decoded label is `bytes`: the inverse of
/// `onion_bytes`. Bytes whose version does not encode to the trailing `d`
/// of a v3 label are refused, as `parse_onion` refuses the text.
///
/// ## Examples
///
/// ```gleam
/// endpoint.onion_from_bytes(endpoint.onion_bytes(address))
/// // -> Ok(address)
/// ```
pub fn onion_from_bytes(
  bytes: BitArray,
) -> Result(OnionAddress, EndpointError) {
  case bit_array.byte_size(bytes) == onion_address_bytes {
    True -> parse_onion(base32_text(bytes, "") <> ".onion")
    False -> Error(NotAnOnionAddress)
  }
}

/// RFC 4648 base32, lowercase and unpadded, of bits whose length is a
/// multiple of five.
fn base32_text(bits: BitArray, acc: String) -> String {
  case bits {
    <<value:size(5), rest:bits>> ->
      base32_text(rest, acc <> string.slice(base32_alphabet, value, 1))
    _ -> acc
  }
}

/// The value of one base32 character: its position in the alphabet.
fn base32_value(character: String) -> Result(Int, Nil) {
  string.to_graphemes(base32_alphabet)
  |> list.index_map(fn(letter, index) { #(letter, index) })
  |> list.key_find(character)
}

/// The hostname, `<56 chars>.onion`.
///
/// ## Examples
///
/// ```gleam
/// endpoint.onion_host(address)
/// // -> "…d.onion"
/// ```
pub fn onion_host(address: OnionAddress) -> String {
  address.host
}

/// A port from an integer.
///
/// ## Examples
///
/// ```gleam
/// endpoint.port(0)
/// // -> Error(InvalidPort)
/// ```
pub fn port(number: Int) -> Result(Port, EndpointError) {
  case number >= 1 && number <= 65_535 {
    True -> Ok(Port(number:))
    False -> Error(InvalidPort)
  }
}

/// The port's number.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(p) = endpoint.port(80)
/// endpoint.port_number(p)
/// // -> 80
/// ```
pub fn port_number(port: Port) -> Int {
  port.number
}

/// Admits an endpoint under a policy. This is the one check between an
/// endpoint read from an invitation or a route update and a connection.
///
/// ## Examples
///
/// ```gleam
/// endpoint.admit(Loopback(port), TorOnly)
/// // -> Error(CarrierNotPermitted)
/// ```
pub fn admit(
  endpoint: Endpoint,
  policy: CarrierPolicy,
) -> Result(Endpoint, EndpointError) {
  case endpoint, policy {
    Onion(..), _ -> Ok(endpoint)
    Loopback(..), TorOrLoopback -> Ok(endpoint)
    Loopback(..), TorOnly -> Error(CarrierNotPermitted)
  }
}

/// Formats an endpoint in canonical `HOST:PORT` text (`127.0.0.1:PORT` for
/// loopback, `<56-char>.onion:PORT` for Tor).
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(p) = endpoint.port(8080)
/// assert endpoint.to_string(endpoint.Loopback(p)) == "127.0.0.1:8080"
/// ```
pub fn to_string(endpoint: Endpoint) -> String {
  case endpoint {
    Onion(address:, port:) -> address.host <> ":" <> int.to_string(port.number)
    Loopback(port:) -> "127.0.0.1:" <> int.to_string(port.number)
  }
}

/// Parses `HOST:PORT` into an `Endpoint`: `127.0.0.1:PORT` or `localhost:PORT`
/// becomes `Loopback`, and anything else must be a valid v3 `.onion:PORT`.
/// Carrier admission stays a separate `admit` step.
///
/// ## Examples
///
/// ```gleam
/// endpoint.parse("127.0.0.1:8080")
/// // -> Ok(Loopback(_))
/// endpoint.parse("example.com:80")
/// // -> Error(NotAnOnionAddress)
/// ```
pub fn parse(text: String) -> Result(Endpoint, EndpointError) {
  use #(host, port_text) <- result.try(
    string.split_once(text, ":") |> result.replace_error(InvalidPort),
  )
  use number <- result.try(
    int.parse(port_text) |> result.replace_error(InvalidPort),
  )
  use parsed_port <- result.try(port(number))

  // Loopback accepts both local hostnames; everything else must be a v3 onion.
  case host {
    "127.0.0.1" | "localhost" -> Ok(Loopback(port: parsed_port))
    _ -> parse_onion(host) |> result.map(Onion(_, port: parsed_port))
  }
}
