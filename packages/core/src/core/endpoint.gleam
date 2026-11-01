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

import gleam/list
import gleam/string

/// A syntactically valid v3 onion service hostname, lowercase, with the
/// `.onion` suffix. Arti verifies the embedded checksum when it connects;
/// this type guarantees the shape, which is all `core` can check without
/// SHA3.
pub opaque type OnionAddress {
  OnionAddress(host: String)
}

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
    [label, "onion"] ->
      case
        string.byte_size(label) == 56
        && string.ends_with(label, "d")
        && list.all(string.to_graphemes(label), string.contains(
          base32_alphabet,
          _,
        ))
      {
        True -> Ok(OnionAddress(host:))
        False -> Error(NotAnOnionAddress)
      }
    _ -> Error(NotAnOnionAddress)
  }
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
