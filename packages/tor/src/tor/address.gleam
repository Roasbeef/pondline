//// Where an outbound stream may go: a v3 onion service and a port.
////
//// `tor` must not depend on `core`, so these two types mirror
//// `core/endpoint`. The point of mirroring them is the same: there is no
//// constructor for a public host, so a clearnet connect is unrepresentable
//// rather than merely refused (spec section 13.1, no silent transport
//// downgrade). The sidecar refuses a non-onion target as well; this is
//// the first of the two walls.

import gleam/list
import gleam/string

/// A syntactically valid v3 onion hostname, lowercase, with the `.onion`
/// suffix. Arti verifies the embedded checksum when it connects; this type
/// guarantees the shape, which is all that is needed to rule out clearnet.
pub opaque type OnionAddress {
  OnionAddress(host: String)
}

/// A TCP port, 1 to 65535.
pub opaque type Port {
  Port(number: Int)
}

const base32_alphabet = "abcdefghijklmnopqrstuvwxyz234567"

/// Parses a v3 onion hostname: fifty-six base32 characters ending in the
/// version character `d`, then `.onion`. Case is folded.
///
/// ## Examples
///
/// ```gleam
/// assert address.parse_onion("example.com") == Error(Nil)
/// ```
pub fn parse_onion(text: String) -> Result(OnionAddress, Nil) {
  let host = string.lowercase(text)

  // Every base32 character is one byte, so the byte size is the character
  // count. Version 3 always encodes to a trailing "d".
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
        False -> Error(Nil)
      }
    _ -> Error(Nil)
  }
}

/// The hostname, `<56 chars>.onion`.
///
/// ## Examples
///
/// ```gleam
/// address.onion_host(onion)
/// // -> "...d.onion"
/// ```
pub fn onion_host(address: OnionAddress) -> String {
  address.host
}

/// A port from an integer.
///
/// ## Examples
///
/// ```gleam
/// assert address.port(0) == Error(Nil)
/// ```
///
/// ```gleam
/// assert address.port(80) |> result.map(address.port_number) == Ok(80)
/// ```
pub fn port(number: Int) -> Result(Port, Nil) {
  case number >= 1 && number <= 65_535 {
    True -> Ok(Port(number:))
    False -> Error(Nil)
  }
}

/// The port's number.
///
/// ## Examples
///
/// ```gleam
/// address.port_number(port)
/// // -> 80
/// ```
pub fn port_number(port: Port) -> Int {
  port.number
}
