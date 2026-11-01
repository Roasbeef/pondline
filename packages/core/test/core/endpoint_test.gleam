import core/endpoint
import gleam/string

// A syntactically valid v3 hostname: fifty-five base32 characters then the
// version character.
const label = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd"

fn port(number: Int) -> endpoint.Port {
  let assert Ok(port) = endpoint.port(number)
  port
}

fn onion() -> endpoint.OnionAddress {
  let assert Ok(address) = endpoint.parse_onion(label <> ".onion")
  address
}

/// A real v3 address parses and keeps its hostname.
pub fn a_v3_address_parses_test() {
  assert endpoint.onion_host(onion()) == label <> ".onion"
}

/// Case is folded, so a hostname typed in capitals is the same address.
pub fn case_is_folded_test() {
  let assert Ok(address) =
    endpoint.parse_onion(string.uppercase(label) <> ".ONION")

  assert address == onion()
  assert endpoint.onion_host(address) == label <> ".onion"
}

/// Clearnet names, v2 addresses, wrong lengths, the wrong version
/// character, characters outside the alphabet and extra labels are all
/// refused.
pub fn non_v3_hosts_are_refused_test() {
  let short = string.drop_end(label, 1)
  let wrong_version = string.drop_end(label, 1) <> "a"
  let bad_alphabet = string.drop_end(label, 2) <> "1d"
  let v2 = "expyuzz4wqqyqhjn"

  assert endpoint.parse_onion("example.com")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion(label) == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion(label <> ".com")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion(v2 <> ".onion")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion(short <> ".onion")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion(label <> "d.onion")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion(wrong_version <> ".onion")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion(bad_alphabet <> ".onion")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion("www." <> label <> ".onion")
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.parse_onion("") == Error(endpoint.NotAnOnionAddress)
}

/// Ports run from 1 to 65535 and nothing else.
pub fn ports_are_bounded_test() {
  assert endpoint.port(0) == Error(endpoint.InvalidPort)
  assert endpoint.port(-1) == Error(endpoint.InvalidPort)
  assert endpoint.port(65_536) == Error(endpoint.InvalidPort)
  assert endpoint.port(1) != Error(endpoint.InvalidPort)
  assert endpoint.port_number(port(65_535)) == 65_535
  assert endpoint.port_number(port(80)) == 80
}

/// An onion endpoint is admitted under both policies; loopback only under
/// the one that names it.
pub fn admit_respects_the_carrier_policy_test() {
  let onion_endpoint = endpoint.Onion(address: onion(), port: port(80))
  let loopback = endpoint.Loopback(port: port(8080))

  assert endpoint.admit(onion_endpoint, endpoint.TorOnly) == Ok(onion_endpoint)
  assert endpoint.admit(onion_endpoint, endpoint.TorOrLoopback)
    == Ok(onion_endpoint)
  assert endpoint.admit(loopback, endpoint.TorOrLoopback) == Ok(loopback)
  assert endpoint.admit(loopback, endpoint.TorOnly)
    == Error(endpoint.CarrierNotPermitted)
}

/// An address's decoded label is its 35 bytes, ending in version 3, and
/// those bytes give back the same address; other sizes are refused.
pub fn an_address_round_trips_through_its_bytes_test() {
  let bytes = endpoint.onion_bytes(onion())
  let assert <<_:bytes-size(34), version>> = bytes

  assert version == 3
  assert endpoint.onion_from_bytes(bytes) == Ok(onion())
  assert endpoint.onion_from_bytes(<<0:264>>)
    == Error(endpoint.NotAnOnionAddress)
  assert endpoint.onion_from_bytes(<<0:272, 4>>)
    == Error(endpoint.NotAnOnionAddress)
}
