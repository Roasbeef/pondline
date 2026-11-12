//// Property and unit checks for `core/grant` (`plg1...` mailbox grant tokens).

import core/capability
import core/codex32
import core/endpoint.{type Endpoint, Loopback, Onion}
import core/grant.{type GrantToken}
import core/secret
import core/ticket
import gleam/bit_array
import gleam/string
import qcheck

const property_count = 150

const property_seed = 415

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

fn port(number: Int) -> endpoint.Port {
  let assert Ok(parsed) = endpoint.port(number)
  parsed
}

fn onion_from(key: BitArray, checksum: BitArray) -> endpoint.OnionAddress {
  let assert Ok(address) =
    endpoint.onion_from_bytes(<<key:bits, checksum:bits, 3>>)
  address
}

fn endpoints() -> qcheck.Generator(Endpoint) {
  qcheck.map3(
    qcheck.bounded_int(0, 1),
    qcheck.fixed_size_byte_aligned_bit_array(34),
    qcheck.bounded_int(1, 65_535),
    fn(kind, bytes, number) {
      let assert <<key:bytes-size(32), checksum:bytes-size(2)>> = bytes

      case kind {
        0 -> Loopback(port(number))
        _ -> Onion(onion_from(key, checksum), port(number))
      }
    },
  )
}

fn grants() -> qcheck.Generator(GrantToken) {
  qcheck.map2(
    endpoints(),
    qcheck.fixed_size_byte_aligned_bit_array(capability.capability_bytes),
    fn(ep, bytes) {
      let assert Ok(made) = grant.from_parts(ep, bytes)
      made
    },
  )
}

fn text_of(token: GrantToken) -> String {
  let assert Ok(encoded) =
    bit_array.to_string(secret.expose(grant.encode(token)))
  encoded
}

pub fn grant_tokens_round_trip_and_match_exact_lengths_test() {
  property(grants(), fn(token) {
    let encoded = text_of(token)

    let expected_len = case grant.endpoint(token) {
      Onion(..) -> 131
      Loopback(..) -> 75
    }
    assert string.length(encoded) == expected_len

    let assert Ok(decoded) = grant.decode(encoded)
    assert grant.endpoint(decoded) == grant.endpoint(token)
    assert capability.expose(grant.provision(decoded))
      == capability.expose(grant.provision(token))
    assert text_of(decoded) == encoded
  })
}

pub fn domain_separated_from_invitation_tickets_and_corruptions_test() {
  let address = onion_from(<<7:256>>, <<1, 2>>)
  let ep = Onion(address, port(80))
  let assert Ok(token) = grant.from_parts(ep, <<9:256>>)
  let assert Ok(invite_ticket) = ticket.from_parts(ep, <<9:256>>)

  let grant_str = text_of(token)
  let assert Ok(ticket_str) =
    bit_array.to_string(secret.expose(ticket.encode(invite_ticket)))

  assert grant.decode(ticket_str) == Error(grant.NotAGrant)
  assert ticket.decode(grant_str) == Error(ticket.NotATicket)
  assert grant.decode(string.uppercase(grant_str)) == Error(grant.NotAGrant)
  assert grant.decode(grant_str <> " ") == Error(grant.NotAGrant)

  // Flipping one data character inside the codeword fails the BCH checksum.
  let mutated = "plg1p" <> string.drop_start(grant_str, 5)
  assert grant.decode(mutated) == Error(grant.BadChecksum)

  // Unknown format symbol with a valid `"plg"` checksum fails as UnknownFormat.
  let unknown_data = [2, 0, 0, 0]
  let unknown_str =
    "plg1"
    <> codex32.from_symbols(unknown_data)
    <> codex32.from_symbols(codex32.checksum(grant.prefix, unknown_data))
  assert grant.decode(unknown_str) == Error(grant.UnknownFormat)
}
