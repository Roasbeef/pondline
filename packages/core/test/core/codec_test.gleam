//// Totality, round trips and secrecy for the codecs and the types that
//// hold secrets: `route`, `message`, `frame`, `invitation` and `snapshot`.

import core/capability
import core/crypto/fake_suite
import core/crypto/identity
import core/crypto/keys
import core/endpoint
import core/frame
import core/id
import core/invitation
import core/message
import core/offer
import core/relationship
import core/route
import core/secret
import core/snapshot
import core/time.{Instant}
import core/world
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import qcheck

const property_count = 150

const property_seed = 77

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

fn ids() -> qcheck.Generator(id.Id(kind)) {
  qcheck.fixed_size_byte_aligned_bit_array(id.id_bytes)
  |> qcheck.map(fn(bytes) {
    let assert Ok(made) = id.from_bytes(bytes) as "sixteen bytes"
    made
  })
}

fn capabilities() -> qcheck.Generator(capability.Capability(kind)) {
  qcheck.fixed_size_byte_aligned_bit_array(capability.capability_bytes)
  |> qcheck.map(fn(bytes) {
    let assert Ok(made) = capability.from_bytes(bytes) as "thirty-two bytes"
    made
  })
}

fn endpoints() -> qcheck.Generator(endpoint.Endpoint) {
  qcheck.bounded_int(1, 65_535)
  |> qcheck.map(fn(number) {
    let assert Ok(port) = endpoint.port(number) as "port in range"
    case int.is_even(number) {
      True -> endpoint.Loopback(port)
      False -> {
        let assert Ok(address) =
          endpoint.parse_onion(string.repeat("a", 55) <> "d.onion")
          as "a v3 onion shape"
        endpoint.Onion(address, port)
      }
    }
  })
}

fn routes() -> qcheck.Generator(route.Route) {
  qcheck.map3(endpoints(), ids(), capabilities(), fn(endpoint, queue, append) {
    route.Route(endpoint:, queue:, append:)
  })
}

fn bodies() -> qcheck.Generator(message.Body) {
  qcheck.from_generators(
    qcheck.map3(
      qcheck.string(),
      qcheck.byte_aligned_bit_array(),
      qcheck.option_from(ids()),
      fn(content_type, payload, in_reply_to) {
        message.Application(
          content_type: string.slice(content_type, 0, 40),
          payload: secret.new(payload),
          in_reply_to:,
        )
      },
    ),
    [
      qcheck.map(qcheck.list_from(ids()), fn(of) {
        message.Receipt(case of {
          [] -> [id_zero()]
          _ -> list.take(of, message.max_receipt_ids)
        })
      }),
      qcheck.constant(message.Accept),
      qcheck.constant(message.Reject),
      qcheck.constant(message.Close),
    ],
  )
}

fn id_zero() -> id.Id(kind) {
  let assert Ok(made) = id.from_bytes(<<0:128>>) as "sixteen bytes"
  made
}

fn messages() -> qcheck.Generator(message.Message) {
  qcheck.map3(
    ids(),
    qcheck.bounded_int(0, 4_000_000_000),
    bodies(),
    fn(id, seconds, body) {
      message.Message(id:, expires_at: Instant(seconds), body:)
    },
  )
}

fn same_message(left: message.Message, right: message.Message) -> Bool {
  left.id == right.id
  && left.expires_at == right.expires_at
  && case left.body, right.body {
    message.Application(a, pa, ra), message.Application(b, pb, rb) ->
      a == b && secret.expose(pa) == secret.expose(pb) && ra == rb
    message.Receipt(a), message.Receipt(b) -> a == b
    message.Accept, message.Accept -> True
    message.Reject, message.Reject -> True
    message.Close, message.Close -> True
    _, _ -> False
  }
}

pub fn routes_round_trip_test() {
  property(routes(), fn(made) {
    assert route.decode(route.encode(made)) == Ok(made)
  })
}

pub fn messages_round_trip_test() {
  property(messages(), fn(made) {
    let assert Ok(back) = message.decode(secret.expose(message.encode(made)))
    assert same_message(made, back)
  })
}

pub fn a_hello_round_trips_and_is_not_a_message_test() {
  property(qcheck.tuple2(ids(), routes()), fn(pair) {
    let hello =
      message.Hello(invitation: pair.0, reply: pair.1, description: "x")
    let bytes = secret.expose(message.encode_hello(hello))

    assert message.decode_hello(bytes) == Ok(hello)
    assert result.is_error(message.decode(bytes))
  })
}

pub fn a_message_is_not_a_hello_test() {
  property(messages(), fn(made) {
    assert result.is_error(
      message.decode_hello(secret.expose(message.encode(made))),
    )
  })
}

pub fn oversized_fields_are_refused_test() {
  let long = string.repeat("x", message.max_content_type_bytes + 1)
  let big =
    message.Message(
      id: id_zero(),
      expires_at: Instant(0),
      body: message.Application(long, secret.new(<<>>), None),
    )
  let many =
    message.Message(
      id: id_zero(),
      expires_at: Instant(0),
      body: message.Receipt(list.repeat(id_zero(), message.max_receipt_ids + 1)),
    )

  assert result.is_error(message.decode(secret.expose(message.encode(big))))
  assert result.is_error(message.decode(secret.expose(message.encode(many))))
}

/// A decoder that is handed random bytes returns, whatever it returns.
fn returns(result: Result(a, e)) -> Nil {
  case result {
    Ok(_) -> Nil
    Error(_) -> Nil
  }
}

pub fn decoders_are_total_on_random_bytes_test() {
  let suite = fake_suite.suite()

  property(qcheck.byte_aligned_bit_array(), fn(bytes) {
    returns(message.decode(bytes))
    returns(message.decode_hello(bytes))
    returns(route.decode(bytes))
    returns(route.decode_inbox(bytes))
    returns(frame.decode(suite, bytes))
    returns(invitation.decode(suite, bytes))
    returns(snapshot.decode_relationship(suite, bytes))
    returns(snapshot.decode_offer(suite, bytes))
  })
}

pub fn frames_round_trip_test() {
  let suite = fake_suite.suite()

  property(qcheck.byte_aligned_bit_array(), fn(bytes) {
    assert frame.decode(suite, frame.encode(frame.Ratchet(bytes)))
      == Ok(frame.Ratchet(bytes))
  })
}

/// The worlds the snapshot tests start from: a random walk, so every phase
/// is reachable.
fn walked() -> qcheck.Generator(world.World) {
  qcheck.fixed_length_list_from(
    qcheck.tuple2(
      qcheck.bounded_int(0, 100_000),
      qcheck.bounded_int(0, 100_000),
    ),
    90,
  )
  |> qcheck.map(fn(picks) {
    world.walk(
      world.new(world.Correct, offer.AutoApprove, 2),
      picks,
      world.Chaotic,
    )
  })
}

pub fn snapshots_round_trip_canonically_test() {
  let suite = fake_suite.suite()

  property(walked(), fn(w) {
    list.each([0, 1, 2], fn(number) {
      let mine = world.party(w, number)

      case mine.relationship {
        Some(blob) -> {
          let assert Ok(rel) = snapshot.decode_relationship(suite, blob)
          assert secret.expose(snapshot.encode_relationship(rel)) == blob
        }
        None -> Nil
      }

      case mine.offer {
        Some(blob) -> {
          let assert Ok(found) = snapshot.decode_offer(suite, blob)
          assert secret.expose(snapshot.encode_offer(found)) == blob
        }
        None -> Nil
      }
    })
  })
}

pub fn corrupted_snapshots_never_crash_the_decoder_test() {
  let suite = fake_suite.suite()
  let paired =
    world.new(world.Correct, offer.AutoApprove, 2)
    |> world.run([world.Setup(0), world.Provision(0, world.Commit)])
    |> world.run([world.Setup(1), world.Provision(1, world.Commit)])
    |> world.settle(5)
  let assert Some(blob) = world.party(paired, 0).relationship

  property(
    qcheck.tuple2(
      qcheck.bounded_int(0, bit_array.byte_size(blob) - 1),
      qcheck.bounded_int(1, 255),
    ),
    fn(change) {
      let assert Ok(before) = bit_array.slice(blob, 0, change.0)
      let assert Ok(<<byte, _:bytes>>) =
        bit_array.slice(blob, change.0, bit_array.byte_size(blob) - change.0)
      let assert Ok(after) =
        bit_array.slice(
          blob,
          change.0 + 1,
          bit_array.byte_size(blob) - change.0 - 1,
        )
      let flipped = <<
        before:bits,
        int.bitwise_exclusive_or(byte, change.1),
        after:bits,
      >>

      returns(snapshot.decode_relationship(suite, flipped))
    },
  )
}

pub fn an_invitation_round_trips_and_a_bad_bundle_is_refused_test() {
  let suite = fake_suite.suite()
  let w =
    world.new(world.Correct, offer.AutoApprove, 2)
    |> world.run([world.Setup(0), world.Provision(0, world.Commit)])
  let assert Some(file) = w.invitation_file
  let assert Ok(invite) = invitation.decode(suite, file)

  assert secret.expose(invitation.encode(invite)) == file

  // A flipped byte inside the bundle breaks a signature, so the file is
  // refused rather than read with a bundle nobody signed.
  let assert Ok(before) = bit_array.slice(file, 60, 1)
  let assert Ok(head) = bit_array.slice(file, 0, 60)
  let assert Ok(tail) =
    bit_array.slice(file, 61, bit_array.byte_size(file) - 61)
  let assert <<byte>> = before
  let bad = <<head:bits, int.bitwise_exclusive_or(byte, 1), tail:bits>>

  assert result.is_error(invitation.decode(suite, bad))
}

// ----------------------------------------------------------- secrecy

const marker_capability = 171

const marker_key = 238

const marker_payload = 205

fn marked(byte: Int, size: Int) -> BitArray {
  list.repeat(<<byte>>, size) |> bit_array.concat
}

/// The rendering of the value must hold no run of a secret's marker byte.
fn assert_unprinted(value: a, byte: Int) -> Nil {
  let rendered = string.inspect(value)
  let run = list.repeat(int.to_string(byte), 6) |> string.join(", ")

  // The control: a bare byte string does print its run, so the absence
  // below means the value hid it.
  assert string.contains(string.inspect(marked(byte, 8)), run)

  assert !string.contains(rendered, run)
}

pub fn secrets_never_appear_in_a_rendering_test() {
  let suite = fake_suite.suite()
  let w =
    world.new(world.Correct, offer.AutoApprove, 2)
    |> world.run([world.Setup(0), world.Provision(0, world.Commit)])
    |> world.run([world.Setup(1), world.Provision(1, world.Commit)])
    |> world.settle(5)
  let assert Some(rel) = world.relationship(w, 0)

  // Seed markers into the inbox capabilities and the identity's secrets.
  let assert Ok(read) = capability.from_bytes(marked(marker_capability, 32))
  let assert Ok(append) = capability.from_bytes(marked(marker_capability, 32))
  let assert Ok(admin) = capability.from_bytes(marked(marker_capability, 32))
  let assert Ok(signing) = keys.ed25519_secret(marked(marker_key, 32))
  let assert Ok(agreement) = keys.x25519_secret(marked(marker_key, 32))
  let marker_rel =
    relationship.Relationship(
      ..rel,
      inbox: route.Inbox(..rel.inbox, read:, append:, admin:),
      us: identity.Identity(..rel.us, signing:, agreement:),
    )

  assert_unprinted(marker_rel, marker_capability)
  assert_unprinted(marker_rel, marker_key)

  // A plan that carries a payload and the audit entry for it.
  let assert Ok(sent) =
    relationship.send(
      suite,
      marker_rel,
      Instant(1000),
      "text/plain",
      marked(marker_payload, 32),
      None,
      None,
    )

  assert_unprinted(sent, marker_payload)
  assert_unprinted(sent, marker_capability)
  assert_unprinted(sent, marker_key)

  // A held offer: prekey secrets and the identity inside it.
  let assert Some(found) = world.offer(w, 0)
  let assert Ok(spk) = keys.x25519_secret(marked(marker_key, 32))
  let marker_offer = case found.phase {
    offer.Open(stock) ->
      offer.Offer(
        ..found,
        phase: offer.Open(offer.Stock(..stock, spk_secret: spk)),
      )
    offer.Provisioning(_) | offer.Consumed(..) | offer.Expired -> found
  }

  assert_unprinted(marker_offer, marker_key)
  assert_unprinted(snapshot.encode_relationship(marker_rel), marker_key)
}
