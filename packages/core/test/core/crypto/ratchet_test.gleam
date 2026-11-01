//// Properties of the handshake and the ratchet, checked over the
//// deterministic fake suite (`fake_suite.gleam`), so that thousands of
//// random conversations run as pure Gleam without OpenSSL.
////
//// The real-primitive tests, with the known-answer HKDF vectors, live in
//// `packages/primitives/test/primitives/`; these establish the protocol
//// logic independent of the algorithms.

import core/crypto/error
import core/crypto/fake_suite
import core/crypto/identity
import core/crypto/pqxdh
import core/crypto/ratchet
import core/secret
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/result
import gleam/string
import qcheck

const property_count = 200

const property_seed = 11

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

/// Two ends of an established session, `a` the joiner and `b` the inviter.
type Session {
  Session(a: ratchet.State, b: ratchet.State)
}

/// Messages in flight to one party, oldest first, each with the plaintext it
/// must decrypt to.
type Inbox =
  List(#(BitArray, BitArray))

fn session() -> Session {
  let suite = fake_suite.suite()
  let assert Ok(inviter) = identity.generate(suite) as "identity generates"
  let assert Ok(joiner) = identity.generate(suite) as "identity generates"
  let assert Ok(prekeys) = pqxdh.generate_prekeys(suite, inviter)
    as "prekeys generate"
  let assert Ok(#(a, initial)) =
    pqxdh.initiate(suite, joiner, prekeys.bundle, <<"first">>)
    as "initiate succeeds"
  let assert Ok(response) = pqxdh.respond(suite, inviter, prekeys, initial)
    as "respond succeeds"

  assert response.plaintext == <<"first">>

  Session(a: a, b: response.state)
}

fn encrypt(state: ratchet.State, text: BitArray) -> #(ratchet.State, BitArray) {
  let assert Ok(sent) = ratchet.encrypt(fake_suite.suite(), state, text)
    as "encrypt succeeds"
  sent
}

fn decrypt(
  state: ratchet.State,
  message: BitArray,
) -> Result(#(ratchet.State, BitArray), error.Error) {
  ratchet.decrypt(fake_suite.suite(), state, message)
}

/// Delivers one of the first three in-flight messages, which bounds how far
/// the network may reorder, and checks it decrypts to what was sent.
fn deliver(
  state: ratchet.State,
  inbox: Inbox,
  pick: Int,
) -> #(ratchet.State, Inbox) {
  case inbox {
    [] -> #(state, inbox)

    _ -> {
      let index = int.min(pick, int.min(2, list.length(inbox) - 1))
      let #(before, after) = list.split(inbox, index)
      let assert [#(message, expected), ..rest] = after
        as "index is within the inbox"
      let assert Ok(#(next, plaintext)) = decrypt(state, message)
        as "an in-window message always decrypts"

      assert plaintext == expected

      // The key is spent on the state that kept the result, so delivering
      // the same message again fails.
      assert result.is_error(decrypt(next, message))

      #(next, list.append(before, rest))
    }
  }
}

fn flush(state: ratchet.State, inbox: Inbox) -> Nil {
  case inbox {
    [] -> Nil
    _ -> {
      let #(state, inbox) = deliver(state, inbox, 0)
      flush(state, inbox)
    }
  }
}

fn play(operations: List(#(Int, Int))) -> #(Session, Inbox, Inbox) {
  let start = #(session(), [], [], 0)
  let #(done, to_a, to_b, _) =
    list.fold(operations, start, fn(world, operation) {
      let #(Session(a, b), to_a, to_b, count) = world
      let text = <<"message ", int.to_string(count):utf8>>

      case operation.0 {
        0 -> {
          let #(a, message) = encrypt(a, text)
          #(
            Session(a, b),
            to_a,
            list.append(to_b, [#(message, text)]),
            count + 1,
          )
        }

        1 -> {
          let #(b, message) = encrypt(b, text)
          #(
            Session(a, b),
            list.append(to_a, [#(message, text)]),
            to_b,
            count + 1,
          )
        }

        2 -> {
          let #(b, to_b) = deliver(b, to_b, operation.1)
          #(Session(a, b), to_a, to_b, count)
        }

        _ -> {
          let #(a, to_a) = deliver(a, to_a, operation.1)
          #(Session(a, b), to_a, to_b, count)
        }
      }
    })

  #(done, to_a, to_b)
}

fn operations() -> qcheck.Generator(List(#(Int, Int))) {
  qcheck.list_from(qcheck.tuple2(
    qcheck.bounded_int(0, 3),
    qcheck.bounded_int(0, 2),
  ))
}

/// Any interleaving of sends in both directions with delivery reordered
/// within a window of three decrypts every message to its plaintext, and a
/// final in-order flush leaves nothing undelivered.
pub fn random_interleavings_decrypt_property_test() {
  use ops <- property(operations())

  let #(Session(a, b), to_a, to_b) = play(ops)

  flush(a, to_a)
  flush(b, to_b)
}

/// A message with any one byte changed is rejected, and the state that
/// refused it can still decrypt the original, which is the prepare/commit
/// guarantee for a failed receive.
pub fn single_byte_corruption_is_rejected_property_test() {
  use #(ops, position, change) <- property(qcheck.tuple3(
    operations(),
    qcheck.bounded_int(0, 1000),
    qcheck.bounded_int(1, 255),
  ))

  let #(Session(a, b), _, _) = play(ops)
  let #(_, message) = encrypt(a, <<"target">>)
  let index = position % bit_array.byte_size(message)
  let corrupted = corrupt(message, index, change)

  // The corrupted message is judged against `b` as the conversation left it,
  // with whatever was in flight undelivered.
  assert result.is_error(decrypt(b, corrupted))

  let assert Ok(#(_, plaintext)) = decrypt(b, message)
    as "the refusing state is unchanged and still decrypts the original"

  assert plaintext == <<"target">>
}

fn corrupt(message: BitArray, index: Int, change: Int) -> BitArray {
  let assert Ok(head) = bit_array.slice(message, 0, index)
  let assert Ok(<<byte>>) = bit_array.slice(message, index, 1)
  let assert Ok(tail) =
    bit_array.slice(
      message,
      index + 1,
      bit_array.byte_size(message) - index - 1,
    )

  <<head:bits, int.bitwise_exclusive_or(byte, change), tail:bits>>
}

/// A restored state encodes to the same bytes as the original and decrypts
/// the next message to the same plaintext.
pub fn state_round_trip_property_test() {
  use ops <- property(operations())

  let #(Session(a, b), _, _) = play(ops)
  let #(_, message) = encrypt(a, <<"after restore">>)

  let encoded = secret.expose(ratchet.encode_state(b))
  let assert Ok(restored) = ratchet.decode_state(encoded)
    as "an encoded state decodes"

  assert secret.expose(ratchet.encode_state(restored)) == encoded

  let assert Ok(#(_, from_original)) = decrypt(b, message)
    as "the original decrypts"
  let assert Ok(#(_, from_restored)) = decrypt(restored, message)
    as "the restored state decrypts"

  assert from_original == from_restored
}

/// Decoding arbitrary bytes returns a result rather than crashing, and a
/// strict prefix of a valid encoding is never accepted.
pub fn decode_state_is_total_property_test() {
  use #(bytes, cut) <- property(qcheck.tuple2(
    qcheck.bit_array(),
    qcheck.bounded_int(0, 10_000),
  ))

  let _ = ratchet.decode_state(bytes)

  let Session(a, _) = session()
  let valid = secret.expose(ratchet.encode_state(a))
  let size = bit_array.byte_size(valid)
  let assert Ok(prefix) = bit_array.slice(valid, 0, cut % size)

  assert result.is_error(ratchet.decode_state(prefix))
}

pub fn the_fake_handshake_rejects_a_bad_bundle_signature_test() {
  let suite = fake_suite.suite()
  let assert Ok(inviter) = identity.generate(suite)
  let assert Ok(prekeys) = pqxdh.generate_prekeys(suite, inviter)
  let encoded = pqxdh.encode_bundle(prekeys.bundle)
  let assert Ok(head) = bit_array.slice(encoded, 0, 130)
  let assert Ok(tail) = bit_array.slice(encoded, 131, 1857 - 131)

  assert pqxdh.decode_bundle(suite, <<head:bits, 0, tail:bits>>)
    == Error(error.BadSignature("signed prekey"))
}

pub fn no_secret_reaches_the_inspected_state_test() {
  let Session(a, _) = session()
  let rendered = string.inspect(a)

  // The state renders its keys as closures, never as bytes.
  assert string.contains(rendered, "fn()")
}

fn send_many(
  state: ratchet.State,
  count: Int,
) -> #(ratchet.State, List(BitArray)) {
  int.range(from: 0, to: count, with: #(state, []), run: fn(acc, _) {
    let #(state, messages) = acc
    let #(state, message) = encrypt(state, <<"filler">>)

    #(state, [message, ..messages])
  })
}

pub fn the_skip_bounds_hold_over_the_fake_suite_test() {
  let Session(a, b) = session()
  let #(_, messages) = send_many(a, 1002)
  let assert [newest, at_bound, ..] = messages

  // Number 1002 against an expected 1 would store 1001 keys.
  assert decrypt(b, newest) == Error(error.SkipLimitExceeded)
  assert result.is_ok(decrypt(b, at_bound))
}

pub fn the_stored_key_bound_evicts_over_the_fake_suite_test() {
  // Fill the store to its bound across two chains, then overflow it.
  let Session(a, b) = session()
  let #(a, first) = send_many(a, 1001)
  let assert [newest, ..] = first
  let assert Ok(#(b, _)) = decrypt(b, newest)
  let #(b, reply) = encrypt(b, <<"r">>)
  let assert Ok(#(a, _)) = decrypt(a, reply)
  let #(a, chain_two) = send_many(a, 1001)
  let assert [newest, ..] = chain_two
  let assert Ok(#(b, _)) = decrypt(b, newest)
  let #(b, reply) = encrypt(b, <<"r">>)
  let assert Ok(#(a, _)) = decrypt(a, reply)
  let #(a, _) = encrypt(a, <<"skipped">>)
  let #(_, third) = encrypt(a, <<"arrives">>)

  // The 2001st key evicts the oldest instead of refusing the message.
  let assert Ok(#(b, _)) = decrypt(b, third)
  let assert [oldest, next_oldest, ..] = list.reverse(first)

  assert decrypt(b, oldest) == Error(error.AuthenticationFailed)
  assert result.is_ok(decrypt(b, next_oldest))
}

pub fn a_message_number_at_the_limit_is_refused_test() {
  let Session(a, b) = session()
  let #(_, message) = encrypt(a, <<"m">>)
  let assert Ok(prefix) = bit_array.slice(message, 0, 36)
  let assert Ok(rest) =
    bit_array.slice(message, 40, bit_array.byte_size(message) - 40)
  let forged = <<prefix:bits, 0xFFFFFFFF:size(32), rest:bits>>

  assert decrypt(b, forged) == Error(error.CounterExhausted)
}

pub fn a_bundle_commitment_naming_another_bundle_is_refused_test() {
  let suite = fake_suite.suite()
  let assert Ok(inviter) = identity.generate(suite)
  let assert Ok(joiner) = identity.generate(suite)
  let assert Ok(held) = pqxdh.generate_prekeys(suite, inviter)
  let assert Ok(other) = pqxdh.generate_prekeys(suite, inviter)
  let assert Ok(#(_, initial)) =
    pqxdh.initiate(suite, joiner, other.bundle, <<"x">>)

  assert pqxdh.respond(suite, inviter, held, initial)
    == Error(error.UnknownBundle)
}
