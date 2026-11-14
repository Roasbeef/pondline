//// CPaceOQUAKE (`core/crypto/cpace_oquake`) against `draft-vos-cfrg-pqpake-03`
//// Appendix E.4, end to end, and over the real primitives.
////
//// The vector is `test/vectors/oquake_cpaceoquake_stage.json`, extracted by
//// script from the draft text for the OQUAKE stage's test; it holds the
//// whole of E.4 (inputs, every random value, `msg1` to `msg3`, the session
//// key and `th`), so this file reads the same fixture rather than a copy.
//// The draft lists one `key` for both sides.
////
//// Every random value is pinned: CPace's `ya` and `yb` through
//// `init_with` and `respond_with`; OQUAKE's key pair, rebuilt from the
//// vector's `oquake_upk` and `kemeleon_m`, and its `r` through
//// `respond_with`. ML-KEM's own randomness (`keygen_seed`, `encaps_m`)
//// cannot be given to OTP, so, as `oquake_test` does, the suite's ML-KEM is
//// replaced by one that answers exactly what the vector says ML-KEM
//// answered, and only for the key and ciphertext the vector names. A run
//// that put the stages in the wrong roles, or fed OQUAKE the wrong
//// contexts, would unmask another key and find no answer.

import core/crypto/bua_skem
import core/crypto/cpace
import core/crypto/cpace_oquake.{
  type Inputs, ClientFinished, Inputs, MalformedFinishMessage,
  MalformedInitMessage, MalformedResponseMessage, ServerFinished,
}
import core/crypto/kemeleon
import core/crypto/suite as core_suite
import core/secret
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import primitives/suite
import primitives/vectors

/// The E.4 case.
fn e4() -> vectors.Vector {
  let assert [vector] = vectors.load("oquake_cpaceoquake_stage")
    as "the fixture has one case"
  vector
}

/// Both parties' inputs in E.4: the same password and public context, and
/// an empty secret context.
fn inputs(v: vectors.Vector) -> Inputs {
  Inputs(
    prs: secret.new(vectors.hex(v, "PRS")),
    public_context: vectors.hex(v, "public_context"),
    secret_context: secret.new(vectors.hex(v, "secret_context")),
  )
}

fn scalar(v: vectors.Vector, key: String) -> cpace.Scalar {
  let assert Ok(scalar) = cpace.scalar_from_bytes(vectors.hex(v, key))
    as "a vector scalar is 32 bytes"
  scalar
}

/// The ciphertext the vector's client sent: the first Nct bytes of `msg3`.
fn ciphertext(v: vectors.Vector) -> BitArray {
  let assert Ok(ciphertext) =
    bit_array.slice(vectors.hex(v, "msg3"), 0, bua_skem.ciphertext_bytes)
    as "msg3 holds a ciphertext"
  ciphertext
}

/// The real suite with ML-KEM's answers replaced by the vector's.
fn replaying(v: vectors.Vector) -> core_suite.Suite {
  let assert Ok(encapsulation_key) =
    kemeleon.decode(vectors.hex(v, "oquake_upk"))
    as "the vector's upk decodes"
  let ciphertext = ciphertext(v)
  let shared_secret = vectors.hex(v, "oquake_k")

  core_suite.Suite(
    ..suite.suite(),
    kem_encapsulate: fn(key) {
      case key == encapsulation_key {
        True -> Ok(#(shared_secret, ciphertext))
        False -> Error(Nil)
      }
    },
    kem_decapsulate: fn(_key, received) {
      case received == ciphertext {
        True -> Ok(shared_secret)
        False -> Error(Nil)
      }
    },
  )
}

/// The server's ML-BUA-sKEM key pair: the vector's public key re-encoded
/// under its `kemeleon_m`, with a placeholder decapsulation key that
/// `replaying` never reads.
fn key_pair(v: vectors.Vector) -> bua_skem.KeyPair {
  let assert Ok(numbers) =
    vectors.text(v, "kemeleon_m")
    |> string.split(" ")
    |> list.try_map(int.parse)
    as "four decimal numbers"
  let assert Ok(randomness) = kemeleon.randomness_from_multiples(numbers)
    as "four non-negative multiples"
  let assert Ok(encapsulation_key) =
    kemeleon.decode(vectors.hex(v, "oquake_upk"))
    as "the vector's upk decodes"
  let assert Ok(pair) =
    bua_skem.key_pair_from(
      secret.new(<<0:size(25_344)>>),
      encapsulation_key,
      randomness,
    )
    as "the vector's key re-encodes"
  pair
}

/// The whole of E.4, both sides, every value the vector lists: `msg1`,
/// `msg2`, `msg3`, the client's key and `th`, the server's key and `th`.
pub fn e4_end_to_end_test() {
  let v = e4()
  let suite = replaying(v)

  let assert Ok(#(client, msg1)) =
    cpace_oquake.init_with(suite, inputs(v), scalar(v, "cpace_ya"))
  assert msg1 == vectors.hex(v, "msg1")

  let assert Ok(#(server, msg2)) =
    cpace_oquake.respond_with(
      suite,
      inputs(v),
      msg1,
      scalar(v, "cpace_yb"),
      key_pair(v),
      secret.new(vectors.hex(v, "oquake_r")),
    )
  assert msg2 == vectors.hex(v, "msg2")

  let assert Ok(ClientFinished(key: client_key, message: msg3, transcript_hash:)) =
    cpace_oquake.initiator_finish(suite, client, msg2)
  assert msg3 == vectors.hex(v, "msg3")
  assert secret.expose(client_key) == vectors.hex(v, "key")
  assert transcript_hash == vectors.hex(v, "th")

  let fallback = secret.new(<<0xAA:size(256)>>)
  let assert Ok(ServerFinished(key: server_key, transcript_hash: server_hash)) =
    cpace_oquake.responder_finish_with(suite, server, msg3, fallback)
  assert secret.expose(server_key) == vectors.hex(v, "key")
  assert server_hash == vectors.hex(v, "th")
}

/// The draft's failure behaviour on the vector: `msg3` with its tag changed
/// finishes at the server with a key unrelated to the vector's, never with
/// an error, and with the transcript of what was received.
pub fn e4_changed_tag_gives_an_unrelated_key_test() {
  let v = e4()
  let suite = replaying(v)
  let assert Ok(#(_client, msg1)) =
    cpace_oquake.init_with(suite, inputs(v), scalar(v, "cpace_ya"))
  let assert Ok(#(server, _msg2)) =
    cpace_oquake.respond_with(
      suite,
      inputs(v),
      msg1,
      scalar(v, "cpace_yb"),
      key_pair(v),
      secret.new(vectors.hex(v, "oquake_r")),
    )
  let assert <<ciphertext:bytes-size(1568), tag:size(256)>> =
    vectors.hex(v, "msg3")
    as "ct || h"
  let changed = <<ciphertext:bits, { int.bitwise_exclusive_or(tag, 1) }:256>>

  let assert Ok(ServerFinished(key:, transcript_hash:)) =
    cpace_oquake.responder_finish_with(
      suite,
      server,
      changed,
      secret.new(<<0xAA:size(256)>>),
    )
  assert secret.expose(key) != vectors.hex(v, "key")
  assert transcript_hash != vectors.hex(v, "th")
}

/// Appendix C.4's parsers: a wrong length or a wrong length prefix is a
/// typed error at each message, before any key is derived.
pub fn e4_malformed_messages_are_refused_test() {
  let v = e4()
  let suite = replaying(v)
  let msg1 = vectors.hex(v, "msg1")
  let msg2 = vectors.hex(v, "msg2")
  let assert <<_:size(16), share:bytes>> = msg1 as "lv(Ya)"
  let assert <<_:size(16), rest:bytes>> = msg2 as "lv(Yb) || init"

  assert cpace_oquake.respond(suite, inputs(v), <<msg1:bits, 0>>)
    |> result_error
    == MalformedInitMessage
  assert cpace_oquake.respond(suite, inputs(v), <<31:16, share:bits>>)
    |> result_error
    == MalformedInitMessage

  let assert Ok(#(client, _)) =
    cpace_oquake.init_with(suite, inputs(v), scalar(v, "cpace_ya"))
  assert cpace_oquake.initiator_finish(suite, client, <<33:16, rest:bits>>)
    |> result_error
    == MalformedResponseMessage
  assert cpace_oquake.initiator_finish(suite, client, <<msg2:bits, 0>>)
    |> result_error
    == MalformedResponseMessage

  let assert Ok(#(server, _)) =
    cpace_oquake.respond_with(
      suite,
      inputs(v),
      msg1,
      scalar(v, "cpace_yb"),
      key_pair(v),
      secret.new(vectors.hex(v, "oquake_r")),
    )
  assert cpace_oquake.responder_finish(suite, server, <<0:size(12_792)>>)
    |> result_error
    == MalformedFinishMessage
}

fn result_error(result: Result(a, e)) -> e {
  let assert Error(error) = result as "the call refuses"
  error
}

/// Over the real ML-KEM and fresh randomness: the same password agrees on
/// key and transcript, and one wrong word completes with unequal keys.
pub fn real_runs_agree_only_on_the_same_password_test() {
  let suite = suite.suite()
  let both = fn(password: String) {
    Inputs(
      prs: secret.new(<<password:utf8>>),
      public_context: <<"Pondline test context":utf8>>,
      secret_context: secret.new(<<>>),
    )
  }

  assert list.all(
    [#("cradle-noble-velvet", True), #("cradle-noble-violet", False)],
    fn(run) {
      let #(server_password, same) = run
      let assert Ok(#(client, msg1)) =
        cpace_oquake.init(suite, both("cradle-noble-velvet"))
      let assert Ok(#(server, msg2)) =
        cpace_oquake.respond(suite, both(server_password), msg1)
      let assert Ok(ClientFinished(key: client_key, message:, transcript_hash:)) =
        cpace_oquake.initiator_finish(suite, client, msg2)
      let assert Ok(ServerFinished(key: server_key, transcript_hash: hash)) =
        cpace_oquake.responder_finish(suite, server, message)

      bit_array.byte_size(msg1) == cpace_oquake.init_message_bytes
      && bit_array.byte_size(msg2) == cpace_oquake.response_message_bytes
      && bit_array.byte_size(message) == cpace_oquake.finish_message_bytes
      && hash == transcript_hash
      && { client_key == server_key } == same
    },
  )
}
