//// Properties of `core/crypto/cpace_oquake` as pure Gleam, over the fake
//// suite with a stand-in ML-KEM, so they run under qcheck without OpenSSL.
////
//// `kem_suite` is `oquake_test`'s stand-in, repeated here and made public
//// so `core/rendezvous_test` can share it: the fake suite's own ML-KEM keys
//// fail Kemeleon's modulus check, so the three ML-KEM fields are replaced
//// by a KEM whose keys are well-formed and whose secret is a hash of key
//// and ciphertext. It is no KEM at all against an attacker; it keeps only
//// what agreement depends on. The draft's vector and the real ML-KEM run in
//// `packages/primitives/test/primitives/cpace_oquake_test.gleam`.

import core/crypto/cpace_oquake.{
  type Inputs, ClientFinished, Inputs, MalformedFinishMessage,
  MalformedInitMessage, MalformedResponseMessage, ServerFinished,
}
import core/crypto/fake_suite
import core/crypto/suite.{type Suite}
import core/secret
import gleam/bit_array
import gleam/string
import qcheck

/// How many runs each property is checked over, and the seed they are
/// drawn from. A run costs three Kemeleon operations and some hundred fake
/// HMACs; the seed is fixed so the gate is deterministic.
const run_count = 100

const run_seed = 7141

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(run_count)
  |> qcheck.with_seed(qcheck.seed(run_seed))
  |> qcheck.run(generator, check)
}

/// A seeded fake suite whose ML-KEM keys pass FIPS 203's modulus check, so
/// Kemeleon accepts them.
pub fn kem_suite(seed: Int) -> Suite {
  let base = fake_suite.seeded(seed)

  suite.Suite(
    ..base,
    kem_keypair: fn() {
      let key = <<reduce(base.random(1536)):bits, base.random(32):bits>>
      #(key, key)
    },
    kem_encapsulate: fn(key) {
      case bit_array.byte_size(key) == 1568 {
        True -> {
          let ciphertext = base.random(1568)
          Ok(#(base.sha256(<<key:bits, ciphertext:bits>>), ciphertext))
        }
        False -> Error(Nil)
      }
    },
    kem_decapsulate: fn(key, ciphertext) {
      case bit_array.byte_size(ciphertext) == 1568 {
        True -> Ok(base.sha256(<<key:bits, ciphertext:bits>>))
        False -> Error(Nil)
      }
    },
  )
}

/// Every 12-bit coefficient of the bytes taken modulo 3329.
fn reduce(bytes: BitArray) -> BitArray {
  case bytes {
    <<low, middle, high, rest:bytes>> -> {
      let first = { low + 256 * { middle % 16 } } % 3329
      let second = { middle / 16 + 16 * high } % 3329
      <<
        { first % 256 },
        { first / 256 + 16 * { second % 16 } },
        { second / 16 },
        reduce(rest):bits,
      >>
    }
    _ -> <<>>
  }
}

fn inputs(prs: BitArray, public: BitArray, private: BitArray) -> Inputs {
  Inputs(
    prs: secret.new(prs),
    public_context: public,
    secret_context: secret.new(private),
  )
}

/// One run with the client on `client` and the server on `server`: both
/// keys and both transcript hashes. The two sides draw from separate
/// seeded suites, as two daemons would.
fn run(
  seed: Int,
  client: Inputs,
  server: Inputs,
) -> #(BitArray, BitArray, BitArray, BitArray) {
  let client_suite = kem_suite(seed)
  let server_suite = kem_suite(seed + 1)
  let assert Ok(#(client_state, msg1)) = cpace_oquake.init(client_suite, client)
  let assert Ok(#(server_state, msg2)) =
    cpace_oquake.respond(server_suite, server, msg1)
  let assert Ok(ClientFinished(key: client_key, message: msg3, transcript_hash:)) =
    cpace_oquake.initiator_finish(client_suite, client_state, msg2)
  let assert Ok(ServerFinished(key: server_key, transcript_hash: server_hash)) =
    cpace_oquake.responder_finish(server_suite, server_state, msg3)

  assert bit_array.byte_size(msg1) == cpace_oquake.init_message_bytes
  assert bit_array.byte_size(msg2) == cpace_oquake.response_message_bytes
  assert bit_array.byte_size(msg3) == cpace_oquake.finish_message_bytes
  #(
    secret.expose(client_key),
    secret.expose(server_key),
    transcript_hash,
    server_hash,
  )
}

/// A seed, then a password, a public and a secret context, each drawn short
/// so a failure shrinks toward empty strings.
fn sessions() -> qcheck.Generator(#(Int, BitArray, BitArray, BitArray)) {
  qcheck.tuple4(
    qcheck.bounded_int(0, 1_000_000),
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
  )
}

/// A session and a non-empty suffix that makes one side's input differ.
fn differing() -> qcheck.Generator(
  #(#(Int, BitArray, BitArray, BitArray), BitArray),
) {
  qcheck.tuple2(sessions(), qcheck.non_empty_byte_aligned_bit_array())
}

/// The same password and contexts give both sides one key and one
/// transcript hash, of the configured sizes.
pub fn honest_runs_agree_test() {
  use #(seed, prs, public, private) <- property(sessions())

  let both = inputs(prs, public, private)
  let #(client, server, client_hash, server_hash) = run(seed, both, both)

  assert client == server
  assert client_hash == server_hash
  assert bit_array.byte_size(client) == cpace_oquake.key_bytes
  assert bit_array.byte_size(client_hash) == cpace_oquake.transcript_hash_bytes
}

/// Another password completes without an error and with unequal keys. The
/// transcript covers only the messages, which both saw alike.
pub fn a_different_password_yields_unequal_keys_test() {
  use #(#(seed, prs, public, private), suffix) <- property(differing())

  let #(client, server, client_hash, server_hash) =
    run(
      seed,
      inputs(prs, public, private),
      inputs(<<prs:bits, suffix:bits>>, public, private),
    )

  assert client != server
  assert client_hash == server_hash
}

/// Another public context changes both the keys and the transcript.
pub fn a_different_public_context_yields_unequal_keys_test() {
  use #(#(seed, prs, public, private), suffix) <- property(differing())

  let #(client, server, client_hash, server_hash) =
    run(
      seed,
      inputs(prs, public, private),
      inputs(prs, <<public:bits, suffix:bits>>, private),
    )

  assert client != server
  assert client_hash != server_hash
}

/// Another secret context changes the keys and not the transcript.
pub fn a_different_secret_context_yields_unequal_keys_test() {
  use #(#(seed, prs, public, private), suffix) <- property(differing())

  let #(client, server, client_hash, server_hash) =
    run(
      seed,
      inputs(prs, public, private),
      inputs(prs, public, <<private:bits, suffix:bits>>),
    )

  assert client != server
  assert client_hash == server_hash
}

fn result_error(result: Result(a, e)) -> e {
  let assert Error(error) = result as "the call refuses"
  error
}

/// Each message of the wrong length or with the wrong length prefix is a
/// typed error naming that message.
pub fn malformed_messages_are_refused_test() {
  let suite = kem_suite(11)
  let both = inputs(<<"password">>, <<"context">>, <<>>)
  let assert Ok(#(client, msg1)) = cpace_oquake.init(suite, both)
  let assert Ok(#(server, msg2)) = cpace_oquake.respond(suite, both, msg1)
  let assert <<_:size(16), share:bytes>> = msg1 as "lv(Ya)"
  let assert <<_:size(16), rest:bytes>> = msg2 as "lv(Yb) || init"

  assert result_error(cpace_oquake.respond(suite, both, <<msg1:bits, 0>>))
    == MalformedInitMessage
  assert result_error(cpace_oquake.respond(suite, both, <<0:16, share:bits>>))
    == MalformedInitMessage
  assert result_error(cpace_oquake.initiator_finish(suite, client, <<>>))
    == MalformedResponseMessage
  assert result_error(
      cpace_oquake.initiator_finish(suite, client, <<31:16, rest:bits>>),
    )
    == MalformedResponseMessage
  assert result_error(cpace_oquake.responder_finish(suite, server, <<0>>))
    == MalformedFinishMessage
}

/// Neither state nor any result prints the password, a context's secret
/// part or a key.
pub fn secrets_do_not_print_test() {
  let suite = kem_suite(12)
  let both = inputs(<<"correct horse battery">>, <<>>, <<"stage secret">>)
  let assert Ok(#(client, msg1)) = cpace_oquake.init(suite, both)
  let assert Ok(#(server, msg2)) = cpace_oquake.respond(suite, both, msg1)
  let assert Ok(finished) = cpace_oquake.initiator_finish(suite, client, msg2)
  let assert Ok(done) =
    cpace_oquake.responder_finish(suite, server, finished.message)
  let printed =
    string.concat([
      string.inspect(client),
      string.inspect(server),
      string.inspect(finished),
      string.inspect(done),
      string.inspect(both),
    ])

  assert !string.contains(printed, "correct horse")
  assert !string.contains(printed, "stage secret")
  assert !string.contains(printed, string.inspect(secret.expose(done.key)))
}
