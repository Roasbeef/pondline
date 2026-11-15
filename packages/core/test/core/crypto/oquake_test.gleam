//// Properties of `core/crypto/oquake` over a pure, deterministic stand-in
//// for ML-KEM, so that they run under qcheck without OpenSSL.
////
//// `fake_suite` alone will not do: its ML-KEM keys are repeated hashes,
//// whose 12-bit coefficients are often 3329 or more, and Kemeleon refuses
//// those as FIPS 203 does. So `kem_suite` replaces the three ML-KEM fields
//// of a seeded fake suite (by record update, so a field added to `Suite`
//// later needs no change here) with a KEM whose encapsulation keys are
//// well-formed and whose shared secret is a hash of the key and the
//// ciphertext. It is not a KEM anyone should use: anyone holding the
//// encapsulation key can compute the secret. What it keeps is what OQUAKE's
//// agreement depends on: the same key and ciphertext give the same secret
//// on both sides, and a different key gives a different one. The real
//// ML-KEM runs in `packages/primitives/test/primitives/oquake_test`, with
//// the draft's vectors.

import core/crypto/fake_suite
import core/crypto/oquake.{
  type Inputs, Established, InitMessageLength, Inputs, Response,
  ResponseMessageLength,
}
import core/crypto/suite.{type Suite}
import core/secret
import gleam/bit_array
import gleam/list
import gleam/string
import qcheck

/// How many runs each agreement property is checked over, and the seed
/// they are drawn from. A run costs two Kemeleon operations and a few
/// dozen fake HMACs; the seed is fixed so the gate is deterministic.
const run_count = 60

const run_seed = 6

/// The `oquake-mlbuaskem1024` DST of pqpake §9.2.1. Any bytes would do for
/// these properties; this is the one the vectors use.
const dst = <<
  0x60, 0x1e, 0xd3, 0x84, 0xc5, 0x77, 0x5d, 0xdd, 0x30, 0x21, 0xf5, 0x1a, 0x46,
  0x60, 0xff, 0xf2, 0x4b, 0xf4, 0xea, 0xa7, 0x84, 0x5a, 0x95, 0x8b, 0x2c, 0xad,
  0xe7, 0x52, 0x89, 0xd1, 0x84, 0xcd,
>>

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(run_count)
  |> qcheck.with_seed(qcheck.seed(run_seed))
  |> qcheck.run(generator, check)
}

/// A seeded fake suite with a KEM whose keys pass FIPS 203's modulus check.
fn kem_suite(seed: Int) -> Suite {
  let base = fake_suite.seeded(seed)

  suite.Suite(
    ..base,
    kem_keypair: fn() {
      let key = <<
        reduce(base.random(1536)):bits,
        base.random(32):bits,
      >>
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

/// Every 12-bit coefficient of the bytes taken modulo 3329, so the result
/// is a valid ByteEncode_12 polynomial vector.
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

/// The inputs of one side of a run.
fn inputs(prs: BitArray, public: BitArray, private: BitArray) -> Inputs {
  Inputs(
    dst:,
    prs: secret.new(prs),
    public_context: public,
    secret_context: secret.new(private),
  )
}

/// Runs OQUAKE with the initiator on `initiator` and the responder on
/// `responder`, returning both keys and both transcript hashes. Any
/// refusal fails the test: none of these runs has a malformed message.
fn run(
  seed: Int,
  initiator: Inputs,
  responder: Inputs,
) -> #(BitArray, BitArray, BitArray, BitArray) {
  let suite = kem_suite(seed)
  let assert Ok(#(state, init_message)) = oquake.init(suite, initiator)
  let assert Ok(Response(message:, key: responder_key, transcript_hash:)) =
    oquake.respond(suite, responder, init_message)
  let assert Ok(Established(key: initiator_key, transcript_hash: finished)) =
    oquake.finish(suite, state, message)

  assert bit_array.byte_size(init_message) == oquake.init_message_bytes
  assert bit_array.byte_size(message) == oquake.response_message_bytes
  #(
    secret.expose(initiator_key),
    secret.expose(responder_key),
    finished,
    transcript_hash,
  )
}

/// One draw for the agreement properties: a seed for the suite, and a
/// PRS, a public context and a secret context of arbitrary bytes.
fn sessions() -> qcheck.Generator(#(Int, BitArray, BitArray, BitArray)) {
  qcheck.tuple4(
    qcheck.bounded_int(0, 1_000_000),
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
  )
}

/// A non-empty suffix, appended to one side's input to make it differ.
fn suffixes() -> qcheck.Generator(BitArray) {
  qcheck.non_empty_byte_aligned_bit_array()
}

/// Two parties with the same PRS and contexts agree on the session key and
/// on the transcript hash. A swapped Feistel round or a mislabelled pad on
/// one side breaks this.
pub fn honest_runs_agree_test() {
  use #(seed, prs, public, private) <- property(sessions())

  let both = inputs(prs, public, private)
  let #(initiator, responder, finished, responded) = run(seed, both, both)

  assert initiator == responder
  assert finished == responded
  assert bit_array.byte_size(initiator) == oquake.key_bytes
  assert bit_array.byte_size(finished) == oquake.transcript_hash_bytes
}

/// A responder with another PRS completes without any error, and its key
/// differs from the initiator's. Skipping the tag check breaks this.
pub fn a_different_prs_yields_unequal_keys_test() {
  use #(#(seed, prs, public, private), suffix) <- property(qcheck.tuple2(
    sessions(),
    suffixes(),
  ))

  let #(initiator, responder, finished, responded) =
    run(
      seed,
      inputs(prs, public, private),
      inputs(<<prs:bits, suffix:bits>>, public, private),
    )

  assert initiator != responder
  assert finished == responded
}

/// A different public context is, to OQUAKE, a different password: the
/// keys differ, and so do the transcript hashes, which cover it.
pub fn a_different_public_context_yields_unequal_keys_test() {
  use #(#(seed, prs, public, private), suffix) <- property(qcheck.tuple2(
    sessions(),
    suffixes(),
  ))

  let #(initiator, responder, finished, responded) =
    run(
      seed,
      inputs(prs, public, private),
      inputs(prs, <<public:bits, suffix:bits>>, private),
    )

  assert initiator != responder
  assert finished != responded
}

/// A different secret context changes the keys and not the transcript,
/// which covers only what was public.
pub fn a_different_secret_context_yields_unequal_keys_test() {
  use #(#(seed, prs, public, private), suffix) <- property(qcheck.tuple2(
    sessions(),
    suffixes(),
  ))

  let #(initiator, responder, finished, responded) =
    run(
      seed,
      inputs(prs, public, private),
      inputs(prs, public, <<private:bits, suffix:bits>>),
    )

  assert initiator != responder
  assert finished == responded
}

/// A response whose tag was changed in any one byte finishes with the
/// fallback key, never with an error, and never with the session key.
pub fn a_changed_tag_finishes_with_the_fallback_test() {
  use #(seed, position) <- property(qcheck.tuple2(
    qcheck.bounded_int(0, 1_000_000),
    qcheck.bounded_int(0, oquake.tag_bytes - 1),
  ))

  let suite = kem_suite(seed)
  let both = inputs(<<"password">>, <<"public">>, <<>>)
  let assert Ok(#(state, init_message)) = oquake.init(suite, both)
  let assert Ok(Response(message:, key:, ..)) =
    oquake.respond(suite, both, init_message)
  let fallback = secret.new(<<0xAA:size(256)>>)
  let changed = flip(message, oquake.response_message_bytes - 32 + position)

  assert oquake.finish_with(suite, state, message, fallback)
    |> result_key
    == secret.expose(key)
  assert oquake.finish_with(suite, state, changed, fallback) |> result_key
    == secret.expose(fallback)
}

/// A changed ciphertext decapsulates to another secret, so the tag no
/// longer matches and the fallback is returned.
pub fn a_changed_ciphertext_finishes_with_the_fallback_test() {
  let suite = kem_suite(3)
  let both = inputs(<<"password">>, <<>>, <<>>)
  let assert Ok(#(state, init_message)) = oquake.init(suite, both)
  let assert Ok(Response(message:, ..)) =
    oquake.respond(suite, both, init_message)
  let fallback = secret.new(<<0xBB:size(256)>>)

  assert oquake.finish_with(suite, state, flip(message, 0), fallback)
    |> result_key
    == secret.expose(fallback)
}

fn result_key(result: Result(oquake.Established, oquake.Refusal)) -> BitArray {
  let assert Ok(Established(key:, ..)) = result as "finish does not refuse"
  secret.expose(key)
}

/// The message with one bit of the byte at `position` inverted.
fn flip(message: BitArray, position: Int) -> BitArray {
  let assert <<before:bytes-size(position), byte, after:bytes>> = message
    as "the position is inside the message"
  <<before:bits, { byte |> bit_xor_one }, after:bits>>
}

fn bit_xor_one(byte: Int) -> Int {
  case byte % 2 {
    0 -> byte + 1
    _ -> byte - 1
  }
}

/// A message of the wrong length is a typed refusal on either side, which
/// is how the draft's MUST abort is surfaced.
pub fn wrong_lengths_are_refused_test() {
  let suite = kem_suite(4)
  let both = inputs(<<"password">>, <<>>, <<>>)
  let assert Ok(#(state, init_message)) = oquake.init(suite, both)

  assert oquake.respond(suite, both, <<init_message:bits, 0>>)
    == Error(InitMessageLength(found: 1661))
  assert oquake.respond(suite, both, <<>>) == Error(InitMessageLength(found: 0))
  assert oquake.finish(suite, state, <<0:size(12_792)>>)
    == Error(ResponseMessageLength(found: 1599))
}

/// A context longer than its two-byte length prefix is refused rather than
/// silently wrapped.
pub fn an_overlong_context_is_refused_test() {
  let suite = kem_suite(5)
  let long = <<0:size(524_288)>>

  assert oquake.init(suite, inputs(<<"p">>, long, <<>>))
    == Error(oquake.ContextTooLong)
  assert oquake.init(suite, inputs(<<"p">>, <<>>, long))
    == Error(oquake.ContextTooLong)
}

/// Neither the state nor the outputs print the keys or the password.
pub fn secrets_do_not_print_test() {
  let suite = kem_suite(8)
  let both = inputs(<<"correct horse battery">>, <<>>, <<"cpace key">>)
  let assert Ok(#(state, init_message)) = oquake.init(suite, both)
  let assert Ok(response) = oquake.respond(suite, both, init_message)
  let assert Ok(established) = oquake.finish(suite, state, response.message)
  let printed =
    string.concat([
      string.inspect(state),
      string.inspect(response),
      string.inspect(established),
      string.inspect(both),
    ])

  assert !string.contains(printed, "correct horse")
  assert !string.contains(printed, "cpace key")
  assert list.all([response.key, established.key], fn(key) {
    !string.contains(printed, string.inspect(secret.expose(key)))
  })
}
