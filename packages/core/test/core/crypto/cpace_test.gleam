//// CPace (`core/crypto/cpace`) and the shared PAKE encodings
//// (`core/crypto/pake_common`) as pure Gleam, over the fake suite.
////
//// The fake suite's X25519 is an XOR, so it agrees commutatively and two
//// honest parties reach one key, but it is not a group: the vectors and
//// the low-order aborts are checked over the real primitives in
//// `packages/primitives/test/primitives/cpace_test.gleam`. What is checked
//// here is the shape of the protocol: which inputs the key depends on, the
//// length checks, and the string utilities against cpace-21 Appendix A's
//// vectors (copied by script from the draft text, A.1.2, A.1.4, A.3.5).

import core/crypto/cpace.{
  type CpaceError, ContextTooLong, DegenerateGenerator, LowOrderShare,
  MalformedShare, PrimitiveFailed,
}
import core/crypto/fake_suite
import core/crypto/pake_common
import core/crypto/suite.{Suite}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/list
import gleam/result
import gleam/string
import qcheck

/// How many runs each property draws, and its fixed seed.
const property_count = 150

const property_seed = 7_748_255

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

fn hex(text: String) -> BitArray {
  let assert Ok(bytes) = bit_array.base16_decode(string.uppercase(text))
    as "test vectors are well-formed hex"
  bytes
}

/// One side's inputs: a password, a public context and a secret context.
type Inputs {
  Inputs(password: Secret, public_context: BitArray, secret_context: Secret)
}

/// Inputs drawn short, so a failure shrinks toward empty strings.
fn inputs() -> qcheck.Generator(Inputs) {
  qcheck.map3(
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
    qcheck.byte_aligned_bit_array(),
    fn(password, public_context, secret_context) {
      Inputs(
        password: secret.new(password),
        public_context:,
        secret_context: secret.new(secret_context),
      )
    },
  )
}

/// One whole run, the initiator with one set of inputs and the responder
/// with another: the two keys and the two transcript hashes.
fn run(
  initiator: Inputs,
  responder: Inputs,
) -> Result(#(Secret, Secret, BitArray, BitArray), CpaceError) {
  let suite = fake_suite.suite()
  let assert Ok(initiated) =
    cpace.init(
      suite,
      initiator.password,
      initiator.public_context,
      initiator.secret_context,
    )
    as "a short context always initiates"

  use responded <- result.try(cpace.respond(
    suite,
    responder.password,
    responder.public_context,
    responder.secret_context,
    initiated.share,
  ))

  let assert Ok(finished) =
    cpace.finish(
      suite,
      initiated.state,
      initiator.public_context,
      responded.share,
    )
    as "a share the fake responder made always finishes"

  Ok(#(
    finished.key,
    responded.key,
    finished.transcript_hash,
    responded.transcript_hash,
  ))
}

/// Two honest parties with the same inputs reach one 64-byte key and one
/// 32-byte transcript hash.
pub fn honest_parties_agree_property_test() {
  use both <- property(inputs())

  let assert Ok(#(initiator_key, responder_key, initiator_th, responder_th)) =
    run(both, both)
    as "an honest run completes"

  assert initiator_key == responder_key
  assert secret.byte_size(initiator_key) == cpace.key_bytes
  assert initiator_th == responder_th
  assert bit_array.byte_size(initiator_th) == 32
}

/// A different password, public context or secret context on the
/// responder's side gives the two parties different keys. The difference
/// is drawn as an index so a failure shrinks toward the password.
pub fn any_differing_input_gives_different_keys_property_test() {
  use #(initiator, which, extra) <- property(qcheck.tuple3(
    inputs(),
    qcheck.bounded_int(0, 2),
    qcheck.non_empty_byte_aligned_bit_array(),
  ))

  let responder = case which {
    0 ->
      Inputs(
        ..initiator,
        password: secret.new(<<
          secret.expose(initiator.password):bits,
          extra:bits,
        >>),
      )
    1 ->
      Inputs(..initiator, public_context: <<
        initiator.public_context:bits,
        extra:bits,
      >>)
    _ ->
      Inputs(
        ..initiator,
        secret_context: secret.new(<<
          secret.expose(initiator.secret_context):bits,
          extra:bits,
        >>),
      )
  }

  let assert Ok(#(initiator_key, responder_key, _, _)) =
    run(initiator, responder)
    as "a mismatched run still completes: CPace has no confirmation"

  assert initiator_key != responder_key
}

/// The transcript hash binds the public context: two runs that differ only
/// there disagree on it, and the secret context does not reach it.
pub fn the_transcript_hash_binds_the_public_context_test() {
  let suite = fake_suite.suite()
  let password = secret.new(<<"password">>)
  let empty = secret.new(<<>>)
  let assert Ok(initiated) = cpace.init(suite, password, <<"one">>, empty)
  let assert Ok(one) =
    cpace.respond(suite, password, <<"one">>, empty, initiated.share)
  let assert Ok(two) =
    cpace.finish(suite, initiated.state, <<"two">>, one.share)

  assert one.transcript_hash != two.transcript_hash
}

/// A share that is not 32 bytes is refused by both sides before any work.
pub fn a_share_of_the_wrong_length_is_refused_test() {
  let suite = fake_suite.suite()
  let password = secret.new(<<"password">>)
  let empty = secret.new(<<>>)
  let assert Ok(initiated) = cpace.init(suite, password, <<>>, empty)

  list.each([<<>>, <<0:248>>, <<0:264>>], fn(share) {
    assert cpace.respond(suite, password, <<>>, empty, share)
      == Error(MalformedShare)
    assert cpace.finish(suite, initiated.state, <<>>, share)
      == Error(MalformedShare)
  })
}

/// Under the fake XOR agreement `K = y XOR Y`, so a peer share equal to
/// this side's own scalar makes the shared point zero: the abort path,
/// reached without real low-order points (those are checked over real
/// X25519 in `packages/primitives`).
pub fn an_identity_shared_point_aborts_test() {
  let suite = fake_suite.suite()
  let password = secret.new(<<"password">>)
  let empty = secret.new(<<>>)
  let assert Ok(scalar) = cpace.scalar_from_bytes(<<7:256>>)
  let assert Ok(initiated) =
    cpace.init_with_scalar(suite, password, <<>>, empty, scalar)

  assert cpace.respond_with_scalar(
      suite,
      password,
      <<>>,
      empty,
      <<7:256>>,
      scalar,
    )
    == Error(LowOrderShare)
  assert cpace.finish(suite, initiated.state, <<>>, <<7:256>>)
    == Error(LowOrderShare)
}

/// The abort is CPace's own and does not lean on the suite: a suite whose
/// X25519 hands back the all-zero point instead of refusing it still makes
/// both sides abort.
pub fn the_abort_holds_for_a_suite_that_returns_zero_test() {
  let lenient =
    Suite(..fake_suite.suite(), x25519: fn(_scalar, _point) { Ok(<<0:256>>) })
  let password = secret.new(<<"password">>)
  let empty = secret.new(<<>>)
  let assert Ok(scalar) = cpace.scalar_from_bytes(<<7:256>>)
  let assert Ok(initiated) =
    cpace.init_with_scalar(lenient, password, <<>>, empty, scalar)

  assert cpace.respond(lenient, password, <<>>, empty, <<9:256>>)
    == Error(LowOrderShare)
  assert cpace.finish(lenient, initiated.state, <<>>, <<9:256>>)
    == Error(LowOrderShare)
}

/// A generator that X25519 sends to the identity under this side's own
/// scalar is refused before a share leaves, and a suite that returns the
/// wrong number of random bytes or a short digest is reported, not
/// trusted.
pub fn a_broken_generator_or_suite_is_refused_test() {
  let base = fake_suite.suite()
  let password = secret.new(<<"password">>)
  let empty = secret.new(<<>>)
  let refusing = Suite(..base, x25519: fn(_scalar, _point) { Error(Nil) })
  let short_random = Suite(..base, random: fn(_count) { <<0:248>> })
  let short_hash = Suite(..base, sha512: fn(_data) { <<0:248>> })

  assert cpace.init(refusing, password, <<>>, empty)
    == Error(DegenerateGenerator)
  assert cpace.init(short_random, password, <<>>, empty)
    == Error(PrimitiveFailed)
  assert cpace.respond(short_random, password, <<>>, empty, <<9:256>>)
    == Error(PrimitiveFailed)
  assert cpace.init(short_hash, password, <<>>, empty) == Error(PrimitiveFailed)
}

/// A public context `TH` cannot frame is refused at `init`, before a share
/// is sent, and at `respond`.
pub fn a_context_too_long_for_the_transcript_hash_is_refused_test() {
  let suite = fake_suite.suite()
  let password = secret.new(<<"password">>)
  let empty = secret.new(<<>>)
  let longest_bits = pake_common.max_field_bytes * 8
  let longest = <<0:size(longest_bits)>>
  let too_long = <<longest:bits, 0>>

  assert cpace.init(suite, password, too_long, empty) == Error(ContextTooLong)
  assert cpace.respond(suite, password, too_long, empty, <<1:256>>)
    == Error(ContextTooLong)

  let assert Ok(_) = cpace.init(suite, password, longest, empty)
    as "the longest framable context is accepted"
}

/// Nothing secret prints: not the password, not the state holding the
/// scalar, not the key in a result.
pub fn no_secret_is_rendered_test() {
  let suite = fake_suite.suite()
  let password = secret.new(<<"hunter2-hunter2">>)
  let empty = secret.new(<<>>)
  let assert Ok(scalar) =
    cpace.scalar_from_bytes(<<"scalar-scalar-scalar-scalar-1234">>)
  let assert Ok(initiated) =
    cpace.init_with_scalar(suite, password, <<>>, empty, scalar)
  let assert Ok(responded) =
    cpace.respond(suite, password, <<>>, empty, initiated.share)
  let key = string.inspect(secret.expose(responded.key))

  assert !string.contains(string.inspect(password), "hunter2")
  assert !string.contains(string.inspect(initiated), "scalar-")
  assert !string.contains(string.inspect(initiated), "hunter2")
  assert !string.contains(string.inspect(responded), key)
}

// ------------------------------------------------- cpace-21 Appendix A

/// A.1.2: `prepend_len`, including the 127- and 128-byte boundary where
/// LEB128 grows a second byte.
pub fn prepend_len_a_1_2_test() {
  let upto_127 = counting_bytes(127)
  let upto_128 = counting_bytes(128)

  assert cpace.prepend_len(<<>>) == hex("00")
  assert cpace.prepend_len(<<"1234">>) == hex("0431323334")
  assert cpace.prepend_len(upto_127) == <<0x7f, upto_127:bits>>
  assert cpace.prepend_len(upto_128) == <<0x80, 0x01, upto_128:bits>>
}

/// `bytes(range(count))` in the draft's Python: 0, 1, ..., count - 1.
fn counting_bytes(count: Int) -> BitArray {
  case count <= 0 {
    True -> <<>>
    False -> <<counting_bytes(count - 1):bits, { count - 1 }>>
  }
}

/// A.1.4: `lv_cat`.
pub fn lv_cat_a_1_4_test() {
  assert cpace.lv_cat([<<"1234">>, <<"5">>, <<>>, <<"678">>])
    == hex("043132333401350003363738")
}

/// A.3.5: `transcript_ir`.
pub fn transcript_ir_a_3_5_test() {
  assert cpace.transcript_ir(<<"123">>, <<"PartyA">>, <<"234">>, <<"PartyB">>)
    == hex("03313233065061727479410332333406506172747942")
  assert cpace.transcript_ir(<<"3456">>, <<"PartyA">>, <<"2345">>, <<"PartyB">>)
    == hex("043334353606506172747941043233343506506172747942")
}

/// The generator string's padding fills SHA-512's first block for a short
/// password and vanishes for a long one. `len_zpad = 128 - 1 - (len + 1) -
/// 9`, so B.1.1's 8-byte password gets 109 zero bytes, a 116-byte one gets
/// one, and one of 117 bytes or more gets none. Each length below counts
/// the DSI (9), the framed password, the framed padding and the two empty
/// framed fields (1 each).
pub fn generator_string_padding_test() {
  let context = secret.new(<<>>)
  let length = fn(password_bytes) {
    let bits = password_bytes * 8
    cpace.generator_string(secret.new(<<0:size(bits)>>), context, <<>>)
    |> secret.byte_size
  }

  assert length(8) == 9 + 9 + 110 + 1 + 1
  assert length(116) == 9 + 117 + 2 + 1 + 1
  assert length(117) == 9 + 118 + 1 + 1 + 1
  assert length(200) == 9 + 202 + 1 + 1 + 1
}

/// C.1: `EncodePublicContext` over E.4's identifiers, against E.4's
/// printed public context.
pub fn encode_public_context_e_4_test() {
  assert pake_common.encode_public_context(
      hex("5f02c05f74ddc40c6a72580fcca6c10e"),
      <<"client">>,
      <<"server">>,
    )
    == Ok(hex(
      "000000105f02c05f74ddc40c6a72580fcca6c10e00000006636c69656e7400000006736572766572",
    ))
}

/// §3.1: `lv_encode` frames with two bytes and refuses what they cannot
/// carry.
pub fn lv_encode_test() {
  assert pake_common.lv_encode(<<0, 1, 2>>) == Ok(<<0, 3, 0, 1, 2>>)
  assert pake_common.lv_encode(<<0:size(65_536 * 8)>>) == Error(Nil)
}
