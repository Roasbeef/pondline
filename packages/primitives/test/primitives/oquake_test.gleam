//// OQUAKE (`core/crypto/oquake`) against the vectors of
//// `draft-vos-cfrg-pqpake-03` and over the real ML-KEM-1024.
////
//// Two vectors exercise it. Appendix E.2 is OQUAKE alone, under the
//// `oquake-mlbuaskem1024` DST, with a public context built by
//// `EncodePublicContext` and an empty secret context. Appendix E.4 is
//// CPaceOQUAKE, whose Stage 2 is OQUAKE under the CPaceOQUAKE DST with
//// CPace's transcript hash as public context and CPace's session key as
//// secret context; this file checks that stage alone, from the `cpace_th`
//// and `cpace_ISK` the vector lists. Running both is what shows the DST is
//// a parameter and not a constant.
////
//// The draft's vectors fix ML-KEM's randomness (`keygen_seed`,
//// `encaps_m`), which OTP cannot take, and list no decapsulation key. So
//// the ML-KEM operations are replaced, by record update of the real suite,
//// with ones that answer exactly what the vector says ML-KEM answered: the
//// encapsulation returns the vector's `oquake_k` and ciphertext, but only
//// for the encapsulation key the vector's `oquake_upk` decodes to, and the
//// decapsulation returns `oquake_k` for the vector's ciphertext. Everything
//// OQUAKE itself computes (Kemeleon, the Feistel pads, the effective
//// password, the tag, the key, the transcript hash, the encodings) runs for
//// real. The honest and wrong-password runs at the end use the real ML-KEM
//// throughout.

import core/crypto/bua_skem
import core/crypto/kemeleon
import core/crypto/oquake.{type Inputs, Established, Inputs, Response}
import core/crypto/suite as core_suite
import core/secret
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import primitives/suite
import primitives/vectors

/// The DST of `oquake-mlbuaskem1024`, pqpake §9.2.1.
const oquake_dst = <<
  0x60, 0x1e, 0xd3, 0x84, 0xc5, 0x77, 0x5d, 0xdd, 0x30, 0x21, 0xf5, 0x1a, 0x46,
  0x60, 0xff, 0xf2, 0x4b, 0xf4, 0xea, 0xa7, 0x84, 0x5a, 0x95, 0x8b, 0x2c, 0xad,
  0xe7, 0x52, 0x89, 0xd1, 0x84, 0xcd,
>>

/// The DST of `cpaceoquake-x25519-mlbuaskem1024`, pqpake §9.4.1, which
/// applies to its OQUAKE stage too.
const cpace_oquake_dst = <<
  0x44, 0x3e, 0x30, 0x89, 0x98, 0x5f, 0x0f, 0x8d, 0xdd, 0xfb, 0x20, 0xcc, 0x5e,
  0x86, 0x18, 0xf4, 0x47, 0xbd, 0xcf, 0xe6, 0xdd, 0x39, 0xab, 0xb2, 0x39, 0x11,
  0xcd, 0x78, 0x4c, 0x07, 0x51, 0x20,
>>

/// One OQUAKE run as a vector records it.
type Stage {
  Stage(
    inputs: Inputs,
    upk: BitArray,
    multiples: kemeleon.Randomness,
    r: BitArray,
    shared_secret: BitArray,
    init_message: BitArray,
    response_message: BitArray,
    key: BitArray,
    transcript_hash: BitArray,
  )
}

fn load(name: String) -> vectors.Vector {
  let assert [vector] = vectors.load(name) as "the fixture has one case"
  vector
}

fn multiples(vector: vectors.Vector) -> kemeleon.Randomness {
  let assert Ok(numbers) =
    vectors.text(vector, "kemeleon_m")
    |> string.split(" ")
    |> list.try_map(int.parse)
    as "four decimal numbers"
  let assert Ok(randomness) = kemeleon.randomness_from_multiples(numbers)
    as "four non-negative multiples"
  randomness
}

/// Appendix E.2: OQUAKE alone.
fn oquake_alone() -> Stage {
  let v = load("oquake_mlbuaskem1024")

  Stage(
    inputs: Inputs(
      dst: oquake_dst,
      prs: secret.new(vectors.hex(v, "PRS")),
      public_context: vectors.hex(v, "public_context"),
      secret_context: secret.new(vectors.hex(v, "secret_context")),
    ),
    upk: vectors.hex(v, "oquake_upk"),
    multiples: multiples(v),
    r: vectors.hex(v, "oquake_r"),
    shared_secret: vectors.hex(v, "oquake_k"),
    init_message: vectors.hex(v, "init_msg"),
    response_message: vectors.hex(v, "resp_msg"),
    key: vectors.hex(v, "key"),
    transcript_hash: vectors.hex(v, "th"),
  )
}

/// Appendix E.4: the OQUAKE stage of CPaceOQUAKE. Its init message is
/// what follows `lv(Yb)` in `msg2` (Appendix C.4), and its response is
/// `msg3`.
fn cpace_stage() -> Stage {
  let v = load("oquake_cpaceoquake_stage")
  let assert <<length:size(16), _yb:bytes-size(length), init_message:bytes>> =
    vectors.hex(v, "msg2")
    as "msg2 is lv(Yb) || oquake_init"

  Stage(
    inputs: Inputs(
      dst: cpace_oquake_dst,
      prs: secret.new(vectors.hex(v, "PRS")),
      public_context: vectors.hex(v, "cpace_th"),
      secret_context: secret.new(vectors.hex(v, "cpace_ISK")),
    ),
    upk: vectors.hex(v, "oquake_upk"),
    multiples: multiples(v),
    r: vectors.hex(v, "oquake_r"),
    shared_secret: vectors.hex(v, "oquake_k"),
    init_message:,
    response_message: vectors.hex(v, "msg3"),
    key: vectors.hex(v, "oquake_key"),
    transcript_hash: vectors.hex(v, "th"),
  )
}

/// The ciphertext the vector's responder sent, the first Nct bytes of its
/// message.
fn ciphertext(stage: Stage) -> BitArray {
  let assert Ok(ciphertext) =
    bit_array.slice(stage.response_message, 0, bua_skem.ciphertext_bytes)
    as "the response holds a ciphertext"
  ciphertext
}

/// The real suite with ML-KEM's answers replaced by the vector's: the
/// encapsulation answers only for the key the vector's `oquake_upk`
/// decodes to, so a responder that unmasked anything else fails here.
fn replaying(stage: Stage) -> core_suite.Suite {
  let assert Ok(encapsulation_key) = kemeleon.decode(stage.upk)
    as "the vector's upk decodes"
  let ciphertext = ciphertext(stage)

  core_suite.Suite(
    ..suite.suite(),
    kem_encapsulate: fn(key) {
      case key == encapsulation_key {
        True -> Ok(#(stage.shared_secret, ciphertext))
        False -> Error(Nil)
      }
    },
    kem_decapsulate: fn(_key, received) {
      case received == ciphertext {
        True -> Ok(stage.shared_secret)
        False -> Error(Nil)
      }
    },
  )
}

/// The initiator's state and message for the vector: its key pair rebuilt
/// from `oquake_upk` and `kemeleon_m` (with a placeholder decapsulation
/// key, which `replaying` never reads), and its `r`.
fn initiate(stage: Stage) -> #(oquake.InitiatorState, BitArray) {
  let assert Ok(encapsulation_key) = kemeleon.decode(stage.upk)
    as "the vector's upk decodes"
  let assert Ok(key_pair) =
    bua_skem.key_pair_from(
      secret.new(<<0:size(25_344)>>),
      encapsulation_key,
      stage.multiples,
    )
    as "the vector's key re-encodes"
  let assert Ok(initiated) =
    oquake.init_with(
      replaying(stage),
      stage.inputs,
      key_pair,
      secret.new(stage.r),
    )
    as "init does not refuse"
  initiated
}

/// `Init` reproduces the vector's message from its key and `r`: the
/// effective password, both Feistel rounds and the C.2 encoding.
fn check_init(stage: Stage) -> Nil {
  let #(_state, message) = initiate(stage)

  assert message == stage.init_message
}

/// `Respond` to the vector's message reproduces its response, key and
/// transcript hash: the unmasking, the tag and every derivation after it.
fn check_respond(stage: Stage) -> Nil {
  let assert Ok(Response(message:, key:, transcript_hash:)) =
    oquake.respond(replaying(stage), stage.inputs, stage.init_message)

  assert message == stage.response_message
  assert secret.expose(key) == stage.key
  assert transcript_hash == stage.transcript_hash
}

/// `Finish` on the vector's response reproduces its key and transcript
/// hash, and never returns the fallback for it.
fn check_finish(stage: Stage) -> Nil {
  let #(state, _message) = initiate(stage)
  let fallback = secret.new(<<0xAA:size(256)>>)
  let assert Ok(Established(key:, transcript_hash:)) =
    oquake.finish_with(
      replaying(stage),
      state,
      stage.response_message,
      fallback,
    )

  assert secret.expose(key) == stage.key
  assert transcript_hash == stage.transcript_hash
}

pub fn e2_init_message_test() {
  check_init(oquake_alone())
}

pub fn e2_respond_test() {
  check_respond(oquake_alone())
}

pub fn e2_finish_test() {
  check_finish(oquake_alone())
}

pub fn e4_stage_init_message_test() {
  check_init(cpace_stage())
}

pub fn e4_stage_respond_test() {
  check_respond(cpace_stage())
}

pub fn e4_stage_finish_test() {
  check_finish(cpace_stage())
}

/// E.2's public context is `EncodePublicContext(sid, U, S)` of Appendix C.1.
pub fn e2_public_context_encoding_test() {
  let v = load("oquake_mlbuaskem1024")

  assert oquake.public_context(
      sid: vectors.hex(v, "sid"),
      client: vectors.hex(v, "U"),
      server: vectors.hex(v, "S"),
    )
    == Ok(vectors.hex(v, "public_context"))
}

/// The two vectors' DSTs are not interchangeable: E.2's message under the
/// CPaceOQUAKE DST is a different message.
pub fn the_dst_is_bound_into_the_message_test() {
  let stage = oquake_alone()
  let other =
    Stage(..stage, inputs: Inputs(..stage.inputs, dst: cpace_oquake_dst))
  let #(_state, message) = initiate(other)

  assert message != stage.init_message
}

/// The draft's failure behaviour on the vector: the response with its tag
/// changed finishes with the fallback key, not an error, and its
/// transcript hash differs because it covers the tag received.
pub fn e2_changed_tag_finishes_with_the_fallback_test() {
  let stage = oquake_alone()
  let #(state, _message) = initiate(stage)
  let fallback = secret.new(<<0xAA:size(256)>>)
  let assert <<ciphertext:bytes-size(1568), tag:size(256)>> =
    stage.response_message
    as "ct || h"
  let changed = <<
    ciphertext:bits,
    { int.bitwise_exclusive_or(tag, 1) }:size(256),
  >>
  let assert Ok(Established(key:, transcript_hash:)) =
    oquake.finish_with(replaying(stage), state, changed, fallback)

  assert key == fallback
  assert transcript_hash != stage.transcript_hash
}

/// A decapsulation failure is the draft's DecapsError, which Finish turns
/// into the fallback key rather than an error.
pub fn e2_decapsulation_failure_finishes_with_the_fallback_test() {
  let stage = oquake_alone()
  let #(state, _message) = initiate(stage)
  let fallback = secret.new(<<0xCC:size(256)>>)
  let failing =
    core_suite.Suite(..replaying(stage), kem_decapsulate: fn(_, _) {
      Error(Nil)
    })
  let assert Ok(Established(key:, transcript_hash:)) =
    oquake.finish_with(failing, state, stage.response_message, fallback)

  assert key == fallback
  assert transcript_hash == stage.transcript_hash
}

fn honest_inputs(prs: String) -> Inputs {
  Inputs(
    dst: cpace_oquake_dst,
    prs: secret.new(<<prs:utf8>>),
    public_context: <<"Pondline test context":utf8>>,
    secret_context: secret.new(<<"stage one key":utf8>>),
  )
}

/// Full runs over the real ML-KEM and fresh randomness: the same password
/// agrees on key and transcript; a different one completes without error
/// and with unequal keys.
pub fn real_runs_agree_only_on_the_same_password_test() {
  let suite = suite.suite()

  assert list.all(
    [#("cradle-noble-velvet", True), #("cradle-noble-violet", False)],
    fn(run) {
      let #(responder_prs, same) = run
      let assert Ok(#(state, init_message)) =
        oquake.init(suite, honest_inputs("cradle-noble-velvet"))
      let assert Ok(Response(message:, key: responded, transcript_hash:)) =
        oquake.respond(suite, honest_inputs(responder_prs), init_message)
      let assert Ok(Established(key: finished, transcript_hash: hash)) =
        oquake.finish(suite, state, message)

      hash == transcript_hash && { finished == responded } == same
    },
  )
}
