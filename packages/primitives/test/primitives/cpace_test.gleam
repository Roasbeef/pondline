//// CPace (`core/crypto/cpace`) over the real primitives, against the two
//// drafts' vectors.
////
//// `test/vectors/cpace_x25519_sha512.json` is cpace-21 Appendix B.1 and
//// `test/vectors/cpace_pqpake_wrapper.json` the CPace part of pqpake-03
//// Appendix E.4 and E.5.4, both extracted by script from the draft text;
//// each file's `source` field says which sections, and the B.1 run was
//// also compared with the draft's own base64 JSON (B.1.9, B.1.10.1) when
//// it was extracted. B.1 pins the suite (`calculate_generator`, the
//// shares, `K`, the session key) through cpace-21's own presentation,
//// whose associated data is not empty; E.4 pins the pqpake wrapper end to
//// end (`init`, `respond`, `finish`: the shares, the key and the
//// transcript hash under the CPaceOQUAKE DST). B.1.10 and E.5.4 pin every
//// abort. The pure properties (agreement, which inputs the key depends on)
//// run over the fake suite in `packages/core/test/core/crypto/cpace_test.gleam`.

import core/crypto/cpace.{LowOrderShare, Responded}
import core/crypto/pake_common
import core/secret.{type Secret}
import gleam/bit_array
import gleam/list
import primitives
import primitives/suite
import primitives/vectors

fn b1() -> vectors.Vector {
  let assert [run] =
    vectors.load("cpace_x25519_sha512") |> vectors.where("kind", "run")
    as "B.1 carries one run"
  run
}

fn low_order() -> List(vectors.Vector) {
  vectors.load("cpace_x25519_sha512") |> vectors.where("kind", "low_order")
}

fn e4() -> vectors.Vector {
  let assert [run] =
    vectors.load("cpace_pqpake_wrapper") |> vectors.where("kind", "run")
    as "E.4 carries one run"
  run
}

fn hidden(vector: vectors.Vector, key: String) -> Secret {
  secret.new(vectors.hex(vector, key))
}

fn scalar(vector: vectors.Vector, key: String) -> cpace.Scalar {
  let assert Ok(scalar) = cpace.scalar_from_bytes(vectors.hex(vector, key))
    as "a vector scalar is 32 bytes"
  scalar
}

pub fn sha512_fips_180_4_abc_test() {
  let assert Ok(expected) =
    bit_array_from_hex(
      "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A"
      <> "2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
    )
    as "the FIPS 180-4 digest is well-formed hex"

  assert primitives.sha512(<<"abc">>) == expected
}

fn bit_array_from_hex(text: String) -> Result(BitArray, Nil) {
  bit_array.base16_decode(text)
}

// ------------------------------------------------- cpace-21 Appendix B.1

/// B.1.1: the generator string, and the generator it hashes and maps to.
pub fn b1_1_calculate_generator_test() {
  let run = b1()
  let password = hidden(run, "prs")
  let channel_identifier = hidden(run, "ci")
  let sid = vectors.hex(run, "sid")
  let string = cpace.generator_string(password, channel_identifier, sid)

  assert secret.expose(string) == vectors.hex(run, "generator_string")

  let assert Ok(generator) =
    cpace.calculate_generator(suite.suite(), password, channel_identifier, sid)
    as "B.1.1's generator is not degenerate"

  assert secret.expose(generator) == vectors.hex(run, "generator")
}

/// B.1.2 to B.1.4: the shares and the shared point. The pqpake wrapper's
/// `init_with_scalar` reads cpace-21's `CI` as its secret context and
/// `sid` as its public context, so B.1's inputs drive it unchanged, and
/// the shares do not depend on the associated data B.1 adds.
pub fn b1_2_to_b1_4_shares_test() {
  let run = b1()
  let s = suite.suite()
  let password = hidden(run, "prs")
  let channel_identifier = hidden(run, "ci")
  let sid = vectors.hex(run, "sid")

  let assert Ok(initiated) =
    cpace.init_with_scalar(
      s,
      password,
      sid,
      channel_identifier,
      scalar(run, "ya"),
    )
    as "B.1.2 initiates"
  let assert Ok(Responded(share: responder_share, ..)) =
    cpace.respond_with_scalar(
      s,
      password,
      sid,
      channel_identifier,
      initiated.share,
      scalar(run, "yb"),
    )
    as "B.1.3 responds"

  assert initiated.share == vectors.hex(run, "share_a")
  assert responder_share == vectors.hex(run, "share_b")
  assert primitives.x25519(vectors.hex(run, "ya"), responder_share)
    == Ok(vectors.hex(run, "k_a"))
  assert primitives.x25519(vectors.hex(run, "yb"), initiated.share)
    == Ok(vectors.hex(run, "k_b"))
}

/// B.1.5: the transcript and the session key, with B.1's associated data
/// `ADa` and `ADb`, through cpace-21's own `transcript_ir` and
/// `intermediate_key`.
pub fn b1_5_intermediate_key_test() {
  let run = b1()
  let transcript =
    cpace.transcript_ir(
      vectors.hex(run, "share_a"),
      vectors.hex(run, "ada"),
      vectors.hex(run, "share_b"),
      vectors.hex(run, "adb"),
    )
  let key =
    cpace.intermediate_key(
      suite.suite(),
      vectors.hex(run, "sid"),
      hidden(run, "k_a"),
      transcript,
    )
  let input = <<
    cpace.lv_cat([
      cpace.isk_label,
      vectors.hex(run, "sid"),
      vectors.hex(run, "k_a"),
    ]):bits,
    transcript:bits,
  >>

  assert transcript == vectors.hex(run, "transcript_ir")
  assert input == vectors.hex(run, "isk_input")
  assert secret.expose(key) == vectors.hex(run, "isk")
}

/// B.1.10: `scalar_mult_vfy(s, u)` is the suite's X25519, which answers
/// `Error(Nil)` exactly where the draft's `q` is the neutral element, and
/// otherwise the draft's `q`, non-canonical encodings with bit 255 set
/// included.
pub fn b1_10_scalar_mult_vfy_test() {
  let cases = low_order()

  assert list.length(cases) == 12
  assert vectors.failing(cases, fn(v) {
      let result =
        primitives.x25519(vectors.hex(v, "scalar"), vectors.hex(v, "u"))

      case vectors.hex(v, "q") == <<0:256>> {
        True -> result == Error(Nil)
        False -> result == Ok(vectors.hex(v, "q"))
      }
    })
    == []
}

/// B.1.10: every point the draft says MUST abort (u0 to u5 and u7) makes
/// both `respond` and `finish` return `LowOrderShare`, and every other one
/// completes. The draft's list and the neutral results agree: the seven
/// aborts are exactly the seven zero `q`.
pub fn b1_10_low_order_shares_abort_test() {
  let s = suite.suite()
  let password = secret.new(<<"password">>)
  let empty = secret.new(<<>>)
  let assert Ok(initiated) = cpace.init(s, password, <<>>, empty)
  let #(aborting, completing) =
    list.partition(low_order(), fn(v) { vectors.text(v, "abort") == "abort" })

  assert list.length(aborting) == 7
  assert list.all(aborting, fn(v) { vectors.hex(v, "q") == <<0:256>> })
  assert vectors.failing(aborting, fn(v) {
      let share = vectors.hex(v, "u")

      cpace.respond(s, password, <<>>, empty, share) == Error(LowOrderShare)
      && cpace.finish(s, initiated.state, <<>>, share) == Error(LowOrderShare)
    })
    == []
  assert vectors.failing(completing, fn(v) {
      let share = vectors.hex(v, "u")

      result_is_ok(cpace.respond(s, password, <<>>, empty, share))
      && result_is_ok(cpace.finish(s, initiated.state, <<>>, share))
    })
    == []
}

fn result_is_ok(result: Result(a, e)) -> Bool {
  case result {
    Ok(_) -> True
    Error(_) -> False
  }
}

// ------------------------------------------- pqpake-03 Appendix B and E.4

/// The DST in `pake_common` is the one §9.4.1 prints.
pub fn the_dst_is_the_configurations_test() {
  let assert Ok(dst) =
    bit_array_from_hex(
      "443E3089985F0F8DDDFB20CC5E8618F447BDCFE6DD39ABB23911CD784C075120",
    )
    as "the DST is well-formed hex"

  assert pake_common.dst == dst
}

/// E.4: the public context is `EncodePublicContext(sid, U, S)`.
pub fn e4_public_context_test() {
  let run = e4()

  assert pake_common.encode_public_context(
      vectors.hex(run, "sid"),
      vectors.hex(run, "client"),
      vectors.hex(run, "server"),
    )
    == Ok(vectors.hex(run, "public_context"))
}

/// E.4: `CPace.Init`, `CPace.Respond` and `CPace.Finish` with the
/// vector's scalars give its two shares, and both sides its `cpace_ISK`
/// and `cpace_th`.
pub fn e4_wrapper_run_test() {
  let run = e4()
  let s = suite.suite()
  let password = hidden(run, "prs")
  let public_context = vectors.hex(run, "public_context")
  let secret_context = hidden(run, "secret_context")

  let assert Ok(initiated) =
    cpace.init_with_scalar(
      s,
      password,
      public_context,
      secret_context,
      scalar(run, "ya"),
    )
    as "E.4 initiates"
  let assert Ok(responded) =
    cpace.respond_with_scalar(
      s,
      password,
      public_context,
      secret_context,
      initiated.share,
      scalar(run, "yb"),
    )
    as "E.4 responds"
  let assert Ok(finished) =
    cpace.finish(s, initiated.state, public_context, responded.share)
    as "E.4 finishes"

  assert initiated.share == vectors.hex(run, "share_a")
  assert responded.share == vectors.hex(run, "share_b")
  assert secret.expose(responded.key) == vectors.hex(run, "isk")
  assert secret.expose(finished.key) == vectors.hex(run, "isk")
  assert responded.transcript_hash == vectors.hex(run, "transcript_hash")
  assert finished.transcript_hash == vectors.hex(run, "transcript_hash")
}

/// E.5.4: a responder that receives the neutral element raises
/// `CPaceError`, whatever its other inputs.
pub fn e5_4_neutral_element_aborts_test() {
  let assert [neutral] =
    vectors.load("cpace_pqpake_wrapper") |> vectors.where("kind", "neutral")
    as "E.5.4 carries one share"
  let share = vectors.hex(neutral, "share_a")

  assert cpace.respond(
      suite.suite(),
      secret.new(<<"password">>),
      <<"any context">>,
      secret.new(<<>>),
      share,
    )
    == Error(LowOrderShare)
}

// --------------------------------------------------------- honest runs

/// Over real X25519 and fresh scalars, two honest parties agree, and a
/// wrong password on either side gives keys that differ while the
/// transcript hashes, which bind only public values, still agree.
pub fn real_runs_agree_only_on_the_same_password_test() {
  let s = suite.suite()
  let context = secret.new(<<>>)
  let public_context = <<"Pondline test":utf8>>
  let right = secret.new(<<"cradle-noble-velvet":utf8>>)
  let wrong = secret.new(<<"cradle-noble-vellum":utf8>>)

  list.each([right, wrong], fn(responder_password) {
    let assert Ok(initiated) = cpace.init(s, right, public_context, context)
    let assert Ok(responded) =
      cpace.respond(
        s,
        responder_password,
        public_context,
        context,
        initiated.share,
      )
    let assert Ok(finished) =
      cpace.finish(s, initiated.state, public_context, responded.share)

    assert { finished.key == responded.key } == { responder_password == right }
    assert finished.transcript_hash == responded.transcript_hash
    assert secret.byte_size(finished.key) == cpace.key_bytes
  })
}
