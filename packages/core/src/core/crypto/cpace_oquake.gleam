//// CPaceOQUAKE: the sequential hybrid PAKE of `draft-vos-cfrg-pqpake-03`
//// §7, configuration `cpaceoquake-x25519-mlbuaskem1024` (§9.4.1), with the
//// message encodings of its Appendix C.4 (ADR-016).
////
//// A spoken code's three words are a password worth 33 bits, so they must
//// key a PAKE, and the PAKE must hold if either X25519 or ML-KEM falls
//// during the pairing. Running CPace and OQUAKE side by side would need
//// both to hide the password unconditionally, which OQUAKE does not. The
//// sequential combiner needs it of CPace alone: CPace runs first
//// (`core/crypto/cpace`), and OQUAKE (`core/crypto/oquake`) then runs on
//// the same password with CPace's session key as its secret context and
//// CPace's transcript hash as its public context. A discrete-log break
//// recovers CPace's key only by first guessing the password, so it cannot
//// test passwords against OQUAKE offline; an ML-KEM break meets a password
//// CPace already hid.
////
//// ## Roles and messages
////
//// The draft names the parties client and server, and its two stages swap
//// direction: the client initiates CPace, the server initiates OQUAKE.
////
//// ```text
//// Client                                              Server
//// init               msg1 = lv(Ya)            -->     respond
////                                                       CPace respond, then
////                                                       OQUAKE init(th1, key1)
////                    msg2 = lv(Yb) || s || T || rho
//// initiator_finish   <--
////   CPace finish, then OQUAKE respond(th1, key1)
////                    msg3 = ct || h           -->     responder_finish
////                                                       OQUAKE finish
//// ```
////
//// | Message | Encoding | Bytes |
//// | --- | --- | --- |
//// | `msg1` | `lv_encode(Ya)` | 34 |
//// | `msg2` | `lv_encode(Yb) \|\| oquake_init` | 1694 |
//// | `msg3` | the OQUAKE response, `ct \|\| h` | 1600 |
////
//// Each parser takes exactly that length and, where there is a length
//// prefix, exactly a 32-byte share behind it. Anything else is a typed
//// error, as Appendix C requires ("Parsing a message MUST fail if the input
//// does not have the expected length or framing").
////
//// ## The session key
////
//// Both sides finish with OQUAKE's key `key2`, CPace's key `key1` and
//// OQUAKE's transcript hash `th2`, which covers CPace's transcript and so
//// both stages, and derive
////
//// ```text
//// prk = HKDF-Extract(salt = key2, ikm = DST || "CPaceOQUAKE" || th2 || key1)
//// key = HKDF-Expand(prk, DST || "key", 32)
//// ```
////
//// exactly as §7.3 and §7.4 write it, with the DST of §9.4.1
//// (`pake_common.dst`). Each side returns the key and `th2`.
////
//// ## Failure behaviour
////
//// Like OQUAKE's `finish`, `responder_finish` never reports a wrong
//// password: a tag that does not verify gives it a fresh random OQUAKE key,
//// so it derives a session key unrelated to the client's. The client never
//// learns anything at all from the messages. Completion is therefore not
//// evidence that the peer knew the password (§6.3), and a caller must
//// confirm explicitly with a key derived from the session key, as
//// `core/rendezvous` does. The errors here are only what a parser or the
//// draft's aborts produce: a malformed message, a low-order CPace share,
//// and a suite that broke its contract.
////
//// ## Randomness and secrets
////
//// `init` draws CPace's `ya`; `respond` draws `yb`, the ML-BUA-sKEM key
//// pair (with Kemeleon's randomness) and OQUAKE's `r`; `responder_finish`
//// draws OQUAKE's fallback key; the client's ML-KEM encapsulation draws
//// inside the suite. `init_with`, `respond_with` and
//// `responder_finish_with` take that randomness as arguments, so the
//// Appendix E.4 vector can drive every step
//// (`packages/primitives/test/primitives/cpace_oquake_test.gleam`);
//// nothing but a test should call them. The password, both contexts' secret
//// parts, CPace's key and the session key are `Secret`s, and both states
//// are opaque, so none of them prints.

import core/crypto/bua_skem.{type KeyPair}
import core/crypto/cpace
import core/crypto/hkdf
import core/crypto/oquake
import core/crypto/pake_common
import core/crypto/suite.{type Suite}
import core/secret.{type Secret}
import gleam/result

/// The bytes of the session key: Nkey in pqpake §9.1.
pub const key_bytes = 32

/// The bytes of the transcript hash, HKDF-SHA-256's extract output.
pub const transcript_hash_bytes = 32

/// The bytes of `msg1`, `lv_encode(Ya)`: a two-byte length and a 32-byte
/// share.
pub const init_message_bytes = 34

/// The bytes of `msg2`, `lv_encode(Yb) || oquake_init`: 34 and
/// `oquake.init_message_bytes`.
pub const response_message_bytes = 1694

/// The bytes of `msg3`, the OQUAKE response: `oquake.response_message_bytes`.
pub const finish_message_bytes = 1600

/// The label of the combiner's extract, §7.3.
const combiner_label = <<"CPaceOQUAKE":utf8>>

/// The label of the combiner's expand, §7.3.
const key_label = <<"key":utf8>>

/// What both parties bring to a run: pqpake §5's common interface. The DST
/// is not here, because the configuration fixes it.
pub type Inputs {
  Inputs(
    /// The password-related string: the code's words, in Pondline.
    prs: Secret,
    /// Public session information both sides agree on, at most
    /// `pake_common.max_field_bytes`.
    public_context: BitArray,
    /// Confidential information both sides share and never send, empty
    /// when there is none; at most `pake_common.max_field_bytes`.
    secret_context: Secret,
  )
}

/// What the client keeps between `init` and `initiator_finish`: its inputs,
/// which the draft passes again to `InitiatorFinish`, and CPace's state.
/// Opaque, and every secret in it is a `Secret`.
pub opaque type ClientState {
  ClientState(inputs: Inputs, cpace: cpace.InitiatorState)
}

/// What the server keeps between `respond` and `responder_finish`: OQUAKE's
/// state and CPace's key, the draft's `State(ctx2, key1)`. Opaque.
pub opaque type ServerState {
  ServerState(oquake: oquake.InitiatorState, cpace_key: Secret)
}

/// The client's result: its session key, `msg3` to send, and the
/// transcript hash.
pub type ClientFinished {
  ClientFinished(
    /// The session key, `key_bytes`. Equal to the server's exactly when the
    /// password and both contexts matched and nothing was changed in flight.
    key: Secret,
    /// `msg3`, `finish_message_bytes`, for the server.
    message: BitArray,
    /// `th2`, public, `transcript_hash_bytes`.
    transcript_hash: BitArray,
  )
}

/// The server's result.
pub type ServerFinished {
  ServerFinished(
    /// The session key, or one unrelated to the client's when OQUAKE's tag
    /// did not verify; the two cannot be told apart from here.
    key: Secret,
    /// `th2`, public, `transcript_hash_bytes`, computed from the messages
    /// as received either way.
    transcript_hash: BitArray,
  )
}

/// Why a run stopped. No variant carries a message, a key or the password.
pub type CombinerError {
  /// `msg1` is not `lv_encode` of a 32-byte share.
  MalformedInitMessage

  /// `msg2` is not `lv_encode` of a 32-byte share followed by an OQUAKE
  /// init message.
  MalformedResponseMessage

  /// `msg3` is not an OQUAKE response message.
  MalformedFinishMessage

  /// The peer's CPace share put the shared point at the identity: a
  /// low-order point or zero. CPace says the party MUST abort.
  LowOrderShare

  /// The public or secret context is longer than `pake_common.max_field_bytes`.
  ContextTooLong

  /// The suite broke its contract, or CPace's own generator was low order
  /// (probability 2^-254). A correct suite never produces this.
  PrimitiveFailed
}

/// `CPaceOQUAKE.Init` (§7.1): CPace's initiation, with `ya` drawn from the
/// suite. Returns the state to keep and `msg1`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(state, message)) = cpace_oquake.init(suite, inputs)
/// bit_array.byte_size(message)
/// // -> 34
/// ```
pub fn init(
  suite: Suite,
  inputs: Inputs,
) -> Result(#(ClientState, BitArray), CombinerError) {
  use scalar <- result.try(draw_scalar(suite))

  init_with(suite, inputs, scalar)
}

/// `init` with CPace's scalar `ya` given, so a test can replay Appendix
/// E.4. Production code calls `init`.
///
/// ## Examples
///
/// ```gleam
/// cpace_oquake.init_with(suite, inputs, ya)
/// // -> Ok(#(state, msg1))
/// ```
pub fn init_with(
  suite: Suite,
  inputs: Inputs,
  scalar: cpace.Scalar,
) -> Result(#(ClientState, BitArray), CombinerError) {
  use cpace.Initiated(state:, share:) <- result.try(
    cpace.init_with_scalar(
      suite,
      inputs.prs,
      inputs.public_context,
      inputs.secret_context,
      scalar,
    )
    |> result.map_error(from_cpace(_, MalformedInitMessage)),
  )
  use message <- result.map(frame_share(share))

  #(ClientState(inputs:, cpace: state), message)
}

/// `CPaceOQUAKE.Respond` (§7.2): the server finishes CPace on `msg1`, then
/// initiates OQUAKE with CPace's transcript hash as public context and
/// CPace's key as secret context. Every random value is drawn from the
/// suite, after `msg1`'s length and framing are checked. Returns the state
/// to keep and `msg2`.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(#(state, message)) =
///   cpace_oquake.respond(suite, inputs, msg1)
/// bit_array.byte_size(message)
/// // -> 1694
/// ```
pub fn respond(
  suite: Suite,
  inputs: Inputs,
  init_message: BitArray,
) -> Result(#(ServerState, BitArray), CombinerError) {
  use _share <- result.try(read_init_message(init_message))
  use scalar <- result.try(draw_scalar(suite))
  use key_pair <- result.try(
    bua_skem.keygen(suite) |> result.replace_error(PrimitiveFailed),
  )
  let r = secret.new(suite.random(oquake.r_bytes))

  respond_with(suite, inputs, init_message, scalar, key_pair, r)
}

/// `respond` with its randomness given: CPace's `yb`, the ML-BUA-sKEM key
/// pair (whose public key already carries Kemeleon's randomness) and
/// OQUAKE's `r`. Production code calls `respond`.
///
/// ## Examples
///
/// ```gleam
/// cpace_oquake.respond_with(suite, inputs, msg1, yb, key_pair, r)
/// // -> Ok(#(state, msg2))
/// ```
pub fn respond_with(
  suite: Suite,
  inputs: Inputs,
  init_message: BitArray,
  scalar: cpace.Scalar,
  key_pair: KeyPair,
  r: Secret,
) -> Result(#(ServerState, BitArray), CombinerError) {
  use initiator_share <- result.try(read_init_message(init_message))

  // Stage 1. CPace's responder has its key and transcript hash at once;
  // its share `Yb` rides in `msg2` beside OQUAKE's first message.
  use cpace.Responded(share:, key:, transcript_hash:) <- result.try(
    cpace.respond_with_scalar(
      suite,
      inputs.prs,
      inputs.public_context,
      inputs.secret_context,
      initiator_share,
      scalar,
    )
    |> result.map_error(from_cpace(_, MalformedInitMessage)),
  )

  // Stage 2 on the same password, bound to Stage 1 twice: CPace's
  // transcript hash is OQUAKE's public context and CPace's key its secret
  // context. The key, not the raw password, is the sequential binding.
  let stage_two =
    oquake.Inputs(
      dst: pake_common.dst,
      prs: inputs.prs,
      public_context: transcript_hash,
      secret_context: key,
    )
  use #(oquake_state, oquake_init) <- result.try(
    oquake.init_with(suite, stage_two, key_pair, r)
    |> result.map_error(from_oquake),
  )
  use framed <- result.map(frame_share(share))

  #(ServerState(oquake: oquake_state, cpace_key: key), <<
    framed:bits,
    oquake_init:bits,
  >>)
}

/// `CPaceOQUAKE.InitiatorFinish` (§7.3): the client finishes CPace on the
/// share in `msg2`, responds to OQUAKE's message with CPace's transcript
/// hash and key as contexts, and derives the session key. The client
/// learns nothing about the server's password here; a mismatch shows only
/// as keys that differ.
///
/// ## Examples
///
/// ```gleam
/// cpace_oquake.initiator_finish(suite, state, msg2)
/// // -> Ok(ClientFinished(key:, message: msg3, transcript_hash:))
/// ```
pub fn initiator_finish(
  suite: Suite,
  state: ClientState,
  response_message: BitArray,
) -> Result(ClientFinished, CombinerError) {
  use #(responder_share, oquake_init) <- result.try(read_response_message(
    response_message,
  ))
  let ClientState(inputs:, cpace: cpace_state) = state

  // Stage 1 ends here for the client, against the public context `init`
  // was given.
  use cpace.Finished(key: cpace_key, transcript_hash: cpace_hash) <- result.try(
    cpace.finish(suite, cpace_state, inputs.public_context, responder_share)
    |> result.map_error(from_cpace(_, MalformedResponseMessage)),
  )

  // Stage 2 under the same binding the server used: CPace's transcript
  // hash public, CPace's key secret.
  let stage_two =
    oquake.Inputs(
      dst: pake_common.dst,
      prs: inputs.prs,
      public_context: cpace_hash,
      secret_context: cpace_key,
    )
  use oquake.Response(message:, key: oquake_key, transcript_hash:) <- result.try(
    oquake.respond(suite, stage_two, oquake_init)
    |> result.map_error(from_oquake),
  )
  use key <- result.map(session_key(
    suite,
    oquake_key,
    transcript_hash,
    cpace_key,
  ))

  ClientFinished(key:, message:, transcript_hash:)
}

/// `CPaceOQUAKE.ResponderFinish` (§7.4): the server finishes OQUAKE on
/// `msg3` and derives the session key, drawing OQUAKE's fallback key from
/// the suite. Only a `msg3` of the wrong length is refused; a wrong
/// password gives an unrelated key, never an error.
///
/// ## Examples
///
/// ```gleam
/// cpace_oquake.responder_finish(suite, state, msg3)
/// // -> Ok(ServerFinished(key:, transcript_hash:))
/// ```
pub fn responder_finish(
  suite: Suite,
  state: ServerState,
  finish_message: BitArray,
) -> Result(ServerFinished, CombinerError) {
  responder_finish_with(
    suite,
    state,
    finish_message,
    secret.new(suite.random(oquake.key_bytes)),
  )
}

/// `responder_finish` with OQUAKE's fallback key given: the key OQUAKE
/// returns in place of its session key when the tag in `msg3` does not
/// verify. Production code calls `responder_finish`.
///
/// ## Examples
///
/// ```gleam
/// cpace_oquake.responder_finish_with(suite, state, msg3, fallback)
/// // -> Ok(ServerFinished(key:, transcript_hash:))
/// ```
pub fn responder_finish_with(
  suite: Suite,
  state: ServerState,
  finish_message: BitArray,
  fallback: Secret,
) -> Result(ServerFinished, CombinerError) {
  use oquake.Established(key: oquake_key, transcript_hash:) <- result.try(
    oquake.finish_with(suite, state.oquake, finish_message, fallback)
    |> result.map_error(from_oquake),
  )
  use key <- result.map(session_key(
    suite,
    oquake_key,
    transcript_hash,
    state.cpace_key,
  ))

  ServerFinished(key:, transcript_hash:)
}

/// §7.3's combiner: `Expand(Extract(key2, DST || "CPaceOQUAKE" || th2 ||
/// key1), DST || "key", 32)`. OQUAKE's key is the extract's salt and
/// CPace's key ends its input, so the session key depends on both stages'
/// keys and on the transcript of both.
fn session_key(
  suite: Suite,
  oquake_key: Secret,
  transcript_hash: BitArray,
  cpace_key: Secret,
) -> Result(Secret, CombinerError) {
  // Both keys are exposed only into the one extract that consumes them.
  let ikm = <<
    pake_common.dst:bits,
    combiner_label:bits,
    transcript_hash:bits,
    secret.expose(cpace_key):bits,
  >>
  let prk = hkdf.extract(suite, secret.expose(oquake_key), ikm)

  hkdf.expand(suite, prk, <<pake_common.dst:bits, key_label:bits>>, key_bytes)
  |> result.map(secret.new)
  |> result.replace_error(PrimitiveFailed)
}

/// Appendix C.4's `msg1`: `lv_encode(Ya)`, accepted only as a two-byte
/// length of 32 and a 32-byte share, so exactly `init_message_bytes`.
fn read_init_message(message: BitArray) -> Result(BitArray, CombinerError) {
  let share_bytes = cpace.share_bytes

  // A wrong prefix or a wrong total length is the same malformation.
  case message {
    <<32:size(16), share:bytes-size(share_bytes)>> -> Ok(share)
    _ -> Error(MalformedInitMessage)
  }
}

/// Appendix C.4's `msg2`: `L`, then `Yb` of `L` bytes, then the OQUAKE init
/// message. Accepted only with `L` of 32 and an OQUAKE message of exactly
/// `oquake.init_message_bytes`, so exactly `response_message_bytes`.
fn read_response_message(
  message: BitArray,
) -> Result(#(BitArray, BitArray), CombinerError) {
  let share_bytes = cpace.share_bytes
  let oquake_bytes = oquake.init_message_bytes

  // The draft reads `L` from the message; a share of any length but 32 is
  // malformed, so `L` is matched as the constant.
  case message {
    <<
      32:size(16),
      share:bytes-size(share_bytes),
      oquake_init:bytes-size(oquake_bytes),
    >> -> Ok(#(share, oquake_init))

    _ -> Error(MalformedResponseMessage)
  }
}

/// A CPace share behind its two-byte length, `lv_encode(Y)`. A share is 32
/// bytes, so framing it cannot fail for a correct CPace.
fn frame_share(share: BitArray) -> Result(BitArray, CombinerError) {
  pake_common.lv_encode(share)
  |> result.replace_error(PrimitiveFailed)
}

/// CPace's scalar from the suite's randomness.
fn draw_scalar(suite: Suite) -> Result(cpace.Scalar, CombinerError) {
  suite.random(cpace.share_bytes)
  |> cpace.scalar_from_bytes
  |> result.replace_error(PrimitiveFailed)
}

/// CPace's errors in the combiner's terms. A malformed share cannot reach
/// CPace past this module's parsers, but it is named for the message that
/// carried it rather than folded into a primitive failure.
fn from_cpace(
  error: cpace.CpaceError,
  malformed: CombinerError,
) -> CombinerError {
  case error {
    cpace.MalformedShare -> malformed
    cpace.LowOrderShare -> LowOrderShare
    cpace.ContextTooLong -> ContextTooLong
    cpace.DegenerateGenerator -> PrimitiveFailed
    cpace.PrimitiveFailed -> PrimitiveFailed
  }
}

/// OQUAKE's refusals in the combiner's terms. OQUAKE's init message
/// travels inside `msg2` and its response is `msg3`, so a length refusal is
/// named for the combiner message that carried it.
fn from_oquake(refusal: oquake.Refusal) -> CombinerError {
  case refusal {
    oquake.InitMessageLength(..) -> MalformedResponseMessage
    oquake.ResponseMessageLength(..) -> MalformedFinishMessage
    oquake.ContextTooLong -> ContextTooLong
    oquake.MalformedKeyMaterial -> PrimitiveFailed
    oquake.PrimitiveFailed -> PrimitiveFailed
  }
}
