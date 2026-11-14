//// CPace over X25519 and SHA-512, as the first stage of CPaceOQUAKE
//// (ADR-016).
////
//// A pairing code is three spoken words, 33 bits: far too few to key
//// anything, so they are a PAKE password, and an attacker gets one guess
//// per run. CPaceOQUAKE runs two PAKEs in sequence. This module is the
//// first, CPace, which hides the password unconditionally and whose key
//// then keys the post-quantum second stage. It is pure: the X25519
//// multiplications and SHA-512 arrive through `core/crypto/suite`, and the
//// map from hash to curve point is `core/crypto/elligator2`.
////
//// ## Which document each function follows
////
//// Two drafts define this, and they are layered. `draft-irtf-cfrg-cpace-21`
//// defines the suite `CPACE-X25519-SHA512` and its string utilities;
//// `prepend_len`, `lv_cat`, `generator_string`, `calculate_generator`,
//// `transcript_ir` and `intermediate_key` follow it (§6.3, §8.1, §8.2,
//// §7.2, Appendix A). `draft-vos-cfrg-pqpake-03` Appendix B wraps that
//// suite into the interface its combiner is specified against, and `init`,
//// `respond` and `finish` follow the wrapper, not cpace-21's symmetric
//// presentation. The wrapper fixes four things cpace-21 leaves open:
////
//// - the roles are initiator and responder, so the transcript is
////   `transcript_ir`, never the ordered concatenation of §6.3;
//// - CPace's channel identifier `CI` is the secret context, which never
////   travels, and CPace's `sid` is the whole public context, which is
////   bound into the session key a second time;
//// - the associated data `ADa` and `ADb` are empty;
//// - beside the key, each side returns the transcript hash
////   `TH("CPace", public_context, Ya, Yb)` of pqpake §5
////   (`core/crypto/pake_common`), which the combiner hands to OQUAKE as its
////   public context.
////
//// ```text
//// Initiator                                    Responder
//// init(PRS, pub, sec)  -- Ya (32 bytes) -->    respond(PRS, pub, sec, Ya)
////                      <-- Yb (32 bytes) --    -> key, Yb, th
//// finish(state, pub, Yb) -> key, th
//// ```
////
//// The shares travel bare here. CPaceOQUAKE frames them with `lv_encode`
//// (pqpake Appendix C.4); that framing is the combiner's.
////
//// ## Aborts and what a caller may rely on
////
//// `respond` and `finish` refuse a peer share that is not 32 bytes, and
//// abort with `LowOrderShare` when the shared point `K` is the identity,
//// which is what a low-order share (cpace-21 Appendix B.1.10) or a share
//// of zero (pqpake Appendix E.5.4) produces. Otherwise both sides get a
//// 64-byte key, equal exactly when the password, both contexts and both
//// shares match. A wrong password is not an error: it yields a key the
//// peer does not hold. CPace has no key confirmation, and nothing here
//// says the peer knew the password; ADR-016 confirms explicitly after the
//// second stage.
////
//// ## Secrets
////
//// The password, the secret context, the generator (from which the
//// password can be tested offline), the scalars, the shared point and the
//// key are all held as `core/secret.Secret`, so none of them prints. The
//// shares and the transcript hash are public.
////
//// ## Randomness
////
//// `init` and `respond` draw their scalar from `suite.random`.
//// `init_with_scalar` and `respond_with_scalar` take it as an argument, so
//// that a test can replay the drafts' vectors; nothing else should call
//// them, because a scalar used twice links two runs and, with a known
//// generator, gives the password away.

import core/crypto/elligator2
import core/crypto/pake_common
import core/crypto/suite.{type Suite}
import core/secret.{type Secret}
import gleam/bit_array
import gleam/bool
import gleam/int
import gleam/list
import gleam/result

/// The domain-separation identifier of the group, `G_X25519.DSI`
/// (cpace-21 §8.2).
pub const dsi = <<"CPace255":utf8>>

/// The label of the session-key hash, `G.DSI || "_ISK"` (cpace-21 §7.2).
pub const isk_label = <<"CPace255_ISK":utf8>>

/// The label of CPace's transcript hash (pqpake Appendix B).
pub const transcript_label = <<"CPace":utf8>>

/// SHA-512's input block size, `H.s_in_bytes`, which sizes the zero
/// padding of the generator string (cpace-21 §8.1).
pub const hash_block_bytes = 128

/// The size of a scalar and of a share, `G_X25519.field_size_bytes`.
pub const share_bytes = 32

/// The size of the session key: SHA-512's output, `H.b_in_bytes`.
pub const key_bytes = 64

/// A secret scalar, `ya` or `yb`: 32 bytes that X25519 clamps. Opaque, and
/// held as a `Secret`, so it cannot be printed or forged at a wrong length.
pub opaque type Scalar {
  Scalar(bytes: Secret)
}

/// What the initiator keeps between `init` and `finish`: its scalar and
/// its own share, which the session key binds (pqpake Appendix B.1).
pub opaque type InitiatorState {
  InitiatorState(scalar: Scalar, share: BitArray)
}

/// The initiator's first move: the state to keep and the share `Ya` to
/// send.
pub type Initiated {
  Initiated(
    /// Kept by the initiator until the responder's share arrives.
    state: InitiatorState,
    /// `Ya`, 32 bytes, sent to the responder.
    share: BitArray,
  )
}

/// The responder's whole run: the share `Yb` to send back, and its result.
pub type Responded {
  Responded(
    /// `Yb`, 32 bytes, sent to the initiator.
    share: BitArray,
    /// `ISK`, 64 bytes. Equal to the initiator's exactly when the password,
    /// both contexts and both shares match.
    key: Secret,
    /// `TH("CPace", public_context, Ya, Yb)`, 32 bytes, public.
    transcript_hash: BitArray,
  )
}

/// The initiator's result.
pub type Finished {
  Finished(
    /// `ISK`, 64 bytes.
    key: Secret,
    /// `TH("CPace", public_context, Ya, Yb)`, 32 bytes, public.
    transcript_hash: BitArray,
  )
}

/// Why a run stopped. These are pqpake's `CPaceError` and the length
/// checks its Appendix C asks of a parser; no variant carries bytes.
pub type CpaceError {
  /// The peer's share is not 32 bytes.
  MalformedShare

  /// The shared point `K` is the identity: the peer sent a low-order
  /// point, or zero. cpace-21 §7.2 says the party MUST abort.
  LowOrderShare

  /// Multiplying the generator by this side's own scalar gave the
  /// identity, so the generator is a low-order point. Elligator 2 reaches
  /// one only from a field element of 0 or p, which a SHA-512 output hits
  /// with probability 2^-254; refused rather than sent.
  DegenerateGenerator

  /// The public context is longer than `TH`'s two-byte framing can carry
  /// (`pake_common.max_field_bytes`).
  ContextTooLong

  /// The suite returned output of the wrong size: randomness that was not
  /// `share_bytes` long, or a SHA-512 digest shorter than a coordinate. A
  /// correct suite never does.
  PrimitiveFailed
}

/// A scalar from 32 bytes. Any 32 bytes are a scalar, because X25519
/// clamps them; any other length is refused.
///
/// ## Examples
///
/// ```gleam
/// cpace.scalar_from_bytes(<<7:256>>)
/// // -> Ok(scalar)
/// ```
pub fn scalar_from_bytes(bytes: BitArray) -> Result(Scalar, Nil) {
  case bit_array.byte_size(bytes) == share_bytes {
    True -> Ok(Scalar(bytes: secret.new(bytes)))
    False -> Error(Nil)
  }
}

/// pqpake Appendix B.1, `CPace.Init`: derive the generator from the
/// password and both contexts, draw the scalar `ya` from the suite, and
/// return the share `Ya` with the state `finish` needs.
///
/// A public context too long for `TH` is refused here rather than at
/// `finish`, so an initiator never sends a share it could not finish.
///
/// ## Examples
///
/// ```gleam
/// cpace.init(suite, password, public_context, secret.new(<<>>))
/// // -> Ok(Initiated(state:, share: <<_:256>>))
/// ```
pub fn init(
  suite: Suite,
  password: Secret,
  public_context: BitArray,
  secret_context: Secret,
) -> Result(Initiated, CpaceError) {
  use scalar <- result.try(draw_scalar(suite))

  init_with_scalar(suite, password, public_context, secret_context, scalar)
}

/// `init` with the scalar supplied rather than drawn, so a test can
/// reproduce the drafts' vectors. Production code calls `init`.
///
/// ## Examples
///
/// ```gleam
/// cpace.init_with_scalar(suite, password, public_context, context, ya)
/// // -> Ok(Initiated(state:, share: ya_share))
/// ```
pub fn init_with_scalar(
  suite: Suite,
  password: Secret,
  public_context: BitArray,
  secret_context: Secret,
  scalar: Scalar,
) -> Result(Initiated, CpaceError) {
  use <- bool.guard(
    when: bit_array.byte_size(public_context) > pake_common.max_field_bytes,
    return: Error(ContextTooLong),
  )

  use generator <- result.try(calculate_generator(
    suite,
    password,
    secret_context,
    public_context,
  ))
  use share <- result.try(own_share(suite, scalar, generator))

  Ok(Initiated(state: InitiatorState(scalar:, share:), share:))
}

/// pqpake Appendix B.2, `CPace.Respond`: derive the same generator, draw
/// `yb`, and from the initiator's share compute `Yb`, the key and the
/// transcript hash in one step. The responder has nothing to keep.
///
/// The share is checked for length before any hashing or group
/// operation (only the scalar is drawn first). `K` is checked
/// against the identity before any key is derived, and an identity aborts
/// with `LowOrderShare`, so a responder never answers a low-order share.
///
/// ## Examples
///
/// ```gleam
/// cpace.respond(suite, password, public_context, secret.new(<<>>), ya)
/// // -> Ok(Responded(share: <<_:256>>, key:, transcript_hash: <<_:256>>))
/// ```
pub fn respond(
  suite: Suite,
  password: Secret,
  public_context: BitArray,
  secret_context: Secret,
  initiator_share: BitArray,
) -> Result(Responded, CpaceError) {
  use scalar <- result.try(draw_scalar(suite))

  respond_with_scalar(
    suite,
    password,
    public_context,
    secret_context,
    initiator_share,
    scalar,
  )
}

/// `respond` with the scalar supplied rather than drawn, so a test can
/// reproduce the drafts' vectors. Production code calls `respond`.
///
/// ## Examples
///
/// ```gleam
/// cpace.respond_with_scalar(suite, password, context, secret, ya, yb)
/// // -> Ok(Responded(share: yb_share, key:, transcript_hash:))
/// ```
pub fn respond_with_scalar(
  suite: Suite,
  password: Secret,
  public_context: BitArray,
  secret_context: Secret,
  initiator_share: BitArray,
  scalar: Scalar,
) -> Result(Responded, CpaceError) {
  use <- bool.guard(
    when: bit_array.byte_size(initiator_share) != share_bytes,
    return: Error(MalformedShare),
  )

  use Initiated(share:, ..) <- result.try(init_with_scalar(
    suite,
    password,
    public_context,
    secret_context,
    scalar,
  ))

  // From here the responder is in the initiator's position with the roles
  // of the shares swapped: its own share is `Yb`, the peer's `Ya`, and the
  // transcript still lists `Ya` first.
  use shared <- result.try(shared_point(suite, scalar, initiator_share))
  use Finished(key:, transcript_hash:) <- result.try(conclude(
    suite,
    public_context,
    shared,
    initiator_share,
    share,
  ))

  Ok(Responded(share:, key:, transcript_hash:))
}

/// pqpake Appendix B.3, `CPace.Finish`: from the state `init` returned and
/// the responder's share, the key and the transcript hash. The public
/// context must be the one given to `init`; the draft passes it again
/// rather than keeping it in the state, and so does this.
///
/// The share is checked for length, and `K` against the identity, before
/// any key is derived.
///
/// ## Examples
///
/// ```gleam
/// cpace.finish(suite, initiated.state, public_context, yb)
/// // -> Ok(Finished(key:, transcript_hash: <<_:256>>))
/// ```
pub fn finish(
  suite: Suite,
  state: InitiatorState,
  public_context: BitArray,
  responder_share: BitArray,
) -> Result(Finished, CpaceError) {
  use <- bool.guard(
    when: bit_array.byte_size(responder_share) != share_bytes,
    return: Error(MalformedShare),
  )

  use shared <- result.try(shared_point(suite, state.scalar, responder_share))

  conclude(suite, public_context, shared, state.share, responder_share)
}

/// cpace-21 §8.2's `G.calculate_generator` for X25519 and SHA-512: hash
/// the generator string, keep the first 32 bytes, read them as a field
/// element with bit 255 cleared, map that onto the curve with Elligator 2
/// and encode the u-coordinate. The generator is a function of the
/// password, so it is returned as a `Secret`.
///
/// ## Examples
///
/// ```gleam
/// cpace.calculate_generator(suite, password, channel_identifier, sid)
/// // -> Ok(generator)
/// ```
pub fn calculate_generator(
  suite: Suite,
  password: Secret,
  channel_identifier: Secret,
  sid: BitArray,
) -> Result(Secret, CpaceError) {
  // The generator string holds the password, and its digest is a function
  // of it; both are exposed only to be hashed and mapped here.
  let generator_string =
    generator_string(password, channel_identifier, sid) |> secret.expose
  let digest = suite.sha512(generator_string)

  use head <- result.try(
    bit_array.slice(digest, 0, elligator2.coordinate_bytes)
    |> result.replace_error(PrimitiveFailed),
  )
  use field_element <- result.try(
    elligator2.decode_u_coordinate(head)
    |> result.replace_error(PrimitiveFailed),
  )

  elligator2.map_to_curve(field_element)
  |> elligator2.encode_u_coordinate
  |> secret.new
  |> Ok
}

/// cpace-21 §8.1's `generator_string(G.DSI, PRS, CI, sid, H.s_in_bytes)`:
/// `lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid)`, where the padding
/// makes the DSI, the password and the zeros fill SHA-512's first input
/// block, so the work of hashing a short password does not depend on its
/// length. A password long enough to fill the block gets no padding. It
/// holds the password, so it is a `Secret`.
///
/// ## Examples
///
/// ```gleam
/// secret.byte_size(cpace.generator_string(password, context, sid))
/// // -> 170, for the 8-byte password, 24-byte CI and 16-byte sid of B.1.1
/// ```
pub fn generator_string(
  password: Secret,
  channel_identifier: Secret,
  sid: BitArray,
) -> Secret {
  // The password and the channel identifier are exposed only to be framed
  // into a string that is itself returned as a secret.
  let password = secret.expose(password)
  let channel_identifier = secret.expose(channel_identifier)

  let used =
    1
    + bit_array.byte_size(prepend_len(password))
    + bit_array.byte_size(prepend_len(dsi))
  let padding = int.max(0, hash_block_bytes - used)

  lv_cat([dsi, password, <<0:size(padding * 8)>>, channel_identifier, sid])
  |> secret.new
}

/// cpace-21 §6.3's `transcript_ir(Ya, ADa, Yb, ADb)`:
/// `lv_cat(Ya, ADa) || lv_cat(Yb, ADb)`, the initiator's share first
/// whichever side computes it.
///
/// ## Examples
///
/// ```gleam
/// assert cpace.transcript_ir(<<"123">>, <<"PartyA">>, <<"234">>, <<"PartyB">>)
///   == <<3, "123", 6, "PartyA", 3, "234", 6, "PartyB">>
/// ```
pub fn transcript_ir(
  initiator_share: BitArray,
  initiator_data: BitArray,
  responder_share: BitArray,
  responder_data: BitArray,
) -> BitArray {
  <<
    lv_cat([initiator_share, initiator_data]):bits,
    lv_cat([responder_share, responder_data]):bits,
  >>
}

/// cpace-21 §7.2's session key, `ISK = H.hash(lv_cat(G.DSI || "_ISK", sid,
/// K) || transcript)`: SHA-512, so 64 bytes. The wrapper passes the whole
/// public context as `sid` and `transcript_ir` with empty associated data
/// as the transcript; the cpace-21 vectors pass their own.
///
/// ## Examples
///
/// ```gleam
/// cpace.intermediate_key(suite, sid, shared, cpace.transcript_ir(ya, <<>>, yb, <<>>))
/// // -> a 64-byte Secret
/// ```
pub fn intermediate_key(
  suite: Suite,
  sid: BitArray,
  shared: Secret,
  transcript: BitArray,
) -> Secret {
  // The shared point is exposed only to be hashed into the key, which is
  // itself returned as a secret.
  let framed = lv_cat([isk_label, sid, secret.expose(shared)])

  suite.sha512(<<framed:bits, transcript:bits>>)
  |> secret.new
}

/// cpace-21 §6.3's `prepend_len`: the data behind its length in LEB128,
/// seven bits per byte, least significant first, with the high bit set on
/// every byte but the last.
///
/// ## Examples
///
/// ```gleam
/// assert cpace.prepend_len(<<"1234">>) == <<4, "1234">>
/// ```
pub fn prepend_len(data: BitArray) -> BitArray {
  <<leb128(bit_array.byte_size(data)):bits, data:bits>>
}

/// cpace-21 §6.3's `lv_cat`: every part behind its own `prepend_len`.
///
/// ## Examples
///
/// ```gleam
/// assert cpace.lv_cat([<<"1234">>, <<"5">>, <<>>, <<"678">>])
///   == <<4, "1234", 1, "5", 0, 3, "678">>
/// ```
pub fn lv_cat(parts: List(BitArray)) -> BitArray {
  list.map(parts, prepend_len)
  |> bit_array.concat
}

/// The scalar for one run, from the suite's randomness. A suite that
/// returns the wrong number of bytes is a broken suite, and is reported.
fn draw_scalar(suite: Suite) -> Result(Scalar, CpaceError) {
  suite.random(share_bytes)
  |> scalar_from_bytes
  |> result.replace_error(PrimitiveFailed)
}

/// `G.scalar_mult(y, g)`: this side's share. The suite refuses a result of
/// zero, which here means the generator was a low-order point.
fn own_share(
  suite: Suite,
  scalar: Scalar,
  generator: Secret,
) -> Result(BitArray, CpaceError) {
  // The scalar and the generator are exposed only to the suite's X25519.
  suite.x25519(secret.expose(scalar.bytes), secret.expose(generator))
  |> result.replace_error(DegenerateGenerator)
}

/// `G.scalar_mult_vfy(y, Y)` and the abort of cpace-21 §7.2: the shared
/// point `K`, or `LowOrderShare` when it is the identity. The suite's
/// X25519 already refuses an all-zero result; the comparison below holds
/// the abort to the draft's own words even for a suite that did not.
fn shared_point(
  suite: Suite,
  scalar: Scalar,
  peer_share: BitArray,
) -> Result(Secret, CpaceError) {
  // The scalar is exposed only to the suite's X25519.
  use shared <- result.try(
    suite.x25519(secret.expose(scalar.bytes), peer_share)
    |> result.replace_error(LowOrderShare),
  )

  use <- bool.guard(
    when: shared == <<0:size(share_bytes * 8)>>,
    return: Error(LowOrderShare),
  )

  Ok(secret.new(shared))
}

/// The common tail of `respond` and `finish` (pqpake Appendix B.2, B.3):
/// the key over the shared point and the transcript with empty associated
/// data, and the transcript hash over the public context and both shares,
/// the initiator's first.
fn conclude(
  suite: Suite,
  public_context: BitArray,
  shared: Secret,
  initiator_share: BitArray,
  responder_share: BitArray,
) -> Result(Finished, CpaceError) {
  use transcript_hash <- result.try(
    pake_common.transcript_hash(suite, transcript_label, [
      public_context,
      initiator_share,
      responder_share,
    ])
    |> result.replace_error(ContextTooLong),
  )

  let transcript = transcript_ir(initiator_share, <<>>, responder_share, <<>>)
  let key = intermediate_key(suite, public_context, shared, transcript)

  Ok(Finished(key:, transcript_hash:))
}

/// The LEB128 encoding of a length: seven bits per byte, least significant
/// first, the high bit marking that another byte follows.
fn leb128(length: Int) -> BitArray {
  // A length under 128 is its own last byte; anything larger emits its low
  // seven bits with the continuation bit and recurses on the rest.
  case length < 128 {
    True -> <<length>>

    False -> {
      let low = int.bitwise_and(length, 0x7f) + 0x80
      let rest = leb128(int.bitwise_shift_right(length, 7))

      <<low, rest:bits>>
    }
  }
}
