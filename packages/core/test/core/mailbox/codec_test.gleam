import core/capability.{
  type Admin, type Append, type Capability, type Provision, type Read,
}
import core/envelope.{type Padded}
import core/id.{type Id, type Queue}
import core/limits
import core/mailbox/codec
import core/mailbox/protocol.{type Request, type Response}
import core/time.{type Instant}
import core/tlv
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import qcheck

const property_count = 200

const property_seed = 23

const max_u64 = 0xffff_ffff_ffff_ffff

fn property(generator: qcheck.Generator(a), check: fn(a) -> Nil) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(generator, check)
}

// ------------------------------------------------------------ generators

fn ids() -> qcheck.Generator(Id(kind)) {
  qcheck.fixed_size_byte_aligned_bit_array(id.id_bytes)
  |> qcheck.map(fn(bytes) {
    let assert Ok(value) = id.from_bytes(bytes)
    value
  })
}

// Capabilities are filled with one recognisable byte so a test can look for
// it in a rendering. 0xa7 is 167.
const marker = 0xa7

fn capabilities() -> qcheck.Generator(Capability(authority)) {
  qcheck.constant(Nil)
  |> qcheck.map(fn(_) { marked_capability() })
}

fn marked_capability() -> Capability(authority) {
  let assert Ok(value) =
    capability.from_bytes(fill(capability.capability_bytes))
  value
}

fn fill(size: Int) -> BitArray {
  bit_array.concat(list.repeat(<<marker>>, size))
}

fn instants() -> qcheck.Generator(Instant) {
  qcheck.from_generators(qcheck.bounded_int(0, 2_000_000_000), [
    qcheck.bounded_int(0, 3),
    qcheck.bounded_int(max_u64 - 3, max_u64),
  ])
  |> qcheck.map(fn(seconds) { time.Instant(unix_seconds: seconds) })
}

// A short random ciphertext, padded: the contents are random, the padding
// is the 4096-byte bucket.
fn ciphertexts() -> qcheck.Generator(Padded) {
  qcheck.generic_byte_aligned_bit_array(
    values_from: qcheck.bounded_int(0, 255),
    byte_size_from: qcheck.bounded_int(0, 40),
  )
  |> qcheck.map(fn(sealed) {
    let assert Ok(padded) = envelope.pad(sealed)
    padded
  })
}

fn u32s() -> qcheck.Generator(Int) {
  qcheck.from_generators(qcheck.bounded_int(0, 100), [
    qcheck.bounded_int(0, 0xffff_ffff),
  ])
}

fn requests() -> qcheck.Generator(Request) {
  let create = {
    use provision, queue, read, append, admin <- qcheck.map5(
      capabilities(),
      ids(),
      capabilities(),
      capabilities(),
      capabilities(),
    )
    protocol.CreateQueue(provision:, queue:, read:, append:, admin:)
  }
  let append = {
    use queue, append, envelope, retention_deadline, ciphertext <- qcheck.map5(
      ids(),
      capabilities(),
      ids(),
      instants(),
      ciphertexts(),
    )
    protocol.Append(
      queue:,
      append:,
      envelope:,
      retention_deadline:,
      ciphertext:,
    )
  }
  let fetch = {
    use queue, read, wait_seconds, max_envelopes <- qcheck.map4(
      ids(),
      capabilities(),
      u32s(),
      u32s(),
    )
    protocol.Fetch(queue:, read:, wait_seconds:, max_envelopes:)
  }
  let ack = {
    use queue, read, envelopes <- qcheck.map3(
      ids(),
      capabilities(),
      qcheck.generic_list(
        elements_from: ids(),
        length_from: qcheck.bounded_int(0, codec.max_ack_envelopes),
      ),
    )
    protocol.Ack(queue:, read:, envelopes:)
  }
  let delete = {
    use queue, admin <- qcheck.map2(ids(), capabilities())
    protocol.DeleteQueue(queue:, admin:)
  }

  qcheck.from_generators(create, [append, fetch, ack, delete])
}

fn stored_envelopes() -> qcheck.Generator(envelope.StoredEnvelope) {
  use queue, envelope, retention_deadline, ciphertext <- qcheck.map4(
    ids(),
    ids(),
    instants(),
    ciphertexts(),
  )
  envelope.StoredEnvelope(queue:, envelope:, retention_deadline:, ciphertext:)
}

const refusals = [
  protocol.Unauthorized,
  protocol.Conflict,
  protocol.QuotaExceeded,
  protocol.TooLarge,
  protocol.BadDeadline,
  protocol.Malformed,
  protocol.UnsupportedVersion,
  protocol.Unavailable,
]

fn responses() -> qcheck.Generator(Response) {
  let created = qcheck.map(ids(), fn(queue) { protocol.QueueCreated(queue:) })
  let appended = {
    use queue, envelope, digest, retention_deadline <- qcheck.map4(
      ids(),
      ids(),
      qcheck.fixed_size_byte_aligned_bit_array(32),
      instants(),
    )
    protocol.Appended(receipt: protocol.AppendReceipt(
      queue:,
      envelope:,
      digest:,
      retention_deadline:,
    ))
  }
  let batch =
    qcheck.generic_list(
      elements_from: stored_envelopes(),
      length_from: qcheck.bounded_int(0, 4),
    )
    |> qcheck.map(fn(envelopes) { protocol.Batch(envelopes:) })
  let refused =
    qcheck.bounded_int(0, 7)
    |> qcheck.map(fn(index) {
      let assert Ok(reason) = list.first(list.drop(refusals, index))
      protocol.Refused(reason:)
    })

  qcheck.from_generators(created, [
    appended,
    batch,
    qcheck.constant(protocol.Acked),
    qcheck.constant(protocol.QueueDeleted),
    refused,
  ])
}

// ------------------------------------------------------------- mutations

// The bytes with the byte at `position` replaced; unchanged when the
// position is past the end.
fn flip(bytes: BitArray, position: Int, value: Int) -> BitArray {
  let size = bit_array.byte_size(bytes)

  case position < size {
    True -> {
      let assert Ok(head) = bit_array.slice(bytes, 0, position)
      let assert Ok(tail) =
        bit_array.slice(bytes, position + 1, size - position - 1)
      <<head:bits, value:size(8), tail:bits>>
    }
    False -> bytes
  }
}

fn truncate(bytes: BitArray, length: Int) -> BitArray {
  let assert Ok(prefix) =
    bit_array.slice(bytes, 0, int.min(length, bit_array.byte_size(bytes)))
  prefix
}

// The bytes with the version record's value replaced. Records are sorted,
// so the version, type 0, is always first: <<0, 2, version:16, ...>>.
fn with_version(bytes: BitArray, version: Int) -> BitArray {
  let assert <<0, 2, _:size(16), rest:bits>> = bytes
  <<0, 2, version:size(16), rest:bits>>
}

// The bytes with one more record, through the TLV layer so order holds.
fn with_record(bytes: BitArray, tag: Int, value: BitArray) -> BitArray {
  let assert Ok(stream) = tlv.parse(bytes, max_bytes: 1_000_000)

  list.fold(tlv.records(stream), tlv.new(), fn(builder, record) {
    tlv.put(builder, record.0, record.1)
  })
  |> tlv.put(tag, value)
  |> tlv.encode
}

fn is_error(result: Result(a, b)) -> Bool {
  case result {
    Ok(_) -> False
    Error(_) -> True
  }
}

// ---------------------------------------------------------------- tests

/// Every request round trips, and re-encoding the decoded request gives
/// the same bytes.
pub fn request_round_trip_property_test() {
  use request <- property(requests())

  let bytes = codec.encode_request(request)

  assert codec.decode_request(bytes) == Ok(request)
  assert codec.encode_request(request) == bytes
}

/// Every response round trips, and re-encodes identically.
pub fn response_round_trip_property_test() {
  use response <- property(responses())

  let bytes = codec.encode_response(response)

  assert codec.decode_response(bytes) == Ok(response)
  assert codec.encode_response(response) == bytes
}

/// Each refusal has its own code and survives the wire.
pub fn every_refusal_round_trips_test() {
  list.each(refusals, fn(reason) {
    let response = protocol.Refused(reason:)

    assert codec.decode_response(codec.encode_response(response))
      == Ok(response)
  })
}

/// Any version but ours is `UnsupportedVersion`, for requests and
/// responses, even when the rest of the stream is garbage-shaped.
pub fn wrong_version_is_detected_property_test() {
  use #(request, response, version) <- property(qcheck.tuple3(
    requests(),
    responses(),
    qcheck.from_generators(qcheck.bounded_int(0, 5), [
      qcheck.bounded_int(0, 65_535),
    ]),
  ))

  case version == protocol.version {
    True -> Nil

    False -> {
      let request_bytes = with_version(codec.encode_request(request), version)
      let response_bytes =
        with_version(codec.encode_response(response), version)

      assert codec.decode_request(request_bytes)
        == Error(codec.UnsupportedVersion)
      assert codec.decode_response(response_bytes)
        == Error(codec.UnsupportedVersion)
      assert codec.decode_request(with_record(request_bytes, 100, <<>>))
        == Error(codec.UnsupportedVersion)
    }
  }
}

/// A version that is not two bytes, or no version, is malformed rather
/// than unsupported.
pub fn missing_or_misshapen_version_is_malformed_test() {
  assert codec.decode_request(<<>>)
    == Error(codec.Malformed(tlv.MissingRequired(0)))
  assert codec.decode_request(<<0, 1, 1, 2, 1, 3>>)
    == Error(codec.Malformed(tlv.InvalidField(0)))
  assert codec.decode_response(<<2, 1, 4>>)
    == Error(codec.Malformed(tlv.MissingRequired(0)))
}

/// Cutting a message short is always an error, never a crash and never a
/// shorter valid message.
pub fn truncation_is_always_rejected_property_test() {
  use #(request, response, cut) <- property(qcheck.tuple3(
    requests(),
    responses(),
    qcheck.bounded_int(0, 400),
  ))

  let request_bytes = codec.encode_request(request)
  let response_bytes = codec.encode_response(response)

  case cut < bit_array.byte_size(request_bytes) {
    True -> {
      assert is_error(codec.decode_request(truncate(request_bytes, cut)))
    }
    False -> Nil
  }

  case cut < bit_array.byte_size(response_bytes) {
    True -> {
      assert is_error(codec.decode_response(truncate(response_bytes, cut)))
    }
    False -> Nil
  }
}

/// Changing one byte never crashes the decoder, and whatever it still
/// accepts re-encodes to the changed bytes.
pub fn single_byte_flip_never_crashes_property_test() {
  use #(request, response, position, value) <- property(qcheck.tuple4(
    requests(),
    responses(),
    qcheck.bounded_int(0, 400),
    qcheck.bounded_int(0, 255),
  ))

  let request_bytes = flip(codec.encode_request(request), position, value)
  let response_bytes = flip(codec.encode_response(response), position, value)

  case codec.decode_request(request_bytes) {
    Ok(decoded) -> {
      assert codec.encode_request(decoded) == request_bytes
    }
    Error(_) -> Nil
  }

  case codec.decode_response(response_bytes) {
    Ok(decoded) -> {
      assert codec.encode_response(decoded) == response_bytes
    }
    Error(_) -> Nil
  }
}

/// Random bytes never crash either decoder.
pub fn random_bytes_never_crash_property_test() {
  use bytes <- property(qcheck.byte_aligned_bit_array())

  assert is_error(codec.decode_request(bytes))
  assert is_error(codec.decode_response(bytes))
}

/// A capability never appears in an error, however the message is broken.
/// The capabilities here are all `0xa7` bytes, so their rendering is
/// distinctive.
pub fn capabilities_never_appear_in_errors_property_test() {
  use #(request, cut, position, value) <- property(qcheck.tuple4(
    requests(),
    qcheck.bounded_int(0, 400),
    qcheck.bounded_int(0, 400),
    qcheck.bounded_int(0, 255),
  ))

  let bytes = codec.encode_request(request)
  let broken = [
    truncate(bytes, cut),
    flip(bytes, position, value),
    with_version(bytes, 9),
    with_record(bytes, 100, <<>>),
    with_record(bytes, 8, <<1, 2, 3>>),
    with_record(bytes, 4, fill(capability.capability_bytes)),
  ]

  list.each(broken, fn(candidate) {
    case codec.decode_request(candidate) {
      Ok(_) -> Nil

      Error(error) -> {
        let rendered = string.inspect(error)
        assert !string.contains(rendered, "167")
        assert !string.contains(rendered, "<<")
      }
    }
  })
}

/// A field the wrong size, an unknown kind, a stray known field, an
/// unknown even field and an unknown odd field each get the right answer.
pub fn field_errors_are_specific_test() {
  let queue = fill(id.id_bytes)
  let assert Ok(queue_id) = id.from_bytes(queue)
  let queue_id: Id(Queue) = queue_id
  let request =
    protocol.DeleteQueue(queue: queue_id, admin: marked_capability())
  let bytes = codec.encode_request(request)

  assert codec.decode_request(with_record(bytes, 4, <<1, 2>>))
    == Error(codec.Malformed(tlv.InvalidField(4)))
  assert codec.decode_request(with_record(bytes, 2, <<9>>))
    == Error(codec.Malformed(tlv.InvalidField(2)))
  assert codec.decode_request(with_record(bytes, 8, <<>>))
    == Error(codec.Malformed(tlv.UnknownRequired(8)))
  assert codec.decode_request(with_record(bytes, 100, <<>>))
    == Error(codec.Malformed(tlv.UnknownRequired(100)))
  assert codec.decode_request(with_record(bytes, 101, <<7, 7>>)) == Ok(request)
  assert codec.decode_request(with_record(bytes, 1, <<7, 7>>)) == Ok(request)
}

/// A ciphertext that is not a bucket size is refused at decode, so an
/// unpadded body cannot reach storage.
pub fn non_bucket_ciphertext_is_refused_test() {
  let assert Ok(padded) = envelope.pad(<<1, 2, 3>>)
  let request =
    protocol.Append(
      queue: ident(),
      append: marked_capability(),
      envelope: ident(),
      retention_deadline: time.Instant(unix_seconds: 5),
      ciphertext: padded,
    )
  let bytes = codec.encode_request(request)

  assert codec.decode_request(with_record(bytes, 18, <<1, 2, 3>>))
    == Error(codec.Malformed(tlv.InvalidField(18)))
}

fn ident() -> Id(kind) {
  let assert Ok(value) = id.from_bytes(fill(id.id_bytes))
  value
}

/// The errors a mailbox answers with: version, size, and everything else.
pub fn errors_map_to_refusals_test() {
  assert codec.refusal(codec.UnsupportedVersion) == protocol.UnsupportedVersion
  assert codec.refusal(codec.Malformed(tlv.InputTooLarge)) == protocol.TooLarge
  assert codec.refusal(codec.Malformed(tlv.Truncated)) == protocol.Malformed
  assert codec.refusal(codec.Malformed(tlv.MissingRequired(4)))
    == protocol.Malformed
}

/// The largest legitimate request, an `Append` with a largest-bucket
/// ciphertext, is inside the bound; one byte over the bound is refused as
/// too large without being read.
pub fn request_bound_holds_at_the_largest_append_test() {
  let assert Ok(padded) = envelope.pad(sealed(limits.max_ciphertext_bytes - 4))
  let request =
    protocol.Append(
      queue: ident(),
      append: marked_capability(),
      envelope: ident(),
      retention_deadline: time.Instant(unix_seconds: max_u64),
      ciphertext: padded,
    )
  let bytes = codec.encode_request(request)

  assert bit_array.byte_size(bytes) <= codec.max_request_bytes()
  assert codec.decode_request(bytes) == Ok(request)

  let oversize = <<0:size({ { codec.max_request_bytes() + 1 } * 8 })>>
  assert codec.decode_request(oversize)
    == Error(codec.Malformed(tlv.InputTooLarge))
}

fn sealed(size: Int) -> BitArray {
  <<0:size({ size * 8 })>>
}

/// The largest legitimate response, a full batch holding the batch byte
/// limit, is inside the bound; more envelopes than the batch limit are
/// refused.
pub fn response_bound_holds_at_a_full_batch_test() {
  let assert Ok(big) = envelope.pad(sealed(limits.max_ciphertext_bytes - 4))
  let stored = fn(padded) {
    envelope.StoredEnvelope(
      queue: ident(),
      envelope: ident(),
      retention_deadline: time.Instant(unix_seconds: max_u64),
      ciphertext: padded,
    )
  }

  // Four of the largest bucket make exactly `fetch_batch_bytes`.
  let full = protocol.Batch(list.repeat(stored(big), 4))
  let full_bytes = codec.encode_response(full)

  assert 4 * limits.max_ciphertext_bytes == limits.fetch_batch_bytes
  assert bit_array.byte_size(full_bytes) <= codec.max_response_bytes()
  assert codec.decode_response(full_bytes) == Ok(full)

  // Sixteen small ones are the envelope-count limit.
  let assert Ok(small) = envelope.pad(<<1>>)
  let sixteen = protocol.Batch(list.repeat(stored(small), 16))
  let seventeen = protocol.Batch(list.repeat(stored(small), 17))

  assert codec.decode_response(codec.encode_response(sixteen)) == Ok(sixteen)
  assert codec.decode_response(codec.encode_response(seventeen))
    == Error(codec.Malformed(tlv.TooManyItems))
}

/// An `Ack` may name one batch's worth of envelopes and no more.
pub fn ack_list_is_bounded_test() {
  let ack = fn(count) {
    protocol.Ack(
      queue: ident(),
      read: marked_capability(),
      envelopes: list.repeat(ident(), count),
    )
  }

  assert codec.decode_request(codec.encode_request(ack(16))) == Ok(ack(16))
  assert codec.decode_request(codec.encode_request(ack(0))) == Ok(ack(0))
  assert codec.decode_request(codec.encode_request(ack(17)))
    == Error(codec.Malformed(tlv.InvalidField(24)))
}

/// Provision, read, append and admin capabilities decode into their own
/// slots, not each other's.
pub fn capabilities_land_in_their_own_slots_test() {
  let provision: Capability(Provision) = distinct_capability(1)
  let read: Capability(Read) = distinct_capability(2)
  let append: Capability(Append) = distinct_capability(3)
  let admin: Capability(Admin) = distinct_capability(4)
  let queue: Id(Queue) = ident()
  let request = protocol.CreateQueue(provision:, queue:, read:, append:, admin:)

  let assert Ok(protocol.CreateQueue(
    provision: got_provision,
    read: got_read,
    append: got_append,
    admin: got_admin,
    ..,
  )) = codec.decode_request(codec.encode_request(request))

  assert capability.expose(got_provision) == capability.expose(provision)
  assert capability.expose(got_read) == capability.expose(read)
  assert capability.expose(got_append) == capability.expose(append)
  assert capability.expose(got_admin) == capability.expose(admin)
}

fn distinct_capability(byte: Int) -> Capability(authority) {
  let assert Ok(value) =
    capability.from_bytes(
      bit_array.concat(list.repeat(<<byte>>, capability.capability_bytes)),
    )
  value
}
