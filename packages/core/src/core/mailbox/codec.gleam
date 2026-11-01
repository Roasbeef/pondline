//// The mailbox protocol's wire form: `protocol.Request` and
//// `protocol.Response` as `core/tlv` streams (spec §6.1, design review
//// §3.1).
////
//// The HTTP binding, and any later carrier, moves bytes; this module is the
//// only place that knows how a typed command becomes bytes and back. Every
//// decode is bounded, total and strict: an unknown even type, a missing
//// field, a field that belongs to another operation, or a wrong-sized
//// identifier is a refusal, never a guess. Unknown odd types are ignored,
//// which is how a later version can add an optional field without breaking
//// this decoder, and an ignored field cannot grant authority because no
//// code path reads it.
////
//// ## Layout
////
//// Every message carries a version (type 0) and a kind (type 2). The
//// version is checked first, from the parsed stream and before any other
//// field is read, so a peer speaking another version is told
//// `UnsupportedVersion` rather than `Malformed` even if its fields have
//// changed shape. Decoders then read exactly the fields of their kind.
//// Field type numbers mean the same thing in every message that uses them.
//// A type number is even when a decoder must understand it, and every
//// field defined so far is required for its kind.
////
//// ### Requests (kind in type 2)
////
//// | Kind | Request       | Types read                                     |
//// |------|---------------|------------------------------------------------|
//// | 1    | `CreateQueue` | 4 queue, 6 provision, 8 read, 10 append, 12 admin |
//// | 2    | `Append`      | 4 queue, 10 append, 14 envelope, 16 deadline, 18 ciphertext |
//// | 3    | `Fetch`       | 4 queue, 8 read, 20 wait, 22 max envelopes     |
//// | 4    | `Ack`         | 4 queue, 8 read, 24 envelope list              |
//// | 5    | `DeleteQueue` | 4 queue, 12 admin                              |
////
//// ### Responses (kind in type 2)
////
//// | Kind | Response       | Types read                                    |
//// |------|----------------|-----------------------------------------------|
//// | 1    | `QueueCreated` | 4 queue                                       |
//// | 2    | `Appended`     | 28 receipt                                    |
//// | 3    | `Batch`        | 30 stored envelopes                           |
//// | 4    | `Acked`        | none                                          |
//// | 5    | `QueueDeleted` | none                                          |
//// | 6    | `Refused`      | 32 refusal code                               |
////
//// ### Field types
////
//// | Type | Field               | Encoding                                  |
//// |------|---------------------|-------------------------------------------|
//// | 0    | version             | u16, `protocol.version`                   |
//// | 2    | kind                | u8, tables above                          |
//// | 4    | queue id            | 16 bytes                                  |
//// | 6    | provision capability| 32 bytes                                  |
//// | 8    | read capability     | 32 bytes                                  |
//// | 10   | append capability   | 32 bytes                                  |
//// | 12   | admin capability    | 32 bytes                                  |
//// | 14   | envelope id         | 16 bytes                                  |
//// | 16   | retention deadline  | u64 unix seconds                          |
//// | 18   | ciphertext          | padded bytes, a bucket size               |
//// | 20   | wait seconds        | u32                                       |
//// | 22   | max envelopes       | u32                                       |
//// | 24   | envelope id list    | concatenated 16-byte ids, at most `max_ack_envelopes` |
//// | 26   | digest              | bytes (inside a receipt)                  |
//// | 28   | append receipt      | nested stream: 4, 14, 26, 16              |
//// | 30   | stored envelopes    | sequence of length-prefixed nested streams: 4, 14, 16, 18 |
//// | 32   | refusal code        | u8, table below                           |
////
//// ### Refusal codes (type 32)
////
//// | Code | Refusal             |
//// |------|---------------------|
//// | 1    | `Unauthorized`      |
//// | 2    | `Conflict`          |
//// | 3    | `QuotaExceeded`     |
//// | 4    | `TooLarge`          |
//// | 5    | `BadDeadline`       |
//// | 6    | `Malformed`         |
//// | 7    | `UnsupportedVersion`|
//// | 8    | `Unavailable`       |
////
//// ## Bounds
////
//// A request is at most `max_request_bytes`: the largest legitimate one is
//// an `Append` carrying a `max_ciphertext_bytes` ciphertext. A response is
//// at most `max_response_bytes`: a `Batch` of `fetch_batch_envelopes`
//// envelopes holding `fetch_batch_bytes` of ciphertext. The fixed fields
//// around the ciphertext are far below the overhead allowances.
////
//// ## Errors and secrets
////
//// A `CodecError` holds a `TlvError`, which holds type numbers and never
//// value bytes, so no capability can reach an error value or its
//// rendering.

import core/capability.{type Capability}
import core/envelope.{type Padded, type StoredEnvelope}
import core/id.{type Id}
import core/limits
import core/mailbox/protocol.{type Refusal, type Request, type Response}
import core/time.{type Instant}
import core/tlv
import gleam/list
import gleam/result

/// Bytes allowed around the ciphertext in a request: identifiers,
/// capabilities, the deadline and TLV headers use well under 300.
pub const request_overhead_bytes = 1024

/// The largest request the codec will read: an `Append` of a
/// `max_ciphertext_bytes` ciphertext plus the fixed fields around it. A
/// function rather than a constant because Gleam constants cannot add.
///
/// ## Examples
///
/// ```gleam
/// codec.max_request_bytes()
/// // -> 263_168
/// ```
pub fn max_request_bytes() -> Int {
  limits.max_ciphertext_bytes + request_overhead_bytes
}

/// Bytes allowed per envelope in a batch response, for its identifiers,
/// deadline and TLV headers (about 70 are used).
pub const response_overhead_per_envelope_bytes = 128

/// The largest response the codec will read: a `Batch` of
/// `fetch_batch_envelopes` envelopes holding `fetch_batch_bytes` of
/// ciphertext, plus per-envelope and fixed overhead.
///
/// ## Examples
///
/// ```gleam
/// codec.max_response_bytes()
/// // -> 1_051_648
/// ```
pub fn max_response_bytes() -> Int {
  limits.fetch_batch_bytes
  + limits.fetch_batch_envelopes
  * response_overhead_per_envelope_bytes
  + request_overhead_bytes
}

/// The most envelope identifiers one `Ack` names: one fetch batch's worth.
/// A recipient with more to acknowledge sends several requests.
pub const max_ack_envelopes = limits.fetch_batch_envelopes

/// Why bytes are not a request or response this build accepts.
pub type CodecError {
  /// The stream names a protocol version this build does not speak.
  UnsupportedVersion

  /// The bytes are not a well-formed message of a version this build
  /// speaks.
  Malformed(reason: tlv.TlvError)
}

/// What a mailbox answers when a request does not decode: a version
/// mismatch, an oversize body, or plain malformed bytes.
///
/// ## Examples
///
/// ```gleam
/// codec.refusal(codec.UnsupportedVersion)
/// // -> protocol.UnsupportedVersion
/// ```
pub fn refusal(error: CodecError) -> Refusal {
  case error {
    UnsupportedVersion -> protocol.UnsupportedVersion
    Malformed(tlv.InputTooLarge) -> protocol.TooLarge
    Malformed(_) -> protocol.Malformed
  }
}

// ------------------------------------------------------------- requests

/// The canonical bytes of a request.
///
/// ## Examples
///
/// ```gleam
/// codec.encode_request(protocol.DeleteQueue(queue:, admin:))
/// ```
pub fn encode_request(request: Request) -> BitArray {
  case request {
    protocol.CreateQueue(provision:, queue:, read:, append:, admin:) ->
      header(1)
      |> put_id(queue_tag, queue)
      |> put_capability(provision_tag, provision)
      |> put_capability(read_tag, read)
      |> put_capability(append_tag, append)
      |> put_capability(admin_tag, admin)
      |> tlv.encode

    protocol.Append(
      queue:,
      append:,
      envelope:,
      retention_deadline:,
      ciphertext:,
    ) ->
      header(2)
      |> put_id(queue_tag, queue)
      |> put_capability(append_tag, append)
      |> put_id(envelope_tag, envelope)
      |> put_instant(deadline_tag, retention_deadline)
      |> tlv.put(ciphertext_tag, envelope.to_wire(ciphertext))
      |> tlv.encode

    protocol.Fetch(queue:, read:, wait_seconds:, max_envelopes:) ->
      header(3)
      |> put_id(queue_tag, queue)
      |> put_capability(read_tag, read)
      |> tlv.put(wait_tag, tlv.encode_u32(wait_seconds))
      |> tlv.put(max_envelopes_tag, tlv.encode_u32(max_envelopes))
      |> tlv.encode

    protocol.Ack(queue:, read:, envelopes:) ->
      header(4)
      |> put_id(queue_tag, queue)
      |> put_capability(read_tag, read)
      |> tlv.put(
        envelope_list_tag,
        tlv.encode_items(list.map(envelopes, id.to_bytes)),
      )
      |> tlv.encode

    protocol.DeleteQueue(queue:, admin:) ->
      header(5)
      |> put_id(queue_tag, queue)
      |> put_capability(admin_tag, admin)
      |> tlv.encode
  }
}

/// Reads a request. The version is checked before anything else, so the
/// error for a future version does not depend on its other fields.
///
/// ## Examples
///
/// ```gleam
/// codec.decode_request(codec.encode_request(request))
/// // -> Ok(request)
/// ```
pub fn decode_request(bytes: BitArray) -> Result(Request, CodecError) {
  use stream <- result.try(parse(bytes, max_request_bytes()))
  use Nil <- result.try(check_version(stream))

  tlv.run(stream, request_decoder())
  |> result.map_error(Malformed)
}

/// Reads a request's kind and then exactly the fields that kind carries.
fn request_decoder() -> tlv.Decoder(Request) {
  use _version <- tlv.required(version_tag, tlv.u16)
  use kind <- tlv.required(kind_tag, tlv.u8)

  // The kind selects which fields the rest of the stream must hold; any
  // field of another kind is left unread and, being even, is refused.
  case kind {
    1 -> create_queue_decoder()
    2 -> append_decoder()
    3 -> fetch_decoder()
    4 -> ack_decoder()
    5 -> delete_queue_decoder()
    _ -> tlv.fail(tlv.InvalidField(kind_tag))
  }
}

/// Reads a `CreateQueue`: the queue and all four capabilities.
fn create_queue_decoder() -> tlv.Decoder(Request) {
  use queue <- tlv.required(queue_tag, id_field())
  use provision <- tlv.required(provision_tag, capability_field())
  use read <- tlv.required(read_tag, capability_field())
  use append <- tlv.required(append_tag, capability_field())
  use admin <- tlv.required(admin_tag, capability_field())

  tlv.success(protocol.CreateQueue(provision:, queue:, read:, append:, admin:))
}

/// Reads an `Append`: queue, append capability, envelope, deadline, padded ciphertext.
fn append_decoder() -> tlv.Decoder(Request) {
  use queue <- tlv.required(queue_tag, id_field())
  use append <- tlv.required(append_tag, capability_field())
  use envelope <- tlv.required(envelope_tag, id_field())
  use retention_deadline <- tlv.required(deadline_tag, instant_field())
  use ciphertext <- tlv.required(ciphertext_tag, ciphertext_field())

  tlv.success(protocol.Append(
    queue:,
    append:,
    envelope:,
    retention_deadline:,
    ciphertext:,
  ))
}

/// Reads a `Fetch`: queue, read capability, and the wait and batch size.
fn fetch_decoder() -> tlv.Decoder(Request) {
  use queue <- tlv.required(queue_tag, id_field())
  use read <- tlv.required(read_tag, capability_field())
  use wait_seconds <- tlv.required(wait_tag, tlv.u32)
  use max_envelopes <- tlv.required(max_envelopes_tag, tlv.u32)

  tlv.success(protocol.Fetch(queue:, read:, wait_seconds:, max_envelopes:))
}

/// Reads an `Ack`: the queue, the read capability and the envelopes to delete.
fn ack_decoder() -> tlv.Decoder(Request) {
  use queue <- tlv.required(queue_tag, id_field())
  use read <- tlv.required(read_tag, capability_field())
  use envelopes <- tlv.required(envelope_list_tag, envelope_list_field())

  tlv.success(protocol.Ack(queue:, read:, envelopes:))
}

fn delete_queue_decoder() -> tlv.Decoder(Request) {
  use queue <- tlv.required(queue_tag, id_field())
  use admin <- tlv.required(admin_tag, capability_field())

  tlv.success(protocol.DeleteQueue(queue:, admin:))
}

// ------------------------------------------------------------ responses

/// The canonical bytes of a response.
///
/// ## Examples
///
/// ```gleam
/// codec.encode_response(protocol.Acked)
/// ```
pub fn encode_response(response: Response) -> BitArray {
  case response {
    protocol.QueueCreated(queue:) ->
      header(1)
      |> put_id(queue_tag, queue)
      |> tlv.encode

    protocol.Appended(receipt:) ->
      header(2)
      |> tlv.put(receipt_tag, encode_receipt(receipt))
      |> tlv.encode

    protocol.Batch(envelopes:) ->
      header(3)
      |> tlv.put(
        stored_envelopes_tag,
        tlv.encode_sequence(list.map(envelopes, encode_stored)),
      )
      |> tlv.encode

    protocol.Acked -> tlv.encode(header(4))

    protocol.QueueDeleted -> tlv.encode(header(5))

    protocol.Refused(reason:) ->
      header(6)
      |> tlv.put(refusal_tag, tlv.encode_u8(refusal_code(reason)))
      |> tlv.encode
  }
}

/// Reads a response, under the same rules as `decode_request`.
///
/// ## Examples
///
/// ```gleam
/// codec.decode_response(codec.encode_response(protocol.Acked))
/// // -> Ok(protocol.Acked)
/// ```
pub fn decode_response(bytes: BitArray) -> Result(Response, CodecError) {
  use stream <- result.try(parse(bytes, max_response_bytes()))
  use Nil <- result.try(check_version(stream))

  tlv.run(stream, response_decoder())
  |> result.map_error(Malformed)
}

/// Reads a response's kind and then exactly the fields that kind carries.
fn response_decoder() -> tlv.Decoder(Response) {
  use _version <- tlv.required(version_tag, tlv.u16)
  use kind <- tlv.required(kind_tag, tlv.u8)

  // As for requests: the kind fixes the fields, and strays are refused.
  case kind {
    1 -> {
      use queue <- tlv.required(queue_tag, id_field())
      tlv.success(protocol.QueueCreated(queue:))
    }

    2 -> {
      use receipt <- tlv.required(receipt_tag, tlv.nested(receipt_decoder()))
      tlv.success(protocol.Appended(receipt:))
    }

    3 -> {
      use envelopes <- tlv.required(stored_envelopes_tag, stored_list_field())
      tlv.success(protocol.Batch(envelopes:))
    }

    4 -> tlv.success(protocol.Acked)

    5 -> tlv.success(protocol.QueueDeleted)

    6 -> {
      use reason <- tlv.required(refusal_tag, refusal_field())
      tlv.success(protocol.Refused(reason:))
    }

    _ -> tlv.fail(tlv.InvalidField(kind_tag))
  }
}

/// The nested stream for an append receipt: queue, envelope, digest, deadline.
fn encode_receipt(receipt: protocol.AppendReceipt) -> BitArray {
  tlv.new()
  |> put_id(queue_tag, receipt.queue)
  |> put_id(envelope_tag, receipt.envelope)
  |> tlv.put(digest_tag, receipt.digest)
  |> put_instant(deadline_tag, receipt.retention_deadline)
  |> tlv.encode
}

/// Reads the nested stream `encode_receipt` writes.
fn receipt_decoder() -> tlv.Decoder(protocol.AppendReceipt) {
  use queue <- tlv.required(queue_tag, id_field())
  use envelope <- tlv.required(envelope_tag, id_field())
  use digest <- tlv.required(digest_tag, tlv.bytes)
  use retention_deadline <- tlv.required(deadline_tag, instant_field())

  tlv.success(protocol.AppendReceipt(
    queue:,
    envelope:,
    digest:,
    retention_deadline:,
  ))
}

/// The nested stream for one stored envelope in a batch.
fn encode_stored(stored: StoredEnvelope) -> BitArray {
  tlv.new()
  |> put_id(queue_tag, stored.queue)
  |> put_id(envelope_tag, stored.envelope)
  |> put_instant(deadline_tag, stored.retention_deadline)
  |> tlv.put(ciphertext_tag, envelope.to_wire(stored.ciphertext))
  |> tlv.encode
}

/// Reads the nested stream `encode_stored` writes.
fn stored_decoder() -> tlv.Decoder(StoredEnvelope) {
  use queue <- tlv.required(queue_tag, id_field())
  use envelope <- tlv.required(envelope_tag, id_field())
  use retention_deadline <- tlv.required(deadline_tag, instant_field())
  use ciphertext <- tlv.required(ciphertext_tag, ciphertext_field())

  tlv.success(envelope.StoredEnvelope(
    queue:,
    envelope:,
    retention_deadline:,
    ciphertext:,
  ))
}

fn stored_list_field() -> tlv.Field(List(StoredEnvelope)) {
  tlv.sequence(
    tlv.nested(stored_decoder()),
    max_items: limits.fetch_batch_envelopes,
  )
}

/// The wire code of a refusal, per the table in the module doc.
fn refusal_code(reason: Refusal) -> Int {
  case reason {
    protocol.Unauthorized -> 1
    protocol.Conflict -> 2
    protocol.QuotaExceeded -> 3
    protocol.TooLarge -> 4
    protocol.BadDeadline -> 5
    protocol.Malformed -> 6
    protocol.UnsupportedVersion -> 7
    protocol.Unavailable -> 8
  }
}

/// Reads a refusal code; an unassigned code is an invalid field.
fn refusal_field() -> tlv.Field(Refusal) {
  tlv.try_map(tlv.u8, fn(code) {
    case code {
      1 -> Ok(protocol.Unauthorized)
      2 -> Ok(protocol.Conflict)
      3 -> Ok(protocol.QuotaExceeded)
      4 -> Ok(protocol.TooLarge)
      5 -> Ok(protocol.BadDeadline)
      6 -> Ok(protocol.Malformed)
      7 -> Ok(protocol.UnsupportedVersion)
      8 -> Ok(protocol.Unavailable)
      _ -> Error(Nil)
    }
  })
}

// -------------------------------------------------------------- helpers

const version_tag = 0

const kind_tag = 2

const queue_tag = 4

const provision_tag = 6

const read_tag = 8

const append_tag = 10

const admin_tag = 12

const envelope_tag = 14

const deadline_tag = 16

const ciphertext_tag = 18

const wait_tag = 20

const max_envelopes_tag = 22

const envelope_list_tag = 24

const digest_tag = 26

const receipt_tag = 28

const stored_envelopes_tag = 30

const refusal_tag = 32

fn header(kind: Int) -> tlv.Builder {
  tlv.new()
  |> tlv.put(version_tag, tlv.encode_u16(protocol.version))
  |> tlv.put(kind_tag, tlv.encode_u8(kind))
}

fn parse(bytes: BitArray, limit: Int) -> Result(tlv.Stream, CodecError) {
  tlv.parse(bytes, max_bytes: limit)
  |> result.map_error(Malformed)
}

/// The version is read from the parsed stream alone. A stream with no
/// readable version is malformed; one with a different version is
/// unsupported, whatever else it holds.
fn check_version(stream: tlv.Stream) -> Result(Nil, CodecError) {
  use version <- result.try(
    tlv.peek(stream, version_tag, tlv.u16)
    |> result.map_error(Malformed),
  )

  // Only the one version this build speaks may be decoded further.
  case version == protocol.version {
    True -> Ok(Nil)
    False -> Error(UnsupportedVersion)
  }
}

fn put_id(builder: tlv.Builder, tag: Int, value: Id(kind)) -> tlv.Builder {
  tlv.put(builder, tag, id.to_bytes(value))
}

/// This is the one place a capability becomes bytes on the wire.
fn put_capability(
  builder: tlv.Builder,
  tag: Int,
  value: Capability(authority),
) -> tlv.Builder {
  tlv.put(builder, tag, capability.expose(value))
}

fn put_instant(builder: tlv.Builder, tag: Int, value: Instant) -> tlv.Builder {
  tlv.put(builder, tag, tlv.encode_u64(value.unix_seconds))
}

fn id_field() -> tlv.Field(Id(kind)) {
  tlv.try_map(tlv.fixed_bytes(id.id_bytes), id.from_bytes)
}

fn capability_field() -> tlv.Field(Capability(authority)) {
  tlv.try_map(
    tlv.fixed_bytes(capability.capability_bytes),
    capability.from_bytes,
  )
}

fn instant_field() -> tlv.Field(Instant) {
  tlv.map(tlv.u64, fn(seconds) { time.Instant(unix_seconds: seconds) })
}

fn ciphertext_field() -> tlv.Field(Padded) {
  tlv.try_map(tlv.bytes, envelope.from_wire)
}

fn envelope_list_field() -> tlv.Field(List(Id(kind))) {
  tlv.items(id.id_bytes, id_field())
  |> bounded_list(max_ack_envelopes)
}

/// Refuses a list over `limit`. Dropping `limit` elements and finding
/// something left is the length comparison without counting the list.
fn bounded_list(field: tlv.Field(List(a)), limit: Int) -> tlv.Field(List(a)) {
  tlv.try_map(field, fn(values) {
    case list.drop(values, limit) {
      [] -> Ok(values)
      [_, ..] -> Error(Nil)
    }
  })
}
