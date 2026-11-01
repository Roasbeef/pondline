//// The plaintext inside the encryption (spec §7.1), and the `Hello` that
//// opens a relationship.
////
//// Everything a peer says after the handshake is a `Message`: an
//// application payload, a receipt, or one of three relationship controls.
//// The first thing the joiner says is different in kind. It travels inside
//// the PQXDH initial message, before any relationship exists, and it must
//// never be mistaken for a message or the reverse, so it is a separate
//// type, `Hello`, with its own decoder. The two share a discriminator
//// space (TLV type 0), and `Hello`'s value is not one a `Message` decoder
//// accepts, so a `Hello` cannot arrive as a message and an `Accept` cannot
//// be smuggled in a `Hello`.
////
//// Application payloads are `Secret`s. Plaintext must not reach a log line
//// or a crash report (`docs/gleam-style.md` Part IV §7), and a record that
//// carries a payload is exactly what a careless `string.inspect` prints.
//// The bytes come out through `secret.expose` where the shell stores or
//// delivers them, and each such call is a place a reviewer reads.
////
//// Both codecs are total and canonical: every field is bounded before it
//// is read, an unknown even TLV type fails closed, and a field that does
//// not belong to the message's kind is an unknown type, so a receipt that
//// carries a payload is refused rather than ignored.

import core/field
import core/id.{
  type Id, type Invitation as InvitationKind, type Message as MessageKind,
}
import core/limits
import core/route.{type Route}
import core/secret.{type Secret}
import core/time.{type Instant}
import core/tlv
import gleam/bit_array
import gleam/list
import gleam/option.{type Option, None, Some}

/// The largest application payload one message carries.
pub const max_payload_bytes = limits.max_body_bytes

/// The longest content type, in bytes. New limit, derived from nothing in
/// `core/limits`; flagged for the spec's §11.3 table.
pub const max_content_type_bytes = 128

/// The longest human-readable description in a `Hello`, in bytes. New
/// limit, flagged for §11.3.
pub const max_description_bytes = 256

/// The most message identifiers one receipt names. New limit, flagged for
/// §11.3.
pub const max_receipt_ids = 64

/// The largest encoded message: the payload bound plus room for the framing,
/// the content type and a full receipt.
pub const max_message_bytes = 67_584

/// A message from a peer, authenticated by the ratchet that carried it.
pub type Message {
  Message(
    /// The sender's identifier, fresh per message and never reused.
    id: Id(MessageKind),
    /// After this instant the message must not reach the agent, though the
    /// ratchet still advances past it (spec §8.3).
    expires_at: Instant,
    /// What the message says.
    body: Body,
  )
}

/// What a message says.
pub type Body {
  /// Opaque application content for the host.
  Application(
    /// A label the host understands; the core does not interpret it.
    content_type: String,
    /// The bytes, at most `max_payload_bytes`.
    payload: Secret,
    /// The message this answers, if any.
    in_reply_to: Option(Id(MessageKind)),
  )

  /// The receiver durably stored these messages (spec §7.3). A receipt
  /// never asks for a receipt.
  Receipt(
    /// The messages stored, at most `max_receipt_ids`.
    of: List(Id(MessageKind)),
  )

  /// The inviter approved the relationship.
  Accept

  /// The inviter declined the relationship.
  Reject

  /// The sender is ending the relationship.
  Close
}

/// The joiner's first words, inside the PQXDH initial message. It names the
/// invitation it answers (the associated data of the handshake's first
/// message) and says where to reply.
pub type Hello {
  Hello(
    /// The invitation being redeemed.
    invitation: Id(InvitationKind),
    /// Where the inviter appends its replies. Carries an append capability.
    reply: Route,
    /// How the joiner describes itself. Informational, unverified.
    description: String,
  )
}

/// The discriminator in TLV type 0, shared by messages and `Hello`.
type Kind {
  ApplicationKind
  ReceiptKind
  AcceptKind
  RejectKind
  CloseKind
  HelloKind
}

/// The canonical plaintext of a message, as a `Secret` because it holds the
/// payload.
///
/// ## Examples
///
/// ```gleam
/// message.decode(secret.expose(message.encode(msg))) == Ok(msg)
/// // -> True
/// ```
pub fn encode(message: Message) -> Secret {
  let header =
    tlv.new()
    |> tlv.put(2, id.to_bytes(message.id))
    |> tlv.put(4, field.encode_instant(message.expires_at))

  secret.new(tlv.encode(encode_body(header, message.body)))
}

/// Adds the body's own records, and the kind that says which they are.
fn encode_body(header: tlv.Builder, body: Body) -> tlv.Builder {
  case body {
    Application(content_type:, payload:, in_reply_to:) ->
      header
      |> tlv.put(0, tlv.encode_u8(0))
      |> tlv.put(6, tlv.encode_text(content_type))
      |> tlv.put(8, secret.expose(payload))
      |> put_optional_id(10, in_reply_to)

    Receipt(of:) ->
      header
      |> tlv.put(0, tlv.encode_u8(1))
      |> tlv.put(12, tlv.encode_items(list.map(of, id.to_bytes)))

    Accept -> tlv.put(header, 0, tlv.encode_u8(2))

    Reject -> tlv.put(header, 0, tlv.encode_u8(3))

    Close -> tlv.put(header, 0, tlv.encode_u8(4))
  }
}

/// Writes an identifier record only when there is one.
fn put_optional_id(
  builder: tlv.Builder,
  tag: Int,
  value: Option(Id(kind)),
) -> tlv.Builder {
  case value {
    Some(value) -> tlv.put(builder, tag, id.to_bytes(value))
    None -> builder
  }
}

/// Decodes a message. Total: every failure is a `TlvError`, none of which
/// carries payload bytes.
///
/// ## Examples
///
/// ```gleam
/// message.decode(<<>>)
/// // -> Error(tlv.MissingRequired(0))
/// ```
pub fn decode(plaintext: BitArray) -> Result(Message, tlv.TlvError) {
  tlv.decode(plaintext, max_bytes: max_message_bytes, with: message_decoder())
}

/// The records common to every message, then the body its kind owns.
fn message_decoder() -> tlv.Decoder(Message) {
  use kind <- tlv.required(0, kind_field())
  use id <- tlv.required(2, field.id())
  use expires_at <- tlv.required(4, field.instant())
  use body <- body_decoder(kind)

  tlv.success(Message(id:, expires_at:, body:))
}

/// Reads the records that belong to `kind` and no others, so a field of a
/// different kind is an unknown type, and even types fail closed.
fn body_decoder(
  kind: Kind,
  next: fn(Body) -> tlv.Decoder(a),
) -> tlv.Decoder(a) {
  // Each kind owns its records; `Hello` is not a message and is refused.
  case kind {
    ApplicationKind -> {
      use content_type <- tlv.required(
        6,
        field.bounded_text(max_content_type_bytes),
      )
      use payload <- tlv.required(
        8,
        tlv.try_map(field.bounded_bytes(max_payload_bytes), fn(raw) {
          Ok(secret.new(raw))
        }),
      )
      use in_reply_to <- tlv.optional(10, field.id())

      next(Application(content_type:, payload:, in_reply_to:))
    }

    ReceiptKind -> {
      use of <- tlv.required(12, receipt_ids())

      next(Receipt(of:))
    }

    AcceptKind -> next(Accept)

    RejectKind -> next(Reject)

    CloseKind -> next(Close)

    HelloKind -> tlv.fail(tlv.InvalidField(0))
  }
}

/// A non-empty list of at most `max_receipt_ids` message identifiers.
fn receipt_ids() -> tlv.Field(List(Id(MessageKind))) {
  tlv.items(id.id_bytes, field.id())
  |> tlv.try_map(fn(ids) {
    case ids != [] && list.drop(ids, max_receipt_ids) == [] {
      True -> Ok(ids)
      False -> Error(Nil)
    }
  })
}

/// The canonical plaintext of a `Hello`, as a `Secret` because it holds an
/// append capability.
///
/// ## Examples
///
/// ```gleam
/// message.decode_hello(secret.expose(message.encode_hello(hello)))
/// // -> Ok(hello)
/// ```
pub fn encode_hello(hello: Hello) -> Secret {
  tlv.new()
  |> tlv.put(0, tlv.encode_u8(5))
  |> tlv.put(2, id.to_bytes(hello.invitation))
  |> tlv.put(4, route.encode(hello.reply))
  |> tlv.put(6, tlv.encode_text(hello.description))
  |> tlv.encode
  |> secret.new
}

/// Decodes a `Hello`. A message's bytes are not a `Hello`: the discriminator
/// differs.
///
/// ## Examples
///
/// ```gleam
/// message.decode_hello(<<>>)
/// // -> Error(tlv.MissingRequired(0))
/// ```
pub fn decode_hello(plaintext: BitArray) -> Result(Hello, tlv.TlvError) {
  tlv.decode(plaintext, max_bytes: max_hello_bytes, with: {
    use kind <- tlv.required(0, kind_field())
    use invitation <- tlv.required(2, field.id())
    use reply <- tlv.required(4, tlv.nested(route.decoder()))
    use description <- tlv.required(
      6,
      field.bounded_text(max_description_bytes),
    )

    // Only the `Hello` discriminator is a `Hello`; a message kind is refused.
    case kind {
      HelloKind -> tlv.success(Hello(invitation:, reply:, description:))

      ApplicationKind | ReceiptKind | AcceptKind | RejectKind | CloseKind ->
        tlv.fail(tlv.InvalidField(0))
    }
  })
}

/// The largest encoded `Hello`: a route, a description and framing.
pub const max_hello_bytes = 1024

/// The discriminator in type 0; an unassigned number is refused.
fn kind_field() -> tlv.Field(Kind) {
  tlv.try_map(tlv.u8, fn(number) {
    case number {
      0 -> Ok(ApplicationKind)
      1 -> Ok(ReceiptKind)
      2 -> Ok(AcceptKind)
      3 -> Ok(RejectKind)
      4 -> Ok(CloseKind)
      5 -> Ok(HelloKind)
      _ -> Error(Nil)
    }
  })
}

/// Whether `payload` is within `max_payload_bytes`, for a sender that checks
/// before encrypting.
///
/// ## Examples
///
/// ```gleam
/// message.payload_fits(<<1, 2, 3>>)
/// // -> True
/// ```
pub fn payload_fits(payload: BitArray) -> Bool {
  bit_array.byte_size(payload) <= max_payload_bytes
}

/// Whether `content_type` is within `max_content_type_bytes`.
///
/// ## Examples
///
/// ```gleam
/// message.content_type_fits("text/plain")
/// // -> True
/// ```
pub fn content_type_fits(content_type: String) -> Bool {
  bit_array.byte_size(bit_array.from_string(content_type))
  <= max_content_type_bytes
}
