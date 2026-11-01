//// What the `reedwire` CLI prints for a successful response.
////
//// Machine-readable output (`--json`) is the response line unchanged and
//// needs no rendering. Human output is built here from the response's
//// `result`, using total decoders: a result that does not have the shape
//// the command expects is an error message, never a crash.
////
//// Output is bytes, not text, because `receive --raw` writes a payload that
//// need not be UTF-8. Anything that is not a payload goes on standard out
//// as text, one record per line, with fields separated by spaces so a shell
//// script can split it.

import daemon/cli.{
  type Action, AcceptInvite, Acknowledge, ApproveContact, CloseContact,
  CreateInvite, DeclineContact, ListContacts, MessageStatus, RaiseBudget, Raw,
  ReceiveMessages, SendMessage, ShowAudit, ShowHealth, ShowIncidents,
}
import gleam/bit_array
import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/int
import gleam/list
import gleam/option
import gleam/result
import gleam/string

/// What a command prints: the bytes for standard output and a line for
/// standard error. Standard error carries only what a script must not
/// parse out of the payload stream, such as the id of a raw message.
pub type Rendered {
  Rendered(stdout: BitArray, stderr: String)
}

/// The invitation bytes of a `create invite` result.
///
/// ## Examples
///
/// ```gleam
/// cli_render.invitation(result)
/// // -> Ok(<<...>>)
/// ```
pub fn invitation(result: Dynamic) -> Result(BitArray, String) {
  use text <- result.try(field(result, "invitation", decode.string))

  bit_array.base64_decode(text)
  |> result.replace_error("the daemon sent a malformed invitation")
}

/// Renders a result for human reading. `CreateInvite` renders only its
/// confirmation, because the caller writes the file.
///
/// ## Examples
///
/// ```gleam
/// cli_render.render(Acknowledge(message), result)
/// // -> Ok(Rendered(<<"ok\n">>, ""))
/// ```
pub fn render(action: Action, result: Dynamic) -> Result(Rendered, String) {
  case action {
    CreateInvite(out:, ..) -> Ok(text("wrote " <> out))
    AcceptInvite(..) -> contact_line(result)
    ListContacts -> contacts(result)

    ApproveContact(..)
    | DeclineContact(..)
    | CloseContact(..)
    | RaiseBudget(..)
    | Acknowledge(..) -> Ok(text("ok"))

    SendMessage(..) -> message_line(result)
    ReceiveMessages(view:, ..) -> deliveries(result, view)
    MessageStatus(..) -> state_line(result)
    ShowAudit(..) -> audit(result)
    ShowIncidents(..) -> incidents(result)
    ShowHealth -> health(result)
  }
}

/// Standard output with one line of text.
fn text(line: String) -> Rendered {
  Rendered(<<line:utf8, "\n">>, "")
}

/// Reads one named field of a result.
fn field(
  result: Dynamic,
  name: String,
  decoder: decode.Decoder(a),
) -> Result(a, String) {
  decode.run(result, decode.field(name, decoder, decode.success))
  |> result.replace_error("the daemon sent a malformed result")
}

/// The `contact` of an accept result.
fn contact_line(result: Dynamic) -> Result(Rendered, String) {
  use contact <- result.try(field(result, "contact", decode.string))
  Ok(text(contact))
}

/// The `message` of a send result.
fn message_line(result: Dynamic) -> Result(Rendered, String) {
  use message <- result.try(field(result, "message", decode.string))
  Ok(text(message))
}

/// The `state` of a status result.
fn state_line(result: Dynamic) -> Result(Rendered, String) {
  use state <- result.try(field(result, "state", decode.string))
  Ok(text(state))
}

/// The contacts as one line each:
/// `<contact> <phase> budget=<used>/<granted> held=<n> <description>`.
fn contacts(result: Dynamic) -> Result(Rendered, String) {
  let row = {
    use contact <- decode.field("contact", decode.string)
    use phase <- decode.field("phase", decode.string)
    use description <- decode.field("description", decode.string)
    use granted <- decode.field("budget_granted", decode.int)
    use used <- decode.field("budget_used", decode.int)
    use held <- decode.field("held", decode.int)

    decode.success(string.join(
      [
        contact,
        phase,
        "budget=" <> int.to_string(used) <> "/" <> int.to_string(granted),
        "held=" <> int.to_string(held),
        description,
      ],
      " ",
    ))
  }

  use lines <- result.try(field(result, "contacts", decode.list(row)))
  Ok(lines_of(lines))
}

/// One delivery as the CLI needs it.
type Row {
  Row(
    message: String,
    contact: String,
    content_type: String,
    payload: BitArray,
    received_at: Int,
  )
}

/// Decodes a delivery, turning its base64 payload into bytes.
fn row_decoder() -> decode.Decoder(Row) {
  use message <- decode.field("message", decode.string)
  use contact <- decode.field("contact", decode.string)
  use content_type <- decode.field("content_type", decode.string)
  use payload <- decode.field("payload", decode.string)
  use received_at <- decode.field("received_at", decode.int)

  // The payload crosses the wire as base64, so a bad one is a malformed result and not a crash.
  case bit_array.base64_decode(payload) {
    Ok(payload) ->
      decode.success(Row(
        message:,
        contact:,
        content_type:,
        payload:,
        received_at:,
      ))

    Error(Nil) -> decode.failure(Row("", "", "", <<>>, 0), "base64 payload")
  }
}

/// The deliveries. Encoded, each is a header line
/// `<message> <contact> <content-type> bytes=<n> at=<seconds>` followed by
/// its payload as base64. Raw, the one message's bytes alone go to standard
/// output and its id and contact to standard error, so `ack` can follow.
fn deliveries(
  result: Dynamic,
  view: cli.PayloadView,
) -> Result(Rendered, String) {
  use rows <- result.try(field(result, "deliveries", decode.list(row_decoder())))

  // Raw output carries the one message alone, while the encoded view lists every delivery.
  case view, rows {
    Raw, [row, ..] ->
      Ok(Rendered(
        row.payload,
        "message " <> row.message <> " contact " <> row.contact,
      ))

    Raw, [] -> Ok(Rendered(<<>>, ""))

    _, _ ->
      Ok(
        lines_of(
          list.flat_map(rows, fn(row) {
            [
              string.join(
                [
                  row.message,
                  row.contact,
                  row.content_type,
                  "bytes=" <> int.to_string(bit_array.byte_size(row.payload)),
                  "at=" <> int.to_string(row.received_at),
                ],
                " ",
              ),
              bit_array.base64_encode(row.payload, True),
            ]
          }),
        ),
      )
  }
}

/// The audit log as one line per entry:
/// `<at> <direction> <contact> <message> <content-type> <payload>`, where
/// the payload is its text, quoted, when it is UTF-8 and `base64:` followed
/// by its bytes otherwise.
fn audit(result: Dynamic) -> Result(Rendered, String) {
  let row = {
    use at <- decode.field("at", decode.int)
    use direction <- decode.field("direction", decode.string)
    use contact <- decode.field("contact", decode.string)
    use message <- decode.field("message", decode.string)
    use content_type <- decode.field("content_type", decode.string)
    use payload <- decode.field("payload", decode.string)

    decode.success(string.join(
      [
        int.to_string(at),
        direction,
        contact,
        message,
        content_type,
        show_payload(payload),
      ],
      " ",
    ))
  }

  use lines <- result.try(field(result, "entries", decode.list(row)))
  Ok(lines_of(lines))
}

/// The incidents as one line per entry:
/// `<at> <kind> contact=<hex|-> message=<hex|-> attempts=<n|->`. An
/// incident carries no payload, so there is none to show.
fn incidents(result: Dynamic) -> Result(Rendered, String) {
  // An absent identifier or count is `null` on the wire and `-` here.
  let text_or_dash =
    decode.optional(decode.string)
    |> decode.map(option.unwrap(_, "-"))
  let count_or_dash =
    decode.optional(decode.int)
    |> decode.map(fn(count) {
      option.map(count, int.to_string) |> option.unwrap("-")
    })

  let row = {
    use at <- decode.field("at", decode.int)
    use kind <- decode.field("kind", decode.string)
    use contact <- decode.field("contact", text_or_dash)
    use message <- decode.field("message", text_or_dash)
    use attempts <- decode.field("attempts", count_or_dash)

    decode.success(string.join(
      [
        int.to_string(at),
        kind,
        "contact=" <> contact,
        "message=" <> message,
        "attempts=" <> attempts,
      ],
      " ",
    ))
  }

  use lines <- result.try(field(result, "incidents", decode.list(row)))
  Ok(lines_of(lines))
}

/// A base64 payload as quoted text when it is UTF-8, else as base64.
fn show_payload(encoded: String) -> String {
  let decoded =
    bit_array.base64_decode(encoded)
    |> result.try(bit_array.to_string)

  // The audit log shows text when the payload is UTF-8 and base64 when it is not.
  case decoded {
    Ok(text) -> string.inspect(text)
    Error(Nil) -> "base64:" <> encoded
  }
}

/// The health fields as `name=value` lines.
fn health(result: Dynamic) -> Result(Rendered, String) {
  use fields <- result.try(
    decode.run(result, decode.dict(decode.string, decode.string))
    |> result.replace_error("the daemon sent a malformed result"),
  )

  let lines =
    fields
    |> dict.to_list
    |> list.map(fn(pair) { pair.0 <> "=" <> pair.1 })
    |> list.sort(string.compare)

  Ok(lines_of(lines))
}

/// Lines of text as standard output, each ending in a newline.
fn lines_of(lines: List(String)) -> Rendered {
  case lines {
    [] -> Rendered(<<>>, "")
    _ -> text(string.join(lines, "\n"))
  }
}
