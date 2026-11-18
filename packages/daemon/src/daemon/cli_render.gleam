//// What the `pondline` CLI prints for a successful response.
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

import core/id
import daemon/cli.{
  type Action, type ContactEntry, type Decoding, AcceptInvite, Acknowledge,
  ApproveContact, CloseContact, CreateInvite, DeclineContact, DecodeText,
  KeepEncoded, ListContacts, MessageStatus, RaiseBudget, Raw, ReceiveMessages,
  RenameContact, SendMessage, ShowAudit, ShowHealth, ShowIncidents, ShowMessages,
}
import daemon/local_api_protocol as protocol
import gleam/bit_array
import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
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

/// The ticket's text of a `create invite --ticket` result (ADR-009).
///
/// ## Examples
///
/// ```gleam
/// cli_render.ticket(result)
/// // -> Ok("pl1...")
/// ```
pub fn ticket(result: Dynamic) -> Result(String, String) {
  field(result, "ticket", decode.string)
}

/// Renders a result for human reading. `names` are the contacts the daemon
/// lists, which `messages` uses to title each section. `CreateInvite` renders nothing:
/// `cli_run` writes the file and prints the ticket or path itself.
///
/// ## Examples
///
/// ```gleam
/// cli_render.render(Acknowledge(message), result, [])
/// // -> Ok(Rendered(<<"ok\n">>, ""))
/// ```
pub fn render(
  action: Action,
  result: Dynamic,
  names: List(ContactEntry),
) -> Result(Rendered, String) {
  case action {
    // `cli_run` hands out an invitation itself, before rendering.
    CreateInvite(..) -> Ok(Rendered(<<>>, ""))

    AcceptInvite(..) -> contact_line(result)
    ListContacts -> contacts(result)

    ApproveContact(..)
    | DeclineContact(..)
    | CloseContact(..)
    | RaiseBudget(..)
    | RenameContact(..)
    | Acknowledge(..) -> Ok(text("ok"))

    SendMessage(..) -> message_line(result)
    ReceiveMessages(view:, ..) -> deliveries(result, view)
    MessageStatus(..) -> state_line(result)
    ShowAudit(..) -> audit(result)
    ShowMessages(decoding:, ..) -> messages(result, names, decoding)
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
                  inline(row.content_type),
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
        inline(content_type),
        show_payload(payload),
      ],
      " ",
    ))
  }

  use lines <- result.try(field(result, "entries", decode.list(row)))
  Ok(lines_of(lines))
}

/// One message of the audit log, with the payload still base64 as the daemon
/// sent it.
type Entry {
  Entry(
    contact: String,
    message: String,
    direction: String,
    at: Int,
    content_type: String,
    payload: String,
  )
}

/// One contact's messages, oldest first, with the name the operator knows the
/// contact by when there is one.
type Conversation {
  Conversation(contact: String, name: Option(String), entries: List(Entry))
}

/// The audit entries of an `audit` result, newest first as the daemon sends
/// them.
fn entries(result: Dynamic) -> Result(List(Entry), String) {
  let row = {
    use at <- decode.field("at", decode.int)
    use direction <- decode.field("direction", decode.string)
    use contact <- decode.field("contact", decode.string)
    use message <- decode.field("message", decode.string)
    use content_type <- decode.field("content_type", decode.string)
    use payload <- decode.field("payload", decode.string)

    decode.success(Entry(
      contact:,
      message:,
      direction:,
      at:,
      content_type:,
      payload:,
    ))
  }

  field(result, "entries", decode.list(row))
}

/// The entries grouped into an inbox: one conversation per contact, the
/// contact with the most recent message first, and each contact's messages
/// oldest first, in the order they were said.
///
/// The daemon answers newest first so that a limit keeps the most recent
/// messages. Taking contacts in the order they first appear therefore sorts
/// them by latest activity, and reversing each contact's own list restores
/// the order of the conversation.
fn conversations(
  all: List(Entry),
  names: List(ContactEntry),
) -> List(Conversation) {
  all
  |> list.map(fn(entry) { entry.contact })
  |> list.unique
  |> list.map(fn(contact) {
    let mine = list.filter(all, fn(entry) { entry.contact == contact })

    Conversation(
      contact:,
      name: name_of(contact, names),
      entries: list.reverse(mine),
    )
  })
}

/// The name the operator gave a contact, if the daemon still lists it.
fn name_of(contact: String, names: List(ContactEntry)) -> Option(String) {
  list.find(names, fn(known) { id.to_hex(known.contact) == contact })
  |> result.map(fn(known) { known.description })
  |> option.from_result
}

/// The audit log as an inbox for a person to read: a section for each
/// contact, then each message as a header, `<UTC time> <-|-> <content type>
/// <message prefix>`, with its payload indented below it. Contacts and
/// messages are separated by a blank line.
///
/// A peer chooses both the payload and the content type, so both are shown
/// with control characters escaped: a raw escape sequence would otherwise
/// reach the operator's terminal. A name is the operator's own and is
/// escaped as well, since it is printed on one line.
fn messages(
  result: Dynamic,
  names: List(ContactEntry),
  decoding: Decoding,
) -> Result(Rendered, String) {
  use all <- result.try(entries(result))

  // A blank element between two sections is the blank line between them.
  let sections =
    conversations(all, names)
    |> list.map(fn(conversation) { conversation_text(conversation, decoding) })

  Ok(lines_of(list.intersperse(sections, "")))
}

/// One contact's section of the inbox.
fn conversation_text(conversation: Conversation, decoding: Decoding) -> String {
  let prefix = string.slice(conversation.contact, 0, 8)

  // A contact with a name is titled by it and its prefix; one the daemon no
  // longer lists is titled by the prefix alone.
  let heading = case conversation.name {
    Some(name) -> inline(name) <> "  (" <> prefix <> ")"
    None -> prefix
  }

  let bodies =
    list.map(conversation.entries, fn(entry) { entry_text(entry, decoding) })

  string.join([heading, ..list.intersperse(bodies, "")], "\n")
}

/// One message: its header line and its payload below it.
fn entry_text(entry: Entry, decoding: Decoding) -> String {
  let header =
    string.join(
      [
        utc_time(entry.at),
        arrow(entry.direction),
        inline(entry.content_type),
        string.slice(entry.message, 0, 8),
      ],
      "  ",
    )

  // Decoding is the only difference between the two views: kept encoded, the
  // payload is the base64 the daemon sent and nothing is interpreted.
  let body = case decoding {
    DecodeText -> message_text(entry.payload)
    KeepEncoded -> "base64:" <> entry.payload
  }

  "  " <> header <> "\n" <> indent_by(body, "    ")
}

/// The same inbox as JSON for a program, as one answer in the usual envelope:
/// `{"contacts": [{"contact", "description", "messages": [...]}]}`.
///
/// A message carries `text` when decoding is on and its payload is UTF-8, and
/// the base64 `payload` otherwise, so a program always gets exactly one of
/// the two. `cli_run` owns the output mode and calls this for `--json`.
///
/// ## Examples
///
/// ```gleam
/// cli_render.messages_json(result, [], cli.DecodeText)
/// // -> Ok("{\"ok\":true,\"result\":{\"contacts\":[]}}")
/// ```
pub fn messages_json(
  result: Dynamic,
  names: List(ContactEntry),
  decoding: Decoding,
) -> Result(String, String) {
  use all <- result.try(entries(result))

  let contacts =
    conversations(all, names)
    |> json.array(fn(conversation) {
      json.object([
        #("contact", json.string(conversation.contact)),
        #("description", json.nullable(conversation.name, json.string)),
        #(
          "messages",
          json.array(conversation.entries, fn(entry) {
            entry_json(entry, decoding)
          }),
        ),
      ])
    })

  Ok(protocol.success_json(json.object([#("contacts", contacts)])))
}

/// One message as a JSON object.
fn entry_json(entry: Entry, decoding: Decoding) -> json.Json {
  let decoded =
    bit_array.base64_decode(entry.payload)
    |> result.try(bit_array.to_string)

  // Exactly one of `text` and `payload` is present.
  let body = case decoding, decoded {
    DecodeText, Ok(text) -> #("text", json.string(text))
    DecodeText, Error(Nil) | KeepEncoded, _ -> #(
      "payload",
      json.string(entry.payload),
    )
  }

  json.object([
    #("message", json.string(entry.message)),
    #("direction", json.string(entry.direction)),
    #("at", json.int(entry.at)),
    #("time", json.string(utc_time(entry.at))),
    #("content_type", json.string(entry.content_type)),
    body,
  ])
}

/// `<-` for a message that arrived and `->` for one that was sent.
fn arrow(direction: String) -> String {
  case direction {
    "inbound" -> "<-"
    "outbound" -> "->"
    other -> inline(other)
  }
}

/// A base64 payload as printable text when it is UTF-8, else as base64.
fn message_text(encoded: String) -> String {
  let decoded =
    bit_array.base64_decode(encoded)
    |> result.try(bit_array.to_string)

  // Text is shown as text, and bytes that are not text as the base64 they
  // arrived in, so nothing is lost and nothing is misread.
  case decoded {
    Ok(text) -> printable(text)
    Error(Nil) -> "base64:" <> encoded
  }
}

/// Every line of `text` behind `margin`.
fn indent_by(text: String, margin: String) -> String {
  string.split(text, "\n")
  |> list.map(fn(line) {
    // A blank line stays empty, so no line ends in trailing spaces.
    case line {
      "" -> ""
      _ -> margin <> line
    }
  })
  |> string.join("\n")
}

/// Whether a newline and a tab stay as they are or are escaped like any other
/// control character.
type Layout {
  /// Multi-line text, where line breaks are the text's own layout.
  KeepLayout

  /// A field on one line, where a line break would start a forged line.
  EscapeLayout
}

/// Multi-line peer text with control characters other than a newline or a tab
/// written as `\xNN`, so it cannot move the cursor or retitle the terminal.
fn printable(text: String) -> String {
  escape_controls(text, KeepLayout)
}

/// A peer's one-line field, such as a content type, with every control
/// character written as `\xNN`, newline and tab included. A newline kept here
/// would let the peer start a line of its own that reads as a header.
fn inline(text: String) -> String {
  escape_controls(text, EscapeLayout)
}

/// Writes controls out as `\xNN` and leaves every other codepoint alone.
fn escape_controls(text: String, layout: Layout) -> String {
  string.to_utf_codepoints(text)
  |> list.map(fn(point) {
    let code = string.utf_codepoint_to_int(point)

    // Layout is the only difference between the two callers: it decides
    // whether a newline or a tab counts as a control to write out.
    let is_layout = case layout {
      KeepLayout -> code == 10 || code == 9
      EscapeLayout -> False
    }

    // Layout stays, and any other control is written out, since a terminal
    // would act on it.
    case is_layout || !is_control(code) {
      True -> string.from_utf_codepoints([point])
      False -> "\\x" <> hex_digits(code, 2)
    }
  })
  |> string.concat
}

/// Whether a codepoint is a C0 control, DEL or a C1 control. The C1 range
/// (0x80 to 0x9f) acts as escape sequences on some terminals.
fn is_control(code: Int) -> Bool {
  code < 32 || code == 127 || { code >= 128 && code <= 159 }
}

/// `value` in lowercase hex, padded with zeros to `width` digits.
fn hex_digits(value: Int, width: Int) -> String {
  string.pad_start(string.lowercase(int.to_base16(value)), width, "0")
}

/// Unix seconds as `YYYY-MM-DD HH:MM:SSZ` in UTC. The calendar part is the
/// civil-from-days algorithm: days are counted from 0000-03-01 so a leap day
/// falls at the end of a year.
fn utc_time(seconds: Int) -> String {
  let seconds = int.max(seconds, 0)
  let days = seconds / 86_400
  let rest = seconds % 86_400

  let z = days + 719_468
  let era = z / 146_097
  let day_of_era = z - era * 146_097
  let year_of_era =
    {
      day_of_era
      - day_of_era
      / 1460
      + day_of_era
      / 36_524
      - day_of_era
      / 146_096
    }
    / 365
  let day_of_year =
    day_of_era - { 365 * year_of_era + year_of_era / 4 - year_of_era / 100 }
  let shifted_month = { 5 * day_of_year + 2 } / 153
  let day = day_of_year - { 153 * shifted_month + 2 } / 5 + 1

  // The year starts in March, so January and February belong to the next
  // calendar year and their shifted months are 10 and 11.
  let month = case shifted_month < 10 {
    True -> shifted_month + 3
    False -> shifted_month - 9
  }

  // January and February fall in the year after the March-based one.
  let year = case month <= 2 {
    True -> year_of_era + era * 400 + 1
    False -> year_of_era + era * 400
  }

  int.to_string(year)
  <> "-"
  <> two_digits(month)
  <> "-"
  <> two_digits(day)
  <> " "
  <> two_digits(rest / 3600)
  <> ":"
  <> two_digits(rest % 3600 / 60)
  <> ":"
  <> two_digits(rest % 60)
  <> "Z"
}

/// A non-negative number below 100 as two digits.
fn two_digits(value: Int) -> String {
  string.pad_start(int.to_string(value), 2, "0")
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
