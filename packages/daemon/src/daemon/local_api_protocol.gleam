//// The wire protocol of the local API: what a request and a response look
//// like, and the bounds both sides share.
////
//// The protocol is newline-delimited JSON over a Unix socket. A client
//// writes one line and reads one line:
////
//// ```text
//// {"v":1,"credential":"<base64>","op":"send","args":{...}}
//// {"ok":true,"result":{...}}
//// {"ok":false,"error":{"category":"forbidden","message":"..."}}
//// ```
////
//// Binary values (payloads, invitation files, the credential) are base64 in
//// the JSON and identifiers are hex. The error `category` is a stable
//// word a program can branch on; the `message` is for a person and never
//// carries a credential or a payload. The server (`local_api`) and the
//// client (`local_api_client`) both build on this module so they cannot
//// drift apart.

import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/json.{type Json}
import gleam/result

/// The protocol version both sides speak.
pub const version = 1

/// The longest request or response line, in bytes, without its newline. A
/// 64 KiB payload is a little under 88 KiB as base64, so this leaves room
/// for the envelope and for a full batch of small deliveries.
pub const max_line_bytes = 262_144

/// The most deliveries one `receive` returns.
pub const max_receive = 64

/// The longest a `receive` may wait for a delivery, in milliseconds.
pub const max_wait_ms = 30_000

/// The stable error categories of the protocol.
pub type Category {
  /// The credential is missing or wrong.
  Unauthorized

  /// The credential is valid but its scope does not allow the operation.
  Forbidden

  /// The contact or message does not exist.
  NotFound

  /// The request is malformed, names an unknown operation or has a bad
  /// argument.
  Invalid

  /// The operation is understood but not allowed now.
  Refused

  /// The daemon cannot serve the call right now.
  Unavailable

  /// A request line or payload exceeds its bound.
  TooLarge
}

/// What a client gets back for one request.
pub type Response {
  Succeeded(result: Dynamic)
  Failed(category: Category, message: String)
}

/// The wire name of a category.
///
/// ## Examples
///
/// ```gleam
/// local_api_protocol.category_name(Forbidden)
/// // -> "forbidden"
/// ```
pub fn category_name(category: Category) -> String {
  case category {
    Unauthorized -> "unauthorized"
    Forbidden -> "forbidden"
    NotFound -> "not_found"
    Invalid -> "invalid"
    Refused -> "refused"
    Unavailable -> "unavailable"
    TooLarge -> "too_large"
  }
}

/// The category with a wire name.
///
/// ## Examples
///
/// ```gleam
/// local_api_protocol.category_from_name("not_found")
/// // -> Ok(NotFound)
/// ```
pub fn category_from_name(name: String) -> Result(Category, Nil) {
  case name {
    "unauthorized" -> Ok(Unauthorized)
    "forbidden" -> Ok(Forbidden)
    "not_found" -> Ok(NotFound)
    "invalid" -> Ok(Invalid)
    "refused" -> Ok(Refused)
    "unavailable" -> Ok(Unavailable)
    "too_large" -> Ok(TooLarge)
    _ -> Error(Nil)
  }
}

/// The JSON of a successful response.
///
/// ## Examples
///
/// ```gleam
/// local_api_protocol.success_json(json.object([]))
/// // -> "{\"ok\":true,\"result\":{}}"
/// ```
pub fn success_json(result: Json) -> String {
  json.object([#("ok", json.bool(True)), #("result", result)])
  |> json.to_string
}

/// The JSON of a failed response.
///
/// ## Examples
///
/// ```gleam
/// local_api_protocol.failure_json(Invalid, "bad op")
/// // -> "{\"ok\":false,\"error\":{\"category\":\"invalid\",\"message\":\"bad op\"}}"
/// ```
pub fn failure_json(category: Category, message: String) -> String {
  json.object([
    #("ok", json.bool(False)),
    #(
      "error",
      json.object([
        #("category", json.string(category_name(category))),
        #("message", json.string(message)),
      ]),
    ),
  ])
  |> json.to_string
}

/// The JSON of a request line, without its newline.
///
/// ## Examples
///
/// ```gleam
/// local_api_protocol.request_json("AAAA", "health", json.object([]))
/// ```
pub fn request_json(credential: String, op: String, args: Json) -> String {
  json.object([
    #("v", json.int(version)),
    #("credential", json.string(credential)),
    #("op", json.string(op)),
    #("args", args),
  ])
  |> json.to_string
}

/// Reads a response line.
///
/// ## Examples
///
/// ```gleam
/// local_api_protocol.parse_response("{\"ok\":true,\"result\":{}}")
/// // -> Ok(Succeeded(_))
/// ```
pub fn parse_response(line: String) -> Result(Response, String) {
  json.parse(line, response_decoder())
  |> result.replace_error("the daemon sent a malformed response")
}

/// A response is a success carrying a result, or a failure carrying a known
/// category.
fn response_decoder() -> decode.Decoder(Response) {
  use ok <- decode.field("ok", decode.bool)

  // A success carries a result, and a failure carries a category and a message.
  case ok {
    True -> {
      use result <- decode.field("result", decode.dynamic)
      decode.success(Succeeded(result:))
    }

    False -> {
      use name <- decode.subfield(["error", "category"], decode.string)
      use message <- decode.subfield(["error", "message"], decode.string)

      // A category this client does not know makes the response malformed.
      case category_from_name(name) {
        Ok(category) -> decode.success(Failed(category:, message:))
        Error(Nil) -> decode.failure(Failed(Invalid, ""), "Category")
      }
    }
  }
}
