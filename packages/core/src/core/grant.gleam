//// Copy-pasteable mailbox provisioning grant tokens (`plg1...`).
////
//// Onboarding an operator to a mailbox server requires two facts: where the
//// mailbox is reached (`Endpoint`) and the 32-byte `Capability(Provision)`
//// that authorizes creating queues there. Handing those out as a raw 32-byte
//// binary file plus a separate `.onion:80` string is awkward over chat. A
//// grant token packs both into one checksummed string using the same BIP-93
//// long codex32 BCH code as invitation tickets (`core/codex32`), under the
//// distinct human-readable prefix `"plg"`.
////
//// ## Text form
////
//// `plg1` followed by a format symbol, the payload regrouped into 5-bit
//// symbols with zero padding, and a fifteen-symbol codex32 checksum:
////
//// | Format | Payload | Token length |
//// |---|---|---|
//// | 0, onion | decoded onion label (35) or port (2) or provision (32) | 131 |
//// | 1, loopback | port (2) or provision (32) | 75 |
////
//// (Read "or" as concatenation.) Because `codex32.checksum` expands `"plg"`,
//// an invitation ticket (`pl1...`) and a grant token (`plg1...`) cannot
//// satisfy each other's prefix or checksum. The decoder is total and strict:
//// lowercase only, no whitespace, checksum verified before reading the
//// payload, exact byte lengths and zero padding bits.

import core/capability.{type Capability, type Provision}
import core/codex32
import core/endpoint.{type Endpoint, Loopback, Onion}
import core/limits
import core/secret.{type Secret}
import gleam/bit_array
import gleam/bool
import gleam/list
import gleam/result
import gleam/string

/// The human-readable part of every mailbox provisioning grant token.
pub const prefix = "plg"

const onion_format = 0

const loopback_format = 1

const onion_payload_bytes = 69

const loopback_payload_bytes = 34

/// A mailbox endpoint bundled with a provisioning capability for that mailbox.
/// Opaque and backed by `Capability(Provision)` (`Secret`), so inspecting a
/// token never prints its capability bytes.
pub opaque type GrantToken {
  GrantToken(endpoint: Endpoint, provision: Capability(Provision))
}

/// Why text is not a valid grant token. None of the variants carries input
/// text, so a misplaced secret never echoes into an error or log.
pub type GrantError {
  /// Not `plg1` and bech32 characters, or longer than
  /// `limits.max_grant_token_bytes`.
  NotAGrant

  /// The codex32 checksum failed: at least one character was mistyped.
  BadChecksum

  /// The leading format symbol names an unknown version.
  UnknownFormat

  /// The payload has the wrong length, non-zero padding, or an invalid
  /// endpoint or capability size.
  BadPayload
}

/// Builds a grant token from a typed endpoint and provisioning capability.
///
/// ## Examples
///
/// ```gleam
/// let assert Ok(cap) = capability.from_bytes(<<1:256>>)
/// let token = grant.new(mailbox_endpoint, cap)
/// assert grant.endpoint(token) == mailbox_endpoint
/// ```
pub fn new(mailbox: Endpoint, provision: Capability(Provision)) -> GrantToken {
  GrantToken(endpoint: mailbox, provision:)
}

/// Builds a grant token from an endpoint and raw capability bytes, which must
/// be `capability.capability_bytes` (32) bytes long.
///
/// ## Examples
///
/// ```gleam
/// grant.from_parts(mailbox_endpoint, <<0:256>>)
/// // -> Ok(token)
/// ```
pub fn from_parts(
  mailbox: Endpoint,
  provision_bytes: BitArray,
) -> Result(GrantToken, Nil) {
  use provision <- result.map(capability.from_bytes(provision_bytes))
  GrantToken(endpoint: mailbox, provision:)
}

/// The mailbox endpoint carried by the token.
///
/// ## Examples
///
/// ```gleam
/// grant.endpoint(token)
/// // -> Loopback(port)
/// ```
pub fn endpoint(token: GrantToken) -> Endpoint {
  token.endpoint
}

/// The provisioning capability carried by the token.
///
/// ## Examples
///
/// ```gleam
/// grant.provision(token)
/// // -> Capability(_)
/// ```
pub fn provision(token: GrantToken) -> Capability(Provision) {
  token.provision
}

/// Encodes `token` into its `plg1...` ASCII representation wrapped in a
/// `Secret`, since possession of the string authorizes queue creation.
///
/// ## Examples
///
/// ```gleam
/// secret.expose(grant.encode(token))
/// // -> <<"plg1...":utf8>>
/// ```
pub fn encode(token: GrantToken) -> Secret {
  let cap_bytes = capability.expose(token.provision)

  // Format 0 carries the 35-byte v3 onion label; format 1 carries loopback.
  let #(format, payload) = case token.endpoint {
    Onion(address:, port:) -> #(onion_format, <<
      endpoint.onion_bytes(address):bits,
      endpoint.port_number(port):size(16),
      cap_bytes:bits,
    >>)

    Loopback(port:) -> #(loopback_format, <<
      endpoint.port_number(port):size(16),
      cap_bytes:bits,
    >>)
  }

  let data = [format, ..codex32.bytes_to_symbols(payload)]
  let symbols = codex32.from_symbols(data)
  let checksum = codex32.from_symbols(codex32.checksum(prefix, data))

  secret.new(<<prefix:utf8, "1":utf8, symbols:utf8, checksum:utf8>>)
}

/// Decodes a `plg1...` grant token, verifying the length bound, prefix and
/// BIP-93 checksum before inspecting payload bytes.
///
/// ## Examples
///
/// ```gleam
/// grant.decode("plg1qq")
/// // -> Error(BadChecksum)
/// ```
pub fn decode(text: String) -> Result(GrantToken, GrantError) {
  use <- bool.guard(
    string.byte_size(text) > limits.max_grant_token_bytes,
    Error(NotAGrant),
  )
  use body <- result.try(after_prefix(text))
  use symbols <- result.try(
    codex32.to_symbols(body) |> result.replace_error(NotAGrant),
  )
  use <- bool.guard(!codex32.verify(prefix, symbols), Error(BadChecksum))

  // Strip the verified 15-symbol checksum; the leading data symbol selects
  // the endpoint layout.
  let data = list.take(symbols, list.length(symbols) - codex32.checksum_symbols)

  // Dispatch on the leading format symbol before reading the payload bytes.
  case data {
    [format, ..payload] if format == onion_format -> read_onion(payload)
    [format, ..payload] if format == loopback_format -> read_loopback(payload)
    [_, ..] -> Error(UnknownFormat)
    [] -> Error(BadPayload)
  }
}

/// Reads an onion grant payload: 35-byte onion label, 16-bit port, 32-byte capability.
fn read_onion(payload: List(Int)) -> Result(GrantToken, GrantError) {
  use bytes <- result.try(payload_bytes(payload, onion_payload_bytes))
  let label_size = endpoint.onion_address_bytes
  let cap_size = capability.capability_bytes

  // Length is already pinned to 69 bytes; validate the onion label and port.
  case bytes {
    <<
      label:bytes-size(label_size),
      number:size(16),
      cap_bytes:bytes-size(cap_size),
    >> -> {
      use address <- result.try(
        endpoint.onion_from_bytes(label) |> result.replace_error(BadPayload),
      )
      use port <- result.try(
        endpoint.port(number) |> result.replace_error(BadPayload),
      )
      use provision <- result.try(
        capability.from_bytes(cap_bytes) |> result.replace_error(BadPayload),
      )

      Ok(GrantToken(endpoint: Onion(address:, port:), provision:))
    }

    _ -> Error(BadPayload)
  }
}

/// Reads a loopback grant payload: 16-bit port, 32-byte capability.
fn read_loopback(payload: List(Int)) -> Result(GrantToken, GrantError) {
  use bytes <- result.try(payload_bytes(payload, loopback_payload_bytes))
  let cap_size = capability.capability_bytes

  // Length is already pinned to 34 bytes; only port range can fail.
  case bytes {
    <<number:size(16), cap_bytes:bytes-size(cap_size)>> -> {
      use port <- result.try(
        endpoint.port(number) |> result.replace_error(BadPayload),
      )
      use provision <- result.try(
        capability.from_bytes(cap_bytes) |> result.replace_error(BadPayload),
      )

      Ok(GrantToken(endpoint: Loopback(port:), provision:))
    }

    _ -> Error(BadPayload)
  }
}

/// Converts 5-bit symbols back to exact `size` bytes with zero padding.
fn payload_bytes(
  payload: List(Int),
  size: Int,
) -> Result(BitArray, GrantError) {
  use bytes <- result.try(
    codex32.symbols_to_bytes(payload) |> result.replace_error(BadPayload),
  )

  // Reject payloads that regroup to any byte count other than the format's.
  case bit_array.byte_size(bytes) == size {
    True -> Ok(bytes)
    False -> Error(BadPayload)
  }
}

/// Strips the mandatory `"plg1"` prefix.
fn after_prefix(text: String) -> Result(String, GrantError) {
  case text {
    "plg1" <> body -> Ok(body)
    _ -> Error(NotAGrant)
  }
}
