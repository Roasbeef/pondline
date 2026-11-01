//// Where to send to a peer, and our own queue's full credentials.
////
//// A relationship is two directional queues (spec §2.2): the peer's, which
//// we append to, and ours, which we read. The two halves carry different
//// authority and must not be confused, so they are different types. A
//// `Route` holds only what a sender needs (the mailbox, the queue and the
//// append capability) and is what travels inside an invitation and a
//// `Hello`. An `Inbox` holds everything about a queue we own, including the
//// read and admin capabilities that never leave this daemon; `route` is the
//// one-way projection from the second to the first, so the credentials we
//// keep cannot be handed out by accident.
////
//// Both have a TLV codec. A `Route` is public, bearer authority to append;
//// an `Inbox` is secret, and its encoder says so. Endpoints are encoded as
//// a discriminated record, so a loopback endpoint (tests and the offline
//// demo) and an onion endpoint are distinct on the wire, and a decoder that
//// reads an onion host re-runs `endpoint.parse_onion`, so no hostname that
//// is not a v3 onion address is ever built.

import core/capability.{type Admin, type Append, type Capability, type Read}
import core/crypto/suite.{type Suite}
import core/endpoint.{type Endpoint, Loopback, Onion}
import core/field
import core/id.{type Id, type Queue}
import core/limits
import core/tlv
import gleam/option.{None, Some}
import gleam/result

/// Where to append to a peer's queue: everything a sender needs and
/// nothing more.
pub type Route {
  Route(
    /// The mailbox that hosts the queue.
    endpoint: Endpoint,
    /// The queue within that mailbox.
    queue: Id(Queue),
    /// The bearer capability to append to it.
    append: Capability(Append),
  )
}

/// Our own queue: the route we hand out plus the capabilities we keep.
pub type Inbox {
  Inbox(
    /// The mailbox that hosts the queue.
    endpoint: Endpoint,
    /// The queue within that mailbox.
    queue: Id(Queue),
    /// Fetch and acknowledge. Never leaves the daemon.
    read: Capability(Read),
    /// Append. This is the capability a `Route` carries to the peer.
    append: Capability(Append),
    /// Delete or reconfigure. Never leaves the daemon.
    admin: Capability(Admin),
  )
}

/// Which endpoint variant a record names.
type EndpointKind {
  OnionKind
  LoopbackKind
}

/// A new inbox at `endpoint` with a fresh queue identifier and three fresh
/// capabilities from the injected randomness source; `Error(Nil)` when the
/// source misbehaves.
///
/// ## Examples
///
/// ```gleam
/// route.new_inbox(suite, endpoint)
/// // -> Ok(Inbox(..))
/// ```
pub fn new_inbox(suite: Suite, endpoint: Endpoint) -> Result(Inbox, Nil) {
  use queue <- result.try(field.fresh_id(suite))
  use read <- result.try(field.fresh_capability(suite))
  use append <- result.try(field.fresh_capability(suite))
  use admin <- result.try(field.fresh_capability(suite))

  Ok(Inbox(endpoint:, queue:, read:, append:, admin:))
}

/// The route a peer needs to append to this inbox.
///
/// ## Examples
///
/// ```gleam
/// route.route(inbox).queue == inbox.queue
/// // -> True
/// ```
pub fn route(inbox: Inbox) -> Route {
  Route(endpoint: inbox.endpoint, queue: inbox.queue, append: inbox.append)
}

/// The canonical TLV encoding of a route. The append capability is inside,
/// so the bytes are authority to write to the peer's queue.
///
/// ## Examples
///
/// ```gleam
/// route.decode(route.encode(route)) == Ok(route)
/// // -> True
/// ```
pub fn encode(route: Route) -> BitArray {
  tlv.new()
  |> tlv.put(0, encode_endpoint(route.endpoint))
  |> tlv.put(2, route.queue |> id.to_bytes)
  |> tlv.put(4, capability.expose(route.append))
  |> tlv.encode
}

/// Decodes a route. Total: any other input is a `TlvError`.
///
/// ## Examples
///
/// ```gleam
/// route.decode(<<>>)
/// // -> Error(tlv.MissingRequired(0))
/// ```
pub fn decode(bytes: BitArray) -> Result(Route, tlv.TlvError) {
  tlv.decode(bytes, max_bytes: max_route_bytes, with: decoder())
}

/// The decoder for a route, for a parent record that nests one.
///
/// ## Examples
///
/// ```gleam
/// tlv.nested(route.decoder())
/// ```
pub fn decoder() -> tlv.Decoder(Route) {
  use endpoint <- tlv.required(0, tlv.nested(endpoint_decoder()))
  use queue <- tlv.required(2, field.id())
  use append <- tlv.required(4, field.capability())

  tlv.success(Route(endpoint:, queue:, append:))
}

/// The largest encoded route: an onion hostname, a port, a queue identifier
/// and a capability, with TLV framing, rounded up. Far above any honest
/// route and far below anything worth allocating for.
pub const max_route_bytes = limits.max_route_bytes

/// The TLV encoding of an inbox, which holds the read and admin
/// capabilities. The caller keeps the bytes inside a `Secret` and never
/// renders them.
///
/// ## Examples
///
/// ```gleam
/// route.decode_inbox(route.encode_inbox(inbox)) == Ok(inbox)
/// // -> True
/// ```
pub fn encode_inbox(inbox: Inbox) -> BitArray {
  tlv.new()
  |> tlv.put(0, encode_endpoint(inbox.endpoint))
  |> tlv.put(2, inbox.queue |> id.to_bytes)
  |> tlv.put(4, capability.expose(inbox.read))
  |> tlv.put(6, capability.expose(inbox.append))
  |> tlv.put(8, capability.expose(inbox.admin))
  |> tlv.encode
}

/// Decodes an inbox. Total.
///
/// ## Examples
///
/// ```gleam
/// route.decode_inbox(<<>>)
/// // -> Error(tlv.MissingRequired(0))
/// ```
pub fn decode_inbox(bytes: BitArray) -> Result(Inbox, tlv.TlvError) {
  tlv.decode(bytes, max_bytes: max_route_bytes, with: inbox_decoder())
}

/// The decoder for an inbox, for a parent record that nests one.
///
/// ## Examples
///
/// ```gleam
/// tlv.nested(route.inbox_decoder())
/// ```
pub fn inbox_decoder() -> tlv.Decoder(Inbox) {
  use endpoint <- tlv.required(0, tlv.nested(endpoint_decoder()))
  use queue <- tlv.required(2, field.id())
  use read <- tlv.required(4, field.capability())
  use append <- tlv.required(6, field.capability())
  use admin <- tlv.required(8, field.capability())

  tlv.success(Inbox(endpoint:, queue:, read:, append:, admin:))
}

/// An endpoint as a record: tag 0 names the variant, tag 2 is the onion
/// hostname when there is one, tag 4 is the port.
fn encode_endpoint(endpoint: Endpoint) -> BitArray {
  case endpoint {
    Onion(address:, port:) ->
      tlv.new()
      |> tlv.put(0, tlv.encode_u8(0))
      |> tlv.put(2, tlv.encode_text(endpoint.onion_host(address)))
      |> tlv.put(4, tlv.encode_u16(endpoint.port_number(port)))
      |> tlv.encode

    Loopback(port:) ->
      tlv.new()
      |> tlv.put(0, tlv.encode_u8(1))
      |> tlv.put(4, tlv.encode_u16(endpoint.port_number(port)))
      |> tlv.encode
  }
}

/// Reads an endpoint record. The hostname must be present exactly when the
/// variant is onion, so an onion record without a host and a loopback
/// record with one are both refused rather than interpreted.
fn endpoint_decoder() -> tlv.Decoder(Endpoint) {
  use kind <- tlv.required(0, endpoint_kind())
  use host <- tlv.optional(2, tlv.text)
  use port <- tlv.required(4, port_field())

  // The variant and the hostname must agree; every other pairing is refused.
  case kind, host {
    OnionKind, Some(host) ->
      case endpoint.parse_onion(host) {
        Ok(address) -> tlv.success(Onion(address:, port:))
        Error(_) -> tlv.fail(tlv.InvalidField(2))
      }

    LoopbackKind, None -> tlv.success(Loopback(port:))

    OnionKind, None -> tlv.fail(tlv.MissingRequired(2))

    LoopbackKind, Some(_) -> tlv.fail(tlv.InvalidField(2))
  }
}

/// The variant record's discriminator.
fn endpoint_kind() -> tlv.Field(EndpointKind) {
  tlv.try_map(tlv.u8, fn(number) {
    case number {
      0 -> Ok(OnionKind)
      1 -> Ok(LoopbackKind)
      _ -> Error(Nil)
    }
  })
}

fn port_field() -> tlv.Field(endpoint.Port) {
  tlv.try_map(tlv.u16, fn(number) {
    result.replace_error(endpoint.port(number), Nil)
  })
}
