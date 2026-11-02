//// The one place the local API meets the daemon runtime.
////
//// `local_api` serves a `Backend`; this module builds one from a running
//// daemon. The local API keeps its own mirror of the runtime's types
//// (`daemon/local_api_types`) so that its wire format is pinned in one
//// module and does not move when the runtime's internals do; this module is
//// the translation between the two, and the only file that changes when the
//// runtime's API changes shape.
////
//// `start_node` also turns the CLI's parsed options into a runtime
//// `Config`: the mailbox address becomes an `Endpoint`, and the carrier
//// choice becomes a `CarrierPolicy`. A loopback mailbox is admitted only
//// when the operator asked for the loopback carrier, which is the one place
//// that choice is made.

import core/endpoint.{type Endpoint, Loopback, Onion, TorOnly, TorOrLoopback}
import core/secret
import daemon/api
import daemon/build
import daemon/cli.{type DaemonOptions}
import daemon/config
import daemon/local_api_types.{
  type ApiError, type Backend, type Event, Backend, Health, Unavailable,
}
import daemon/node
import daemon/status
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string

/// A backend that refuses every call as `Unavailable`. It answers `health`
/// with a state saying why. Tests of the local API use it as a stand-in.
///
/// ## Examples
///
/// ```gleam
/// let backend = local_api_backend.unavailable()
/// backend.contacts()
/// // -> Error(Unavailable)
/// ```
pub fn unavailable() -> Backend {
  Backend(
    invite: fn(_, _, _) { Error(Unavailable) },
    invite_ticket: fn(_, _, _) { Error(Unavailable) },
    accept: fn(_, _) { Error(Unavailable) },
    accept_ticket: fn(_, _) { Error(Unavailable) },
    contacts: fn() { Error(Unavailable) },
    approve: fn(_) { Error(Unavailable) },
    decline: fn(_) { Error(Unavailable) },
    close: fn(_) { Error(Unavailable) },
    raise_budget: fn(_, _) { Error(Unavailable) },
    send: fn(_, _, _, _, _) { Error(Unavailable) },
    receive: fn(_, _) { Error(Unavailable) },
    acknowledge: fn(_) { Error(Unavailable) },
    status: fn(_) { Error(Unavailable) },
    audit: fn(_, _) { Error(Unavailable) },
    incidents: fn(_) { Error(Unavailable) },
    subscribe: fn(_) { Nil },
    health: fn() { Health([#("runtime", "not linked")]) },
  )
}

/// Starts the daemon runtime for `options` and returns the backend that
/// serves it, or a one-line reason it could not start.
///
/// ## Examples
///
/// ```gleam
/// local_api_backend.start_node(options)
/// // -> Ok(Backend(..))
/// ```
pub fn start_node(options: DaemonOptions) -> Result(Backend, String) {
  use mailbox <- result.try(parse_mailbox(options.mailbox))

  // The carrier option decides both the policy and whether a sidecar runs:
  // Tor admits only onion mailboxes and needs the sidecar binary, while
  // loopback is the explicit operator choice for tests and the offline demo.
  let #(policy, tor) = case options.carrier {
    cli.Tor -> #(TorOnly, options.tor_bin)
    cli.Loopback -> #(TorOrLoopback, None)
  }

  let base =
    config.new(
      options.state_dir,
      config.Mailbox(
        endpoint: mailbox,
        provisioning_file: options.provision_file,
      ),
      policy,
    )

  node.start(config.Config(..base, tor:))
  |> result.map(from_daemon)
  |> result.map_error(describe_start_error)
}

/// The backend over a running daemon: every field calls the runtime and
/// translates its answer into the local API's types.
///
/// ## Examples
///
/// ```gleam
/// let backend = local_api_backend.from_daemon(daemon)
/// backend.contacts()
/// // -> Ok([])
/// ```
pub fn from_daemon(daemon: api.Daemon) -> Backend {
  Backend(
    invite: fn(description, approval, budget) {
      api.invite(daemon, description, approval, budget) |> map_error
    },
    invite_ticket: fn(description, approval, budget) {
      api.invite_ticket(daemon, description, approval, budget)
      |> result.map(fn(issued) { #(secret.expose(issued.file), issued.ticket) })
      |> map_error
    },
    accept: fn(file, description) {
      api.accept(daemon, file, description) |> map_error
    },
    accept_ticket: fn(text, description) {
      api.accept_ticket(daemon, text, description) |> map_error
    },
    contacts: fn() {
      api.contacts(daemon)
      |> result.map(list.map(_, contact_view))
      |> map_error
    },
    approve: fn(contact) { api.approve(daemon, contact) |> map_error },
    decline: fn(contact) { api.decline(daemon, contact) |> map_error },
    close: fn(contact) { api.close(daemon, contact) |> map_error },
    raise_budget: fn(contact, by) {
      api.raise_budget(daemon, contact, by) |> map_error
    },
    send: fn(contact, key, content_type, payload, in_reply_to) {
      // A key makes the send safe to retry (ADR-011).
      case key {
        None -> api.send(daemon, contact, content_type, payload, in_reply_to)
        Some(key) ->
          api.send_with_key(
            daemon,
            contact,
            key,
            content_type,
            payload,
            in_reply_to,
          )
      }
      |> map_error
    },
    receive: fn(contact, max) {
      api.receive(daemon, contact, max)
      |> result.map(list.map(_, delivery))
      |> map_error
    },
    acknowledge: fn(message) { api.acknowledge(daemon, message) |> map_error },
    status: fn(message) {
      api.status(daemon, message)
      |> result.map(message_state)
      |> map_error
    },
    audit: fn(contact, limit) {
      api.audit(daemon, contact, limit)
      |> result.map(list.map(_, audit_entry))
      |> map_error
    },
    incidents: fn(limit) {
      api.incidents(daemon, limit)
      |> result.map(list.map(_, incident))
      |> map_error
    },
    subscribe: fn(subscriber) { subscribe(daemon, subscriber) },
    health: fn() { health(api.health(daemon)) },
  )
}

/// Parses the `--mailbox` option: `127.0.0.1:PORT` or `localhost:PORT` is
/// a loopback endpoint, and anything else must be a v3 onion address with a
/// port. Whether a loopback endpoint is admitted is the runtime's policy
/// check, not this parser's.
fn parse_mailbox(text: String) -> Result(Endpoint, String) {
  let invalid = "--mailbox must be ONION:PORT or 127.0.0.1:PORT"

  use #(host, port_text) <- result.try(
    string.split_once(text, ":") |> result.replace_error(invalid),
  )
  use number <- result.try(
    int.parse(port_text) |> result.replace_error(invalid),
  )
  use port <- result.try(endpoint.port(number) |> result.replace_error(invalid))

  // The host names the carrier: loopback for the two local spellings, an
  // onion address for everything else.
  case host {
    "127.0.0.1" | "localhost" -> Ok(Loopback(port:))
    _ ->
      endpoint.parse_onion(host)
      |> result.map(fn(address) { Onion(address:, port:) })
      |> result.replace_error(invalid)
  }
}

/// A runtime start failure as one line for the operator.
fn describe_start_error(error: node.StartError) -> String {
  case error {
    node.StateDirUnusable -> "the state directory cannot be used"
    node.StateDirLocked -> "another daemon holds this state directory"
    node.MailboxNotPermitted ->
      "the mailbox endpoint is not permitted by the carrier policy"
    node.BadProvisioning -> "the provisioning file is missing or malformed"
    node.StartupFailed -> "the daemon failed to start"
  }
}

fn map_error(outcome: Result(a, api.ApiError)) -> Result(a, ApiError) {
  result.map_error(outcome, api_error)
}

/// A runtime error as the local API's error, constructor for constructor.
fn api_error(error: api.ApiError) -> ApiError {
  case error {
    api.NotFound -> local_api_types.NotFound
    api.InvalidInvitation(reason) -> local_api_types.InvalidInvitation(reason)
    api.Refused(reason) -> local_api_types.Refused(reason)
    api.Unavailable -> local_api_types.Unavailable
  }
}

/// A contact as the local API reports it.
fn contact_view(view: api.ContactView) -> local_api_types.ContactView {
  local_api_types.ContactView(
    contact: view.contact,
    phase: phase_name(view.phase),
    description: view.description,
    peer_fingerprint: view.peer_fingerprint,
    budget_granted: view.budget_granted,
    budget_used: view.budget_used,
    held: view.held,
  )
}

/// A runtime phase name as the local API's, which the wire format pins.
fn phase_name(phase: api.PhaseName) -> local_api_types.PhaseName {
  case phase {
    api.Joining -> local_api_types.Joining
    api.AwaitingAccept -> local_api_types.AwaitingAccept
    api.PendingApproval -> local_api_types.PendingApproval
    api.Active -> local_api_types.Active
    api.Closed -> local_api_types.Closed
  }
}

/// A ready delivery as the local API reports it.
fn delivery(item: api.Delivery) -> local_api_types.Delivery {
  local_api_types.Delivery(
    message: item.message,
    contact: item.contact,
    content_type: item.content_type,
    payload: item.payload,
    in_reply_to: item.in_reply_to,
    received_at: item.received_at,
  )
}

/// A sent message's spec §7.2 state as the local API reports it.
fn message_state(state: api.MessageState) -> local_api_types.MessageState {
  case state {
    api.LocallyQueued -> local_api_types.LocallyQueued
    api.StoredByMailbox -> local_api_types.StoredByMailbox
    api.ReceivedByPeer -> local_api_types.ReceivedByPeer
    api.Failed -> local_api_types.Failed
  }
}

/// An audit row as the local API reports it.
fn audit_entry(entry: api.AuditEntry) -> local_api_types.AuditEntry {
  local_api_types.AuditEntry(
    contact: entry.contact,
    direction: case entry.direction {
      api.Inbound -> local_api_types.Inbound
      api.Outbound -> local_api_types.Outbound
    },
    message: entry.message,
    content_type: entry.content_type,
    payload: entry.payload,
    at: entry.at,
  )
}

/// An incident as the local API reports it.
fn incident(found: api.Incident) -> local_api_types.Incident {
  local_api_types.Incident(
    kind: case found.kind {
      api.RepeatedMessageId -> local_api_types.RepeatedMessageId
      api.QuarantinedEnvelope -> local_api_types.QuarantinedEnvelope
    },
    contact: found.contact,
    message: found.message,
    attempts: found.attempts,
    at: found.at,
  )
}

/// Subscribes `subscriber` to the runtime's events through a forwarding
/// process that translates each one. The forwarder is linked to the caller,
/// so it lives exactly as long as the subscription's owner.
fn subscribe(daemon: api.Daemon, subscriber: Subject(Event)) -> Nil {
  let ready = process.new_subject()

  let _forwarder =
    process.spawn(fn() {
      let inbox = process.new_subject()
      api.subscribe(daemon, inbox)
      process.send(ready, Nil)
      forward(inbox, subscriber)
    })

  // Wait for the forwarder to register, so an event that fires right after
  // subscribe returns is not lost.
  let _ = process.receive(ready, 5000)
  Nil
}

/// Forwards runtime events to a local API subscriber, forever.
fn forward(inbox: Subject(api.Event), subscriber: Subject(Event)) -> Nil {
  let event = process.receive_forever(inbox)

  // Each runtime event has exactly one local counterpart.
  let translated = case event {
    api.MessagesReady(contact) -> local_api_types.MessagesReady(contact)
    api.ContactChanged(contact) -> local_api_types.ContactChanged(contact)
  }

  process.send(subscriber, translated)
  forward(inbox, subscriber)
}

/// The runtime's health as the local API's flat string map, with the
/// build's identity first, so an operator can tell which build answered.
fn health(report: api.Health) -> local_api_types.Health {
  let identity = build.current()

  Health([
    #("version", identity.version),
    #("commit", identity.commit),
    #("carrier", case report.carrier {
      TorOnly -> "tor"
      TorOrLoopback -> "tor-or-loopback"
    }),
    #("tor", case report.tor {
      status.TorNotUsed -> "not-used"
      status.TorStarting -> "starting"
      status.TorBootstrapped -> "bootstrapped"
      status.TorUnavailable -> "unavailable"
    }),
    #("mailbox", case report.mailbox {
      status.MailboxUnknown -> "unknown"
      status.MailboxReachable -> "reachable"
      status.MailboxUnreachable -> "unreachable"
    }),
    #("outbox_pending", int.to_string(report.outbox_pending)),
    #("incidents", int.to_string(report.incidents)),
  ])
}
