//// A fake backend and a live local API server for the tests.
////
//// The fake records every call it receives, so a test can assert both what
//// came back over the socket and what reached the backend (a forbidden call
//// must not reach it). It also holds an inbox and a subscriber list, which
//// is enough to drive the wake path of `receive`.

import core/id.{type Contact, type Id, type Message}
import core/secret
import core/time.{Instant}
import daemon/credential
import daemon/internal/ffi_local_system
import daemon/local_api
import daemon/local_api_types.{
  type Backend, type Delivery, type Event, Backend, Delivery, Health,
}
import gleam/bit_array
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{None, Some}
import gleam/otp/actor
import gleam/result
import gleam/string
import primitives
import simplifile

/// The fake's mailbox.
pub type Fake =
  Subject(FakeMessage)

/// What the fake's actor handles.
pub type FakeMessage {
  Record(call: String)
  Calls(reply: Subject(List(String)))
  Push(delivery: Delivery)
  Take(max: Int, reply: Subject(List(Delivery)))
  Subscribe(subscriber: Subject(Event))
  Announce(event: Event)
}

type FakeState {
  FakeState(
    calls: List(String),
    inbox: List(Delivery),
    subscribers: List(Subject(Event)),
  )
}

/// A running server and what a test needs to talk to it.
pub type Fixture {
  Fixture(
    dir: String,
    socket: String,
    operator: BitArray,
    agent: BitArray,
    fake: Fake,
  )
}

/// A fixed contact id.
pub fn contact() -> Id(Contact) {
  let assert Ok(identifier) = id.from_bytes(<<1:128>>)
  identifier
}

/// A fixed message id.
pub fn message() -> Id(Message) {
  let assert Ok(identifier) = id.from_bytes(<<2:128>>)
  identifier
}

/// A delivery with the given payload.
pub fn delivery(payload: BitArray) -> Delivery {
  Delivery(
    message: message(),
    contact: contact(),
    content_type: "text/plain",
    payload: secret.new(payload),
    in_reply_to: None,
    received_at: Instant(1_700_000_000),
  )
}

/// A scratch directory short enough for a Unix socket path, which the
/// operating system limits to about a hundred bytes.
pub fn scratch_dir() -> String {
  let tmp = ffi_local_system.getenv("TMPDIR") |> result.unwrap("/tmp")
  let base = case string.ends_with(tmp, "/") {
    True -> string.drop_end(tmp, 1)
    False -> tmp
  }
  let suffix = bit_array.base16_encode(primitives.random_bytes(5))

  base <> "/rw-" <> string.lowercase(suffix)
}

/// Starts a fake and a server over it, runs `body`, and cleans up.
pub fn with_server(body: fn(Fixture) -> Nil) -> Nil {
  with_backend(fn(fake) { backend(fake) }, body)
}

/// Like `with_server`, with the backend derived from the fake.
pub fn with_backend(
  make: fn(Fake) -> Backend,
  body: fn(Fixture) -> Nil,
) -> Nil {
  let dir = scratch_dir()
  let assert Ok(credentials) = credential.ensure(dir)
  let assert Ok(fake) = start_fake()

  let socket = dir <> "/api.sock"
  let assert Ok(server) = local_api.start(make(fake), credentials, socket)

  let assert Ok(operator) = simplifile.read_bits(dir <> "/operator.cred")
  let assert Ok(agent) = simplifile.read_bits(dir <> "/agent.cred")
  body(Fixture(dir:, socket:, operator:, agent:, fake:))

  local_api.stop(server)
  let _ = simplifile.delete(dir)
  Nil
}

fn start_fake() -> Result(Fake, actor.StartError) {
  actor.new(FakeState([], [], []))
  |> actor.on_message(fake_message)
  |> actor.start
  |> result.map(fn(started) { started.data })
}

fn fake_message(
  state: FakeState,
  message: FakeMessage,
) -> actor.Next(FakeState, FakeMessage) {
  case message {
    Record(call:) ->
      actor.continue(FakeState(..state, calls: [call, ..state.calls]))

    Calls(reply:) -> {
      process.send(reply, list.reverse(state.calls))
      actor.continue(state)
    }

    Push(delivery:) ->
      actor.continue(
        FakeState(..state, inbox: list.append(state.inbox, [delivery])),
      )

    Take(max:, reply:) -> {
      process.send(reply, list.take(state.inbox, max))
      actor.continue(FakeState(..state, inbox: list.drop(state.inbox, max)))
    }

    Subscribe(subscriber:) ->
      actor.continue(
        FakeState(..state, subscribers: [subscriber, ..state.subscribers]),
      )

    Announce(event:) -> {
      list.each(state.subscribers, fn(subscriber) {
        process.send(subscriber, event)
      })
      actor.continue(state)
    }
  }
}

/// The calls the backend has received, oldest first.
pub fn calls(fake: Fake) -> List(String) {
  actor.call(fake, 1000, Calls)
}

/// Puts a delivery in the inbox and announces `MessagesReady`.
pub fn deliver(fake: Fake, delivery: Delivery) -> Nil {
  actor.send(fake, Push(delivery))
  actor.send(fake, Announce(local_api_types.MessagesReady(delivery.contact)))
}

/// A backend that records each call and answers with fixed values.
pub fn backend(fake: Fake) -> Backend {
  let record = fn(call) { actor.send(fake, Record(call)) }

  Backend(
    invite: fn(description, approval, budget) {
      record(
        "invite "
        <> description
        <> " "
        <> string.inspect(approval)
        <> " "
        <> string.inspect(budget),
      )
      Ok(<<"INVITATION-BYTES", 255, 0>>)
    },
    accept: fn(invitation, description) {
      record(
        "accept " <> bit_array.base16_encode(invitation) <> " " <> description,
      )
      Ok(contact())
    },
    contacts: fn() {
      record("contacts")
      Ok([
        local_api_types.ContactView(
          contact: contact(),
          phase: local_api_types.Active,
          description: "bob",
          peer_fingerprint: option.Some("ab12"),
          budget_granted: 10,
          budget_used: 3,
          held: 1,
        ),
      ])
    },
    approve: fn(c) {
      record("approve " <> id.to_hex(c))
      Ok(Nil)
    },
    decline: fn(c) {
      record("decline " <> id.to_hex(c))
      Ok(Nil)
    },
    close: fn(c) {
      record("close " <> id.to_hex(c))
      Ok(Nil)
    },
    raise_budget: fn(c, by) {
      record("raise_budget " <> id.to_hex(c) <> " " <> string.inspect(by))
      Ok(Nil)
    },
    send: fn(c, content_type, payload, reply) {
      record(
        "send "
        <> id.to_hex(c)
        <> " "
        <> content_type
        <> " "
        <> bit_array.base16_encode(payload)
        <> " "
        <> string.inspect(option.map(reply, id.to_hex)),
      )
      Ok(message())
    },
    receive: fn(_contact, max) {
      record("receive " <> string.inspect(max))
      Ok(actor.call(fake, 1000, Take(max, _)))
    },
    acknowledge: fn(m) {
      record("acknowledge " <> id.to_hex(m))
      Ok(Nil)
    },
    status: fn(m) {
      record("status " <> id.to_hex(m))
      Ok(local_api_types.StoredByMailbox)
    },
    audit: fn(_contact, limit) {
      record("audit " <> string.inspect(limit))
      Ok([
        local_api_types.AuditEntry(
          contact: contact(),
          direction: local_api_types.Outbound,
          message: message(),
          content_type: "text/plain",
          payload: secret.new(<<"hello audit":utf8>>),
          at: Instant(1_700_000_001),
        ),
      ])
    },
    incidents: fn(limit) {
      record("incidents " <> string.inspect(limit))
      Ok([
        local_api_types.Incident(
          kind: local_api_types.RepeatedMessageId,
          contact: Some(contact()),
          message: Some(message()),
          attempts: None,
          at: Instant(1_700_000_002),
        ),
      ])
    },
    subscribe: fn(subscriber) { actor.send(fake, Subscribe(subscriber)) },
    health: fn() {
      record("health")
      Health([#("mailbox", "reachable")])
    },
  )
}
