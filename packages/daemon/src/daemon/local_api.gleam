//// The daemon's local API server (spec §9).
////
//// An agent adapter and the operator's CLI reach the daemon through a Unix
//// domain socket, `api.sock` in the state directory. The state directory is
//// mode 0700 and the socket 0600, so the filesystem keeps other users out,
//// and a scoped credential (`daemon/credential`) separates the agent from
//// the operator inside that boundary. The server speaks the line protocol of
//// `daemon/local_api_protocol`: one JSON request line, one JSON response
//// line.
////
//// The server serves a `Backend` (`daemon/local_api_types`), never the
//// runtime itself, so the same code runs over a fake in a test and over the
//// real daemon in production.
////
//// ## Flow
////
//// 1. `start` binds the socket, starts the wake hub and spawns the acceptor.
//// 2. `accept_loop` spawns one process per connection, so a slow or
////    crashing client cannot stall the others or the acceptor.
//// 3. `serve_connection` reads a line (refusing one over the line bound),
////    calls `handle`, writes the answer and reads again.
//// 4. `handle` checks, in order: the line parses, the version matches, the
////    credential authenticates, the operation exists, the scope permits it,
////    the arguments decode. Only then does it call the backend through
////    `execute`. That order means an agent probing an operator operation
////    learns "forbidden" and nothing about the arguments.
//// 5. A receive with a wait goes through `receive_deliveries`, which
////    registers with the hub before its first read, so a delivery announced
////    between the read and the wait is not lost, and then waits in
////    `poll_for_wake` for the hub's wake or the deadline.
////
//// ## What is a weft primitive here, and what is not
////
//// The wake hub is a `weft/actor`: a list of waiters flushed on a state
//// change, which is the shape the hand-written fan-outs were. It has one
//// state and no timers, so it is not a `weft/state_machine`, and its waiters
//// are all alike, so it is not a `weft/event_manager`. A `receive` that
//// waits is a `weft/poll` whose rest is a wait on the hub's wake instead of
//// a sleep, so the immediate first read, the read at the deadline and the
//// early exit on a failed read are the loop's rules and not copies of them
//// here.
////
//// Two processes stay plain `process.spawn_unlinked`, on purpose. The
//// acceptor blocks in `accept` on a socket, a call no message can
//// interrupt: an actor would stop answering system messages for as long as
//// it sat there, so wrapping it adds nothing, and `stop` ends it the only
//// way that works, by closing the listener. A connection process is long
//// lived and its deadline is an idle read timeout armed on the socket by
//// `recv_line` and reset by each request. A bounded `weft` run is a
//// deadline on one task's total time, and a deadline over the connection
//// would cut a client that is still using it. Per `docs/weft.md` ("When
//// not to"), a deadline that is really an idle timeout on a blocking
//// read is kept where the blocking happens.
////
//// Malformed input is answered with a category and never crashes the
//// server, never becomes an atom and never reaches the backend.

import core/id.{type Contact, type Id, type Message}
import core/limits
import core/offer.{type Approval, AutoApprove, OperatorApproves}
import core/secret
import daemon/credential.{type Credentials, type Scope, Agent, Operator}
import daemon/internal/ffi_local_socket.{type Socket}
import daemon/internal/ffi_local_system
import daemon/local_api_protocol as protocol
import daemon/local_api_types.{
  type ApiError, type AuditEntry, type Backend, type ContactView, type Delivery,
  type Event, type Health, type MessageState,
}
import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/process.{type Subject}
import gleam/int
import gleam/json.{type Json}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import weft/actor
import weft/poll

/// How long a connection may sit silent between requests, in milliseconds.
const idle_timeout_ms = 60_000

/// The most audit entries one call returns.
const max_audit = 256

/// The most payload bytes one `receive` or `audit` response carries, so the
/// response line stays under `max_line_bytes` once base64 and the envelope
/// are added. At least one entry is always returned, and the rest wait for
/// the next call.
const max_response_payload_bytes = 131_072

/// A running server. The hub is opaque to callers; `stop` ends it.
pub type Server {
  Server(path: String, listener: Socket, hub: Subject(HubMessage))
}

/// What the connection processes share.
type Context {
  Context(backend: Backend, credentials: Credentials, hub: Subject(HubMessage))
}

/// Why a request failed, as the category and text the client sees.
type Failure {
  Failure(category: protocol.Category, message: String)
}

/// The operations, before their arguments are read.
type Operation {
  InviteOp
  AcceptOp
  ContactsOp
  ApproveOp
  DeclineOp
  CloseOp
  RaiseBudgetOp
  SendOp
  ReceiveOp
  AcknowledgeOp
  StatusOp
  AuditOp
  HealthOp
}

/// An operation with its arguments.
type Call {
  Invite(description: String, approval: Approval, budget: Int)
  Accept(invitation: BitArray, description: String)
  ListContacts
  Approve(contact: Id(Contact))
  Decline(contact: Id(Contact))
  Close(contact: Id(Contact))
  RaiseBudget(contact: Id(Contact), by: Int)
  Send(
    contact: Id(Contact),
    content_type: String,
    payload: BitArray,
    in_reply_to: Option(Id(Message)),
  )
  Receive(contact: Option(Id(Contact)), max: Int, wait_ms: Int)
  Acknowledge(message: Id(Message))
  Status(message: Id(Message))
  Audit(contact: Option(Id(Contact)), limit: Int)
  Health
}

/// The request envelope, with the arguments still undecoded.
type Request {
  Request(version: Int, credential: String, op: String, args: Dynamic)
}

/// What the wake hub receives.
pub opaque type HubMessage {
  /// A waiting `receive` asks to be told when messages are ready.
  Register(waiter: Subject(Nil))

  /// A waiting `receive` is done.
  Unregister(waiter: Subject(Nil))

  /// The runtime announced an event.
  Announced(event: Event)

  /// The server stopped, so the hub ends.
  Shutdown
}

/// Binds the socket at `socket_path` and starts serving `backend`. A stale
/// socket file at that path is replaced. The caller stays the owner of the
/// socket, so the server lives as long as the caller does, or until `stop`.
///
/// ## Examples
///
/// ```gleam
/// local_api.start(backend, credentials, "/var/lib/reedwire/api.sock")
/// // -> Ok(Server(path: "/var/lib/reedwire/api.sock", ..))
/// ```
pub fn start(
  backend: Backend,
  credentials: Credentials,
  socket_path: String,
) -> Result(Server, String) {
  use hub <- result.try(
    start_hub(backend)
    |> result.replace_error("the wake hub could not start"),
  )
  use listener <- result.try(
    ffi_local_socket.listen(socket_path)
    |> result.map_error(fn(reason) {
      "could not listen on " <> socket_path <> ": " <> reason
    }),
  )

  let context = Context(backend:, credentials:, hub: hub.data)
  let _ = process.spawn_unlinked(fn() { accept_loop(context, listener) })

  Ok(Server(path: socket_path, listener:, hub: hub.data))
}

/// Stops accepting connections and closes the socket. Connections already
/// being served finish their current request.
///
/// ## Examples
///
/// ```gleam
/// local_api.stop(server)
/// // -> Nil
/// ```
pub fn stop(server: Server) -> Nil {
  ffi_local_socket.close(server.listener)
  process.send(server.hub, Shutdown)
}

/// Starts the actor that fans the runtime's events out to waiting
/// receives. The runtime keeps one subscription for the whole server, so a
/// receive never has to unsubscribe.
///
/// The subscription is made in the initialiser and not in a `continuing`
/// message: the event subject has to exist, and the runtime has to know it,
/// before `start` returns, or an event announced between the two would be
/// lost to a receive that had already registered.
fn start_hub(backend: Backend) -> actor.StartResult(Subject(HubMessage)) {
  actor.new_with_initialiser(1000, fn(self) {
    // The event subject must be created in the hub process, because only
    // its owner can receive from it.
    let events = process.new_subject()
    backend.subscribe(events)

    let selector =
      process.new_selector()
      |> process.select(self)
      |> process.select_map(events, Announced)

    actor.initialised([])
    |> actor.selecting(selector)
    |> actor.returning(self)
    |> Ok
  })
  |> actor.on_message(hub_message)
  |> actor.start
}

/// Updates the waiter list, and wakes every waiter when messages are ready.
fn hub_message(
  waiters: List(Subject(Nil)),
  message: HubMessage,
) -> actor.Next(List(Subject(Nil)), HubMessage) {
  case message {
    Register(waiter:) -> actor.continue([waiter, ..waiters])

    Unregister(waiter:) ->
      actor.continue(list.filter(waiters, fn(other) { other != waiter }))

    // A woken waiter re-reads and decides for itself whether the event was
    // for its contact, so the hub does not filter.
    Announced(local_api_types.MessagesReady(..)) -> {
      list.each(waiters, fn(waiter) { process.send(waiter, Nil) })
      actor.continue(waiters)
    }

    Announced(local_api_types.ContactChanged(..)) -> actor.continue(waiters)

    Shutdown -> actor.stop()
  }
}

/// Accepts connections until the listener closes, one process each.
fn accept_loop(context: Context, listener: Socket) -> Nil {
  case ffi_local_socket.accept(listener) {
    Ok(connection) -> {
      let _ =
        process.spawn_unlinked(fn() {
          serve_connection(context, connection, <<>>)
        })

      accept_loop(context, listener)
    }

    // A closed listener is `stop`; anything else, such as running out of
    // descriptors, is transient, so back off and keep serving.
    Error("closed") -> Nil

    Error(_) -> {
      process.sleep(100)
      accept_loop(context, listener)
    }
  }
}

/// Answers requests on one connection until the client goes away.
fn serve_connection(
  context: Context,
  connection: Socket,
  buffer: BitArray,
) -> Nil {
  let line =
    ffi_local_socket.recv_line(
      connection,
      buffer,
      protocol.max_line_bytes,
      idle_timeout_ms,
    )

  // A line is answered, an over-long one ends the connection with a reason, and anything else is a client that left.
  case line {
    Ok(#(request, rest)) -> {
      let answer = respond(context, request)

      // A client that has gone away makes the write fail, and then there is
      // nobody to answer.
      case ffi_local_socket.send(connection, <<answer:utf8, "\n">>) {
        Ok(Nil) -> serve_connection(context, connection, rest)
        Error(_) -> ffi_local_socket.close(connection)
      }
    }

    // After an over-long line the stream cannot be resynchronized, so the
    // connection ends once the client has been told why.
    Error("too_large") -> {
      let answer =
        protocol.failure_json(
          protocol.TooLarge,
          "the request line exceeds " <> int.to_string(protocol.max_line_bytes),
        )
      let _ = ffi_local_socket.send(connection, <<answer:utf8, "\n">>)
      ffi_local_socket.close(connection)
    }

    Error(_) -> ffi_local_socket.close(connection)
  }
}

/// The response line for one request line.
fn respond(context: Context, line: BitArray) -> String {
  case handle(context, line) {
    Ok(result) -> protocol.success_json(result)
    Error(Failure(category:, message:)) ->
      protocol.failure_json(category, message)
  }
}

/// Runs the checks in the order the module doc gives, then the operation.
fn handle(context: Context, line: BitArray) -> Result(Json, Failure) {
  use text <- result.try(
    bit_array.to_string(line)
    |> result.map_error(fn(_) { invalid("the request is not UTF-8 text") }),
  )
  use request <- result.try(
    json.parse(text, request_decoder())
    |> result.map_error(fn(_) { invalid("the request is malformed") }),
  )
  use Nil <- result.try(check_version(request.version))
  use scope <- result.try(authenticate(context, request.credential))
  use operation <- result.try(
    parse_operation(request.op)
    |> result.map_error(fn(_) { invalid("unknown operation") }),
  )
  use Nil <- result.try(check_scope(scope, operation))
  use call <- result.try(parse_call(operation, request.args))

  execute(context, call)
}

/// A failure in the `invalid` category.
fn invalid(message: String) -> Failure {
  Failure(protocol.Invalid, message)
}

/// The request envelope. `args` may be missing, which reads as no
/// arguments.
fn request_decoder() -> decode.Decoder(Request) {
  use version <- decode.field("v", decode.int)
  use credential <- decode.field("credential", decode.string)
  use op <- decode.field("op", decode.string)
  use args <- decode.optional_field(
    "args",
    dynamic.properties([]),
    decode.dynamic,
  )

  decode.success(Request(version:, credential:, op:, args:))
}

/// Only version 1 exists.
fn check_version(version: Int) -> Result(Nil, Failure) {
  case version == protocol.version {
    True -> Ok(Nil)
    False -> Error(invalid("unsupported protocol version"))
  }
}

/// The scope a presented credential grants. A credential that is not base64
/// is simply a wrong one, and the answer does not say which way.
fn authenticate(context: Context, presented: String) -> Result(Scope, Failure) {
  let unauthorized =
    Failure(protocol.Unauthorized, "the credential is not valid")

  use bytes <- result.try(
    bit_array.base64_decode(presented) |> result.replace_error(unauthorized),
  )

  credential.authenticate(context.credentials, bytes)
  |> result.replace_error(unauthorized)
}

/// The operation a wire name stands for.
fn parse_operation(name: String) -> Result(Operation, Nil) {
  case name {
    "invite" -> Ok(InviteOp)
    "accept" -> Ok(AcceptOp)
    "contacts" -> Ok(ContactsOp)
    "approve" -> Ok(ApproveOp)
    "decline" -> Ok(DeclineOp)
    "close" -> Ok(CloseOp)
    "raise_budget" -> Ok(RaiseBudgetOp)
    "send" -> Ok(SendOp)
    "receive" -> Ok(ReceiveOp)
    "acknowledge" -> Ok(AcknowledgeOp)
    "status" -> Ok(StatusOp)
    "audit" -> Ok(AuditOp)
    "health" -> Ok(HealthOp)
    _ -> Error(Nil)
  }
}

/// The scope an operation needs. An agent adapter may only move messages
/// and look; everything that changes who may talk to the agent, or reads the
/// plaintext trail, is the operator's (spec §9).
fn required_scope(operation: Operation) -> Scope {
  case operation {
    ContactsOp | SendOp | ReceiveOp | AcknowledgeOp | StatusOp | HealthOp ->
      Agent

    InviteOp
    | AcceptOp
    | ApproveOp
    | DeclineOp
    | CloseOp
    | RaiseBudgetOp
    | AuditOp -> Operator
  }
}

/// Refuses an operation outside the credential's scope.
fn check_scope(scope: Scope, operation: Operation) -> Result(Nil, Failure) {
  case credential.permits(scope, required: required_scope(operation)) {
    True -> Ok(Nil)

    False ->
      Error(Failure(
        protocol.Forbidden,
        "this credential's scope does not allow that operation",
      ))
  }
}

/// Reads an operation's arguments.
fn parse_call(operation: Operation, args: Dynamic) -> Result(Call, Failure) {
  // Each operation reads the arguments it needs and nothing else.
  case operation {
    InviteOp -> {
      use description <- result.try(required(args, "description", decode.string))
      use approval <- result.try(approval(args))
      use budget <- result.try(positive(args, "budget"))

      Ok(Invite(description:, approval:, budget:))
    }

    AcceptOp -> {
      use text <- result.try(required(args, "invitation", decode.string))
      use invitation <- result.try(base64(text, "invitation"))
      use description <- result.try(optional(
        args,
        "description",
        decode.string,
        "",
      ))

      Ok(Accept(invitation:, description:))
    }

    ContactsOp -> Ok(ListContacts)
    ApproveOp -> result.map(contact_id(args), Approve)
    DeclineOp -> result.map(contact_id(args), Decline)
    CloseOp -> result.map(contact_id(args), Close)

    RaiseBudgetOp -> {
      use contact <- result.try(contact_id(args))
      use by <- result.try(positive(args, "by"))

      Ok(RaiseBudget(contact:, by:))
    }

    SendOp -> parse_send(args)

    ReceiveOp -> {
      use contact <- result.try(optional_id(args, "contact"))
      use max <- result.try(optional(args, "max", decode.int, 16))
      use wait_ms <- result.try(optional(args, "wait_ms", decode.int, 0))

      Ok(Receive(
        contact:,
        max: int.clamp(max, 1, protocol.max_receive),
        wait_ms: int.clamp(wait_ms, 0, protocol.max_wait_ms),
      ))
    }

    AcknowledgeOp -> result.map(message_id(args), Acknowledge)
    StatusOp -> result.map(message_id(args), Status)

    AuditOp -> {
      use contact <- result.try(optional_id(args, "contact"))
      use limit <- result.try(optional(args, "limit", decode.int, 50))

      Ok(Audit(contact:, limit: int.clamp(limit, 1, max_audit)))
    }

    HealthOp -> Ok(Health)
  }
}

/// Reads a `send`: the payload is base64 and is bounded by the protocol's
/// body limit once decoded.
fn parse_send(args: Dynamic) -> Result(Call, Failure) {
  use contact <- result.try(contact_id(args))
  use content_type <- result.try(optional(
    args,
    "content_type",
    decode.string,
    "application/octet-stream",
  ))
  use text <- result.try(required(args, "payload", decode.string))
  use payload <- result.try(base64(text, "payload"))
  use in_reply_to <- result.try(optional_id(args, "in_reply_to"))

  // The bound is checked after decoding so that padding does not count.
  case bit_array.byte_size(payload) > limits.max_body_bytes {
    True ->
      Error(Failure(
        protocol.TooLarge,
        "the payload exceeds "
          <> int.to_string(limits.max_body_bytes)
          <> " bytes",
      ))

    False -> Ok(Send(contact:, content_type:, payload:, in_reply_to:))
  }
}

/// The `approval` argument: `"operator"` (the default) or `"auto"`.
fn approval(args: Dynamic) -> Result(Approval, Failure) {
  use name <- result.try(optional(args, "approval", decode.string, "operator"))

  // Approval is a closed set of two words, so anything else is invalid.
  case name {
    "operator" -> Ok(OperatorApproves)
    "auto" -> Ok(AutoApprove)
    _ -> Error(invalid("approval must be \"operator\" or \"auto\""))
  }
}

/// Decodes one named field, or fails with a message naming the field.
fn required(
  args: Dynamic,
  name: String,
  decoder: decode.Decoder(a),
) -> Result(a, Failure) {
  decode.run(args, decode.field(name, decoder, decode.success))
  |> result.map_error(fn(_) {
    invalid("missing or malformed argument " <> name)
  })
}

/// Decodes one named field that may be absent or null, giving `default`.
fn optional(
  args: Dynamic,
  name: String,
  decoder: decode.Decoder(a),
  default: a,
) -> Result(a, Failure) {
  decode.run(
    args,
    decode.optional_field(name, None, decode.optional(decoder), decode.success),
  )
  |> result.map(option.unwrap(_, default))
  |> result.map_error(fn(_) { invalid("malformed argument " <> name) })
}

/// An integer argument that must be at least one.
fn positive(args: Dynamic, name: String) -> Result(Int, Failure) {
  use value <- result.try(required(args, name, decode.int))

  // A count below one has nothing to do.
  case value >= 1 {
    True -> Ok(value)
    False -> Error(invalid(name <> " must be at least 1"))
  }
}

/// Decodes base64, naming the field on failure.
fn base64(text: String, name: String) -> Result(BitArray, Failure) {
  bit_array.base64_decode(text)
  |> result.map_error(fn(_) { invalid(name <> " is not valid base64") })
}

/// The required `contact` argument.
fn contact_id(args: Dynamic) -> Result(Id(Contact), Failure) {
  use text <- result.try(required(args, "contact", decode.string))
  hex_id(text, "contact")
}

/// The required `message` argument.
fn message_id(args: Dynamic) -> Result(Id(Message), Failure) {
  use text <- result.try(required(args, "message", decode.string))
  hex_id(text, "message")
}

/// An identifier argument that may be absent or null.
fn optional_id(
  args: Dynamic,
  name: String,
) -> Result(Option(Id(kind)), Failure) {
  use text <- result.try(optional(args, name, decode.string, ""))

  // The empty default stands for absent, and no identifier is empty.
  case text {
    "" -> Ok(None)
    _ -> result.map(hex_id(text, name), Some)
  }
}

/// Parses a hex identifier, naming the field on failure.
fn hex_id(text: String, name: String) -> Result(Id(kind), Failure) {
  id.from_hex(text)
  |> result.map_error(fn(_) { invalid(name <> " is not a valid identifier") })
}

/// Calls the backend and encodes what it returns.
fn execute(context: Context, call: Call) -> Result(Json, Failure) {
  let backend = context.backend

  // Each call goes to its backend function, and the result is encoded for the wire.
  case call {
    Invite(description:, approval:, budget:) ->
      backend.invite(description, approval, budget)
      |> lift
      |> result.map(fn(invitation) {
        json.object([#("invitation", json.string(encode64(invitation)))])
      })

    Accept(invitation:, description:) ->
      backend.accept(invitation, description)
      |> lift
      |> result.map(fn(contact) {
        json.object([#("contact", json.string(id.to_hex(contact)))])
      })

    ListContacts ->
      backend.contacts()
      |> lift
      |> result.map(fn(views) {
        json.object([#("contacts", json.array(views, contact_json))])
      })

    Approve(contact:) -> unit(backend.approve(contact))
    Decline(contact:) -> unit(backend.decline(contact))
    Close(contact:) -> unit(backend.close(contact))
    RaiseBudget(contact:, by:) -> unit(backend.raise_budget(contact, by))

    Send(contact:, content_type:, payload:, in_reply_to:) ->
      backend.send(contact, content_type, payload, in_reply_to)
      |> lift
      |> result.map(fn(message) {
        json.object([#("message", json.string(id.to_hex(message)))])
      })

    Receive(contact:, max:, wait_ms:) ->
      receive_deliveries(context, contact, max, wait_ms)
      |> result.map(fn(deliveries) {
        json.object([#("deliveries", json.array(deliveries, delivery_json))])
      })

    Acknowledge(message:) -> unit(backend.acknowledge(message))

    Status(message:) ->
      backend.status(message)
      |> lift
      |> result.map(fn(state) {
        json.object([#("state", json.string(state_name(state)))])
      })

    Audit(contact:, limit:) ->
      backend.audit(contact, limit)
      |> lift
      |> result.map(fn(entries) {
        let kept =
          within_budget(entries, fn(entry) { secret.byte_size(entry.payload) })
        json.object([#("entries", json.array(kept, audit_json))])
      })

    Health -> Ok(health_json(backend.health()))
  }
}

/// Maps a backend error to the failure the client sees.
fn lift(outcome: Result(a, ApiError)) -> Result(a, Failure) {
  result.map_error(outcome, fn(error) {
    case error {
      local_api_types.NotFound ->
        Failure(protocol.NotFound, "no such contact or message")

      local_api_types.InvalidInvitation(reason:) ->
        Failure(protocol.Invalid, "invalid invitation: " <> reason)

      local_api_types.Refused(reason:) -> Failure(protocol.Refused, reason)

      local_api_types.Unavailable ->
        Failure(protocol.Unavailable, "the daemon cannot serve that call now")
    }
  })
}

/// An operation with no result of its own answers with an empty object.
fn unit(outcome: Result(Nil, ApiError)) -> Result(Json, Failure) {
  outcome |> lift |> result.replace(json.object([]))
}

/// Reads deliveries, waiting up to `wait_ms` for one when none is ready.
fn receive_deliveries(
  context: Context,
  contact: Option(Id(Contact)),
  max: Int,
  wait_ms: Int,
) -> Result(List(Delivery), Failure) {
  let backend = context.backend
  let read = fn() { lift(backend.receive(contact, max)) }

  // Without a wait the receive is one read, and with one it waits for a wake.
  case wait_ms {
    0 -> read() |> result.map(bounded)

    // The waiter registers before the first read. A delivery announced
    // after the read but before the wait then still leaves a wake waiting
    // in the waiter's mailbox.
    _ -> {
      let waiter = process.new_subject()
      process.send(context.hub, Register(waiter))

      let outcome = poll_for_wake(read, waiter, wait_ms)

      process.send(context.hub, Unregister(waiter))
      result.map(outcome, bounded)
    }
  }
}

/// Reads, and while nothing is ready waits for a wake or the deadline.
///
/// This is `poll.until_on` with a clock whose rest is a receive on the
/// waiter instead of a sleep. A wake ends the rest early, the loop reads
/// again, and a read that finds nothing rests again for what remains of the
/// budget. `every` equals the whole wait, so the rest is clipped by the
/// deadline and not by the interval: an idle wait costs one receive, not a
/// probe per tick. The last read at the deadline is the loop's rule, and it
/// closes the window between the final wake and the timeout.
fn poll_for_wake(
  read: fn() -> Result(List(Delivery), Failure),
  waiter: Subject(Nil),
  wait_ms: Int,
) -> Result(List(Delivery), Failure) {
  let wake_clock =
    poll.Clock(now: ffi_local_system.monotonic_ms, sleep: fn(rest_ms) {
      // A wake and a timeout both end the rest; the next read tells them apart.
      let _ = process.receive(waiter, rest_ms)
      Nil
    })

  let waited =
    poll.until_on(
      clock: wake_clock,
      within: wait_ms,
      every: poll.Fixed(wait_ms),
      attempt: fn() {
        case read() {
          // Nothing ready means waiting, and anything else, an error included, is returned as read.
          Ok([]) -> poll.Retry
          Ok(ready) -> poll.Done(ready)
          Error(failure) -> poll.Fail(failure)
        }
      },
    )

  // A deadline that passes with nothing ready is an empty answer, not a failure.
  case waited {
    poll.Answered(ready) -> Ok(ready)
    poll.Failed(failure) -> Error(failure)
    poll.Expired -> Ok([])
  }
}

/// Keeps the response line within its bound.
fn bounded(deliveries: List(Delivery)) -> List(Delivery) {
  within_budget(deliveries, fn(delivery) { secret.byte_size(delivery.payload) })
}

/// Takes items while their payload bytes total at most the response budget,
/// always keeping the first so a single large item still gets through.
fn within_budget(items: List(a), size: fn(a) -> Int) -> List(a) {
  take_within(items, size, 0, [])
}

/// The accumulating half of `within_budget`.
fn take_within(
  items: List(a),
  size: fn(a) -> Int,
  used: Int,
  kept: List(a),
) -> List(a) {
  // An empty list ends the walk, and otherwise each item is kept until the budget is spent.
  case items {
    [] -> list.reverse(kept)

    [item, ..rest] -> {
      let total = used + size(item)

      // Past the budget with something kept, the rest waits for the next call.
      case kept != [] && total > max_response_payload_bytes {
        True -> list.reverse(kept)
        False -> take_within(rest, size, total, [item, ..kept])
      }
    }
  }
}

/// Base64 with padding.
fn encode64(bytes: BitArray) -> String {
  bit_array.base64_encode(bytes, True)
}

/// The JSON of a contact.
fn contact_json(view: ContactView) -> Json {
  json.object([
    #("contact", json.string(id.to_hex(view.contact))),
    #("phase", json.string(phase_name(view.phase))),
    #("description", json.string(view.description)),
    #("peer_fingerprint", json.nullable(view.peer_fingerprint, json.string)),
    #("budget_granted", json.int(view.budget_granted)),
    #("budget_used", json.int(view.budget_used)),
    #("held", json.int(view.held)),
  ])
}

/// The wire name of a phase.
fn phase_name(phase: local_api_types.PhaseName) -> String {
  case phase {
    local_api_types.Joining -> "joining"
    local_api_types.AwaitingAccept -> "awaiting_accept"
    local_api_types.PendingApproval -> "pending_approval"
    local_api_types.Active -> "active"
    local_api_types.Closed -> "closed"
  }
}

/// The JSON of a delivery. The payload is plaintext the agent asked for.
fn delivery_json(delivery: Delivery) -> Json {
  json.object([
    #("message", json.string(id.to_hex(delivery.message))),
    #("contact", json.string(id.to_hex(delivery.contact))),
    #("content_type", json.string(delivery.content_type)),
    #("payload", json.string(encode64(secret.expose(delivery.payload)))),
    #(
      "in_reply_to",
      json.nullable(delivery.in_reply_to, fn(reply) {
        json.string(id.to_hex(reply))
      }),
    ),
    #("received_at", json.int(delivery.received_at.unix_seconds)),
  ])
}

/// The wire name of a message state.
fn state_name(state: MessageState) -> String {
  case state {
    local_api_types.LocallyQueued -> "locally_queued"
    local_api_types.StoredByMailbox -> "stored_by_mailbox"
    local_api_types.ReceivedByPeer -> "received_by_peer"
    local_api_types.Failed -> "failed"
  }
}

/// The JSON of an audit entry. The audit log is plaintext by the owner's
/// ruling, and only the operator scope reaches it.
fn audit_json(entry: AuditEntry) -> Json {
  // The direction is a word on the wire.
  let direction = case entry.direction {
    local_api_types.Inbound -> "inbound"
    local_api_types.Outbound -> "outbound"
  }

  json.object([
    #("contact", json.string(id.to_hex(entry.contact))),
    #("direction", json.string(direction)),
    #("message", json.string(id.to_hex(entry.message))),
    #("content_type", json.string(entry.content_type)),
    #("payload", json.string(encode64(secret.expose(entry.payload)))),
    #("at", json.int(entry.at.unix_seconds)),
  ])
}

/// The JSON of the health summary: its fields as strings.
fn health_json(health: Health) -> Json {
  json.object(
    list.map(health.fields, fn(field) { #(field.0, json.string(field.1)) }),
  )
}
