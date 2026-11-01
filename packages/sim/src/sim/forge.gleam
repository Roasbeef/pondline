//// A byzantine authenticated peer: a daemon that sends, under its real
//// session, what an honest daemon never would.
////
//// An honest daemon cannot be made to repeat a message id: its own store
//// refuses a second `sent_messages` row for it. So the forger plays a
//// modified daemon. It reads the forging party's relationship from that
//// party's store, seals the message itself with the core's own codecs and
//// ratchet (`message.encode`, `ratchet.encrypt`, `frame.seal`), commits the
//// advanced session back through `store.commit` exactly as the engine would
//// (so the party's next honest message follows the forged one in the
//// ratchet instead of colliding with it), and returns the `Append` the
//// runner then hands to the real mailbox. Nothing about the receiving
//// daemon is touched: it fetches and processes the forgery like any other
//// envelope.
////
//// The forgeries:
////
//// - `RepeatId`: an application message reusing an id this side already
////   sent on the relationship (hypothesis H2 of the audit).
//// - `StrayAccept` and `StrayReject`: control messages in the wrong phase.
//// - `Garbage`: a ratchet frame that does not decrypt; the session is not
////   advanced.
////
//// The forger commits only at quiescence, when the party's engine holds
//// no transaction, and the version check of `store.commit` still guards
//// the write.

import core/crypto/ratchet
import core/crypto/suite.{type Suite}
import core/envelope
import core/field
import core/frame
import core/id
import core/limits
import core/mailbox/protocol
import core/message
import core/plan
import core/relationship
import core/secret
import core/time.{type Instant}
import daemon/store
import gleam/list
import gleam/option.{None}
import gleam/result
import sim/seed
import sim/tables
import sqlight

/// Forges one message from the party whose database is `uri`, on its
/// first active relationship, and returns the `Append` that delivers it.
/// `Error` names why nothing was forged (no active relationship, no id to
/// repeat), in which case nothing was written.
///
/// ## Examples
///
/// ```gleam
/// forge.forge(uri, keeper, suite, now, seed.RepeatId)
/// // -> Ok(protocol.Append(..))
/// ```
pub fn forge(
  uri: String,
  keeper: sqlight.Connection,
  suite: Suite,
  now: Instant,
  forgery: seed.Forgery,
) -> Result(protocol.Request, String) {
  use opened <- result.try(
    store.open(uri, suite) |> result.replace_error("the store did not open"),
  )

  let forged = forge_in(opened, keeper, suite, now, forgery)
  let _ = store.close(opened)
  forged
}

/// The forgery against an open store.
fn forge_in(
  opened: store.Store,
  keeper: sqlight.Connection,
  suite: Suite,
  now: Instant,
  forgery: seed.Forgery,
) -> Result(protocol.Request, String) {
  use records <- result.try(
    store.contacts(opened) |> result.replace_error("contacts did not read"),
  )
  use #(record, link) <- result.try(first_active(records))
  use envelope <- result.try(fresh(suite))

  // Garbage needs no session; every other forgery is sealed under it.
  case forgery {
    seed.Garbage -> {
      let bytes = suite.random(200)
      use padded <- result.try(
        frame.seal(frame.Ratchet(bytes))
        |> result.replace_error("the frame did not seal"),
      )
      Ok(append(link, envelope, padded, now))
    }

    seed.RepeatId | seed.StrayAccept | seed.StrayReject -> {
      use #(message_id, body) <- result.try(body_of(
        forgery,
        keeper,
        record,
        suite,
      ))
      use #(padded, advanced) <- result.try(seal(
        suite,
        link,
        message_id,
        body,
        now,
      ))
      use Nil <- result.try(commit(opened, record, advanced, now))

      Ok(append(link, envelope, padded, now))
    }
  }
}

/// The first relationship whose phase has an active session.
fn first_active(
  records: List(store.ContactRecord),
) -> Result(#(store.ContactRecord, relationship.Link), String) {
  list.find_map(records, fn(record) {
    case record.relationship.phase {
      relationship.Active(link) -> Ok(#(record, link))

      relationship.Joining(..)
      | relationship.AwaitingAccept(_)
      | relationship.PendingApproval(_)
      | relationship.Closed(_) -> Error(Nil)
    }
  })
  |> result.replace_error("no active relationship")
}

/// A fresh identifier from the forger's suite.
fn fresh(suite: Suite) -> Result(id.Id(kind), String) {
  field.fresh_id(suite) |> result.replace_error("no randomness")
}

/// The message id and body a forgery sends.
fn body_of(
  forgery: seed.Forgery,
  keeper: sqlight.Connection,
  record: store.ContactRecord,
  suite: Suite,
) -> Result(#(id.Id(id.Message), message.Body), String) {
  let contact = id.to_bytes(record.relationship.contact)

  // A repeat needs an id this side already sent; the strays are new ids.
  case forgery {
    seed.RepeatId -> {
      use row <- result.try(
        tables.sent(keeper)
        |> list.find(fn(row) { row.contact == contact })
        |> result.replace_error("no message to repeat"),
      )
      use repeated <- result.try(
        id.from_bytes(row.message) |> result.replace_error("bad id"),
      )
      let body =
        message.Application(
          content_type: "text/plain",
          payload: secret.new(<<"forged|repeat":utf8>>),
          in_reply_to: None,
        )
      Ok(#(repeated, body))
    }

    seed.StrayAccept ->
      result.map(fresh(suite), fn(new) { #(new, message.Accept) })

    seed.StrayReject ->
      result.map(fresh(suite), fn(new) { #(new, message.Reject) })

    seed.Garbage -> Error("garbage has no body")
  }
}

/// Seals a message under the link's session, returning the padded frame
/// and the link with the advanced session.
fn seal(
  suite: Suite,
  link: relationship.Link,
  message_id: id.Id(id.Message),
  body: message.Body,
  now: Instant,
) -> Result(#(envelope.Padded, relationship.Link), String) {
  let expires_at =
    time.add(
      now,
      limits.message_retention_seconds - limits.retention_slack_seconds,
    )
  let plaintext =
    message.encode(message.Message(id: message_id, expires_at:, body:))

  use #(session, ciphertext) <- result.try(
    ratchet.encrypt(suite, link.session, secret.expose(plaintext))
    |> result.replace_error("the ratchet refused"),
  )
  use padded <- result.try(
    frame.seal(frame.Ratchet(ciphertext))
    |> result.replace_error("the frame did not seal"),
  )

  Ok(#(padded, relationship.Link(..link, session:)))
}

/// Commits the advanced session as the engine would, with no records.
fn commit(
  opened: store.Store,
  record: store.ContactRecord,
  link: relationship.Link,
  now: Instant,
) -> Result(Nil, String) {
  let advanced =
    relationship.Relationship(
      ..record.relationship,
      phase: relationship.Active(link),
    )
  let change =
    store.Revised(
      plan: plan.Plan(state: advanced, records: [], effects: []),
      version: record.version,
    )

  store.commit(opened, now, change)
  |> result.replace(Nil)
  |> result.replace_error("the session did not commit")
}

/// The `Append` that delivers a forged envelope to the peer's queue.
fn append(
  link: relationship.Link,
  envelope: id.Id(id.Envelope),
  padded: envelope.Padded,
  now: Instant,
) -> protocol.Request {
  protocol.Append(
    queue: link.outbound.queue,
    append: link.outbound.append,
    envelope:,
    retention_deadline: time.add(
      now,
      limits.message_retention_seconds - limits.retention_slack_seconds,
    ),
    ciphertext: padded,
  )
}
