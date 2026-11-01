//// A repeated message identifier from an authenticated peer, between two
//// real daemons and a real mailbox (ADR-010, hypothesis H2 of the DST
//// audit, `packages/sim` regression seed `000001...08c0`).
////
//// An honest daemon cannot be made to repeat an identifier, so the test
//// plays a modified one, as `sim/forge` does: it stops the sender, reads its
//// relationship from its own database, seals a second application message
//// under the identifier of one already delivered with the real session,
//// commits the advanced session the way the engine would, and appends the
//// envelope to the receiver's queue itself. The receiver fetches and
//// processes it like any other envelope.
////
//// Before the fix the receiver's commit failed on the deliveries'
//// uniqueness, the envelope was never acknowledged, and every later
//// envelope on the queue waited behind it.

import core/crypto/ratchet
import core/field
import core/frame
import core/id
import core/limits
import core/mailbox/protocol
import core/message
import core/offer
import core/plan
import core/relationship
import core/secret
import core/time
import daemon/api
import daemon/config
import daemon/engine
import daemon/mailbox_client
import daemon/node
import daemon/store
import daemon/support
import gleam/list
import gleam/option.{None, Some}

fn active_contact(daemon: api.Daemon) {
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(daemon)

    case list.find(views, fn(view) { view.phase == api.Active }) {
      Ok(view) -> Some(view.contact)
      Error(Nil) -> None
    }
  })
}

/// The payloads the receiving agent can read, in order.
fn readable(daemon: api.Daemon) -> List(BitArray) {
  let assert Ok(found) = api.receive(daemon, None, 20)
  list.map(found, fn(delivery) { secret.expose(delivery.payload) })
}

/// Seals an application message under `repeated` with the sender's real
/// session, commits the advanced session to the stopped sender's database,
/// and returns the `Append` that carries it to the peer's queue.
fn forge(settings: config.Config, repeated: id.Id(id.Message)) {
  let path = settings.state_dir <> "/" <> node.database_file
  let assert Ok(opened) = store.open(path, settings.suite)
  let assert Ok(records) = store.contacts(opened)
  let assert [record] = records
  let assert relationship.Active(link) = record.relationship.phase

  let now = support.now()
  let expires_at =
    time.add(
      now,
      limits.message_retention_seconds - limits.retention_slack_seconds,
    )
  let body =
    message.Application(
      content_type: "text/plain",
      payload: secret.new(<<"forged":utf8>>),
      in_reply_to: None,
    )
  let plaintext =
    message.encode(message.Message(id: repeated, expires_at:, body:))
  let assert Ok(#(session, ciphertext)) =
    ratchet.encrypt(settings.suite, link.session, secret.expose(plaintext))
  let assert Ok(padded) = frame.seal(frame.Ratchet(ciphertext))

  // The sender's next honest message must follow the forged one in the
  // ratchet, so the advanced session is committed as the engine would.
  let advanced =
    relationship.Relationship(
      ..record.relationship,
      phase: relationship.Active(relationship.Link(..link, session:)),
    )
  let assert Ok(_) =
    store.commit(
      opened,
      now,
      store.Revised(
        plan: plan.Plan(state: advanced, records: [], effects: []),
        version: record.version,
      ),
    )
  let assert Ok(Nil) = store.close(opened)

  let assert Ok(envelope) = field.fresh_id(settings.suite)
  #(
    link.outbound,
    protocol.Append(
      queue: link.outbound.queue,
      append: link.outbound.append,
      envelope:,
      retention_deadline: expires_at,
      ciphertext: padded,
    ),
  )
}

pub fn a_repeated_message_id_is_ignored_and_the_queue_moves_on_test() {
  let mailbox = support.start_mailbox()
  let #(a, settings_a) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = active_contact(a)
  let _ = active_contact(b)
  let assert Ok([inbox_b]) = engine.live_inboxes(api.engine_handle(b))

  // An honest first message, delivered and receipted.
  let assert Ok(first) = api.send(a, at_a, "text/plain", <<"first":utf8>>, None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, first) == Ok(api.ReceivedByPeer))
  })

  // A turns forger: a different message under the first one's identifier.
  node.stop(a)
  let #(target, append) = forge(settings_a, first)
  let assert Ok(protocol.Appended(_)) =
    mailbox_client.call(
      support.loopback_dialer(),
      target.endpoint,
      mailbox_client.isolation_group(target.queue),
      append,
      5000,
    )

  // B processes and acknowledges it, and tells its operator.
  let incident =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.incidents(b, 10)
      list.first(found) |> option.from_result
    })
  assert incident.kind == api.RepeatedMessageId
  assert incident.message == Some(first)
  assert incident.contact != None
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox_b) == [])
  })
  assert api.health(b).incidents == 1

  // The queue is not wedged: A's next honest message, sealed after the
  // forged one, is delivered.
  let assert Ok(a) = node.start(settings_a)
  let assert Ok(second) =
    api.send(a, at_a, "text/plain", <<"second":utf8>>, None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, second) == Ok(api.ReceivedByPeer))
  })

  // The agent never saw the forged payload.
  assert readable(b) == [<<"first":utf8>>, <<"second":utf8>>]
}
