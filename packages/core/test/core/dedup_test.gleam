//// A message identifier an authenticated peer already used is ignored
//// (ADR-010, hypothesis H2 of the DST audit). An honest sender never reuses
//// one, since a retransmit is the same ciphertext and is answered by its
//// fingerprint before it is opened, so the peer here is a forger: it seals
//// two different application messages under one identifier with its real
//// session, exactly as `packages/sim/src/sim/forge.gleam` does against the
//// daemon.

import core/crypto/fake_suite
import core/crypto/ratchet
import core/crypto/suite.{type Suite}
import core/frame
import core/id
import core/limits
import core/message
import core/offer
import core/plan
import core/relationship.{type Relationship}
import core/secret
import core/time.{type Instant, Instant}
import core/world.{Commit, Provision, Setup}
import gleam/list
import gleam/option.{None, Some}

/// Two parties, paired and active: the forger first, the receiver second.
fn active_pair() -> #(Relationship, Relationship) {
  let w =
    world.new(world.Correct, offer.AutoApprove, 3)
    |> world.run([
      Setup(0),
      Provision(0, Commit),
      Setup(1),
      Provision(1, Commit),
    ])
    |> world.settle(5)
  let assert Some(forger) = world.relationship(w, 0)
  let assert Some(receiver) = world.relationship(w, 1)

  #(forger, receiver)
}

/// Seals an application message under a chosen identifier with the
/// forger's real session, returning the advanced link and the ratchet bytes
/// inside the frame.
fn seal(
  suite: Suite,
  link: relationship.Link,
  message_id: id.Id(id.Message),
  payload: BitArray,
  expires_at: Instant,
) -> #(relationship.Link, BitArray) {
  let body =
    message.Application(
      content_type: "text/plain",
      payload: secret.new(payload),
      in_reply_to: None,
    )
  let plaintext =
    message.encode(message.Message(id: message_id, expires_at:, body:))
  let assert Ok(#(session, ciphertext)) =
    ratchet.encrypt(suite, link.session, secret.expose(plaintext))

  // The frame is sealed and opened again only to show the bytes are what a
  // shell would hand the relationship.
  let assert Ok(padded) = frame.seal(frame.Ratchet(ciphertext))
  let assert Ok(frame.Ratchet(bytes)) = frame.open(suite, padded)

  #(relationship.Link(..link, session:), bytes)
}

fn envelope_ref(receiver: Relationship, n: Int) -> plan.EnvelopeRef {
  let assert Ok(envelope) = id.from_bytes(<<n:128>>)
  plan.EnvelopeRef(queue: receiver.inbox.queue, envelope:, digest: <<n>>)
}

fn link_of(found: Relationship) -> relationship.Link {
  let assert relationship.Active(link) = found.phase
  link
}

fn is_delivery(record: plan.Record) -> Bool {
  case record {
    plan.Delivered(..) | plan.Audit(..) | plan.Outbound(..) -> True
    _ -> False
  }
}

pub fn a_repeated_message_id_is_ignored_and_recorded_test() {
  let suite = fake_suite.suite()
  let #(forger, receiver) = active_pair()
  let now = Instant(1000)
  let expires = time.add(now, limits.message_retention_seconds)
  let assert Ok(repeated) = id.from_bytes(<<7:128>>)
  let #(link, first) =
    seal(suite, link_of(forger), repeated, <<"first">>, expires)
  let #(_, second) = seal(suite, link, repeated, <<"second">>, expires)

  // The first message under the identifier is delivered like any other.
  let first_ref = envelope_ref(receiver, 1)
  let assert Ok(opened) =
    relationship.open(suite, receiver, now, first_ref, first)
  assert relationship.opened_message(opened) == repeated
  let assert Ok(delivered) = relationship.receive(opened, relationship.FreshId)
  assert list.any(delivered.records, fn(record) {
    case record {
      plan.Delivered(message:, ..) -> message == repeated
      _ -> False
    }
  })

  // The second is different bytes under the same identifier, which the
  // shell finds among the deliveries. It is processed and recorded, and
  // nothing else: no delivery, no audit, no receipt, no fingerprint.
  let second_ref = envelope_ref(receiver, 2)
  let assert Ok(opened) =
    relationship.open(suite, delivered.state, now, second_ref, second)
  assert relationship.opened_message(opened) == repeated
  let assert Ok(ignored) = relationship.receive(opened, relationship.UsedId)

  assert ignored.records
    == [
      plan.applied(second_ref),
      plan.RepeatedMessage(
        contact: receiver.contact,
        message: repeated,
        queue: second_ref.queue,
        envelope: second_ref.envelope,
      ),
    ]
  assert ignored.effects == []

  // The budget is untouched, and the session advanced past the message, so
  // the forger's next honest message still decrypts.
  assert ignored.state.budget == delivered.state.budget
  assert link_of(ignored.state).session != link_of(delivered.state).session
}

pub fn an_expired_message_under_a_used_id_records_nothing_test() {
  let suite = fake_suite.suite()
  let #(forger, receiver) = active_pair()
  let assert Ok(repeated) = id.from_bytes(<<9:128>>)
  let #(_, bytes) =
    seal(suite, link_of(forger), repeated, <<"late">>, Instant(1500))

  // Past its expiry the message is stored for nobody, whatever its
  // identifier's history: only the `Processed` record is written.
  let ref = envelope_ref(receiver, 3)
  let assert Ok(opened) =
    relationship.open(suite, receiver, Instant(2000), ref, bytes)
  let assert Ok(ignored) = relationship.receive(opened, relationship.UsedId)

  assert ignored.records == [plan.applied(ref)]
}

pub fn the_history_reaches_only_application_messages_test() {
  let suite = fake_suite.suite()
  let #(forger, receiver) = active_pair()
  let now = Instant(1000)
  let assert Ok(message_id) = id.from_bytes(<<11:128>>)
  let #(link, bytes) =
    seal(
      suite,
      link_of(forger),
      message_id,
      <<"fresh">>,
      time.add(now, limits.message_retention_seconds),
    )
  let ref = envelope_ref(receiver, 4)

  // A fresh identifier is stored; nothing is refused or recorded twice.
  let assert Ok(opened) = relationship.open(suite, receiver, now, ref, bytes)
  let assert Ok(fresh) = relationship.receive(opened, relationship.FreshId)
  assert list.count(fresh.records, is_delivery) == 3

  // A receipt names messages rather than being stored under its own
  // identifier, so its history changes nothing about it.
  let assert Ok(#(session, ciphertext)) =
    ratchet.encrypt(
      suite,
      link.session,
      secret.expose(
        message.encode(message.Message(
          id: message_id,
          expires_at: time.add(now, limits.message_retention_seconds),
          body: message.Receipt([message_id]),
        )),
      ),
    )
  let _ = session
  let assert Ok(opened) =
    relationship.open(suite, fresh.state, now, envelope_ref(receiver, 5), {
      ciphertext
    })
  let assert Ok(receipted) = relationship.receive(opened, relationship.UsedId)
  assert list.any(receipted.records, fn(record) {
    case record {
      plan.PeerReceived(messages:, ..) -> messages == [message_id]
      _ -> False
    }
  })
}
