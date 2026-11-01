//// End-to-end retransmission (ADR-006), case by case: the schedule
//// `retransmit.due_at` gives, and the refusals `retransmit.retransmit`
//// and `relationship.resend_receipt` make.

import core/crypto/fake_suite
import core/id
import core/limits
import core/offer
import core/plan
import core/relationship
import core/retransmit
import core/time.{Instant}
import core/world.{Ack, Approve, Provision, Setup}
import gleam/option.{None, Some}

/// A two-party world with the pairing approved and both sides `Active`.
fn active() -> world.World {
  world.new(world.Correct, offer.OperatorApproves, 10)
  |> world.run([
    Setup(0),
    Provision(0, world.Commit),
    Setup(1),
    Provision(1, world.Commit),
  ])
  |> world.settle(4)
  |> world.run([Approve(0, world.Commit)])
  |> world.settle(4)
  |> world.run([Ack(0), Ack(1)])
}

fn message_id() -> id.Id(id.Message) {
  let assert Ok(message) = id.from_bytes(fake_suite.fresh(id.id_bytes))
  message
}

pub fn the_window_doubles_and_stops_at_the_bound_test() {
  let kind = plan.ApplicationOut(message_id())
  let far = Instant(10_000_000)
  let window = limits.receipt_window_seconds

  assert retransmit.due_at(window, kind, Instant(0), 0, far)
    == Some(Instant(window))
  assert retransmit.due_at(window, kind, Instant(0), 2, far)
    == Some(Instant(window * 4))
  assert retransmit.due_at(
      window,
      kind,
      Instant(0),
      limits.max_retransmits,
      far,
    )
    == None
}

pub fn receipts_and_handshakes_are_never_scheduled_test() {
  let far = Instant(10_000_000)

  assert retransmit.due_at(
      60,
      plan.ReceiptOut(message_id()),
      Instant(0),
      0,
      far,
    )
    == None
  assert retransmit.due_at(60, plan.Handshake, Instant(0), 0, far) == None
  assert retransmit.due_at(
      60,
      plan.ControlOut(message_id()),
      Instant(0),
      0,
      far,
    )
    == Some(Instant(60))
}

pub fn no_copy_is_scheduled_past_the_deadline_test() {
  let kind = plan.ApplicationOut(message_id())

  // The deadline itself is still valid (`time.is_past`).
  assert retransmit.due_at(60, kind, Instant(0), 0, Instant(60))
    == Some(Instant(60))
  assert retransmit.due_at(60, kind, Instant(0), 0, Instant(59)) == None
}

pub fn a_retransmit_is_a_fresh_envelope_test() {
  let w = active()
  let assert Some(rel) = world.relationship(w, 1)
  let assert Ok(old) = id.from_bytes(fake_suite.fresh(id.id_bytes))
  let row =
    retransmit.Unreceipted(
      envelope: old,
      kind: plan.ApplicationOut(message_id()),
      deadline: Instant(10_000_000),
      retransmits: 2,
    )

  let assert Ok(made) =
    retransmit.retransmit(fake_suite.suite(), rel, row, Instant(5000))
  assert made.replaces == old
  assert made.envelope != old
  assert made.retransmits == 3
}

pub fn the_retransmit_refusals_test() {
  let w = active()
  let suite = fake_suite.suite()
  let assert Some(rel) = world.relationship(w, 1)
  let assert Ok(closed) = relationship.close(suite, rel, Instant(2000))
  let assert Ok(old) = id.from_bytes(fake_suite.fresh(id.id_bytes))
  let application =
    retransmit.Unreceipted(
      envelope: old,
      kind: plan.ApplicationOut(message_id()),
      deadline: Instant(10_000),
      retransmits: 0,
    )
  let control =
    retransmit.Unreceipted(..application, kind: plan.ControlOut(message_id()))

  // An application message needs a relationship that can still be
  // receipted; a control is sent again whatever the phase.
  assert retransmit.retransmit(suite, closed.state, application, Instant(2000))
    == Error(retransmit.NotActive)
  let assert Ok(_) =
    retransmit.retransmit(suite, closed.state, control, Instant(2000))

  assert retransmit.retransmit(
      suite,
      rel,
      retransmit.Unreceipted(..application, kind: plan.ReceiptOut(message_id())),
      Instant(2000),
    )
    == Error(retransmit.NotRetransmitted)
  assert retransmit.retransmit(
      suite,
      rel,
      retransmit.Unreceipted(..application, retransmits: limits.max_retransmits),
      Instant(2000),
    )
    == Error(retransmit.Exhausted)
  assert retransmit.retransmit(suite, rel, application, Instant(10_001))
    == Error(retransmit.Expired)
}

pub fn a_known_ciphertext_is_answered_not_delivered_test() {
  let w = active()
  let suite = fake_suite.suite()
  let assert Some(rel) = world.relationship(w, 0)
  let assert Ok(queue) = id.from_bytes(fake_suite.fresh(id.id_bytes))
  let assert Ok(envelope) = id.from_bytes(fake_suite.fresh(id.id_bytes))
  let ref = plan.EnvelopeRef(queue:, envelope:, digest: <<1>>)
  let message = message_id()
  let known =
    plan.Fingerprint(
      digest: <<2>>,
      message:,
      expires_at: Instant(10_000),
      receipts: 1,
    )

  let assert Ok(made) =
    relationship.resend_receipt(suite, rel, Instant(2000), ref, known)
  let assert [
    plan.Processed(outcome: plan.Applied, ..),
    plan.Outbound(kind: plan.ReceiptOut(_), ..),
    plan.Remembered(fingerprint: again, ..),
  ] = made.records
  assert again == plan.Fingerprint(..known, receipts: 2)

  // Expired, or answered as often as an honest sender asks: dropped.
  assert relationship.resend_receipt(suite, rel, Instant(10_001), ref, known)
    == Error(relationship.DuplicateIgnored)
  assert relationship.resend_receipt(
      suite,
      rel,
      Instant(2000),
      ref,
      plan.Fingerprint(..known, receipts: limits.max_retransmits + 1),
    )
    == Error(relationship.DuplicateIgnored)
}
