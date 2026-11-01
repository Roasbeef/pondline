//// End-to-end retransmission (ADR-006), case by case: the schedule
//// `retransmit.due_at` gives, the refusals `retransmit.retransmit` and
//// `relationship.resend_receipt` make, and two scripted worlds in which a
//// mailbox spoils the only copy of a message and of a receipt, and the
//// message is still delivered once and receipted.

import core/crypto/fake_suite
import core/id
import core/limits
import core/offer
import core/plan
import core/relationship
import core/retransmit
import core/time.{Instant}
import core/world.{
  Ack, Approve, Corrupt, Fetch, Lose, Provision, Retransmit, Send, Setup, Tick,
  Transmit,
}
import gleam/list
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

/// The index of the last row in a party's outbox whose kind matches.
fn last_row(
  w: world.World,
  number: Int,
  kind: fn(plan.OutboundKind) -> Bool,
) -> Int {
  let found =
    list.index_fold(world.party(w, number).outbox, None, fn(found, row, index) {
      case kind(row.kind) {
        True -> Some(index)
        False -> found
      }
    })
  let assert Some(index) = found as "the party committed such a row"
  index
}

fn is_application(kind: plan.OutboundKind) -> Bool {
  case kind {
    plan.ApplicationOut(_) -> True
    _ -> False
  }
}

fn is_receipt(kind: plan.OutboundKind) -> Bool {
  case kind {
    plan.ReceiptOut(_) -> True
    _ -> False
  }
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

pub fn a_corrupted_message_is_delivered_by_its_retransmit_test() {
  let w = active() |> world.run([Send(1, 7, world.Commit)])
  let row = last_row(w, 1, is_application)

  // The mailbox stores it, answers, then corrupts the only copy; the
  // receiver drops what it cannot decrypt and acknowledges it.
  let w =
    world.run(w, [
      Transmit(1, row),
      Corrupt(0, 0),
      Fetch(0, 0, world.Commit),
      Ack(0),
    ])
  assert world.count_delivered(w, 0, plan.Ready) == 0

  // The receipt window passes with no receipt, so the sender sends the same
  // bytes again under a new envelope.
  let w =
    world.run(w, [
      Tick(limits.receipt_window_seconds),
      Retransmit(1, row),
    ])
  let copy = list.length(world.party(w, 1).outbox) - 1
  let w = world.run(w, [Transmit(1, copy), Fetch(0, 0, world.Commit), Ack(0)])
  assert world.count_delivered(w, 0, plan.Ready) == 1
  assert world.saw(w, "delivered-by-retransmit")

  // The receipt for the copy reaches the sender and ends the schedule.
  let receipt = last_row(w, 0, is_receipt)
  let w =
    world.run(w, [Transmit(0, receipt), Fetch(1, 0, world.Commit), Ack(1)])
  assert list.length(world.party(w, 1).received_by_peer) == 1
  assert list.all(world.party(w, 1).outbox, fn(sent) {
    !is_application(sent.kind) || sent.retransmit_at == None
  })
  assert world.violations_of(w) == []
}

pub fn a_lost_receipt_is_regenerated_by_the_retransmit_test() {
  let w = active() |> world.run([Send(1, 9, world.Commit)])
  let row = last_row(w, 1, is_application)

  // Delivered, and the receipt is stored at the sender's mailbox and lost
  // there after `Appended`.
  let w = world.run(w, [Transmit(1, row), Fetch(0, 0, world.Commit), Ack(0)])
  let receipt = last_row(w, 0, is_receipt)
  let w = world.run(w, [Transmit(0, receipt), Lose(1, 0)])
  assert world.count_delivered(w, 0, plan.Ready) == 1
  assert world.party(w, 1).received_by_peer == []

  // The sender's retransmit cannot be decrypted (its key is spent), but its
  // fingerprint is known: the receiver answers with the receipt again and
  // does not deliver a second time.
  let w =
    world.run(w, [
      Tick(limits.receipt_window_seconds),
      Retransmit(1, row),
    ])
  let copy = list.length(world.party(w, 1).outbox) - 1
  let w = world.run(w, [Transmit(1, copy), Fetch(0, 0, world.Commit), Ack(0)])
  assert world.saw(w, "receipt-regenerated")
  assert world.count_delivered(w, 0, plan.Ready) == 1

  let again = last_row(w, 0, is_receipt)
  let w = world.run(w, [Transmit(0, again), Fetch(1, 0, world.Commit), Ack(1)])
  assert list.length(world.party(w, 1).received_by_peer) == 1
  assert world.violations_of(w) == []
}
