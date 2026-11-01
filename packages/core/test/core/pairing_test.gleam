//// A full pairing between two in-memory parties and messages both ways,
//// with the refusals around it.

import core/frame
import core/id
import core/offer
import core/plan
import core/relationship
import core/time.{Instant}
import core/world.{Approve, Decline, Provision, Send, Setup}
import gleam/list
import gleam/option.{None, Some}

fn phase_of(w: world.World, number: Int) -> relationship.Phase {
  let assert Some(rel) = world.relationship(w, number)
    as "the party has a relationship"
  rel.phase
}

fn paired() -> world.World {
  let w = world.new(world.Correct, offer.OperatorApproves, 3)

  w
  |> world.run([Setup(0), Provision(0), Setup(1), Provision(1)])
  |> world.settle(4)
}

pub fn pairing_reaches_pending_test() {
  let w = paired()

  assert world.violations_of(w) == []
  assert w.redeemed == 1

  let assert relationship.PendingApproval(_) = phase_of(w, 0)
  let assert relationship.AwaitingAccept(_) = phase_of(w, 1)
}

pub fn approval_activates_both_sides_test() {
  let w =
    paired()
    |> world.run([Approve(0)])
    |> world.settle(4)

  assert world.violations_of(w) == []

  let assert relationship.Active(_) = phase_of(w, 0)
  let assert relationship.Active(_) = phase_of(w, 1)
}

pub fn messages_flow_both_ways_with_receipts_test() {
  let w =
    paired()
    |> world.run([Approve(0)])
    |> world.settle(4)
    |> world.run([Send(0, 1), Send(0, 2), Send(1, 3)])
    |> world.settle(4)

  assert world.violations_of(w) == []

  // Each side saw what the other sent, and each message's receipt came back.
  assert world.count_delivered(w, 1, plan.Ready) == 2
  assert world.count_delivered(w, 0, plan.Ready) == 1
  assert list.length(world.party(w, 0).received_by_peer) == 2
  assert list.length(world.party(w, 1).received_by_peer) == 1
}

pub fn auto_approve_needs_no_operator_test() {
  let w =
    world.new(world.Correct, offer.AutoApprove, 3)
    |> world.run([Setup(0), Provision(0), Setup(1), Provision(1)])
    |> world.settle(5)

  assert world.violations_of(w) == []

  let assert relationship.Active(_) = phase_of(w, 0)
  let assert relationship.Active(_) = phase_of(w, 1)
}

pub fn decline_closes_both_sides_test() {
  let w =
    paired()
    |> world.run([Decline(0)])
    |> world.settle(4)

  let assert relationship.Closed(relationship.Declined) = phase_of(w, 0)
  let assert relationship.Closed(relationship.RejectedByPeer) = phase_of(w, 1)
}

pub fn a_second_joiner_cannot_consume_the_invitation_test() {
  let w =
    world.new(world.Correct, offer.OperatorApproves, 3)
    |> world.run([Setup(0), Provision(0), Setup(1), Setup(2)])
    |> world.run([Provision(1), Provision(2)])
    |> world.settle(5)

  assert world.violations_of(w) == []
  assert w.redeemed == 1

  // Exactly one joiner is paired; the other waits forever for an answer.
  let phases = [phase_of(w, 1), phase_of(w, 2)]
  let waiting =
    list.filter(phases, fn(phase) {
      case phase {
        relationship.AwaitingAccept(_) -> True
        _ -> False
      }
    })

  assert list.length(waiting) == 2

  let assert Some(inviter) = world.offer(w, 0)
  let assert offer.Consumed(..) = inviter.phase

  // Approval answers the one that won: one joiner becomes active, the other
  // is never answered.
  let approved =
    world.run(w, [Approve(0)])
    |> world.settle(4)
  let active =
    list.filter([phase_of(approved, 1), phase_of(approved, 2)], fn(phase) {
      case phase {
        relationship.Active(_) -> True
        _ -> False
      }
    })

  assert list.length(active) == 1
}

pub fn send_before_approval_is_refused_test() {
  let w = paired()

  // The inviter is pending and the joiner is awaiting: neither may send.
  let after = world.run(w, [Send(0, 9), Send(1, 9)])

  assert world.party(after, 0).outbox == world.party(w, 0).outbox
  assert world.party(after, 1).outbox == world.party(w, 1).outbox
}

/// A hostile joiner that sends an application message before the inviter
/// has decided: the session advances and nothing reaches the agent.
pub fn application_before_approval_is_never_delivered_test() {
  let w = paired()
  let assert Some(joiner) = world.relationship(w, 1)
  let assert Some(inviter) = world.relationship(w, 0)
  let assert relationship.AwaitingAccept(link) = joiner.phase

  // Force the joiner's phase so it can encrypt, as a peer running other
  // code would.
  let forced =
    relationship.Relationship(..joiner, phase: relationship.Active(link))
  let assert Ok(sent) =
    relationship.send(
      w.suite,
      forced,
      Instant(1000),
      "text/plain",
      <<"early">>,
      None,
      None,
    )
  let assert [plan.Outbound(padded:, ..), ..] = sent.records
  let assert Ok(frame.Ratchet(bytes)) = frame.open(w.suite, padded)
  let assert Ok(queue) = id.from_bytes(<<1:128>>)
  let assert Ok(envelope_id) = id.from_bytes(<<2:128>>)
  let ref = plan.EnvelopeRef(queue:, envelope: envelope_id, digest: <<>>)
  let assert Ok(received) =
    relationship.receive(w.suite, inviter, Instant(1000), ref, bytes)

  let delivered =
    list.filter(received.records, fn(record) {
      case record {
        plan.Delivered(..) | plan.Released(..) -> True
        _ -> False
      }
    })

  assert delivered == []

  let assert relationship.PendingApproval(_) = received.state.phase
}
