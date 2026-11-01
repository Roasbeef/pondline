//// Regressions from the independent review: implicit accept on reordering
//// (ADR-004), bounded caller-supplied fields, expired messages stored
//// without their payload, and a `Hello` that points at the inviter itself.

import core/crypto/fake_suite
import core/endpoint
import core/frame
import core/id
import core/offer
import core/plan
import core/relationship
import core/route
import core/secret
import core/snapshot
import core/time.{Instant}
import core/world.{Approve, Commit, Fetch, Provision, Send, Setup, Transmit}
import gleam/list
import gleam/option.{None, Some}
import gleam/string

fn phase_of(w: world.World, number: Int) -> relationship.Phase {
  let assert Some(rel) = world.relationship(w, number)
    as "the party has a relationship"
  rel.phase
}

/// The inviter's first application message overtakes its `Accept`: the
/// joiner is still awaiting acceptance when it arrives. The message is not
/// lost; it is an implicit accept.
pub fn an_application_message_overtaking_accept_is_delivered_test() {
  let w =
    world.new(world.Correct, offer.OperatorApproves, 3)
    |> world.run([
      Setup(0),
      Provision(0, Commit),
      Setup(1),
      Provision(1, Commit),
    ])
    |> world.settle(4)
    |> world.run([Approve(0, Commit), Send(0, 7, Commit)])

  // The inviter's outbox is [Accept, Application]; only the second goes.
  let reordered = world.run(w, [Transmit(0, 1), Fetch(1, 0, Commit)])

  let assert relationship.Active(_) = phase_of(reordered, 1)

  assert world.count_delivered(reordered, 1, plan.Ready) == 1
  assert world.violations_of(reordered) == []

  // The late Accept changes nothing, and the receipt comes home.
  let settled =
    world.run(reordered, [Transmit(0, 0)])
    |> world.settle(4)

  let assert relationship.Active(_) = phase_of(settled, 1)

  assert world.count_delivered(settled, 1, plan.Ready) == 1
  assert list.length(world.party(settled, 0).received_by_peer) == 1
  assert world.violations_of(settled) == []
}

fn terms(description: String, budget: Int) -> relationship.Terms {
  let suite = fake_suite.suite()
  let assert Ok(port) = endpoint.port(7000)
  let assert Ok(inbox) = route.new_inbox(suite, endpoint.Loopback(port))

  relationship.Terms(inbox:, description:, budget:)
}

pub fn an_overlong_description_is_refused_up_front_test() {
  let suite = fake_suite.suite()
  let long = string.repeat("d", 300)
  let assert Ok(made) =
    offer.create(suite, terms("fine", 1), offer.AutoApprove, Instant(1000))
  let assert Ok(invite) = offer.invitation(offer.provisioned(made.state))

  assert result_is(
    offer.create(suite, terms(long, 1), offer.AutoApprove, Instant(1000)),
    offer.DescriptionTooLong,
  )
  assert relationship.join(
      suite,
      invite,
      endpoint.TorOrLoopback,
      terms(long, 1),
      Instant(1000),
    )
    == Error(relationship.DescriptionTooLong)
}

fn result_is(
  outcome: Result(a, offer.Rejection),
  expected: offer.Rejection,
) -> Bool {
  case outcome {
    Error(found) -> found == expected
    Ok(_) -> False
  }
}

pub fn budgets_are_clamped_so_snapshots_round_trip_test() {
  let suite = fake_suite.suite()

  list.each([-5, 0, 3, 5_000_000_000_000], fn(budget) {
    let assert Ok(made) =
      offer.create(
        suite,
        terms("x", budget),
        offer.OperatorApproves,
        Instant(1000),
      )
    let blob = secret.expose(snapshot.encode_offer(made.state))
    let assert Ok(back) = snapshot.decode_offer(suite, blob)

    assert back == made.state
  })
}

/// An expired application message advances the session and nothing else:
/// no payload is written, in a delivery or in the audit log.
pub fn an_expired_message_stores_no_plaintext_test() {
  let suite = fake_suite.suite()
  let w =
    world.new(world.Correct, offer.AutoApprove, 3)
    |> world.run([
      Setup(0),
      Provision(0, Commit),
      Setup(1),
      Provision(1, Commit),
    ])
    |> world.settle(5)
  let assert Some(sender) = world.relationship(w, 0)
  let assert Some(receiver) = world.relationship(w, 1)
  let assert Ok(sent) =
    relationship.send(
      suite,
      sender,
      Instant(1000),
      "text/plain",
      <<"secret words">>,
      None,
      Some(5),
    )
  let assert [plan.Outbound(padded:, ..), ..] = sent.records
  let assert Ok(frame.Ratchet(bytes)) = frame.open(suite, padded)
  let assert Ok(envelope_id) = id.from_bytes(<<2:128>>)
  let ref =
    plan.EnvelopeRef(
      queue: receiver.inbox.queue,
      envelope: envelope_id,
      digest: <<>>,
    )

  let assert Ok(received) =
    relationship.receive(suite, receiver, Instant(2000), ref, bytes)
  let stored =
    list.filter(received.records, fn(record) {
      case record {
        plan.Delivered(..) | plan.Audit(..) | plan.Outbound(..) -> True
        _ -> False
      }
    })

  assert stored == []
}

/// A `Hello` whose reply route is the inviter's own inbox is refused.
pub fn a_hello_replying_to_the_inviter_itself_is_refused_test() {
  let suite = fake_suite.suite()
  let shared = terms("both", 2)
  let assert Ok(made) =
    offer.create(suite, shared, offer.OperatorApproves, Instant(1000))
  let opened = offer.provisioned(made.state)
  let assert Ok(invite) = offer.invitation(opened)
  let assert Ok(joining) =
    relationship.join(
      suite,
      invite,
      endpoint.TorOrLoopback,
      shared,
      Instant(1000),
    )
  let assert Ok(started) =
    relationship.joined(suite, joining.state, Instant(1000))
  let assert [plan.Outbound(padded:, ..)] = started.records
  let assert Ok(frame.Initial(initial)) = frame.open(suite, padded)
  let assert offer.Open(stock) = opened.phase
  let assert Ok(envelope_id) = id.from_bytes(<<2:128>>)
  let ref =
    plan.EnvelopeRef(
      queue: stock.inbox.queue,
      envelope: envelope_id,
      digest: <<>>,
    )

  let assert Error(offer.ReplyIsOwnInbox) =
    offer.redeem(
      suite,
      opened,
      endpoint.TorOrLoopback,
      ref,
      initial,
      Instant(1000),
    )
}
