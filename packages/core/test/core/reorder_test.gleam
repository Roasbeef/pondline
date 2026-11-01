//// Regression: a burst of application messages that reaches the mailbox in
//// reverse order. The demo's unpaced runs once showed such a burst recorded
//// as dropped; every message must be delivered exactly once whatever the
//// arrival order.

import core/offer
import core/plan
import core/world.{Ack, Approve, Fetch, Provision, Send, Setup, Transmit}
import gleam/list

/// A two-party world with the pairing approved and both sides `Active`.
fn active(budget: Int) -> world.World {
  world.new(world.Correct, offer.OperatorApproves, budget)
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

pub fn a_reversed_burst_is_delivered_test() {
  let w = active(10)
  let before = list.length(world.party(w, 1).outbox)
  let w =
    world.run(w, [
      Send(1, 1, world.Commit),
      Send(1, 2, world.Commit),
      Send(1, 3, world.Commit),
      Send(1, 4, world.Commit),
      Send(1, 5, world.Commit),
    ])
  assert list.length(world.party(w, 1).outbox) == before + 5

  let w =
    world.run(w, [
      Transmit(1, before + 4),
      Transmit(1, before + 3),
      Transmit(1, before + 2),
      Transmit(1, before + 1),
      Transmit(1, before),
      Fetch(0, 0, world.Commit),
      Fetch(0, 1, world.Commit),
      Fetch(0, 2, world.Commit),
      Fetch(0, 3, world.Commit),
      Fetch(0, 4, world.Commit),
    ])

  assert world.violations_of(w) == []
  assert world.count_delivered(w, 0, plan.Ready) == 5
}
