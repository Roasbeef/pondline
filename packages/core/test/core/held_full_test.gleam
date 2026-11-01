//// Reach for the held queue's bound. A random schedule is 160 steps, so it
//// can never hold the 256 messages `HeldFull` needs; this test drives it
//// directly. With no budget every message is held, the 257th is refused
//// (the shell drops and acknowledges it, and the sender gets no receipt),
//// and a heal that raises the budget releases exactly the held ones.

import core/limits
import core/offer
import core/plan
import core/world.{Ack, Approve, Fetch, Provision, Send, Setup, Transmit}
import gleam/list

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

fn indices(count: Int) -> List(Int) {
  list.repeat(Nil, count) |> list.index_map(fn(_, index) { index })
}

pub fn a_full_held_queue_refuses_the_next_message_test() {
  let extra = 3
  let total = limits.max_held_messages + extra
  let sent =
    list.fold(indices(total), active(0), fn(w, tag) {
      world.run(w, [Send(1, tag, world.Commit)])
    })
  let rows = list.length(world.party(sent, 1).outbox)
  let delivered =
    list.fold(indices(total), sent, fn(w, offset) {
      world.run(w, [
        Transmit(1, rows - total + offset),
        Fetch(0, 0, world.Commit),
        Ack(0),
      ])
    })

  // The queue is full, and the overflow was dropped, not stored.
  assert world.violations_of(delivered) == []
  assert world.count_delivered(delivered, 0, plan.Held)
    == limits.max_held_messages
  assert world.count_delivered(delivered, 0, plan.Ready) == 0

  // The audit sees the dropped messages as undelivered, which is the
  // documented refusal, so it reports them rather than excusing them.
  let healed = delivered |> world.heal |> world.audit_all
  assert world.count_delivered(healed, 0, plan.Held) == 0
  assert world.count_delivered(healed, 0, plan.Ready)
    == limits.max_held_messages
  assert list.length(world.violations_of(healed)) == extra
}
