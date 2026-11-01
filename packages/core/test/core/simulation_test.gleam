//// The invariants of spec §13.1, checked over random schedules of a pure
//// world (`core/world`): two or three parties, a mailbox that duplicates,
//// reorders, drops and corrupts, a clock that moves, and crashes that
//// discard a computed plan at any point.
////
//// The properties are checked where the event happens and collected as
//// violations: no send before commit, no ack before commit, no
//// replay-driven redelivery, no invitation double consumption, no
//// application message before `Active`, and never more `Ready` deliveries
//// than the budget allows. A second group runs the same schedules through
//// deliberately broken shells and requires the checks to notice, so a green
//// run means the checks can fail.

import core/offer
import core/plan
import core/world
import gleam/list
import qcheck

const property_count = 60

const schedule_length = 160

const property_seed = 20_261_031

const sharpness_seed = 31

/// An approval policy, a budget, and a schedule of picks.
type Case =
  #(Int, Int, List(#(Int, Int)))

fn cases() -> qcheck.Generator(Case) {
  qcheck.tuple3(
    qcheck.bounded_int(0, 1),
    qcheck.bounded_int(0, 4),
    qcheck.fixed_length_list_from(
      qcheck.tuple2(
        qcheck.bounded_int(0, 100_000),
        qcheck.bounded_int(0, 100_000),
      ),
      schedule_length,
    ),
  )
}

fn approval(choice: Int) -> offer.Approval {
  case choice {
    0 -> offer.AutoApprove
    _ -> offer.OperatorApproves
  }
}

fn play(bug: world.Bug, case_: Case) -> world.World {
  let #(approval_choice, budget, picks) = case_

  world.walk(world.new(bug, approval(approval_choice), budget), picks)
}

pub fn invariants_hold_over_random_schedules_test() {
  qcheck.default_config()
  |> qcheck.with_test_count(property_count)
  |> qcheck.with_seed(qcheck.seed(property_seed))
  |> qcheck.run(cases(), fn(case_) {
    assert world.violations_of(play(world.Correct, case_)) == []
  })
}

/// Counts the schedules whose final world satisfies `reached`, over a fixed
/// sample, so a property that holds vacuously (no schedule gets anywhere)
/// is caught.
fn count_reaching(bug: world.Bug, reached: fn(world.World) -> Bool) -> Int {
  let #(sample, _) =
    qcheck.generate(cases(), property_count, qcheck.seed(sharpness_seed))

  sample
  |> list.map(fn(case_) { play(bug, case_) })
  |> list.filter(reached)
  |> list.length
}

pub fn schedules_reach_the_interesting_states_test() {
  let paired = fn(w: world.World) { w.redeemed == 1 }
  let delivered = fn(w: world.World) {
    world.count_delivered(w, 0, plan.Ready)
    + world.count_delivered(w, 1, plan.Ready)
    + world.count_delivered(w, 2, plan.Ready)
    > 0
  }
  let held = fn(w: world.World) {
    world.count_delivered(w, 0, plan.Held)
    + world.count_delivered(w, 1, plan.Held)
    + world.count_delivered(w, 2, plan.Held)
    > 0
  }
  let expired = fn(w: world.World) {
    world.count_delivered(w, 0, plan.Expired)
    + world.count_delivered(w, 1, plan.Expired)
    + world.count_delivered(w, 2, plan.Expired)
    > 0
  }

  assert count_reaching(world.Correct, paired) > 10
  assert count_reaching(world.Correct, delivered) > 5
  assert count_reaching(world.Correct, held) > 0
  assert count_reaching(world.Correct, expired) > 0
}

pub fn a_shell_that_sends_before_commit_is_caught_test() {
  assert count_reaching(world.SendBeforeCommit, fn(w) {
      list.contains(world.violations_of(w), "sent before commit")
    })
    > 0
}

pub fn a_shell_that_acks_before_commit_is_caught_test() {
  assert count_reaching(world.AckBeforeCommit, fn(w) {
      list.contains(world.violations_of(w), "acknowledged before commit")
    })
    > 0
}
