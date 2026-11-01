//// The invariants of spec §13.1, checked over random schedules of a pure
//// world (`core/world`): two or three parties, a mailbox that duplicates,
//// reorders, drops and corrupts, a clock that moves, and crashes that
//// discard a computed plan at any point, outbound operations included.
////
//// The properties are checked where the event happens and collected as
//// violations: no send before commit, no ack before commit, no
//// replay-driven redelivery, no invitation double consumption, no
//// application message before `Active`, never more `Ready` deliveries than
//// the budget allows, and no message key used twice (the same ratchet
//// header committed with different bytes), a relationship phase never goes
//// backwards, a receipt names only messages that were sent, and a raise
//// releases the oldest held messages.
////
//// A second property runs benign schedules, and a third chaotic ones, through
//// the heal phase (`world.heal`, which only turns faults off and lets time
//// pass, receipt windows included) and requires quiescence, delivery and
//// receipt of every committed message, every close to reach its peer, and no
//// message left held, under a mailbox that corrupts, loses and expires
//// envelopes: end-to-end retransmission (ADR-006) recovers what the mailbox
//// spoiled. Where a state cannot deliver (the receiver closed, the message
//// expired), the audit records a named excuse. A final group runs the
//// same schedules through deliberately broken shells and requires the
//// checks to notice, so a green run means the checks can fail.

import core/offer
import core/plan
import core/world
import gleam/list
import qcheck

const property_count = 25

/// Benign cases settle to quiescence, which costs several times a walk, and
/// each test has five seconds.
const benign_count = 8

const sample_size = 150

const schedule_length = 160

/// Chosen so the sample reaches every state below more than once; the reach
/// of a rarer state such as `decline` depends on the seed.
const sharpness_seed = 38

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

fn play(bug: world.Bug, mode: world.Mode, case_: Case) -> world.World {
  let #(approval_choice, budget, picks) = case_

  world.walk(world.new(bug, approval(approval_choice), budget), picks, mode)
}

fn check(seed: Int, count: Int, run: fn(Case) -> List(String)) -> Nil {
  qcheck.default_config()
  |> qcheck.with_test_count(count)
  |> qcheck.with_seed(qcheck.seed(seed))
  |> qcheck.run(cases(), fn(case_) {
    assert run(case_) == []
  })
}

fn chaotic(case_: Case) -> List(String) {
  world.violations_of(play(world.Correct, world.Chaotic, case_))
}

/// Benign schedules, then the heal phase and every audit: each committed
/// application message is delivered and receipted once, and the world is
/// quiescent. The audits excuse only the named states in
/// `world.audit_delivery`.
fn benign_delivery(case_: Case) -> List(String) {
  play(world.Correct, world.Benign, case_)
  |> world.heal
  |> world.audit_all
  |> world.violations_of
}

/// Chaotic schedules (closes, declines, the clock) healed and audited: the
/// liveness that is well defined once faults stop, with its excuses.
fn chaotic_healed(case_: Case) -> List(String) {
  play(world.Correct, world.Chaotic, case_)
  |> world.heal
  |> world.audit_all
  |> world.violations_of
}

pub fn invariants_hold_over_random_schedules_a_test() {
  check(20_261_031, property_count, chaotic)
}

pub fn invariants_hold_over_random_schedules_b_test() {
  check(20_261_101, property_count, chaotic)
}

pub fn invariants_hold_over_random_schedules_c_test() {
  check(20_261_102, property_count, chaotic)
}

pub fn a_healed_chaotic_world_is_live_a_test() {
  check(20_261_201, benign_count, chaotic_healed)
}

pub fn a_healed_chaotic_world_is_live_b_test() {
  check(20_261_202, benign_count, chaotic_healed)
}

pub fn every_committed_message_is_delivered_and_receipted_once_a_test() {
  check(41, benign_count, benign_delivery)
}

pub fn every_committed_message_is_delivered_and_receipted_once_b_test() {
  check(42, benign_count, benign_delivery)
}

pub fn every_committed_message_is_delivered_and_receipted_once_c_test() {
  check(43, benign_count, benign_delivery)
}

pub fn every_committed_message_is_delivered_and_receipted_once_d_test() {
  check(44, benign_count, benign_delivery)
}

/// A fixed sample of generated cases, so the reach and sharpness tests see
/// the same schedules every run.
fn sample() -> List(Case) {
  qcheck.generate(cases(), sample_size, qcheck.seed(sharpness_seed)).0
}

fn total_delivered(w: world.World, status: plan.DeliveryStatus) -> Int {
  world.count_delivered(w, 0, status)
  + world.count_delivered(w, 1, status)
  + world.count_delivered(w, 2, status)
}

fn count(worlds: List(world.World), reached: fn(world.World) -> Bool) -> Int {
  list.length(list.filter(worlds, reached))
}

pub fn schedules_reach_the_interesting_states_test() {
  let worlds =
    list.map(sample(), fn(case_) { play(world.Correct, world.Chaotic, case_) })

  assert count(worlds, fn(w) { w.redeemed == 1 }) > 10
  assert count(worlds, fn(w) { total_delivered(w, plan.Ready) > 0 }) > 5
  assert count(worlds, fn(w) { total_delivered(w, plan.Held) > 0 }) > 0
  assert count(worlds, fn(w) { world.saw(w, "expired-message") }) > 0
  assert count(worlds, fn(w) { world.saw(w, "offer-expired") }) > 0
  assert count(worlds, fn(w) { world.saw(w, "close-from-joining") }) > 0
  assert count(worlds, fn(w) { world.saw(w, "close-from-awaiting") }) > 0
  assert count(worlds, fn(w) { world.saw(w, "decline") }) > 0

  // The joiner race: both joiners have a relationship and one invitation
  // was consumed.
  assert count(worlds, fn(w) {
      w.redeemed == 1
      && world.party(w, 1).relationship != world.party(w, 0).relationship
      && world.party(w, 1).queue != world.party(w, 2).queue
      && world.relationship(w, 1) != world.relationship(w, 2)
      && world.party(w, 2).queue != world.party(w, 0).queue
      && world.relationship(w, 2) != world.relationship(w, 0)
    })
    > 0
}

/// Whether a broken shell is flagged on some sampled schedule. It stops at
/// the first one, since walking all of them would only count.
fn flagged(bug: world.Bug, violation: String) -> Bool {
  list.any(sample(), fn(case_) {
    play(bug, world.Chaotic, case_)
    |> world.violations_of
    |> list.contains(violation)
  })
}

pub fn a_shell_that_sends_before_commit_is_caught_test() {
  assert flagged(world.SendBeforeCommit, "sent before commit")
}

pub fn a_shell_that_acks_before_commit_is_caught_test() {
  assert flagged(world.AckBeforeCommit, "acknowledged before commit")
}
