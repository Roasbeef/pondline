//// The swarm corpus and campaign for the pure world (`core/swarm`).
////
//// The fixed qcheck schedules in `simulation_test` stay as the corpus of
//// regression schedules. These tests add three things: swarm seeds, each
//// enabling its own subset of fault classes; a fixed list of seeds that
//// once exercised the interesting states; and a determinism check that
//// plays every seed twice and requires identical worlds, which holds only
//// because the suite is seeded.
////
//// `PONDLINE_SWARM=<count>` and `PONDLINE_SWARM_SEED=<number>` size and seed
//// the campaign test, and `PONDLINE_REPLAY=<hex>` plays one seed with its
//// log. A failing campaign prints the seed and run index.

import core/offer
import core/plan
import core/swarm
import core/world
import gleam/int
import gleam/list
import gleam/result
import gleam/string

@external(erlang, "os", "getenv")
fn getenv(name: List(Int), default: List(Int)) -> List(Int)

@external(erlang, "unicode", "characters_to_list")
fn to_charlist(text: String) -> List(Int)

@external(erlang, "unicode", "characters_to_binary")
fn from_charlist(text: List(Int)) -> String

fn env(name: String, default: String) -> String {
  from_charlist(getenv(to_charlist(name), to_charlist(default)))
}

fn env_int(name: String, default: Int) -> Int {
  int.parse(env(name, int.to_string(default))) |> result.unwrap(default)
}

/// Small enough for a test's five seconds; a shell run sets its own.
const default_runs = 40

const default_generator_seed = 20_261_101

pub fn a_swarm_of_seeds_holds_the_invariants_and_audits_test() {
  swarm.campaign(
    env_int("PONDLINE_SWARM", default_runs),
    env_int("PONDLINE_SWARM_SEED", default_generator_seed),
  )
}

pub fn a_seed_given_in_the_environment_replays_test() {
  case env("PONDLINE_REPLAY", "") {
    "" -> Nil
    hex -> swarm.replay(hex)
  }
}

pub fn a_seed_replays_to_the_same_world_test() {
  swarm.runs(12)
  |> list.each(fn(index) {
    let seed = swarm.generate(default_generator_seed, index)
    let first = swarm.run(seed)
    let second = swarm.run(seed)

    assert first.parties == second.parties
    assert first.mailbox == second.mailbox
    assert first.tombstones == second.tombstones
    assert first.events == second.events
    assert first.excuses == second.excuses
    assert first.now == second.now
  })
}

pub fn every_seed_decodes_test() {
  assert swarm.decode(<<>>).mask == world.every_fault
  assert swarm.decode(<<0, 1>>).picks == []
  assert swarm.decode(<<1, 0xFF, 0x00, 0, 5, 9, 1>>).picks == [#(5, 9)]
  assert swarm.decode(<<1, 0xFF, 0x00>>).mode == world.Benign
  assert swarm.decode(<<2, 0, 0>>).approval == offer.OperatorApproves
  assert swarm.decode(<<0b1100, 0, 0>>).budget == 3
  assert swarm.generate(3, 4) == swarm.generate(3, 4)
  assert swarm.generate(3, 4) != swarm.generate(3, 5)
}

/// A seed with a fault class off never produces that class's events.
pub fn a_class_that_is_off_never_fires_test() {
  let corruption_off = world.mask_of([world.Crashes, world.Replays])

  swarm.runs(30)
  |> list.each(fn(index) {
    let seed = swarm.generate(7, index)
    let decoded = swarm.decode(seed)
    let walked =
      world.new_seeded(world.Correct, decoded.approval, decoded.budget, 1)
      |> world.walk_with(decoded.picks, world.Chaotic, corruption_off)

    assert world.violations_of(walked) == []
    assert !world.saw(walked, "close-from-joining")
    assert !world.saw(walked, "close-from-awaiting")
    assert !world.saw(walked, "decline")
    assert !world.saw(walked, "offer-expired")
  })
}

/// The scripted phase of a seed, before the heal.
fn walked(seed: BitArray) -> world.World {
  let decoded = swarm.decode(seed)

  world.new_seeded(
    world.Correct,
    decoded.approval,
    decoded.budget,
    decoded.world_seed,
  )
  |> world.walk_with(decoded.picks, decoded.mode, decoded.mask)
}

fn held(w: world.World) -> Int {
  world.count_delivered(w, 0, plan.Held)
  + world.count_delivered(w, 1, plan.Held)
  + world.count_delivered(w, 2, plan.Held)
}

/// Across a campaign the swarm reaches the states the audits reason about:
/// closes, the clock, held messages before the heal raises them, a mailbox
/// losing a stored envelope, both retransmit paths (a message delivered from
/// a copy, a receipt regenerated), and the excuses the audits know.
fn audit_seeds() -> List(BitArray) {
  list.map(swarm.runs(60), swarm.generate(11, _))
}

fn scripted_reaches(predicate: fn(world.World) -> Bool) -> Bool {
  list.any(audit_seeds(), fn(seed) { predicate(walked(seed)) })
}

fn healed_reaches(predicate: fn(world.World) -> Bool) -> Bool {
  list.any(audit_seeds(), fn(seed) { predicate(swarm.run(seed)) })
}

pub fn the_swarm_audit_seeds_hold_invariants_a_test() {
  let first_half = list.take(audit_seeds(), 30)
  assert list.all(first_half, fn(seed) {
    world.violations_of(swarm.run(seed)) == []
  })
  assert string.length(swarm.hex(
      first_half |> list.first |> result.unwrap(<<>>),
    ))
    > 6
}

pub fn the_swarm_audit_seeds_hold_invariants_b_test() {
  let second_half = list.drop(audit_seeds(), 30)
  assert list.all(second_half, fn(seed) {
    world.violations_of(swarm.run(seed)) == []
  })
}

pub fn the_swarm_reaches_scripted_states_test() {
  assert scripted_reaches(fn(w) { world.saw(w, "close-from-awaiting") })
  assert scripted_reaches(fn(w) { world.saw(w, "offer-expired") })
  assert scripted_reaches(fn(w) { held(w) > 0 })
  assert scripted_reaches(fn(w) { world.saw(w, "lost-in-mailbox") })
}

pub fn the_swarm_reaches_healed_states_test() {
  assert healed_reaches(fn(w) { world.saw(w, "delivered-by-retransmit") })
  assert healed_reaches(fn(w) { world.saw(w, "receipt-regenerated") })
  assert healed_reaches(fn(w) {
    list.contains(world.excuses_of(w), "receiver-closed")
  })
}
