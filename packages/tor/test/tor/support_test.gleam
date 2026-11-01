//// The polling helpers the other tests wait with. A wait that only works
//// when the condition already holds would pass every test that is lucky
//// about timing, so these two make the condition arrive late.

import gleam/erlang/process
import tor
import tor/support

pub fn wait_until_retries_until_the_check_holds_test() {
  let arrived = process.new_subject()
  process.spawn(fn() {
    process.sleep(200)
    process.send(arrived, Nil)
  })

  assert support.wait_until(
    fn() { process.receive(arrived, 0) == Ok(Nil) },
    3000,
  )
  assert !support.wait_until(fn() { False }, 100)
}

pub fn wait_event_finds_a_late_event_among_others_test() {
  let events = process.new_subject()
  process.spawn(fn() {
    process.send(events, tor.SidecarDied(1))
    process.sleep(200)
    process.send(events, tor.SidecarRestarted)
  })

  let restarted = fn(e) { e == tor.SidecarRestarted }
  assert support.wait_event(events, restarted, 3000) == Ok(tor.SidecarRestarted)
  assert support.wait_event(events, restarted, 100) == Error(Nil)
}
