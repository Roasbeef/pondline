//// The spoken-code run drivers (ADR-016) against a scripted rendezvous:
//// the security rules `daemon/pairing` holds whatever the mailbox says.
//// One step per index on the first message only, a hand-off sealed once
//// and resent byte for byte, a run bounded by its slot's lifetime on the
//// link's clock, and the endings and the count each side reaches. The
//// registry's own deadline is checked here too. The honest exchange over a
//// real mailbox is `pairing_code_test`.

import core/capability
import core/crypto/suite.{type Suite, Suite}
import core/id.{type Id, type Rendezvous}
import core/mailbox/protocol.{type Request, type Response, RendezvousMessage}
import core/nameplate
import core/pairing_code.{type PairingCode}
import core/rendezvous
import core/secret
import daemon/mail
import daemon/pairing
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/otp/actor
import primitives/suite as primitive_suite
import weft/poll
import weft/timer

// ------------------------------------------------------------- fixtures

/// The ticket text the inviter releases in these runs.
const ticket_text = "pl1-the-ticket-these-runs-hand-off"

/// How long each driver run here may last, on the fake clock.
const lifetime_ms = 120_000

/// A scripted rendezvous mailbox and a clock that moves only when a wait
/// sleeps, both held by one process so a run's calls are seen in order.
type Fake =
  Subject(FakeMessage)

type FakeMessage {
  Call(request: Request, reply: Subject(Result(Response, Nil)))
  Calls(reply: Subject(List(Request)))
  Now(reply: Subject(Int))
  Sleep(ms: Int)
}

type FakeState {
  FakeState(
    calls: List(Request),
    clock: Int,
    answer: fn(Request, List(Request)) -> Result(Response, Nil),
  )
}

/// Starts a fake whose `answer` sees each request and the requests before
/// it, oldest first.
fn start_fake(
  answer: fn(Request, List(Request)) -> Result(Response, Nil),
) -> Fake {
  let assert Ok(started) =
    actor.new(FakeState(calls: [], clock: 0, answer:))
    |> actor.on_message(fake_handle)
    |> actor.start

  started.data
}

fn fake_handle(
  state: FakeState,
  message: FakeMessage,
) -> actor.Next(FakeState, FakeMessage) {
  case message {
    Call(request:, reply:) -> {
      process.send(reply, state.answer(request, list.reverse(state.calls)))
      actor.continue(FakeState(..state, calls: [request, ..state.calls]))
    }

    Calls(reply:) -> {
      process.send(reply, list.reverse(state.calls))
      actor.continue(state)
    }

    Now(reply:) -> {
      process.send(reply, state.clock)
      actor.continue(state)
    }

    Sleep(ms:) -> actor.continue(FakeState(..state, clock: state.clock + ms))
  }
}

/// The link a driver uses to reach the fake, on the fake's clock.
fn link(fake: Fake) -> pairing.Link {
  pairing.Link(
    call: fn(request, _budget) { actor.call(fake, 60_000, Call(request, _)) },
    clock: poll.Clock(now: fn() { actor.call(fake, 1000, Now) }, sleep: fn(ms) {
      actor.send(fake, Sleep(ms))
    }),
  )
}

fn calls(fake: Fake) -> List(Request) {
  actor.call(fake, 1000, Calls)
}

fn now(fake: Fake) -> Int {
  actor.call(fake, 1000, Now)
}

fn rid() -> Id(Rendezvous) {
  let assert Ok(value) = id.from_bytes(<<7:128>>)
  value
}

fn slot(read: Int, append: Int) -> pairing.Slot {
  let assert Ok(read) = capability.from_bytes(<<read:256>>)
  let assert Ok(append) = capability.from_bytes(<<append:256>>)
  pairing.Slot(rendezvous: rid(), read:, append:)
}

fn code() -> PairingCode {
  let assert Ok(plate) = nameplate.from_int(482_719)
  pairing_code.generate(primitive_suite.suite(), plate)
}

fn waiting(code: PairingCode) -> rendezvous.InviterWaiting {
  let assert Ok(waiting) =
    rendezvous.invite(code, rid(), secret.new(<<ticket_text:utf8>>))
  waiting
}

/// A recorder for `record_failure`, and how many times it was called.
fn recorder() -> #(Subject(Nil), fn() -> Nil) {
  let failures = process.new_subject()
  #(failures, fn() { process.send(failures, Nil) })
}

fn count(subject: Subject(a)) -> Int {
  count_loop(subject, 0)
}

fn count_loop(subject: Subject(a), seen: Int) -> Int {
  case process.receive(subject, 0) {
    Ok(_) -> count_loop(subject, seen + 1)
    Error(Nil) -> seen
  }
}

/// The bodies this side sent at `index`, in order.
fn sent_at(requests: List(Request), index: Int) -> List(BitArray) {
  list.filter_map(requests, fn(request) {
    case request {
      protocol.RendezvousSend(index: at, body:, ..) if at == index -> Ok(body)
      _ -> Error(Nil)
    }
  })
}

fn is_fetch(request: Request) -> Bool {
  case request {
    protocol.RendezvousFetch(..) -> True
    _ -> False
  }
}

fn closed(requests: List(Request)) -> Bool {
  list.any(requests, fn(request) {
    case request {
      protocol.CloseRendezvous(..) -> True
      _ -> False
    }
  })
}

/// The joiner's `m1` an honest joiner with `code` sends, and its state.
fn honest_join(code: PairingCode) -> #(rendezvous.JoinerSent, BitArray) {
  let assert Ok(joined) = rendezvous.join(primitive_suite.suite(), code, rid())
  joined
}

// ---------------------------------------------------- one step per index

/// An inviter given two messages at index 0 steps on the first and never on
/// the second. The first is malformed, so the run ends there: nothing is
/// answered, the slot is closed, and nothing is counted. Running the step
/// again on the honest second message would be a second guess at the
/// words, handed to whoever wrote it, so the fake answers any later read of
/// index 0 with the honest message alone, as a mailbox playing the
/// adversary would.
pub fn an_inviter_steps_once_on_the_first_message_at_an_index_test() {
  let code = code()
  let #(_, real_m1) = honest_join(code)
  let junk = <<0:size(272)>>

  let fake =
    start_fake(fn(request, earlier) {
      case request {
        protocol.RendezvousFetch(after: -1, ..) ->
          case list.any(earlier, is_fetch) {
            False ->
              Ok(
                protocol.RendezvousMessages([
                  RendezvousMessage(index: 0, body: junk),
                  RendezvousMessage(index: 0, body: real_m1),
                ]),
              )

            True ->
              Ok(protocol.RendezvousMessages([RendezvousMessage(0, real_m1)]))
          }
        protocol.CloseRendezvous(..) -> Ok(protocol.RendezvousClosed)
        _ -> Ok(protocol.RendezvousMessages([]))
      }
    })
  let #(failures, record) = recorder()

  let ended =
    pairing.run_inviter(
      primitive_suite.suite(),
      link(fake),
      slot(1, 2),
      waiting(code),
      lifetime_ms,
      record,
    )

  assert ended == Error(pairing.Stalled)
  assert sent_at(calls(fake), 0) == []
  assert closed(calls(fake))
  assert count(failures) == 0
}

/// The joiner's half of the same rule: two answers at index 0, the first
/// malformed, end the run without a confirmation sent.
pub fn a_joiner_steps_once_on_the_first_message_at_an_index_test() {
  let code = code()
  let suite = primitive_suite.suite()
  let inviter = waiting(code)

  let fake =
    start_fake(fn(request, earlier) {
      case request {
        protocol.RendezvousSend(..) -> Ok(protocol.RendezvousSent)

        // The honest answer to whatever `m1` the joiner sent, behind junk
        // the first time and alone after that.
        protocol.RendezvousFetch(after: -1, ..) -> {
          let assert [m1, ..] = sent_at(earlier, 0)
          let assert Ok(#(_, real_m2)) =
            rendezvous.inviter_answer(suite, inviter, m1)
          let junk = RendezvousMessage(index: 0, body: <<0:size(13_552)>>)
          let real = RendezvousMessage(index: 0, body: real_m2)

          case list.any(earlier, is_fetch) {
            False -> Ok(protocol.RendezvousMessages([junk, real]))
            True -> Ok(protocol.RendezvousMessages([real]))
          }
        }

        protocol.CloseRendezvous(..) -> Ok(protocol.RendezvousClosed)
        _ -> Ok(protocol.RendezvousMessages([]))
      }
    })
  let #(failures, record) = recorder()

  let ended =
    pairing.run_joiner(suite, link(fake), slot(3, 4), code, lifetime_ms, record)

  assert ended == Error(pairing.Stalled)
  assert list.length(sent_at(calls(fake), 0)) == 1
  assert sent_at(calls(fake), 1) == []
  assert closed(calls(fake))
  assert count(failures) == 0
}

// ---------------------------------------------------------- m4 is sealed once

/// A suite that tells `seals` about every AEAD seal it makes, and otherwise
/// is the real one.
fn counting_suite(seals: Subject(Nil)) -> Suite {
  let real = primitive_suite.suite()

  Suite(..real, aead_seal: fn(key, nonce, associated, plaintext) {
    process.send(seals, Nil)
    real.aead_seal(key, nonce, associated, plaintext)
  })
}

/// A hand-off whose first send loses its answer is sent again with exactly
/// the bytes of the first, and the inviter sealed it once: the hand-off key
/// and nonce never cover a second plaintext. The joiner then opens it to
/// the ticket, so the run was an honest one.
pub fn a_retried_hand_off_carries_the_bytes_sealed_once_test() {
  let code = code()
  let suite = primitive_suite.suite()
  let #(sent, m1) = honest_join(code)
  let confirmations = process.new_subject()

  let fake =
    start_fake(fn(request, earlier) {
      case request {
        protocol.RendezvousFetch(after: -1, ..) ->
          Ok(protocol.RendezvousMessages([RendezvousMessage(0, m1)]))

        // The joiner's confirmation, made from the inviter's own answer.
        protocol.RendezvousFetch(after: 0, ..) -> {
          let assert [m2] = sent_at(earlier, 0)
          let assert Ok(#(confirmed, m3)) =
            rendezvous.joiner_confirm(suite, sent, m2)
          process.send(confirmations, confirmed)
          Ok(protocol.RendezvousMessages([RendezvousMessage(1, m3)]))
        }

        // The first hand-off's answer is lost; the second is stored.
        protocol.RendezvousSend(index: 1, ..) ->
          case sent_at(earlier, 1) {
            [] -> Error(Nil)
            _ -> Ok(protocol.RendezvousSent)
          }

        protocol.RendezvousSend(..) -> Ok(protocol.RendezvousSent)

        // The joiner has read the hand-off and closed the slot.
        protocol.RendezvousFetch(..) ->
          Ok(protocol.Refused(protocol.Unauthorized))
        protocol.CloseRendezvous(..) ->
          Ok(protocol.Refused(protocol.Unauthorized))
        _ -> Error(Nil)
      }
    })
  let seals = process.new_subject()
  let #(failures, record) = recorder()

  let ended =
    pairing.run_inviter(
      counting_suite(seals),
      link(fake),
      slot(1, 2),
      waiting(code),
      lifetime_ms,
      record,
    )

  assert ended == Ok(Nil)

  let assert [first, second] = sent_at(calls(fake), 1)
  assert first == second
  assert count(seals) == 1
  assert count(failures) == 0

  let assert Ok(confirmed) = process.receive(confirmations, 1000)
  let assert Ok(ticket) = rendezvous.joiner_receive(suite, confirmed, first)
  assert secret.expose(ticket) == <<ticket_text:utf8>>
}

// ------------------------------------------------------------------- time

/// A slot nobody claims holds the inviter for its lifetime on the link's
/// clock and no longer: the run ends `NeverClaimed` once the fake clock
/// passes the lifetime, closes the slot, counts nothing, and no long poll
/// asked the mailbox to hold it past what remained.
pub fn a_run_never_outlives_its_slot_test() {
  // Shorter than a long poll, so a wait the mailbox may hold is bounded by
  // what remains of the slot and not by the protocol's own limit.
  let short_ms = 10_000

  let fake =
    start_fake(fn(request, _) {
      case request {
        protocol.CloseRendezvous(..) -> Ok(protocol.RendezvousClosed)
        _ -> Ok(protocol.RendezvousMessages([]))
      }
    })
  let #(failures, record) = recorder()

  let ended =
    pairing.run_inviter(
      primitive_suite.suite(),
      link(fake),
      slot(1, 2),
      waiting(code()),
      short_ms,
      record,
    )

  assert ended == Error(pairing.NeverClaimed)
  assert closed(calls(fake))
  assert count(failures) == 0

  // The close may rest once more past the deadline; the waits did not.
  assert now(fake) >= short_ms
  assert now(fake) <= short_ms + pairing.close_ms

  let waits =
    list.filter_map(calls(fake), fn(request) {
      case request {
        protocol.RendezvousFetch(wait_seconds:, ..) -> Ok(wait_seconds)
        _ -> Error(Nil)
      }
    })
  assert waits != []
  assert list.all(waits, fn(wait) { wait * 1000 <= short_ms })
}

/// A slot that goes away before any message is a code nobody used, and it
/// is not counted.
pub fn a_slot_gone_before_the_first_message_was_never_claimed_test() {
  let fake =
    start_fake(fn(_, _) { Ok(protocol.Refused(protocol.Unauthorized)) })
  let #(failures, record) = recorder()

  let ended =
    pairing.run_inviter(
      primitive_suite.suite(),
      link(fake),
      slot(1, 2),
      waiting(code()),
      lifetime_ms,
      record,
    )

  assert ended == Error(pairing.NeverClaimed)
  assert count(failures) == 0
}

/// A joiner whose confirmation was stored and answered by nothing, the
/// slot running out or being closed, ends `ConfirmationFailed` and counts
/// it once: an inviter whose check failed sends nothing and closes, so this
/// is how a wrong code looks from the joiner's side.
pub fn a_joiner_whose_confirmation_goes_unanswered_counts_it_test() {
  let code = code()
  let suite = primitive_suite.suite()
  let inviter = waiting(code)

  list.each(
    [
      Ok(protocol.RendezvousMessages([])),
      Ok(protocol.Refused(protocol.Unauthorized)),
    ],
    fn(after_m3) {
      let fake =
        start_fake(fn(request, earlier) {
          case request {
            protocol.RendezvousSend(..) -> Ok(protocol.RendezvousSent)

            protocol.RendezvousFetch(after: -1, ..) -> {
              let assert [m1] = sent_at(earlier, 0)
              let assert Ok(#(_, m2)) =
                rendezvous.inviter_answer(suite, inviter, m1)
              Ok(protocol.RendezvousMessages([RendezvousMessage(0, m2)]))
            }

            protocol.RendezvousFetch(after: 0, ..) -> after_m3
            _ -> Ok(protocol.RendezvousClosed)
          }
        })
      let #(failures, record) = recorder()

      let ended =
        pairing.run_joiner(
          suite,
          link(fake),
          slot(3, 4),
          code,
          lifetime_ms,
          record,
        )

      assert ended == Error(pairing.ConfirmationFailed)
      assert list.length(sent_at(calls(fake), 1)) == 1
      assert count(failures) == 1
    },
  )
}

/// An inviter whose check of `confirm_J` fails ends `ConfirmationFailed`,
/// sends no hand-off, closes the slot and counts the failure once.
pub fn an_inviter_whose_check_fails_counts_it_and_sends_nothing_test() {
  let code = code()
  let suite = primitive_suite.suite()
  let #(_, m1) = honest_join(code)

  // The stranger's confirmation is the right size and the wrong words.
  let assert Ok(other_plate) = nameplate.from_int(482_719)
  let other = pairing_code.generate(suite, other_plate)
  let assert Ok(#(other_sent, _)) = rendezvous.join(suite, other, rid())

  let fake =
    start_fake(fn(request, earlier) {
      case request {
        protocol.RendezvousFetch(after: -1, ..) ->
          Ok(protocol.RendezvousMessages([RendezvousMessage(0, m1)]))

        protocol.RendezvousFetch(after: 0, ..) -> {
          let assert [m2] = sent_at(earlier, 0)
          let assert Ok(#(_, m3)) =
            rendezvous.joiner_confirm(suite, other_sent, m2)
          Ok(protocol.RendezvousMessages([RendezvousMessage(1, m3)]))
        }

        protocol.RendezvousSend(..) -> Ok(protocol.RendezvousSent)
        _ -> Ok(protocol.RendezvousClosed)
      }
    })
  let #(failures, record) = recorder()

  let ended =
    pairing.run_inviter(
      suite,
      link(fake),
      slot(1, 2),
      waiting(code),
      lifetime_ms,
      record,
    )

  assert ended == Error(pairing.ConfirmationFailed)
  assert sent_at(calls(fake), 1) == []
  assert closed(calls(fake))
  assert count(failures) == 1
}

// --------------------------------------------------------------- registry

fn registry() -> mail.Handle(pairing.Message) {
  let name = process.new_name("pairing_test_registry")
  let assert Ok(_) = pairing.start(name, timer.WallClock, poll.monotonic().now)
  mail.direct(name)
}

/// A run that hangs past the registry's deadline is abandoned, its slot is
/// closed for it, and a caller waiting on it hears `Stalled`.
pub fn the_registry_abandons_a_run_at_its_deadline_test() {
  let registry = registry()
  let abandoned = process.new_subject()

  let assert Ok(Nil) =
    pairing.begin(
      registry,
      rid(),
      fn() {
        process.sleep_forever()
        Ok(Nil)
      },
      200,
      fn() { process.send(abandoned, Nil) },
    )

  assert pairing.await(registry, rid(), 10_000)
    == Ok(pairing.Ended(Error(pairing.Stalled)))
  assert process.receive(abandoned, 5000) == Ok(Nil)
}

/// A run's own ending is what a caller hears, before or after it ends, and
/// a run the registry never started is unknown.
pub fn the_registry_reports_how_a_run_ended_test() {
  let registry = registry()
  let assert Ok(other) = id.from_bytes(<<8:128>>)

  let assert Ok(Nil) =
    pairing.begin(
      registry,
      rid(),
      fn() {
        process.sleep(100)
        Error(pairing.ConfirmationFailed)
      },
      10_000,
      fn() { Nil },
    )

  assert pairing.await(registry, rid(), 10_000)
    == Ok(pairing.Ended(Error(pairing.ConfirmationFailed)))
  assert pairing.await(registry, rid(), 1000)
    == Ok(pairing.Ended(Error(pairing.ConfirmationFailed)))
  assert pairing.await(registry, other, 1000) == Ok(pairing.Unknown)
}
