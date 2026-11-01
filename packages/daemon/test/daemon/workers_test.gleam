//// The network workers' timeouts and retries: each test is the one that
//// notices when a deadline, a backoff or a periodic tick is removed (the
//// mutation list is in `packages/daemon/CLAUDE.md`).
////
//// A hanging or refusing carrier is an onion dialer whose dial function the
//// test writes, so nothing here needs Tor or a fake server: the dial
//// function announces itself on a subject, and the test counts dials.

import core/capability
import core/endpoint
import core/envelope
import core/id
import core/offer
import core/route.{type Inbox, Inbox, Route}
import core/time.{Instant}
import daemon/api
import daemon/carrier
import daemon/engine
import daemon/fetcher
import daemon/mail
import daemon/node
import daemon/scheduler
import daemon/status
import daemon/store
import daemon/support
import daemon/transport
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{None, Some}
import gleam/otp/actor
import primitives
import tor
import weft
import weft/timer

fn onion() -> endpoint.Endpoint {
  let assert Ok(address) =
    endpoint.parse_onion(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
    )
  let assert Ok(port) = endpoint.port(80)

  endpoint.Onion(address, port)
}

/// An onion dialer whose dials announce themselves and then hang for a
/// minute, long past any deadline a test sets.
fn hanging_dialer(dials: Subject(Nil)) -> transport.Dialer {
  transport.new_dialer(endpoint.TorOrLoopback, fn(_, _, _, _) {
    process.send(dials, Nil)
    process.sleep(60_000)
    Error(transport.ConnectFailed)
  })
}

/// An onion dialer whose dials announce themselves and fail at once.
fn refusing_dialer(dials: Subject(Nil)) -> transport.Dialer {
  transport.new_dialer(endpoint.TorOrLoopback, fn(_, _, _, _) {
    process.send(dials, Nil)
    Error(transport.ConnectFailed)
  })
}

/// Waits for `count` dials, each within `within_ms` of the one before.
fn await_dials(dials: Subject(Nil), count: Int, within_ms: Int) -> Nil {
  case count {
    0 -> Nil

    _ -> {
      let assert Ok(Nil) = process.receive(dials, within_ms)
        as "a dial that should have happened did not"

      await_dials(dials, count - 1, within_ms)
    }
  }
}

fn outbox_row(number: Int) -> store.OutboxRow {
  let assert Ok(queue) = id.from_bytes(<<1:128>>)
  let assert Ok(envelope_id) = id.from_bytes(<<number:128>>)
  let assert Ok(append) = capability.from_bytes(<<3:256>>)
  let assert Ok(padded) = envelope.pad(<<"sealed":utf8>>)

  store.OutboxRow(
    envelope: envelope_id,
    route: Route(endpoint: onion(), queue:, append:),
    padded:,
    deadline: Instant(100),
    attempts: 0,
  )
}

/// Reads a run's pushes until its end marker.
fn collect(sink: Subject(scheduler.Sent), seen: List(scheduler.Sent)) {
  let assert Ok(pulled) = process.receive(sink, 5000)
    as "the run did not end within its deadline"

  case pulled {
    weft.AllDelivered -> list.reverse(seen)
    weft.PulledOutcome(_) | weft.NotYet | weft.RunLost(_) ->
      collect(sink, [pulled, ..seen])
  }
}

pub fn a_run_of_sends_is_limited_and_ends_at_its_deadline_test() {
  let dials = process.new_subject()
  let config =
    scheduler.Config(
      dialer: hanging_dialer(dials),
      engine: mail.direct(process.new_name("workers_test_engine")),
      status: mail.direct(process.new_name("workers_test_status")),
      clock: fn() { Instant(0) },
      sha256: primitives.sha256,
      send_deadline_ms: 400,
      timer: timer.WallClock,
    )
  let rows = list.map([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], outbox_row)
  let sink = process.new_subject()
  let _relay = scheduler.send_batch(config, rows, sink)

  let pushed = collect(sink, [])

  // Only `max_in_flight` sends got a slot; the deadline abandoned them and
  // the other four never started.
  await_dials(dials, scheduler.max_in_flight, 1000)
  assert process.receive(dials, 100) == Error(Nil)

  let abandoned =
    list.count(pushed, fn(pulled) {
      case pulled {
        weft.PulledOutcome(weft.Abandoned(_)) -> True
        _ -> False
      }
    })
  let never_started =
    list.count(pushed, fn(pulled) {
      case pulled {
        weft.PulledOutcome(weft.NeverStarted(_)) -> True
        _ -> False
      }
    })

  assert abandoned == scheduler.max_in_flight
  assert never_started == 12 - scheduler.max_in_flight
}

/// A daemon with an open offer, and the inbox that offer reads from. The
/// inbox's endpoint is then replaced by an onion one, so a fetcher built on
/// it reaches the network only through the test's dialer.
fn open_inbox() -> #(api.Daemon, Inbox) {
  let mailbox = support.start_mailbox()
  let #(daemon, _) = support.start_daemon(mailbox)
  let assert Ok(_) = api.invite(daemon, "inbox", offer.AutoApprove, 5)
  let assert Ok([inbox]) = engine.live_inboxes(api.engine_handle(daemon))

  #(daemon, Inbox(..inbox, endpoint: onion()))
}

fn fetcher_config(
  daemon: api.Daemon,
  inbox: Inbox,
  dialer: transport.Dialer,
  poll_deadline_ms: Int,
) -> fetcher.Config {
  fetcher.Config(
    dialer:,
    engine: api.engine_handle(daemon),
    status: mail.direct(process.new_name("workers_test_status")),
    inbox:,
    ack_deadline_ms: 5000,
    poll_deadline_ms:,
    timer: timer.WallClock,
  )
}

pub fn a_failed_round_backs_off_and_then_tries_again_test() {
  let #(daemon, inbox) = open_inbox()
  let dials = process.new_subject()
  let assert Ok(_) =
    fetcher.start(fetcher_config(daemon, inbox, refusing_dialer(dials), 5000))

  // Failures wait 500 ms, then a second, then two: three dials need the
  // backoff state to end by itself twice.
  await_dials(dials, 3, 4000)
}

pub fn a_poll_that_hangs_is_abandoned_and_retried_test() {
  let #(daemon, inbox) = open_inbox()
  let dials = process.new_subject()
  let assert Ok(_) =
    fetcher.start(fetcher_config(daemon, inbox, hanging_dialer(dials), 300))

  // The call alone would hold the round for the client's own timeout, far
  // longer than this wait; the run's deadline ends it, and the backoff
  // starts the next round.
  await_dials(dials, 2, 4000)
}

pub fn an_acknowledgement_that_hangs_is_abandoned_and_retried_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, settings_b) = support.start_daemon(mailbox)
  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = active_contact(a)
  let _ = active_contact(b)

  // B finishes acknowledging the `Accept` it processed during pairing, goes
  // down, and misses a message, which then waits in its queue.
  let assert Ok([before]) = engine.live_inboxes(api.engine_handle(b))
  support.eventually(15_000, fn() {
    support.when(support.stored_in(before) == [])
  })
  node.stop(b)
  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"hi":utf8>>, None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.StoredByMailbox))
  })

  // B comes back without workers and commits the envelope by hand, so it
  // owes the mailbox an acknowledgement.
  let assert Ok(offline) = node.start_offline(settings_b)
  let assert Ok([inbox]) = engine.live_inboxes(api.engine_handle(offline))
  let assert [stored] = support.stored_in(inbox)
  assert engine.process(
      api.engine_handle(offline),
      inbox.queue,
      stored.envelope,
      stored.ciphertext,
    )
    == Ok(engine.Fresh)

  // The acknowledgement's call hangs. Only the run's deadline can end it,
  // and the backoff then starts a round that acknowledges again.
  let dials = process.new_subject()
  let config =
    fetcher.Config(
      ..fetcher_config(
        offline,
        Inbox(..inbox, endpoint: onion()),
        hanging_dialer(dials),
        5000,
      ),
      ack_deadline_ms: 300,
    )
  let assert Ok(_) = fetcher.start(config)
  await_dials(dials, 2, 4000)
}

pub fn a_fetcher_for_a_retired_queue_ends_by_itself_test() {
  let #(daemon, inbox) = open_inbox()
  let assert Ok(other) = id.from_bytes(<<9:128>>)
  let dials = process.new_subject()
  let assert Ok(started) =
    fetcher.start(fetcher_config(
      daemon,
      Inbox(..inbox, queue: other),
      refusing_dialer(dials),
      5000,
    ))

  support.eventually(5000, fn() { support.when(!process.is_alive(started.pid)) })

  // It ended before its first call.
  assert process.receive(dials, 100) == Error(Nil)
}

pub fn a_mailbox_that_comes_back_gets_the_sends_and_the_fetches_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)
  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = active_contact(a)
  let _ = active_contact(b)

  // The mailbox goes away. The send commits locally and fails on the
  // network, so it is retried by the periodic scan, not by any nudge.
  support.stop_listener(mailbox)
  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"late":utf8>>, None)
  process.sleep(1500)
  assert api.status(a, sent) == Ok(api.LocallyQueued)

  // Both daemons' fetchers have been failing meanwhile and wait out their
  // backoffs. When the mailbox is back, the scheduler's tick sends and B's
  // fetcher fetches, with nothing told to either.
  let _ = support.restart_listener(mailbox)
  let delivered =
    support.eventually(30_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })

  assert list.map(delivered, fn(delivery) { delivery.message }) == [sent]
}

pub fn an_invitation_made_while_the_mailbox_is_down_is_provisioned_later_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  support.stop_listener(mailbox)

  // `invite` waits for the queue to exist. The nudge's scan fails, and the
  // only thing that can scan again is the provisioner's own timeout.
  let result = process.new_subject()
  process.spawn(fn() {
    process.send(result, api.invite(a, "late", offer.AutoApprove, 5))
  })
  process.sleep(500)
  let _ = support.restart_listener(mailbox)

  let assert Ok(Ok(_)) = process.receive(result, 20_000)
}

fn active_contact(daemon: api.Daemon) {
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(daemon)

    case list.find(views, fn(view) { view.phase == api.Active }) {
      Ok(view) -> Some(view.contact)
      Error(Nil) -> None
    }
  })
}

fn status_cell(tor: status.TorStatus) -> mail.Handle(status.Message) {
  let name = process.new_name("workers_test_status_cell")
  let assert Ok(_) = status.start(name, tor)

  mail.direct(name)
}

fn tor_of(cell: mail.Handle(status.Message)) -> status.TorStatus {
  status.read(cell).tor
}

pub fn a_completed_bootstrap_reports_bootstrapped_test() {
  let cell = status_cell(status.TorStarting)
  let assert Ok(_) =
    carrier.start_with_bootstrap(
      process.new_name("workers_test_carrier"),
      cell,
      fn() { Ok(Nil) },
      5000,
      fn(_) { Nil },
    )

  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorBootstrapped)
  })
}

pub fn a_failed_bootstrap_reports_unavailable_test() {
  let cell = status_cell(status.TorStarting)
  let assert Ok(_) =
    carrier.start_with_bootstrap(
      process.new_name("workers_test_carrier"),
      cell,
      fn() { Error(Nil) },
      5000,
      fn(_) { Nil },
    )

  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorUnavailable)
  })
}

pub fn a_bootstrap_that_hangs_is_abandoned_at_its_deadline_test() {
  let cell = status_cell(status.TorStarting)
  let assert Ok(_) =
    carrier.start_with_bootstrap(
      process.new_name("workers_test_carrier"),
      cell,
      fn() {
        process.sleep(60_000)
        Ok(Nil)
      },
      300,
      fn(_) { Nil },
    )

  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorUnavailable)
  })
}

/// What one scripted bootstrap attempt does.
type Attempt {
  Succeeds
  Fails
  Hangs
}

/// A bootstrap whose successive calls do what `script` says, and announce
/// themselves on `calls`. A call past the end of the script hangs.
fn scripted(
  script: List(Attempt),
  calls: Subject(Nil),
) -> fn() -> Result(Nil, Nil) {
  let assert Ok(started) =
    actor.new(script)
    |> actor.on_message(fn(remaining, reply: Subject(Attempt)) {
      case remaining {
        [next, ..rest] -> {
          process.send(reply, next)
          actor.continue(rest)
        }

        [] -> {
          process.send(reply, Hangs)
          actor.continue([])
        }
      }
    })
    |> actor.start

  fn() {
    let attempt = actor.call(started.data, 1000, fn(reply) { reply })
    process.send(calls, Nil)

    case attempt {
      Succeeds -> Ok(Nil)
      Fails -> Error(Nil)
      Hangs -> {
        process.sleep(60_000)
        Ok(Nil)
      }
    }
  }
}

fn carrier_with(
  script: List(Attempt),
) -> #(mail.Handle(status.Message), Subject(Nil), Subject(tor.Event)) {
  let cell = status_cell(status.TorStarting)
  let calls = process.new_subject()
  let handoff = process.new_subject()
  let assert Ok(_) =
    carrier.start_with_bootstrap(
      process.new_name("workers_test_carrier"),
      cell,
      scripted(script, calls),
      60_000,
      process.send(handoff, _),
    )
  let assert Ok(events) = process.receive(handoff, 1000)

  #(cell, calls, events)
}

pub fn a_restarted_sidecar_is_bootstrapped_again_test() {
  let #(cell, calls, events) = carrier_with([Succeeds, Succeeds])
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorBootstrapped)
  })
  await_dials(calls, 1, 1000)

  // The replacement sidecar is not bootstrapped, so a second run starts and
  // the carrier does not claim to be ready in the meantime.
  process.send(events, tor.SidecarRestarted)
  await_dials(calls, 1, 5000)
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorBootstrapped)
  })
}

pub fn a_restart_that_fails_to_bootstrap_is_unavailable_test() {
  let #(cell, calls, events) = carrier_with([Succeeds, Fails, Succeeds])
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorBootstrapped)
  })

  process.send(events, tor.SidecarRestarted)
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorUnavailable)
  })
  await_dials(calls, 2, 1000)

  // A later restart is a new chance: `Unavailable` is not terminal for a
  // sidecar that comes back.
  process.send(events, tor.SidecarRestarted)
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorBootstrapped)
  })
}

pub fn a_restart_during_a_bootstrap_starts_a_new_run_test() {
  let #(cell, calls, events) = carrier_with([Hangs, Succeeds])
  await_dials(calls, 1, 1000)
  assert tor_of(cell) == status.TorStarting

  // The first run is stuck. The restart replaces it, and the new run's
  // answer is the one the carrier believes.
  process.send(events, tor.SidecarRestarted)
  await_dials(calls, 1, 5000)
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorBootstrapped)
  })
}

pub fn a_sidecar_that_is_given_up_on_makes_the_carrier_unavailable_test() {
  let #(cell, _calls, events) = carrier_with([Succeeds])
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorBootstrapped)
  })

  // A death alone decides nothing; giving up does.
  process.send(events, tor.SidecarDied(1))
  process.sleep(200)
  assert tor_of(cell) == status.TorBootstrapped

  process.send(events, tor.SidecarGaveUp)
  support.eventually(5000, fn() {
    support.when(tor_of(cell) == status.TorUnavailable)
  })
}
