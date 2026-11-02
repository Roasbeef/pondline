//// Crash and restart: a daemon that dies between the commit and the network
//// step resumes from committed state, delivering exactly once and
//// acknowledging only what it committed (spec §12.2, §13.1).

import core/offer
import core/secret
import daemon/api
import daemon/engine
import daemon/node
import daemon/support
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}

/// Pairs two daemons with a preapproved invitation and waits for both to be
/// active. Returns the contact each holds for the other.
fn pair(a: api.Daemon, b: api.Daemon) {
  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(at_b) = api.accept(b, file, "a")
  let at_a = active_contact(a)
  let _ = active_contact(b)

  #(at_a, at_b)
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

fn inbox_of(daemon: api.Daemon) {
  let assert Ok([inbox]) = engine.live_inboxes(api.engine_handle(daemon))
  inbox
}

pub fn a_committed_send_is_delivered_once_after_a_restart_test() {
  let mailbox = support.start_mailbox()
  let #(a, settings_a) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)
  let #(at_a, _) = pair(a, b)

  // A restarts with no network workers, so its send commits and nothing
  // leaves the machine.
  node.stop(a)
  let assert Ok(offline) = node.start_offline(settings_a)
  let assert Ok(sent) =
    api.send(offline, at_a, "text/plain", secret.new(<<"once":utf8>>), None)

  assert api.status(offline, sent) == Ok(api.LocallyQueued)
  assert api.health(offline).outbox_pending == 1
  process.sleep(500)
  let assert Ok([]) = api.receive(b, None, 10)

  // The daemon dies there. The next start finds the committed row and sends
  // it.
  node.stop(offline)
  let assert Ok(online) = node.start(settings_a)

  let delivered =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })
  assert list.map(delivered, fn(delivery) { delivery.message }) == [sent]

  // Exactly once: the retry path resent the same bytes and nothing more.
  process.sleep(1500)
  let assert Ok(again) = api.receive(b, None, 10)
  assert list.length(again) == 1

  support.eventually(15_000, fn() {
    support.when(api.status(online, sent) == Ok(api.ReceivedByPeer))
  })
}

pub fn a_processed_envelope_is_acknowledged_after_a_restart_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, settings_b) = support.start_daemon(mailbox)
  let #(at_a, _) = pair(a, b)

  // B is down while A sends, so the envelope waits in B's queue. B first
  // finishes acknowledging the `Accept` it processed during pairing, so the
  // queue holds only the new envelope.
  let before = inbox_of(b)
  support.eventually(15_000, fn() {
    support.when(support.stored_in(before) == [])
  })
  node.stop(b)
  let assert Ok(sent) =
    api.send(a, at_a, "text/plain", secret.new(<<"hi":utf8>>), None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.StoredByMailbox))
  })

  // B comes back without fetchers, and processes the envelope by hand:
  // committed, never acknowledged.
  let assert Ok(offline) = node.start_offline(settings_b)
  let inbox = inbox_of(offline)
  let assert [stored] = support.stored_in(inbox)
  let name = api.engine_handle(offline)

  assert engine.process(name, inbox.queue, stored.envelope, stored.ciphertext)
    == Ok(engine.Fresh)
  assert engine.process(name, inbox.queue, stored.envelope, stored.ciphertext)
    == Ok(engine.Repeat)
  let assert Ok([_]) = api.receive(offline, None, 10)
  assert list.length(support.stored_in(inbox)) == 1

  // The daemon dies between the commit and the acknowledgement.
  node.stop(offline)
  let assert Ok(online) = node.start(settings_b)

  // The fetcher acknowledges the committed envelope, and the agent is not
  // handed it a second time.
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
  process.sleep(1000)
  let assert Ok(visible) = api.receive(online, None, 10)
  assert list.length(visible) == 1

  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.ReceivedByPeer))
  })
}

pub fn nothing_is_sent_when_the_commit_fails_test() {
  let mailbox = support.start_mailbox()
  let #(a, settings_a) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)
  let #(at_a, _) = pair(a, b)

  // With the database locked from outside, the commit cannot happen.
  let held = support.hold_database(settings_a.state_dir)
  assert api.send(a, at_a, "text/plain", secret.new(<<"never":utf8>>), None)
    == Error(api.Unavailable)

  // The ciphertext for that failed commit must not have reached B.
  process.sleep(2000)
  support.release_database(held)
  let assert Ok([]) = api.receive(b, None, 10)

  // The ratchet did not advance, so the next send works and arrives once.
  let assert Ok(sent) =
    api.send(a, at_a, "text/plain", secret.new(<<"later":utf8>>), None)
  let delivered =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })
  assert list.map(delivered, fn(delivery) { delivery.message }) == [sent]
}

pub fn an_envelope_stays_in_the_mailbox_until_its_commit_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, settings_b) = support.start_daemon(mailbox)
  let #(at_a, _) = pair(a, b)
  let inbox = inbox_of(b)

  // B cannot commit while its database is held.
  let held = support.hold_database(settings_b.state_dir)
  let assert Ok(sent) =
    api.send(a, at_a, "text/plain", secret.new(<<"hold":utf8>>), None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.StoredByMailbox))
  })
  process.sleep(1500)

  // B fetched it and could not commit, so it must not have acknowledged it.
  assert list.length(support.stored_in(inbox)) == 1
  support.release_database(held)

  // Once the lock is gone the retry commits, delivers and acknowledges.
  let assert [delivery] =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })
  assert delivery.message == sent
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
}
