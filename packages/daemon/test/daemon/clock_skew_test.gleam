//// A daemon whose clock disagrees with the mailbox's (ADR-008), between two
//// real daemons and a real mailbox. The mailbox accepts a retention
//// deadline no later than its own `now + message_retention_seconds`, so a
//// sender whose clock runs ahead used to be refused `BadDeadline` for
//// every row, `Accept` included, and the refusal failed the row for good.
////
//// Three cases, each from the outside: a sender ahead by the whole slack is
//// stored on the first offer; a sender further ahead is stored under a
//// shortened deadline; and a mailbox no offer can satisfy leaves the row
//// queued, not failed, until its clock is corrected.

import core/limits
import core/offer
import core/time
import daemon/api
import daemon/config
import daemon/engine
import daemon/node
import daemon/support
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}

/// Pairs two daemons with a preapproved invitation from `a` and waits for
/// both to be active, which needs `a`'s `Accept` to be stored. Returns the
/// contact `a` holds for `b`.
fn pair(a: api.Daemon, b: api.Daemon) {
  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = active_contact(a)
  let _ = active_contact(b)

  at_a
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

/// A sender whose clock leads the mailbox's by `ahead` seconds from the
/// start, and a receiver on the mailbox's clock, paired.
fn ahead_by(ahead: Int, prefix: String) {
  let mailbox = support.start_mailbox()
  let shift = support.fresh(prefix)
  support.shift_clock(shift, ahead)

  let settings_a =
    config.Config(
      ..support.daemon_config(mailbox, support.fresh("state")),
      clock: support.shiftable_clock(shift),
    )
  let assert Ok(a) = node.start(settings_a)
  let #(b, settings_b) = support.start_daemon(mailbox)
  let at_a = pair(a, b)

  #(a, b, settings_b, at_a)
}

/// Sends one message from `a` while `b` is down, so the mailbox still holds
/// it, and returns its message id and the retention deadline the mailbox
/// stored it under. Then brings `b` back and waits for the receipt.
fn stored_deadline(a: api.Daemon, b: api.Daemon, settings_b, at_a) {
  let inbox = inbox_of(b)
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
  node.stop(b)

  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"skew":utf8>>, None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.StoredByMailbox))
  })
  let assert [stored] = support.stored_in(inbox)

  // The message is delivered and receipted as if the clocks agreed.
  let assert Ok(b) = node.start(settings_b)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.ReceivedByPeer))
  })
  let assert Ok(delivered) = api.receive(b, None, 10)
  assert list.map(delivered, fn(delivery) { delivery.message }) == [sent]

  stored.retention_deadline
}

pub fn a_sender_ahead_by_the_slack_is_stored_on_the_first_offer_test() {
  let #(a, b, settings_b, at_a) =
    ahead_by(limits.retention_slack_seconds, "skew_slack")
  let deadline = stored_deadline(a, b, settings_b, at_a)

  // The first offer is `now + retention - slack` by the sender's clock,
  // which is the mailbox's own maximum. A shortened offer would be days
  // earlier.
  let floor =
    time.add(
      support.now(),
      limits.message_retention_seconds - limits.retention_slack_seconds,
    )
  assert deadline.unix_seconds >= floor.unix_seconds
}

pub fn a_sender_further_ahead_is_stored_under_a_shorter_deadline_test() {
  // Two days ahead: the first offer is refused, and a halved one fits.
  let ahead = 2 * 86_400
  let #(a, b, settings_b, at_a) = ahead_by(ahead, "skew_days")
  let deadline = stored_deadline(a, b, settings_b, at_a)
  let latest = time.add(support.now(), limits.message_retention_seconds)

  assert deadline.unix_seconds
    < latest.unix_seconds - limits.retention_slack_seconds
  assert deadline.unix_seconds > support.now().unix_seconds
}

pub fn a_row_no_offer_fits_waits_for_the_clock_to_be_corrected_test() {
  let shift = support.fresh("skew_mailbox")
  let mailbox = support.start_mailbox_on(support.shiftable_clock(shift))
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)
  let at_a = pair(a, b)

  // The mailbox's clock falls thirty days behind: every offer is past its
  // window, so each attempt ends in `BadDeadline` after the last offer.
  support.shift_clock(shift, -30 * 86_400)
  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"late":utf8>>, None)

  // The row is retried, not failed: it stays queued across attempts.
  process.sleep(3000)
  assert api.status(a, sent) == Ok(api.LocallyQueued)

  // The clock is put right, and the next retry is stored and delivered.
  support.shift_clock(shift, 0)
  support.eventually(30_000, fn() {
    support.when(api.status(a, sent) == Ok(api.ReceivedByPeer))
  })
  let assert Ok(delivered) = api.receive(b, None, 10)
  assert list.map(delivered, fn(delivery) { delivery.message }) == [sent]
}
