//// End-to-end retransmission (ADR-006) between two real daemons and a real
//// mailbox. The mailbox answers `Appended` and then spoils what it stored:
//// it corrupts the only copy of a message, or loses the receipt for one.
//// The sender's clock is the injected one, so the test lets the receipt
//// window pass at once instead of waiting an hour; the scheduler's own tick
//// notices the due row.
////
//// Both tests show the same two properties from the outside: the message
//// reaches the receiving agent exactly once, and the sender ends at
//// `ReceivedByPeer`.

import core/limits
import core/offer
import daemon/api
import daemon/config
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

/// A sender whose clock the test can move, and a receiver on the wall
/// clock, paired.
fn senders(prefix: String) {
  let mailbox = support.start_mailbox()
  let shift = support.fresh(prefix)
  let settings_a =
    config.Config(
      ..support.daemon_config(mailbox, support.fresh("state")),
      clock: support.shiftable_clock(shift),
    )
  let assert Ok(a) = node.start(settings_a)
  let #(b, settings_b) = support.start_daemon(mailbox)
  let #(at_a, _) = pair(a, b)

  #(mailbox, shift, a, settings_a, b, settings_b, at_a)
}

/// Lets the receipt window pass on the sender's clock.
fn window_passes(shift: String) -> Nil {
  support.shift_clock(shift, limits.receipt_window_seconds + 1)
}

pub fn a_message_the_mailbox_corrupted_is_delivered_once_test() {
  let #(mailbox, shift, a, _, b, settings_b, at_a) = senders("corrupt")

  // B drains its queue (the `Accept`) and goes down, so the message waits
  // at the mailbox.
  let inbox = inbox_of(b)
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
  node.stop(b)

  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"once":utf8>>, None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.StoredByMailbox))
  })

  // The mailbox answered, and now spoils the only copy.
  let assert [stored] = support.stored_in(inbox)
  support.corrupt_stored(mailbox, inbox.queue, stored.envelope)

  // B comes back, cannot decrypt the copy, drops it durably and
  // acknowledges it. Nothing reaches the agent and no receipt is sent.
  let assert Ok(b) = node.start(settings_b)
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
  process.sleep(1000)
  let assert Ok([]) = api.receive(b, None, 10)
  assert api.status(a, sent) == Ok(api.StoredByMailbox)

  // The receipt window passes with no receipt: A sends the same bytes
  // again under a new envelope, and B delivers them.
  window_passes(shift)
  let delivered =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })
  assert list.map(delivered, fn(delivery) { delivery.message }) == [sent]

  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.ReceivedByPeer))
  })

  // Exactly once: B handed the agent the copy and nothing more.
  process.sleep(1500)
  let assert Ok(again) = api.receive(b, None, 10)
  assert list.length(again) == 1
}

pub fn a_lost_receipt_is_regenerated_by_the_retransmit_test() {
  let #(mailbox, shift, a, settings_a, b, settings_b, at_a) = senders("receipt")

  // B goes down so the message waits, and A sends it.
  let inbox_b = inbox_of(b)
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox_b) == [])
  })
  node.stop(b)
  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"hi":utf8>>, None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.StoredByMailbox))
  })

  // A goes down so its receipt waits at the mailbox; B comes back, delivers
  // the message, and queues the receipt to A.
  let inbox_a = inbox_of(a)
  node.stop(a)
  let assert Ok(b) = node.start(settings_b)
  let receipt =
    support.eventually(15_000, fn() {
      case support.stored_in(inbox_a) {
        [stored] -> Some(stored)
        _ -> None
      }
    })
  let assert Ok([_]) = api.receive(b, None, 10)

  // The mailbox loses the receipt after answering for it.
  support.lose_stored(mailbox, inbox_a.queue, receipt.envelope)

  // A is stopped, so nothing else reads its inbox: an empty inbox proves
  // the receipt is gone, and only the retransmit can bring a new one.
  assert support.stored_in(inbox_a) == []

  // A comes back after the window. Its retransmit cannot be decrypted by B
  // (the key is spent), but B knows the ciphertext and answers with the
  // same logical receipt again.
  window_passes(shift)
  let assert Ok(a) = node.start(settings_a)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.ReceivedByPeer))
  })

  // The agent was handed the message once.
  process.sleep(1000)
  let assert Ok(visible) = api.receive(b, None, 10)
  assert list.map(visible, fn(delivery) { delivery.message }) == [sent]
}
