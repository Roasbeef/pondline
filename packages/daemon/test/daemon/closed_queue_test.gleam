//// A relationship that closes under its fetcher still has its last
//// envelopes acknowledged (the DST's `closed_queue_unacked` policy gap).
////
//// The fetcher acknowledges what the store committed at the start of each
//// round, and used to check whether its queue was still live before that,
//// so a batch whose last envelope closed the relationship was processed,
//// committed and never acknowledged: the mailbox kept it until retention.
//// Now the acknowledgement comes first and liveness after it, and a retired
//// queue a restart left owing acknowledgements gets a fetcher that pays
//// them and stops.

import core/offer
import daemon/api
import daemon/config
import daemon/engine
import daemon/node
import daemon/support
import gleam/dynamic/decode
import gleam/list
import gleam/option.{None, Some}
import sqlight

fn active_contact(daemon: api.Daemon) {
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(daemon)

    case list.find(views, fn(view) { view.phase == api.Active }) {
      Ok(view) -> Some(view.contact)
      Error(Nil) -> None
    }
  })
}

fn database(settings: config.Config) -> sqlight.Connection {
  let path = settings.state_dir <> "/" <> node.database_file
  let assert Ok(connection) = sqlight.open(path)
  connection
}

/// How many processed envelopes the daemon has not acknowledged.
fn unacked(settings: config.Config) -> Int {
  let connection = database(settings)
  let assert Ok([count]) =
    sqlight.query(
      "SELECT COUNT(*) FROM processed WHERE acked = 0",
      on: connection,
      with: [],
      expecting: decode.at([0], decode.int),
    )
  let assert Ok(Nil) = sqlight.close(connection)

  count
}

/// B is down while A sends a message and closes, so B's first poll after
/// it comes back returns both in one batch, and the `Close` retires the
/// queue in the same round that processed them.
fn closed_in_one_batch() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, settings_b) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = active_contact(a)
  let _ = active_contact(b)
  let assert Ok([inbox_b]) = engine.live_inboxes(api.engine_handle(b))
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox_b) == [])
  })
  node.stop(b)

  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"bye":utf8>>, None)
  let assert Ok(Nil) = api.close(a, at_a)
  support.eventually(15_000, fn() {
    support.when(list.length(support.stored_in(inbox_b)) == 2)
  })
  let _ = sent

  let assert Ok(b) = node.start(settings_b)
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(b)
    support.when(list.all(views, fn(view) { view.phase == api.Closed }))
  })

  #(b, settings_b, inbox_b)
}

pub fn a_closing_batch_is_acknowledged_before_the_fetcher_retires_test() {
  let #(_, settings_b, inbox_b) = closed_in_one_batch()

  // Both envelopes were committed, and both leave the mailbox.
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox_b) == [])
  })
  support.eventually(15_000, fn() { support.when(unacked(settings_b) == 0) })
}

pub fn a_retired_queue_owing_acknowledgements_is_drained_after_a_restart_test() {
  let #(b, settings_b, inbox_b) = closed_in_one_batch()
  support.eventually(15_000, fn() { support.when(unacked(settings_b) == 0) })
  node.stop(b)

  // As if B had stopped after committing the batch and before the fetcher
  // acknowledged it: the queue is retired and its rows are owed.
  let connection = database(settings_b)
  let assert Ok(Nil) =
    sqlight.exec("UPDATE processed SET acked = 0", connection)
  let assert Ok(Nil) = sqlight.close(connection)
  assert unacked(settings_b) > 0

  // Nothing fetches a closed relationship's queue, yet the restarted daemon
  // pays what it owes.
  let assert Ok(_) = node.start(settings_b)
  support.eventually(15_000, fn() { support.when(unacked(settings_b) == 0) })
  assert support.stored_in(inbox_b) == []
}
