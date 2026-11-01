//// A poison envelope, between two real daemons and a real mailbox
//// (ADR-010). The receiver's database refuses every delivery, through a
//// trigger the test installs behind its back, so the sender's message can
//// never commit: each attempt fails and the fetcher retries the same
//// envelope. Before quarantine it blocked its queue for good.
////
//// After `limits.max_process_attempts` failures the receiver sets the
//// envelope aside: it records an incident, drops the envelope and
//// acknowledges it. Nothing of the relationship changed, so once the
//// database is healed the sender's retransmit (ADR-006), which it sends
//// because no receipt came, is processed fresh and delivered once.

import core/limits
import core/offer
import core/secret
import daemon/api
import daemon/config
import daemon/engine
import daemon/node
import daemon/support
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

/// Runs `statement` against a daemon's database from outside it.
fn tamper(settings: config.Config, statement: String) -> Nil {
  let path = settings.state_dir <> "/" <> node.database_file
  let assert Ok(connection) = sqlight.open(path)

  // The daemon may be mid-commit; wait for its write lock as it would.
  let assert Ok(Nil) = sqlight.exec("PRAGMA busy_timeout=5000", connection)
  let assert Ok(Nil) = sqlight.exec(statement, connection)
  let assert Ok(Nil) = sqlight.close(connection)

  Nil
}

pub fn a_poison_envelope_is_quarantined_and_its_retransmit_delivered_test() {
  let mailbox = support.start_mailbox()
  let shift = support.fresh("poison")
  let settings_a =
    config.Config(
      ..support.daemon_config(mailbox, support.fresh("state")),
      clock: support.shiftable_clock(shift),
    )
  let assert Ok(a) = node.start(settings_a)
  let #(b, settings_b) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = active_contact(a)
  let _ = active_contact(b)
  let assert Ok([inbox_b]) = engine.live_inboxes(api.engine_handle(b))

  // Every delivery B tries to commit now fails, so the message is poison.
  tamper(
    settings_b,
    "CREATE TRIGGER poison BEFORE INSERT ON deliveries
     BEGIN SELECT RAISE(ABORT, 'poisoned'); END;",
  )
  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"once":utf8>>, None)

  // B fails it the bounded number of times, then sets it aside: the
  // incident names the count and the queue drains.
  let incident =
    support.eventually(40_000, fn() {
      let assert Ok(found) = api.incidents(b, 10)
      list.find(found, fn(found) { found.kind == api.QuarantinedEnvelope })
      |> option.from_result
    })
  assert incident.attempts == Some(limits.max_process_attempts)
  assert incident.contact != None
  assert incident.message == None
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox_b) == [])
  })
  let assert Ok([]) = api.receive(b, None, 10)
  assert api.status(a, sent) == Ok(api.StoredByMailbox)

  // B's database heals. A heard no receipt, so once the window passes it
  // sends the same ciphertext again, and B, whose session never advanced
  // past the poisoned attempts, delivers it.
  tamper(settings_b, "DROP TRIGGER poison;")
  support.shift_clock(shift, limits.receipt_window_seconds + 1)
  support.eventually(30_000, fn() {
    support.when(api.status(a, sent) == Ok(api.ReceivedByPeer))
  })

  let assert Ok(delivered) = api.receive(b, None, 10)
  assert list.map(delivered, fn(d) { secret.expose(d.payload) })
    == [<<"once":utf8>>]
}
