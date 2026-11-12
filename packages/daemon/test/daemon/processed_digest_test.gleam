//// An envelope counts as already processed only when both its identifier and
//// its digest match its `Processed` row (spec §8.3, `core/plan`).
////
//// When a corrupted copy of an envelope is fetched first, the core refuses
//// it and the engine commits `Processed(queue, envelope, sha256(bad),
//// Dropped)` so the fetcher acknowledges and clears it. If the intact bytes
//// later arrive under the same envelope identifier (from a restored backup
//// or a late sender retry after the tombstone expired), the differing digest
//// forces the engine through `attempt` rather than `Repeat`, delivering the
//// message once.

import core/id
import core/offer
import core/secret
import daemon/api
import daemon/engine
import daemon/node
import daemon/support
import gleam/list
import gleam/option.{None, Some}

fn active_contact(daemon: api.Daemon) -> id.Id(id.Contact) {
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(daemon)

    case list.find(views, fn(view) { view.phase == api.Active }) {
      Ok(view) -> Some(view.contact)
      Error(Nil) -> None
    }
  })
}

fn readable(daemon: api.Daemon) -> List(BitArray) {
  let assert Ok(found) = api.receive(daemon, None, 10)
  list.map(found, fn(delivery) { secret.expose(delivery.payload) })
}

pub fn differing_digest_under_processed_id_is_attempted_test() {
  let mailbox = support.start_mailbox()
  let #(a, _settings_a) = support.start_daemon(mailbox)
  let #(b, settings_b) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 100)
  let assert Ok(_) = api.accept(b, file, "a")
  let contact = active_contact(a)
  let _ = active_contact(b)
  let assert Ok([inbox]) = engine.live_inboxes(api.engine_handle(b))

  // Drain handshake traffic and stop B so A's application envelope rests at
  // the mailbox where we can copy its intact bytes and then corrupt them.
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
  node.stop(b)

  let payload = <<"intact after bad copy":utf8>>
  let assert Ok(sent) =
    api.send(a, contact, "text/plain", secret.new(payload), None)
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.StoredByMailbox))
  })

  let intact_backup = support.back_up_queue(mailbox, inbox.queue)
  let assert [stored] = support.stored_in(inbox)
  support.corrupt_stored(mailbox, inbox.queue, stored.envelope)

  // B starts, fetches the damaged envelope, drops it as undecryptable,
  // commits `Processed` with the damaged digest, and acknowledges the queue.
  let assert Ok(b) = node.start(settings_b)
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
  assert readable(b) == []

  // Stop B so the backup restore does not sit behind a parked 25-second long
  // poll, then restore the intact ciphertext under the same envelope id.
  // Because its digest differs from the stored `Processed` row, B runs it
  // through the core instead of treating it as a `Repeat`.
  node.stop(b)
  support.restore_backup(mailbox, intact_backup)
  let assert Ok(b) = node.start(settings_b)
  support.eventually(15_000, fn() {
    support.when(readable(b) == [payload] && support.stored_in(inbox) == [])
  })
  support.eventually(15_000, fn() {
    support.when(api.status(a, sent) == Ok(api.ReceivedByPeer))
  })

  node.stop(a)
  node.stop(b)
}
