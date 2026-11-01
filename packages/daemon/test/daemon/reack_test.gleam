//// An envelope the mailbox serves again after the receiver acknowledged
//// it, under the same identifier and bytes, is acknowledged again
//// (ADR-010, addendum; found by the P model, `docs/formal/p.md`).
////
//// Two real daemons and a real mailbox. B goes down while A sends sixteen
//// messages, a full fetch batch; B comes back, delivers them and
//// acknowledges them. Then the mailbox brings all sixteen back, in one of
//// the two ways it can:
////
//// - restored from a backup taken before the acknowledgement: the same
////   rows at the head of the queue, their tombstones gone;
//// - stored again by the sender's late retry: the tombstones swept once
////   their retention deadline passed, and A's own `Append` requests sent
////   again, which the mailbox takes as new.
////
//// Then A sends a seventeenth. Before the fix, B answered each zombie
//// `Repeat`, committed nothing, and never named it in an acknowledgement
//// again, because its processed row was already acknowledged; the mailbox
//// returned the same sixteen oldest envelopes to every fetch, so the
//// seventeenth was never delivered and the queue never drained. Now the
//// repeat marks the row unacknowledged, the next round acknowledges it,
//// the seventeenth arrives, and the agent sees every message once.

import core/envelope
import core/id
import core/mailbox/protocol
import core/offer
import core/route
import core/secret
import core/time
import daemon/api
import daemon/engine
import daemon/mailbox_client
import daemon/node
import daemon/support
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import gleam/set
import sqlight

/// How many messages come back: one whole fetch batch, so a fetch that
/// returns only them hides everything queued behind.
const zombies = 16

/// The world after B delivered and acknowledged A's sixteen messages.
type Delivered {
  Delivered(
    mailbox: support.Mailbox,
    a: api.Daemon,
    b: api.Daemon,
    contact: id.Id(id.Contact),
    inbox: route.Inbox,
    sent: List(id.Id(id.Message)),
    backup: List(support.BackedUp),
    appends: List(protocol.Request),
  )
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

/// The payloads the agent behind `daemon` can read, in order.
fn readable(daemon: api.Daemon) -> List(BitArray) {
  let assert Ok(found) = api.receive(daemon, None, 50)
  list.map(found, fn(delivery) { secret.expose(delivery.payload) })
}

/// A's committed application rows as the `Append` requests its scheduler
/// sent, read from its database: what a retry would send again.
fn outbox_appends(directory: String) -> List(protocol.Request) {
  let assert Ok(connection) = sqlight.open(directory <> "/daemon.db")
  let assert Ok(found) =
    sqlight.query(
      "SELECT envelope, route, padded, deadline FROM outbox
       WHERE kind = 'application' ORDER BY rowid",
      connection,
      [],
      {
        use envelope <- decode.field(0, decode.bit_array)
        use target <- decode.field(1, decode.bit_array)
        use padded <- decode.field(2, decode.bit_array)
        use deadline <- decode.field(3, decode.int)
        decode.success(#(envelope, target, padded, deadline))
      },
    )
  let assert Ok(Nil) = sqlight.close(connection)

  list.map(found, fn(row) {
    let #(envelope_bytes, route_bytes, padded_bytes, deadline) = row
    let assert Ok(envelope_id) = id.from_bytes(envelope_bytes)
    let assert Ok(target) = route.decode(route_bytes)
    let assert Ok(padded) = envelope.from_wire(padded_bytes)

    protocol.Append(
      queue: target.queue,
      append: target.append,
      envelope: envelope_id,
      retention_deadline: time.Instant(deadline),
      ciphertext: padded,
    )
  })
}

/// Pairs A and B, has A send sixteen messages while B is down, backs B's
/// queue up, and lets B deliver and acknowledge them.
fn delivered_and_acknowledged() -> Delivered {
  let mailbox = support.start_mailbox()
  let #(a, settings_a) = support.start_daemon(mailbox)
  let #(b, settings_b) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 100)
  let assert Ok(_) = api.accept(b, file, "a")
  let contact = active_contact(a)
  let _ = active_contact(b)
  let assert Ok([inbox]) = engine.live_inboxes(api.engine_handle(b))

  // B drains its queue and goes down, so A's messages wait at the mailbox
  // where the backup can see them.
  support.eventually(15_000, fn() {
    support.when(support.stored_in(inbox) == [])
  })
  node.stop(b)

  let sent =
    int.range(from: 1, to: zombies + 1, with: [], run: list.prepend)
    |> list.reverse
    |> list.map(fn(n) {
      let payload = <<"zombie ":utf8, int.to_string(n):utf8>>
      let assert Ok(sent) = api.send(a, contact, "text/plain", payload, None)
      sent
    })
  support.eventually(15_000, fn() {
    support.when(
      list.all(sent, fn(message) {
        api.status(a, message) == Ok(api.StoredByMailbox)
      }),
    )
  })

  let backup = support.back_up_queue(mailbox, inbox.queue)
  assert list.length(backup) == zombies
  let appends = outbox_appends(settings_a.state_dir)
  assert list.length(appends) == zombies

  // B comes back, delivers all sixteen and acknowledges them: the mailbox
  // holds nothing for the queue but tombstones.
  let assert Ok(b) = node.start(settings_b)
  support.eventually(20_000, fn() {
    support.when(
      list.length(readable(b)) == zombies && support.stored_in(inbox) == [],
    )
  })

  Delivered(mailbox:, a:, b:, contact:, inbox:, sent:, backup:, appends:)
}

/// With the sixteen back at the mailbox, A sends one more. It is delivered,
/// the queue drains, and the agent sees each of the seventeen once.
fn the_queue_moves_on(world: Delivered) -> Nil {
  let assert Ok(behind) =
    api.send(world.a, world.contact, "text/plain", <<"behind":utf8>>, None)

  // The seventeenth sits behind sixteen envelopes the mailbox serves first;
  // it arrives only once they are acknowledged again.
  support.eventually(40_000, fn() {
    support.when(list.contains(readable(world.b), <<"behind":utf8>>))
  })
  support.eventually(15_000, fn() {
    support.when(support.stored_in(world.inbox) == [])
  })
  support.eventually(15_000, fn() {
    support.when(api.status(world.a, behind) == Ok(api.ReceivedByPeer))
  })

  // Every message once: the zombies were acknowledged, never delivered
  // again.
  process.sleep(1500)
  let assert Ok(found) = api.receive(world.b, None, 50)
  let messages = list.map(found, fn(delivery) { delivery.message })
  assert list.length(messages) == zombies + 1
  assert set.from_list(messages) == set.from_list([behind, ..world.sent])
}

pub fn a_restored_mailbox_is_acknowledged_again_test() {
  let world = delivered_and_acknowledged()

  // The mailbox is restored from the backup: the sixteen rows return under
  // their old sequence numbers, at the head of the queue.
  support.restore_backup(world.mailbox, world.backup)
  assert list.length(support.stored_in(world.inbox)) == zombies

  the_queue_moves_on(world)
}

pub fn a_late_retry_is_acknowledged_again_test() {
  let world = delivered_and_acknowledged()

  // The tombstones' retention deadline passes and the sweep removes them;
  // the sender's retries of the same envelopes then land as new ones.
  support.sweep_tombstones(world.mailbox, world.inbox.queue)
  list.each(world.appends, fn(request) {
    let assert protocol.Append(queue:, ..) = request
    let assert Ok(protocol.Appended(_)) =
      mailbox_client.call(
        support.loopback_dialer(),
        world.inbox.endpoint,
        mailbox_client.isolation_group(queue),
        request,
        5000,
      )
  })

  the_queue_moves_on(world)
}
