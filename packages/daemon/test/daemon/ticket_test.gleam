//// Pairing by ticket (ADR-009), between two real daemons and a real
//// mailbox: the inviter stores the sealed invitation at its own mailbox
//// and hands out a short ticket; the joiner fetches, opens and imports it.
//// Then the cases a mailbox or an operator can get wrong: a mailbox that
//// answers with another ticket's invitation, a ticket whose invitation has
//// expired, a ticket for nothing, a mistyped one, and a ticket whose
//// mailbox the joiner's carrier policy does not allow.

import core/capability
import core/endpoint
import core/id
import core/mailbox/protocol
import core/offer
import core/secret.{type Secret}
import core/ticket
import core/time
import daemon/api
import daemon/config
import daemon/node
import daemon/support
import gleam/bit_array
import gleam/dynamic/decode
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import mailbox/node as mailbox_node
import primitives
import primitives/suite
import simplifile
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

fn text(ticket: Secret) -> String {
  let assert Ok(text) = bit_array.to_string(secret.expose(ticket))
  text
}

/// The locator a ticket's sealed invitation is stored under.
fn locator(ticket: Secret) -> BitArray {
  let assert Ok(made) = ticket.decode(text(ticket))
  let assert Ok(keys) = ticket.keys(suite.suite(), made)
  id.to_bytes(keys.locator)
}

/// Replaces the sealed bytes stored for `victim` with those stored for
/// `donor`, behind the mailbox's back: a mailbox answering one ticket with
/// another ticket's invitation.
fn substitute_blob(mailbox: support.Mailbox, victim: Secret, donor: Secret) {
  let assert Ok(connection) = sqlight.open(mailbox.path)
  let assert Ok(Nil) = sqlight.exec("PRAGMA busy_timeout=5000", connection)
  let assert Ok([sealed]) =
    sqlight.query(
      "SELECT sealed FROM blobs WHERE blob_id = ?",
      on: connection,
      with: [sqlight.blob(locator(donor))],
      expecting: decode.field(0, decode.bit_array, decode.success),
    )
  let assert Ok(_) =
    sqlight.query(
      "UPDATE blobs SET sealed = ? WHERE blob_id = ?",
      on: connection,
      with: [sqlight.blob(sealed), sqlight.blob(locator(victim))],
      expecting: decode.success(Nil),
    )
  let assert Ok(Nil) = sqlight.close(connection)

  Nil
}

/// Create with a ticket, accept with the ticket, pair, and exchange a
/// message: the whole path a copy-pasted ticket stands for.
pub fn a_ticket_pairs_two_daemons_and_a_message_crosses_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(issued) =
    api.invite_ticket(a, "by ticket", offer.AutoApprove, 5)
  assert string.starts_with(text(issued.ticket), "rw1p")
  assert string.length(text(issued.ticket)) == 74

  // A pasted ticket arrives with a newline; that is not part of it.
  let pasted = secret.new(<<text(issued.ticket):utf8, "\n":utf8>>)
  let assert Ok(at_b) = api.accept_ticket(b, pasted, "inviter")

  let at_a = active_contact(a)
  assert active_contact(b) == at_b

  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<"hi":utf8>>, None)
  let delivered =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)

      case found {
        [] -> None
        [first, ..] -> Some(first)
      }
    })

  assert delivered.message == sent
  assert secret.expose(delivered.payload) == <<"hi":utf8>>

  let _ = node.stop(a)
  let _ = node.stop(b)
}

/// A mailbox that answers a ticket with another ticket's invitation is
/// caught before anything is imported: the blob does not open under the
/// ticket's key.
pub fn a_mailbox_that_returns_another_invitation_is_refused_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(meant) = api.invite_ticket(a, "meant", offer.AutoApprove, 5)
  let assert Ok(other) = api.invite_ticket(a, "other", offer.AutoApprove, 5)
  substitute_blob(mailbox, meant.ticket, other.ticket)

  assert api.accept_ticket(b, meant.ticket, "x")
    == Error(api.InvalidInvitation(
      "the mailbox returned an invitation this ticket does not open",
    ))
  assert api.contacts(b) == Ok([])

  // The other ticket still names its own, untouched invitation.
  let assert Ok(_) = api.accept_ticket(b, other.ticket, "x")

  let _ = node.stop(a)
  let _ = node.stop(b)
}

/// Once the invitation's deadline has passed by the mailbox's clock, the
/// blob is gone for every purpose, and accepting fails with a reason and
/// no ticket in it.
pub fn an_expired_ticket_fails_cleanly_test() {
  let shift = support.fresh("ticket_expiry")
  let mailbox = support.start_mailbox_on(support.shiftable_clock(shift))
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(issued) = api.invite_ticket(a, "late", offer.AutoApprove, 5)

  // Two days later by the mailbox's clock: past the 24-hour window.
  support.shift_clock(shift, 2 * 86_400)

  let refused = api.accept_ticket(b, issued.ticket, "x")
  assert refused
    == Error(api.InvalidInvitation(
      "the mailbox holds no invitation for this ticket; it may have expired",
    ))
  assert !string.contains(string.inspect(refused), text(issued.ticket))
  assert api.contacts(b) == Ok([])

  let _ = node.stop(a)
  let _ = node.stop(b)
}

/// A ticket the mailbox never stored anything for, and a ticket with one
/// character changed, are refused without a relationship being started.
pub fn a_ticket_for_nothing_and_a_mistyped_ticket_are_refused_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(issued) = api.invite_ticket(a, "real", offer.AutoApprove, 5)
  let assert Ok(port) = endpoint.port(mailbox.port)
  let assert Ok(stranger) =
    ticket.from_parts(endpoint.Loopback(port), <<7:256>>)

  assert api.accept_ticket(b, ticket.encode(stranger), "x")
    == Error(api.InvalidInvitation(
      "the mailbox holds no invitation for this ticket; it may have expired",
    ))

  let spelled = text(issued.ticket)
  let flipped = case string.ends_with(spelled, "q") {
    True -> string.drop_end(spelled, 1) <> "p"
    False -> string.drop_end(spelled, 1) <> "q"
  }
  assert api.accept_ticket(b, secret.new(<<flipped:utf8>>), "x")
    == Error(api.InvalidInvitation("the ticket is not valid"))
  assert api.contacts(b) == Ok([])

  let _ = node.stop(a)
  let _ = node.stop(b)
}

/// A daemon that dials only onion mailboxes refuses a loopback ticket
/// before it opens any connection.
pub fn a_ticket_outside_the_carrier_policy_is_refused_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let assert Ok(issued) = api.invite_ticket(a, "p", offer.AutoApprove, 5)

  // B's own mailbox is an onion one, which is all a `TorOnly` daemon may
  // have; it runs offline, so nothing ever dials it.
  let assert Ok(onion) =
    endpoint.parse_onion(
      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
    )
  let assert Ok(port) = endpoint.port(80)
  let settings =
    config.new(
      support.fresh("tor_only"),
      config.Mailbox(
        endpoint: endpoint.Onion(onion, port),
        provisioning_file: mailbox.provisioning_file,
      ),
      endpoint.TorOnly,
    )
  let assert Ok(b) = node.start_offline(settings)

  assert api.accept_ticket(b, issued.ticket, "x")
    == Error(api.Refused(
      "the carrier policy does not permit the ticket's mailbox",
    ))

  let _ = node.stop(a)
  let _ = node.stop(b)
}

/// Someone who holds a ticket's secret can seal any invitation under it,
/// so the joiner also checks the invitation names the mailbox its ticket
/// came from. Here a genuine invitation from A, whose queue is at the
/// first mailbox, is sealed under a ticket for a second mailbox and stored
/// there: the AEAD and the commitment both pass, and the mailbox check is
/// what refuses it.
pub fn an_invitation_for_another_mailbox_is_refused_test() {
  let home = support.start_mailbox()
  let elsewhere = support.start_mailbox()
  let #(a, _) = support.start_daemon(home)
  let #(b, _) = support.start_daemon(home)

  let assert Ok(file) = api.invite(a, "moved", offer.AutoApprove, 5)

  // A queue at the second mailbox to pay for the blob.
  let assert Ok(provision_bytes) =
    simplifile.read_bits(elsewhere.provisioning_file)
  let assert Ok(provision) = capability.from_bytes(provision_bytes)
  let assert Ok(queue) = id.from_bytes(primitives.random_bytes(16))
  let assert Ok(admin) = capability.from_bytes(primitives.random_bytes(32))
  let assert Ok(read) = capability.from_bytes(primitives.random_bytes(32))
  let assert Ok(append) = capability.from_bytes(primitives.random_bytes(32))
  let assert protocol.QueueCreated(_) =
    mailbox_node.handle(
      elsewhere.node,
      protocol.CreateQueue(provision:, queue:, read:, append:, admin:),
    )

  let assert Ok(port) = endpoint.port(elsewhere.port)
  let assert Ok(made) =
    ticket.from_parts(endpoint.Loopback(port), primitives.random_bytes(32))
  let assert Ok(keys) = ticket.keys(suite.suite(), made)
  let assert Ok(sealed) = ticket.seal(suite.suite(), keys, file)
  let assert protocol.BlobStored(_) =
    mailbox_node.handle(
      elsewhere.node,
      protocol.PutBlob(
        queue:,
        admin:,
        blob: keys.locator,
        retrieve: keys.retrieve,
        retention_deadline: time.add(support.now(), 3600),
        sealed:,
      ),
    )

  assert api.accept_ticket(b, ticket.encode(made), "x")
    == Error(api.InvalidInvitation(
      "the invitation names a different mailbox than its ticket",
    ))
  assert api.contacts(b) == Ok([])

  let _ = node.stop(a)
  let _ = node.stop(b)
}
