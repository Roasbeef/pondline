//// End to end: two daemons and a mailbox in one VM, over loopback.

import core/id
import core/offer
import core/secret
import daemon/api
import daemon/node
import daemon/support
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/order
import gleam/string

/// Waits until `daemon` lists a contact in `phase`, and returns its handle.
fn contact_in(daemon: api.Daemon, phase: api.PhaseName) {
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(daemon)

    case list.find(views, fn(view) { view.phase == phase }) {
      Ok(view) -> Some(view.contact)
      Error(Nil) -> None
    }
  })
}

pub fn pairing_and_messages_both_ways_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "from a", offer.OperatorApproves, 10)
  let assert Ok(joined) = api.accept(b, file, "a's offer")

  // The inviter sees the claimant and waits for its operator.
  let at_a = contact_in(a, api.PendingApproval)
  let assert Ok(Nil) = api.approve(a, at_a)
  let _ = contact_in(a, api.Active)
  let at_b = contact_in(b, api.Active)
  assert at_b == joined

  // Messages in both directions.
  let assert Ok(from_a) =
    api.send(a, at_a, "text/plain", <<"hello b":utf8>>, None)
  let assert Ok(from_b) =
    api.send(b, at_b, "text/plain", <<"hello a":utf8>>, None)

  let at_b_inbox =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })
  let assert [delivered] = at_b_inbox
  assert delivered.message == from_a
  assert delivered.content_type == "text/plain"
  assert bit_array.to_string(secret.expose(delivered.payload)) == Ok("hello b")

  // Consuming removes it from the agent's view.
  let assert Ok(Nil) = api.acknowledge(b, delivered.message)
  let assert Ok([]) = api.receive(b, None, 10)

  let _ =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(a, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })

  // Receipts carry both messages to ReceivedByPeer.
  support.eventually(15_000, fn() {
    let assert Ok(one) = api.status(a, from_a)
    let assert Ok(two) = api.status(b, from_b)
    support.when(one == api.ReceivedByPeer && two == api.ReceivedByPeer)
  })

  // Both sides audit both messages, in plaintext.
  let assert Ok(entries) = api.audit(a, Some(at_a), 10)
  assert list.length(entries) == 2
  let assert Ok(entries_b) = api.audit(b, Some(at_b), 10)
  assert list.length(entries_b) == 2
}

pub fn auto_approve_activates_without_an_operator_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "preapproved", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")

  let _ = contact_in(a, api.Active)
  let _ = contact_in(b, api.Active)
}

pub fn a_second_daemon_on_one_directory_refuses_to_start_test() {
  let mailbox = support.start_mailbox()
  let #(daemon, settings) = support.start_daemon(mailbox)

  assert node.start(settings) == Error(node.StateDirLocked)

  // After a stop the directory is free again.
  node.stop(daemon)
  let assert Ok(_) = node.start(settings)
}

pub fn the_inbound_budget_holds_messages_until_it_is_raised_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  // A grants a budget of one inbound message.
  let assert Ok(file) = api.invite(a, "tight", offer.AutoApprove, 1)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = contact_in(a, api.Active)
  let at_b = contact_in(b, api.Active)

  let assert Ok(first) = api.send(b, at_b, "text/plain", <<"1":utf8>>, None)
  let assert Ok(second) = api.send(b, at_b, "text/plain", <<"2":utf8>>, None)

  // One is delivered and one is held, whichever the mailbox handed over
  // first.
  let visible =
    support.eventually(15_000, fn() {
      let assert Ok(views) = api.contacts(a)
      let assert [view] = views
      let assert Ok(found) = api.receive(a, None, 10)

      case view.held == 1 && view.budget_used == 1 && found != [] {
        True -> Some(found)
        False -> None
      }
    })
  let assert [only] = visible
  let assert Ok(Nil) = api.acknowledge(a, only.message)
  let assert Ok([]) = api.receive(a, None, 10)

  // Raising the budget releases the other.
  let assert Ok(Nil) = api.raise_budget(a, at_a, 1)
  let assert [released] =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(a, None, 10)
      case found {
        [] -> None
        [_, ..] -> Some(found)
      }
    })

  let both = list.sort([only.message, released.message], by: id_order)
  assert both == list.sort([first, second], by: id_order)
  assert released.message != only.message
}

fn id_order(left, right) {
  bit_array_compare(id.to_bytes(left), id.to_bytes(right))
}

fn bit_array_compare(left: BitArray, right: BitArray) -> order.Order {
  string.compare(bit_array.base16_encode(left), bit_array.base16_encode(right))
}
