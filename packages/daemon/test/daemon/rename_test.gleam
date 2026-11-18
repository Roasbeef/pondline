//// A contact's description is the name the operator finds it by, and
//// `api.rename` changes it: a real daemon, no mailbox traffic needed beyond
//// the pairing that creates the contact.

import core/id
import core/offer
import daemon/api
import daemon/support
import gleam/list
import gleam/option.{None, Some}
import gleam/string

/// A daemon with one active contact, its handle, and the daemon.
fn paired() -> #(api.Daemon, id.Id(id.Contact)) {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "first name", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "b's view")

  let contact =
    support.eventually(15_000, fn() {
      let assert Ok(views) = api.contacts(a)

      case list.find(views, fn(view) { view.phase == api.Active }) {
        Ok(view) -> Some(view.contact)
        Error(Nil) -> None
      }
    })

  #(a, contact)
}

/// The description the daemon lists for `contact`.
fn description_of(daemon: api.Daemon, contact: id.Id(id.Contact)) -> String {
  let assert Ok(views) = api.contacts(daemon)
  let assert Ok(view) = list.find(views, fn(view) { view.contact == contact })

  view.description
}

pub fn rename_changes_the_description_and_survives_a_second_rename_test() {
  let #(daemon, contact) = paired()
  assert description_of(daemon, contact) == "first name"

  let assert Ok(Nil) = api.rename(daemon, contact, "kevin")
  assert description_of(daemon, contact) == "kevin"

  // A rename is not one-way: the name can change again, and spaces are fine.
  let assert Ok(Nil) = api.rename(daemon, contact, "kevin at work")
  assert description_of(daemon, contact) == "kevin at work"
}

pub fn rename_refuses_names_that_cannot_be_typed_back_test() {
  let #(daemon, contact) = paired()

  assert api.rename(daemon, contact, "") |> is_refused
  assert api.rename(daemon, contact, "two\nlines") |> is_refused
  assert api.rename(daemon, contact, "tab\there") |> is_refused
  assert api.rename(daemon, contact, "esc\u{1b}[2J") |> is_refused
  assert api.rename(daemon, contact, string.repeat("x", 257)) |> is_refused

  // A refusal changed nothing, and the longest allowed name is accepted.
  assert description_of(daemon, contact) == "first name"
  let longest = string.repeat("x", 256)
  let assert Ok(Nil) = api.rename(daemon, contact, longest)
  assert description_of(daemon, contact) == longest
}

pub fn rename_of_an_unknown_contact_is_not_found_test() {
  let #(daemon, _) = paired()
  let assert Ok(stranger) = id.from_hex("000000000000000000000000000000aa")

  assert api.rename(daemon, stranger, "nobody") == Error(api.NotFound)
}

fn is_refused(outcome: Result(Nil, api.ApiError)) -> Bool {
  case outcome {
    Error(api.Refused(..)) -> True
    _ -> False
  }
}
