//// Secrets stay out of observable output (spec §12.4, style Part IV §7):
//// the whole log of a real exchange, and the rendering of every API value
//// and error, are searched for the bytes that must never appear.

import core/capability
import core/offer
import core/route
import daemon/api
import daemon/engine
import daemon/support
import gleam/bit_array
import gleam/list
import gleam/option.{None, Some}
import gleam/string

const payload = "SECRET-PAYLOAD-0b1c2d3e4f"

/// Lowercase hex of some bytes.
fn hex(bytes: BitArray) -> String {
  string.lowercase(bit_array.base16_encode(bytes))
}

/// The three capabilities of an inbox, in hex.
fn capabilities(inbox: route.Inbox) -> List(String) {
  [
    hex(capability.expose(inbox.read)),
    hex(capability.expose(inbox.append)),
    hex(capability.expose(inbox.admin)),
  ]
}

pub fn logs_and_errors_carry_no_secret_test() {
  support.capture_start()

  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "secrets", offer.AutoApprove, 5)
  let assert Ok(at_b) = api.accept(b, file, "a")
  let at_a =
    support.eventually(15_000, fn() {
      let assert Ok(views) = api.contacts(a)
      case list.find(views, fn(view) { view.phase == api.Active }) {
        Ok(view) -> Some(view.contact)
        Error(Nil) -> None
      }
    })
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(b)
    support.when(list.any(views, fn(view) { view.phase == api.Active }))
  })

  let assert Ok(sent) = api.send(a, at_a, "text/plain", <<payload:utf8>>, None)
  let delivered =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)
      case found {
        [] -> None
        [first, ..] -> Some(first)
      }
    })
  assert delivered.message == sent

  // Errors of every kind, each rendered.
  let errors = [
    string.inspect(api.accept(b, <<"junk":utf8>>, "x")),
    string.inspect(api.send(b, at_a, "text/plain", <<payload:utf8>>, None)),
    string.inspect(api.approve(a, at_a)),
    string.inspect(api.status(a, delivered.message)),
  ]

  // Values, including the delivery and its audit entry.
  let assert Ok(entries) = api.audit(b, Some(at_b), 10)
  let rendered = [string.inspect(delivered), string.inspect(entries), ..errors]

  // The capabilities of both sides' inboxes, and the invitation file.
  let assert Ok(inboxes_a) = engine.live_inboxes(api.engine_name(a))
  let assert Ok(inboxes_b) = engine.live_inboxes(api.engine_name(b))
  let secrets =
    list.flat_map(list.append(inboxes_a, inboxes_b), capabilities)
    |> list.prepend(hex(file))
    |> list.prepend(payload)

  let captured = case bit_array.to_string(support.capture_stop()) {
    Ok(text) -> text
    Error(Nil) -> ""
  }

  // The log is not empty, so the search below means something.
  assert string.contains(captured, "queue_created")

  list.each(secrets, fn(secret) {
    assert !string.contains(captured, secret)
    assert !string.contains(string.lowercase(captured), secret)
    assert list.all(rendered, fn(text) { !string.contains(text, secret) })
  })
}
