//// Secrets stay out of observable output (spec §12.4, style Part IV §7):
//// the whole log of a real exchange, and the rendering of every API value
//// and error, are searched for the bytes that must never appear.

import core/capability
import core/codex32
import core/crypto/suite.{type Suite, Suite} as _core_suite
import core/endpoint
import core/offer
import core/pairing_code/words
import core/route
import core/secret.{type Secret}
import core/ticket
import daemon/api
import daemon/config
import daemon/engine
import daemon/mail
import daemon/node
import daemon/support
import gleam/bit_array
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import mailbox/mail as mailbox_mail
import primitives/suite
import telemetry/handler
import telemetry/level

const payload = "SECRET-PAYLOAD-0b1c2d3e4f"

/// The three capabilities of an inbox, in hex.
fn capabilities(inbox: route.Inbox) -> List(BitArray) {
  [
    capability.expose(inbox.read),
    capability.expose(inbox.append),
    capability.expose(inbox.admin),
  ]
}

/// A ticket's text, its secret `K`, and every value derived from `K` that
/// stays with the two daemons (ADR-009).
fn ticket_secrets(issued: Secret) -> List(BitArray) {
  let assert Ok(text) = bit_array.to_string(secret.expose(issued))
  let assert Ok(made) = ticket.decode(text)
  let assert Ok(keys) = ticket.keys(suite.suite(), made)

  // A loopback ticket's payload is the port and then `K`.
  let assert Ok([_format, ..payload]) =
    codex32.to_symbols(string.drop_end(string.drop_start(text, 3), 15))
  let assert Ok(<<_port:size(16), k:bytes-size(32)>>) =
    codex32.symbols_to_bytes(payload)

  [
    secret.expose(issued),
    <<string.drop_start(text, 3):utf8>>,
    k,
    capability.expose(keys.retrieve),
    secret.expose(keys.key),
    secret.expose(keys.commit_key),
  ]
}

pub fn logs_and_errors_carry_no_secret_test() {
  let assert Ok(Nil) = handler.install(level.Info)
  support.capture_start()

  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "secrets", offer.AutoApprove, 5)
  let assert Ok(at_b) = api.accept(b, file, "a")

  // A second pairing by ticket, so the ticket's whole path is logged too.
  let assert Ok(issued) =
    api.invite_ticket(a, "by ticket", offer.AutoApprove, 5)
  let assert Ok(_) = api.accept_ticket(b, issued.ticket, "a")
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

  let assert Ok(sent) =
    api.send(a, at_a, "text/plain", secret.new(<<payload:utf8>>), None)
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
    string.inspect(api.accept_ticket(b, secret.new(<<"pl1junk":utf8>>), "x")),
    string.inspect(issued),
    string.inspect(api.send(
      b,
      at_a,
      "text/plain",
      secret.new(<<payload:utf8>>),
      None,
    )),
    string.inspect(api.approve(a, at_a)),
    string.inspect(api.status(a, delivered.message)),
  ]

  // Values, including the delivery and its audit entry.
  let assert Ok(entries) = api.audit(b, Some(at_b), 10)

  // The engine's answer with an invitation file is a message between
  // processes, which a crash report's mailbox or an actor's "discarding
  // unexpected message" warning would print: rendered, it holds no file.
  let assert Ok(offered) =
    engine.invite(api.engine_handle(a), "rendered", offer.AutoApprove, 1)
  let answer =
    support.eventually(15_000, fn() {
      case engine.invitation_file(api.engine_handle(a), offered) {
        Ok(Some(_)) as ready -> Some(ready)
        _ -> None
      }
    })
  let assert Ok(Some(offered_file)) = answer
  let file_rendering = string.inspect(answer)
  let flat_rendering = string.replace(file_rendering, " ", "")
  list.each(support.spellings(secret.expose(offered_file)), fn(spelling) {
    assert !string.contains(flat_rendering, spelling)
  })

  let rendered = [
    string.inspect(delivered),
    string.inspect(entries),
    file_rendering,
    ..errors
  ]

  // The capabilities of both sides' inboxes, and the invitation file.
  let assert Ok(inboxes_a) = engine.live_inboxes(api.engine_handle(a))
  let assert Ok(inboxes_b) = engine.live_inboxes(api.engine_handle(b))
  let secrets =
    list.flat_map(list.append(inboxes_a, inboxes_b), capabilities)
    |> list.prepend(file)
    |> list.prepend(<<payload:utf8>>)
    |> list.append(ticket_secrets(issued.ticket))
    |> list.flat_map(support.spellings)

  // Whitespace goes, because a decimal byte list prints with spaces in an
  // inspected bit array and without them in a crash report's frame.
  let captured = support.flatten(support.capture_stop())
  let rendered = list.map(rendered, string.replace(_, " ", ""))

  // The log is not empty, so the search below means something.
  assert string.contains(captured, "response=queue_created")

  list.each(secrets, fn(secret) {
    assert !string.contains(captured, secret)
    assert !string.contains(string.lowercase(captured), secret)
    assert list.all(rendered, fn(text) { !string.contains(text, secret) })
  })
}

/// Delivers every parcel at once, in the sender's process, after crashing
/// that process if a crash is armed for its role. A direct send with a
/// fault point.
fn crashing_daemon_interceptor() -> mail.Interceptor {
  mail.Interceptor(park: fn(parcel) {
    support.crash_if_armed("daemon:" <> parcel.from <> ">" <> parcel.label)
    let _ = parcel.deliver()
    Nil
  })
}

fn crashing_mailbox_interceptor() -> mailbox_mail.Interceptor {
  mailbox_mail.Interceptor(park: fn(parcel) {
    support.crash_if_armed("mailbox:" <> parcel.label)
    let _ = parcel.deliver()
    Nil
  })
}

/// The same search over a run in which three processes crash with secrets
/// in reach (ADR-012): the engine mid-send (OpenSSL raising with the key
/// and the plaintext as arguments), the scheduler while it records a send
/// (raising with the peer's append capability as an argument), and a
/// mailbox request process while it calls the coordinator (raising with
/// the queue's read capability as an argument). Each report is still
/// there, names its process and reason, and spells no secret.
pub fn crash_reports_carry_no_secret_test() {
  let assert Ok(Nil) = handler.install(level.Info)
  support.capture_start()

  let mailbox =
    support.start_mailbox_with(
      config.system_clock(),
      Some(crashing_mailbox_interceptor()),
    )
  let #(a, _) = support.start_daemon(mailbox)
  let settings =
    config.Config(
      ..support.daemon_config(mailbox, support.fresh("state")),
      suite: support.crashing_suite(<<payload:utf8>>),
      interceptor: Some(crashing_daemon_interceptor()),
    )
  let assert Ok(b) = node.start(settings)

  let assert Ok(file) = api.invite(a, "crashes", offer.AutoApprove, 5)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a =
    support.eventually(15_000, fn() {
      let assert Ok(views) = api.contacts(b)
      case list.find(views, fn(view) { view.phase == api.Active }) {
        Ok(view) -> Some(view.contact)
        Error(Nil) -> None
      }
    })

  // The secrets the scheduler and the mailbox crash with: capabilities of
  // the inbox the message travels to, which both of them really hold.
  let assert Ok([inbox_a, ..]) = engine.live_inboxes(api.engine_handle(a))
  support.arm_crash(
    "daemon:scheduler>record_send",
    capability.expose(inbox_a.append),
  )
  support.arm_crash("mailbox:handle", capability.expose(inbox_a.read))

  // The engine crashes sealing the payload; the send runs aside because its
  // ask has no monitor. A second message then goes out through a restarted
  // engine, a scheduler that crashes once recording it, and a mailbox whose
  // first request after arming crashes; it still arrives.
  process.spawn_unlinked(fn() {
    api.send(b, at_a, "text/plain", secret.new(<<payload:utf8>>), None)
  })
  let after = "delivered after the crashes"
  let sent =
    support.eventually(30_000, fn() {
      case api.send(b, at_a, "text/plain", secret.new(<<after:utf8>>), None) {
        Ok(sent) -> Some(sent)
        Error(_) -> None
      }
    })
  support.eventually(30_000, fn() {
    let assert Ok(found) = api.receive(a, None, 10)
    support.when(list.any(found, fn(delivery) { delivery.message == sent }))
  })
  let captured = support.flatten(support.capture_stop())

  let secrets =
    [
      <<payload:utf8>>,
      support.sealing_key(),
      capability.expose(inbox_a.append),
      capability.expose(inbox_a.read),
      capability.expose(inbox_a.admin),
      file,
    ]
    |> list.flat_map(support.spellings)
  list.each(secrets, fn(spelling) {
    assert !string.contains(captured, spelling)
  })

  // Each crash left its line.
  assert string.contains(captured, "process=daemon_engine$")
  assert string.contains(captured, "process=daemon_scheduler$")
  assert string.contains(captured, "event=foreign_text")
  assert string.contains(captured, "context=child_terminated")
  assert !string.contains(captured, "event=unformattable")
}

// ---------------------------------------------------------- spoken codes

/// The words the recording suite draws for every code, chosen so that no
/// log line spells one by accident: a common word such as `event` would
/// make the search below find what was never leaked.
const spoken = ["quantum", "vintage", "walnut"]

/// The real suite, except that it reports every 32-byte draw to `draws`, so
/// the test can rebuild the ticket a code's run hands off from its secret,
/// and answers the five-byte draw a code's words are read from with the
/// `spoken` words.
fn recording_suite(draws: Subject(BitArray)) -> Suite {
  let real = suite.suite()
  let assert [first, second, third] =
    list.map(spoken, fn(word) {
      let assert Ok(index) = words.index_of(word)
      index
    })

  Suite(..real, random: fn(size) {
    case size {
      5 -> <<first:11, second:11, third:11, 0:7>>

      32 -> {
        let drawn = real.random(size)
        process.send(draws, drawn)
        drawn
      }

      _ -> real.random(size)
    }
  })
}

/// Every ticket text one of the recorded draws would make at `mailbox`: the
/// ticket a code's run hands off is one of them.
fn possible_tickets(
  draws: Subject(BitArray),
  mailbox: endpoint.Endpoint,
) -> List(BitArray) {
  drain(draws, [])
  |> list.filter_map(fn(drawn) {
    case ticket.from_parts(mailbox, drawn) {
      Ok(made) -> Ok(secret.expose(ticket.encode(made)))
      Error(Nil) -> Error(Nil)
    }
  })
}

fn drain(subject: Subject(a), found: List(a)) -> List(a) {
  case process.receive(subject, 0) {
    Ok(value) -> drain(subject, [value, ..found])
    Error(Nil) -> found
  }
}

/// A whole pairing by spoken code, a misheard one and the refusals around
/// it log nothing and render nothing that spells the code, any of its
/// words, the words joined as the password, or the ticket the run handed
/// off (ADR-016, ADR-012). The one place the code is printed is the
/// operator's answer, which is not a log.
pub fn a_spoken_code_reaches_no_log_and_no_rendering_test() {
  let assert Ok(Nil) = handler.install(level.Info)
  support.capture_start()

  let draws = process.new_subject()
  let mailbox = support.start_mailbox()
  let settings =
    config.Config(
      ..support.daemon_config(mailbox, support.fresh("state")),
      suite: recording_suite(draws),
    )
  let assert Ok(a) = node.start(settings)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(invited) = api.invite_code(a, "spoken", offer.AutoApprove, 5)
  let joined = api.accept_code(b, invited.code, None, "a", None)
  let assert Ok(api.Paired(contact: Some(_))) = joined
  let awaited = api.await_code(a, invited.run)

  let assert Ok(code_text) = bit_array.to_string(secret.expose(invited.code))
  assert string.contains(code_text, string.join(spoken, "-"))

  // A second code, misheard by one word, and refusals that read a code.
  let assert Ok(again) = api.invite_code(a, "misheard", offer.AutoApprove, 5)
  let assert Ok(again_text) = bit_array.to_string(secret.expose(again.code))
  let misheard = string.replace(again_text, "walnut", "abandon")
  let failed =
    api.accept_code(b, secret.new(<<misheard:utf8>>), None, "a", None)
  assert failed == Ok(api.ConfirmationFailed)
  let failed_inviter = api.await_code(a, again.run)

  let typo = string.replace(code_text, "vintage", "vintag")
  let errors = [
    string.inspect(api.accept_code(
      b,
      secret.new(<<typo:utf8>>),
      None,
      "a",
      None,
    )),
    string.inspect(api.accept_code(
      b,
      secret.new(<<code_text:utf8>>),
      Some("not an endpoint"),
      "a",
      None,
    )),
    string.inspect(api.accept_code(b, invited.code, None, "a", None)),
  ]

  let rendered =
    [
      string.inspect(invited),
      string.inspect(again),
      string.inspect(joined),
      string.inspect(awaited),
      string.inspect(failed),
      string.inspect(failed_inviter),
      ..errors
    ]
    |> list.map(string.replace(_, " ", ""))

  let assert Ok(port) = endpoint.port(mailbox.port)
  let tickets = possible_tickets(draws, endpoint.Loopback(port))
  assert tickets != []

  let secrets =
    [
      <<code_text:utf8>>,
      <<again_text:utf8>>,
      <<misheard:utf8>>,
      <<string.join(spoken, "-"):utf8>>,
      ..list.map(spoken, fn(word) { <<word:utf8>> })
    ]
    |> list.append(tickets)
    |> list.flat_map(support.spellings)

  let captured = support.flatten(support.capture_stop())

  // The log is not empty, so the search means something.
  assert string.contains(captured, "response=rendezvous_opened")

  list.each(secrets, fn(spelling) {
    assert !string.contains(captured, spelling)
    assert !string.contains(string.lowercase(captured), spelling)
    assert list.all(rendered, fn(text) { !string.contains(text, spelling) })
  })

  let _ = node.stop(a)
  let _ = node.stop(b)
}
