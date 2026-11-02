//// Ambiguous accepts and sends, retried, between two real daemons and a
//// real mailbox (ADR-011, hypothesis H4 of the DST audit).
////
//// The engine's fault hook makes the joiner's `Accept` and `Send` jobs run,
//// commit and then answer `Unavailable`, as an ask whose reply was lost
//// does. A caller cannot tell that from a failure that changed nothing, so
//// it retries. Before ADR-011 the retried accept started a second joiner,
//// which sat in `AwaitingAccept` forever, and the retried send queued the
//// payload again under a new message id, which the peer delivered twice.

import core/offer
import core/secret
import daemon/api
import daemon/config
import daemon/engine
import daemon/node
import daemon/support
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{None, Some}
import gleam/otp/actor

/// Whether the hook makes accepts and sends lose their answers.
type Switch {
  Lossy
  Clean
}

type SwitchMessage {
  Set(Switch)
  Get(reply: Subject(Switch))
}

fn start_switch() -> Subject(SwitchMessage) {
  let assert Ok(started) =
    actor.new(Clean)
    |> actor.on_message(fn(current, message) {
      case message {
        Set(next) -> actor.continue(next)
        Get(reply:) -> {
          process.send(reply, current)
          actor.continue(current)
        }
      }
    })
    |> actor.start
  started.data
}

fn set(switch: Subject(SwitchMessage), to: Switch) -> Nil {
  process.send(switch, Set(to))
  // A read after the write orders it before the next engine job.
  let _ = process.call(switch, 1000, Get)
  Nil
}

/// Applies every job, except that an accept or a send applies and then
/// answers `Unavailable` while the switch is `Lossy`.
fn hook(
  switch: Subject(SwitchMessage),
) -> fn(engine.JobKind) -> engine.JobFate {
  fn(kind) {
    case kind, process.call(switch, 1000, Get) {
      engine.Accept, Lossy | engine.Send, Lossy -> engine.ApplyThenFail
      _, _ -> engine.Apply
    }
  }
}

fn active_contacts(daemon: api.Daemon) -> List(api.ContactView) {
  let assert Ok(views) = api.contacts(daemon)
  list.filter(views, fn(view) { view.phase == api.Active })
}

pub fn a_retried_accept_and_a_retried_keyed_send_happen_once_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let switch = start_switch()
  let settings_b =
    config.Config(
      ..support.daemon_config(mailbox, support.fresh("state")),
      engine_faults: Some(hook(switch)),
    )
  let assert Ok(b) = node.start(settings_b)
  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)

  // Two accepts whose answers are lost, then one that is heard: all three
  // are the same relationship.
  set(switch, Lossy)
  assert api.accept(b, file, "a") == Error(api.Unavailable)
  assert api.accept(b, file, "a") == Error(api.Unavailable)
  set(switch, Clean)
  let assert Ok(contact) = api.accept(b, file, "a")
  let assert Ok(views) = api.contacts(b)
  assert list.map(views, fn(view) { view.contact }) == [contact]

  // And it pairs: nothing is left waiting for an accept that cannot come.
  support.eventually(15_000, fn() {
    support.when(list.length(active_contacts(b)) == 1)
  })
  support.eventually(15_000, fn() {
    support.when(list.length(active_contacts(a)) == 1)
  })

  // The same for a keyed send: two lost answers, then the heard one names
  // the message the first one queued.
  set(switch, Lossy)
  let send = fn(payload) {
    api.send_with_key(
      b,
      contact,
      "order-17",
      "text/plain",
      secret.new(payload),
      None,
    )
  }
  assert send(<<"once":utf8>>) == Error(api.Unavailable)
  assert send(<<"once":utf8>>) == Error(api.Unavailable)
  set(switch, Clean)
  let assert Ok(message) = send(<<"once":utf8>>)
  support.eventually(15_000, fn() {
    support.when(api.status(b, message) == Ok(api.ReceivedByPeer))
  })

  // The key named that message, so another payload under it is refused.
  let assert Error(api.Refused(_)) = send(<<"twice":utf8>>)

  // The peer's agent was handed the payload exactly once.
  process.sleep(1500)
  let assert Ok(delivered) = api.receive(a, None, 10)
  assert list.map(delivered, fn(found) { secret.expose(found.payload) })
    == [<<"once":utf8>>]
}

pub fn an_idempotency_key_is_bounded_and_scoped_to_its_send_test() {
  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)
  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(contact) = api.accept(b, file, "a")
  support.eventually(15_000, fn() {
    support.when(list.length(active_contacts(b)) == 1)
  })

  let keyed = fn(key, payload) {
    api.send_with_key(b, contact, key, "text/plain", secret.new(payload), None)
  }

  // An empty key and one past the bound are refused before anything
  // commits; a key at the bound is fine.
  let assert Error(api.Refused(_)) = keyed("", <<"x":utf8>>)
  let long = string_of(129)
  let assert Error(api.Refused(_)) = keyed(long, <<"x":utf8>>)
  let assert Ok(_) = keyed(string_of(128), <<"x":utf8>>)

  // Two keys are two messages, and a repeated key is the first.
  let assert Ok(first) = keyed("k-1", <<"a":utf8>>)
  let assert Ok(second) = keyed("k-2", <<"a":utf8>>)
  assert first != second
  let assert Ok(again) = keyed("k-1", <<"a":utf8>>)
  assert again == first
}

fn string_of(n: Int) -> String {
  list.repeat("k", n) |> list.fold("", fn(acc, piece) { acc <> piece })
}
