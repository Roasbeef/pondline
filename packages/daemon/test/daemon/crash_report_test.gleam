//// An engine that crashes mid-send prints no plaintext and no key
//// (ADR-012).
////
//// The receiving daemon runs the real suite except that sealing the test's
//// payload reaches OpenSSL with a key one byte short, so the NIF raises
//// `badarg` inside the engine's send job. A NIF's exception carries its
//// whole argument list in the top stack frame: the message key, the nonce,
//// and the padded plaintext frame holding the payload. Before the handler
//// was installed, OTP's formatter printed that frame in the engine's crash
//// report and again in the supervisor's `child_terminated` report, the
//// payload as a decimal byte list (`67,82,65,83,72,...`), which a search
//// for the payload's text does not find; so the search here covers every
//// spelling.

import core/offer
import core/secret
import daemon/api
import daemon/config
import daemon/node
import daemon/support
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import telemetry/handler
import telemetry/level

const marker = "CRASH-PAYLOAD-7f3e9a"

pub fn an_engine_crash_mid_send_prints_no_plaintext_test() {
  let assert Ok(Nil) = handler.install(level.Info)
  support.capture_start()

  let mailbox = support.start_mailbox()
  let #(a, _) = support.start_daemon(mailbox)
  let settings = support.daemon_config(mailbox, support.fresh("state"))
  let crashing = support.crashing_suite(<<marker:utf8>>)
  let assert Ok(b) = node.start(config.Config(..settings, suite: crashing))

  let assert Ok(file) = api.invite(a, "crash", offer.AutoApprove, 5)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a =
    support.eventually(15_000, fn() {
      let assert Ok(views) = api.contacts(b)
      case list.find(views, fn(view) { view.phase == api.Active }) {
        Ok(view) -> Some(view.contact)
        Error(Nil) -> None
      }
    })

  // The send's ask has no monitor, so its caller would wait out the call
  // timeout; it runs aside and the test watches the log instead.
  process.spawn_unlinked(fn() {
    api.send(b, at_a, "text/plain", secret.new(<<marker:utf8>>), None)
  })
  // Any formatter names the supervisor's context, so the wait does not
  // depend on the one under test.
  support.eventually(15_000, fn() {
    support.when(string.contains(
      support.flatten(support.capture_peek()),
      "child_terminated",
    ))
  })
  let captured = support.flatten(support.capture_stop())

  // Neither the payload nor the key OpenSSL was handed, in any spelling.
  let secrets =
    list.append(
      support.spellings(<<marker:utf8>>),
      support.spellings(support.sealing_key()),
    )
  list.each(secrets, fn(spelling) {
    assert !string.contains(captured, spelling)
  })

  // And the report still says what crashed, why and where.
  assert string.contains(captured, "event=crash_report")
  assert string.contains(captured, "process=daemon_engine$")
  assert string.contains(captured, "reason=badarg")
  assert string.contains(captured, "at=crypto:crypto_one_time_aead/7")
  assert string.contains(captured, "event=supervisor_report")
}
