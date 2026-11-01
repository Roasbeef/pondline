//// The carrier policy at the daemon's edges, and the Tor path behind an
//// environment gate.

import core/endpoint
import core/offer
import daemon/api
import daemon/config
import daemon/node
import daemon/status
import daemon/support
import gleam/io
import gleam/option.{Some}

fn onion() -> endpoint.Endpoint {
  let assert Ok(address) =
    endpoint.parse_onion(
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion",
    )
  let assert Ok(port) = endpoint.port(80)

  endpoint.Onion(address, port)
}

pub fn tor_only_refuses_a_loopback_invitation_at_accept_test() {
  let mailbox = support.start_mailbox()
  let #(inviter, _) = support.start_daemon(mailbox)

  // A TorOnly daemon whose own mailbox is an onion service; the sidecar is
  // absent, so it can reach nothing, which is all this test needs.
  let strict =
    config.Config(
      ..config.new(
        support.fresh("strict"),
        config.Mailbox(
          endpoint: onion(),
          provisioning_file: mailbox.provisioning_file,
        ),
        endpoint.TorOnly,
      ),
      tor: option.None,
    )
  let assert Ok(joiner) = node.start(strict)

  let assert Ok(file) = api.invite(inviter, "loopback", offer.AutoApprove, 5)

  let assert Error(api.Refused(_)) = api.accept(joiner, file, "x")
  let assert Ok([]) = api.contacts(joiner)
}

pub fn a_loopback_mailbox_is_refused_under_tor_only_test() {
  let mailbox = support.start_mailbox()
  let loose = support.daemon_config(mailbox, support.fresh("refused"))
  let strict = config.Config(..loose, carrier: endpoint.TorOnly)

  assert node.start(strict) == Error(node.MailboxNotPermitted)
}

pub fn a_missing_provisioning_file_is_refused_test() {
  let mailbox = support.start_mailbox()
  let loose = support.daemon_config(mailbox, support.fresh("noprovision"))
  let broken =
    config.Config(
      ..loose,
      mailbox: config.Mailbox(
        ..loose.mailbox,
        provisioning_file: "build/does-not-exist.cap",
      ),
    )

  assert node.start(broken) == Error(node.BadProvisioning)
}

/// The real sidecar needs a network, so it runs only when asked for.
pub fn tor_carrier_bootstraps_when_enabled_test() {
  case support.env("REEDWIRE_TOR_NETWORK") {
    Error(Nil) ->
      io.println_error("SKIP tor_carrier_bootstraps_when_enabled_test")

    Ok(_) -> {
      let mailbox = support.start_mailbox()
      let loose = support.daemon_config(mailbox, support.fresh("tor"))
      let binary = case support.env("REEDWIRE_TOR_BIN") {
        Ok(path) -> path
        Error(Nil) -> "../../native/reedwire-tor/target/release/reedwire-tor"
      }
      let settings = config.Config(..loose, tor: Some(binary))
      let assert Ok(daemon) = node.start(settings)

      support.eventually(300_000, fn() {
        support.when(api.health(daemon).tor == status.TorBootstrapped)
      })
    }
  }
}
