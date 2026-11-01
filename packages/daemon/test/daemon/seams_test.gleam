//// The simulation seams: unset, they are production; set, each one reaches
//// the boundary it claims to.

import core/offer
import core/secret
import daemon/api
import daemon/config
import daemon/engine
import daemon/mail
import daemon/node
import daemon/store
import daemon/support
import gleam/bit_array
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import primitives/suite as primitive_suite
import simplifile
import weft/poll
import weft/timer

/// Waits until `daemon` lists an active contact, and returns its handle.
fn active(daemon: api.Daemon) {
  support.eventually(15_000, fn() {
    let assert Ok(views) = api.contacts(daemon)

    // The pairing is done once a contact is active.
    case list.find(views, fn(view) { view.phase == api.Active }) {
      Ok(view) -> Some(view.contact)
      Error(Nil) -> None
    }
  })
}

/// Every message already waiting on `subject`, oldest first.
fn drain(subject: process.Subject(a), seen: List(a)) -> List(a) {
  // An empty mailbox ends the drain.
  case process.receive(subject, 0) {
    Ok(next) -> drain(subject, [next, ..seen])
    Error(Nil) -> list.reverse(seen)
  }
}

/// A daemon config with every seam written out at its production value.
fn production(mailbox: support.Mailbox) -> config.Config {
  let settings = support.daemon_config(mailbox, support.fresh("seams"))

  config.Config(
    ..settings,
    timer: timer.WallClock,
    poll_clock: poll.monotonic(),
    dialer: None,
    database: None,
    store_faults: None,
    engine_faults: None,
    interceptor: None,
  )
}

pub fn every_seam_defaults_to_production_test() {
  let mailbox = support.start_mailbox()
  let defaults = support.daemon_config(mailbox, support.fresh("seams"))

  // `config.new` is what production builds, and it sets no seam.
  assert defaults.timer == timer.WallClock
  assert defaults.dialer == None
  assert defaults.database == None
  assert defaults.store_faults == None
  assert defaults.engine_faults == None
  assert defaults.interceptor == None

  // Two daemons started with every seam at that value pair and exchange a
  // message over the real mailbox.
  let assert Ok(a) = node.start(production(mailbox))
  let assert Ok(b) = node.start(production(mailbox))
  let assert Ok(file) = api.invite(a, "a", offer.AutoApprove, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = active(a)
  let _ = active(b)

  let assert Ok(sent) =
    api.send(a, at_a, "text/plain", <<"through the seams":utf8>>, None)
  let delivered =
    support.eventually(15_000, fn() {
      let assert Ok(found) = api.receive(b, None, 10)

      // Nothing yet is an ordinary wait.
      case found {
        [] -> None
        [first, ..] -> Some(first)
      }
    })

  assert delivered.message == sent
  assert bit_array.to_string(secret.expose(delivered.payload))
    == Ok("through the seams")

  node.stop(a)
  node.stop(b)
}

pub fn an_interceptor_sees_every_engine_call_and_delivers_it_test() {
  let mailbox = support.start_mailbox()
  let parcels = process.new_subject()

  // This interceptor releases each parcel at once and reports its labels.
  let interceptor =
    mail.Interceptor(park: fn(parcel: mail.Parcel) {
      let delivered = parcel.deliver()
      process.send(parcels, #(parcel.from, parcel.to, parcel.label, delivered))
    })
  let assert Ok(daemon) =
    node.start_offline(
      config.Config(..production(mailbox), interceptor: Some(interceptor)),
    )

  let assert Ok([]) = api.contacts(daemon)
  let seen = drain(parcels, [])

  // The carrier's first report and the API's call both went through it.
  assert list.contains(seen, #("carrier", "status", "set_tor", mail.Delivered))
  assert list.contains(seen, #("api", "engine", "contacts", mail.Delivered))

  node.stop(daemon)
}

pub fn an_engine_fault_fails_before_or_after_the_job_test() {
  let mailbox = support.start_mailbox()

  // An invitation that fails before it applies leaves no offer behind.
  let before =
    config.Config(
      ..production(mailbox),
      engine_faults: Some(fn(kind) {
        case kind {
          engine.Invite -> engine.FailBeforeApply
          _ -> engine.Apply
        }
      }),
    )
  let assert Ok(daemon) = node.start_offline(before)
  assert api.invite(daemon, "a", offer.AutoApprove, 10)
    == Error(api.Unavailable)
  assert engine.pending_inboxes(api.engine_handle(daemon)) == Ok([])
  node.stop(daemon)

  // One that fails after it applies committed its offer all the same.
  let after =
    config.Config(
      ..production(mailbox),
      engine_faults: Some(fn(kind) {
        case kind {
          engine.Invite -> engine.ApplyThenFail
          _ -> engine.Apply
        }
      }),
    )
  let assert Ok(daemon) = node.start_offline(after)
  assert api.invite(daemon, "a", offer.AutoApprove, 10)
    == Error(api.Unavailable)
  let assert Ok([_]) = engine.pending_inboxes(api.engine_handle(daemon))
  node.stop(daemon)
}

pub fn a_store_fault_fails_before_begin_or_after_commit_test() {
  let mailbox = support.start_mailbox()

  // Every transaction down: the offer is never written.
  let down =
    config.Config(
      ..production(mailbox),
      store_faults: Some(fn() { store.Down }),
    )
  let assert Ok(daemon) = node.start_offline(down)
  assert api.invite(daemon, "a", offer.AutoApprove, 10)
    == Error(api.Unavailable)
  assert engine.pending_inboxes(api.engine_handle(daemon)) == Ok([])
  node.stop(daemon)

  // Every acknowledgement lost: the offer is written and the call failed.
  let lost =
    config.Config(
      ..production(mailbox),
      store_faults: Some(fn() { store.AckLost }),
    )
  let assert Ok(daemon) = node.start_offline(lost)
  assert api.invite(daemon, "a", offer.AutoApprove, 10)
    == Error(api.Unavailable)
  let assert Ok([_]) = engine.pending_inboxes(api.engine_handle(daemon))
  node.stop(daemon)
}

pub fn an_in_memory_database_override_serves_the_engine_test() {
  let mailbox = support.start_mailbox()
  let directory = support.fresh("seams")
  let uri = "file:seams_test?mode=memory&cache=shared"

  // A keeper connection holds the shared in-memory database open, as a
  // simulation's harness does across restarts.
  let assert Ok(keeper) = store.open(uri, primitive_suite.suite())
  let assert Ok(daemon) =
    node.start_offline(
      config.Config(
        ..support.daemon_config(mailbox, directory),
        database: Some(uri),
      ),
    )
  let handle = api.engine_handle(daemon)
  let assert Ok(_) = engine.invite(handle, "a", offer.AutoApprove, 10)
  let assert Ok([_]) = engine.pending_inboxes(handle)

  // The engine wrote to memory: no database file was made, and the lock is
  // still a file in the state directory.
  assert simplifile.is_file(directory <> "/" <> node.database_file) == Ok(False)
  assert simplifile.is_file(directory <> "/" <> node.lock_file) == Ok(True)

  node.stop(daemon)
  let assert Ok(Nil) = store.close(keeper)
}
