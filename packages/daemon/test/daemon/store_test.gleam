//// The durable store: settings, the modes of the state directory, the
//// refusal of a newer schema, and the commit's version check and atomicity.

import core/endpoint
import core/offer
import core/plan.{Plan}
import core/relationship
import core/route
import core/time.{Instant}
import daemon/config
import daemon/node
import daemon/store
import daemon/support
import gleam/option.{None, Some}
import primitives/suite
import simplifile
import sqlight

const at = Instant(1000)

fn open() -> #(store.Store, String) {
  let path = support.fresh("store") <> ".db"
  let assert Ok(opened) = store.open(path, suite.suite())

  #(opened, path)
}

fn terms() -> relationship.Terms {
  let assert Ok(port) = endpoint.port(7000)
  let assert Ok(inbox) = route.new_inbox(suite.suite(), endpoint.Loopback(port))

  relationship.Terms(inbox:, description: "peer", budget: 3)
}

/// A new offer, committed as `Provisioning`.
fn started(opened: store.Store) -> offer.Offer {
  let assert Ok(made) =
    offer.create(suite.suite(), terms(), offer.OperatorApproves, at)
  let assert Ok(_) = store.commit(opened, at, store.OfferStarted(made, "label"))

  made.state
}

pub fn durability_settings_are_in_effect_test() {
  let #(opened, _) = open()
  let assert Ok(settings) = store.settings(opened)

  assert settings.journal_mode == "wal"
  assert settings.synchronous == 2
  assert settings.fullfsync == 1
  assert settings.foreign_keys == 1
  assert settings.busy_timeout == store.busy_timeout_ms
  assert settings.user_version == store.schema_version
}

pub fn a_newer_schema_is_refused_test() {
  let #(opened, path) = open()
  let assert Ok(Nil) = store.close(opened)

  let assert Ok(connection) = sqlight.open(path)
  let assert Ok(Nil) = sqlight.exec("PRAGMA user_version=99", connection)
  let assert Ok(Nil) = sqlight.close(connection)

  let assert Error(store.FutureSchema(found: 99, supported: 1)) =
    store.open(path, suite.suite())
}

pub fn the_state_directory_and_files_are_private_test() {
  let mailbox = support.start_mailbox()
  let settings = support.daemon_config(mailbox, support.fresh("modes"))
  let assert Ok(_) = node.start(settings)

  let mode = fn(path) {
    let assert Ok(info) = simplifile.file_info(path)
    simplifile.file_info_permissions_octal(info)
  }

  assert mode(settings.state_dir) == 0o700
  assert mode(settings.state_dir <> "/" <> node.database_file) == 0o600
  assert mode(settings.state_dir <> "/" <> node.lock_file) == 0o600
}

pub fn a_stale_version_is_a_conflict_and_changes_nothing_test() {
  let #(opened, _) = open()
  let made = started(opened)
  let opened_offer = offer.provisioned(made)

  // Version 5 was never written.
  assert store.commit(opened, at, store.OfferRevised(opened_offer, 5))
    |> result_is_conflict
  let assert Ok(Some(record)) = offer_by_queue(opened, made)
  let assert offer.Provisioning(_) = record.offer.phase
  assert record.version == 1

  // The right version succeeds once, and then it is stale.
  let assert Ok(_) =
    store.commit(opened, at, store.OfferRevised(opened_offer, 1))
  assert store.commit(opened, at, store.OfferRevised(opened_offer, 1))
    |> result_is_conflict
  let assert Ok(Some(after)) = offer_by_queue(opened, made)
  assert after.version == 2
}

pub fn a_failed_record_rolls_the_state_back_test() {
  let #(opened, _) = open()
  let made = started(opened)
  let opened_offer = offer.provisioned(made)
  let assert Ok(_) =
    store.commit(opened, at, store.OfferRevised(opened_offer, 1))

  // A joiner commits its handshake row once.
  let assert offer.Open(stock) = opened_offer.phase
  let assert Ok(joining) =
    relationship.join(
      suite.suite(),
      stock.invitation,
      endpoint.TorOrLoopback,
      terms(),
      at,
    )
  let assert Ok(_) =
    store.commit(opened, at, store.Started(joining, "invitation"))
  let assert Ok(started_session) =
    relationship.joined(suite.suite(), joining.state, at)
  let assert Ok(_) = store.commit(opened, at, store.Revised(started_session, 1))
  let assert Ok(Some(before)) =
    store.relationship_by_contact(opened, joining.state.contact)

  // The same outbox row again violates its key after the state write. The
  // whole commit must roll back, the state write included.
  let replay = Plan(..started_session, records: started_session.records)
  assert store.commit(opened, at, store.Revised(replay, before.version))
    |> result_is_failure

  let assert Ok(Some(after)) =
    store.relationship_by_contact(opened, joining.state.contact)
  assert after.version == before.version
}

fn offer_by_queue(opened: store.Store, made: offer.Offer) {
  let assert offer.Provisioning(stock) = made.phase
  store.offer_by_queue(opened, stock.inbox.queue)
}

fn result_is_conflict(outcome) -> Bool {
  case outcome {
    Error(store.Conflict) -> True
    _ -> False
  }
}

fn result_is_failure(outcome) -> Bool {
  case outcome {
    Error(_) -> True
    Ok(_) -> False
  }
}

pub fn meta_and_pending_counts_round_trip_test() {
  let #(opened, _) = open()

  assert store.meta_get(opened, "k") == Ok(None)
  let assert Ok(Nil) = store.meta_put(opened, "k", <<1, 2>>)
  assert store.meta_get(opened, "k") == Ok(Some(<<1, 2>>))
  assert store.pending_count(opened) == Ok(0)
  assert config.default_accept_budget > 0
}
