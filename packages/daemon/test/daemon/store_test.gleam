//// The durable store: settings, the modes of the state directory, the
//// refusal of a newer schema, and the commit's version check and atomicity.

import core/endpoint
import core/id
import core/offer
import core/plan.{Plan}
import core/relationship
import core/route
import core/secret
import core/time.{Instant}
import daemon/config
import daemon/node
import daemon/store
import daemon/support
import gleam/dynamic/decode
import gleam/list
import gleam/option.{None, Some}
import gleam/result
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

  let assert Error(store.FutureSchema(found: 99, supported:)) =
    store.open(path, suite.suite())
  assert supported == store.schema_version
}

/// A file written by schema 1, with a committed outbox row, migrates to
/// schema 2 in place: the row survives, nothing is due for retransmission,
/// and the new fingerprint table answers.
pub fn a_populated_first_schema_migrates_test() {
  let #(opened, path) = open()
  let #(contact, _) = joined(opened)
  let assert Ok(Nil) = store.close(opened)

  // Take the file back to what a schema 1 build left on disk.
  let assert Ok(connection) = sqlight.open(path)
  let assert Ok(Nil) =
    sqlight.exec(
      "DROP INDEX outbox_retransmit;
       ALTER TABLE outbox DROP COLUMN retransmits;
       ALTER TABLE outbox DROP COLUMN retransmit_at;
       DROP TABLE fingerprints;
       DROP TABLE incidents;
       DROP TABLE attempts;
       DROP INDEX relationships_by_invitation;
       ALTER TABLE relationships DROP COLUMN invitation;
       DROP TABLE send_keys;
       PRAGMA user_version=1;",
      connection,
    )
  let assert Ok(rows_before) = outbox_rows(connection)
  let assert Ok(Nil) = sqlight.close(connection)
  assert rows_before > 0

  let assert Ok(migrated) = store.open(path, suite.suite())
  let assert Ok(settings) = store.settings(migrated)
  assert settings.user_version == store.schema_version
  assert store.due_retransmits(migrated, at, 16) == Ok([])
  assert store.fingerprint(migrated, contact, <<0:256>>) == Ok(None)
  let assert Ok(Nil) = store.close(migrated)

  let assert Ok(connection) = sqlight.open(path)
  assert outbox_rows(connection) == Ok(rows_before)
  let assert Ok(Nil) = sqlight.close(connection)
}

fn outbox_rows(connection: sqlight.Connection) -> Result(Int, sqlight.Error) {
  let count = {
    use rows <- decode.field(0, decode.int)
    decode.success(rows)
  }

  use found <- result.try(sqlight.query(
    "SELECT count(*) FROM outbox",
    on: connection,
    with: [],
    expecting: count,
  ))
  let assert [rows] = found as "count(*) returns one row"
  Ok(rows)
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

/// A joiner's relationship, committed through `Revised` at version 2, with
/// the plan that wrote it.
fn joined(opened: store.Store) {
  let made = started(opened)
  let opened_offer = offer.provisioned(made)
  let assert Ok(_) =
    store.commit(opened, at, store.OfferRevised(opened_offer, 1))
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
  let assert Ok(session) = relationship.joined(suite.suite(), joining.state, at)
  let assert Ok(_) = store.commit(opened, at, store.Revised(session, 1))

  #(joining.state.contact, session)
}

fn delivery(contact, payload: BitArray) -> plan.Record {
  let assert Ok(message) = id.from_bytes(<<9:128>>)

  plan.Delivered(
    message:,
    contact:,
    content_type: "text/plain",
    payload: secret.new(payload),
    in_reply_to: None,
    status: plan.Ready,
    at:,
  )
}

pub fn a_second_delivery_of_one_message_fails_the_whole_commit_test() {
  let #(opened, _) = open()
  let #(contact, session) = joined(opened)
  let assert Ok(Some(before)) = store.relationship_by_contact(opened, contact)

  // The first delivery of the message commits.
  let first = Plan(..session, records: [delivery(contact, <<"first":utf8>>)])
  let assert Ok(_) =
    store.commit(opened, at, store.Revised(first, before.version))
  let assert Ok(Some(middle)) = store.relationship_by_contact(opened, contact)
  assert middle.version == before.version + 1

  // A second delivery of the same message must not be ignored: the commit
  // fails and its state write rolls back with it.
  let second = Plan(..session, records: [delivery(contact, <<"second":utf8>>)])
  assert store.commit(opened, at, store.Revised(second, middle.version))
    |> result_is_failure
  let assert Ok(Some(after)) = store.relationship_by_contact(opened, contact)
  assert after.version == middle.version

  // The row that was stored first is the only one.
  let assert Ok(ready) = store.ready_deliveries(opened, None, 10)
  assert list.map(ready, fn(row) { secret.expose(row.payload) })
    == [<<"first":utf8>>]
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

/// The history the core is told is the deliveries' own: an identifier is
/// used once a delivery under it commits, on that relationship only. A
/// `RepeatedMessage` record becomes an incident the operator can list.
pub fn message_history_and_incidents_test() {
  let #(opened, _) = open()
  let #(contact, session) = joined(opened)
  let assert Ok(message) = id.from_bytes(<<9:128>>)
  let assert Ok(other) = id.from_bytes(<<8:128>>)
  let assert Ok(Some(before)) = store.relationship_by_contact(opened, contact)

  assert store.message_history(opened, contact, message)
    == Ok(relationship.FreshId)

  let assert Ok(queue) = id.from_bytes(<<3:128>>)
  let assert Ok(envelope) = id.from_bytes(<<4:128>>)
  let records = [
    delivery(contact, <<"first":utf8>>),
    plan.RepeatedMessage(contact:, message:, queue:, envelope:),
  ]
  let assert Ok(_) =
    store.commit(
      opened,
      at,
      store.Revised(Plan(..session, records:), before.version),
    )

  assert store.message_history(opened, contact, message)
    == Ok(relationship.UsedId)
  assert store.message_history(opened, contact, other)
    == Ok(relationship.FreshId)

  let assert Ok([incident]) = store.incidents(opened, 10)
  assert incident.kind == store.RepeatedMessageId
  assert incident.contact == Some(contact)
  assert incident.message == Some(message)
  assert incident.envelope == envelope
  assert incident.attempts == None
  assert store.incident_count(opened) == Ok(1)
}

/// An attempt count goes up one per call, survives a reopen of the file,
/// and is cleared by the `Processed` row that settles the envelope; a
/// quarantine writes that row as dropped and an incident with the count.
pub fn attempts_count_durably_and_settle_with_the_envelope_test() {
  let #(opened, path) = open()
  let assert Ok(queue) = id.from_bytes(<<5:128>>)
  let assert Ok(envelope) = id.from_bytes(<<6:128>>)
  let ref = plan.EnvelopeRef(queue:, envelope:, digest: <<1, 2>>)

  assert store.count_attempt(opened, queue, envelope) == Ok(1)
  assert store.count_attempt(opened, queue, envelope) == Ok(2)
  let assert Ok(Nil) = store.close(opened)

  let assert Ok(opened) = store.open(path, suite.suite())
  assert store.count_attempt(opened, queue, envelope) == Ok(3)

  let assert Ok(_) =
    store.commit(
      opened,
      at,
      store.Quarantined(ref:, contact: None, attempts: 3),
    )
  assert store.processed_digest(opened, queue, envelope) == Ok(Some(<<1, 2>>))
  assert store.unacked(opened, queue) == Ok([envelope])
  let assert Ok([incident]) = store.incidents(opened, 10)
  assert incident.kind == store.QuarantinedEnvelope
  assert incident.attempts == Some(3)
  assert incident.contact == None

  // Settled, the envelope's count starts again from nothing.
  assert store.count_attempt(opened, queue, envelope) == Ok(1)
}
