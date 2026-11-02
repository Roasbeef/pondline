//// Regression tests for bursts of application messages. The two-agent demo
//// once showed, with its sends unpaced, a reordered burst recorded as
//// dropped and a burst over the pairing budget handed to the agent as
//// `ready` while the contact's `held` count rose. Neither reproduced after
//// the weft port, and these tests keep both symptoms from returning: a
//// burst that reaches the mailbox newest first is delivered in full, and a
//// burst over budget is held, with the rows and the counters agreeing.

import core/endpoint
import core/envelope
import core/id
import core/mailbox/protocol
import core/offer
import core/route
import core/secret
import core/time
import daemon/api
import daemon/mailbox_client
import daemon/node
import daemon/support
import gleam/dynamic/decode
import gleam/int
import gleam/list
import gleam/option.{None, Some}
import sqlight

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

/// A name and a count per group, read from the daemon's database file.
fn groups(directory: String, sql: String) -> List(#(String, Int)) {
  let assert Ok(connection) = sqlight.open(directory <> "/daemon.db")
  let assert Ok(found) =
    sqlight.query(sql, connection, [], {
      use name <- decode.field(0, decode.string)
      use count <- decode.field(1, decode.int)
      decode.success(#(name, count))
    })
  let assert Ok(Nil) = sqlight.close(connection)

  found
}

/// Sends `count` messages from `daemon` back to back, none waiting for the
/// mailbox.
fn send_burst(daemon: api.Daemon, contact, count: Int) -> Nil {
  list.each(
    list.repeat(Nil, count) |> list.index_map(fn(_, i) { i + 1 }),
    fn(n) {
      let assert Ok(_) =
        api.send(
          daemon,
          contact,
          "text/plain",
          secret.new(<<int.to_string(n):utf8>>),
          None,
        )
    },
  )
}

pub fn a_burst_over_budget_is_held_test() {
  let mailbox = support.start_mailbox()
  let #(a, a_config) = support.start_daemon(mailbox)
  let #(b, _) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "tight", offer.OperatorApproves, 3)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = contact_in(a, api.PendingApproval)
  let assert Ok(Nil) = api.approve(a, at_a)
  let _ = contact_in(a, api.Active)
  let at_b = contact_in(b, api.Active)
  send_burst(b, at_b, 5)

  // All five are accounted for once used and held add up to five.
  let view =
    support.eventually(20_000, fn() {
      let assert Ok([view]) = api.contacts(a)

      support.when(view.budget_used + view.held >= 5)
      |> option.map(fn(_) { view })
    })
  assert view.budget_used == 3
  assert view.held == 2

  // The agent sees only the three within budget, and the rows say the same.
  let assert Ok(ready) = api.receive(a, None, 10)
  assert list.length(ready) == 3
  assert groups(
      a_config.state_dir,
      "SELECT status, count(*) FROM deliveries GROUP BY status ORDER BY status",
    )
    == [#("held", 2), #("ready", 3)]

  // Raising the budget releases the two that waited, and nothing else.
  let assert Ok(Nil) = api.raise_budget(a, at_a, 2)
  let released =
    support.eventually(20_000, fn() {
      let assert Ok(more) = api.receive(a, None, 10)
      support.when(list.length(more) == 5)
      |> option.map(fn(_) { more })
    })
  assert list.length(released) == 5
  assert groups(
      a_config.state_dir,
      "SELECT status, count(*) FROM deliveries GROUP BY status",
    )
    == [#("ready", 5)]
}

/// B's committed application rows, oldest first, as the `Append` requests
/// that would put them in A's queue, and the mailbox endpoint they target.
fn outbox_appends(directory: String) -> List(protocol.Request) {
  let assert Ok(connection) = sqlight.open(directory <> "/daemon.db")
  let assert Ok(found) =
    sqlight.query(
      "SELECT envelope, route, padded, deadline FROM outbox
       WHERE kind = 'application' ORDER BY rowid",
      connection,
      [],
      {
        use envelope <- decode.field(0, decode.bit_array)
        use target <- decode.field(1, decode.bit_array)
        use padded <- decode.field(2, decode.bit_array)
        use deadline <- decode.field(3, decode.int)
        decode.success(#(envelope, target, padded, deadline))
      },
    )
  let assert Ok(Nil) = sqlight.close(connection)

  list.map(found, fn(row) {
    let #(envelope_bytes, route_bytes, padded_bytes, deadline) = row
    let assert Ok(envelope_id) = id.from_bytes(envelope_bytes)
    let assert Ok(target) = route.decode(route_bytes)
    let assert Ok(padded) = envelope.from_wire(padded_bytes)

    protocol.Append(
      queue: target.queue,
      append: target.append,
      envelope: envelope_id,
      retention_deadline: time.Instant(deadline),
      ciphertext: padded,
    )
  })
}

pub fn a_burst_appended_out_of_order_is_delivered_test() {
  let mailbox = support.start_mailbox()
  let #(a, a_config) = support.start_daemon(mailbox)
  let #(b, b_config) = support.start_daemon(mailbox)

  let assert Ok(file) = api.invite(a, "burst", offer.OperatorApproves, 10)
  let assert Ok(_) = api.accept(b, file, "a")
  let at_a = contact_in(a, api.PendingApproval)
  let assert Ok(Nil) = api.approve(a, at_a)
  let _ = contact_in(a, api.Active)
  let at_b = contact_in(b, api.Active)

  // B goes offline so that nothing but this test delivers its rows.
  node.stop(b)
  let assert Ok(b) = node.start_offline(b_config)
  send_burst(b, at_b, 5)

  // The mailbox stores them newest first.
  let appends = outbox_appends(b_config.state_dir)
  assert list.length(appends) == 5
  let assert Ok(port) = endpoint.port(mailbox.port)
  list.each(list.reverse(appends), fn(request) {
    let assert Ok(protocol.Appended(_)) =
      mailbox_client.call(
        support.loopback_dialer(),
        endpoint.Loopback(port),
        "test",
        request,
        5000,
      )
  })

  // A's queue holds the Initial from pairing and then the five. Every one
  // is applied, and none is recorded as dropped.
  let ready =
    support.eventually(20_000, fn() {
      let assert Ok(found) = api.receive(a, None, 10)

      support.when(list.length(found) == 5)
      |> option.map(fn(_) { found })
    })
  assert list.length(ready) == 5
  assert groups(
      a_config.state_dir,
      "SELECT outcome, count(*) FROM processed GROUP BY outcome",
    )
    == [#("applied", 6)]
}
