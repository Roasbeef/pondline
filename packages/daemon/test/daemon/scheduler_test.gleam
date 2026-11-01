//// The pure parts of the workers' policy: backoff, and what each mailbox
//// answer means to the scheduler.

import core/capability
import core/endpoint
import core/envelope
import core/id
import core/mailbox/protocol
import core/route.{Route}
import core/time.{Instant}
import daemon/fetcher
import daemon/mailbox_client
import daemon/provisioner
import daemon/scheduler
import daemon/store
import gleam/list
import primitives

fn row() -> store.OutboxRow {
  let assert Ok(port) = endpoint.port(9000)
  let assert Ok(queue) = id.from_bytes(<<1:128>>)
  let assert Ok(envelope_id) = id.from_bytes(<<2:128>>)
  let assert Ok(append) = capability.from_bytes(<<3:256>>)
  let assert Ok(padded) = envelope.pad(<<"sealed":utf8>>)

  store.OutboxRow(
    envelope: envelope_id,
    route: Route(endpoint: endpoint.Loopback(port), queue:, append:),
    padded:,
    deadline: Instant(100),
    attempts: 0,
  )
}

fn receipt(row: store.OutboxRow, digest: BitArray) -> protocol.AppendReceipt {
  protocol.AppendReceipt(
    queue: row.route.queue,
    envelope: row.envelope,
    digest:,
    retention_deadline: row.deadline,
  )
}

pub fn backoff_doubles_and_is_capped_test() {
  assert list.map([0, 1, 2, 3, 4, 5], scheduler.backoff_seconds)
    == [2, 2, 4, 8, 16, 32]
  assert scheduler.backoff_seconds(9) == scheduler.backoff_cap_seconds
  assert scheduler.backoff_seconds(1000) == scheduler.backoff_cap_seconds
}

pub fn other_workers_back_off_the_same_way_test() {
  assert fetcher.backoff_ms(0) == fetcher.backoff_base_ms
  assert fetcher.backoff_ms(1000) == fetcher.backoff_cap_ms
  assert provisioner.delay_ms(0) == provisioner.tick_ms
  assert provisioner.delay_ms(1000) == provisioner.backoff_cap_ms
}

pub fn a_matching_receipt_is_accepted_test() {
  let sent = row()
  let digest = primitives.sha256(envelope.to_wire(sent.padded))

  let assert scheduler.Accepted(_) =
    scheduler.classify(
      primitives.sha256,
      sent,
      Ok(protocol.Appended(receipt(sent, digest))),
    )
}

pub fn a_receipt_for_other_bytes_is_refused_test() {
  let sent = row()

  assert scheduler.classify(
      primitives.sha256,
      sent,
      Ok(protocol.Appended(receipt(sent, <<0:256>>))),
    )
    == scheduler.Refused
}

pub fn permanent_refusals_fail_and_transient_ones_retry_test() {
  let sent = row()
  let verdict = fn(reason) {
    scheduler.classify(primitives.sha256, sent, Ok(protocol.Refused(reason)))
  }

  list.each(
    [
      protocol.Conflict,
      protocol.Unauthorized,
      protocol.TooLarge,
      protocol.Malformed,
      protocol.UnsupportedVersion,
    ],
    fn(reason) {
      assert verdict(reason) == scheduler.Refused
    },
  )

  // A deadline outside the mailbox's window is a clock disagreement, not a
  // verdict on the envelope (ADR-008), so it is retried.
  list.each(
    [protocol.QuotaExceeded, protocol.Unavailable, protocol.BadDeadline],
    fn(reason) {
      assert verdict(reason) == scheduler.Transient
    },
  )
}

pub fn a_transport_failure_retries_test() {
  assert scheduler.classify(
      primitives.sha256,
      row(),
      Error(mailbox_client.TimedOut),
    )
    == scheduler.Transient
  assert scheduler.classify(
      primitives.sha256,
      row(),
      Error(mailbox_client.DialFailed),
    )
    == scheduler.Transient
}
