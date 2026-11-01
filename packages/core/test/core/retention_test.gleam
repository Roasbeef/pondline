//// The retention deadlines a sender offers a mailbox (ADR-008): the default
//// sits the slack below the mailbox's maximum, the fallbacks halve it, and
//// the list is bounded and never offers a deadline the mailbox would refuse
//// as already past. The mailbox's own window is restated here as a
//// predicate so that a sender ahead of it by a given skew can be checked
//// against the offers directly.

import core/limits
import core/retention
import core/time.{type Instant, Instant}
import gleam/list
import qcheck

const now = Instant(1_000_000_000)

/// Whether a mailbox whose clock reads `mailbox_now` accepts `deadline`,
/// as `mailbox/service.insert_new` judges it.
fn accepted(deadline: Instant, mailbox_now: Instant) -> Bool {
  deadline.unix_seconds > mailbox_now.unix_seconds
  && deadline.unix_seconds
  <= mailbox_now.unix_seconds + limits.message_retention_seconds
}

fn all(offers: #(Instant, List(Instant))) -> List(Instant) {
  let #(first, shorter) = offers
  [first, ..shorter]
}

pub fn the_default_sits_the_slack_below_the_maximum_test() {
  let expires_at = time.add(now, limits.message_retention_seconds)
  let #(first, _) = retention.offers(expires_at:, now:)

  assert first
    == time.add(
      now,
      limits.message_retention_seconds - limits.retention_slack_seconds,
    )
}

pub fn a_sender_ahead_by_the_slack_is_accepted_first_test() {
  let expires_at = time.add(now, limits.message_retention_seconds)
  let #(first, _) = retention.offers(expires_at:, now:)

  // The sender reads its clock `slack` seconds ahead of the mailbox: the
  // first offer is still inside the window. One second more is not.
  assert accepted(first, time.add(now, 0 - limits.retention_slack_seconds))
  assert !accepted(first, time.add(now, -1 - limits.retention_slack_seconds))
}

pub fn a_short_lifetime_is_offered_unchanged_test() {
  let expires_at = time.add(now, 60)

  assert retention.offers(expires_at:, now:)
    == #(expires_at, [time.add(now, 30), time.add(now, 15), time.add(now, 7)])
}

pub fn the_fallbacks_halve_and_are_bounded_test() {
  let expires_at = time.add(now, limits.message_retention_seconds)
  let #(first, shorter) = retention.offers(expires_at:, now:)
  let lifetime = first.unix_seconds - now.unix_seconds

  assert list.length(shorter) == limits.max_deadline_offers - 1
  assert shorter
    == [
      time.add(now, lifetime / 2),
      time.add(now, lifetime / 4),
      time.add(now, lifetime / 8),
    ]
}

pub fn no_offer_is_made_for_a_deadline_already_reached_test() {
  // A row at its deadline still gets its one offer (the mailbox's answer is
  // the scheduler's to judge), but nothing shorter, which would be past.
  assert retention.offers(expires_at: now, now:) == #(now, [])
  assert retention.offers(expires_at: time.add(now, 1), now:)
    == #(time.add(now, 1), [])
}

pub fn every_offer_is_in_the_future_and_within_expiry_test() {
  use lifetime <- qcheck.given(qcheck.bounded_int(
    1,
    2 * limits.message_retention_seconds,
  ))
  let expires_at = time.add(now, lifetime)
  let offers = all(retention.offers(expires_at:, now:))

  assert list.length(offers) <= limits.max_deadline_offers
  assert list.all(offers, fn(deadline) {
    deadline.unix_seconds > now.unix_seconds
    && deadline.unix_seconds <= expires_at.unix_seconds
  })
}

pub fn some_offer_is_accepted_for_any_skew_the_ladder_covers_test() {
  // ADR-008 claims a sender up to six days ahead of the mailbox finds an
  // accepted deadline among its offers. The reach is the claim, not derived
  // from the ladder, so losing a rung fails this test.
  let expires_at = time.add(now, limits.message_retention_seconds)
  let offers = all(retention.offers(expires_at:, now:))
  let reach = 6 * 86_400

  use skew <- qcheck.given(qcheck.bounded_int(0, reach))
  let mailbox_now = time.add(now, 0 - skew)

  assert list.any(offers, accepted(_, mailbox_now))
}

pub fn the_slack_is_a_small_part_of_retention_test() {
  // An hour of a week: the slack must not eat the retention it protects.
  assert limits.retention_slack_seconds > 0
  assert limits.retention_slack_seconds * 100 < limits.message_retention_seconds

  // ADR-006's addendum: a retransmitted copy goes out at least one receipt
  // window after the original was stored, so its first offer is the
  // message's own expiry only while the slack is no wider than that window.
  assert limits.retention_slack_seconds <= limits.receipt_window_seconds
}
