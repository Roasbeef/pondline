//// The retention deadline a sender asks a mailbox to keep an envelope
//// until, and the shorter ones it falls back to when the mailbox refuses
//// (`docs/adr/008-deadline-slack.md`, spec §6.3, §6.4).
////
//// A mailbox accepts an `Append` only if its retention deadline is in the
//// future and no later than its own `now + message_retention_seconds`, and
//// it judges both against its own clock. A sender that asked for exactly
//// that maximum by its own clock was refused `BadDeadline` whenever its
//// clock ran even a second ahead of the mailbox's, and the refusal used to
//// fail the outbox row for good: messages, receipts and `Accept` alike, so
//// a pairing could stick forever. The mailbox stays strict; the sender
//// makes room instead, in two steps.
////
//// ## Slack, then shorter offers
////
//// The first deadline a sender offers sits `retention_slack_seconds` below
//// the mailbox's maximum by the sender's clock, and never past the row's own
//// deadline (a message's `expires_at`). A sender up to that far ahead of the
//// mailbox is accepted on the first try.
////
//// A sender further ahead is refused `BadDeadline`, and offers again, in the
//// same attempt, with the lifetime halved, up to `max_deadline_offers`
//// offers in all. Halving reaches a deadline the mailbox accepts in a few
//// round trips for any skew short of the whole retention window, and the
//// list is finite by construction, so an attempt can never offer without
//// end. What happens after the last offer is the scheduler's policy: the
//// attempt counts as failed and is retried with backoff, and the row's own
//// deadline ends that, because a row past it is never sent.
////
//// ## What is computed, and when
////
//// Everything here is a function of the row's deadline and the time of the
//// send, so nothing new is stored. The deadline offered travels in the
//// `Append` request beside the padded ciphertext, not inside it, so the
//// committed bytes and the message's authenticated `expires_at` never
//// change; only how long the mailbox is asked to hold them does.

import core/limits
import core/time.{type Instant}
import gleam/int

/// The retention deadlines one append offers a mailbox, in the order it
/// offers them: the default first, then the shorter ones it falls back to
/// after a `BadDeadline`, each halving the lifetime of the one before. The
/// default is `retention_slack_seconds` below the mailbox's maximum by the
/// sender's clock, and never later than `expires_at`. The shorter list holds
/// at most `max_deadline_offers - 1` deadlines, each still after `now`, so
/// it is empty when the default leaves no second to halve.
///
/// ## Examples
///
/// ```gleam
/// retention.offers(expires_at: time.add(now, 604_800), now:)
/// // -> #(time.add(now, 601_200),
/// //      [time.add(now, 300_600), time.add(now, 150_300), time.add(now, 75_150)])
///
/// retention.offers(expires_at: time.add(now, 60), now:)
/// // -> #(time.add(now, 60), [time.add(now, 30), time.add(now, 15), time.add(now, 7)])
/// ```
pub fn offers(
  expires_at expires_at: Instant,
  now now: Instant,
) -> #(Instant, List(Instant)) {
  let ceiling =
    time.add(
      now,
      limits.message_retention_seconds - limits.retention_slack_seconds,
    )
  let first =
    time.Instant(int.min(expires_at.unix_seconds, ceiling.unix_seconds))
  let lifetime = first.unix_seconds - now.unix_seconds

  #(first, halved(now, lifetime, limits.max_deadline_offers - 1))
}

/// Up to `left` deadlines after `now`, each halving the lifetime before it.
fn halved(now: Instant, lifetime: Int, left: Int) -> List(Instant) {
  let half = lifetime / 2

  // A half of zero seconds is a deadline of `now`, which the mailbox
  // refuses as already past, and every later half is no better; the list
  // stops there or at its bound, whichever comes first.
  case left > 0 && half > 0 {
    True -> [time.add(now, half), ..halved(now, half, left - 1)]
    False -> []
  }
}
