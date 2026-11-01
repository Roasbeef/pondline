# ADR-008 — A sender offers a retention deadline below the mailbox's maximum, and retries a refused one shorter

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §6.3, §6.4, §8.2, §11.3

## Decision

**The mailbox stays strict.** It accepts an `Append` only if the retention
deadline is after its own `now` and no later than its own
`now + message_retention_seconds`, and refuses anything else with
`BadDeadline` (`mailbox/service.insert_new`). Nothing here changes it.

**The sender makes room.** For every append the scheduler computes the
deadlines to offer with `core/retention.offers(expires_at: row.deadline,
now:)`, by its own clock, at the time of the send:

- The first offer is `now + message_retention_seconds -
  retention_slack_seconds`, and never later than the row's deadline (a
  message's own `expires_at`). `limits.retention_slack_seconds` is 3600.
- After a `BadDeadline`, the same envelope and the same bytes are offered
  again in the same attempt with the lifetime halved, up to
  `limits.max_deadline_offers` (4) offers in all. An offer is never `now` or
  earlier.
- A `BadDeadline` to the last offer is a failed attempt, retried with the
  scheduler's ordinary backoff (`scheduler.classify` now calls it
  `Transient`). The row's deadline bounds the retries: a row past it is
  failed without a send, as before.

Nothing about the offers is stored. The row's `deadline` column is still the
message's expiry, which is also the bound retransmission uses (ADR-006).

## Why

The DST harness found it blind (`docs/review/2026-11-01-dst-audit.md`, H1;
the swarm hit it in 32 runs). The sender asked for exactly the mailbox's
maximum by its own clock, so a daemon whose clock led the mailbox's by even
one second was refused `BadDeadline`, and the scheduler classed that as
permanent and failed the row. That covers application messages, receipts and
`Accept`, all of which use the full retention, so one skewed inviter left a
pairing stuck in `AwaitingAccept` for good. The owner ruled for sender slack
and a retryable refusal, with the mailbox left strict (`docs/dst/plan.md`).

**Why one hour.** A clock kept by NTP is within a second of true time; an
unsynchronised host drifts by seconds a day, minutes over a month; a host
that applies a daylight-saving change twice is an hour off. The slack covers
all of these on the first offer, and covers the simulation's skews (up to
600 s) many times over. An hour of a week's retention costs a receiver who
is offline for six days and 23 hours its message, which retransmission now
partly recovers (below). A larger slack buys coverage of misconfigured
clocks that the shorter offers already handle.

**Why halve, and why four offers.** A clock off by more than the slack is
misconfigured (a wrong time zone, a reset clock), and the sender cannot
learn the mailbox's time from the refusal. Halving the lifetime reaches an
accepted deadline in a few round trips for any lead short of the retention
window: after three halvings the lifetime is about 21 hours, which a sender
up to about six days ahead fits. Four offers bound the cost of a hopeless
clock at three extra round trips per attempt to a mailbox that has already
answered. The price of halving is retention: a sender just past the slack is
stored for three and a half days instead of nearly seven. That falls only on
a sender whose clock is wrong.

**Why in the same attempt, and why not stored.** A `BadDeadline` refusal
writes nothing (the mailbox checks the deadline before the quota and the
write), so offering the same envelope again under another deadline is safe,
and a replay of an envelope already stored answers from what was stored
whatever the new offer says. Computing the offers from the row and the time
of the send needs no schema change, and the deadline travels in the `Append`
request beside the padded ciphertext, not inside it, so the committed bytes
and the message's authenticated `expires_at` are untouched. Using the row's
attempt count as the step instead would have shortened the retention of any
row that merely met a network outage.

**Why retried rather than failed after the last offer.** A clock that is
wrong now is often corrected later (NTP catching up, an operator fixing the
zone). A permanent failure would lose the message, and for `Accept` the
pairing; a retry until the row's deadline delivers it once the clocks agree.

What is implemented and tested:

- `core/retention.offers`, the two limits, and `test/core/retention_test.gleam`
  (the default sits the slack below the maximum; a sender exactly the slack
  ahead is accepted on the first offer and one second more is not; the
  fallbacks halve and are bounded; as properties, every offer is in the
  future and within the row's deadline, and some offer is accepted for any
  skew the offers reach).
- `scheduler.send_row` and `classify_refusal`, and
  `test/daemon/clock_skew_test.gleam` with two real daemons and a real
  mailbox: a sender an hour ahead pairs and is stored on the first offer; a
  sender two days ahead pairs and is stored under a halved deadline; a
  mailbox thirty days behind leaves the row queued, not failed, and the
  message is delivered once the clock is put right. Mutation-checked: a zero
  slack fails the first, dropping the shorter offers fails the second, and a
  permanent `BadDeadline` fails the third and the classification test.
- The H1 seed now passes the simulation's oracle and sits in the corpus.

## Consequences

- Every envelope is held an hour less than the mailbox would allow, unless
  its message expires sooner.
- A sender whose clock is far enough ahead to need a shorter offer gets
  shorter retention, down to about 21 hours at the fourth offer. Nothing
  tells the operator; a status signal for "the mailbox disagrees with this
  clock" would.
- A sender more than about six days ahead, or a mailbox far enough ahead of
  the sender that the row's own deadline is already past by its clock, makes
  four appends per attempt until the row's deadline, at the scheduler's
  capped backoff (one attempt per five minutes): bounded, and the same order
  of cost as a mailbox that answers `Unavailable` for a week.
- A clock that jumps back while rows wait for a retry leaves their
  `next_attempt_at` in the future by the size of the jump, so the retry waits
  for the clock to catch up. This predates ADR-008 and applies to every
  retried row; this decision does not address it.
- Retransmitted copies (ADR-006) are sent at least `receipt_window_seconds`
  after the original was stored, which is no less than the slack, so their
  first offer is the message's own expiry: the copies outlive the original
  by up to the slack. ADR-006's addendum records what that recovers.
- Revisit the slack with measurements of real clock skew between daemons
  and mailboxes, and revisit halving if misconfigured clocks turn out to be
  common enough that the retention it costs matters.

## Addendum (2026-11-01): the offer at the deadline itself

The Lean proof of the offer ladder (`docs/formal/lean.md`) found that "an
offer is never `now` or earlier" holds for the halved fallbacks but not for
the first offer: at `now == expires_at`, `retention.offers` returns that
instant alone, and the mailbox refuses a deadline that is not after its
`now`. The scheduler still dispatches such a row, because `time.is_past`
treats the deadline itself as valid. The cost is one refused append in the
one second a row can be at its deadline, after which the retry finds the
row past it and fails it. That is cheaper than any mechanism to avoid it,
so the behaviour stands and the sentence above is read as applying to the
fallbacks.

