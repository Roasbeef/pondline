# ADR-006 — A stored message with no peer receipt is sent again, and a repeated ciphertext is answered with its receipt

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §6.4, §7.3, §8.2, §11.3

## Decision

**Sender.** An outbound application message, or an `Accept`, `Reject` or
`Close`, whose envelope the mailbox stored (`Appended`) and whose message has
no peer receipt is sent again once its receipt window passes. A retransmit
is the **same committed padded ciphertext** under a **new envelope
identifier**. It is never re-encrypted.

- The schedule is `core/retransmit.due_at`: a row the mailbox stored at `t`
  after `k` earlier copies is due at `t + receipt_window_seconds * 2^k`.
  `limits.receipt_window_seconds` is 3600 and `limits.max_retransmits` is 5,
  so the last copy goes out 31 hours after the first was stored.
- No copy is scheduled or sent past the row's retention deadline, which for
  a message is its own `expires_at`.
- `core/retransmit.retransmit` decides against the relationship as it is
  when the row comes due: an application message is sent again only while
  the relationship is `Active` (the one phase that can still read the receipt
  that ends the schedule); a control is sent again whatever the phase, since
  it earns no receipt and the session that sealed it may be gone. Receipts
  and the handshake are never sent again.
- The peer's receipt (`PeerReceived`) ends the schedule of every row carrying
  the message. A control's schedule runs to its bound.
- In the daemon the store does the copy, as an `INSERT ... SELECT` from the
  replaced row inside the commit (`store.Retransmitted`), and the scheduler
  asks for due copies on every tick (`engine.retransmit`). The copy is an
  ordinary queued outbox row, so "no send before commit" holds for it as for
  every row.

**Receiver.** A relationship remembers the fingerprint of every ciphertext it
stored an application message from: SHA-256 of the ratchet message inside the
padding (`relationship.fingerprint`), the message identifier, the message's
expiry and how many receipts it has been answered with (`plan.Fingerprint`,
committed as a `Remembered` record with the delivery). Before decrypting a
`Ratchet` frame the shell looks its fingerprint up. A known one is a
retransmit or a replay: it is recorded processed, acknowledged, and answered
with the same logical receipt (a new receipt message naming the same message
identifier, `relationship.resend_receipt`). It is never delivered again.

- A known ciphertext is answered at most `max_retransmits` times beyond the
  first receipt, and never after the message expired; past either, it is
  dropped and acknowledged (`relationship.DuplicateIgnored`).
- Fingerprints are pruned once their message expires, which bounds the table
  by the inbound budget and the retention window.
- A receipt for a message already `ReceivedByPeer` changes nothing.

## Why

A mailbox's `Appended` is evidence of acceptance, not a promise to deliver
(spec §6.4). Three cases lost a message for good: a mailbox that corrupts a
stored envelope (the receiver cannot decrypt it, so it drops and acknowledges
it), a mailbox that drops an envelope after acknowledging its append, and an
envelope the mailbox expires before the receiver fetches it. In each the
scheduler had stopped at `Appended` and nothing ever sent again. The pure
simulation carried this as three counted excuses
(`message-corrupted-in-mailbox`, `close-corrupted-in-mailbox`,
`receipt-corrupted-in-mailbox`). The owner ruled to fix it with sender
retransmission.

**Why the same bytes.** Encryption is deterministic in the ratchet state
(`docs/crypto-profile-v1.md`). Re-encrypting from the state that sealed the
original would seal two ciphertexts under one message key; encrypting from
the current state would make a second message with a second identifier, which
the receiver would deliver twice. Sending the committed bytes keeps "one
message, one key, one delivery".

**Why a new envelope identifier.** The mailbox keeps a tombstone for every
acknowledged envelope and answers a repeated append of it from the tombstone
without storing anything (spec §6.5). The receiver acknowledged the
corrupted copy, so the old identifier can never be stored again.

**Why the receiver needs fingerprints.** If the first copy arrived and only
the receipt was lost, the ratchet has spent the message's key, and the copy
fails to decrypt. That is what keeps the message from being delivered twice,
but it would also leave the sender without its receipt forever. Spec §7.3
already asks that a receiver "retain enough information to regenerate the
same logical receipt when an already processed envelope is delivered again";
the fingerprint is that information. Hashing inside the padding means a copy
whose padding tail a mailbox damaged still matches, and a failed decrypt of a
ciphertext never stored is unaffected.

**Why the bound on regenerated receipts.** A mailbox can replay a stored
ciphertext under fresh identifiers at will. Without a bound, each replay
would cost the receiver a ratchet step and an outbound envelope. An honest
sender sends at most `max_retransmits` copies, so that many regenerated
receipts is all an honest exchange ever needs.

**Why the window doubles from one hour.** A receiver may be offline for hours;
each copy costs it queue capacity and one regenerated receipt. Doubling from
one hour keeps a day-long outage to five copies, and the recovery for the
rare mailbox fault this addresses to an hour or two.

What is implemented and tested:

- `core`: `retransmit.due_at` and `retransmit.retransmit`,
  `relationship.fingerprint` and `relationship.resend_receipt`, the
  `Remembered` record, and the two limits (`test/core/retransmit_test.gleam`).
- The pure simulation (`test/core/world.gleam`): the excuses are gone; the
  mailbox also sweeps expired envelopes and has a `Loss` fault (an envelope
  dropped after `Appended`); the heal phase moves the clock through the
  receipt windows. Swarm campaigns of thousands of seeds pass. Mutation:
  never scheduling a retransmit fails the swarm with "committed message was
  never delivered"; never remembering a fingerprint fails it with "delivered
  message was never receipted".
- The daemon: schema version 2 (`outbox.retransmits`,
  `outbox.retransmit_at`, `fingerprints`), `engine.retransmit`, the
  scheduler's tick, and the fingerprint lookup in `engine.process`.
  `test/daemon/retransmit_test.gleam` runs two daemons and a real mailbox
  whose database the test damages after `Appended`: a corrupted message is
  delivered once and receipted, and a lost receipt is regenerated. Both fail
  with retransmission disabled, and the second with the lookup disabled.

## Consequences

- An honest exchange can now hold up to `1 + max_retransmits` copies of one
  message in a receiver's queue (when the receiver is offline long enough),
  and a receiver can send as many receipts for it. Receipts are idempotent at
  the sender.
- A control (`Accept`, `Reject`, `Close`) is always sent `max_retransmits`
  extra times over 31 hours, because no receipt ends its schedule. The copies
  fail to decrypt at a receiver that already processed the original and are
  dropped. Giving controls receipts, or ending an `Accept`'s schedule on the
  peer's first message, would remove this; neither is needed for
  correctness.
- A message refused with `HeldFull` spends no key, so its retransmit is
  stored once the operator raises the budget. Before, it was lost.
- The handshake's `Initial` frame is not retransmitted. A mailbox that
  spoils it still strands the joiner in `AwaitingAccept` until the
  invitation expires. Redeeming a repeated `Initial` is already idempotent
  (`offer.Duplicate`), so adding it later is cheap.
- Retention expiry is recovered only when the retention deadline is earlier
  than the message's expiry. Today the two are equal, so a message the
  mailbox expired is also past retransmission; the planned sender slack on
  the retention deadline (`docs/dst/plan.md`, clock skew) would make the
  retransmit cover that window too.
- Rows a schema 1 file holds as stored and unreceipted at upgrade get no
  `retransmit_at` (the migration adds the column empty, and only a later
  `record_send(Stored)` sets it), so they are never retransmitted. This is
  a one-time gap at the upgrade.
- Revisit the window and the bound with measurements from real deployments:
  how long receivers are offline, and how often mailboxes lose data.

## Addendum (2026-11-01): retention slack (ADR-008)

The consequence above about retention expiry assumed the retention
deadline and the message's expiry were equal. ADR-008 makes them differ: a
send offers the mailbox `min(expires_at, now + message_retention_seconds -
retention_slack_seconds)`, computed at the time of each send, while the
row's `deadline`, which bounds the retransmit schedule, stays the message's
`expires_at`.

So the slack does let retransmission cover part of the retention-expiry
window. The original copy is held until about an hour before the message
expires (less the time between sealing and the first send). Every
retransmitted copy is sent at least `receipt_window_seconds` after the
original was stored, and that window is no shorter than the slack, so a
copy's first offer is the message's own expiry and the mailbox holds it to
the end. A receiver offline long enough that the mailbox swept the original,
but back before the message expires, fetches a copy and delivers it. The
window this recovers is at most `retention_slack_seconds` wide, and only for
a message that earned no receipt in the 31 hours its copies are sent over:
no copy is scheduled in response to the mailbox's expiry, so a longer gap
between sweep and expiry would need a schedule that runs later than
`due_at`'s does today. If the slack is ever raised above the receipt
window, the first copy is held short of the expiry too, and only the later
copies cover the window.
