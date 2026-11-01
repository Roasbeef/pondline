# ADR-004 — An authenticated application message from the inviter is an implicit Accept

**Status**: accepted · **Date**: 2026-10-31 · **Spec ref**: §4.3, §6.5

## Decision

Spec §4.3 says the joiner does not present the relationship as active until
it authenticates `Accept`. This ADR amends that to: until it authenticates
`Accept` **or an application message from the inviter's session**.

In `core/relationship`, a relationship in `AwaitingAccept` that receives an
authenticated `Application` message becomes `Active` and then handles the
message exactly as an `Active` relationship does: it is checked for expiry,
counted against the inbound budget, stored `Ready` or `Held`, audited, and
answered with a receipt. A `Receipt` in `AwaitingAccept` is still ignored.
`Reject` and `Close` still close the relationship.

## Why

The mailbox does not promise order (spec §6.5), and the inviter queues its
`Accept` and its first application message as two envelopes on two
independent transmissions. If the application message is fetched first, the
joiner receives an authenticated message while it is still `AwaitingAccept`.
The earlier rule advanced the session and dropped the message, and the
inviter's receipt bookkeeping then waited forever for a receipt that was
never sent. Ordinary reordering lost an honest message.

The inviter can send an application message only from `Active`, which it
reaches only by approving, and after `Reject` its session is `Closed`. So an
application message that authenticates under the inviter's session proves
the approval as well as `Accept` does: the ratchet authenticates the
sender, and the sender's state machine has no path to produce the message
without having accepted. Treating it as an implicit `Accept` loses no
security and removes the loss.

A receipt does not carry the same proof. A joiner sends no application
message before it is `Active`, so no receipt can answer one, and a receipt
in `AwaitingAccept` is ignored.

What is implemented and tested: the transition in `relationship.in_awaiting`,
a pairing test that delivers the inviter's application message to the joiner
before its `Accept`, and a simulation property that every committed
application message is delivered once and receipted once after a fault-free
settle.

## Consequences

- The joiner may deliver application messages to its agent before it has
  seen `Accept`. That is within the authorization the inviter gave.
- The late `Accept` then arrives in `Active` and is ignored.
- A peer running other code could send an application message while the
  relationship is `PendingApproval` at the inviter. That case is unchanged:
  the inviter ignores it, because the inviter has not approved. The
  implicit accept applies only to the joiner, whose peer is the inviter.
- Revisit if a protocol version lets a joiner send before `Active`, since
  the argument that only an approved inviter can send would then need the
  same check on the other side.
