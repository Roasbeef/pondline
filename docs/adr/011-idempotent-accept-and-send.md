# ADR-011 — Accepting an invitation twice returns the first relationship, and a send may carry an idempotency key

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §8.2, §8.5, §9.1, §9.2

## Decision

**Accept is idempotent by the invitation.** An invitation is redeemed once.
`engine.accept` decodes the file, looks the invitation's identifier up among
the relationships this daemon started and has not closed
(`store.contact_by_invitation`), and returns the relationship it finds
without starting anything. Only an invitation with no open joiner starts
one.

- Schema version 5 adds `relationships.invitation`, written for a joiner
  (`Started`, the one phase that holds the invitation) and empty for a
  relationship an offer produced, with a unique index over the joiners not
  `closed` as the backstop.
- A closed joiner releases its invitation, so an operator can close a
  joiner that cannot move (its `Hello` quarantined at the inviter, ADR-010)
  and accept again while the offer is open. A retry that races a close is
  not a case worth guarding: the caller closed the relationship itself.
  Closing a joiner whose `Hello` the inviter did process and accepting
  again gives a new joiner that waits for good, since the consumed offer
  refuses a second `Hello`; the operator chose that.
- `api.accept`, the local API's `accept` and the CLI keep their shape.

**Send takes an optional, caller-supplied idempotency key.**

- *Scope*: one relationship. The same key on two contacts is two keys.
- *Bound*: 1 to `limits.max_send_key_bytes` (128) bytes of UTF-8; anything
  else is refused before anything commits.
- *Lifetime*: `limits.send_key_seconds`, the 7-day message retention. A key
  older than that is forgotten (pruned in the transaction that stores the
  next key) and a send under it is a new message. A retry that late cannot
  be about a message still in flight: it has expired at the mailbox and at
  its reader.
- *Retry*: a send whose key is remembered with the same request (content
  type, reply target and payload, compared by a SHA-256 over a framed
  encoding of them) answers with the first message's identifier and queues
  nothing, whatever happened to that message since.
- *Reuse*: the same key with a different request is refused
  (`Refused("the idempotency key was used for a different message")`).
- The key commits in the send's own transaction (`store.KeyedSend`), so it
  exists exactly when the message does.
- `api.send` is unchanged; `api.send_with_key` is the keyed form. The local
  API's `send` takes an optional `idempotency_key`, and the CLI's `send` an
  optional `--idempotency-key KEY`. A send without a key is always new.

## Why

Hypothesis H4 of the DST audit, which the shell DST then counted as two
excuses (`h4_retried_accept`, `h4_retried_send`): `accept` and `send` answer
`Unavailable` when their commit landed but the answer did not reach the
caller (a store commit whose acknowledgement was lost, an engine job that
applied and then failed, an ask that timed out after the job ran). The
caller cannot tell that from a failure that changed nothing, and the only
sensible response, retrying, duplicated the effect:

- A retried accept started a second joiner for the same invitation. The
  inviter consumed the invitation on the first `Hello` and drops the
  second as a duplicate, so the second joiner sat in `AwaitingAccept`
  forever.
- A retried send queued the payload again under a fresh message identifier,
  which the peer delivered as a second message.

Spec §8.5 already says hosts need idempotency keys for external effects;
this gives the two commands that duplicate their effect on a retry, and
that the DST counted, one each.

**Why the invitation is the accept's key.** It already identifies exactly
the thing that must happen once, and the inviter enforces the same rule on
its side. A caller needs nothing new.

**Why send needs a caller's key.** Two sends of the same bytes may be two
messages on purpose ("ping", "ping"), so the daemon cannot infer a retry
from content. Only the caller knows that a second call is the first one
again.

**Why refuse a reused key rather than send.** A key reused for a different
request is a caller bug, and sending would hide it; answering with the first
message would report a payload as sent that never was.

**Why `invite` has no key.** A retried invite creates a second offer, which
costs a mailbox queue allowance and is visible to the operator; nothing is
delivered twice and nothing waits forever, since the unused offer expires.
The owner approved keys for accept and send.

What is implemented and tested:

- `daemon`: schema 5, `store.contact_by_invitation`, `send_by_key`,
  `KeyedSend`, `engine.accept`'s lookup, `engine.send`'s keyed path, the
  API, local API and CLI. `test/daemon/idempotency_test.gleam` runs two real
  daemons over a real mailbox with an engine fault hook that makes accept and
  send apply and then answer `Unavailable`: two lost accepts and a heard one
  are one relationship that pairs; two lost keyed sends and a heard one are
  one message, delivered once; the key reused with another payload is
  refused; key bounds and scope hold. Dropping the accept's lookup, or
  treating a keyed send as unkeyed, fails it.
- `sim`: every send carries its payload tag as its key; both H4 excuses are
  removed, and campaigns with engine `ApplyThenFail` faults on `Accept` and
  `Send` find no duplicate delivery and no unpaired joiner.

## Consequences

- `raise_budget(by)` is relative, so a raise that committed and answered
  `Unavailable`, retried, grants `2 * by` and may release more held messages
  than meant. An absolute target would make it idempotent; it is left for a
  later change. `approve`, `decline`, `close` and `acknowledge` apply once,
  but a retry after a lost answer is told `Refused` or `NotFound` because
  the first one moved the state on.
- The lookup is by invitation identifier. A different file that reuses an
  identifier (someone who saw the first file forging a second) gets the
  earlier contact back rather than a new joiner; such a holder could have
  redeemed the real invitation anyway.
- Relationships started before schema 5 have no `invitation`, so a retried
  accept of an invitation accepted before the upgrade still starts a second
  joiner. Pre-release; no backfill.
- `send_keys` holds at most the keyed sends of the last seven days.
- A caller that wants retry safety must choose and keep a key; the agent
  adapters in `scripts/agents/` can adopt it as they are revised.
- Revisit if invites become expensive enough to need a key, or if a
  per-agent rather than per-contact scope is wanted once a daemon hosts more
  than one agent principal.
