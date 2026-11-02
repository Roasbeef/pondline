# ADR-013 — The invitation embeds the prekey bundle and carries no join secret

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §4.2, §4.3, §6.2

## Decision

**The invitation file carries the inviter's public prekey bundle itself.** A
mailbox never holds or serves a bundle, so `PublishBundle`, `ClaimBundle`,
the bundle commitment, and the enrollment capability that authorized a fetch
do not exist.

**There is no `join_secret`.** The invitation does not carry one, the `Hello`
does not carry one, and the inviter checks none. Possession of the invitation
is proved by the handshake: the joiner can only build a valid initial message
from the bundle's prekeys, and the inviter's offer accepts one authenticated
`Hello`, naming that invitation, once.

The code has worked this way since the state machines landed
(`core/invitation`, `core/message`, `core/offer`). This record closes the gap
with the spec, which still required the check.

## Why

The join secret answered a threat that the published bundle created. A
mailbox that stored the bundle and knew the enrollment capability could have
run the handshake itself, so the spec added a second secret the mailbox never
saw (`docs/design-intent.md`, "Two different secrets serve two different
purposes"). The design review (`docs/review/2026-10-31-design-review.md`
§3.3) proposed removing the cause: with the bundle out of band, the mailbox
never sees it and cannot run the handshake, and the bundle substitution attack
cannot occur. The size argument for the indirection did not hold, since the
invitation is a file and ADR-009 gives a short ticket for the cases where a
file is awkward.

A ticket does put the invitation at a mailbox, but sealed under a key the
mailbox does not have, with a key-committing check (ADR-009). The mailbox's
view is still ciphertext.

A join secret inside the same file would add nothing. It would be read and
leaked together with the rest of the invitation, which is already a bearer
credential.

Evidence from the symbolic model (`docs/formal/crypto.md`): in the row `base`,
the model has no join secret and Q5 is proved: every session the inviter
accepts matches one that an honest joiner started. In the row `leak`, where the
attacker holds the invitation, the same query is refused, which is the
bearer-credential behaviour the spec already states. This is a symbolic result
under that model's assumptions; it is not a computational proof.

## Consequences

- A stolen invitation can be redeemed by the thief, as before. The defences
  are the same as before: the deadline, single consumption, and local approval
  of the contact. A joiner who redeems first locks the honest joiner out.
- The mailbox can still deny service by dropping a `Hello`. It cannot make an
  invalid claimant into a contact.
- The first message remains signed by the joiner (ADR-005), so it is not
  deniable. `docs/research/initiator-deniability.md` sketches a join-secret MAC
  for a future `CryptoProfileV2` as a way to restore that. If that is adopted,
  the secret returns for a new reason, by a new record that supersedes this
  part.
- The invitation is about 14.6 KB, which is why the ticket exists.
- `docs/spec.md` §4.2, §4.3 and §6.2 and `docs/design-intent.md`'s pairing
  section and scenario table are amended to match.
