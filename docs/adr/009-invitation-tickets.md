# ADR-009 — An invitation travels as a short ticket, and the invitation waits sealed at the inviter's mailbox

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §4.2, §4.3, §6.2, §9.2, §11.3

## Decision

**A ticket.** `invite create --ticket` prints a string such as

```text
pl1q0x7vvfgcfvz3jjt4c29kddntq35l0aj4d7c6cvvf57d5phdr9u0jz3crqpg88nlchnwdxp6qxla0x2u0hahqymxe23aefrlxk9utlqsq662klmqgan6g959vd0p6z3
```

130 characters for an onion mailbox, 74 for a loopback one (tests and the
demo). It holds the inviter mailbox's endpoint and a fresh 32-byte secret
`K`, and nothing else. `invite accept --ticket` reads one from `--file` or
`--stdin`. The invitation file stays supported: `--out` still writes it,
with or without `--ticket`, and `invite accept --file` still reads one.

**Text form** (`core/ticket`, `core/codex32`). `pl1`, then data symbols in
the bech32 alphabet, then a fifteen-symbol checksum. The first data symbol
is the format: 0 onion, 1 loopback; any other is refused. The payload is
regrouped as 5-bit symbols, most significant bit first, its padding bits
zero:

| Format | Payload | Bytes |
|---|---|---|
| 0, onion | decoded onion label (key 32, checksum 2, version 1), port (u16), `K` | 69 |
| 1, loopback | port (u16), `K` | 34 |

The onion label travels as its 35 decoded bytes, not its 62 characters, and
carrying the label's own checksum and version byte means no SHA3 is needed
to rebuild the hostname. The decoder is total and strict: at most
`limits.max_ticket_bytes` (192), lowercase only, no whitespace, the checksum
checked before the payload is read, the exact length for the format, zero
padding, a valid port and a v3 label. A string it accepts is the only
spelling of its ticket.

**The checksum is BIP-93's long codex32 code, not bech32m's.** Bech32m's
six-symbol checksum guarantees to detect four substituted characters only
for a data part, checksum included, of up to 89 characters (BIP-173); an
onion ticket's would be 118. The onion key and `K` alone are 64 bytes, 103
symbols, so no layout fits under 89. BIP-93
defines a BCH code over the same alphabet with a fifteen-symbol checksum
that guarantees to detect any error changing at most eight symbols in an
expanded codeword (prefix expansion, data, checksum) of up to 1023
symbols, and gives a random error a chance below 3 in 10^23 of passing.
The generator, the target residue `0x43381e570bf4798ab26` and BIP-173's
prefix expansion are taken unchanged; `codex32_test` reproduces BIP-93's
fifth test vector. Only the human-readable part (`rw`) differs from a
codex32 seed's (`ms`), which keeps the two from being mistaken for each
other. The cost is nine characters over bech32m.

**Derivations** (`core/ticket.keys`):

```text
PRK        = HKDF-Extract(salt = "Pondline_Ticket_v1", ikm = K)
locator    = HKDF-Expand(PRK, "Pondline_TicketLocator_v1", 16)     the blob's name
retrieve   = HKDF-Expand(PRK, "Pondline_TicketCapability_v1", 32)  fetches it
key, nonce = HKDF-Expand(PRK, "Pondline_TicketKey_v1", 44)         32 then 12
commit_key = HKDF-Expand(PRK, "Pondline_TicketCommitment_v1", 32)
```

**The sealed blob**:

```text
blob       = 0x01 || commitment (32) || ChaCha20-Poly1305(key, nonce,
               aad = "Pondline_TicketBlob_v1" || locator, invitation file)
commitment = HMAC-SHA-256(commit_key, invitation file)
```

`open` checks the version, then the AEAD, then recomputes the commitment
from the plaintext and compares it in constant time; nothing leaves `open`
that has not passed both. The joiner then decodes the invitation (which
verifies the bundle's hybrid signatures) and refuses one whose route names
a different mailbox than the ticket, before importing it through the
existing `accept`.

**The mailbox protocol gains two requests** (`core/mailbox/protocol`,
codec kinds 6 and 7, responses 7 and 8, field types 34 to 38):

- `PutBlob(queue, admin, blob, retrieve, retention_deadline, sealed)` stores
  the sealed invitation under `blob` (the locator). It is authorized by the
  admin capability of `queue` and charged to that queue's byte quota in the
  transaction that inserts it. The mailbox keeps `SHA-256(retrieve)`, the
  digest, the deadline and the bytes. A taken locator answers first: the
  identical request is `BlobStored` again, anything else is `Conflict`.
  Then the size (`limits.max_ticket_blob_bytes`, 16 640), the deadline
  (after `now`, at most `now + message_retention_seconds`) and the quota.
- `GetBlob(blob, retrieve)` returns `SealedBlob(sealed)` for a live blob
  whose stored hash matches, compared in constant time. A missing blob, an
  expired one and a wrong capability are all `Unauthorized`.
- The sweep deletes blobs past their deadline and returns their bytes to
  the queue; deleting the queue deletes its blobs.

**A fetch does not consume the blob.**

**The daemon** (`api.invite_ticket`, `api.accept_ticket`). The inviter
creates the invitation as before, waits for its queue, seals it under a new
ticket and stores it with `PutBlob` paid for by the offer queue's admin
capability, with the invitation's own `expires_at` as the deadline. The
ticket is returned only after `BlobStored`. The joiner admits the ticket's
endpoint under its carrier policy before any connection, fetches, opens,
checks the mailbox, and accepts. Each mailbox call is retried with
`weft/poll` for at most `ticket_wait_ms` (60 s), a call at most
`ticket_call_ms` (30 s), on the daemon's poll clock. Neither call writes
durable state of its own.

**The ticket is a secret.** It is a `Secret` from `ticket.encode` to the
local API's answer; it never reaches argv (`--ticket` is a flag, and a
stray word is refused without being repeated), a log, an error or a
rendering. `secrets_test` searches a whole exchange's stderr and every
rendered value for the ticket, `K`, the AEAD key, the commitment key and
the retrieve capability.

## Why

An invitation file embeds the inviter's post-quantum prekey bundle: about
13.8 KB in practice, up to 14.6 KB. Operators had to move a binary file
between machines, which is the one step of pairing that cannot be done in
a chat window or read over the phone. The bundle cannot shrink without
giving up hybrid authentication (ADR-005). So the bundle stays where the
inviter already has a durable, reachable place, its own mailbox, and the
ticket carries only what a joiner needs to find and open it.

**What the mailbox learns.** The locator, a hash of the retrieve
capability, the sealed bytes and their deadline: the same kind of opaque
identifier, hashed credential and ciphertext it already holds for a
queue. It cannot read the invitation (it does not know `K`), cannot forge
a blob that opens under the ticket (Poly1305 under a key it does not
know), and cannot link the blob to the joiner beyond the connection that
fetches it, which goes over its own isolation group (the locator in hex).
Before this, the invitation's bundle never touched a mailbox; now its
ciphertext does, and the mailbox can withhold or delete it. That is a
denial of service the mailbox could already commit by refusing the
joiner's `Hello`, and the file path remains for an operator who prefers
not to depend on it.

**Why a commitment as well as the AEAD.** ChaCha20-Poly1305 is not
key-committing: a party who chooses two keys can build one ciphertext that
opens under both. A mailbox does not know `K` and cannot do this, but the
inviter, or anyone a ticket leaked to, does. With the HMAC commitment one
stored blob opens to at most one invitation for every ticket, so an
invitation is accepted only if it is the one sealed for this ticket, and
the property does not rest on Poly1305 behaving as a commitment. The cost
is 32 bytes and one HMAC. What it cannot do: someone who holds `K` can
seal a different invitation of their own under it, commitment included.
The ticket is a bearer credential, exactly as the invitation file is
(spec §4.2), and its channel is what establishes whom the operator meant
to invite.

**Why distinct labels.** Each value comes from its own HKDF-Expand label,
so none is a prefix of another: a single label expanded twice would give
the locator as the first 16 bytes of the capability, and the mailbox,
which sees the locator, would learn half of it.
`every_derived_value_is_distinct_test` compares 12-byte prefixes of all
five outputs across two tickets.

**Why the fetch does not consume.** Spec §4.3 already rules that fetching
a prekey bundle does not consume an invitation; only a valid `Hello`
does, and the offer enforces that (`core/offer`). A consuming fetch would
add nothing to that, would strand a joiner that crashed or lost its
connection after the mailbox answered (the ticket would be dead and the
operator would have to invite again), and would let anyone holding a
leaked ticket deny the intended joiner by fetching first, gaining nothing
they could not get by fetching without consuming. The blob lives until
the invitation's deadline and is swept then.

**Why the admin capability and the queue's quota.** The offer's queue
belongs to the inviter, and its admin capability never leaves the
inviter's daemon, so it is the natural authority to spend that queue's
storage. Charging the queue's quota means a blob needs no allowance of
its own and goes with the queue. The append capability was rejected: it
is in the invitation, and anyone holding the invitation could then store
blobs at the inviter's expense.

**Why `message_retention_seconds` bounds the deadline, not the invitation
window.** The inviter sets the deadline from its own clock (its
invitation's `expires_at`, 24 hours ahead). A mailbox that capped the
deadline at its own `now + invitation_window_seconds` would refuse an
inviter whose clock ran one second ahead, the failure ADR-008 fixed for
envelopes. The envelope bound leaves six days of room and needs no new
limit.

**Why a foreground call.** The inviter's `PutBlob` runs inside
`invite_ticket` rather than as a durable outbox row. The operator is
waiting for the ticket anyway, a ticket that is printed must name a
stored blob, and a failure leaves only an offer that was never handed
out, which a timed-out `invite` already does. A durable row would add a
table and engine changes to buy retries the operator can do by asking
again.

What is implemented and tested:

- `core/codex32` against BIP-93's vector 5; round trip, strict padding.
- `core/ticket`: round trip over generated tickets; every single
  substitution and any up to eight substitutions at distinct positions
  caught by the checksum; anything accepted re-encodes to the same text,
  including over arbitrary checksummed data; bad payloads refused past a
  valid checksum; derivations distinct; seal and open, another ticket's
  blob refused, a substituted commitment refused, malformed blobs refused
  (`test/core/ticket_test.gleam`, `codex32_test.gleam`).
- The codec's round trips and refusals cover the new kinds, and the blob
  bound is exact in both directions.
- `mailbox/test/mailbox/blob_test.gleam`: store and repeated fetch, the
  charge, admin-only storing, `Unauthorized` for wrong, unknown and
  expired, idempotent store and conflicts, deadline, size and quota
  bounds, the sweep, the queue's cascade, the hash at rest.
- `daemon/test/daemon/ticket_test.gleam`, two real daemons and a real
  mailbox: pairing by ticket and a message exchanged; a mailbox answering
  with another ticket's invitation refused; an expired ticket refused
  cleanly; a ticket for nothing and a mistyped one refused; a loopback
  ticket refused under `TorOnly`. `cli_test` checks that no command takes
  a ticket in argv and no refusal echoes one.
- Mutations: dropping the commitment check fails
  `a_substituted_invitation_is_refused_by_the_commitment_test`; deriving
  the commitment key under the AEAD key's label fails
  `every_derived_value_is_distinct_test`.
- `scripts/demo.sh --carrier=loopback` pairs by ticket and passes;
  `--pairing=file` keeps the file path exercised.

## Consequences

- A ticket depends on the inviter's mailbox being reachable when the
  joiner redeems it. The file path does not, and stays.
- The sealed invitation costs its queue up to 16 640 bytes of quota until
  the invitation's deadline. There is no `DeleteBlob`: a consumed offer's
  blob lingers until then, readable only by holders of the ticket, whose
  invitation the offer will no longer redeem.
- The onion ticket is 130 characters, about 20 more than a bech32m one
  would be. Shortening it means a shorter `K` or dropping the onion
  checksum bytes (and computing SHA3 in `core`); neither was worth it.
- The mailbox protocol gained two request kinds. A mailbox that predates
  them refuses them as `Malformed`, which the daemon reports as a refused
  store; such a mailbox can still serve file invitations.
- Revisit if invitations need to be redeemable while the inviter's
  mailbox is down, if a mailbox operator objects to holding invitation
  ciphertext, or if a second implementation needs a different checksum.

## Addendum: 2026-11-02

The project was renamed from Reedwire, and this record was updated to match. [ADR-014](014-the-name-is-pondline.md) has the decision.
