# ADR-016 — A spoken code pairs two daemons through a hybrid PAKE at a rendezvous mailbox, and what it delivers is a ticket

**Status**: accepted · **Date**: 2026-11-14 · **Spec ref**: §2.3, §4.2, §4.3, §6.2, §9.2, §11.3

Tracks Roasbeef/pondline#1. `docs/research/hybrid-pake.md` is the survey
this decision rests on; where the two differ, this record is the ruling
and says why.

## Decision

**A code.** `invite create --code` prints a string such as

```text
482719-cradle-noble-velvet
```

and waits. `invite accept --code` reads one from `--stdin` or a prompt and
pairs. The code is a nameplate and three words. The file and the ticket stay supported and stay the default; the
code is the opt-in path for a pairing set up by voice.

| Part | What it is | Secret |
| --- | --- | --- |
| Nameplate | Six decimal digits, drawn at random by the rendezvous mailbox | no |
| Words | Three words from the BIP-39 English list, eleven bits each, drawn by the inviter | yes, 33 bits |

`core/pairing_code` parses and prints it. The decoder is total and
strict: lowercase, single hyphens, every word on the list, so a mistyped
word is refused locally and never spends the code.

**The words are the password of CPaceOQUAKE**, the sequential hybrid PAKE
of `draft-vos-cfrg-pqpake-03`, configuration
`cpaceoquake-x25519-mlbuaskem1024` (CPace over X25519 and SHA-512, then
OQUAKE over ML-KEM-1024 with the Kemeleon encoding at `t = 132`,
HKDF-SHA-256, the draft's DST). The implementation follows that draft's
functions and encodings exactly and is pinned by its vectors.

```text
PRS            = word1 "-" word2 "-" word3
sid            = the rendezvous identifier (16 random bytes, inviter-chosen)
public_context = lv("Pondline_Rendezvous_v1") || lv(nameplate, ASCII) ||
                 EncodePublicContext(sid, U = "joiner", S = "inviter")
secret_context = empty
```

**The joiner is the draft's client and the inviter its server**, so the
inviter verifies the joiner before it releases anything:

```text
Joiner J                     Rendezvous mailbox R                 Inviter I
                                                 <---- OpenRendezvous
                             draws nameplate N, returns it and the expiry
  (operator reads "N-w1-w2-w3" to J's operator)
  ClaimRendezvous(N) ---->   binds J's capabilities, returns sid
  m1  lv(Ya) ------------------------------------------------------> I
  J <----------------------------------- m2  lv(Yb) || oquake_init
  m3  ct || h || confirm_J ----------------------------------------> I
                               I checks confirm_J; a mismatch burns the code
  J <----------------------------------- m4  AEAD(handoff, ticket)
  J opens m4, then redeems the ticket as `invite accept --ticket` does
```

**Explicit confirmation is ours, in both directions.** The draft's
`Finish` returns a random key on any failure and says a caller MUST NOT
read completion as evidence that the peer knows the password. So:

```text
PRK          = HKDF-Extract(salt = "Pondline_Rendezvous_v1", ikm = session_key)
confirm_key  = HKDF-Expand(PRK, "Pondline_RendezvousConfirm_v1", 32)
confirm_J    = HMAC-SHA-256(confirm_key, th)
key, nonce   = HKDF-Expand(PRK, "Pondline_RendezvousHandoff_v1", 44)   32 then 12
m4           = ChaCha20-Poly1305(key, nonce,
                 aad = "Pondline_RendezvousHandoff_v1" || th, ticket text)
```

`th` is the draft's transcript hash. The inviter compares `confirm_J` in
constant time and sends `m4` only if it matches. The joiner's proof that
the inviter knew the words is `m4`'s tag. One run per code: any failed
check ends the run at both daemons, the inviter closes the rendezvous, and
the operator makes a new code.

**What it delivers is a ticket (ADR-009), not the invitation.** The
inviter first does everything `invite create --ticket` does, including
`PutBlob` at its own mailbox, and `m4` carries the `pl1` ticket text.
After `m4` the joiner's flow is the ticket's, unchanged.

**`m4` is sealed once.** Its key and nonce are fixed by the session key,
so two different plaintexts under them would break the AEAD. The ticket is
minted and `BlobStored` before the inviter reads `m1`, `m4` is computed
exactly once per run, and a resend sends the same bytes.

**Failures are told apart and counted.** A run ends as paired, never
claimed, claimed then stalled, or confirmation failed. Only the last is a
spent guess. Each daemon keeps a durable count of confirmation failures
per rendezvous endpoint, and after three in 24 hours it refuses `--code`
at that endpoint and points the operator to a ticket and a fingerprint
check. That count is the only rendezvous state a daemon stores.

**The mailbox protocol gains a rendezvous**, a short-lived slot holding at
most four small messages in each direction:

- `OpenRendezvous(provision, rendezvous, read, append, lifetime_seconds)`
  creates the slot under a provisioning allowance, with the inviter's two
  capabilities, and answers `RendezvousOpened(nameplate, expires_at)`. The
  identical request answers the same nameplate.
- `ClaimRendezvous(nameplate, read, append)` binds the joiner's two
  capabilities to an unclaimed slot and answers
  `RendezvousClaimed(rendezvous, expires_at)`. The identical claim answers
  the same; a different claim on a claimed slot, an unknown nameplate and
  an expired one are all `Unauthorized`, and the first claim stands.
- `RendezvousSend(rendezvous, append, index, body)` stores message `index`
  for the peer; the same bytes twice are the same message, different bytes
  a `Conflict`.
- `RendezvousFetch(rendezvous, read, after, wait_seconds)` long-polls for
  the peer's messages past `after`.
- `CloseRendezvous(rendezvous, read)` deletes the slot; either side may.

The mailbox stores, per slot: the identifier, the nameplate, the expiry,
the grant it is charged to, the SHA-256 of each of the four capabilities,
and the message bodies. It never holds the words, a key, or an identity,
and the sweep deletes a slot at its expiry.

**Limits** (`core/limits`):

| Limit | Value |
| --- | --- |
| Slot lifetime from `OpenRendezvous` | 600 s |
| Slot lifetime after a claim | the earlier of the above and claim + 120 s |
| Message body | 2 048 bytes |
| Messages per direction | 4 |
| Live slots per provisioning grant | 4 |
| Live slots per mailbox | 1 000; `OpenRendezvous` beyond that is refused |
| Nameplate width | 6 digits |
| Confirmation failures per rendezvous endpoint | 3 in 24 hours |

**The rendezvous is the inviter's mailbox.** The inviter opens the slot
at its own mailbox. The joiner uses its own mailbox's endpoint, which is
right when both use one service, or takes `--rendezvous HOST:PORT`. No
managed rendezvous and no alias scheme ship with this change.

**The run is not durable.** Apart from the failure count, neither daemon
writes rendezvous state to its store, so the words and the ephemeral
secrets never reach disk. A daemon that restarts mid-run loses the run and the operator makes
a new code; the invitation and its ticket are durable exactly as before.

**The cryptography is pure Gleam** over the existing `Suite`, which gains
only `sha512`: `core/crypto/elligator2`, `cpace`, `kemeleon`, `bua_skem`,
`oquake`, `cpace_oquake`. The protocol run is `core/rendezvous`, a pure
step function for each side.

## Why

**A code cannot be a key.** Thirty-three bits fall to an offline search in
seconds, so the words must be a PAKE password: a passive observer learns
nothing and an active one tests one guess per run.

**CPaceOQUAKE, not a composition of our own.** The research note compares
five constructions (§3.6). This is the only one whose password protection
survives a break of either X25519 or ML-KEM during the pairing: CPace
hides the password unconditionally and its key is never confirmed, and
OQUAKE runs on a password that includes CPace's key. "CPace, then ML-KEM
inside" protects the session key from a recording but lets a
discrete-log break test the password offline. The draft has a UC proof in
the random-oracle model and test vectors.

**The roles are the reverse of the note's §5.2.** There the inviter spoke
first and sent the invitation with no proof from the joiner, so a wrong
guess by an impostor was invisible to the inviter, and the note's claim
that each attempt shows up as a burned code did not hold. With the joiner
as client, OQUAKE's own tag `h` and `confirm_J` both reach the inviter
before `m4`, in four messages rather than five. The joiner arrives second
in any case, so nothing is lost by having it speak first.

**A ticket, because it is already built and proved.** Carrying the
invitation would put 16 KiB bodies and the sealed invitation at the
rendezvous. Carrying the ticket keeps rendezvous bodies under 2 KiB, which
bounds what a public rendezvous must store, and makes everything after
`m4` the code and the ProVerif model of ADR-009. The cost is one more
onion fetch for the joiner and a sealed blob that waits out its deadline.

**BIP-39 words, not the PGP list.** The note proposed three words of
eight bits. Three BIP-39 words carry 33 bits for the same spoken length,
512 times fewer successful guesses, and the list was built so that four
letters identify a word. The mnemonic checksum is not used; these are
words, not a seed.

**Random nameplates, and the first claim stands.** A claim needs only the
nameplate, which is not secret. Smallest-free-integer allocation lets
anyone burn every live code by claiming 1, 2, 3. With six random digits
and at most a thousand live slots, a blind claim hits with probability at
most one in a thousand. Refusing later claims rather than
burning the slot means a stranger who claims after the real joiner changes
nothing. A stranger who claims first still spends the code, and the
inviter sees a failed confirmation. A claim carries no credential, because
a joiner need not have an account at the rendezvous; charging for a claim
is left to the L402 admission of spec Appendix A.

**Pure Gleam, knowing it is not constant time.** ADR-002 keeps protocols
in Gleam over OTP's primitives. The X25519 scalar multiplications, ML-KEM
and the AEAD run inside OpenSSL. The Elligator 2 map and the Kemeleon
encoding are big-integer arithmetic on the BEAM, on values derived from
the password, and the drafts ask for constant time there. The attacker
with a timing vantage is one on the same host; across Tor the jitter is
orders of magnitude above the signal, and a code is used once. A native
helper is the remedy if review says this is not enough, and it would need
its own ADR.

Implemented, tested and assumed are recorded in `docs/next.md` as the work
lands. Assumed until an outside reader says otherwise: that the draft's
argument carries over to a store-and-forward rendezvous, that the
confirmation and hand-off derivations above are sound uses of its session
key, and the timing argument.

## Consequences

- The rendezvous mailbox is a new party. It can deny service and it sees
  who opens rendezvous and when. It alone can play joiner to the inviter
  and inviter to the joiner in one run, so it gets two guesses per run,
  one against each side, and a right guess on either pairs it as that
  party: about one chance in 2^32. A retry after a failure is two more
  guesses, which is what the failure count bounds. Spec §2.3 and §4.3 say
  a mailbox cannot make an invalid claimant an accepted contact; for the
  code path they are amended to say it can with that probability, and
  operators pairing by voice should compare fingerprints when it matters
  (spec §4.4).
- A code is weaker than a ticket by construction: one guess in 2^33 per
  attempt against a 256-bit bearer secret.
- Both daemons must be up inside the slot's lifetime. The inviter's
  command waits; nothing is asynchronous.
- A stranger who learns or guesses a nameplate can spend that code before
  the joiner does. It fails closed.
- `draft-vos-cfrg-pqpake` is an individual submission at -03. The DST pins
  the version; a later draft that changes the wire is a new profile.
- New code that no outside cryptographer has read. This path should not be
  recommended in the quickstart until one has.
- A word misheard as another word on the list passes the local check,
  spends the code and counts as a confirmation failure. The BIP-39 list
  was not built for speech the way the PGP list was.
- Revisit on: review of the timing argument, CFRG adoption or abandonment
  of the draft, a managed rendezvous, or L402 admission for claims.

## Addendum: 2026-11-14, review before implementation

A read-only review of the first text of this record, made before any code
depended on it, changed five things, and the text above now states them.
The rendezvous was said to get one guess per pairing; it gets two per
run, so failures are now counted durably and capped, and spec §2.3 and
§4.3 are amended. The nameplate was four to eight digits with a width
that adapted to occupancy, which held a blind claim's hit rate near one
in ten at every width; it is six digits with a cap on live slots. `m4`
was not required to be computed once. The nameplate was concatenated into
the public context without a length prefix. And the `@alias` part of the
code was cut: it was parser and configuration surface with no security
value.

The review confirmed the role assignment (it is the draft's own §7
assignment, so its proof and vector apply unchanged), the confirmation
schedule, leaving the endpoint out of the context, the BIP-39 words, the
ticket hand-off and the non-durable run.

## Addendum: 2026-11-14, what implementation and the formal model established

The decision above is unchanged. Writing `core/rendezvous` and the
ProVerif model of `docs/formal/crypto.md` made three things explicit that
the record did not state. The first two are rules for the daemon, whose
side of this change is still in progress; `core` cannot enforce them.

**Each step runs on the first message at its index only.** The run's
states are opaque and each step takes the state the previous one
returned, so the steps can only be taken in order, but a Gleam value can
be used twice, and nothing stops a caller from running one step on two
different messages at the same index. A second message is a second
guess: each answer a side computes from a message the peer chose is
something the peer can check a candidate code against, so a joiner that
answered a second `m2`, or an inviter that answered a second `m1`,
would give the peer two tries in one run. The
mailbox's `Conflict` on different bytes at a filed index is no defence,
because the mailbox may be the attacker, and it alone stores and serves
those messages. So each daemon acts on the first message at each index,
ignores any other, and ends the run on any error.

**A joiner that sent `m3` and received no `m4` counts a possible spent
guess.** An inviter whose check of `confirm_J` fails sends nothing:
`inviter_release` returns `ConfirmationFailed` and no `m4` exists for
the run. From the joiner's side that looks like a stall, which the
failure classification above does not count. But a mailbox playing
inviter to the joiner has used its guess against the joiner by then, and
if the joiner did not count it, that guess would be free of the cap. So
the joiner counts a run in which it sent `m3` and received no `m4` as a
confirmation failure.

**Kemeleon is load-bearing for the hybrid claim specifically.** The
model's mutation without Kemeleon, where an unmasked `ut` is
recognisable as an ML-KEM key with nothing broken, does not lose the code
with nothing broken, because OQUAKE's effective password is keyed by
CPace's session key and the attacker has nothing to unmask. It loses the
code to an X25519 break alone (`docs/formal/crypto.md`, "Spoken pairing
codes", finding 2 and rows `rv_no_kemeleon_dh` and
`rv_oracle_no_kemeleon`). Kemeleon is what stops a discrete-log break
with ML-KEM intact from testing the code offline, which is the case the
hybrid claim exists for; a change that weakened the encoding would leave
the classical case standing and quietly lose the post-quantum one.
