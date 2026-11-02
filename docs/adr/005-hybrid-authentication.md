# ADR-005 — Every authentication step requires both a classical and a post-quantum proof

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §5.1, §5.2

## Decision

Authentication in `CryptoProfileV1` is hybrid from day one. Every
signature the handshake relies on is a pair, an Ed25519 signature and an
ML-DSA-65 (FIPS 204) signature over the same bytes, and every check
requires both halves:

- **Identity.** An identity is two signing keys, Ed25519 and ML-DSA-65,
  and an X25519 agreement key. Its binding is a hybrid signature over
  `"Reedwire_IdentityBinding_v1" || ed25519_public || mldsa65_public ||
  x25519_public`, so it binds the two signing keys to each other as well
  as to the agreement key. A public identity is 5389 bytes, and the
  fingerprint (SHA-256 of it) covers all three keys.
- **Bundle.** The signed X25519 prekey and the signed ML-KEM-1024 prekey
  each carry a hybrid signature, under their existing distinct labels. A
  bundle is 13736 bytes.
- **Initiator.** The joiner signs the handshake transcript with both of
  its signing keys and sends the pair in the `InitialMessage`. The
  transcript is `"Reedwire_InitiatorTranscript_v1" || version || AD ||
  bundle_commitment || EK || CT || ratchet_message`, with `AD =
  encode(IK_init) || encode(IK_resp)`: every field of the initial message
  except the signature, plus the responder's identity. The responder
  verifies both halves before any agreement.
- **Responder.** Stays implicitly authenticated, as in PQXDH: only the
  holder of the SPK and PQSPK secrets, both prekeys signed under the
  responder's hybrid identity, can derive the session key.

The key agreement is unchanged (X25519 three times and ML-KEM-1024 into
one HKDF). The profile is not yet frozen (spec §5.2), so it stays V1 and
keeps its `_v1` labels. The byte layouts are in `docs/crypto-profile-v1.md`
§1 to §4, and the code in `packages/core/src/core/crypto` (`keys`,
`identity`, `pqxdh`).

This amends spec §5.1, which said PQXDH authentication relies on classical
assumptions, and `docs/adr/002-pq-crypto-over-otp.md`, which listed
Ed25519 as the only signature and quantum-resistant authentication as not
provided (addendum there).

## Why

Before this, key agreement was hybrid but authentication was classical.
Identities were Ed25519 with an Ed25519 binding, both prekeys were signed
with Ed25519 alone, and the joiner was authenticated only through DH1, an
X25519 agreement. A quantum adversary active during pairing could forge an
inviter's bundle or impersonate a joiner. Recorded traffic stays safe
either way, since `SK` mixes ML-KEM, but pairing is the one moment two
agents establish who the other is, and Reedwire has no later step that
re-establishes it. A relationship whose identities were forged at pairing
stays forged. So the owner ruled (2026-11-01) that authentication is hybrid
from day one rather than retrofitted, since retrofitting means a new
profile version and re-pairing every relationship.

Why hybrid rather than ML-DSA alone: ML-DSA is new, and a flaw in it or in
its implementation should not cost authentication outright. Requiring both
halves means forging needs Ed25519 and ML-DSA-65 broken.

Why ML-DSA-65: OTP 29's `crypto` provides it over OpenSSL 3.5 and later,
which ADR-002 already requires for ML-KEM, so it adds no dependency. It is
NIST's category 3 parameter set and the owner's choice; ML-DSA-87
(category 5) would add 1318 bytes to every signature and 640 to every
key. SLH-DSA, also available, has far larger signatures (7856 bytes at its
smallest parameter set) for the same purpose.

Why an explicit initiator signature: PQXDH authenticates the initiator
only through DH1, which is X25519 and has no post-quantum counterpart in
the agreement (the KEM ciphertext is made by the initiator, so it proves
nothing about the initiator). A signature is the direct way to put an
ML-DSA proof on the initiator. It covers the ratchet message as well, so
every byte the responder acts on is bound to the initiator's keys.

Evidence, from this machine (OTP 29.0.5, OpenSSL 3.6.3):

- `crypto:generate_key(mldsa65, [])` gives a 1952-byte public key and a
  4032-byte expanded secret; `crypto:sign(mldsa65, none, M, Secret)` gives
  3309 bytes; signing is hedged, so two signatures of one message differ.
  `crypto:generate_key(mldsa65, [], {seed, Seed})` raises, so there is no
  seeded key generation and no fixed-output vector; `crypto:verify` raises
  on a wrong-sized public key, and an uncaught raise would put the key into
  a crash report through the stack-trace arguments, so the shim catches it.
  `packages/primitives/test/primitives/mldsa_test.gleam` checks sizes, round
  trips and rejections.
- `packages/primitives/test/primitives/hybrid_auth_test.gleam` checks over
  the real primitives that each of the three signature checks refuses a
  pair with exactly one valid half, in both directions; that a genuine
  half from another signature (another identity, the other prekey, another
  transcript) is refused; that a spliced ML-DSA-65 key is refused; that a
  transcript signature moved to another bundle commitment, ephemeral key,
  ratchet message or responder is refused; the transcript's exact layout;
  and that the invitation file, the offer and relationship snapshots and
  the initial frame round-trip the larger identities.
- Mutations confirmed to fail a test: skipping the ML-DSA half of the
  shared hybrid verifier; verifying only the classical half at each of the
  identity binding, the bundle signatures and the transcript, one site at
  a time; skipping the transcript check; leaving the ML-DSA key out of the
  binding message; and leaving each of EK, the bundle commitment, the
  ratchet message and the responder's identity out of the transcript.

Considered and rejected: signing the two prekeys under one hybrid
signature (saves 3373 bytes, but the two prekeys then cannot be checked or
replaced separately, and the owner asked for distinct labels); a
fingerprint-sized AD (two SHA-256 digests instead of 10778 bytes) in place
of the full identity encodings, which would cut every ratchet state and
every message's associated data by about 10.7 KB but changes what the
session binds and was not asked for; it is left open.

## Consequences

- **Sizes.** An identity grows from 128 to 5389 bytes, a bundle from 1857
  to 13736, and an invitation file to about 14.6 KB at most;
  `limits.max_invitation_bytes` moves from 4 KiB to 16 KiB. The initial
  message's fixed part grows from 1761 to 10395 bytes, so the padded
  initial frame moves from the 4 KiB bucket to the 16 KiB bucket, and it
  always lands there whatever the `Hello` holds. The session AD in every
  ratchet state and every message's associated data grows from 256 to
  10778 bytes. No other bound moves.
- **Stored state.** Identity snapshots gain the ML-DSA-65 secret (4032
  bytes) as a new record, and every encoding that holds an identity
  changes. There is no migration: nothing has been released, and state
  written before this change does not decode after it.
- **Deniability.** The transcript signature is a transferable proof that
  the initiator began a handshake with the responder, which gives up
  PQXDH's offline deniability for the initiator. Identities are pairwise
  and unpublished, which limits what the proof names.
- **Not changed.** Key agreement, and post-compromise security, which is
  still X25519 ratchet steps only. The sparse post-quantum ratchet remains
  future work.
- **Cost.** On this machine ML-DSA-65 signs a 14 KB message in about
  460 µs and verifies it in about 90 µs; it runs only at pairing and when
  a stored identity is decoded. The deterministic fake
  suite under `core`'s `test/` hashes these larger inputs, which roughly
  doubled the core property suites' run time.
- Revisit if ML-DSA-65 is weakened (the pair then rests on Ed25519, which
  is where classical PQXDH already was), if a bundle-size budget (QR
  invitations) forces the single-signature form, or when the sparse
  post-quantum ratchet is designed.

## Addendum (2026-11-01): the session AD is the two fingerprints

The open question above is closed. The session associated data, stored in
every ratchet state and authenticated with every message, is now
`fingerprint(IK_init) || fingerprint(IK_resp)` (SHA-256 of each full
public identity encoding, 64 bytes) instead of the two encodings (10778
bytes). SHA-256's collision resistance binds the identities as tightly:
two different identities that give the same `AD` are a SHA-256 collision,
and the protocol already rests on SHA-256 for the bundle commitment and
the fingerprint users compare. It saves 10714 bytes in every stored
ratchet state (a fresh state is now 211 bytes for the initiator and 279
for the responder, against 10925 and 10993) and in the associated data of
every message (104 bytes with the header, against 10818). The wire size
of a ratchet message does not change, since `AD` is never sent. There is
no domain label on `AD`: it is only ever associated data under keys
derived from this handshake's `SK`.

The transcript the initiator signs keeps both identities in full, now
written as `encode(IK_init) || encode(IK_resp)` rather than as `AD`.
Nothing else in the transcript carries them (the bundle commitment names
the responder's identity only through a hash, the initiator's not at
all), the signature is made once per relationship, and signing the full
encodings binds the keys themselves rather than through SHA-256. The
"session AD" line under Consequences is superseded by this addendum; the
transcript bytes are unchanged.

A test pins the layout (both ends' stored `AD` is exactly the two
fingerprints, initiator first), and the mutations that use only one
fingerprint, swap their order, or drop the ML-DSA-65 key from the binding
message each fail it or another test.

## Addendum (2026-11-01): what the symbolic model says about this reasoning

`docs/formal/crypto.md` modelled the handshake in ProVerif. Two results bear
on this record. Nothing in the protocol changes.

**The reasoning for the transcript signature's Ed25519 half was wrong.** This
record treats the classical half as what preserves joiner authentication if
ML-DSA-65 falls. For the transcript signature it is DH1 that does so, as in
classical PQXDH: with ML-DSA-65 broken and X25519 intact there is no attack on
a verifier that checks only the ML-DSA-65 half (rows `ml_only_leak_pq` and
`ml_only_leak_ml_dh`). So the "Revisit" line above, "the pair then rests on
Ed25519", should read as resting on DH1 for the joiner. The ML-DSA-65 half does
the new work: it authenticates the joiner when X25519 and Ed25519 are both
broken (`ed_only_leak_quantum` is attacked, `quantum` is proved). The Ed25519
half stays. The pair is uniform across the three signatures and cheap, and for
the identity binding and prekey signatures that half is not redundant. This is
a symbolic result, not a computational proof.

**Ed25519 verification stays as it is, without rejecting small-order or
mixed-order keys.** OpenSSL accepts them, as all 29 `acceptable` Wycheproof
cases show. A strict check would need a custom point check beside the OTP
binding, against ADR-002, and would protect nothing today: no honest identity
has such a key, every identity is also bound to an ML-DSA-65 key, and no trust
derives from an Ed25519 key alone. The test suite pins the behaviour, so a
library change that altered it is noticed. Revisit if any feature compares
Ed25519 keys on their own, such as a directory or a pin.
