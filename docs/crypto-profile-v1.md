# CryptoProfileV1

This document fixes the cryptography of Pondline v1: the algorithms, every
byte layout, every domain-separation string, the limits, what a mailbox can
see, and what the construction does and does not guarantee. It is the
statement `docs/spec.md` §5.2 asks for, and the code in `core/crypto` is
checked against it. Where this document and the code disagree, that is a
bug in one of them, to be settled by an ADR.

The decision to build this over OTP's `crypto` is `docs/adr/002-pq-crypto-over-otp.md`,
and the decision to make every authentication step hybrid is
`docs/adr/005-hybrid-authentication.md`. No new primitive is designed here:
every algorithm below is a published one, and the protocols are Signal's
PQXDH and Double Ratchet, specialised. The profile is not yet frozen
(`docs/spec.md` §5.2), so it is still V1 and its labels still end in `_v1`.

## 1. Algorithms

| Role | Algorithm | Sizes (bytes) |
| --- | --- | --- |
| Key agreement | X25519 (RFC 7748) | key 32, shared secret 32 |
| Signatures (classical half) | Ed25519 (RFC 8032, pure) | key 32, signature 64 |
| Signatures (post-quantum half) | ML-DSA-65 (FIPS 204, pure, empty context, hedged signing) | public key 1952, secret key 4032 (OpenSSL's expanded form), signature 3309 |
| Post-quantum KEM | ML-KEM-1024 (FIPS 203) | encapsulation key 1568, decapsulation key 3168 (OpenSSL's expanded form), ciphertext 1568, shared secret 32 |
| Hash | SHA-256 (FIPS 180-4) | 32 |
| MAC | HMAC-SHA-256 (RFC 2104) | 32 |
| KDF | HKDF-SHA-256 (RFC 5869) | up to 8160 |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | key 32, nonce 12, tag 16 |

Integers in every layout are big-endian. A "version" byte is `0x01` in v1.

A **hybrid signature** is an Ed25519 signature and an ML-DSA-65 signature by
one identity's two signing keys over the same message, encoded as

```text
HybridSignature = ed25519_signature (64) || mldsa65_signature (3309)       3373 bytes
```

and it verifies only when both halves verify. No step in this profile
accepts one half alone, and the implementation has no function that
verifies one half alone. ML-DSA-65 signing is hedged (OpenSSL mixes fresh
randomness into every signature), so two signatures of one message differ;
nothing here relies on a signature being reproducible.

## 2. Identity

Each relationship has its own identity, so an identity links nothing across
relationships. An identity is two signing keys, Ed25519 and ML-DSA-65, and
an X25519 agreement key. The three are tied by a hybrid binding signature,
in place of Signal's XEdDSA use of one key for both jobs.

```text
binding_message = "Pondline_IdentityBinding_v1" || ed25519_public (32)
                  || mldsa65_public (1952) || x25519_public (32)
binding         = Ed25519.Sign(ed25519_secret, binding_message)
                  || ML-DSA-65.Sign(mldsa65_secret, binding_message)          3373 bytes

PublicIdentity  = ed25519_public (32) || mldsa65_public (1952)
                  || x25519_public (32) || binding (3373)                     5389 bytes
fingerprint     = SHA-256(PublicIdentity)
```

Both halves sign all three public keys, so the binding ties the two
signing keys to each other as well as to the agreement key: an attacker
cannot keep someone's Ed25519 key and splice in an ML-DSA-65 key of its
own, because the Ed25519 half also signed the original ML-DSA-65 key. The
fingerprint covers all three keys and the binding.

A decoder verifies both halves of the binding and refuses the identity if
either fails, so no public identity that reaches the protocol lacks a
valid hybrid binding. A stored identity holds the three secret keys
(Ed25519 32, ML-DSA-65 4032, X25519 32) beside its public identity.

## 3. Prekey bundle

The inviter's bundle is embedded in the invitation file. There is no
publication and no claim step, and no one-time prekeys, because an
invitation's bundle is single-use by construction.

```text
spk_signature   = HybridSign(identity, "Pondline_SignedPrekey_v1"   || spk)      3373 bytes
pqspk_signature = HybridSign(identity, "Pondline_PQSignedPrekey_v1" || pqspk)    3373 bytes

Bundle = version (1) || PublicIdentity (5389) || spk (32) || spk_signature (3373)
         || pqspk (1568) || pqspk_signature (3373)                   13736 bytes
bundle_commitment = SHA-256(Bundle)
```

`HybridSign(identity, m)` is the Ed25519 signature of `m` followed by the
ML-DSA-65 signature of `m`, both by the identity's signing keys. Decoding a
bundle verifies the identity binding and both prekey signatures, each with
both halves, under the bundle's identity. A bundle whose prekey was
replaced by anyone other than the identity's owner is rejected there. The
two labels differ, so a half of one prekey signature never verifies for
the other prekey.

## 4. Handshake (PQXDH)

The joiner is the initiator and the inviter is the responder.

```text
DH1 = X25519(IK_init.x25519_secret, SPK)
DH2 = X25519(EK_secret,             IK_resp.x25519_public)
DH3 = X25519(EK_secret,             SPK)
(SS, CT) = ML-KEM-1024.Encaps(PQSPK)

SK = HKDF-SHA-256(salt = 0x00 x 32,
                  ikm  = 0xFF x 32 || DH1 || DH2 || DH3 || SS,
                  info = "Pondline_PQXDH_X25519_SHA-256_ML-KEM-1024_v1",
                  L    = 32)
AD = SHA-256(PublicIdentity(IK_init)) || SHA-256(PublicIdentity(IK_resp))   64 bytes
   = fingerprint(IK_init) || fingerprint(IK_resp)
```

Signal's `AD` is the two identity encodings themselves. A hybrid identity
is 5389 bytes, and `AD` is stored in every ratchet state and authenticated
with every message, so here it is the two fingerprints (§2) instead.
SHA-256's collision resistance binds the identities as tightly: two
distinct identities with equal fingerprints are a SHA-256 collision. The
fingerprints save 10714 bytes in every stored ratchet state and in the
associated data of every message. `AD` carries no domain label; it is only
ever associated data under keys derived from this handshake's `SK`, so it
cannot be confused with any other use of the same bytes.

The prefix is 32 bytes of `0xFF`, Signal's `F`. For DH1 = `0x01` x 32,
DH2 = `0x02` x 32, DH3 = `0x03` x 32 and SS = `0x04` x 32, `SK` is
`6fba3e33d9b8711d0c4d6c4cd0a02a835617f0313bfe5f74992c5fb903b75473`
(computed independently and pinned by `pqxdh_shared_secret_known_answer_test`).

### Initiator authentication

Classical PQXDH authenticates the initiator only implicitly, through DH1,
an X25519 agreement. Here the initiator also signs the handshake
transcript with both of its signing keys:

```text
transcript = "Pondline_InitiatorTranscript_v1" || version (1)
             || PublicIdentity(IK_init) (5389) || PublicIdentity(IK_resp) (5389)
             || bundle_commitment (32) || EK_public (32) || CT (1568)
             || ratchet_message (rest)
transcript_signature = HybridSign(IK_init, transcript)                3373 bytes
```

The transcript is every field of the initial message except the signature
itself, plus the responder's identity. It signs both identities in full,
not by fingerprint as `AD` does: nothing else in the transcript carries
them (the commitment names the responder's identity only through a hash,
and the initiator's not at all), the signature is made once per
relationship so the bytes cost nothing that recurs, and the signature then
binds the keys themselves rather than through SHA-256. Every field before the ratchet
message has a fixed size, so the concatenation needs no length prefixes.
The initiator signs after encrypting the first ratchet message, so the
signature covers it.

The initiator's first message:

```text
InitialMessage = version (1) || PublicIdentity(IK_init) (5389) || EK_public (32)
                 || CT (1568) || bundle_commitment (32)
                 || transcript_signature (3373) || ratchet_message (rest)
                 fixed part 10395 bytes
```

The responder, in this order: checks that its identity is the bundle's;
checks the commitment against the bundle it holds; verifies both halves of
the transcript signature under `IK_init` (refusing with `BadSignature("initiator
transcript")` before any agreement); recomputes `SK` (using the signed prekey
secret and the ML-KEM secret); and decrypts the ratchet message. The
initiator's identity binding was verified when the message was decoded. It
starts its ratchet with the signed prekey as its first ratchet key pair.
After the caller stores the new state it retires the bundle's secrets.
Until then a retry of the same initial message gives the same session,
because the handshake does not mutate the prekeys. A retry resends the
committed bytes; the hedged signature is never recomputed.

ML-KEM rejects implicitly: a `CT` the initiator itself mangled (and then
signed) decapsulates to an unrelated secret, so the responder sees a failed
authentication of the first ratchet message and not a KEM error. A `CT`
anyone else changed fails the transcript signature first.

### Responder authentication

The responder stays implicitly authenticated, as in PQXDH, but now under
hybrid assumptions. Its first reply is encrypted under keys derived from
`SK`, and `SK` needs the SPK secret (for DH3, and DH1), the PQSPK secret
(for `SS`) and the identity's X25519 secret (for DH2). The SPK and the
PQSPK are each signed under both of the responder's signing keys, so a
party that substitutes either prekey must forge an Ed25519 and an
ML-DSA-65 signature, and a party that does not substitute them cannot
derive `SK` without the PQSPK secret, which a quantum adversary cannot
recover from the ML-KEM-1024 public key.

## 5. Double Ratchet

```text
KDF_RK(rk, dh_out)   = HKDF-SHA-256(salt = rk, ikm = dh_out,
                                    info = "Pondline_Ratchet_v1", L = 64)
                       -> (rk', chain_key)       first 32 bytes, last 32 bytes
KDF_CK(ck)           : message_key = HMAC-SHA-256(ck, 0x01)
                       ck'         = HMAC-SHA-256(ck, 0x02)
message keys         = HKDF-SHA-256(salt = 0x00 x 32, ikm = message_key,
                                    info = "Pondline_MessageKeys_v1", L = 44)
                       -> AEAD key (32) || AEAD nonce (12)
Header               = ratchet_public (32) || PN (u32) || N (u32)               40 bytes
ratchet_message      = Header || ChaCha20-Poly1305(key, nonce, aad = AD || Header, plaintext)
```

The initiator's first sending chain comes from `KDF_RK(SK, X25519(its new
ratchet key, SPK))`. A responder has no sending chain until it has received
a message. Skipped message keys are stored under the sender's ratchet public
key and message number. A sender never uses message number 2^32 - 1: a chain
that reaches it stops with an error rather than wrapping, and a receiver
refuses a header carrying it.

Encryption is deterministic in the state. Two different plaintexts encrypted
from one state reuse a message key and nonce, so a ciphertext must not leave
the process unless the state that produced it is committed (`docs/spec.md`
§8.2, commit then send), and a crash is recovered by resending the committed
bytes, not by encrypting again.

### State serialization

`encode_state` produces a versioned fixed layout, held as a secret: the
version byte (1); the session AD with a 32-bit length; the sending key pair
(32 and 32); the root key (32); the sending chain (tag byte 0 or 1, then 32
bytes when 1); the receiving chain (tag byte, then the peer's ratchet public
key 32, the chain key 32 and the next number u32 when 1); the sent count
and PN (u32 each); the skipped-key count (u32); then each skipped key as
ratchet public key (32), number (u32) and message key (32). `decode_state`
is total, enforces the skipped-key bound before reading entries, and rejects
trailing bytes. It checks structure only; it does not check that a stored
public key matches its secret.

## 6. Limits

| Limit | Value | Where |
| --- | --- | --- |
| Skipped keys per gap in one chain | 1000 | `limits.max_skip_per_message` |
| Skipped keys retained in total | 2000 | `limits.max_skipped_message_keys` |
| Largest message number | 2^32 - 1 | `limits.max_message_number` |
| Largest invitation file | 16 384 | `limits.max_invitation_bytes` |
| Largest sealed invitation for a ticket (§11) | 16 640 | `limits.max_ticket_blob_bytes` |

### Sizes

| Encoding | Bytes |
| --- | --- |
| `HybridSignature` | 3373 |
| `PublicIdentity` | 5389 |
| `Bundle` | 13 736 |
| Largest invitation file (route and description at their bounds) | about 14 550 |
| `InitialMessage`, fixed part | 10 395 |
| Initial frame before padding (length prefix, tag, fixed part, ratchet header, AEAD tag, `Hello` of 0 to 1024 bytes) | 10 456 to 11 480 |
| Padded initial frame | 16 384, always (the 4 KiB bucket is too small) |
| Session AD (in every ratchet state and every message's associated data) | 64 |
| Ratchet state after the handshake (initiator, responder) | 211, 279 |
| Ratchet state with a full skipped-key store | about 136 300 |
| Associated data authenticated per message (`AD` and the header) | 104 |

The invitation bound moved from 4 KiB to 16 KiB with hybrid
authentication; no other bound moved. A `Hello` carries no identity, so
`limits.max_hello_bytes` stands, and the largest snapshot (a full
skipped-key store, about 136 KB) stays far under
`limits.max_snapshot_bytes`.

A header claiming a gap over `max_skip_per_message` is refused, since the gap
is attacker-chosen, and the check precedes any key derivation. Storing past
`max_skipped_message_keys` evicts the oldest stored keys instead of
refusing, so a session whose earlier messages were lost for good is never
wedged; a message whose key was evicted is undecryptable, exactly as a lost
message is. A decoded state with a stored count over the bound is refused.

## 7. What the mailbox can see

Headers are not encrypted in v1. A mailbox, or anyone who can read it, sees
for every ratchet message the sender's current ratchet public key, PN and
N, and the ciphertext length (after the padding of `docs/spec.md` §11.3).
That reveals when a DH ratchet step happened and how many messages each
chain carried. The header is authenticated, since it is part of the AEAD's
associated data, so a mailbox can read it but not alter it. It also sees the
initiator's public identity, the ephemeral key, the bundle commitment and
the transcript signature in the first message of a relationship. The
initial frame always pads to the 16 KiB bucket (§6), so its padded size
reveals nothing about the `Hello` inside it. Header encryption is deliberately left
for a later profile.

For an invitation redeemed by ticket (§11), the inviter's mailbox also
holds the sealed invitation: it sees the locator, the hash of the retrieve
capability, the ciphertext's length and its deadline, and which
connection fetched it, but not `K` or anything derived from it that could
open the blob.

## 8. Guarantees, stated honestly

What v1 provides:

- **Hybrid authentication.** Every authentication step needs both a
  classical proof (Ed25519 signatures, and for the implicit parts the
  X25519 agreements) and a post-quantum one (ML-DSA-65 signatures, and
  for the implicit parts ML-KEM-1024). The identity binding, both prekey
  signatures and the initiator's transcript signature are hybrid, and each
  check requires both halves, so forging an identity, substituting a
  prekey or impersonating the initiator needs Ed25519 and ML-DSA-65 both
  broken. The responder is authenticated implicitly, through prekeys whose
  signatures are hybrid and an ML-KEM secret only it holds (§4). Messages
  after the handshake are authenticated by the AEAD under ratchet keys
  that descend from `SK`, so they inherit this until a ratchet state is
  compromised; recovery from that is classical (below).
- **Confidentiality of the initial key against a quantum adversary.** `SK`
  mixes an ML-KEM-1024 shared secret with three X25519 secrets, so a
  recording of the handshake does not let a future quantum computer recover
  `SK` unless it also breaks ML-KEM. This is the harvest-now-decrypt-later
  protection PQXDH exists for. Hybrid authentication did not change the
  key agreement: `SK` is derived exactly as before.
- **Forward secrecy and post-compromise security against a classical
  adversary**, from the Double Ratchet's DH steps and chain-key deletion.
  Forward secrecy of `SK` itself rests on two things: retiring the prekeys
  (`offer.consume` drops the secret stock once a `Hello` consumes the offer)
  and the first DH ratchet step inside `respond`. Long-term identity keys
  alone do not expose a past session, but if either of those two moved, a
  recorded handshake plus a later disk image would yield the session key
  (`docs/formal/crypto.md`, rows `fs_longterm` and `fs_prekeys`).
- **Authenticated, replay-resistant, bounded-reordering delivery**, with
  every message bound to both identities through the associated data.

What v1 does not provide:

- **Post-quantum post-compromise security.** After the handshake every DH
  ratchet step is X25519, so a quantum adversary who learns a ratchet state
  is not locked out by later steps. The version bytes in the state, bundle
  and initial message reserve room for Signal's sparse post-quantum ratchet,
  which is not implemented.
- **Deniability for the initiator.** PQXDH authenticates the initiator
  only through key agreement, so a transcript proves nothing a party could
  not have produced alone. The transcript signature changes that: it is a
  transferable proof, under the initiator's two signing keys, that the
  initiator began this handshake with this responder. Identities are
  pairwise and never published, which limits what the proof names, but
  the offline deniability PQXDH gives the initiator is given up.
- **Hot code upgrade of `core/secret`.** Secrets are closures, which the BEAM
  ties to the module version that created them. The daemon does not support
  hot code upgrades of `core/secret`; an upgrade restarts the VM.
- **Memory erasure.** The BEAM gives no way to zero key material; a deleted
  key may linger in memory until collected, and in any swap or dump.
- **Metadata protection beyond Tor.** See §7.

## 9. Domain-separation strings

| String | Used for |
| --- | --- |
| `Pondline_IdentityBinding_v1` | identity binding signature (both halves) |
| `Pondline_SignedPrekey_v1` | signed X25519 prekey signature (both halves) |
| `Pondline_PQSignedPrekey_v1` | signed ML-KEM prekey signature (both halves) |
| `Pondline_InitiatorTranscript_v1` | initiator's transcript signature (both halves) |
| `Pondline_PQXDH_X25519_SHA-256_ML-KEM-1024_v1` | handshake HKDF info |
| `Pondline_Ratchet_v1` | root-key HKDF info |
| `Pondline_MessageKeys_v1` | message-key HKDF info |
| `Pondline_Ticket_v1` | ticket HKDF-Extract salt (§11) |
| `Pondline_TicketLocator_v1` | ticket blob locator HKDF info (§11) |
| `Pondline_TicketCapability_v1` | ticket retrieve capability HKDF info (§11) |
| `Pondline_TicketKey_v1` | ticket AEAD key and nonce HKDF info (§11) |
| `Pondline_TicketCommitment_v1` | ticket commitment key HKDF info (§11) |
| `Pondline_TicketBlob_v1` | prefix of the sealed invitation's associated data (§11) |

All are ASCII, with no terminator or length prefix. Each signature input is
the string followed immediately by fixed-size fields; only the transcript
ends in a variable-length field, the ratchet message, which is last. Both
halves of a hybrid signature sign the same input; the algorithms differ,
so no further separation between the halves is needed. ML-DSA-65 is used
with an empty context string.

## 10. Status

Implemented and tested in `packages/core/src/core/crypto` and
`packages/primitives`. HKDF matches RFC 5869 test cases 1 to 3. ML-DSA-65
has no fixed-output vector through OTP 29 (signing is hedged, and
`crypto:generate_key/3` cannot derive a key pair from a seed), so it is
checked by sizes, round trips and rejections
(`packages/primitives/test/primitives/mldsa_test.gleam`). Every hybrid
check is covered by a test that a signature with exactly one valid half is
refused, in both directions, and each was confirmed by mutation
(`packages/primitives/test/primitives/hybrid_auth_test.gleam`). There are no
external test vectors for PQXDH or this ratchet, so correctness rests on the
round-trip, tamper, replay, bound and persistence tests, a property suite
over a deterministic fake, mutation checks, and review. Cross-implementation
vectors remain to be produced if a second implementation is ever written.

Queued for a `CryptoProfileV2`: bind `CT || PQSPK` into the handshake's HKDF
`info`. Today those values are bound by the transcript signature and the signed
bundle commitment, which the symbolic model shows is sufficient and necessary
under the hybrid signatures; a KDF binding would also hold against a forger,
and costs nothing on the wire (`docs/formal/crypto.md`, finding 1).

Ed25519 verification is the RFC 8032 equation as OpenSSL implements it, and
accepts small-order and mixed-order public keys; X25519 accepts non-canonical
encodings. Both are decided and pinned by the Wycheproof tests (ADR-005,
addendum).

## 11. Invitation tickets

*Added by ADR-009.* A ticket carries a mailbox endpoint and a 32-byte
secret `K` from the CSPRNG; its text form is in
`docs/adr/009-invitation-tickets.md`. Everything else comes from `K`:

```text
PRK        = HKDF-Extract(salt = "Pondline_Ticket_v1", ikm = K)
locator    = HKDF-Expand(PRK, "Pondline_TicketLocator_v1", 16)
retrieve   = HKDF-Expand(PRK, "Pondline_TicketCapability_v1", 32)
key, nonce = HKDF-Expand(PRK, "Pondline_TicketKey_v1", 44)        32 then 12
commit_key = HKDF-Expand(PRK, "Pondline_TicketCommitment_v1", 32)

blob       = 0x01 || commitment (32) || ChaCha20-Poly1305(key, nonce,
               aad = "Pondline_TicketBlob_v1" || locator, invitation file)
commitment = HMAC-SHA-256(commit_key, invitation file)
```

Each output has its own label, so none is a prefix of another; the
mailbox sees the locator and `SHA-256(retrieve)`, and they reveal nothing
about the key or the commitment key. One key seals exactly one invitation,
so the derived nonce is never reused; sealing the same invitation again
under the same ticket gives the same bytes. Opening checks the version,
the AEAD, and then the commitment in constant time, and returns nothing
unless all pass. The commitment makes the blob key-committing: no one,
including a holder of `K`, can make one blob open to two invitations under
two tickets, which Poly1305 alone does not prevent. A holder of `K` can
seal an invitation of its own, as a holder of an invitation file can hand
on a different file; the ticket is a bearer credential.
