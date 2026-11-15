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
| Hash (CPace only, §12) | SHA-512 (FIPS 180-4) | 64 |
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
`3ead1ec7a28aaab8448c828a178f7cd6f772fc65336720a0670e066844066bc6`
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

For a pairing by spoken code (§12), the rendezvous mailbox sees the
nameplate, the rendezvous identifier, which grant opened the slot and
when it was opened and claimed, and the four messages, whose lengths are
fixed except `m4`'s, which is the ticket text's length plus 16. It never
sees the words. It can play either side, which gives it two online
guesses per run (§12).

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
| `Pondline_Rendezvous_v1` | first field of the spoken-code PAKE's public context, the one string here that is length-prefixed (`lv`), and the rendezvous HKDF-Extract salt (§12) |
| `Pondline_RendezvousConfirm_v1` | rendezvous confirmation key HKDF info (§12) |
| `Pondline_RendezvousHandoff_v1` | rendezvous hand-off key and nonce HKDF info, and prefix of `m4`'s associated data (§12) |

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

## 12. Spoken pairing codes

*Added by ADR-016.* This section is part of V1 for the same reason §11
is: the profile is not yet frozen (`docs/spec.md` §5.2), and an addition
made before the freeze is made by an ADR and recorded here, with labels
ending in `_v1`. ADR-016 is that decision; this section is its bytes. One
part of it is pinned from outside: the PAKE is `draft-vos-cfrg-pqpake-03`,
an individual submission, and its DST fixes that version, so a later
draft that changes the wire is a new profile, not an edit to this one.

### Code and password

```text
code     = nameplate "-" word "-" word "-" word        at most 64 bytes read
nameplate= 6 ASCII digits, zero-padded, drawn by the rendezvous mailbox
word     = a word of the BIP-39 English list (2048 words, published order,
           SHA-256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda)
PRS      = word1 "-" word2 "-" word3                   ASCII, 33 bits of secret
```

The inviter draws the words as the first 33 bits of five bytes from the
CSPRNG, read as three consecutive eleven-bit big-endian indices; the list
has 2048 words, so no index is biased. Only the words are used, not
BIP-39's checksum or seed derivation. The decoder accepts exactly the
text the encoder produces: lowercase ASCII letters, digits and single
hyphens, six digits, three listed words, no case folding and no trimming.

### The PAKE

CPaceOQUAKE, `draft-vos-cfrg-pqpake-03` §7, configuration
`cpaceoquake-x25519-mlbuaskem1024` (§9.4.1), with the message encodings of
its Appendix C.4. Its DST applies throughout, including inside CPace's
transcript hash:

```text
DST = 443e3089985f0f8dddfb20cc5e8618f447bdcfe6dd39abb23911cd784c075120   32 bytes
lv(x)  = len(x) as 2 big-endian bytes || x          (refused above 65 535 bytes)
TH(label, f_1, ..., f_n) = HKDF-Extract(salt = DST || "TH-" || label,
                                        ikm  = lv(f_1) || ... || lv(f_n))      32 bytes
EncodePublicContext(sid, U, S) = len32(sid) || sid || len32(U) || U || len32(S) || S
```

**Stage 1, CPace** is `CPACE-X25519-SHA512` of `draft-irtf-cfrg-cpace-21`
inside the draft's Appendix B wrapper: the channel identifier `CI` is the
secret context, CPace's own `sid` is the whole public context, and the
associated data `ADa` and `ADb` are empty. `lv_cat` is cpace-21's LEB128
framing, not `lv`.

```text
generator_string = lv_cat("CPace255", PRS, zero padding, CI, public_context)
g    = Elligator2(SHA-512(generator_string)[0:32], bit 255 cleared)   RFC 9380 §6.7.1, Z = 2
Ya   = X25519(ya, g)          Yb = X25519(yb, g)      32 bytes each
K    = X25519(ya, Yb) = X25519(yb, Ya)                abort if K is all zero
key1 = SHA-512(lv_cat("CPace255_ISK", public_context, K)
               || lv_cat(Ya, "") || lv_cat(Yb, ""))  64 bytes
th1  = TH("CPace", public_context, Ya, Yb)
```

**Stage 2, OQUAKE** runs on the same PRS with `key1` as its secret
context and `th1` as its public context, over ML-BUA-sKEM-1024: ML-KEM-1024
whose encapsulation key is Kemeleon-encoded at `t = 132` (each of the
four polynomials as a 391-byte little-endian integer, then the 32-byte
seed `rho`), 1596 bytes, split as `ut` (the first 1564) and `rho`. In
the block below `public_context` and `secret_context` are OQUAKE's, that
is `th1` and `key1`, and `Extract(salt, ikm)` and `Expand(prk, info, L)`
are HKDF-SHA-256 with their arguments in that order.

```text
effective_PRS = Expand(Extract(PRS, DST || "OQUAKE-context" ||
                  lv(public_context) || lv(secret_context)),
                DST || "effective_PRS", 32)
T   = ut XOR Expand(Extract(effective_PRS, DST || "OQUAKE" || rho || r), DST || "T_pad", 1564)
s   = r  XOR Expand(Extract(effective_PRS, DST || "OQUAKE" || rho || T), DST || "s_pad", 64)
upk = ut || rho;  (ct, k) = ML-KEM-1024.Encaps(Kemeleon.Decode(upk))   at the client
prk_sk  = Extract(effective_PRS, DST || "OQUAKE" || s || T || rho || upk || ct || k)
h    = Expand(prk_sk, DST || "confirm", 32)
key2 = Expand(prk_sk, DST || "key", 32)
th   = TH("OQUAKE", th1, s, T, rho, ct, h)
```

`r` is 64 fresh bytes. The server sends `s`, `T` and `rho`; the client
runs the two rounds backwards (`s_pad` first, recovering `r`, then
`T_pad`, recovering `ut`) under its own PRS, so a wrong PRS gives another
`ut` that Kemeleon still decodes to a valid key.

**Kemeleon** at `t = 132`, as `core/crypto/kemeleon` implements it, for
each polynomial `t_i` of the encapsulation key (256 coefficients below
3329, read as FIPS 203's `ByteDecode_12`):

```text
x_i   = sum_j t_i[j] * 3329^j                          0 <= x_i < 3329^256
range = floor((2^3128 - 1 - x_i) / 3329^256) + 1       multiples allowed for x_i
m_i   = draw_i mod range                               draw_i: 48 fresh bytes per polynomial
r_i   = x_i + m_i * 3329^256                           391 bytes, little-endian
encoded key = r_1 || r_2 || r_3 || r_4 || rho          1596 bytes
Decode(r_i) = r_i mod 3329^256, written back as 256 coefficients
```

The range differs from `draft-irtf-cfrg-kemeleon-02` §4.1, whose
`VectorEncode` draws `m_i` from `[0, floor((2^3128 - x_i) / 3329^256)]`
inclusive. For the single value `x* = 2^3128 mod 3329^256` the draft's
largest multiple makes `r_i` exactly `2^3128`, which 391 bytes cannot
hold; written in 3128 bits it becomes zero and decodes to a different
key. This profile excludes that one multiple. For every other value the
two ranges are equal, so every multiple the draft allows elsewhere is
used unchanged and no draft vector is affected. With the change the
encoding is a bijection between pairs `(x_i, m_i)` and 391-byte strings
(`docs/formal/lean.md`, Kemeleon). Reported upstream as
Roasbeef/pondline#10.

**The combiner**:

```text
prk         = HKDF-Extract(salt = key2, ikm = DST || "CPaceOQUAKE" || th || key1)
session_key = HKDF-Expand(prk, DST || "key", 32)
```

### Context and roles

```text
public_context = lv("Pondline_Rendezvous_v1") || lv(nameplate, 6 ASCII digits)
                 || EncodePublicContext(sid = rendezvous identifier (16),
                                        U = "joiner", S = "inviter")      73 bytes
secret_context = empty
```

The rendezvous identifier is the 16 random bytes the inviter opened the
slot under; the joiner learns it from its claim. The nameplate and the
identifier are bound into CPace's generator, its key and `th1`, so a
mailbox that showed the joiner a different slot from the inviter's gives
the two sides different passwords in effect. The endpoint is not in the
context.

The **joiner is the draft's client** (CPace initiator, OQUAKE responder)
and the **inviter its server** (CPace responder, OQUAKE initiator), the
draft's own §7 assignment, so its proof and vector apply unchanged and
the inviter has the joiner's proof of the words before it releases
anything.

### Messages

| Message | From | Contents | Bytes |
| --- | --- | --- | --- |
| `m1` | joiner | `lv(Ya)` | 34 |
| `m2` | inviter | `lv(Yb) \|\| s (64) \|\| T (1564) \|\| rho (32)` | 1694 |
| `m3` | joiner | `ct (1568) \|\| h (32) \|\| confirm_J (32)` | 1632 |
| `m4` | inviter | ChaCha20-Poly1305 of the ticket text, with its 16-byte tag | ticket text + 16, at most 208 (146 for an onion ticket) |

Each is checked for exactly its length, and `m1` and `m2` for a 32-byte
share behind their prefix, before anything else is done with it. Every
message fits a rendezvous body of 2048 bytes.

### Confirmation and hand-off

OQUAKE's Finish never reports a wrong password: on a bad `h` or a failed
decapsulation it returns a fresh random `key2`, and the draft forbids
reading completion as evidence that the peer knew the password. So both
directions are confirmed explicitly, from the session key and `th`:

```text
PRK         = HKDF-Extract(salt = "Pondline_Rendezvous_v1", ikm = session_key)
confirm_key = HKDF-Expand(PRK, "Pondline_RendezvousConfirm_v1", 32)
confirm_J   = HMAC-SHA-256(confirm_key, th)                              32 bytes
key, nonce  = HKDF-Expand(PRK, "Pondline_RendezvousHandoff_v1", 44)      32 then 12
m4          = ChaCha20-Poly1305(key, nonce,
                aad = "Pondline_RendezvousHandoff_v1" || th, ticket text)
```

The inviter compares `confirm_J` in constant time and seals `m4` only on a
match. The joiner's proof that the inviter held the words is that `m4`
opens. Either failure ends the run. For the session key and `th` of the
draft's E.4 vector, `confirm_J` is
`0465897caf04e2ddb1c32c09bc8cf992227c6d01026bb31cbd9eef420bd33c09` and
the hand-off nonce `705b8662948b4521b87ceb0a`, computed by an independent
script and pinned by `schedule_matches_the_independent_vector_test`.

**`m4` is sealed once.** Its key and nonce are fixed by the session key,
so two different plaintexts under them would break ChaCha20-Poly1305. The
ticket is minted and stored at the mailbox before the inviter reads `m1`,
`m4` is computed exactly once per run, and a resend sends the same bytes.
Separately, a step run on a second message at the same index is a second
guess at the words, so each side acts only on the first message at each
index and ends the run on any error.

### What is and is not constant time

The X25519 multiplications, ML-KEM-1024, SHA-256, SHA-512, HMAC, HKDF
and ChaCha20-Poly1305 run inside OpenSSL. The comparison of `confirm_J`
and OQUAKE's comparison of `h` are constant-time equality, and OQUAKE
draws its fallback key whether or not it uses it, so both outcomes make
the same calls. The Elligator 2 map, the Kemeleon encoding and decoding,
and the Feistel XOR are arithmetic on the BEAM's arbitrary-precision
integers, on values derived from the password or from secret randomness,
and **are not constant time**: bignum operations take time that depends
on their operands, and Elligator 2's final choice between two points is
an ordinary branch. Both drafts ask for constant time there. ADR-016
accepts the gap on an argument: the observer would have to share the
host, across Tor the jitter is orders of magnitude above the signal, and
a code is used once. That argument is assumed, not shown.

### Status

Implemented in `core/crypto/elligator2`, `pake_common`, `cpace`,
`kemeleon`, `bua_skem`, `oquake`, `cpace_oquake` and `core/rendezvous`,
and tested against cpace-21 Appendix B.1 (including the low-order points
that must abort), pqpake-03 Appendices E.1.2, E.2, E.4 end to end for
both roles and E.5.4, and the independent schedule vector
(`packages/primitives/test/primitives/`). OTP's `crypto` takes neither a
key-generation seed nor an encapsulation seed, so ML-KEM's own steps
inside the draft's vectors are reproduced by a test-only FIPS 203
reference (`mlkem_reference.gleam`, held first to NIST ACVP keyGen and
encapsulation cases and to OpenSSL): the key pair from `keygen_seed` and
the ciphertext and `k` from `encaps_m` equal the vector's. The vector
tests seed only encapsulation through it; decapsulation is OpenSSL's,
with the derived key. The draft's values do not pin the second half of
`keygen_seed` (`z`, which enters only the implicit-rejection key); ACVP
does. The reference lives under `test/` and is not in a release. The
ProVerif model of the exchange is in `docs/formal/crypto.md`, "Spoken
pairing codes"; Kemeleon, the nameplate, the word indices, the context
framing and the Elligator 2 map's range are proved in Lean against
transcriptions tied to the Gleam by conformance vectors
(`docs/formal/lean.md`). That the Elligator 2 output lies on the curve is
tested, not proved. The daemon's run, `daemon/pairing`, holds the two rules
above that `core` cannot, acting only on the first message at each index
and sealing `m4` once and resending those bytes; both are tested against a
scripted mailbox in `packages/daemon/test/daemon/pairing_test.gleam`, and
the whole pairing between two daemons and a real mailbox in
`pairing_code_test.gleam`. Assumed, until an outside reader says otherwise: that the
draft's argument carries over to a store-and-forward rendezvous, that the
confirmation and hand-off derivations above are sound uses of the session
key, and the timing argument. No outside cryptographer has reviewed this
code.
