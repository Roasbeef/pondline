# CryptoProfileV1

This document fixes the cryptography of Reedwire v1: the algorithms, every
byte layout, every domain-separation string, the limits, what a mailbox can
see, and what the construction does and does not guarantee. It is the
statement `docs/spec.md` §5.2 asks for, and the code in `core/crypto` is
checked against it. Where this document and the code disagree, that is a
bug in one of them, to be settled by an ADR.

The decision to build this over OTP's `crypto` is `docs/adr/002-pq-crypto-over-otp.md`.
No new primitive is designed here: every algorithm below is a published one,
and the protocols are Signal's PQXDH and Double Ratchet, specialised.

## 1. Algorithms

| Role | Algorithm | Sizes (bytes) |
| --- | --- | --- |
| Key agreement | X25519 (RFC 7748) | key 32, shared secret 32 |
| Signatures | Ed25519 (RFC 8032, pure) | key 32, signature 64 |
| Post-quantum KEM | ML-KEM-1024 (FIPS 203) | encapsulation key 1568, decapsulation key 3168 (OpenSSL's expanded form), ciphertext 1568, shared secret 32 |
| Hash | SHA-256 (FIPS 180-4) | 32 |
| MAC | HMAC-SHA-256 (RFC 2104) | 32 |
| KDF | HKDF-SHA-256 (RFC 5869) | up to 8160 |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | key 32, nonce 12, tag 16 |

Integers in every layout are big-endian. A "version" byte is `0x01` in v1.

## 2. Identity

Each relationship has its own identity, so an identity links nothing across
relationships. An identity is an Ed25519 signing key and an X25519 agreement
key. The two are tied by a binding signature, in place of Signal's XEdDSA
use of one key for both jobs.

```text
binding   = Ed25519.Sign(signing_secret, "Reedwire_IdentityBinding_v1" || x25519_public)
PublicIdentity = ed25519_public (32) || x25519_public (32) || binding (64)    128 bytes
fingerprint    = SHA-256(PublicIdentity)
```

A decoder verifies the binding and refuses the identity if it fails, so no
public identity that reaches the protocol lacks a valid binding.

## 3. Prekey bundle

The inviter's bundle is embedded in the invitation file. There is no
publication and no claim step, and no one-time prekeys, because an
invitation's bundle is single-use by construction.

```text
spk_signature   = Ed25519.Sign(signing_secret, "Reedwire_SignedPrekey_v1"   || spk)
pqspk_signature = Ed25519.Sign(signing_secret, "Reedwire_PQSignedPrekey_v1" || pqspk)

Bundle = version (1) || PublicIdentity (128) || spk (32) || spk_signature (64)
         || pqspk (1568) || pqspk_signature (64)                      1857 bytes
bundle_commitment = SHA-256(Bundle)
```

Decoding a bundle verifies the identity binding and both prekey signatures
under the bundle's Ed25519 key. A bundle whose prekey was replaced by anyone
other than the identity's owner is rejected there.

## 4. Handshake (PQXDH)

The joiner is the initiator and the inviter is the responder.

```text
DH1 = X25519(IK_init.x25519_secret, SPK)
DH2 = X25519(EK_secret,             IK_resp.x25519_public)
DH3 = X25519(EK_secret,             SPK)
(SS, CT) = ML-KEM-1024.Encaps(PQSPK)

SK = HKDF-SHA-256(salt = 0x00 x 32,
                  ikm  = 0xFF x 32 || DH1 || DH2 || DH3 || SS,
                  info = "Reedwire_PQXDH_X25519_SHA-256_ML-KEM-1024_v1",
                  L    = 32)
AD = PublicIdentity(IK_init) || PublicIdentity(IK_resp)                256 bytes
```

The prefix is 32 bytes of `0xFF`, Signal's `F`. For DH1 = `0x01` x 32,
DH2 = `0x02` x 32, DH3 = `0x03` x 32 and SS = `0x04` x 32, `SK` is
`6fba3e33d9b8711d0c4d6c4cd0a02a835617f0313bfe5f74992c5fb903b75473`
(computed independently and pinned by `pqxdh_shared_secret_known_answer_test`).

The initiator's first message:

```text
InitialMessage = version (1) || PublicIdentity(IK_init) (128) || EK_public (32)
                 || CT (1568) || bundle_commitment (32) || ratchet_message (rest)
```

The responder checks the commitment against the bundle it holds, verifies
the initiator's identity binding, recomputes `SK` (using the signed prekey
secret and the ML-KEM secret), and decrypts the ratchet message. It starts
its ratchet with the signed prekey as its first ratchet key pair. After the
caller stores the new state it retires the bundle's secrets. Until then a
retry of the same initial message gives the same session, because the
handshake does not mutate the prekeys.

ML-KEM rejects implicitly: a forged `CT` decapsulates to an unrelated
secret, so the responder sees a failed authentication of the first ratchet
message and not a KEM error.

## 5. Double Ratchet

```text
KDF_RK(rk, dh_out)   = HKDF-SHA-256(salt = rk, ikm = dh_out,
                                    info = "Reedwire_Ratchet_v1", L = 64)
                       -> (rk', chain_key)       first 32 bytes, last 32 bytes
KDF_CK(ck)           : message_key = HMAC-SHA-256(ck, 0x01)
                       ck'         = HMAC-SHA-256(ck, 0x02)
message keys         = HKDF-SHA-256(salt = 0x00 x 32, ikm = message_key,
                                    info = "Reedwire_MessageKeys_v1", L = 44)
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
initiator's public identity, the ephemeral key and the bundle commitment in
the first message of a relationship. Header encryption is deliberately left
for a later profile.

## 8. Guarantees, stated honestly

What v1 provides:

- **Confidentiality of the initial key against a quantum adversary.** `SK`
  mixes an ML-KEM-1024 shared secret with three X25519 secrets, so a
  recording of the handshake does not let a future quantum computer recover
  `SK` unless it also breaks ML-KEM. This is the harvest-now-decrypt-later
  protection PQXDH exists for.
- **Forward secrecy and post-compromise security against a classical
  adversary**, from the Double Ratchet's DH steps and chain-key deletion.
- **Authenticated, replay-resistant, bounded-reordering delivery**, with
  every message bound to both identities through the associated data.

What v1 does not provide:

- **Quantum-resistant authentication.** Identities, the bundle signatures and
  the DH agreements are classical (Ed25519, X25519). A quantum adversary who
  can break them while the session is live can impersonate a party.
- **Post-quantum post-compromise security.** After the handshake every DH
  ratchet step is X25519, so a quantum adversary who learns a ratchet state
  is not locked out by later steps. The version bytes in the state, bundle
  and initial message reserve room for Signal's sparse post-quantum ratchet,
  which is not implemented.
- **Hot code upgrade of `core/secret`.** Secrets are closures, which the BEAM
  ties to the module version that created them. The daemon does not support
  hot code upgrades of `core/secret`; an upgrade restarts the VM.
- **Memory erasure.** The BEAM gives no way to zero key material; a deleted
  key may linger in memory until collected, and in any swap or dump.
- **Metadata protection beyond Tor.** See §7.

## 9. Domain-separation strings

| String | Used for |
| --- | --- |
| `Reedwire_IdentityBinding_v1` | identity binding signature |
| `Reedwire_SignedPrekey_v1` | signed X25519 prekey signature |
| `Reedwire_PQSignedPrekey_v1` | signed ML-KEM prekey signature |
| `Reedwire_PQXDH_X25519_SHA-256_ML-KEM-1024_v1` | handshake HKDF info |
| `Reedwire_Ratchet_v1` | root-key HKDF info |
| `Reedwire_MessageKeys_v1` | message-key HKDF info |

All are ASCII, with no terminator or length prefix; each signature input is
the string followed immediately by a fixed-size key.

## 10. Status

Implemented and tested in `packages/core/src/core/crypto` and
`packages/primitives`. HKDF matches RFC 5869 test cases 1 to 3. There are no
external test vectors for PQXDH or this ratchet, so correctness rests on the
round-trip, tamper, replay, bound and persistence tests, a property suite
over a deterministic fake, mutation checks, and review. Cross-implementation
vectors remain to be produced if a second implementation is ever written.
