# ADR-002 — Post-quantum crypto is OTP primitives with the protocols written in Gleam

**Status**: accepted · **Date**: 2026-10-31 · **Spec ref**: §5

## Decision

Reedwire's cryptography is built from the primitives in OTP's `crypto`
application (X25519, Ed25519, ML-KEM-1024, ChaCha20-Poly1305, SHA-256,
HMAC-SHA-256 and the OS CSPRNG), reached through the `primitives` package.
The protocols are written in Gleam in `core/crypto`: HKDF, PQXDH, and the
Double Ratchet, with the ratchet state an ordinary immutable value. The
algorithms, layouts and domain-separation strings are frozen in
`docs/crypto-profile-v1.md`. This supersedes the Rust crypto NIF as the
plan for v1; the Rust boundary remains for Arti.

## Why

`docs/spec.md` §5.3 requires that a crypto operation never advance hidden
state before the application commits its transaction. A ratchet held in a
native resource cannot satisfy that; one that is an immutable value in
Gleam does, and a failed or uncommitted decrypt simply leaves the caller
holding the old state. That settles where the protocol lives. What remained
open was where the primitives come from.

Evidence, from this machine:

- Erlang/OTP 29 over OpenSSL 3.6.3 provides every primitive above, including
  ML-KEM-1024 (OpenSSL 3.5 and later).
- The bindings match the published vectors in
  `packages/primitives/test/primitives/known_answer_test.gleam` (RFC 7748,
  8032, 8439, 4231, FIPS 180-4). ML-KEM has no deterministic key generation
  through OTP, so it is checked by round trip, size and implicit rejection.
- HKDF, written over HMAC in Gleam, matches RFC 5869 test cases 1 to 3
  (`packages/primitives/test/primitives/hkdf_test.gleam`).
- `packages/primitives/test/primitives/protocol_test.gleam` runs the full
  handshake and ratchet over the real primitives: both directions, bounded
  reordering, replay, every single-byte tamper, both skip bounds, state
  persistence, bad and substituted prekeys, swapped identities, a forged KEM
  ciphertext. `packages/core/test/core/crypto/ratchet_test.gleam` checks
  properties over a deterministic fake suite that exists only under `test/`.
- Mutations that were confirmed to fail a test: one-sided DH3, skipped
  prekey signature check, keeping a consumed skipped key, removing either
  skip bound, removing the replay check, removing the header from the
  associated data, removing the bundle commitment check, and removing the
  decoder's key-count bound.

Considered and rejected: `libsignal` (AGPL, and its maintainers state that
external use is unsupported and its API unstable), and `vodozemac` (no
post-quantum handshake).

Implemented and tested: everything above. Still assumed: that PQXDH as
specialised here (Ed25519 identity with a binding signature, bundle embedded
in the invitation, no one-time prekeys) keeps Signal's security argument.
No external vectors exist for it.

## Consequences

- **No memory zeroization.** The BEAM cannot erase a binary. Secrets are
  held in closures (`core/secret`) so they stay out of logs and crash
  reports, but a deleted key can persist in memory. This is a platform
  limit stated in the profile, not something this design can fix.
- **No hot upgrade of `core/secret`.** Secrets are closures, which the BEAM
  ties to the module version that created them, so the daemon does not
  support hot code upgrades of that module; upgrades restart the VM.
- **OpenSSL 3.5 or newer is required for ML-KEM.** Ubuntu 24.04 ships
  OpenSSL 3.0, so a release must bundle a newer OpenSSL with its Erlang.
  `primitives.openssl_version()` lets the daemon check at startup.
- **No external test vectors for PQXDH.** Correctness rests on this
  repository's tests, the property suite and review. Producing vectors for
  a second implementation is future work.
- **The suite is the only way `core` reaches crypto.** `core` stays pure and
  property-testable, and the test suite is not compilable into a release.
- **No post-quantum ratchet in v1.** The version bytes reserve room for
  Signal's sparse post-quantum ratchet.
- Revisit if OTP's ML-KEM binding changes, if a reviewed native
  implementation becomes a better home for the primitives, or if
  zeroization becomes a requirement.

## Addendum (2026-11-01): authentication is hybrid

`docs/adr/005-hybrid-authentication.md` amends this record. The primitive
list above gains ML-DSA-65, also from OTP's `crypto` over OpenSSL 3.5 or
newer, so the dependency is unchanged. Two statements above no longer
hold as written. "Ed25519 identity with a binding signature" is now an
identity of two signing keys, Ed25519 and ML-DSA-65, whose binding and
prekey signatures are hybrid (both algorithms over the same bytes, both
required). And the assumption that PQXDH as specialised here keeps
Signal's security argument now covers one more departure: the initiator
signs the handshake transcript with both of its keys, which PQXDH does
not do. Quantum-resistant authentication, which the profile listed as not
provided, is provided at the handshake. ML-DSA-65 has no fixed-output
vector through OTP 29 (hedged signing, no seeded key generation), so like
ML-KEM it is checked by sizes, round trips and rejections.
