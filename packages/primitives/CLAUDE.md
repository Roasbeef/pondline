# primitives

## Purpose

The cryptographic primitives Reedwire's protocols are built from: X25519,
Ed25519, ML-KEM-1024, ML-DSA-65, ChaCha20-Poly1305, SHA-256, HMAC-SHA-256
and the OS CSPRNG, all taken from OTP's `crypto` application over OpenSSL
(3.5 or newer, for ML-KEM and ML-DSA). No Rust and no NIF of our own.

The API is byte-level on purpose. The typed layer, where an X25519 key
cannot be passed as an Ed25519 key and a secret cannot be printed, lives in
`core/crypto`, which receives these functions as a suite record so that
the protocol logic stays pure.

## Key Types

- `primitives`: one function per primitive, sizes as named constants.
  Fallible operations return `Result(_, Nil)` and never raise.
- `primitives/internal/ffi_crypto`: the externals, confined here by the FFI
  rule.
- `src/primitives_ffi.erl`: the Erlang shim. Every wrapper catches every
  exception.
- `primitives/suite`: `suite()`, the production `core/crypto/suite.Suite`
  built from the functions above. The only place the record is filled with
  real implementations; the fake lives in `core`'s `test/` only.

## Relationships

Depends on `gleam_stdlib`, OTP's `crypto`, and `core` (for the `Suite` type
alone; `core` never depends back). Consumed by the daemon and mailbox
shells, which take `primitives/suite.suite()`. Its tests run the real
handshake and ratchet over these primitives.

## Traffic

None. Pure function calls into OpenSSL; no processes, no messages.

## Invariants

- No exception leaves `primitives_ffi`. OTP's crypto errors carry their
  arguments, which are keys, so a raised error would print a private key
  into a crash report.
- Every primitive matches its standard's published vectors
  (`test/primitives/known_answer_test.gleam`: RFC 7748, 8032, 8439, 4231,
  FIPS 180-4). ML-KEM, which has no deterministic key generation through
  OTP, is checked by round trip, size and implicit rejection. ML-DSA-65
  has neither seeded key generation through OTP 29 nor deterministic
  signing (OpenSSL hedges), so `test/primitives/mldsa_test.gleam` checks
  sizes, round trips and every rejection a verifier owes instead.
- HKDF (`core/crypto/hkdf`) matches RFC 5869 cases 1 to 3
  (`test/primitives/hkdf_test.gleam`), and the full PQXDH and ratchet tests
  in `test/primitives/protocol_test.gleam` are the only tests of the
  protocols over real crypto.
- ML-KEM decapsulation of a forged ciphertext returns an unrelated secret,
  not an error. Authentication comes from what that secret later keys.
- `test/primitives/hybrid_auth_test.gleam` holds the tests that fail if any
  hybrid signature check verifies only its classical half: identity
  binding, both prekey signatures and the joiner's transcript, each with
  exactly one valid half, in both directions.

## Deep Docs

- `docs/adr/002-pq-crypto-over-otp.md` (the decision and its evidence).
- `docs/crypto-profile-v1.md` (the algorithms, layouts and guarantees).
- `docs/spec.md` §5 (the crypto contract).
