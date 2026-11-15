# primitives

## Purpose

The cryptographic primitives Pondline's protocols are built from: X25519,
Ed25519, ML-KEM-1024, ML-DSA-65, ChaCha20-Poly1305, SHA-256, SHA-512,
HMAC-SHA-256 and the OS CSPRNG, all taken from OTP's `crypto` application over OpenSSL
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
- `src/primitives_ffi.erl`: the Erlang shim. Every fallible key or verification
  wrapper catches exceptions so key material cannot leak through crash reports;
  total operations (`sha256`, `sha512`, `hmac_sha256`, `equal`,
  `random_bytes`, keypair generation and `openssl_version`) stay direct
  calls. `sha512` exists for CPace (ADR-016) and is the suite's only
  SHA-512 field.
- `primitives/suite`: `suite()`, the production `core/crypto/suite.Suite`
  built from the functions above. The only place the record is filled with
  real implementations; the fake lives in `core`'s `test/` only.
- `test/primitives/vectors` (test only): the loader for the trimmed
  Wycheproof and NIST ACVP vector files under `test/vectors/`, which
  `test/vectors/trim.py` derives from the upstream repositories at the
  commit and SHA-256 each file records. The same loader reads the
  spoken-code PAKE's fixtures (ADR-016), which `trim.py` does not
  produce: they were extracted from the draft text by a script that is
  not in the repository, and are never edited by hand. Each file's
  `source` names its sections; the three OQUAKE-stage files also record
  the draft's SHA-256.
  - `cpace_x25519_sha512.json`: `draft-irtf-cfrg-cpace-21` B.1.1 to B.1.5
    as one run (generator string, generator, shares, `K`, the ISK under
    cpace-21's own presentation with non-empty associated data) and the
    twelve B.1.10 low-order cases with whether each must abort.
  - `cpace_pqpake_wrapper.json`: the CPace part of
    `draft-vos-cfrg-pqpake-03` E.4 (the Appendix B wrapper under the
    CPaceOQUAKE DST: shares, key, transcript hash) and E.5.4's
    neutral-element `msg1`.
  - `bua_skem_mlbuaskem1024.json`: E.1.2, one ML-BUA-sKEM key generation
    and encapsulation, reproduced from its seeds.
  - `oquake_mlbuaskem1024.json`: E.2, OQUAKE alone under the
    `oquake-mlbuaskem1024` DST.
  - `oquake_cpaceoquake_stage.json`: the whole of E.4 (inputs, every
    random value, `msg1` to `msg3`, the key and `th`), read by both
    `oquake_test` (the OQUAKE stage) and `cpace_oquake_test` (end to end,
    both roles).
  - `cpace_oquake_rendezvous_schedule.json` is not from the draft: an
    independent Python script (`hmac`, `hashlib`, `cryptography`'s
    ChaCha20-Poly1305, kept outside the repository) computed ADR-016's
    `confirm_key`, `confirm_J`, hand-off key, nonce and `m4`, and the
    public context for nameplate `482719` and identifier
    `000102...0f`, from E.4's key and `th`.
- `test/primitives/mlkem_reference` (test only): a FIPS 203 reference for
  ML-KEM-1024's two deterministic algorithms, `keygen_internal(d, z)`
  (Algorithm 16) and `encaps_internal(ek, m)` (Algorithm 17), in pure
  Gleam, with `derive_key_pair` cutting the draft's 64-byte `keygen_seed`
  into `d || z`. It exists because OTP's `crypto` takes neither a key
  generation seed nor encapsulation randomness, and the pqpake-03 vectors
  fix both. It is not constant time and is written for clarity. Its hash
  steps (SHA3-256, SHA3-512, SHAKE128, SHAKE256) come from
  `test/primitives/internal/ffi_sha3`, direct `@external`s to
  `crypto:hash/2` and `crypto:hash_xof/3` named as an `internal/ffi_*`
  module so they stay in one place; the production API has no SHA-3 and
  gains none for a test. Both modules live under `test/`, which a release
  never compiles, so the reference can no more reach a production build
  than `core`'s fake suite can (`docs/spec.md` §13.3).

## Relationships

Depends on `gleam_stdlib`, OTP's `crypto`, and `core` (for the `Suite` type
alone; `core` never depends back). The tests also take `simplifile` and
`gleam_json`, to read the vector files; neither reaches `src/`. Consumed by the daemon and mailbox
shells, which take `primitives/suite.suite()`. Its tests run the real
handshake and ratchet over these primitives.

## Traffic

None. Pure function calls into OpenSSL; no processes, no messages.

## Invariants

- Fallible key and verification operations catch every exception inside
  `primitives_ffi` and return `Error(Nil)` or `False`. OTP's crypto errors carry
  their arguments, which are keys, so an uncaught error on a bad key or input
  would print key material into a crash report.
- Every primitive matches its standard's published vectors
  (`test/primitives/known_answer_test.gleam`: RFC 7748, 8032, 8439, 4231,
  FIPS 180-4). ML-KEM, which has no deterministic key generation through
  OTP, is checked through the binding by round trip, size and implicit
  rejection, and byte for byte through the test-only reference below. ML-DSA-65
  has neither seeded key generation through OTP 29 nor deterministic
  signing (OpenSSL hedges), so `test/primitives/mldsa_test.gleam` checks
  sizes, round trips and every rejection a verifier owes instead.
- HKDF (`core/crypto/hkdf`) matches RFC 5869 cases 1 to 3
  (`test/primitives/hkdf_test.gleam`), and the full PQXDH and ratchet tests
  in `test/primitives/protocol_test.gleam` are the only tests of the
  protocols over real crypto.
- ML-KEM decapsulation of a forged ciphertext returns an unrelated secret,
  not an error. Authentication comes from what that secret later keys.
- The standard vector suites run through the `primitives` API, never
  through `crypto:` directly (`test/primitives/wycheproof_*_test.gleam`,
  `test/primitives/acvp_*_test.gleam`): Wycheproof X25519 (every zero
  shared secret refused, every other case computed as RFC 7748 says),
  Ed25519 (every invalid and malleated signature refused; the small-order
  and mixed-order `acceptable` cases are pinned as accepted), ChaCha20-
  Poly1305 (every modified tag and every nonce size but 12 bytes refused),
  HMAC-SHA-256 and HKDF-SHA-256 (sizes past 8160 refused); NIST ACVP
  ML-KEM-1024 (NIST key pairs and ciphertexts, the implicit-rejection
  secret of every modified ciphertext, the encapsulation-key modulus check
  and the decapsulation-key hash check) and ML-DSA-65 (NIST key pairs sign
  and verify through the binding, NIST signatures with an empty context
  verify and ones under another context do not). `docs/formal/crypto.md`
  records the sources, counts and what each suite cannot reach.
- SHA-512 matches FIPS 180-4's `abc` digest
  (`sha512_fips_180_4_abc_test` in `test/primitives/cpace_test.gleam`).
- The spoken-code PAKE (`core/crypto/cpace`, `kemeleon`, `bua_skem`,
  `oquake`, `cpace_oquake`, ADR-016) is tested over these primitives
  only here; `core`'s own tests use a fake suite and a stand-in ML-KEM.
  `cpace_test` reproduces cpace-21 B.1 and the CPace values of pqpake-03
  E.4 exactly and aborts on every B.1.10 case marked `abort` and on
  E.5.4. `bua_skem_test` re-encodes E.1.2's key byte for byte under its
  four multiples, which pins Kemeleon's base-3329 reading, the multiple
  of 3329^256, the 391-byte little-endian width and the seed's place, and
  checks that every string of the encoded length is a key OpenSSL
  accepts. `oquake_test` reproduces E.2 and E.4's OQUAKE stage, and
  `cpace_oquake_test` reproduces E.4 end to end for both roles; running
  both DSTs is what shows the DST is a parameter. `rendezvous_test` pins
  `core/rendezvous`'s key schedule and public context against the
  independent vector, then runs whole exchanges with fresh randomness: an
  honest run, a wrong word at either end, another context, a changed bit
  in each of `m1` to `m4`, wrong lengths and length prefixes, a zero
  share, and a ticket out of bounds.
- The ML-KEM steps inside those vectors are reproduced from their seeds.
  `mlkem_reference` is trusted only after `mlkem_reference_test` holds it
  to every trimmed NIST ACVP ML-KEM-1024 keyGen case (`d`, `z` to `ek`,
  `dk`) and encapsulation case (`ek`, `m` to `c`, `k`) byte for byte, and
  to OpenSSL on ten fresh seed sets (OpenSSL accepts the reference's
  `ek`, and with the reference's `dk` opens both its own ciphertext and
  the reference's). Then, for E.1.2, E.2 and E.4, the key pair derived
  from `keygen_seed` must Kemeleon-encode under `kemeleon_m` to the
  vector's `upk` or `oquake_upk`, `encaps_m` must give its ciphertext and
  shared secret, and OpenSSL with the derived `dk` must open that
  ciphertext to that secret. `oquake_test`, `cpace_oquake_test` and
  `bua_skem_test` seed only encapsulation through the reference, by
  record update of the real suite's `kem_encapsulate`, answering only for
  the key `keygen_seed` derives, so a run in the wrong roles or with the
  wrong contexts unmasks another key and finds no answer. Decapsulation
  is OpenSSL's, with the derived key; everything OQUAKE and the combiner
  compute runs for real, and the honest and wrong-password runs use
  OpenSSL's ML-KEM throughout.
- Two things the draft's values cannot pin. The second half of
  `keygen_seed`, `z`, enters only the implicit-rejection key inside
  `dk`, and no draft value exercises implicit rejection, so a reference
  that mishandled `z` would still pass E.1.2, E.2 and E.4; the ACVP keyGen
  cases, which list the whole `dk`, are what pin it. And ML-KEM-1024's
  two CBD parameters are both 2 (`eta1`, `eta2` in the reference), so a
  reference that drew the encryption errors with eta1 or the secret with
  eta2 would compute identical bytes: no vector, ACVP's included, can
  detect that swap for this parameter set, and it would matter only for
  ML-KEM-512, which Pondline does not use.
- `test/primitives/hybrid_auth_test.gleam` holds the tests that fail if any
  hybrid signature check verifies only its classical half: identity
  binding, both prekey signatures and the joiner's transcript, each with
  exactly one valid half, in both directions.

## Deep Docs

- `docs/adr/002-pq-crypto-over-otp.md` (the decision and its evidence).
- `docs/crypto-profile-v1.md` (the algorithms, layouts and guarantees).
- `docs/spec.md` §5 (the crypto contract).
- `docs/formal/crypto.md` (the symbolic proof of the handshake and the
  vector results, with what each abstracts).
- `docs/adr/016-spoken-pairing-codes.md` and `docs/crypto-profile-v1.md`
  §12 (the spoken-code PAKE the new fixtures pin).
