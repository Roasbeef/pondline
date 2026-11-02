# Hybrid PAKE for human-typable pairing codes

**Status**: research note · **Date**: 2026-11-01 · **Tracks**: issue #1 ·
**Depends on**: the short invitation ticket (`pl1…`), being built in parallel

This note works out how Pondline could pair two daemons from a code an
operator can read over the phone, in the magic-wormhole style
(`7-guitarist-revenge`), without weakening the post-quantum posture of
`docs/crypto-profile-v1.md`. It surveys the published constructions,
verifies the citations issue #1 wrote from memory, measures each candidate
against what OTP's `crypto` already provides, and recommends one with a
concrete message flow over the mailbox. Nothing here is scheduled; the
note exists so the decision can be made once, with the evidence in one
place.

The one-sentence conclusion: adopt the sequential CPace-then-OQUAKE
composition that the CFRG draft `draft-vos-cfrg-pqpake` specifies, rather
than composing a hybrid PAKE in-house, because it is the only candidate
whose password protection survives a break of either X25519 or ML-KEM, it
has a UC proof and test vectors, and every primitive it needs is either in
OTP or a few hundred lines of pure Gleam.

## 1. The problem

### 1.1 What a code can carry

The invitation file (about 14.6 KB with hybrid authentication) and the
ticket (about 110 characters: the mailbox onion plus a 32-byte key `K`
that decrypts and commits to the full invitation stored at the mailbox)
are both high-entropy bearer credentials. They are copied, never read
aloud. A spoken code carries far less:

| Code shape | Entropy | Example |
| --- | --- | --- |
| magic-wormhole default: nameplate plus two words from a 256-word even/odd list (PGP word list) | 16 bits in the words; the nameplate is public | `4-purple-sausages` |
| Three words from the same list | 24 bits | `4-purple-sausages-anvil` |
| Four words | 32 bits | `4-purple-sausages-anvil-quota` |
| Ticket (for comparison) | 256 bits | `pl1…` (about 110 characters) |

magic-wormhole's own attack notes state the consequence plainly: with 16
bits, a network or server attacker has one chance in 65 536 per attempt,
and the honest parties see about 32 000 failures before the attacker has
even odds. The number that matters is not the entropy but the number of
guesses an attacker gets, which the protocol must hold to one per run.

### 1.2 Why the code must be a PAKE password, not a key

A 24-bit value cannot encrypt anything: an attacker who records the
rendezvous traffic would try all 2^24 codes offline in seconds. A
password-authenticated key exchange (PAKE) changes the game. In the
Bellare, Pointcheval and Rogaway model, and in the UC functionality that
CPace realises, an active attacker learns at most whether one guess per
protocol run was right, and a passive one learns nothing. The protocol
turns a 24-bit secret into a 256-bit session key `k` that only two parties
holding the same code can derive, and the only way to test a guess is to
run the protocol against one of them, which they can refuse after one
failure.

The code is single-use and short-lived, so the PAKE has an easier job
than a login PAKE. In particular, "harvest now, decrypt later" against the
PAKE transcript matters less than it does for the handshake it bootstraps:
once the pairing has completed, a future quantum computer that recovers
`k` from a recording learns the full invitation (the inviter's public
bundle, routes, queue identifiers, the description) but no session secret,
since the PQXDH handshake that follows mixes an ML-KEM-1024 secret the PAKE
never saw. What the PAKE must get right is the active case: an attacker
with a quantum computer at the moment of pairing must still be held to one
guess. That is what "hybrid PAKE" has to mean here, and it is a stronger
requirement than hybrid key secrecy, as §3 shows.

### 1.3 Rendezvous: both sides online, at a mailbox

The file and the ticket are asynchronous: the inviter can be offline while
the joiner redeems them. A PAKE is interactive. Both daemons must be
online at roughly the same time and must find each other. magic-wormhole
solves the finding with a nameplate: a short handle, allocated at a
rendezvous server that both sides already know, which points at a
mailbox the two sides share for the duration of the exchange.

Pondline has no server both sides already know. A mailbox is an onion
address, 56 base32 characters, which is no more speakable than the ticket.
So the code must imply the rendezvous mailbox rather than name it:

- **Managed default.** The managed service (`docs/design-intent.md` §12,
  "managed by default") runs a rendezvous mailbox whose onion address
  ships with the daemon. A code with no mailbox token means that one.
- **Configured aliases.** An operator who self-hosts configures named
  rendezvous mailboxes once (`rendezvous.acme = <onion>`), and the code's
  first token selects one: `acme-7-guitarist-revenge`. The alias is
  public; it carries no entropy.

Either way the rendezvous mailbox is a trust boundary of the same kind as
any mailbox (`docs/spec.md` §2.3): it can refuse service, and it sees the
PAKE messages, but it learns nothing about the code and cannot impersonate
a party to the code. The inviter's own mailbox is the natural rendezvous
when the joiner already knows it, which is the case issue #1 assumed; the
alias scheme covers the case where it does not.

### 1.4 Nameplate lifecycle

magic-wormhole's rules, which this note keeps:

- The server allocates the shortest free nameplate and the allocation
  claims it for the allocating side.
- A nameplate maps to one mailbox. Each side claims it once; a third side
  is refused (`crowded`), which both honest parties observe as a failure.
- The nameplate is released once both sides have learned the mailbox, and
  deleted after inactivity, so short nameplates recycle quickly.
- A failed PAKE (any message that does not authenticate under the derived
  key) closes the mailbox with mood `scary`, and the client gives up. The
  code is never retried; the operator makes a new one.

magic-wormhole's documented weak point is denial of service: anyone can
claim nameplates. Its author lists hashcash, per-IP limits and
rate-limiting tickets as unimplemented mitigations. Pondline's mailboxes
already require a credential to create a queue (`docs/spec.md` §3.2), so
nameplate allocation can be bound to the inviter's provisioning allowance,
and a claim can be bound to the nameplate alone; §5.3 sets the limits.

## 2. What OTP's `crypto` provides

Measured on the development machine (Erlang/OTP 29, OpenSSL 3.6.3), via
`crypto:supports/0`:

| Needed by | Primitive | In OTP | Notes |
| --- | --- | --- | --- |
| CPace | X25519 scalar multiplication by an arbitrary u-coordinate | yes | `crypto:compute_key(ecdh, U, Secret, x25519)`; the peer "public key" is any 32-byte string, which is exactly what multiplying by a hashed generator needs. OpenSSL fails the call when the result is all-zero (low-order input), which is CPace's required abort. To be confirmed by a test. |
| CPace | SHA-512 | yes | |
| CPace | Elligator 2 map to Curve25519 (RFC 9380 `map_to_curve_elligator2`) | **no** | Field arithmetic mod 2^255 - 19: one exponentiation for the Legendre symbol or square root, a few multiplications and inversions. Gleam's `Int` is arbitrary precision on the BEAM, so this is pure Gleam, roughly a hundred lines, checked against the RFC 9380 and CPace draft vectors. Not constant time; see §6. |
| CPace | Uniform encoding of the public shares (inverse Elligator 2) | not needed | CPace sends plain u-coordinates. See §7 on this correction to issue #1. |
| OQUAKE, OCAKE, CAKE | ML-KEM-1024 keygen, encaps, decaps | yes | `crypto:generate_key(mlkem1024, [])`, `crypto:encapsulate_key`, `crypto:decapsulate_key`. Implicit rejection. Keys are FIPS 203 byte encodings, so the `t` vector and the seed `rho` can be split off directly. |
| OQUAKE, OCAKE, CAKE | Kemeleon encoding of an ML-KEM encapsulation key | **no** | Decode the 12-bit coefficients, accumulate each polynomial into a base-3329 integer, add a random multiple of 3329^256 to fill 384 bytes (the draft's rejection-free variant), append `rho`. Pure Gleam over bit arrays and big integers, roughly two hundred lines. The draft has no test vectors of its own; `draft-vos-cfrg-pqpake` has vectors for the encoded keys it uses. |
| OQUAKE | HKDF-SHA-256 | yes (in `core/crypto`) | Already written over `crypto:mac`. |
| OQUAKE | Two-round Feistel over HKDF pads | trivial | XORs. |
| OCAKE, CAKE | Ideal cipher over a 1.5 KB block | **no** | OTP has no wide-block cipher. The CAKE line models the password encryption as an ideal cipher on the whole public key; instantiating that is the known weak point of the line (§3.3), and the reason CHIC, NoIC, Tempo and OQUAKE replace it with a Feistel over hash outputs. |
| nested combiner | Inverse Elligator 2 (uniform encoding of X25519 shares) | **no** | Needed only if the classical half must look random on the wire. Pure Gleam, with retry on unmappable points. |
| all | ChaCha20-Poly1305, SHA-256, HMAC, CSPRNG | yes | |

Nothing on the list needs a NIF. The two pieces of new code, the Elligator
2 map and Kemeleon, are integer arithmetic that the BEAM's bignums handle
directly; the cost is that neither runs in constant time.

## 3. Candidate constructions

Notation: `PRS` is the password (the code's words), `CI` the channel
identifier (rendezvous mailbox, nameplate), `sid` a session identifier. "DL
broken" means an attacker can compute X25519 discrete logarithms during
the pairing; "MLWE broken" means the attacker can distinguish ML-KEM
public keys from random and recover ML-KEM shared secrets.

### 3.1 CPace alone (reference)

CPace (Abdalla, Haase, Hesse; CFRG `draft-irtf-cfrg-cpace-21`, in the RFC
Editor queue since April 2026) is one round. Each side computes a
password-dependent generator `g = map_to_curve_elligator2(H(DSI || PRS ||
ZPAD || CI || sid))`, sends `Y = X25519(y, g)` (32 bytes), and derives
`ISK = H(DSI_ISK || sid || K || transcript)` from `K = X25519(y, Y_peer)`.
The two messages may be sent concurrently (the draft's symmetric
transcript, `transcript_oc`), which suits a mailbox where neither side
waits for the other. The UC proof (Abdalla, Haase, Hesse, Asiacrypt 2021)
covers adaptive corruptions without idealising the map.

Security: one online guess per run under the DH assumptions on
Curve25519. If DL is broken, the attacker computes `K` for each candidate
password from a recorded transcript and tests it against anything
encrypted under `ISK`: an offline dictionary attack, then active
impersonation. Not acceptable on its own, but it is the classical half of
everything below.

### 3.2 CPace, then ML-KEM inside it (issue #1, direction 1)

Run CPace, then send an ML-KEM-1024 encapsulation key under `ISK`, reply
with the ciphertext under `ISK`, and combine. Three messages
(`Ya`; `Yb || AEAD_ISK(ek)`; `AEAD_ISK(ct)` plus confirmation), about 32,
1 616 and 1 616 bytes.

This is the shape of the post's "classical channel, then PQ upgrade", and
of the 2026 "PAKE inside a KEM" compiler (Vazirinejad, Hao, Lyu, Liu,
eprint 2026/1832), which proves it UC-secure with post-quantum forward
secrecy of the session key. The point to see is what it does not give.
If DL is broken, the attacker recovers `ISK` for every password candidate
and checks which one decrypts the AEAD to a well-formed ML-KEM key: the
password falls offline, and an active attacker then impersonates either
side. The ML-KEM layer protects the session key from a recording, not the
password from an active quantum attacker. For a single-use code, the
password's confidentiality after the fact is worth little; its protection
during the run is the whole point. So this option is "PQ key secrecy, but
a classical PAKE", which is not the hybrid property §1.2 asks for.

### 3.3 OCAKE over Kemeleon-encoded ML-KEM (issue #1, direction 2)

CAKE and OCAKE (Beguinet, Chevalier, Pointcheval, Ricosset, Rossi, ACNS
2023, eprint 2023/470) are the EKE idea applied to a KEM: the initiator
sends its public key encrypted under the password with an ideal cipher,
the responder encapsulates to it. CAKE also encrypts the ciphertext;
OCAKE sends it in the clear and adds explicit confirmation, so it needs
only public-key uniformity. Two messages: about 1 568 and 1 600 bytes
with ML-KEM-1024.

The UC proof in the original paper covers classical adversaries only. The
tight BPR-model proof of a minor OCAKE variant (Alnahawi, Hövelmanns,
Hülsing, Ritsch, Wiesmaier, CANS 2024, eprint 2023/1368) states the KEM
properties required: ciphertext indistinguishability, anonymity, and
computational public-key uniformity. ML-KEM keys are not uniform
(coefficients mod 3329 with a biased top bit), which is what Kemeleon
(Günther, Stebila, Veitch, CCS 2024, eprint 2024/1086; CFRG
`draft-irtf-cfrg-kemeleon-02`) repairs. Kemeleon's uniformity is
computational, resting on MLWE, where Elligator's is statistical.

Three problems, in order of weight:

1. **Not hybrid.** If MLWE is broken, the attacker distinguishes decrypted
   keys from random, so the password falls offline and the session key
   with it. Nothing classical is in the way.
2. **The ideal cipher.** The proof needs a random permutation on the whole
   1.5 KB key. No standard primitive is that. CHIC (Arriaga, Barbosa,
   Jarecki, Skrobot, Asiacrypt 2024, eprint 2024/308) and NoIC (Arriaga,
   Barbosa, Jarecki, eprint 2025/231) replace it with a two-round Feistel
   over hash outputs and split the key so only the secret-dependent part
   is masked; those are the designs OQUAKE inherits.
3. **Timing.** Once the key is password-encrypted it is secret, and
   ML-KEM's variable-time `SampleNTT` expansion of the seed leaks through
   timing (Tempo: Arriaga, Barbosa, Jarecki, TCHES 2026, eprint 2025/1399).
   The fix is to send the seed `rho` in the clear, which OQUAKE does.

### 3.4 Nested combiner: CAKE over OEINC[DHKEM + Elligator 2, ML-Kemeleon] (issue #1, direction 3)

OEINC, the outer-encrypts-inner nested combiner, and the Drivel protocol
built on it are from the follow-up paper, not from the CCS 2024 one:
Günther, Rosenberg, Stebila, Veitch, "Hybrid Obfuscated Key Exchange and
KEMs", CRYPTO 2025, eprint 2025/408 (also the NIST PQC 2025 slides). The
outer KEM is DHKEM with Elligator 2 encoding, the inner is ML-KEM with
Kemeleon; the outer shared secret encrypts the inner ciphertext and both
secrets feed one PRF. The combined OKEM has hybrid IND-CCA security and
hybrid ciphertext obfuscation, and the paper names "the first hybrid PAKE
secure against adaptive corruptions in the UC model" as an application:
CAKE instantiated with the combined OKEM. Two messages, about 1 600 bytes
each.

What it does not have is hybrid public-key uniformity. The slides say so
directly ("We don't get hybrid public key uniformity! (Likely
impossible)"), and the reason is structural: the password-encrypted first
message is `IC_PRS(pk_outer || pk_inner)`, and an attacker who can
distinguish `pk_inner` candidates from random, which an MLWE break
allows, tests passwords offline on that half alone. The CRYPTO 2025 paper
gives unconditional public-key obfuscation techniques for LWE-based OKEMs
(the slides' instantiation is a statistically uniform FrodoKEM variant),
which OTP does not provide. With ML-KEM as the inner KEM, this option's
password protection rests on MLWE alone, like §3.3, while its key secrecy
is hybrid. It also needs the ideal cipher of §3.3 and inverse Elligator 2,
and the slides put its communication at about 7.5 times a three-round
PAKE's. It is the right construction when the transcript must look random
from the first byte, which is BIP 324's requirement and not Pondline's
(§6).

### 3.5 CPaceOQUAKE: sequential composition (the recommendation)

Hesse and Rosenberg ("PAKE Combiners and Efficient Post-Quantum
Instantiations", Eurocrypt 2025, eprint 2024/1621) prove two generic PAKE
combiners in the UC model and observe that a sequential one, where the
second PAKE runs on a password derived from the first PAKE's key, yields a
hybrid PAKE from CPace and a KEM-based PAKE. Vos, Jarecki, Wood, Yun,
Myers and Sierra ("A Hybrid Asymmetric Password-Authenticated Key Exchange
in the Random Oracle Model", eprint 2025/1343) build exactly that from
CPace and OQUAKE, a KEM-based PAKE in the CHIC/NoIC/Tempo line, and the
CFRG draft `draft-vos-cfrg-pqpake-03` (Vos, Jarecki, Wood, October 2026)
specifies it with test vectors. The draft's primary subject is the
asymmetric `CPaceOQUAKE+` for client-server logins; the symmetric
`CPaceOQUAKE` it is built from is the balanced PAKE Pondline needs.

The construction:

1. CPace runs first and yields `SK1` and a transcript hash `th1`.
2. OQUAKE runs on `effective_PRS = KDF(PRS, th1, SK1)` instead of the
   password. The responder generates an ML-KEM-1024 key, Kemeleon-encodes
   it (the rejection-free variant, for constant time), splits off the
   32-byte seed `rho` (sent in the clear, which is the Tempo fix), and
   masks the secret-dependent part `ut` with HKDF pads in a two-round
   Feistel keyed by `effective_PRS`: `T = ut XOR pad(effective_PRS, rho,
   r)`, `s = r XOR pad(effective_PRS, rho, T)`. The initiator unmasks,
   encapsulates, and returns the ciphertext with a confirmation tag `h`.
   A failed decapsulation or confirmation yields a random key, never a
   distinguishable error.
3. `session_key = HKDF(key2, DST || "CPaceOQUAKE" || th2 || key1)`.

Why the order matters, in the draft's own argument: CPace hides the
password unconditionally against a passive observer, and its key is never
checked on its own, so a DL break reveals nothing from the CPace messages
by itself; the attacker must still make one online guess against OQUAKE,
whose password is now `effective_PRS`. If instead MLWE is broken, OQUAKE
falls, but the attacker is then holding a transcript whose password-hiding
rests on CPace. The draft states the resulting property as needing to
"break both a classical and a post-quantum hard problem simultaneously"
to recover the password. OQUAKE alone realises only a relaxed UC PAKE
functionality (it exposes password equality to a passive observer, and a
simulator cannot extract the password against quantum random-oracle
access), which is why it is only ever run second.

Three messages. From the draft's Appendix D (octets per message, X25519
with ML-BUA-sKEM-1024, excluding transport framing): `msg1` 34, `msg2`
1 694, `msg3` 1 600; total 3 328 bytes, one and a half round trips.

### 3.6 Comparison

| | 3.1 CPace | 3.2 CPace then KEM | 3.3 OCAKE/Kemeleon | 3.4 CAKE/OEINC | 3.5 CPaceOQUAKE |
| --- | --- | --- | --- | --- | --- |
| Password held to one online guess if DL broken | no | no | yes | no (pk half) | yes |
| Password held to one online guess if MLWE broken | yes | yes | no | no | yes |
| Session key secret from a recording, later quantum | no | yes | yes | yes | yes |
| Messages (round trips) | 2 (1) | 3 (1.5) | 2 (1) | 2 (1) | 3 (1.5) |
| Bytes, approximate | 64 | 3 300 | 3 200 | 3 300 | 3 328 |
| Proof | UC, adaptive | UC (2026/1832, for J-PAKE) | BPR (classical); UC classical | UC, adaptive | UC, ROM |
| Standards status | CFRG, RFC Editor queue | none | none | none | CFRG individual draft, with vectors |
| New code beyond OTP | Elligator 2 map | Elligator 2 map | Kemeleon, ideal cipher | Kemeleon, ideal cipher, inverse Elligator 2 | Elligator 2 map, Kemeleon |
| Transcript uniform to the mailbox | no | no | yes | yes | no |
| Outside review needed | low | low | high | high | medium |

The "ideal cipher" rows are the decisive implementation risk for the CAKE
line: there is no agreed instantiation, and the papers that fix it
(CHIC, NoIC, Tempo) converge on the Feistel that OQUAKE already uses.

## 4. Security argument for the recommendation, in Pondline's terms

- **One guess per code.** An attacker who claims a nameplate and runs the
  protocol learns whether one `PRS` guess was right. The nameplate burns
  on the first failure (§5.3), so one guess per code, with success
  probability 2^-24 for three words. A thousand attempts against a
  thousand different codes would still succeed about once in sixteen
  thousand, and each attempt is visible to the honest inviter as a burned
  code.
- **Hybrid.** Per §3.5, offline recovery of the code needs both DL and
  MLWE broken during the attack window; active impersonation needs the
  same. This matches the profile's rule that every authentication step
  needs a classical and a post-quantum proof, read for a password.
- **Hand-off.** The derived `k` encrypts the full invitation file (bundle,
  route, deadline, description) with ChaCha20-Poly1305 under a key
  expanded from `session_key` with a Pondline label. The invitation is
  then decoded exactly as a file would be: identity binding and both
  prekey signatures verified, PQXDH run, transcript signed, ratchet
  started. The PAKE replaces the trusted channel the file travels over,
  nothing else. In particular the inviter's identity is still
  authenticated by its hybrid prekey signatures and ML-KEM prekey, not by
  the code.
- **The rendezvous mailbox.** It sees three random-looking messages and an
  AEAD blob. It can deny service and burn codes; it cannot test the code
  (one online guess, like anyone) and cannot alter the invitation (AEAD
  under `k`). A malicious mailbox that forwards the honest parties'
  messages to a third claimant is refused by the two-sides rule, and a
  mailbox that substitutes its own messages is an active attacker with one
  guess.
- **Deniability** is unaffected: PAKE transcripts are simulatable by
  either party, and what follows is the existing handshake, whose
  properties `docs/research/initiator-deniability.md` treats.

## 5. Concrete flow over the mailbox

### 5.1 Objects

```text
Nameplate        short decimal string allocated by the rendezvous mailbox
RendezvousPair   two directional queues, I->J and J->I, with append and read
                 capabilities for each side, created with the nameplate
Code             [alias "-"] nameplate "-" word1 "-" word2 "-" word3
PRS              word1 "-" word2 "-" word3              (24 bits)
CI               "Pondline_Rendezvous_v1" || rendezvous_onion || nameplate
sid              16 random bytes chosen by the mailbox at claim time and
                 given to both sides; freshness is all CPace needs of it
```

### 5.2 Steps

```text
Inviter I                       Rendezvous mailbox M                 Joiner J
  AllocateNameplate(cap) ------>  allocates N, creates pair,
                                  claims N for I, returns N, sid,
                                  I's capabilities, N's lifetime
  shows code N-w1-w2-w3 to the operator; the operator reads it to J's operator
                                                        <------ ClaimNameplate(N)
                                  second claim: returns the pair,
                                  sid, J's capabilities; marks N as
                                  fully claimed. A third claim is
                                  refused and burns N.
  msg1: Ya (CPace, 32 + framing) ---------------------------------------> J
  J <--------------------------- msg2: Yb || s || T || rho (CPace + OQUAKE init)
  msg3: ct || h (OQUAKE response) --------------------------------------> J
  both derive k = session_key; both verify (I through h, J through msg4)
  msg4: AEAD_k(invitation file), padded to 16 KiB --------------------> J
  J decodes the invitation as from a file, then appends its PQXDH
  InitialMessage to the inviter's queue named in the invitation: unchanged.
  I releases N on sending msg4; J releases it on decoding msg4; M deletes
  the pair when both have released or the lifetime ends.
```

The inviter is the CPace initiator because it is online first, and the
joiner is the OQUAKE responder because the draft has the second speaker
generate the KEM key, which keeps the three-message shape. The messages
are appended to the pair's queues as ordinary envelopes with a reserved
rendezvous tag, fetched with the existing long-poll, so no new transport
is involved; the only new mailbox operations are `AllocateNameplate`,
`ClaimNameplate` and `ReleaseNameplate`.

`msg4` is where the derived key meets the existing pairing. It carries the
same bytes the file would, so `core/invitation` decodes it unchanged, and
the acceptance deadline inside still bounds how long the joiner may take
to send its `InitialMessage`. Explicit key confirmation is `h` in one
direction and the AEAD tag of `msg4` in the other.

### 5.3 Burn-after-one-failure and limits

| Rule | Value | Why |
| --- | --- | --- |
| Claims per nameplate | 2, then refused | magic-wormhole's `crowded`; a third claimant means a guesser or a relay |
| Failures per nameplate | 1 | A bad `h` or a bad `msg4` tag burns the nameplate at both daemons and at the mailbox; the operator makes a new code |
| Nameplate lifetime | 10 minutes from allocation, configurable | Long enough to read a code over the phone; short enough that nameplate space recycles |
| Allocation rate | per inviter credential, from its provisioning allowance (spec §3.2); proposal 10 per hour | Nameplate allocation is the one unauthenticated-looking operation; it is not, since allocation needs the inviter's capability |
| Claim rate | per nameplate only: one second claim | A claim without a valid nameplate is refused; the mailbox cannot rate-limit by source inside Tor and does not try |
| Nameplate space | smallest free integer, as magic-wormhole does | Short codes; collisions are impossible by construction |
| Code entropy | 3 words, 24 bits, from a 256-word even/odd list | 2^-24 per attempt against a burned-on-failure code; 2 words (16 bits) is magic-wormhole's default and is an option for low-risk settings, 4 words for high-risk |

A burned code is a visible event. The inviter's daemon reports it to the
operator ("someone guessed at code 7 and failed"), which is the signal
magic-wormhole relies on and the one a per-pairing budget should surface.

## 6. Implementation risk

- **Timing side channels.** The Elligator 2 map input is derived from the
  password, and the CPace draft says the map "SHALL execute in constant
  time". Pure Gleam big-integer arithmetic is not. The Kemeleon draft and
  the OQUAKE draft say the same of the big-integer encoding and of
  rejection sampling. The mitigations in order of preference: use the
  rejection-free Kemeleon variant (no data-dependent loop); accept that the
  attacker's only timing vantage is across Tor, where circuit jitter is
  tens of milliseconds against field operations of microseconds, and that
  one guess per code bounds what a timing oracle can confirm; and record
  this as the one place a small native helper (constant-time field
  arithmetic) might later be justified under the "custom FFI is a last
  resort" rule. The mailbox itself is not a timing vantage either, since it
  sees only message arrival.
- **Test vectors.** CPace's draft has vectors for X25519 (`CPace255`),
  including low-order and non-canonical inputs that must abort. The OQUAKE
  draft has vectors for `ML-BUA-sKEM-1024`, OQUAKE, and one for
  `cpaceoquake-x25519-mlbuaskem1024`. The Kemeleon draft has none, so the
  OQUAKE vectors are what pin the encoding. The draft's own numbers for
  the encoded key (`Npk` 1 596, `T` 1 564) exceed the Kemeleon draft's
  1 568 for ML-KEM-1024, because the OQUAKE draft pads for a 2^-128
  per-key statistical distance; an implementation must follow one document
  and say which.
- **Draft stability.** `draft-irtf-cfrg-cpace` is past IESG review and
  waiting on the RFC Editor. `draft-vos-cfrg-pqpake` is an individual
  submission at -03, not adopted by CFRG, with a stated open issue on
  identity requirements, and its Section 12 says the design has been
  analysed by at least three groups and that the compiler techniques are
  "recent and still under development". An implementation should pin the
  draft version in its domain-separation string and expect to re-derive
  vectors.
- **No uniformity on the wire.** CPace's shares are u-coordinates, about
  half of all 32-byte strings, so the rendezvous mailbox can tell a PAKE
  message from a padded ciphertext with a few samples. Inside Tor, to a
  mailbox that already knows it is serving a rendezvous queue, this
  reveals nothing it does not have. Uniform shares (inverse Elligator 2,
  as obfs4 does) can be added later without changing the PAKE.
- **Effort.** Elligator 2 map and CPace: about 300 lines of Gleam plus
  vectors. Kemeleon and OQUAKE: about 400. The combiner, the invitation
  hand-off and the rendezvous state machine in the daemon: comparable to
  the ticket work. Mailbox nameplate operations and their DST coverage:
  the larger half.

## 7. Corrections to the citations in issue #1 and the post

| As written | Verified | Correction |
| --- | --- | --- |
| Günther, Stebila, Veitch, "Obfuscated Key Exchange" (Kemeleon, OEINC, Drivel), eprint 2024/1086 | Title, authors and number correct; CCS 2024 | Kemeleon and the `pq-obfs` protocol are in 2024/1086. OEINC and Drivel are in the follow-up: Günther, Rosenberg, Stebila, Veitch, "Hybrid Obfuscated Key Exchange and KEMs", CRYPTO 2025, eprint 2025/408. The post's reference [8] has the same conflation. |
| CPace, CFRG draft (`draft-irtf-cfrg-cpace`) | Correct | Now at -21 (April 2026), past IESG review, in the RFC Editor queue; cite it as such. |
| Beguinet et al., "GeT a CAKE", eprint 2023/470 | Correct; five authors (Beguinet, Chevalier, Pointcheval, Ricosset, Rossi), ACNS 2023 | None. The UC proof there is classical; the post-quantum-leaning proof of OCAKE is Alnahawi et al., CANS 2024, eprint 2023/1368. |
| "CPace over X25519 (Elligator2-encoded points, so the transcript looks random)" | Partly | CPace uses Elligator 2 only to derive the generator from the password (RFC 9380 `map_to_curve`). The shares on the wire are plain u-coordinates and are not uniform; uniform shares need the inverse map, which CPace does not specify. |
| Kemeleon: "key generation is ~3x slower" (post) | Not verifiable from the primary sources | Neither the paper's abstract, the slides nor the draft give a keygen factor. The rejection variant for ML-KEM-1024 succeeds with probability 0.62, so expected keygens are about 1.6; the rejection-free variant never rejects. |
| Kemeleon: "keys end up a bit smaller, ciphertexts larger" (post) | Correct for the rejection variant | ML-KEM-1024: key 1 530 (0.62 success) or 1 568 (rejection-free); ciphertext 1 658 (0.57) or 1 920 (rejection-free), against 1 568 and 1 568 raw. |
| magic-wormhole: nameplate, burn-after-failure | Correct | The code's default entropy is 16 bits (two words); the failure mood is `scary`, the third-claimant refusal is `crowded`. |

## 8. Open questions and what needs outside review

1. **Resting on an individual draft.** `draft-vos-cfrg-pqpake` is not
   adopted by CFRG. The alternative is to compose CPace with a KEM-based
   PAKE by the Hesse-Rosenberg sequential combiner directly, with the
   same shape and a Eurocrypt proof but no vectors. The recommendation
   prefers the draft for its vectors and reference implementation, and
   should be revisited if the draft stalls or changes its KEM wrapping.
2. **The rendezvous mailbox for self-hosters.** Whether the alias scheme
   of §1.3 is acceptable UX, or whether every daemon should ship with the
   managed rendezvous and self-hosters accept that one hop through it.
3. **Code length as policy.** Three words by default, with the per-pairing
   budget and operator policy able to require four, or allow two.
4. **Whether `k` should also carry the ticket's `K`** so that the PAKE
   flow and the ticket flow converge on one encrypted-invitation object
   at the mailbox, with the PAKE delivering `K` rather than the file.
   Smaller `msg4` (48 bytes against 16 KiB), one storage path, but the
   invitation then lives at the inviter's mailbox rather than at the
   rendezvous.
5. **Outside review** of: the claim that the symmetric `CPaceOQUAKE` keeps
   the draft's hybrid argument when run over a store-and-forward queue
   rather than a connection (the draft assumes a live client-server
   session and recommends but does not require `sid`); the choice of `CI`
   and `sid`; and the timing argument of §6 for a non-constant-time map in
   a one-guess setting. A cryptographer who has reviewed CPace or OQUAKE
   should read the final flow before it is built.

## References

Primary sources, each checked on 2026-11-01 for title, authors, venue and
the claim cited.

- Abdalla, Haase, Hesse. "CPace, a balanced composable PAKE".
  `draft-irtf-cfrg-cpace-21`, April 2026, IRTF stream, sent to the RFC
  Editor. <https://datatracker.ietf.org/doc/draft-irtf-cfrg-cpace/>
- Abdalla, Haase, Hesse. "Security Analysis of CPace". Asiacrypt 2021.
  <https://eprint.iacr.org/2021/114>
- Alnahawi, Hövelmanns, Hülsing, Ritsch, Wiesmaier. "Towards post-quantum
  secure PAKE: A tight security proof for OCAKE in the BPR model". CANS
  2024. <https://eprint.iacr.org/2023/1368>
- Arriaga, Barbosa, Jarecki, Skrobot. "C'est très CHIC: A compact
  password-authenticated key exchange from lattice-based KEM". Asiacrypt
  2024. <https://eprint.iacr.org/2024/308>
- Arriaga, Barbosa, Jarecki. "NoIC: PAKE from KEM without Ideal Ciphers".
  <https://eprint.iacr.org/2025/231>
- Arriaga, Barbosa, Jarecki. "Tempo: An ML-KEM to PAKE Compiler Resilient
  to Timing Attacks". TCHES 2026. <https://eprint.iacr.org/2025/1399>
- Beguinet, Chevalier, Pointcheval, Ricosset, Rossi. "GeT a CAKE: Generic
  Transformations from Key Encapsulation Mechanisms to Password
  Authenticated Key Exchanges". ACNS 2023.
  <https://eprint.iacr.org/2023/470>
- Bellare, Pointcheval, Rogaway. "Authenticated Key Exchange Secure
  Against Dictionary Attacks". Eurocrypt 2000.
  <https://eprint.iacr.org/2000/014>
- Bellovin, Merritt. "Encrypted Key Exchange: Password-Based Protocols
  Secure Against Dictionary Attacks". IEEE S&P 1992.
  <https://www.cs.columbia.edu/~smb/papers/neke.pdf>
- Bernstein, Hamburg, Krasnova, Lange. "Elligator: Elliptic-curve points
  indistinguishable from uniform random strings". CCS 2013.
  <https://eprint.iacr.org/2013/325>
- Faz-Hernandez, Scott, Sullivan, Wahby, Wood. "Hashing to Elliptic
  Curves". RFC 9380, August 2023.
  <https://www.rfc-editor.org/rfc/rfc9380>
- Giacon, Heuer, Poettering. "KEM Combiners". PKC 2018.
  <https://eprint.iacr.org/2018/024>
- Günther, Stebila, Veitch. "Obfuscated Key Exchange". CCS 2024.
  <https://eprint.iacr.org/2024/1086>
- Günther, Stebila, Veitch. "Kemeleon Encodings".
  `draft-irtf-cfrg-kemeleon-02`, July 2026.
  <https://datatracker.ietf.org/doc/draft-irtf-cfrg-kemeleon/>
- Günther, Rosenberg, Stebila, Veitch. "Hybrid Obfuscated Key Exchange and
  KEMs". CRYPTO 2025. <https://eprint.iacr.org/2025/408>. Slides:
  "Kemeleon: Elligator-like Obfuscation for ML-KEM", NIST PQC 2025.
  <https://csrc.nist.gov/csrc/media/Presentations/2025/kemeleon/images-media/kemeleon.pdf>
- Hesse, Rosenberg. "PAKE Combiners and Efficient Post-Quantum
  Instantiations". Eurocrypt 2025. <https://eprint.iacr.org/2024/1621>
- Ladd. "SPAKE2, a Password-Authenticated Key Exchange". RFC 9382,
  September 2023. <https://www.rfc-editor.org/rfc/rfc9382>
- magic-wormhole. "Mailbox Server Protocol", "Client-to-Client Protocol",
  "Known Vulnerabilities". Repository documentation, read from the tree on
  2026-11-01.
  <https://github.com/magic-wormhole/magic-wormhole/tree/master/docs>
- Osuntokun. "Post-quantum BIP 324" (bitcoin-dev). Local copy read; the
  OEINC and Drivel sketches there are from eprint 2025/408 per the
  correction in §7.
- Vazirinejad, Hao, Lyu, Liu. "Universally Composable Hybrid PAKE Secure
  Against Harvest-Now-Decrypt-Later Attacks".
  <https://eprint.iacr.org/2026/1832>
- Vos, Jarecki, Wood, Yun, Myers, Sierra. "A Hybrid Asymmetric
  Password-Authenticated Key Exchange in the Random Oracle Model".
  <https://eprint.iacr.org/2025/1343>
- Vos, Jarecki, Wood. "Hybrid Post-Quantum Password Authenticated Key
  Exchange". `draft-vos-cfrg-pqpake-03`, October 2026, individual
  submission. <https://datatracker.ietf.org/doc/draft-vos-cfrg-pqpake/>
