# Initiator deniability under hybrid authentication

**Status**: research note · **Date**: 2026-11-01 · **Tracks**: issue #2 ·
**Profile**: `docs/crypto-profile-v1.md` §4, §8; `docs/adr/005-hybrid-authentication.md`

`CryptoProfileV1` has the joiner sign the PQXDH transcript with Ed25519
and ML-DSA-65. That is what makes the joiner's authentication
post-quantum, and it is also a transferable proof that the joiner began a
conversation with the inviter, which PQXDH's implicit authentication did
not produce. Issue #2 records that the trade was accepted for now. This
note says precisely what was traded, in whose hands the proof ends up, when
it would matter for agents whose operators keep plaintext audit logs, what
the literature offers to get it back, and what a `CryptoProfileV2` would
change if the owner decides it should. The recommendation is at the end;
the short form is "not now, but decide before the freeze, because the
cheapest V2 is a small one".

## 1. What the profile signs, and what each signature proves

Every signature in v1 is hybrid, and every check needs both halves, so
"proof" below means a proof that stands against a quantum judge as well
as a classical one.

| Artefact | Signer | Over | Who holds it | What a judge learns from it | Transferable |
| --- | --- | --- | --- | --- | --- |
| Identity binding | each party, over its own keys | `"Pondline_IdentityBinding_v1"`, its three public keys | the peer; for the joiner, also the inviter's mailbox (the `InitialMessage` fixed part is in the clear, profile §7) | that someone holding these keys created this identity. Names no counterparty. | yes, but it proves nothing about participation |
| Prekey signatures (`spk`, `pqspk`) | inviter | each prekey, labelled | the joiner (inside the invitation) | that `IK_resp` issued a bundle, which is to say an invitation. Not that anyone redeemed it. | yes |
| Transcript signature | joiner | `version`, both full public identities, `bundle_commitment`, `EK`, `CT`, the first ratchet message | the inviter; the inviter's mailbox (in the clear) | that the holder of `IK_init`'s two signing keys began a PQXDH handshake with `IK_resp`'s bundle and produced this exact first ciphertext | yes |
| Every later message | neither | AEAD under ratchet keys | both | nothing a judge can check: either party could have produced it | no |

Two consequences of the transcript signature are easy to miss.

**The first message's contents are bound, not only its existence.** The
signature covers the ratchet message, whose plaintext is the `Hello`
(invitation identifier, the joiner's reply route, its self-description).
The inviter can hand a judge the message key with the ciphertext; the
judge verifies the AEAD tag and reads the plaintext. ChaCha20-Poly1305 is
not key-committing, but with the ciphertext and tag fixed by the signature
the inviter cannot find a second key that opens them, so the joiner cannot
deny what its `Hello` said, including the onion address of its reply
queue.

**The mailbox is a holder.** The transcript signature travels in the clear
in the `InitialMessage`, so the inviter's mailbox, and anyone who read
that queue, holds it too. It cannot verify it without
`PublicIdentity(IK_resp)`, which the transcript includes but the wire
message does not; the bundle is in the invitation file and, in the ticket
design, encrypted at the mailbox under `K`. The proof is latent at the
mailbox: a leak of the invitation or of `K` activates it. Signal's server
is in the same position with PQXDH's signed prekeys; the difference is
that Signal's initiator does not sign.

## 2. Offline and online deniability

The vocabulary, so the claims below are precise:

- **Offline deniability** (Di Raimondo, Gennaro, Krawczyk, CCS 2006; the
  notion Signal's specifications use): a judge who receives the transcript
  and the parties' secret keys after the fact cannot tell a real
  transcript from one a single party simulated with only its own secrets.
  Vatandas, Gennaro, Ithurburn and Krawczyk (ACNS 2020) prove it for X3DH
  under knowledge-of-exponent style assumptions; Signal's PQXDH
  specification §4.4 claims "1-out-of-2 deniability for semi-honest
  parties against a big brother judge", with the responder's half resting
  on a plaintext-awareness assumption for the KEM that Kyber does not meet
  as-is.
- **Online deniability** (Dodis, Katz, Smith, Walfish, TCC 2009): the
  judge may collude with one party during the run. It is impossible in
  the PKI model with adaptive corruptions, even with secure erasure.
  Signal does not claim it; PQXDH §4.4 says that a party collaborating
  with a third party during the protocol "will be able to provide proof".
  Pondline cannot have it either, and nothing below tries: an inviter who
  lets a judge choose `SPK` has handed over a proof whatever the joiner
  signs.

Two recent analyses sharpen what PQXDH itself gives. Fiedler and Janson
(PoPETs 2024, eprint 2024/741) show PQXDH's deniability is weaker than
X3DH's because of the signature on the KEM prekey and the reliance on
plaintext awareness, and that initiator and responder get different
guarantees; their analysis is classical. Katsumata, Niot, Tucker and
Wiggers (USENIX Security 2025, eprint 2025/1090) find settings where
PQXDH is and is not deniable against a quantum judge who assesses
classical users after the fact ("harvest now, judge later"), and show
undeniability against a malicious receiver when the distinguisher is
quantum. Both confirm the direction ADR-005 took away: PQXDH's initiator
was offline-deniable in the classical setting, and signing the transcript
removes that.

What v1 gives up is therefore exactly: the joiner's offline deniability
of having started the handshake and of the contents of its first message.
The inviter keeps its offline deniability of participation (its only
signatures are on prekeys, which prove an invitation and not a
conversation); both keep deniability of everything after the first
message; and neither ever had online deniability.

## 3. Who can prove what to whom

| Prover | Evidence | Claim a judge accepts | What the judge still needs |
| --- | --- | --- | --- |
| Inviter | transcript signature, bundle, message key | the holder of `IK_init` started this handshake with `IK_resp` and sent this `Hello` | a link from `IK_init` to a person or operator. Identities are pairwise and never published (spec §3.1), so the link comes only from the joiner's own stored state (seizure, discovery), the joiner's own audit log naming its identity, or an admission |
| Inviter's mailbox, or a reader of the queue | transcript signature | as above, once it obtains `IK_resp`'s public identity | the invitation (file or `K`) and the `IK_init` link |
| Joiner | prekey signatures, invitation | `IK_resp` issued this invitation | a link from `IK_resp` to the inviter's operator; the description string in the invitation is unverified and is the obvious one |
| Either | later ciphertexts, keys | nothing: forgeable by the other party | |
| Inviter, without the signature (PQXDH as published) | transcript | nothing: the inviter can compute `DH1` from `SPK`'s secret and can invent `IK_init` outright | |

The pairwise identity is the real mitigation ADR-005 relied on, and it
holds: the proof names a key that exists nowhere else. The weakness is
that the link the judge needs is exactly what an audit-logging operator
produces for itself.

## 4. The threat model: agents whose operators keep audit logs

Pondline's parties are agents. The design review's ruling (2026-10-31)
that pairing grants a bounded message budget or an operator-readable
plaintext audit log means each operator already holds plaintext of
everything its agent said and heard. The question deniability answers is
not "can the operator know" but "can the operator, or someone who takes
the operator's state, convince a third party who does not trust the
operator's word".

| Situation | Without the signature | With the signature (v1) | Does it matter |
| --- | --- | --- | --- |
| Commercial dispute between two operators (the vendor and customer of the reference use case, spec §1.3) | each side's log is its own claim; a judge weighs credibility | the inviter's log of the first message is proof, if the joiner's identity is linked (its own log does that) | yes, but in both directions: an operator may want its counterpart bound, and may want itself not to be |
| Compelled disclosure or seizure of the inviter's daemon | a transcript the inviter could have fabricated | a proof that some key holder contacted this inviter; with the joiner's state as well, a proof of who | yes; this is the classical argument for deniable messaging, and it applies to agents' operators as it does to people |
| A hostile mailbox operator | nothing beyond metadata | a latent proof, activated by a leak of the invitation or `K` | yes; it widens who can end up holding the proof |
| Prompt-injection or a compromised agent | the agent's operator is accountable either way under its budget | a cryptographic record that this identity initiated, which may be wanted as evidence against a rogue agent | cuts the other way: non-repudiation is a feature when the agent, not the operator, is the suspect |
| A later public-identity or directory mode (deferred, design intent §4) | | the proof then names a long-lived key | the pairwise mitigation disappears; this is the trigger that would make V2 urgent |

So the honest summary is that deniability for agents is a policy
question, not a pure security property: some deployments want the joiner
bound and some want it free. v1 chose bound, for every relationship,
without a knob.

## 5. What the signature is actually doing

Before choosing a fix it is worth stating what the signature
authenticates in Pondline's specialisation, since the answer narrows the
options. The joiner's identity is fresh and pairwise: the inviter sees
`IK_init` for the first time in the `InitialMessage` and has no prior
expectation of it. The invitation is a bearer credential (spec §4.2) and
the tree has no join secret: `core/invitation` says so in its header, and
the bundle inside the invitation is what a joiner must know to produce a
`CT` that decapsulates and a `DH3` that matches. Possession of the
invitation is the authenticator of "invited party", and it is already
post-quantum: a quantum attacker without the invitation cannot produce a
first message the inviter accepts, because it cannot encapsulate to a
`PQSPK` it has never seen.

What the hybrid transcript signature adds over that is proof of
possession of `IK_init`'s signing keys at the moment of the handshake. In
PQXDH that is `DH1`'s job, and `DH1` is X25519. The case where the
difference is live: an attacker who both holds the invitation (a bearer,
so otherwise a legitimate claimant) and watches the honest joiner's
`InitialMessage` on the mailbox, and has a quantum computer during the
pairing. It can then copy the honest joiner's `PublicIdentity(IK_init)`,
compute `IK_init`'s X25519 secret, and run the handshake as the identity
whose fingerprint the two operators will compare out of band (spec §4.4).
The signature stops this; `DH1` does not. Nothing else in the handshake
depends on the signature for post-quantum security. The joiner's signing
keys are used in exactly two places in the tree, the identity binding
(`core/crypto/identity`) and the transcript (`core/crypto/pqxdh`), and
never after the handshake.

That is a narrow residual: invitation theft, a mailbox vantage, an active
quantum attacker, and an operator pair who verify fingerprints. The
options below are judged against it.

## 6. Candidate fixes

| Option | Mechanism | Flights | Bytes | Deniability | PQ auth of joiner | Primitives | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| A. Join-secret MAC | the invitation carries a 32-byte `join_secret` (spec §4.2 already lists one; the tree dropped it); the joiner replaces the transcript signature with `HMAC(join_secret, transcript)` | none added | +32 in the invitation, 32 on the wire instead of 3 373 | yes: the inviter knows `join_secret` and can forge the MAC, so it proves only "someone with the invitation" | invitation possession, PQ; identity possession rests on `DH1` (classical) | HMAC, in OTP | nothing to standardise; needs review of §5's argument |
| B. KEM-based implicit authentication | the joiner's identity gains a static ML-KEM-1024 key, covered by the binding; the inviter encapsulates to it in `Accept`; the secret is mixed into the root key; the joiner proves possession by decrypting | none added to pairing's existing `Hello`, `Accept` exchange; the inviter is assured one message later than today | +1 568 identity, +1 568 in `Accept`, one encaps and decaps | yes: both directions implicit, as in PQXDH's responder side | yes, and closes §5's residual: an impostor cannot read anything after `Accept`, and the relationship never activates | ML-KEM, in OTP | the standard move (KEMTLS-PDK's client authentication); needs an ADR for the identity layout |
| A + B together | A authenticates the invitation, B the identity | as B | as A plus B | yes | yes | all in OTP | the V2 shape §8 recommends |
| C. Split-KEM X3DH (K-Waay; Sparrow) | a split KEM gives DH-like implicit authentication without an extra flight | none | K-Waay with FrodoKEX+: 21.3 KB prekeys per the paper's Table 1; Sparrow cuts communication by a factor 5.1 | yes, by the papers' peer-deniability notions | yes | plain or module LWE schemes with no OTP implementation; custom lattice code | research; against the "no new primitives" rule |
| D. Ring signatures (RingXKEM; Gandalf) | the joiner signs with a ring of `{IK_init, IK_resp}`, so the inviter could have signed | none | Gandalf: 1 236 bytes for a ring of two, Falcon-based | yes (anonymity, or Katsumata et al.'s weaker "deniability for ring signatures") | yes | Falcon-family lattice code; not in OTP | research; same objection as C |
| E. Designated-verifier signatures | a signature only the inviter can check and could have forged | none | depends on the DVS | yes | yes | no standardised PQ DVS; Brendel et al. build them from ring signatures | research; same objection as C |
| F. OTR-style key disclosure | after `Accept`, the joiner sends its signing secrets to the inviter, so the inviter could have made the signature thereafter | none | +4 064 once | weak: forgeability after the fact, not simulatability; a judge who trusts the inviter's timeline is unmoved | unchanged | none | cheap, but not a real fix |

On C, D and E: each would be a reviewed-primitive problem the project has
ruled out for v1 (ADR-002: OTP primitives, protocols in Gleam, no custom
crypto), and none has a standard or an OTP binding. They are the right
pointers if the question returns in a public-identity mode where A's
bearer argument no longer applies. On the issue's citation: K-Waay
(Collins, Huguenin-Dumittan, Nguyen, Rolin, Vaudenay, USENIX Security
2024, eprint 2024/120) is as described, and its split KEM is the one
Brendel, Fischlin, Günther, Janson and Stebila introduced (SAC 2020) with
extra unforgeability and deniability notions the authors had to add. The
2025 follow-up (Niot, ASIA CCS 2025, eprint 2025/853) is the current
state of that line.

## 7. Costs

| | V1 today | A | B | A + B |
| --- | --- | --- | --- | --- |
| `InitialMessage` fixed part | 10 395 | 7 054 | 11 963 (identity grows) | 8 622 |
| Padded initial frame | 16 KiB | 16 KiB (the bundle still dominates the invitation; the frame bucket does not move) | 16 KiB | 16 KiB |
| `PublicIdentity` | 5 389 | 5 389 | 6 957 | 6 957 |
| Invitation | about 14 550 | about 14 582 | about 14 550 | about 14 582 |
| `Accept` | AEAD only | AEAD only | +1 568 | +1 568 |
| Handshake compute | 2 signatures, 2 verifications | 1 HMAC | +1 encaps, +1 decaps | both |
| Inviter assured of the joiner's identity | on `Hello` | on `Hello` (classically), invitation possession PQ | on the joiner's first message after `Accept` | as B |
| Deniability of the first message | no | yes | yes | yes |
| Residual of §5 (bearer plus quantum plus fingerprint check) | closed | open | closed | closed |
| Change class | | profile version, invitation format | profile version, identity layout, `Accept` layout | both |

B's "assured one message later" costs nothing in Pondline's flow: the
inviter already withholds the relationship until local approval and sends
`Accept` before anything else, and the joiner already waits for `Accept`
before presenting the relationship as active (spec §4.3 step 5). The
inviter's first application message would be encrypted under keys the
impostor cannot derive, so what B delays is the inviter's certainty, not
its safety.

## 8. Recommendation

Not now, with the reason stated as what V2 would be rather than as a
deferral.

1. **Keep V1 for the first release unless the owner wants the knob.** The
   loss is bounded: one message per relationship, naming a pairwise key,
   with online deniability never on the table. The operators Pondline
   serves first already log plaintext, and in the compromised-agent case
   the proof is evidence they may want. The issue's "acceptable for now"
   holds. What this note adds to the record is §1's two points: the first
   message's contents are bound, and the mailbox is a latent holder.

2. **If deniability is wanted, `CryptoProfileV2` is A + B, and nothing
   from the literature.** Replace the hybrid transcript signature with a
   MAC under a join secret carried in the invitation, which restores
   spec §4.2's join secret and makes the first message deniable; and
   give the joiner's identity an ML-KEM-1024 key that the inviter
   encapsulates to in `Accept`, which gives post-quantum implicit
   authentication of the joiner and closes §5's residual. Both are OTP
   primitives, the handshake flights do not change, the initial frame
   shrinks by 1 773 bytes, and `Accept` grows by 1 568. The profile
   version byte, the identity encoding, the invitation format and the
   `Accept` layout change; the key agreement and the ratchet do not. It
   needs an ADR amending ADR-005, whose "why an explicit initiator
   signature" paragraph would be answered by §5 here.

3. **Decide before the freeze.** ADR-005 chose hybrid authentication
   from day one because retrofitting means a new profile and re-pairing
   every relationship. The same arithmetic applies to this change:
   before the freeze it is a layout change; after it, a migration. The
   note therefore asks for a ruling, not for work.

4. **Triggers that would reopen it regardless:** a public-identity or
   directory mode (the pairwise mitigation disappears and the bearer
   argument for A with it); a dispute model in which Pondline is expected
   to produce evidence, which argues for keeping the signature and
   exposing it as policy; or a standardised post-quantum ring or
   designated-verifier signature with an OTP binding, which would make D
   or E a drop-in.

5. **Outside review**, if V2 is pursued, of §5's claim that invitation
   possession is the authenticator and that A + B gives offline
   deniability under Fiedler and Janson's model for both parties,
   including against a quantum judge in Katsumata et al.'s sense. The
   PQXDH analyses were done for Signal's layout; Pondline's departures
   (embedded bundle, no one-time prekeys, fingerprint `AD`, and under V2
   the MAC and the `Accept` encapsulation) would each need to be carried
   through.

## 9. Corrections to the citations in issue #2

| As written | Verified | Correction |
| --- | --- | --- |
| "split-KEM approaches such as K-Waay" | Collins, Huguenin-Dumittan, Nguyen, Rolin, Vaudenay, USENIX Security 2024, eprint 2024/120 | Correct. The split KEM is from Brendel, Fischlin, Günther, Janson, Stebila (SAC 2020, eprint 2019/1356), whose own final instantiation is CSIDH-based; K-Waay instantiates it from plain LWE (FrodoKEX+) and adds the unforgeability and deniability notions the original lacked. Niot's Sparrow-KEM (ASIA CCS 2025, eprint 2025/853) is the compact follow-up. |
| "older designs built on ring or designated-verifier signatures" | Hashimoto, Katsumata, Kwiatkowski, Prest (PKC 2021, JoC 2022, eprint 2021/616) for ring signatures; Brendel, Fiedler, Günther, Janson, Stebila (PKC 2022, eprint 2021/769) for designated-verifier signatures | Correct as pointers. The current ring-signature work is Katsumata, Niot, Tucker, Wiggers (USENIX Security 2025, eprint 2025/1090: RingXKEM) and Gajland, Janneck, Kiltz (CRYPTO 2024, eprint 2024/890: Gandalf). |
| "No standardized PQ instantiation [of DVS] that I know of" | Confirmed by search | None found built on ML-DSA, Falcon or Dilithium; the 2024 and 2025 lattice SDVS papers are academic constructions on Ring-SIS/LWE. |
| "PQXDH's offline deniability for the initiator" | Signal PQXDH spec rev. 3 §4.4; Fiedler and Janson 2024; Katsumata et al. 2025 | Correct in the classical setting. The spec itself says deniability against quantum adversaries "requires further research", and Katsumata et al. show it is not uniformly present. |

## References

Primary sources, each checked on 2026-11-01 for title, authors, venue and
the claim cited.

- Bhargavan, Jacomme, Kiefer, Schmidt. "Formal verification of the PQXDH
  Post-Quantum key agreement protocol for end-to-end secure messaging".
  USENIX Security 2024. <https://eprint.iacr.org/2024/702>
- Brendel, Fischlin, Günther, Janson, Stebila. "Towards Post-Quantum
  Security for Signal's X3DH Handshake". SAC 2020.
  <https://eprint.iacr.org/2019/1356>
- Brendel, Fiedler, Günther, Janson, Stebila. "Post-quantum Asynchronous
  Deniable Key Exchange and the Signal Handshake". PKC 2022.
  <https://eprint.iacr.org/2021/769>
- Collins, Huguenin-Dumittan, Nguyen, Rolin, Vaudenay. "K-Waay: Fast and
  Deniable Post-Quantum X3DH without Ring Signatures". USENIX Security
  2024. <https://eprint.iacr.org/2024/120>
- Di Raimondo, Gennaro, Krawczyk. "Deniable Authentication and Key
  Exchange". CCS 2006. <https://eprint.iacr.org/2006/280>
- Dodis, Katz, Smith, Walfish. "Composability and On-Line Deniability of
  Authentication". TCC 2009.
  <https://cs-people.bu.edu/ads22/pubs/2009/DKSW-TCC2009.pdf>
- Fiedler, Janson. "A Deniability Analysis of Signal's Initial Handshake
  PQXDH". PoPETs 2024(4). <https://eprint.iacr.org/2024/741>
- Gajland, Janneck, Kiltz. "Ring Signatures for Deniable AKEM: Gandalf's
  Fellowship". CRYPTO 2024. <https://eprint.iacr.org/2024/890>
- Hashimoto, Katsumata, Kwiatkowski, Prest. "An Efficient and Generic
  Construction for Signal's Handshake (X3DH): Post-Quantum, State Leakage
  Secure, and Deniable". PKC 2021; Journal of Cryptology 2022.
  <https://eprint.iacr.org/2021/616>
- Katsumata, Niot, Tucker, Wiggers. "Comprehensive Deniability Analysis of
  Signal Handshake Protocols: X3DH, PQXDH to Fully Post-Quantum with
  Deniable Ring Signatures". USENIX Security 2025.
  <https://eprint.iacr.org/2025/1090>
- Kret, Schmidt. "The PQXDH Key Agreement Protocol". Revision 3, Signal,
  2023 (updated 2024). <https://signal.org/docs/specifications/pqxdh/>
- Niot. "Practical Deniable Post-Quantum X3DH: A Lightweight Split-KEM for
  K-Waay". ASIA CCS 2025. <https://eprint.iacr.org/2025/853>
- Schwabe, Stebila, Wiggers. "More efficient post-quantum KEMTLS with
  pre-distributed public keys". ESORICS 2021.
  <https://eprint.iacr.org/2021/779>
- Unger, Goldberg. "Improved Strongly Deniable Authenticated Key Exchanges
  for Secure Messaging". PoPETs 2018(1).
  <https://petsymposium.org/popets/2018/popets-2018-0003.php>
- Vatandas, Gennaro, Ithurburn, Krawczyk. "On the Cryptographic
  Deniability of the Signal Protocol". ACNS 2020.
  <https://eprint.iacr.org/2021/642>
