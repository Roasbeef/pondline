# Design review, 2026-10-31

Two independent reads of `docs/spec.md` (v0.1) and `docs/design-intent.md`,
taken against the tree at `05eeeea`, and a reconciliation of where they
agree and disagree. Neither review ran code; every claim below is an
argument to be settled by a spike or an ADR, not a finding.

## Rulings after the review

The owner answered the reviews the same day. Where a ruling overrules a
position taken below, the position is left as written and the ruling is
recorded here, so the record shows what was proposed and what was decided.

- **Tor-first stays, and the clearnet TLS carrier is dropped.** Tor is
  there for NAT traversal and location hiding, not only content privacy.
  Reedwire is not an enterprise tool; the support flow was a demonstration
  idea, so the "Tor conflicts with the flagship use case" argument does not
  apply. The connection layer is abstracted behind the mailbox command
  boundary so that other carriers, Lightning onion messages first, can be
  added later.
- **Post-quantum from day one.** This overrules both reviews' "classical
  v1". The profile is PQXDH followed by the Double Ratchet, with a version
  field that leaves room for Signal's sparse post-quantum ratchet later.
  vodozemac has no PQ and is out.
- **Crypto direction: OTP's `crypto` for the primitives, the protocols in
  Gleam.** OTP 29 linked against OpenSSL 3.6.3 provides ML-KEM-512/768/1024,
  X25519, Ed25519, ChaCha20-Poly1305 and HMAC; an ML-KEM-1024 round trip
  was run on the development machine (1568-byte key and ciphertext, 32-byte
  secret). PQXDH and the Double Ratchet are written in Gleam over those
  primitives, with the ratchet state an ordinary value, which makes §5.3's
  prepare/commit a property of the code rather than of a library. This
  supersedes the "bytes-in, bytes-out crypto NIF" and the vodozemac
  position below. A spike and an ADR still settle it.
- **Every agent is sandboxed, and pairing grants a bounded message
  budget** (or an operator-readable plaintext audit log), so a pairing is
  not an unlimited prompt-injection channel. The daemon's state directory
  sits outside the agent's sandbox.
- **One agent principal per daemon in v1.** The `AgentId` column stays.
- **HTTP is the first mailbox protocol.** QR invitations are a
  nice-to-have; the PQ bundle (about 1.8 KB) is embedded in file
  invitations.

## Reconciliation

**Both reviews reached these independently**, so they are the strongest
signals:

- Tor-first conflicts with the flagship support flow. Make a clearnet TLS
  carrier an explicit per-relationship transport policy in v1, with Tor as
  the private default. The typed mailbox command boundary (§6.2) already
  makes this cheap.
- Run Arti as a supervised sidecar (SOCKS5 out, onion-service port
  forwarding in) instead of a NIF; keep NIFs for crypto, where short pure
  calls are the right shape. Settle it with a crash test.
- Make the crypto boundary bytes in, bytes out:
  `(state, input) -> (state', output)`, with Gleam holding the only copy
  of the state. That makes §5.3's prepare/commit contract a property of the
  boundary rather than of the library.
- Replace protobuf with BOLT-style TLV for every committed structure.
- Make one Arti isolation group per queue mandatory, and state that a
  first-party mailbox hosting both directions sees the whole bidirectional
  timing pattern.
- Add outbound policy: the dominant risk is a prompt-injected local agent
  exfiltrating to an approved contact, not a hostile inbound message.
- Cut multiple local principals per daemon from v1.
- The mailbox design is close to SimpleX's SMP; mine it for lessons even
  though adoption is ruled out.

**Raised only by the advisor, and worth adopting:**

- Embed the public bundle in the invitation and drop `join_secret`,
  `PublishBundle` and `ClaimBundle`. If the bundle is never published, only
  an invitation holder can produce a valid `Hello`, so possession of the
  bundle is possession of the invitation; substitution becomes impossible
  rather than detected. The open question is whether a QR-sized invitation
  is a requirement.
- The inviter creates both queues; rotate the bootstrap append capability
  at `Accept`.
- DI §5B has the customer's agent import and join, while §9.1 says an
  ordinary adapter should not approve contacts. Import must create a
  pending relationship that an operator activates.
- Wake cost is a DoS target: quotas bound storage, not inference.
- Piggyback receipts on outbound traffic and send a standalone receipt only
  after an idle timeout.
- `PRAGMA fullfsync` on macOS, since `synchronous=FULL` alone does not flush
  the drive cache there.
- Expose omission detection from ratchet counters; run the mailbox with
  vanguards; restrict and surface `route update` targets.

**Where the reviews disagree, and the position taken here:**

- *Drop the test-only crypto provider (advisor) vs keep it.* Keep a fake,
  but only under `test/`, so it cannot compile into a release at all. That
  removes the failure mode §13.3 guards with a rule, and lets the durable
  core's tests run before the crypto spike lands. The pure `core`
  transitions never call crypto anyway; the shell does and feeds results in
  as events.
- *Own ~500-line value-semantic Double Ratchet (advisor option) vs a
  library.* Prefer vodozemac for v1: its pickled `Session` already has value
  semantics, it is audited and Apache-2.0, and writing a ratchet contradicts
  DI §1. libsignal is AGPL-3.0, which would make the daemon AGPL.
- *Reader-level long-poll over one stream (advisor 3.6) vs per-queue
  isolation (advisor 3.5).* These conflict once a first-party mailbox hosts
  queues created by different inviters: those queues are not otherwise
  linked, and a shared fetch would link them. Keep per-queue isolation
  unless measurement shows the circuit count is a real cost.
- *PQ in v1.* Both lean classical v1 with PQXDH as `CryptoProfileV2` via a
  new invitation format. Short-lived support sessions gain little from
  harvest-now-decrypt-later protection; say in writing that v1 is not
  post-quantum.

## Review A: session review

**The product idea is real, but the flagship use case conflicts with
Tor-first.** Vendor-to-customer support is an enterprise scenario, and
enterprise networks are where Tor is most often blocked and treated as a
warning sign. Content is already end-to-end encrypted; what Tor adds is
hiding which mailbox you talk to, which matters little when the mailbox
belongs to your counterparty. Keep Tor as the default, but plan an HTTPS
carrier early. The Lightning appendix currently gets more design attention
than the carrier the flagship customer most likely needs.

**The biggest security gap is outbound.** The spec is careful that a
received message is only a request. The likelier harm is a local agent
steered by incoming text into sending data out, over an encrypted,
Tor-routed channel that data-loss tooling cannot see. v1 needs an
operator-readable plaintext audit log, per-contact outbound size and rate
limits, and an optional human-approval mode for sends.

**Run Arti as a separate process; keep NIFs for crypto.** Most of §10.4
(read credit, operation ownership, generations) is what a local socket
gives for free. A crash then kills one OS process instead of the VM, which
removes §10.5's problem. Check the current maturity of Arti's onion-service
hosting before relying on it.

**Prepare/commit is easier than the spec implies; licensing is the real
constraint.** Any library with serializable state supports it: load, step a
copy, persist the copy only if the commit succeeds. vodozemac (Apache-2.0,
audited, no PQ) fits directly; libsignal's stores can buffer writes until
commit, but it is AGPL-3.0. OpenMLS deserves one row in the comparison.

**TLV over protobuf.** Gleam has no mature protobuf tooling, and Erlang's
would break `core`'s purity. BOLT-style TLV is canonical by construction,
its odd/even rule is §6.1's fail-closed rule, it decodes in pure Gleam, and
the onion-message ingress carries it anyway.

**Two leaks to name.** Fetching several queues over one circuit links them
and reveals contact count and activity; make per-queue isolation a MUST or
document the linkage. And with the return queue on the vendor's mailbox,
the vendor's operator sees both directions; §11.2 should say so.

**Smaller points.** Mix the join secret into the key schedule where the
library allows it. Cut multiple principals per daemon from v1. Borrow from
SimpleX's queue rotation and private routing. §9, the agent layer, is the
thinnest part of the spec and the one that differentiates the product;
carrying A2A- or MCP-shaped payloads as content types gives interop without
inventing a task model.

**Sequencing.** Feasibility first is right. Make the first end-to-end run
two daemons and a mailbox over localhost HTTP, add Tor after, and leave
Appendix A until the admission and entitlement checks exist.

## Review B: advisor pass

### 1. Motivation and product framing

The real gap is narrower than "agents need a private durable line." Agents across org boundaries already talk over TLS to hosted relays; what they lack is (a) pairing without an account at a shared provider, (b) delivery while the other side is offline, and (c) no trust in the relay. Those three are the wedge, and §2.2's recipient-chosen mailbox plus pairwise queues delivers them. Tor is not part of the wedge. It is the single hardest engineering piece (§10.3–10.5) attached to the least-certain product value: Tor bootstrap is tens of seconds, corporate networks block it, and the customer-support hero flow (DI §5) asks a customer to install a Tor daemon to get help from a vendor. That flow is a conversion killer; vendors have ticketing systems and customers will not install a daemon for one ticket.

Who adopts first: the owner's own agents, then Bitcoin/privacy developers whose agents already live in that world. That is a developer-tool market, not a support-tooling market. Frame v1 that way.

What makes it fail: both sides must install something, and the first conversation takes longer than pasting a webhook URL. The spec already has `permitted_transport_policy` (§4.2) and "no silent downgrade" (§13.1). Use that: make clearnet TLS to the mailbox an explicit, per-relationship carrier in v1, Tor the private default. The E2E design is unchanged; the thing that actually ships gets a fallback that is a policy, not a leak.

One sentence on the build-vs-adopt question, then I drop it: §2.2, §3.2, §4 and §6 are nearly isomorphic to SimpleX's SMP (recipient-chosen servers, unidirectional random-ID queues, invitation-link pairing, double ratchet, Tor-optional). Adopting SMP as the *wire* protocol while writing the Gleam implementation and the agent layer from scratch would have bought years of protocol review and server interop at zero cost to the stack goal. Noted; moving on.

### 2. What is right

Recipient-chosen mailbox with two directional queues and no sender-side forwarding (§2.2). The four-authority split and "transport carries requests, not authority" (DI §7, §1.1); this is the part that is actually novel for agents. Commit-before-send, ack-after-commit, non-destructive Fetch, exact-envelope Ack (§6.5, §8.2–8.3). Pairwise identities and no directory (§3.1, §4.1). The honest privacy profile (§11.1–11.2). The typed mailbox command boundary (§6.2). Single-writer with OCC version checks (§8.4).

### 3. Decisions to change, ranked by cost to change later

**3.1 Wire encoding: protobuf is wrong for committed bytes (§6.1).** Claim: any structure that is signed, hashed, or used as AEAD associated data must have one encoding, and protobuf does not give you that. §6.1 half-admits this. Protobuf also has thin Gleam support (you would codegen via Erlang gpb). Alternative: BOLT-style TLV streams, which the owner knows, which have canonical ordering rules, and which Gleam's `bit_array` pattern matching handles natively. If protobuf stays for the outer HTTP body, every committed structure (invitation, Hello, Accept, Append response, inner Message) must be an opaque `bytes` field with its own fixed encoding. Wire formats are the most expensive thing to change; decide now.

**3.2 Crypto profile and the prepare/commit contract (§5.3, DI §9).** The contract is satisfiable, but not the way the spec implies. No library exposes "candidate state" as a value; what they expose is either (a) store traits the library mutates during encrypt/decrypt (libsignal: `SessionStore`, `PreKeyStore`, `KyberPreKeyStore`, with `remove_pre_key` called inside `message_decrypt`) or (b) a mutable `Session` with `pickle()`/`from_pickle()` (vodozemac). Both can satisfy §5.3 with the same trick: make the crypto NIF a pure function over bytes, `(state_bytes, input) -> (state_bytes', output)`. Load in-memory stores from the blob, run the operation, serialize the stores back, return. Gleam holds the only copy of the state; the NIF holds nothing. This makes the §5.3 requirement a property of the boundary rather than of the library, and it makes "an opaque NIF resource that silently advances a ratchet" (§5.3) unrepresentable, which is the right fix. Serialization per message is cheap at this throughput.

Then choose: libsignal (PQXDH, but explicitly unsupported externally and API-unstable), vodozemac (audited, value-friendly, but Olm has no PQ), or a value-semantic Double Ratchet of your own over RustCrypto primitives (~500 lines, needs review, but the integration risk is one you own anyway). The deciding fact is 3.9 below: ML-KEM-1024 makes the Hello ~1.8 KB, which forecloses the small onion-message packet. My recommendation: classical X3DH-style + Double Ratchet in `CryptoProfileV1`, with the profile version and per-invitation bundle (§4.1) making a PQXDH `V2` a new invitation format rather than a migration. Say in writing that v1 is not PQ.

**3.3 Invitation design: embed the bundle, drop the join secret (§4.1–4.3).** Claim: the `prekey_bundle_commitment` + `PublishBundle`/`ClaimBundle` indirection exists only to keep the invitation small, and it is what creates the need for `join_secret`. A full public bundle is ~200 bytes classical (~1.8 KB with ML-KEM), which is fine for a file or a long URL. Embedding it removes two mailbox operations, the bundle-substitution attack (§13.1 row 3) becomes impossible rather than detected, the "fetch does not consume" subtlety (§4.3 step 4) disappears, and the mailbox never sees the bundle, so it can no longer run the handshake, which is the whole reason `join_secret` exists (§4.2). Keep `invitation_id` as associated data on the Hello. If a QR-size invitation is a hard requirement, say so; otherwise this is pure complexity.

While here: §4.3 step 1's "provisioning grant allowing B to create a return queue" adds a capability type and a CreateQueue call to the pairing path and links both queues at the mailbox anyway. Simpler: the inviter creates both queues and puts B's read capability for the return queue in the invitation. B provisions nothing. B can `route update` to its own mailbox later. Also rotate the bootstrap append capability at Accept; the invitation file will live forever in someone's ticket system.

**3.4 Arti as a NIF is wrong; run it as a sidecar process (§10.3–10.5).** Claim: the entire §10.4 apparatus (read credit, bounded writes, ownership generations, cancellation, cleanup on owner death) reimplements what `gen_tcp` with `{active, N}` gives you for free, and the payoff is that a panic in a young async Tor stack kills a daemon whose only job is durability. §10.5's answer ("external supervisor and tested restart recovery") is machinery to cope with a failure mode you can remove. Arti already supports this shape: `arti proxy` for a SOCKS5 listener, and onion services configured with `proxy_ports` forwarding to a local TCP port. Then the mailbox is a normal Gleam HTTP server (mist/glisten) on localhost and the client uses a SOCKS-capable HTTP client; neither of the Gleam HTTP libraries can speak a non-socket NIF stream anyway, which §6.1 does not acknowledge. Ship the Arti binary in the release bundle, supervise it from a port owner. The stack goal is still met: the crypto NIF (3.2) is where a NIF is the right tool, short pure calls with no resources, threads, or ownership.

**3.5 Capabilities and linkability (§3.2, DI §3).** Pond-style anonymous admission is correctly out of scope. What the spec is missing is the cheap rule that keeps the simplification from getting worse: Append MUST present only the per-queue capability, never an account-, sponsor-, or L402-level credential, and the client MUST use a separate Arti isolation group per queue (§10.3 has the parameter; make it mandatory). Without this, a sender's provisioning account or L402 token reused across queues links all of its relationships at the mailbox. Intra-queue linkability is the relationship itself and is fine. Also state plainly that with a first-party default mailbox hosting both directions of most relationships, the operator sees the full bidirectional timing pattern; §11.2 lists the pieces but not the conclusion.

**3.6 Fetch long-poll over HTTP/1.1 (§6.1, §11.3).** One 25-second long-poll per queue means N open rendezvous circuits for N relationships. Define Fetch-wait at the reader level (all queues the caller holds read capabilities for at that mailbox) over one stream. The recipient already linked those queues by provisioning them from one account (§11.2), so this costs no privacy. The L402 argument for HTTP is weak as a transport justification (402 + header maps to any framing); the real justification is tooling, which is fine.

**3.7 Receipts (§7.3).** Claim: one standalone ratchet message per received message doubles traffic and produces the cleanest timing signal in the system (every message yields a reply seconds later). Piggyback receipt acks in the next outbound application message and send a standalone receipt only after an idle timeout. Make receipt generation per-relationship policy.

**3.8 Dedup tombstones (§6.4–6.5).** Correctness already lives in the recipient: the authenticated inner `message_id` (§8.3 step 2) and the ratchet's deleted message keys reject a re-appended envelope without state mutation. Server tombstones are a quota-protection convenience. Say that, set tombstone TTL = the envelope's accepted retention deadline, and store the content digest with the tombstone (needed for the "different bytes, conflict" rule). Spell out the client dedup keys: outer `(queue, envelope_id, digest)` is unauthenticated and may only short-circuit; inner `message_id` is authoritative.

**3.9 Appendix A.** Payload reality: the 1366-byte onion packet leaves roughly 1 KB for the final hop; a PQXDH Hello does not fit at all, and no padding bucket (§11.3) fits either. So LN ingress is "large packets only" (which nodes rate-limit heavily and relay for free) or "post-handshake control messages only." Write the number down. Correlation: an L402 macaroon on the per-message path links every queue it touches; L402 must buy a provisioning allowance once and the mailbox then mints per-queue capabilities (3.5). Reply paths require the sender to be an LN node and the mailbox to run one; that is fine for the lnd audience but should be stated as the audience. All of this is cheap to change later; only the Kyber-size constraint feeds back into 3.2.

**3.10 SQLite (§8.1).** The `synchronous=FULL` claim is correct but incomplete: on macOS add `PRAGMA fullfsync`; verify whether the chosen driver (sqlight/esqlite) runs on dirty schedulers; and design the storage coordinator to take a complete write batch with a version precondition in one message (no interactive transactions across process hops). Low cost to change.

### 4. Threat-model gaps

- **Agent-approves-invitations contradiction.** §9.1 says a generic integration SHOULD NOT approve contacts; DI §5B has the customer's agent import and join. A prompt-injected agent that can run `invite accept` pairs with the attacker. Resolve: import creates a pending relationship; activation needs an admin-credential action or a stated preapproval rule.
- **Wake cost as a DoS target (§9.3).** A peer with a lifetime append capability can cause model invocations, which cost money. Quotas bound storage, not inference. Need per-relationship rates on host notification.
- **Outbound policy is missing.** §9.1 scopes adapters by contact but not by content. A prompt-injected agent can exfiltrate anything to any approved contact. Add a per-relationship outbound policy hook (content types, size, schema) mirroring §9.3's inbound one.
- **Route updates as a probe.** A peer's `route update` makes A's daemon connect to an arbitrary onion address. Restrict to v3 onions, rate-limit, surface to the operator.
- **Omission detection.** §6.5 says tolerate omission; it should also say detect and report. The ratchet header's counters give you "N messages missing from this peer" for free. Expose it.
- **Mailbox guard discovery.** A long-lived onion service is a guard-discovery target; the mailbox should run with Arti's vanguards enabled. Not mentioned.
- **Keys at rest for an unattended daemon (DI §17).** Passphrase-wrapped keys cannot restart unattended; unwrapped keys are readable by any same-user process, including the agent's tools (§9.3). The honest v1 answer is a dedicated OS user with a 0600 state dir; say it rather than leaving it open.
- **Content type is attacker-controlled (§7.1).** Adapters must not dispatch on `content_type` without host policy.
- **Adapter credential lifetime** (§9.1) is unspecified; add expiry and revocation.

### 5. Scope and sequencing

§13.3 and DI §15 disagree: DI §15 (spike the integration risks first) is right. Smallest de-risking slice: two spikes of a few days each. (1) Arti sidecar: one BEAM opens an onion stream to another's onion service via SOCKS, then kill Arti mid-stream and watch the VM survive. (2) Crypto boundary: pick the library, prove bytes-in/bytes-out with a crash injected between prepare and commit. Then build the durable core with real crypto from day one over plain localhost TCP. Drop the test-only crypto provider (§13.3) entirely; a pure-function crypto NIF is as deterministic as a fake, and "must never be selectable in production" is a rule you only need because you built the thing.

Cut from v1: PublishBundle/ClaimBundle and join_secret (3.3); the return-queue provisioning grant and CreateQueue on the pairing path (3.3); multiple local principals per daemon (§9.1); UpdatePolicy; wake hooks in favor of `receive --wait`; `application_namespace`/`correlation_id` (keep `in_reply_to`). Appendix A stays an appendix.

### 6. Answer before writing protocol code

1. PQ in v1 or `CryptoProfileV2`? (Decides library, Hello size, LN viability.)
2. libsignal-with-staging-stores, vodozemac, or own value-semantic DR, after the spike.
3. TLV or protobuf-with-opaque-committed-bytes; the exact bytes under every signature and AEAD AD.
4. Is QR-sized invitation a requirement? If not, embed the bundle.
5. Who activates a contact in the hero flow: the agent or the operator?
6. Is clearnet TLS an allowed v1 carrier under `permitted_transport_policy`?
7. NIF or sidecar for Arti, settled by the crash test, not by preference.
8. Receipt policy: per message, delayed, or per-relationship opt-in.
9. Tombstone TTL and sender retry window as numbers.
10. Storage coordinator contract: batched writes with version precondition, and which SQLite driver.
11. Keys at rest for unattended daemons.
12. Per-relationship rate limits on host notification and outbound content.
