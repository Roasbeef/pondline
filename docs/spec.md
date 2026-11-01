# Reedwire: Core System Specification
### Version 0.1 — architecture and protocol draft

*Reedwire is a working name.*

**The core is a standalone, Tor-first, encrypted messaging substrate for independently operated agents.** Gleam/BEAM owns the application protocol, durable state, policy, and supervision. Rust provides Arti integration and a narrowly scoped cryptographic implementation.

The design should be useful without Loom, a Lightning wallet, a public identity directory, or an agent-specific framework.

Its primary user experience is:

> Install → create or import an invitation → approve the relationship → exchange durable messages.

This draft specifies the architecture, state transitions, interfaces, and security boundaries. It is not yet a frozen, independently reviewed cryptographic wire specification. The exact cryptographic implementation and profile are explicit release gates.

**MUST** indicates a required property of the proposed system. **SHOULD** indicates a default that can change with a documented rationale.

---

# 1. Purpose and scope

## 1.1 Product contract

An operator must be able to connect an existing agent to another independently operated agent without giving either side control over the other’s runtime.

The system provides:

| Capability | Core responsibility |
|---|---|
| Pairing | Establish a relationship through an authenticated invitation. |
| Confidential communication | Encrypt messages end to end, independently of mailbox operators. |
| Offline delivery | Store ciphertext while a recipient is unavailable. |
| Durable local delivery | Preserve inboxes, outboxes, and protocol state across crashes. |
| Admission control | Restrict who may consume inbox resources. |
| Runtime integration | Expose a CLI and local API usable by different agent hosts. |

The system transports **requests**, not ambient authority.

A valid incoming message does not authorize shell execution, filesystem access, model invocation, spending, or disclosure of local data.

## 1.2 Initial non-goals

Version 1 does not implement a distributed agent runtime, remote shell, workflow engine, global identity directory, group messaging, active-active device synchronization, or a new mixnet.

It also does not attempt to establish unconditional exactly-once execution of external effects.

Large-file distribution, sophisticated cover traffic, anonymous payment credentials, and additional carriers are extensions—not prerequisites for useful communication.

## 1.3 Reference use case

A vendor’s agent and a customer’s agent establish a temporary support relationship.

The vendor agent requests diagnostics. The customer agent inspects its environment using its existing permissions and sends approved results. Configuration changes remain subject to the customer’s local approval policy.

Either runtime can restart without losing the conversation or silently repeating an acknowledged operation.

---

# 2. System architecture

## 2.1 Three deployment roles

**Client daemon.** Runs beside the agent host. Owns local identities, encryption state, contacts, durable inbox/outbox, and the local API.

**Mailbox service.** Stores ciphertext and public handshake material. Enforces queue admission, resource limits, and retention. It has no message-decryption keys.

**Agent adapter.** Connects an existing agent host to the local daemon. The CLI is the baseline adapter; MCP and native SDKs can wrap the same API.

These roles may share a repository and release package, but their trust boundaries remain separate.

## 2.2 Delivery topology

```text
Agent A
   │ local authenticated API
   ▼
Daemon A ── Tor ──► B's mailbox ◄── Tor ── Daemon B
                                               │
                                      local authenticated API
                                               ▼
                                            Agent B

Replies:
Daemon B ── Tor ──► A's mailbox ◄── Tor ── Daemon A
```

The sender connects directly to the recipient’s chosen mailbox. There is no SMTP-like forwarding through the sender’s provider.

Each relationship has two directional queues. Multiple agents and queues may share a mailbox service’s onion address.

**An agent does not need its own onion service.**

The first-party managed service would be the default deployment. Organization-operated and self-hosted services would implement the same protocol.

Arti exposes both client connections and onion-service hosting APIs, so both client and server roles can use the same native integration strategy. [Arti](https://arti.torproject.org/integrating-arti/)

## 2.3 Trust boundaries

A mailbox is trusted for availability and resource accounting, **not** confidentiality or peer authenticity.

A client daemon is trusted with plaintext and key material. Its host operating system is part of that trusted boundary.

The model is not trusted with private keys, mailbox administration credentials, or unrestricted access to the daemon.

An agent adapter is trusted only for the permissions explicitly granted to it.

---

# 3. Core objects and identities

The design separates local agent identity, relationship identity, cryptographic sessions, and delivery addresses.

| Object | Meaning |
|---|---|
| `AgentId` | Durable local identifier for an agent principal. Never required as a global network identifier. |
| `ContactId` | Local handle for an approved remote relationship. |
| `Relationship` | Pairwise identities, directional routes, lifecycle, and local policy. |
| `CryptoSession` | A particular handshake/ratchet instance within that relationship. |
| `QueueId` | Random identifier for one directional mailbox queue. |
| `MessageId` | Sender-generated logical message identifier, authenticated inside the encrypted message. |
| `EnvelopeId` | Identifier for a particular immutable ciphertext submission and its retries. |
| `InvitationId` | Identifier for a single-use pairing offer. |

Identifiers and capabilities MUST be generated from a cryptographically secure randomness source. They must not derive from agent names, prompts, repository names, or model output.

## 3.1 Pairwise identities

Each relationship uses its own cryptographic identity material.

The same local agent may therefore appear under different public identities to different contacts. Version 1 does not publish a global agent key.

An onion address identifies a mailbox service. It does not identify the agent whose ciphertext is stored there.

## 3.2 Queue capabilities

A queue uses separate credentials for separate operations:

| Capability | Authority |
|---|---|
| Administration | Configure limits, rotate credentials, revoke access, delete the queue. |
| Read/acknowledge | Retrieve queued ciphertext and acknowledge durable local receipt. |
| Append | Submit bounded ciphertext to that queue. |
| Enrollment | Fetch or claim the invitation’s public handshake material. |
| Provisioning | Create a limited number of queues within an existing service allowance. |

Version 1 SHOULD use simple, opaque, server-maintained capabilities rather than introducing a general-purpose authorization language.

Capabilities MUST have explicit scope and expiration. Quotas are enforced by the service, not merely described in the token.

**Mailbox credentials are not proof of peer identity.** A malicious mailbox operator can bypass its own admission checks. End-to-end authentication must remain secure in that case.

---

# 4. Pairing and first contact

## 4.1 One-use invitations, not a global prekey directory

To keep the first implementation narrow, **each invitation publishes a dedicated public prekey bundle**.

There is no globally searchable directory and no mandatory shared pool of prekeys. Generating a new invitation automatically generates the required material. Established conversations do not fetch prekeys for every message.

This retains asynchronous establishment—the inviter may be offline—without immediately building a general-purpose identity and device directory.

Asynchronous protocols such as PQXDH are designed around publishing public material in advance while keeping the corresponding private material at the recipient. [Signal Messenger](https://signal.org/docs/specifications/pqxdh/)

## 4.2 Invitation contents

An invitation contains:

```text
Invitation {
    format_version
    invitation_id
    inviter_identity_commitment
    prekey_bundle_commitment

    mailbox_endpoint
    bootstrap_queue_id
    enrollment_capability
    bootstrap_append_capability

    join_secret
    acceptance_deadline

    required_protocol_profile
    permitted_transport_policy

    optional_return_queue_provisioning_grant
    human_readable_description
}
```

The `join_secret` is a high-entropy secret known to the inviter and invitation holder. It MUST NOT be uploaded to the mailbox in plaintext.

This secret is distinct from the mailbox’s enrollment capability.

That distinction matters: **the mailbox may know who can fetch a bundle, but it must not thereby gain the ability to impersonate the invited peer.**

An invitation is a bearer credential. Whoever obtains it may attempt to redeem it. The trusted channel used to share it establishes whom the operator intended to invite.

The human-readable description is informational, not independently verified identity.

*Added by ADR-009.* An invitation may also travel as a **ticket**: a checksummed `rw1` string of 130 characters (74 for a loopback mailbox) carrying only the inviter mailbox's endpoint and a fresh 32-byte secret `K`. The invitation itself is stored at that mailbox sealed under keys derived from `K` (ChaCha20-Poly1305 plus an HMAC commitment to the plaintext), named by a locator and fetched with a capability also derived from `K`; the mailbox sees only the locator, the capability's hash and ciphertext. The joiner MUST check the AEAD and the commitment, and that the invitation names the ticket's mailbox, before using it. A ticket is a bearer credential exactly as the file is, and MUST NOT appear in argv, logs or errors. `docs/adr/009-invitation-tickets.md` has the format and `docs/crypto-profile-v1.md` §11 the derivations.

## 4.3 Establishment flow

### Step 1: Inviter prepares

Daemon A creates its relationship-specific identity, private prekey material, and inbound queue.

It uploads only the public bundle, records the invitation locally, and exports the invitation file.

*Added by ADR-009.* With a ticket, A also stores the sealed invitation at its own mailbox with `PutBlob`, under the invitation's deadline and charged to the inbound queue's quota, and exports the ticket only after the mailbox has stored it.

A may include a narrowly scoped provisioning grant allowing B to create a return queue without establishing a separate service account.

### Step 2: Joiner imports

Daemon B validates the invitation format, deadline, transport policy, and supported protocol profile.

It persists its own pairing attempt, identity material, and request identifiers **before** making retriable network operations.

B then creates its return queue and fetches the public bundle.

*Added by ADR-009.* Given a ticket, B first fetches the sealed invitation with `GetBlob` and opens and checks it before anything is persisted; from there the flow is the file's. Fetching does not consume the blob, as fetching a bundle does not consume the invitation.

The bundle MUST match the identity and bundle commitments in the invitation.

### Step 3: Joiner sends `Hello`

B establishes the proposed encrypted session and durably queues an encrypted `Hello` containing:

```text
Hello {
    invitation_id
    invitation_commitment
    join_secret
    initiator_identity
    return_queue_route
    proposed_session_parameters
}
```

The initiator identity in the payload must agree with the identity authenticated by the cryptographic protocol.

The same committed ciphertext is reused on transport retries.

### Step 4: Inviter validates

A decrypts the initial message and checks the invitation commitment, join secret, deadline, peer identity binding, and supported parameters.

Only a valid authenticated `Hello` may consume the invitation.

**Fetching a prekey bundle does not consume the invitation locally.** A mailbox can interfere with availability, but it cannot cause an invalid claimant to become an accepted contact.

The valid claim and resulting session state MUST commit atomically.

### Step 5: Local approval and acceptance

A applies local policy. A preapproved invitation may be accepted automatically; otherwise the contact remains pending.

A sends an encrypted `Accept` or `Reject`. B does not present the relationship as active until it authenticates `Accept`.

Application messages MUST NOT reach the host before the relationship is authorized.

## 4.4 Retry and race behavior

Prekey claims and queue provisioning MUST be idempotent for an identical request.

A competing claimant cannot replace a contact after a valid invitation consumption. Replayed valid handshakes must resolve to the existing outcome, not create additional relationships.

A stolen invitation can be raced. The system cannot infer which bearer was the intended human. Sensitive deployments should require out-of-band fingerprint confirmation or an independently pinned peer identity.

---

# 5. Cryptographic profile and key lifecycle

## 5.1 Required properties

The cryptographic component must support asynchronous session establishment, authenticated encryption, evolving session keys, bounded out-of-order reception, and explicit state serialization.

The proposed reference construction is **PQXDH followed by an established ratcheting protocol**, rather than a custom handshake or custom symmetric-key schedule.

PQXDH strengthens initial confidentiality against quantum adversaries but its specified authentication still relies on classical assumptions. Reedwire's profile does not inherit that: every authentication step MUST require both a classical and a post-quantum proof, with identity bindings, prekey signatures and an initiator transcript signature each made with Ed25519 and ML-DSA-65 together (`docs/adr/005-hybrid-authentication.md`, `docs/crypto-profile-v1.md`). A classical Double Ratchet alone does not provide continuous post-quantum recovery after compromise; Signal documents separate post-quantum and hybrid ratchets for that purpose. [Signal Messenger](https://signal.org/docs/specifications/pqxdh/)

The product must describe the guarantees of the selected profile accurately, rather than label the whole system simply “post-quantum.”

## 5.2 Crypto profile freeze

Before an interoperable release, `CryptoProfileV1` MUST fix:

- Handshake, ratchet, algorithms, encodings, and domain separation.
- Authenticated transcript fields and identity bindings.
- Header-visibility properties.
- Limits on skipped keys, candidate sessions, and handshake sizes.
- State serialization and upgrade compatibility.
- Known-answer and cross-implementation test vectors.

The existing Rust `libsignal` implementation is a candidate to evaluate, not an assumed stable dependency: its maintainers explicitly state that external use is unsupported and APIs may change. [GitHub](https://github.com/signalapp/libsignal)

**Building a new application protocol does not require building new cryptographic primitives.**

## 5.3 Transactional crypto interface

The crypto adapter must support a prepare/commit model:

```text
prepare_send(current_state, plaintext, context)
    -> candidate_state, ciphertext, key_changes

prepare_receive(current_state, ciphertext, context)
    -> candidate_state, plaintext, key_changes
```

These operations MUST NOT irreversibly advance hidden native state before the application commits its database transaction.

A candidate state becomes authoritative only after persistence succeeds. Failed transactions discard the candidate.

This requirement is central: an opaque NIF resource that silently advances a ratchet cannot be the sole source of truth.

## 5.4 Key retention and deletion

Private prekeys remain local. They must survive for the full permitted lifetime of a valid queued initiation, including an explicit delivery/skew allowance.

They must not be deleted merely because the mailbox reports a fetch.

After establishment commits, one-time private material can be retired according to the selected protocol, with replay handling supported by durable handshake records.

Local ratchet state, private keys, and retained plaintext MUST be protected at rest. Secrets must not enter logs, tracing attributes, crash reports, or model context.

Deletion is a storage-policy claim, not a guarantee that every filesystem snapshot or backup has erased old material. Ratchet specifications explicitly identify secure deletion and retained keys as implementation concerns. [Signal Messenger](https://signal.org/docs/specifications/doubleratchet/)

---

# 6. Mailbox protocol

## 6.1 Transport and encoding

The initial network binding SHOULD use **HTTP/1.1 with bounded binary bodies over Arti onion streams**.

This reuses ordinary request/response semantics and permits a later standard HTTP payment challenge without inventing another transport encryption protocol.

Application encryption remains independent of the onion connection.

The client MUST accept only configured v3 onion endpoints in the core profile. It MUST disable automatic redirects, ambient proxy fallback, and public-network fallback for mailbox operations.

Protobuf is a reasonable initial body encoding. Security-sensitive commitments must cover explicitly specified bytes; implementations MUST NOT assume that decoding and reserializing a message produces a universal canonical representation.

Unknown required features fail closed. Unknown optional fields must not grant authority.

## 6.2 Minimum operations

| Operation | Purpose |
|---|---|
| `CreateQueue` | Allocate a queue within a provisioning allowance. |
| `PublishBundle` / `ClaimBundle` | Publish and idempotently claim invitation-specific handshake material. |
| `Append` | Submit immutable ciphertext with an envelope ID and retention request. |
| `Fetch` | Retrieve a bounded batch; optionally wait for activity. |
| `Ack` | Acknowledge specific envelopes after local durable processing. |
| `UpdatePolicy` / `Revoke` | Change queue limits or credentials under administration authority. |
| `PutBlob` / `GetBlob` | *Added by ADR-009.* Store a sealed invitation under a ticket's locator until a deadline, authorized by a queue's admin capability and charged to its quota; fetch it, without deleting it, with the ticket's retrieve capability. |

The network binding should translate into typed domain commands. Storage logic must not depend on HTTP objects.

This is the extension point for a later non-Tor carrier.

## 6.3 Outer envelope

The mailbox sees approximately:

```text
StoredEnvelope {
    protocol_version
    queue_id
    envelope_id
    requested_retention_deadline
    padded_ciphertext
}
```

It also sees the presented admission credential and transport activity.

Agent names, task IDs, repository names, application correlation IDs, and message content MUST NOT be added to the outer envelope.

The encrypted content carries its own authenticated validity bounds. A mailbox cannot extend an application message’s validity by editing storage metadata.

## 6.4 Append semantics

For a given `(QueueId, EnvelopeId)`:

**Same bytes, repeated request:** return the original acceptance result.

**Different bytes:** return a conflict.

**Expired or revoked authorization:** reject.

Quota reservation and durable insertion MUST occur atomically. The server must not acknowledge storage before the committed record is durable under its advertised storage configuration.

The response binds the queue, envelope, content digest, and accepted retention deadline. It is evidence of the provider’s acceptance—not proof that the provider will behave honestly.

*Amended by ADR-008.* The mailbox judges a requested retention deadline by its own clock and refuses one that is not in the future or exceeds its maximum retention. A client offers a deadline `retention_slack_seconds` below that maximum by its own clock, never past the message's expiry, so a clock modestly ahead is still accepted. A client refused for the deadline offers the same envelope again with the lifetime halved, at most `max_deadline_offers` offers per attempt, and treats a refusal of the last as a retryable failure bounded by the message's expiry, never as a permanent rejection.

## 6.5 Fetch and acknowledgment

`Fetch` is non-destructive.

`Ack` identifies exact envelopes; it must not implicitly delete unseen messages through a cumulative cursor.

The recipient acknowledges only after its local transaction succeeds. Repeated acknowledgments are harmless.

The service retains bounded deduplication records so that a retry after deletion cannot recreate an already acknowledged message indefinitely. Record retention must cover the operation’s permitted retry/validity window.

Queue ordering is a delivery convenience, not a cryptographic guarantee. Clients must tolerate duplication, reordering, delay, and omission.

---

# 7. Message model and delivery semantics

## 7.1 Inner message

```text
Message {
    message_id
    relationship_epoch
    kind
    expires_at

    optional_in_reply_to
    optional_application_namespace
    optional_application_correlation_id

    content_type
    body
}
```

The core understands a small number of message kinds:

**Application message:** opaque structured content or bytes.

**Receipt:** recipient-level acknowledgment of durable processing.

**Relationship control:** acceptance, close, route update, or another explicitly specified lifecycle operation.

The core should not embed a full agent-task framework. A host may encode `request`, `progress`, `result`, or `cancel` inside application messages.

A cancellation request is not proof that execution stopped.

## 7.2 User-visible states

```text
LocallyQueued
    → StoredByMailbox
    → ReceivedByPeer
    → ConsumedByLocalAdapter
```

The last state is observed on the receiving side unless the application explicitly reports it.

Failures include expiration, rejection, revocation, unsupported profile, and unresolved delivery.

**Task execution is a separate application state machine.**

## 7.3 Recipient receipts

`ReceivedByPeer` requires an authenticated receipt generated after the receiver’s durable transaction.

A mailbox acknowledgment cannot establish this state.

Receipts do not request further recipient receipts; otherwise the protocol creates acknowledgment loops. Receipt delivery still uses ordinary mailbox storage and retry semantics.

A receiver should retain enough information to regenerate the same logical receipt when an already processed envelope is delivered again.

*Amended by ADR-006.* The receiver retains, per relationship, the digest of every ciphertext it stored an application message from (SHA-256 of the ratchet message inside the padding) with the message identifier and the message's expiry. An envelope whose ciphertext matches one of these is a retransmit or a replay: the receiver records it processed, acknowledges it, and answers it with the same logical receipt, a new receipt message naming the same message identifier. It MUST NOT deliver the message again. It answers one ciphertext at most `max_retransmits` times beyond the first receipt, and not after the message expires; past either it drops and acknowledges the envelope. A receipt for a message already `ReceivedByPeer` changes nothing.

## 7.4 Small artifacts

Version 1 supports bounded binary content inside an ordinary encrypted message. This is sufficient for diagnostic summaries, small log extracts, and compact patches.

Bulk object storage and chunk reassembly are deferred.

The daemon MUST NOT automatically follow external URLs, generate link previews, or fetch arbitrary attachment locations.

---

# 8. Persistence and crash recovery

## 8.1 Storage model

Use SQLite for the initial client and mailbox implementations, with schema migrations and an explicit durability configuration.

For durable acknowledgments, the baseline SHOULD use WAL mode with `synchronous=FULL`, tested on supported filesystems. SQLite distinguishes this from WAL `NORMAL`, where recently committed transactions can be lost after power failure. [SQLite](https://www.sqlite.org/pragma.html)

This is a single-node durability contract, not replicated storage.

The client’s logical tables include:

```text
agents
relationships
invitations
crypto_sessions
private_prekeys
outbox
inbox
delivery_receipts
local_event_log
adapter_grants
scheduled_work
```

The mailbox additionally maintains queues, capability records, public bundles, claims, stored envelopes, quotas, and deduplication tombstones.

## 8.2 Outbound transaction

Sending follows this sequence:

1. Validate the local caller’s grant and requested operation.
2. Read the current session and its version.
3. Prepare the ciphertext and candidate cryptographic state.
4. Atomically compare/update the session version, persist key changes, insert immutable ciphertext into the outbox, and append the local event.
5. Only after commit, schedule network transmission.

A database conflict discards the candidate. It does not transmit it.

Once committed, transport retries reuse the same ciphertext. They do not rerun encryption merely because a response was lost.

*Amended by ADR-006.* The same holds for end-to-end retransmission. An application message, or an `Accept`, `Reject` or `Close`, that the mailbox stored but that has no peer receipt within a receipt window is sent again: the same committed padded ciphertext under a new envelope identifier, because the mailbox's tombstone for the old identifier would answer without storing. The window starts when the mailbox stores the copy and doubles with each copy; at most `max_retransmits` copies are sent, none past the message's expiry, and an application message is sent again only while its relationship is active. Receipts and the handshake are never sent again; a lost receipt is regenerated by the receiver when the retransmit arrives (§7.3). The copy is an outbox row committed like any other, so it too is sent only after commit.

## 8.3 Inbound transaction

Receiving follows the corresponding sequence:

1. Bound and parse the fetched envelope.
2. Detect exact duplicates using durable records.
3. Authenticate and decrypt new ciphertext.
4. Validate relationship state, expiry, message identity, and policy.
5. Atomically commit session changes, prekey consumption where applicable, inbox/deduplication records, local events, and any required receipt work.
6. Acknowledge the mailbox only after commit.

Authenticated but expired content may require cryptographic state advancement; it must not be delivered to the agent as actionable work.

An invalid ciphertext must not mutate authoritative session state.

## 8.4 Single-writer ownership

A relationship has one logical writer for cryptographic state.

An actor serializes ordinary operations; database version checks remain the correctness backstop.

The daemon also takes an exclusive ownership lock on its state directory.

This does not protect against someone copying the directory onto another machine and running both copies. Independent clones of a live session are unsupported.

## 8.5 Host consumption

The local API provides durable events and explicit acknowledgment.

If an adapter crashes before acknowledging, the event is redelivered. The adapter must persist its own processing outcome before acknowledging.

For external effects, the host still needs idempotency keys, transactional integration, or an explicit “outcome unknown” state.

**The system promises durable, replay-aware delivery—not universal exactly-once effects.**

---

# 9. Local API and agent permissions

## 9.1 Access model

The client API SHOULD initially use a Unix-domain socket protected by filesystem permissions and a scoped adapter credential.

A daemon may host multiple local agent principals. Each adapter credential restricts which principal, contacts, and operations it can access.

A generic agent integration SHOULD be allowed to send, receive, and inspect status for approved relationships. It SHOULD NOT automatically be allowed to approve contacts, export invitations, change providers, or alter retention policy.

Local administration is a separate privilege.

## 9.2 CLI surface

Illustrative commands:

```sh
reedwire daemon

reedwire invite create --profile support --out session.invite
reedwire invite accept --file session.invite

reedwire contacts list --json
reedwire send --contact customer --file diagnostics.json
reedwire receive --contact customer --wait --json
reedwire acknowledge --delivery <delivery-id>

reedwire status --message <message-id>
reedwire contact close --contact customer
```

Secrets should be passed through protected files, descriptors, or standard input—not exposed in command-line arguments.

*Added by ADR-009.* `reedwire invite create ... --ticket` prints a ticket on standard output (and still writes the file with `--out`); `reedwire invite accept --ticket (--file F | --stdin)` redeems one. `--ticket` is a flag and never takes the ticket as a value.

Machine-readable output and stable exit/error categories are required.

MCP and Loom integrations should invoke this same local API rather than implementing independent protocol logic.

## 9.3 Wake and execution policy

The daemon may notify an explicitly configured host adapter that messages are available.

An incoming message cannot name an executable, set an arbitrary callback URL, or install a wake hook.

Whether notification causes model invocation is a host policy decision. Tool execution and disclosure permissions remain host-enforced.

If the agent’s tools can read the daemon’s files or memory, the local security boundary has already been weakened. Strong deployments should isolate the daemon and untrusted execution using operating-system permissions or sandbox boundaries—not rely on opaque NIF handles alone.

---

# 10. Gleam/BEAM implementation architecture

## 10.1 Functional core, processful shell

Protocol logic should use pure transitions:

```text
transition(model, event)
    -> proposed_state_changes
     + durable_work
     + effects_allowed_after_commit
```

Time, randomness, network outcomes, and storage outcomes enter as explicit events or dependencies.

The core must not perform hidden network calls or mutate native session state as an incidental consequence of evaluating a transition.

Expected conditions—unreachable peer, expired invitation, exhausted capacity—are typed results. Broken internal invariants should fail visibly and trigger supervision.

## 10.2 Process organization

```text
Client supervisor
├── Storage coordinator
├── Native runtime bridge
├── Relationship registry/supervisor
│   └── Active relationship actors
├── Delivery scheduler
├── Provider connection workers
├── Local API server
└── Event subscribers

Mailbox supervisor
├── Storage coordinator
├── Onion-service bridge
├── Admission/request workers
├── Queue notification registry
└── Expiration and quota maintenance
```

Actors are runtime ownership mechanisms, not durable identities.

Inactive relationships need not retain an actor. They can be reconstructed from durable state when work arrives.

Do not create a permanent process for every stored message or every queue ever allocated.

## 10.3 Native boundary

The Rust networking component owns Arti and its asynchronous executor. Its interface should remain narrow:

```text
start_runtime(config)
open_stream(endpoint, isolation_group)
start_onion_service(config)

write(stream, bytes)
grant_read_credit(stream, bytes)
close(stream)
cancel(operation)

stop_runtime()
```

Operations return references promptly. Results arrive as bounded events through a dedicated bridge process.

Arti stream handling must not block normal BEAM schedulers. Erlang’s NIF documentation supports dispatching work to threads and returning results asynchronously; it also warns that lengthy native calls harm VM responsiveness. [Erlang.org](https://www.erlang.org/doc/apps/erts/erl_nif.html)

Cryptographic and database operations likewise need appropriate execution strategies when they can exceed normal scheduler budgets.

## 10.4 Backpressure and lifecycle

The native bridge MUST enforce:

**Read credit.** Rust cannot flood an unbounded BEAM mailbox with stream data.

**Bounded writes.** Excess queued data returns backpressure instead of allocating indefinitely.

**Operation ownership.** Each operation belongs to a live process/resource generation. Late completions from a replaced owner cannot mutate a new session accidentally.

**Cancellation and deadlines.** Cancelling an operation stops local work where possible; it does not imply that bytes already sent were never delivered.

**Shutdown cleanup.** Owner death closes or cancels associated resources. Native upgrades must account for outstanding resources; version 1 may require a controlled daemon restart.

Unknown network values must never become dynamically allocated Erlang atoms. Untrusted input must not be decoded as arbitrary Erlang terms.

## 10.5 Failure boundary

A NIF is inside the VM. A native crash can crash the whole BEAM; actor supervision cannot isolate it. The service must therefore also have an external process supervisor and tested restart recovery. [Erlang.org](https://www.erlang.org/doc/apps/erts/erl_nif.html)

BEAM distribution is not part of the external protocol. Remote agents never become trusted Erlang nodes.

---

# 11. Privacy, limits, and latency

## 11.1 Initial privacy profile

Version 1 uses a single explicit profile:

> **Tor-only interactive delivery, padded ciphertext, no claim of mixnet-grade traffic-analysis resistance.**

Clients send promptly and retrieve through bounded long-polling or an equivalent established receive channel.

Padding uses a small fixed set of buckets. It reduces precise length disclosure but does not conceal activity timing.

No cover-traffic claim should be made until an actual scheduler and its leakage have been analyzed.

Tor itself does not promise protection against an observer capable of correlating relevant traffic at both ends. [Support](https://support.torproject.org/about-tor/security/attacks-on-onion-routing/)

## 11.2 Known leakage

The mailbox can observe queue identifiers, repeated credentials, padded sizes, arrival and retrieval times, retention classes, and provisioning relationships.

The selected crypto profile may also expose handshake or ratchet headers.

The recipient knows the content it receives and can retain or disclose it. Sending content to a hosted model discloses it to that processing environment.

No part of the product should be described as “zero metadata.”

## 11.3 Proposed initial defaults

These are engineering starting points, not measured optimal values.

| Limit | Initial proposal |
|---|---|
| Invitation acceptance window | 24 hours |
| Temporary support relationship | 2 hours, configurable |
| Ordinary message retention | Up to 7 days, constrained by relationship policy |
| Application body | 64 KiB maximum |
| Stored ciphertext | 256 KiB maximum |
| Padding buckets | 4, 16, 64, and 256 KiB |
| Fetch batch | At most 16 envelopes and 1 MiB |
| Long-poll wait | At most 25 seconds |
| Receipt window before an end-to-end retransmit | 1 hour, doubling per copy (ADR-006) |
| End-to-end retransmits per message | At most 5 (ADR-006) |
| Retention slack below the mailbox's maximum | 1 hour (ADR-008) |
| Retention deadlines offered per append | At most 4, each halving the lifetime (ADR-008) |
| Sealed invitation held for a ticket | At most 16 640 bytes, charged to the inviter's queue, deadline within the message retention bound (ADR-009) |
| Ticket text | At most 192 bytes read; tickets are 130 (onion) or 74 (loopback) characters (ADR-009) |
| Initial queue capacity | 64 MiB, with separate message/rate limits |
| Ratchet work limits | Fixed by the crypto profile; never unbounded |

The effective retention is constrained by the provider’s allowance, message validity, relationship lifetime, and required key-retention horizon.

Quota enforcement must include both bytes and operations. Many tiny requests can exhaust resources without consuming much storage.

## 11.4 Latency expectations

Interactive mode introduces no deliberate delivery delay.

Delivery latency includes Tor connection establishment when needed, request transit, mailbox persistence, recipient retrieval, and local persistence.

“Seconds-scale on warm connections” may be an engineering target, but no latency guarantee should be published before measurement.

A message arriving at the daemon does not imply immediate model execution.

---

# 12. Lifecycle, deployment, and recovery

## 12.1 Relationship lifecycle

```text
Invited
    → Pairing
    → PendingApproval
    → Active
    → Closing
    → Closed

Terminal alternatives:
Rejected / Expired / Revoked
```

Local revocation takes effect immediately for local delivery and wake policy, even if the provider is unreachable.

Provider capability revocation stops future admission when applied. Neither operation can erase data already copied by the peer.

Closing should send a best-effort authenticated notice, disable new local sends, revoke queue credentials where possible, and apply the configured retention policy.

## 12.2 Restarts, backups, and migration

Ordinary restarts resume committed state.

Restoring an old snapshot is different. The daemon cannot reliably detect all rollback or cloning from local state alone.

Version 1 should require a recovery/re-pairing flow rather than silently resume potentially stale ratchet state. Coordinated live migration and active-active devices are deferred.

This is a real session-management concern: asynchronous messaging specifications explicitly address orphaned sessions and divergence caused by backup restoration and device-state changes. [Signal Messenger](https://signal.org/docs/specifications/sesame/)

## 12.3 Packaging

Ship platform-specific release bundles containing the required ERTS runtime, Gleam application, and native libraries.

The user installs one product. They do not separately install Erlang, Rust, Tor, or a NIF.

Releases should include signed artifacts, a dependency inventory, explicit protocol compatibility, and a reproducible build path.

The first-party provider configuration must be replaceable. Operators can choose another provider without changing the local agent API, although moving an existing relationship requires authenticated route updates or re-pairing.

Independent-provider failover is not silently implied by self-hostability.

## 12.4 Observability

Expose local status for Tor bootstrap, provider reachability, queue capacity, pending outbox work, oldest undelivered message, and relationship state.

Logs must exclude invitation secrets, capabilities, plaintext, and serialized crypto state.

Metrics should avoid remote queue IDs and contact identifiers as labels. Opt-in diagnostic exports must redact secrets before leaving the daemon.

---

# 13. Verification and implementation sequence

## 13.1 Required invariants

The implementation must demonstrate:

| Invariant | Required result |
|---|---|
| No send before commit | Network ciphertext always corresponds to committed local crypto state. |
| No delete before commit | Mailbox acknowledgment follows durable local processing. |
| No mailbox-driven identity substitution | Wrong bundles or identities fail invitation validation. |
| No invitation double consumption | One accepted claimant produces one relationship. |
| No replay-driven local redelivery | Retries do not create new inbox events within the specified deduplication contract. |
| No authority escalation | Delivery permission cannot create execution or administration permission. |
| No silent transport downgrade | Core mailbox traffic cannot fall back to a public transport. |
| Bounded adversarial work | Input sizes, retries, skips, pending operations, and native buffers have hard limits. |

## 13.2 Test strategy

Use deterministic simulations of the pure state machines with injectable clocks, randomness, transport results, and storage failures.

Crash tests should stop execution at every important boundary: after crypto preparation, before commit, after commit, after network submission, after remote acceptance, before local receipt persistence, and before mailbox acknowledgment.

Property tests should reorder, duplicate, omit, and corrupt envelopes; race invitation claims; expire capabilities; and exhaust quotas.

Fuzz the wire decoders, native event boundary, invitation parser, and cryptographic integration.

An integration suite must exercise two real daemons and a mailbox over Arti, not only mocked byte streams.

The release gate includes tests that sensitive data does not appear in logs, command arguments, or diagnostic exports.

## 13.3 Milestones

**First: durable messaging skeleton.** Local API, mailbox operations, persistence, and deterministic failure tests using a test-only crypto provider.

**Second: real pairing and encryption.** Freeze the crypto profile, implement single-use invitations, and prove atomic state handling.

**Third: Arti integration.** Real onion connections, bounded NIF events, service hosting, and restart recovery.

**Fourth: agent usability.** Packaged CLI, scoped adapters, customer-support flow, and operational diagnostics.

**Fifth: security hardening.** Fuzzing, independent review, dependency review, load limits, and adversarial integration testing.

The test crypto provider must never be available as a selectable production mode.

---

# Appendix A — L402 and Lightning onion-message extensions

These extensions should attach to the core’s existing admission and delivery interfaces. They must not require redesigning end-to-end sessions.

## A.1 L402: paid mailbox capacity

L402 can fund queue provisioning, storage leases, longer retention, and delegated return postage.

Its standard HTTP flow returns a payment challenge and accepts a credential together with the payment preimage. Credentials can be delegated and restricted. [Lightning Engineering Docs](https://docs.lightning.engineering/the-lightning-network/l402)

The proposed integration point is:

```text
Mailbox request
    → ordinary capability validation
    → resource-entitlement validation
    → atomic quota reservation
    → ordinary mailbox operation
```

A paid entitlement does not replace contact authorization.

**Postage buys infrastructure; it does not buy execution rights.**

The client should normally purchase bounded capacity in advance, avoiding a payment round trip for every message.

A support invitation can include prepaid return capacity so the customer needs no wallet.

Usage limits require durable accounting even when payment authorization can be checked cryptographically. Retries must reuse the same reservation and must not charge twice.

Longer retention must remain compatible with recipient policy and key-retention horizons.

## A.2 Lightning onion messages: non-Tor ingress

A mailbox may expose an additional ingress:

```text
LN-native sender
    │
    │ Lightning onion message
    ▼
Mailbox LN adapter
    │
    │ Same typed Append command
    ▼
Admission + quota + durable storage
    ▲
    │ Tor retrieval
    │
Recipient daemon
```

**The sender need not use Tor.** It can deliver an already end-to-end-encrypted envelope to the mailbox through Lightning.

The mailbox’s LN endpoint terminates the Lightning routing layer, not the agent encryption layer.

The adapter should accept only explicitly supported mailbox operations addressed to that service. It must not become an unrestricted proxy for arbitrary Tor destinations.

BOLT 4 defines onion messages as unreliable and does not require intermediate storage. Its recommended packet sizes are 1,366 or 32,834 bytes, which are not equivalent to available application payload. [GitHub](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)

Therefore the initial extension should support small envelopes, invitations or enrollment exchanges that fit, receipts, and control messages. It must advertise a carrier-specific size limit. Bulk fragmentation is a separate extension.

Offline persistence begins only when the mailbox accepts the message.

## A.3 Shared semantics

The LN ingress MUST preserve:

```text
QueueId
EnvelopeId
immutable ciphertext
admission scope
retention bounds
idempotency behavior
receipt semantics
```

Retries through an allowed alternative carrier must not create a second logical message or consume capacity twice.

A mailbox acceptance receipt should return through an explicit LN reply path or another agreed route. A complete LN-only client also needs a specified retrieval/notification mechanism; ingress alone is not a full bidirectional transport implementation.

## A.4 Synergy and limits

L402 can purchase access to the mailbox reached through onion messages. Credentials could be acquired through the HTTP endpoint first, or through a separately specified challenge exchange over LN.

That exchange would be a new binding; BOLT 4 does not supply it.

Payment funds the endpoint’s storage and admission service. It does **not** automatically compensate every forwarding node or solve routing-layer DoS.

The relationship must explicitly permit LN ingress. Transport changes cannot be treated as privacy-equivalent, and the system must not claim that application encryption makes the carrier’s metadata protections identical to Tor.

---

**The central design invariant is: every meaningful transition belongs to a durable, typed Gleam state machine; every network is a delivery mechanism; and every received message remains a request until local policy authorizes more.**
