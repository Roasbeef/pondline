# Implementation handoff: Pondline
## Design intent, architectural context, and implementation guidance

**Working name:** Pondline. The name is provisional; no domain, package, or trademark clearance has been established.

**Project status:** Architecture and specification stage. This discussion has not established a working implementation, completed security review, production deployment, or measured performance.

**Companion document:** *Pondline: Core System Specification, Version 0.1.* That document describes the proposed protocol and state transitions. This handoff explains the motivations, decisions, tradeoffs, and implementation priorities behind them.

---

## 1. Your mandate

You are implementing a **standalone, encrypted, asynchronous communication system for independently operated agents**.

The intended experience is:

> Tell an agent to install the application, create or import an invitation, and communicate with another agent—even when the agents use different frameworks, belong to different organizations, and are not continuously online.

The system must not require Loom. Loom is a likely early integration and a source of architectural experience, not a prerequisite.

The owner has explicitly chosen to build an independent system. Existing projects—including SimpleX, Loopix, and Katzenpost—were considered. Their overlap was discussed, and the decision to proceed is intentional.

There are two complementary motivations:

**Product motivation:** Make private, bounded collaboration between independently controlled agents easy.

**Engineering motivation:** Build something new while exercising and validating a Gleam/BEAM stack, including native integration with Rust and Arti.

Do not reinterpret the assignment as “find the smallest SimpleX integration.” That outside-view analysis has already happened.

Equally, do not interpret “build something new” as permission to invent cryptographic primitives or replace established constructions without justification.

**Build our application architecture. Reuse sound cryptographic and networking foundations.**

---

## 2. The product in one sentence

> **Give any compatible agent a private, durable line to another agent, without giving either side control over the other’s environment.**

“Compatible” means the agent can execute the CLI or access a supported local tool/API integration. The product cannot install itself inside a closed environment that exposes neither.

The basic interaction is:

```text
Install → invite → approve → communicate → disconnect
```

For continuing relationships:

```text
Install → establish contact → exchange durable messages over time
```

The tool should feel like a small communications utility, not a new agent framework.

### The motivating use case

A vendor is helping a customer debug a problem.

The vendor’s agent creates a temporary support invitation. The customer gives that invitation to their existing agent. The agents exchange diagnostic requests, approved logs, hypotheses, and results.

The customer’s agent controls what happens locally. A proposed configuration change still requires whatever approval its host normally enforces.

This is **agent-assisted collaboration**, not an encrypted remote shell.

A second useful case is persistent cooperation between agents owned by different people: requesting a review, handing off research, exchanging a bounded task, or returning an artifact after the other side reconnects.

Do not optimize the initial product around continuous token streaming or tightly coupled remote procedure calls. The natural unit is a message, request, result, or small artifact.

---

## 3. Where the design came from

### Pond provided the starting point

The original exploration concerned Pond and its attempt to address more than message confidentiality. Particularly interesting was its distinction between an authorized sender and a globally identifiable sender. Pond used group signatures so a server could reject messages from non-contacts without identifying which contact sent an accepted message. Its repository now describes the project as being in stasis. [GitHub](https://github.com/agl/pond)

The lessons we want to carry forward are:

**Treat metadata as part of the threat model.** Encryption is not a reason to ignore addresses, timing, identifiers, or service relationships.

**Support asynchronous delivery.** A recipient should not need to be online when a sender submits work.

**Control admission before spending substantial resources.** An address must not imply unlimited permission to occupy an inbox or wake an expensive agent.

We are **not** copying Pond’s implementation, reproducing its entire cryptographic design, or claiming its precise anonymity properties.

In particular, our initial per-relationship queues and reusable admission capabilities make activity linkable within a queue. That is an explicit simplification, not an equivalent replacement for anonymous group-signature authorization.

### The scope evolved from “agent messaging” to “standalone agent connectivity”

The initial discussion referenced Loom because the owner is developing expertise in Gleam/BEAM. The scope was subsequently clarified:

> This must work with other agents simply by installing the tool and exchanging an invitation.

Preserve that distinction throughout the codebase. Loom-specific concepts belong in an adapter, not the wire protocol.

### Lightning became an extension, not the core dependency

Lightning payments were introduced as a way to fund retention and limit resource abuse. Lightning onion messages were introduced as an additional path into the system.

Neither should be required for the first successful Tor-based conversation.

The architecture should make them straightforward to add without making the initial implementation pay the complexity cost of implementing them prematurely.

---

## 4. Decision status: what is settled and what is not

| Area | Direction |
|---|---|
| Independent implementation | **Settled.** Build the proposed system, not a wrapper around another messaging platform. |
| Primary application stack | **Settled.** Gleam/BEAM owns protocol state, persistence coordination, policy, and supervision. |
| Initial networking | **Settled.** Tor-first, using Rust Arti through a native integration. |
| Runtime independence | **Settled.** Standalone daemon and CLI; Loom is an adapter. |
| Offline delivery | **Settled.** Recipient-selected ciphertext mailboxes. |
| Pairing | **Settled direction.** Invitation-based, with pairwise identities and asynchronous establishment. |
| Default operations model | **Settled direction.** Managed by default, self-hostable through the same protocol. No hosted service exists merely because the design calls for one. |
| Persistence | **Proposed baseline.** SQLite, explicit durability, transactional inbox/outbox and cryptographic-state updates. |
| Network binding | **Proposed baseline.** Bounded HTTP requests with binary bodies over onion streams. |
| Cryptographic profile | **Not frozen.** Existing asynchronous key agreement plus a ratchet; implementation and exact profile require evaluation. |
| Numeric limits and CLI spelling | **Provisional.** Sensible starting values, not immutable contracts. |
| L402 and LN delivery | **Planned extensions.** Preserve the necessary interfaces; do not block the core on them. |
| Public discovery, groups, multi-device | **Deferred.** Do not build these into the first release. |

When a concrete implementation problem requires changing a proposed detail, document the change and its consequences.

Do not silently change a security property because a dependency makes the original design inconvenient.

---

## 5. The reference user journey

The complete customer-support scenario is the best integration test of the product.

### A. The vendor creates a session

The vendor tells its agent:

> “Open a private support session for this issue. Expire it after two hours. Do not request credentials or unrelated customer data.”

The tool creates an invitation, inbound mailbox route, relationship-specific identity, and public handshake material.

The operator shares the invitation through an already trusted support conversation.

An invitation is **data**, not a script. It must not contain executable installation instructions that the recipient blindly follows.

### B. The customer joins

The customer tells its existing agent:

> “Install Pondline from its official distribution and join this session. Help diagnose the issue. Ask before changing anything.”

Installation should provide the daemon, CLI, required runtime, and native libraries. Users should not separately configure Erlang, Rust, Tor, or NIF loading.

The customer imports the invitation and approves the relationship.

The UI or CLI should distinguish the invitation’s claimed display name from independently established identity. The existing trusted channel is what gives the invitation its meaning.

### C. The agents collaborate

The vendor requests a version number and a bounded diagnostic summary.

The customer agent executes permitted local diagnostics, redacts material according to its host’s policy, and returns results.

If the vendor requests a change, the customer agent asks for approval where required.

**The transport carries the request. It does not authorize the operation.**

A “read-only” label in a prompt is not a security boundary. Actual restrictions must come from the agent host or a deliberately constrained diagnostic adapter.

### D. A runtime disconnects

The mailbox retains undelivered ciphertext within its limits.

When the runtime returns, it retrieves and commits messages before acknowledging them. The agent host resumes its work through durable local events.

### E. The session closes

The relationship expires or an operator closes it. New local sends and wakeups stop according to policy, and mailbox credentials are revoked where possible.

Closing does not retract data the peer has already received.

---

## 6. Architectural shape and responsibility boundaries

The system has three roles:

```text
Agent host
    │
    │ Scoped local API
    ▼
Client daemon
    │
    │ Tor / Arti
    ▼
Recipient's mailbox
    ▲
    │ Tor / Arti
    │
Recipient daemon
    │
    │ Scoped local API
    ▼
Recipient agent host
```

Replies use a corresponding queue in the other direction.

### Client daemon

The daemon owns identities, contacts, pairing, session encryption, durable inbox/outbox state, retries, delivery status, and the local API.

It does not own the agent’s reasoning loop or general tool execution.

### Mailbox service

The mailbox stores ciphertext and public handshake material. It enforces admission, quotas, expiration, and acknowledgment semantics.

It does not receive message-decryption keys.

A single mailbox service can host many queues and many agents. An agent does not need a dedicated onion service.

### Agent adapter

The adapter exposes the daemon to an agent host.

Start with a CLI and stable machine-readable output. Add MCP and native SDK integrations over the same local API.

Do not create separate messaging implementations for each adapter.

### Gleam and Rust

**Gleam owns the application.** Rust provides native networking and the selected cryptographic integration.

Arti explicitly supports Rust API integration and custom FFI wrappers, making the proposed embedding strategy consistent with its intended integration model. [Arti](https://arti.torproject.org/integrating-arti/)

Do not gradually move the application into Rust until Gleam becomes a launcher. The point is to exercise Gleam meaningfully while using Rust where its libraries and native interfaces are appropriate.

---

## 7. Identity and authority must remain separate

Several concepts that might otherwise collapse into “the agent” need distinct representations.

**Local agent identity** is a durable principal inside one daemon.

**Pairwise identity** is what a particular contact recognizes.

**Cryptographic session** is one evolving encryption relationship.

**Mailbox route** is where ciphertext is deposited.

**BEAM process identity** identifies the actor currently managing some work.

Restarting an actor must not change a contact’s identity. Changing a mailbox must not automatically mean changing the peer. Forking an agent must not duplicate writable ownership of a live cryptographic session.

There are also four separate kinds of authority:

| Authority | What it means |
|---|---|
| Peer authentication | This message belongs to the expected cryptographic relationship. |
| Delivery admission | This sender may occupy bounded mailbox resources. |
| Resource entitlement | Someone has sponsored or purchased the necessary capacity. |
| Execution permission | The local host permits the requested work. |

None implies the next.

A paid sender is not necessarily an approved contact. An approved contact cannot necessarily wake the agent. A valid request cannot necessarily modify a file.

Mailbox admission credentials are not end-to-end identity credentials. The mailbox controls its own admission checks and must not be able to impersonate a peer merely by bypassing them.

---

## 8. Pairing and prekeys: preserve the intended simplification

The proposed first version uses **invitation-specific prekey bundles**, not a public directory or a general multi-device prekey service.

The inviter generates the private material locally and uploads only the public bundle to its mailbox. The invitation pins the expected identity and bundle.

The joiner fetches that material and establishes encryption while the inviter may be offline. This is the asynchronous setting that protocols such as PQXDH are designed to support. [Signal Messenger](https://signal.org/docs/specifications/pqxdh/)

### Two different secrets serve two different purposes

*Superseded by ADR-013.* The invitation embeds the prekey bundle and carries no join secret, so no mailbox can run the handshake. What follows is the original reasoning.

The invitation contains a mailbox enrollment capability and a separate high-entropy **join secret**.

The enrollment capability lets the mailbox authorize a fetch or claim.

The join secret authenticates possession of the invitation to the inviter. It is carried inside the encrypted initial message and must not be uploaded to the mailbox in plaintext.

Do not collapse them. A server-known token must not become the sole proof that the peer was invited.

### Pairing is a durable state machine

The joiner persists its pairing attempt before network operations.

It sends an encrypted `Hello` containing the invitation binding and a return route, under a handshake that authenticates its identity.

The inviter validates the cryptographic message and invitation before consuming the invitation or accepting the peer.

A valid claim may await local approval. Application messages must not reach the host as actionable work before authorization.

Mailbox claims and network retries must be idempotent. Losing a response must not force the joiner to generate a new identity or a second unrelated handshake.

### Invitation theft remains meaningful

A bearer invitation can be stolen and raced. The system cannot infer the intended human from possession alone.

Sensitive deployments may require an independently pinned identity or explicit fingerprint verification.

Do not market the invitation flow as solving trust establishment without a trusted sharing channel.

---

## 9. Cryptography is a release gate, not a placeholder to hide

The reference direction is asynchronous authenticated establishment followed by a ratchet.

The exact implementation must be selected based on correctness, review history, licensing compatibility, supported interfaces, bounded resource behavior, and persistence integration.

PQXDH’s documented properties do not mean every aspect of the resulting system becomes post-quantum: its authentication remains based on classical assumptions. Likewise, Signal distinguishes the classical Double Ratchet from its post-quantum and hybrid ratchet constructions. [Signal Messenger](https://signal.org/docs/specifications/pqxdh/)

Choose and document a specific profile. Do not use the word “post-quantum” as a substitute for describing it.

If evaluating `libsignal`, account for its maintainers’ explicit statement that use outside Signal is unsupported and APIs may change. It is a candidate to investigate, not an assumed drop-in stable dependency. [GitHub](https://github.com/signalapp/libsignal)

### The most important integration requirement

The crypto implementation must allow the application to prepare a candidate state and ciphertext **without irreversibly advancing hidden state before persistence**.

Conceptually:

```text
prepare_send(current_state, plaintext)
    → candidate_state + immutable_ciphertext

prepare_receive(current_state, ciphertext)
    → candidate_state + authenticated_plaintext
```

The new state becomes authoritative only when the relevant database transaction commits.

If a library’s callbacks mutate prekeys, sessions, or skipped-key stores, those mutations must participate in the same transactional contract.

A working encrypt/decrypt demo is not sufficient evidence that this integration is correct.

Test-only fake cryptography may help develop state machines. It must be impossible to select in a production build.

---

## 10. Durability is the central correctness problem

Treat cryptographic state, message state, and delivery state as one coordinated system.

### Sending

```text
Validate local permission
    → prepare ciphertext and candidate session state
    → atomically persist state + immutable outbox item
    → commit
    → attempt transmission
```

Never transmit a candidate whose persistence failed.

After commit, retries reuse the same envelope and ciphertext. They do not rerun encryption because a response was lost.

### Receiving

```text
Fetch ciphertext without deleting it
    → authenticate and decrypt
    → atomically persist session changes + inbox/deduplication + receipt work
    → commit
    → acknowledge the mailbox
```

Invalid ciphertext must not advance authoritative state.

Outer envelope identifiers must not let unauthenticated input poison the authenticated message-deduplication records.

### Acknowledgments represent different facts

The following are distinct:

```text
Accepted into local outbox
Stored by mailbox
Durably received by peer
Consumed by peer's adapter
Executed by peer's application
```

Do not collapse them into “delivered.”

The mailbox can attest only to its own acceptance. `ReceivedByPeer` requires an authenticated peer receipt.

The core should not claim that a task completed merely because the adapter consumed an event.

### Exactly-once execution is outside the transport contract

The daemon can suppress duplicates and provide durable delivery.

An external effect may still require a downstream idempotency key, a transaction, or an “outcome unknown” result after a crash.

A remote cancellation request similarly does not prove that execution stopped.

### Single-writer ownership is mandatory

An actor may serialize ordinary session operations, but the database also needs version checks or equivalent concurrency protection.

One runtime owns a live session. Copying a state directory and running two copies is unsupported.

A stale backup must not silently resume a ratchet that may have advanced elsewhere. Recovery needs an explicit reset or re-pairing path.

---

## 11. Use Gleam/BEAM deliberately

The preferred structure is a pure protocol core surrounded by processes that perform effects.

```text
transition(state, event)
    → proposed durable changes
    → pending work
    → effects permitted after commit
```

Time, randomness, network completion, and storage failure should be injectable inputs.

This makes the same logic usable in production actors and deterministic tests.

### Code organization should make ownership obvious

Keep relationship state, mailbox protocol, storage coordination, native transport, and local API in separate modules.

Use explicit domain types rather than generic maps for protocol state.

Avoid deeply nested callbacks or overly abstract combinator layers that make lifecycle transitions difficult to follow. The owner wants to build Gleam fluency, not navigate an unnecessarily opaque functional framework.

A reasonable process structure includes a storage coordinator, relationship actors, delivery scheduler, provider connection workers, native bridge, and local API server.

Not every stored queue or message needs a permanent actor. Durable records are not processes.

### Native integration must be asynchronous and bounded

Arti should run on a Rust asynchronous runtime. NIF entry points submit work and return promptly; completions arrive as events.

Erlang’s NIF documentation warns that lengthy native work harms VM responsiveness and that native crashes can crash the entire VM. It also documents asynchronous/threaded approaches. Supervision of a Gleam actor does not isolate a native crash. [Erlang.org](https://www.erlang.org/doc/apps/erts/erl_nif.html)

Therefore, design read credit, bounded write queues, operation ownership, cancellation, deadlines, and cleanup on owner death.

Late events from an old connection or actor generation must not mutate a replacement session.

Never turn arbitrary network strings into atoms. Never treat untrusted bytes as arbitrary Erlang terms.

An external service supervisor is still necessary for whole-process recovery.

**Do not use distributed Erlang as the inter-agent protocol.** Remote peers are not trusted members of the runtime.

---

## 12. Privacy and usability should be honest

### The initial privacy profile is deliberately limited

The first version is:

> Tor-only interactive messaging, padded ciphertext, explicit metadata limitations.

It is not a new mixnet. It does not claim protection from a global traffic observer. It does not silently switch to a public endpoint when Tor is unavailable.

The mailbox may observe queue activity, repeated credentials, padded sizes, timing, retention choices, and provisioning associations.

The selected cryptographic profile may expose some headers. Record exactly which ones.

### The endpoint remains a trust boundary

The recipient can copy plaintext. A hosted model may receive the content its agent passes to it.

The tool does not magically prevent a model provider from seeing content deliberately submitted to that provider.

Keep private keys, invitation secrets, and mailbox credentials out of model context and tool output.

Also keep them out of logs, command arguments, tracing attributes, crash dumps where practical, and diagnostic exports.

### Managed by default is a product commitment

The long-term default experience assumes a first-party operated mailbox service, with replacement providers and self-hosting available.

Development can begin with a local or self-hosted service. Do not confuse that with having delivered a seamless public onboarding experience.

The packaged product should hide routine key generation, prekey maintenance, retry behavior, and Tor bootstrap behind clear status.

Users should see:

> Waiting for recipient  
> Stored until the retention deadline  
> Connection approval required  
> Mailbox capacity exhausted

—not raw cryptographic or networking internals.

---

## 13. Keep the first implementation narrow

The first useful release needs the daemon, mailbox server, CLI, scoped local API, invitation pairing, encrypted delivery, persistence, and failure recovery.

Small binary artifacts can travel inside bounded messages.

It does not need a human chat interface, public directory, global usernames, group chat, marketplace, distributed workflow engine, active-active devices, bulk attachment service, or plugin architecture for every conceivable network.

The prior specification’s starting limits included a 64 KiB application body, a 256 KiB maximum stored ciphertext, bounded fetch batches, and finite queue quotas. These are provisional engineering defaults.

Keep limits centralized, advertised where necessary, and tested. Do not scatter them through unrelated modules.

### Narrow extension points are enough

Preserve a typed mailbox command boundary, a cryptographic provider boundary, a local adapter boundary, and a resource-entitlement check.

Do not build an elaborate abstraction hierarchy for hypothetical future systems.

For example, a network adapter should ultimately produce something like:

```text
AppendEnvelope {
    queue_id
    envelope_id
    admission
    retention_request
    ciphertext
}
```

The admission and storage implementation should not need to know whether the request arrived through HTTP over Tor or a future Lightning adapter.

---

## 14. Appendix-level extensions: L402 and Lightning onion messages

These are strategically important but remain secondary to the core.

### L402: funding mailbox resources

The intended purchases are mailbox leases, bounded storage, longer retention, and return postage.

Prefer prepaid capacity or bounded service allowances to a new payment for every message.

L402 provides an HTTP challenge flow and payment-linked bearer credentials that can be delegated and restricted. It does not by itself implement our storage quotas or consume a message allowance exactly once. [Lightning Engineering Docs](https://docs.lightning.engineering/the-lightning-network/l402)

Our service must atomically account for consumption and recognize retries.

The key customer-support experience is:

> The vendor sponsors the session. The customer joins without setting up a Lightning wallet.

A future invitation can delegate limited return capacity without exposing the sponsor’s wallet credentials.

Payment does not override recipient admission, execution policy, retention policy, or capacity limits.

Longer storage also requires compatible key-retention behavior. It is not enough to keep ciphertext after the recipient has discarded the material necessary to process it.

L402 also introduces correlation: do not describe ordinary reusable payment credentials as unlinkable postage.

### Lightning onion messages: non-Tor ingress

The intended architecture includes:

```text
LN-native sender
    → Lightning onion message
    → mailbox LN adapter
    → existing admission/quota/storage pipeline
    → recipient retrieves over Tor
```

**The sender does not need Tor in this scenario.**

The LN endpoint terminates the carrier’s routing layer, not the agent’s end-to-end encryption. Inner agent ciphertext remains opaque to the mailbox.

BOLT 4 specifies onion messages as unreliable, with no required forwarding storage or intermediate error response. It recommends packet sizes of 1,366 or 32,834 bytes; those are packet sizes, not available application payload. [GitHub](https://github.com/lightning/bolts/blob/master/04-onion-routing.md)

Start with compact envelopes and control exchanges that fit. Do not assume it is a bulk log-transfer channel.

Mailbox acceptance, idempotency, retention, and peer receipts retain their existing meanings.

A full LN-only client would also require a reply/retrieval mechanism. Implementing ingress alone must not be advertised as complete bidirectional transport support.

### Preserve the distinction

L402 pays the endpoint for a service. It does not automatically pay forwarding peers.

LN onion routing does not replace application authentication.

A payment preimage does not prove storage.

Adding a second carrier does not make its privacy properties equivalent to Tor.

Transport policy must be explicit; no silent fallback or opportunistic duplication across networks.

---

## 15. Implementation sequence

### First, validate the high-risk integration assumptions

Before building a large framework, perform narrow feasibility tests for the Arti NIF, crypto-state persistence, and packaged runtime.

Prove that an onion stream can be opened and serviced asynchronously without scheduler blocking or unbounded native-to-BEAM events.

Prove that the selected crypto library can participate in the transaction model.

Confirm how a user-facing release bundles ERTS and native dependencies.

Record exact toolchain versions, dependency licenses, build steps, and limitations. Do not guess APIs from this handoff.

### Then build the durable core

Implement domain types, state transitions, storage schema, queue operations, and local events using deterministic test dependencies.

Exercise failure boundaries before adding polished onboarding.

SQLite is the proposed first backend; select and test the actual driver and durability configuration. Do not acknowledge persistence merely because an in-memory actor accepted a command.

### Add real pairing and encryption

Freeze a versioned cryptographic profile and test vectors.

Implement identity commitments, invitation claims, encrypted `Hello`/`Accept`, approval, and bounded retry behavior.

Remove any possibility of production use of test cryptography.

### Complete the Tor delivery path

Connect client and server roles to Arti. Enforce endpoint restrictions, request limits, timeouts, backpressure, and restart behavior.

Test with separate daemons and a real onion-service mailbox—not only in-process mocks.

### Deliver the agent experience

Provide the CLI, stable JSON output, scoped local credentials, and clear status.

Demonstrate a session between independently controlled agent hosts. Loom must not be necessary.

Then add the first Loom or MCP adapter without changing core semantics.

### Harden before making strong security claims

Add fuzzing, adversarial simulations, resource-exhaustion tests, recovery tests, dependency review, and an independent security review.

A successful happy-path demo is a milestone, not a security assessment.

---

## 16. Acceptance tests that matter

The implementation should eventually demonstrate the following scenarios:

| Scenario | Expected outcome |
|---|---|
| Inviter goes offline after creating an invitation | Joiner can submit a valid initial message using published material. |
| Mailbox tries to substitute a public bundle | Impossible: the bundle travels in the invitation, not through the mailbox (ADR-013). |
| Mailbox holds a sealed invitation from a ticket | It sees ciphertext and cannot establish an authorized peer identity (ADR-009, ADR-013). |
| Sender crashes after commit but before transmission | Restart sends the committed ciphertext. |
| Mailbox stores a message but its response is lost | Retry returns the existing result without another stored copy or quota charge. |
| Receiver crashes before its local transaction commits | Mailbox still has the message. |
| Receiver crashes after commit but before acknowledgment | Redelivery does not create a second application event. |
| Invalid ciphertext arrives | No authoritative crypto-state mutation occurs. |
| Agent adapter crashes before acknowledgment | Its durable event is available again. |
| Contact is revoked while provider is unreachable | Local wake and execution-facing delivery stop according to policy. |
| Session state is restored from an unsafe stale backup | Recovery is explicit; the daemon does not pretend it can safely resume. |
| Native operation outlives its owner | Resources are reclaimed and stale completions cannot affect new state. |
| Queue or native buffer reaches its limit | Backpressure or rejection occurs without unbounded allocation. |
| Tor is unavailable | Messages remain queued or fail explicitly; there is no public-network fallback. |

Add property-based tests for arbitrary interleavings of duplication, delay, reordering, expiry, revocation, and crashes.

A useful test harness should make a failing event sequence replayable.

---

## 17. Open questions to resolve explicitly

The architecture is chosen, but several engineering choices remain open.

**Cryptographic implementation:** Which library and exact profile meet the persistence and maintenance requirements?

**Native integration:** Which NIF binding approach best supports ownership, cancellation, event bounds, and packaging?

**Local secret protection:** How are keys wrapped at rest on supported platforms, and what does unattended startup require?

**Wire details:** Freeze encodings, authenticated transcript bytes, error categories, and version negotiation. Do not assume a serializer’s output is universally canonical.

**Expired and malformed traffic:** Define bounded handling, acknowledgments, diagnostic recording, and retention without creating poisoning or resource-exhaustion paths.

**Recovery:** Specify the supported backup/export behavior without implying safe rollback of live ratchets.

**Operational deployment:** Decide the first supported platforms and first-party mailbox provisioning flow.

Resolve these through small experiments and architecture decision records. Do not convert every open detail into a reason to postpone the implementation.

---

## 18. Deliverables and final implementation posture

Alongside code, maintain the core specification, threat model, architecture decisions, wire/profile definitions, test vectors, deployment instructions, and a record of unsupported guarantees.

Report progress as **implemented, tested, or still assumed**. Those categories should never blur.

The priorities are:

> **A correct durable core, a comprehensible Gleam architecture, bounded native integration, and a genuinely easy first conversation.**

The owner deliberately wants to build this system. Respect that decision without overstating what the design has proven.

**Build a small standalone communications substrate—not another agent framework. Keep identities independent of processes, encryption independent of carriers, delivery independent of execution, and every consequential state transition durable.**
