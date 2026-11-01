# Next

**Read this first.** This is the handoff between sessions: where the tree
stands against the plan of record, what to work on next, the rulings
already made so nobody re-litigates them, what is deliberately left open,
and how to verify a change. Rewrite it when you finish a body of work.

It is deliberately not a history; the git log and the PR bodies carry how
each change was reviewed. This edition was written 2026-10-31 against the
scaffold at `05eeeea`, then revised the same day to record the owner's
rulings on the design review (`docs/review/2026-10-31-design-review.md`).
Every claim below was checked against the tree it was committed with.

---

## Where the tree is

The plan of record is `docs/spec.md` (the core system specification, v0.1)
read with `docs/design-intent.md` (motivation, decision status, sequence).
The spec's milestones are §13.3; the design intent puts feasibility work in
front of them (§15).

| Phase | Body of work | Where it stands |
|---|---|---|
| 0 | Feasibility: Arti sidecar, PQ crypto over OTP, packaged runtime (design intent §15) | Not started. No Rust in the tree. ML-KEM-1024 through OTP's `crypto` was round-tripped by hand on the development machine; nothing is committed. |
| 1 | Durable messaging skeleton: pure core, SQLite, mailbox over localhost HTTP, fake crypto under `test/` only (spec §13.3, first) | Not started. `core/limits` holds the §11.3 provisional limits and nothing else. |
| 2 | Real pairing and encryption: PQXDH and the Double Ratchet in Gleam, `CryptoProfileV1` frozen with test vectors | Not started. |
| 3 | Tor delivery path: the Arti sidecar, onion-service mailbox, one isolation group per queue, restart recovery | Not started. |
| 4 | The demonstration: two daemons, two sandboxed agents, CLI with JSON output, per-pairing message budget, packaged release | Not started. |
| 5 | Security hardening: fuzzing, review, load limits | Not started. |

The spec still describes Arti as a NIF (§10.3) and the root `CLAUDE.md`
still gives Rust a cryptographic role. Both change through the ADRs that
close phase 0, not by silent edit.

What exists is tooling. `packages/lint` is loom's house lint carried over
with loom's package tables replaced (`lint/policy`, `lint/qualified`):
`core` is the one portable package (R6), and the harness and import-wall
tables are empty. `packages/core` is a pure package with one module.
`make check` runs format, a warning-free build, both test suites, the lint
and the doc check.

## What to do next

In this order. The first item is a body of work; the rest are smaller and
can be interleaved by whoever is not on it.

### 1. Feasibility spikes, each ending in an ADR

Three narrow experiments, per `docs/design-intent.md` §15, before any
framework is built around their assumptions:

- **Arti as a sidecar.** A small `reedwire-tor` Rust binary on
  `arti-client` and the onion-service crates, run from an Erlang port and
  exiting when its stdin closes. One BEAM opens an onion stream to another
  BEAM's onion service through it; then kill the sidecar mid-stream and
  show the VM survives and the port owner restarts it. Show that a slow
  reader pushes back to the sender through the socket rather than through
  hand-built read credit (spec §10.4). This replaces the NIF of §10.3.
- **PQ crypto over OTP.** Thin bindings to `crypto` for ML-KEM-1024,
  X25519, Ed25519, ChaCha20-Poly1305 and HMAC, HKDF over HMAC checked
  against RFC 5869's vectors, and a PQXDH handshake plus one ratchet step
  as pure Gleam over those primitives. Show a crash injected between
  prepare and commit leaves the stored state usable (spec §5.3).
- **The packaged runtime.** One release bundle with ERTS, the Gleam
  application, the sidecar, and an OpenSSL of at least 3.5 (OTP's ML-KEM
  needs it; Ubuntu 24.04 ships 3.0), run on a host with no Erlang, Rust or
  OpenSSL development install (spec §12.3).

Exit: three ADRs under `docs/adr/`, each recording toolchain versions,
licenses, the measured result, and the limitation found.

Note what this does *not* do: no protocol types, no storage schema, no CLI.
A spike that grows into the implementation has stopped being a spike.

### 2. The pure core of the durable skeleton

Domain types and `transition` functions for the outbox and inbox paths
(spec §8.2, §8.3) in `core`, with injected time, randomness and outcomes,
and property tests that stop at every crash point in §13.2. This can start
in parallel with item 1, since `core` is pure and depends on none of the
spike outcomes.

Exit: the §13.1 invariants "no send before commit", "no delete before
commit" and "no replay-driven local redelivery" each held by a property test
that a mutation breaks.

### 3. A CI job for `make check`

Exit: the gate runs on every push to `main` and every pull request.

## Rulings already made

Each of these is settled. Re-open one only with new evidence, and record the
reopening where the ruling lives.

- **Build an independent system, not a wrapper around SimpleX, Loopix or
  Katzenpost** (`docs/design-intent.md` §1, §4).
- **Gleam/BEAM owns protocol state, persistence coordination, policy and
  supervision; Rust is a narrow native boundary** (§4, §6).
- **Tor-first through Arti; no silent public-network fallback** (§4; spec
  §6.1).
- **Standalone daemon and CLI; Loom is an adapter, never a dependency**
  (§4).
- **Offline delivery through recipient-selected ciphertext mailboxes**
  (§4; spec §2.2).
- **Invitation-based pairing with pairwise identities and per-invitation
  prekey bundles, no global directory** (§4, §8; spec §4.1).
- **Reuse established cryptographic constructions; invent no primitives**
  (§1, §9).
- **Tor-first stays; no clearnet carrier in v1.** Tor gives NAT traversal
  and location hiding. The connection layer sits behind the mailbox command
  boundary so other carriers, Lightning onion messages first, come later
  (review, "Rulings after the review").
- **Not an enterprise tool.** The vendor-support flow is a demonstration,
  not the product's centre (review).
- **Post-quantum from day one: PQXDH, then the Double Ratchet**, with a
  version field that leaves room for the sparse post-quantum ratchet
  (review). The primitives come from OTP's `crypto`; the protocols are
  written in Gleam with the ratchet state as a value. A phase 0 ADR
  records the evidence.
- **Every agent is sandboxed, and pairing grants a bounded message
  budget**, so a pairing is not an unlimited prompt-injection channel. The
  daemon's state directory is outside the agent's sandbox (review).
- **One agent principal per daemon in v1**; the `AgentId` column stays
  (review; spec §9.1).
- **HTTP is the first mailbox protocol; QR invitations are a
  nice-to-have.** File invitations embed the PQ bundle (review).
- **L402 and Lightning onion-message ingress are extensions; the core does
  not wait on them** (§4, §14; spec Appendix A).

## Deliberately open

Named, with the section that frames each. None of these is unfinished work
somebody forgot.

- **The exact crypto profile** (design intent §17; spec §5.2). The
  direction is ruled; the KDF labels, transcript bytes and prekey
  signature scheme (Ed25519 identity key rather than XEdDSA is proposed)
  are undesigned.
- **Arti as a sidecar** (§17; spec §10.3). Proposed by both reviews and
  not yet ruled; the phase 0 crash test settles it.
- **Local secret protection at rest and unattended startup** (§17).
  Undesigned.
- **Wire encodings, transcript bytes, error categories, version
  negotiation** (§17; spec §6.1). Undesigned. The review proposes
  BOLT-style TLV for everything signed, hashed or sent, and msgpack or
  JSON for the local API and storage, in place of the spec's protobuf.
- **Bounded handling of expired and malformed traffic** (§17). Undesigned.
- **Backup, export and recovery semantics** (§17; spec §12.2). Undesigned.
- **First supported platforms and the first-party mailbox provisioning
  flow** (§17). Undesigned.
- **Group messaging, public discovery, multi-device** (§4). Deferred by
  ruling, not by omission.

## How to verify

`make check` is the full gate: `gleam format --check`, a warning-free
build, every package's tests, `make lint` (errors gate) and
`make doc-check`. `make check-<package>` runs one package's share of it.

Hazards, each of which has cost real time in loom and applies here:

- **Verify a gate by its own exit code.** Capture the status of the command
  you care about, not of the `tail` after it.
- **A long-lived tree's build cache can lie.** Check a fresh worktree
  before calling a failure in an untouched package a flake.

`docs/execution.md` is the rest: how a wave is planned, how sub-agents are
briefed and monitored, the standard of proof, and why a correction goes on
the issue rather than only in a commit.
