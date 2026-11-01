# Next

**Read this first.** This is the handoff between sessions: where the tree
stands against the plan of record, what to work on next, the rulings
already made so nobody re-litigates them, what is deliberately left open,
and how to verify a change. Rewrite it when you finish a body of work.

It is deliberately not a history; the git log and the PR bodies carry how
each change was reviewed. This is the first edition, written 2026-10-31
with the initial scaffold, so there is no previous edition to correct.
Every claim below was checked against the tree it was committed with.

---

## Where the tree is

The plan of record is `docs/spec.md` (the core system specification, v0.1)
read with `docs/design-intent.md` (motivation, decision status, sequence).
The spec's milestones are §13.3; the design intent puts feasibility work in
front of them (§15).

| Phase | Body of work | Where it stands |
|---|---|---|
| 0 | Feasibility: Arti NIF, crypto-state persistence, packaged runtime (design intent §15) | Not started. No Rust in the tree. |
| 1 | Durable messaging skeleton with a test-only crypto provider (spec §13.3, first) | Not started. `core/limits` holds the §11.3 provisional limits and nothing else. |
| 2 | Real pairing and encryption; `CryptoProfileV1` frozen | Not started; blocked on the crypto library choice. |
| 3 | Arti integration: onion connections, bounded NIF events, hosting | Not started. |
| 4 | Agent usability: packaged CLI, scoped adapters, support flow | Not started. |
| 5 | Security hardening: fuzzing, review, load limits | Not started. |

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

- **Arti through a NIF.** Open an onion stream from the BEAM, service it
  asynchronously without blocking a scheduler, and show read credit bounds
  native-to-BEAM events (spec §10.3, §10.4). Compare a NIF against a port
  or a separate OS process given that a NIF crash takes the VM (§10.5).
- **Crypto state under prepare/commit.** Show a candidate library can
  produce a candidate state and ciphertext without advancing hidden state
  before the database commits (spec §5.3). `libsignal` is a candidate with
  an unsupported-outside-Signal caveat (§5.2).
- **The packaged runtime.** One release bundle with ERTS, the Gleam
  application and the native library, run on a host with no Erlang or Rust
  installed (spec §12.3).

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
- **L402 and Lightning onion-message ingress are extensions; the core does
  not wait on them** (§4, §14; spec Appendix A).

## Deliberately open

Named, with the section that frames each. None of these is unfinished work
somebody forgot.

- **The crypto library and exact profile** (design intent §17; spec §5.2).
  Undesigned, and the most load-bearing open question.
- **The native integration approach** (§17; spec §10.3). Undesigned.
- **Local secret protection at rest and unattended startup** (§17).
  Undesigned.
- **Wire encodings, transcript bytes, error categories, version
  negotiation** (§17; spec §6.1). Undesigned; protobuf is a proposal.
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
