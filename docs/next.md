# Next

**Read this first.** This is the handoff between sessions: where the tree
stands, what is in flight, what to work on next, the rulings already made
so nobody re-litigates them, what is deliberately left open, and how to
verify a change. Rewrite it when you finish a body of work.

It is deliberately not a history; the git log and the commit bodies carry
how each change was reviewed. This edition was written 2026-11-01 against
`main` at `c003770` (pushed to `origin/main`). Every claim about `main`
was checked against that tree; claims about the work in progress were
checked against the worktrees named below, as they stood when work
stopped.

The previous edition (scaffold era, `05eeeea`) planned feasibility
spikes, the pure core and a first CI job. The spikes and the core are
long done; its "where the tree is" table described a tree that no longer
exists, and CI still does not exist. This edition replaces it wholesale.

---

## Where the tree is

`make check` exits 0 on `main` (the last full run was on the `reack`
branch head, whose tree `main`'s equals; doc-check rerun on `main`
itself). `make formal` runs the merged formal checks (Lean, P).

| Body of work | Where it stands |
| --- | --- |
| Protocol core (`packages/core`) | Pure `transition(model, event)` state machines, hybrid PQXDH + Double Ratchet, TLV codec, tickets, retention and retransmit policy. Pure simulation swarm in `test/core/world.gleam`. |
| Crypto (`packages/primitives`) | OTP 29 / OpenSSL 3.6 bindings: X25519, Ed25519, ML-KEM-1024, ML-DSA-65, ChaCha20-Poly1305, HKDF. Hybrid authentication (ADR-005). |
| Mailbox (`packages/mailbox`) | SQLite store on generated SQL (ADR-007), HTTP binding, Tor onion hosting, sealed-blob storage for tickets (ADR-009). |
| Daemon (`packages/daemon`) | Engine, scheduler, fetchers, provisioner, carrier, local API, CLI. End-to-end retransmit (ADR-006), deadline slack (ADR-008), dedup, quarantine and re-acknowledged repeats (ADR-010), idempotent accept and keyed send (ADR-011), tickets (ADR-009), build identity. |
| Tor (`packages/tor`, `native/reedwire-tor`) | Arti sidecar over an Erlang port, a weft state machine (ADR-001). |
| Shell DST (`packages/sim`) | Two real daemons and a real mailbox in one VM, seeded, exact replay. Corpus and regression seeds double-run in `gleam test`; `sim.regressions()` is empty (H1, H2 and the re-served repeat all fixed and moved to the corpus). Fault classes include a mailbox restore. |
| Packaging | One self-contained release tree, `make release`, `make release-smoke`, `make install`/`uninstall`, `make dist` (ADR-003 addendum). macOS arm64 tested; Linux recipe written, never run. |
| Formal (`formal/`, `docs/formal/`) | Lean 4 proofs with 11,201 conformance vectors replayed by core (`docs/formal/lean.md`); P model of end-to-end delivery with a mutation and recall judge (`docs/formal/p.md`). |
| Research (`docs/research/`) | Hybrid PAKE survey (recommends CPaceOQUAKE), initiator deniability analysis (recommends deciding before the profile freeze). |

## In flight: three unmerged worktrees

Work stopped on a usage limit with three branches unfinished. Each lives
in a git worktree under `.worktrees/` in the main checkout (local to that
machine; not pushed). Read the worktree's `git status` and log before
continuing; the agent that owned each stopped mid-step, so the uncommitted
state may not build.

1. **Structured logging** (`.worktrees/logging`, branch `logging`, from
   `b6f439f`). Committed: a `telemetry` package (typed logfmt fields over
   Erlang `logger`) and its lint-table registration. Uncommitted: about 39
   files across daemon, mailbox and sim moving call sites onto it and
   wrapping payloads, plus an untracked `docs/adr/012-logging-and-crash-reports.md`
   draft. The goal and the judge: a test that crashes the engine mid-send
   must show that today's OTP crash report prints the plaintext payload
   (`engine.gleam` carries `payload: BitArray` in the actor message), and
   then must pass once a `logger` formatter scrubs crash, supervisor and
   progress reports and the payload is a `Secret` from the local API to
   the engine and back. Tickets and their derived keys get the same
   treatment. **Exit:** the crash test fails on old code and passes;
   `secrets_test` covers injected crashes in engine, scheduler and a
   mailbox request process; mutation (remove the formatter, unwrap the
   payload) fails a test; merged with `main` (it predates the ticket and
   reack merges); `make check` and `make release-smoke` pass.
2. **PlusCal/TLA+ models** (`.worktrees/formal-tla`, branch `formal-tla`,
   from `9c07a47`). Untracked: `formal/tla/{Scheduler,Fetcher}.tla`, 19
   configs (mutants included), `check.sh`, `docs/formal/tla.md`. Results
   so far: TLC reproduces the stale-end-marker interleaving the daemon
   docs said no test could build (claims keyed per batch, as before
   `3035697`), and finds a second, shorter path to the same hazard through
   `NeverStarted` that the code comments never mentioned; the current
   per-run claims close both. The agent was regenerating the fetcher
   configs after renaming modes. **Exit:** `formal/tla/check.sh` passes
   with state counts printed, every mutant fails, the fetcher model
   reflects the dedup-era code (ack before the liveness check, draining
   inboxes) with the pre-fix behaviour kept as the closed-queue mutant,
   merged with `main`, doc-check clean, committed and merged.
3. **Crypto verification** (`.worktrees/formal-crypto`, branch
   `formal-crypto`, from `9c07a47`). Committed: Wycheproof and ACVP vectors
   run through `primitives` (trimmed vector files, dev deps). Untracked:
   ProVerif models `formal/crypto/{pairing,ticket}.pv.in`, `check.sh`,
   `out/` logs, and `docs/formal/crypto.md`. `check.sh` needs `proverif`
   on `PATH` (2.05); it is not on `PATH` in a fresh shell, so find or
   reinstall it (opam). The doc lists eight findings, none a vulnerability
   under the profile's assumptions; see "What to do next", item 4.
   **Exit:** `check.sh` passes, every broken variant yields an attack,
   `out/` either regenerated by the script or left out of git, merged
   with `main`, doc-check clean, committed and merged.

## What to do next

In order. The first is the in-flight work above; the rest can interleave.

1. **Land the three worktrees** above, each by its exit clause, merging
   `main` into the branch first. Gate the merged tree with `make check`
   and run `scripts/doc_check.sh` before every push (see the hazards).
   Then add `docs/formal/README.md` indexing `lean.md`, `p.md`, `tla.md`
   and `crypto.md`. *Cut:* no new models while landing these.
2. **Judge the shell DST** (`docs/dst/plan.md` items 8 to 10). Blind
   recall for the known fixes not yet tried (stale session after send,
   the processed id-and-digest rule, carrier re-bootstrap after
   `SidecarRestarted`, expired-message payloads): revert each in a scratch
   copy, run `gleam run -m sim/swarm -- --seed 1 --runs N --keep-going`,
   record runs-to-find. Then a mutation score of the core state machines,
   coverage under the DST alone (`scripts/dst/cov.erl`), the harness
   architecture document with `/arch-doc`, and one `/advisor-review` of
   the harness asking for false passes. **Exit:** the recall table,
   mutation score and coverage numbers in the arch doc, as printed by the
   tools. *Cut:* the nightly CI job (blocked, see "Deliberately open").
   Run these campaigns alone on the machine: concurrent test suites made
   the daemon's timing tests flaky before.
3. **Resolve the `join_secret` divergence.** `docs/spec.md` §4.2 still
   requires the inviter to check a `join_secret`; `core/invitation.gleam`
   says there is none. The research note and the crypto model both found
   it; no ADR records the drop. Either amend the spec through an ADR
   (the likely outcome: the invitation itself is the authenticator) or
   implement the check. **Exit:** spec and code agree, with the decision
   in an ADR.
4. **Act on the crypto findings** (`docs/formal/crypto.md` once merged):
   state in `docs/crypto-profile-v1.md` §8 that forward secrecy of the
   session key rests on prekey retirement (`offer.consume` dropping the
   stock) and the first DH ratchet step; note in ADR-005 that DH1, not the
   Ed25519 half, is what keeps joiner authentication when ML-DSA-65 falls;
   decide whether Ed25519 verification should reject small-order and
   mixed-order public keys (strict verification); queue for a
   CryptoProfileV2 the binding of `CT || PQSPK` into the HKDF info.
   **Exit:** each finding has a doc change or a recorded decision.
5. **Rewrite this file** at the end of that body of work.

## Rulings already made

Each of these is settled. Re-open one only with new evidence, and record
the reopening where the ruling lives.

**Tor-first, transport abstracted, Arti as a sidecar** (ADR-001).
**PQ from day one over OTP's crypto, no custom crypto library** (ADR-002).
**Self-contained releases with their own ERTS and libcrypto; one tree for
both programs** (ADR-003 and its addenda).
**An authenticated application message in `AwaitingAccept` is an implicit
Accept** (ADR-004).
**Authentication is hybrid Ed25519 + ML-DSA-65; the joiner signs the
transcript; initiator deniability is given up for now** (ADR-005; tracked
in Roasbeef/reedwire#2 and `docs/research/initiator-deniability.md`).
**End-to-end retransmit of the same committed bytes under a fresh envelope
id; receivers answer a known ciphertext with its receipt** (ADR-006).
**SQL is generated by parrot from checked-in `.sql`; parrot is a dev
dependency and its runtime is vendored, trimmed to four parameter kinds;
a shipped migration never changes and is hash-pinned** (ADR-007 and its
addendum).
**A sender's retention deadline sits one hour below the mailbox maximum
and `BadDeadline` is retried with shorter offers; the mailbox stays
strict** (ADR-008).
**Short `rw1` tickets carry the mailbox and a 32-byte key; the invitation
is sealed, key-committed, at the inviter's mailbox; fetching does not
consume it** (ADR-009).
**A repeated message id is ignored and recorded; an envelope that fails
five times is quarantined; a repeat served after its ack is acknowledged
again** (ADR-010 and its addendum).
**A retried accept returns the first relationship; `send` takes an
optional idempotency key** (ADR-011).
**One agent per daemon, a per-pairing message budget, a plaintext audit
log, HTTP for the demo** (`docs/review/2026-10-31-design-review.md`).
**DST policy: exact replay, dedup and quarantine, sender slack and retry**
(`docs/dst/plan.md`, Rulings).

## Deliberately open

None of these is unfinished work somebody forgot.

- **CI.** Undecided: Ubuntu's OTP links OpenSSL 3.0 (no ML-KEM), and macOS
  minutes cost more. Needs the owner's call before a nightly swarm or a
  `make check` job exists.
- **Weft on Hex.** Weft 0.4.7 is pushed to GitHub; `gleam publish` needs
  the owner. Until then daemon, mailbox, tor and sim pin weft by git ref.
- **Hybrid PAKE for spoken codes** (Roasbeef/reedwire#1): researched,
  unbuilt. The recommendation is CPaceOQUAKE (`draft-vos-cfrg-pqpake`),
  which needs Elligator 2 and Kemeleon in pure Gleam.
- **Initiator deniability** (Roasbeef/reedwire#2): undesigned for V1,
  sketched for a CryptoProfileV2.
- **Release signing and Linux.** No Developer ID signing or notarization;
  the Linux release recipe has never run.
- **Known operational gaps.** `raise_budget` is relative, so retrying it
  after a lost answer doubles the grant (ADR-011); `incidents` and
  `attempts` rows are never pruned (ADR-010); blobs have no `DeleteBlob`
  (ADR-009); the ticket's onion path is unit-tested only; a clock that
  jumps back stalls retries until it catches up (ADR-008).

## How to verify

`make check` is the full gate: `gleam format --check`, a warning-free
build, every package's tests, `make lint` (errors gate) and
`make doc-check`. Set `REEDWIRE_TOR_BIN` to a built sidecar and run
`make -o sidecar check` to skip the cargo build in a worktree.
`make formal` runs the formal checks (they need Lean, P and, once merged,
TLC and ProVerif). `make release release-smoke` checks the shipped tree.

Hazards that have cost real time here:

- **Run `scripts/doc_check.sh` before pushing any merge, docs-only
  included.** A docs branch written before another branch moved code
  carried `file:line` citations that had drifted, and `main` failed
  doc-check until the next merge's gate caught it.
- **Verify a gate by its own exit code.** A `| tail` inside an `&&` chain
  hid a failing doc-check and a bad commit landed.
- **Concurrent test suites make the daemon's timing tests flaky.** Re-run
  a timing failure on a quiet machine before diagnosing it, and run DST
  campaigns alone.
- **Adding a package means three lint tables**: `qualified.project_roots`,
  `policy.literate_packages`, and the pinned assertions in
  `lint_test.gleam`, one of which `gleam format` wraps across lines.
- **After editing any `.sql`, run `make gen-sql`** and commit the
  regenerated modules; never edit a shipped migration (the drift test pins
  their SHA-256s); use only Int, String, BitArray and Nullable parameters.
- **A worker stopped by a usage limit leaves uncommitted work.** Read the
  worktree's status before assuming a branch is what its log says.

`docs/execution.md` is the rest: how a wave is planned, how sub-agents are
briefed and monitored, the standard of proof.
