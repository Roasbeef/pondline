# Next

**Read this first.** This is the handoff between sessions: where the tree
stands, what is in flight, what to work on next, the rulings already made
so nobody re-litigates them, what is deliberately left open, and how to
verify a change. Rewrite it when you finish a body of work.

It is deliberately not a history; the git log and the commit bodies carry
how each change was reviewed. This edition was written 2026-11-02 against
`main` after `1e770a7`. Every claim about `main` was checked against that
tree.

The previous edition's three unmerged worktrees have landed, its
`join_secret` and crypto items are closed, and its DST judging is done. Its
expectation that judging would mostly confirm the harness was wrong: judging
found that the harness exercises much less than its fault list suggests, which
is now the first item below.

---

## Where the tree is

`make check` and `make release-smoke` exit 0 on Gleam 1.19.2. `make formal` runs
Lean, P, TLC and ProVerif; each check last passed on the code it models, and no
modelled code has changed since except line positions.

| Body of work | Where it stands |
| --- | --- |
| Protocol core (`packages/core`) | Pure `transition(model, event)` state machines, hybrid PQXDH + Double Ratchet, TLV codec, tickets, retention and retransmit policy. Pure simulation swarm in its tests. |
| Crypto (`packages/primitives`) | OTP 29 bindings; Wycheproof and ACVP vectors run through them. Hybrid authentication (ADR-005). |
| Mailbox (`packages/mailbox`) | SQLite store on generated SQL (ADR-007), HTTP binding, onion hosting, sealed blobs (ADR-009). |
| Daemon (`packages/daemon`) | Engine, scheduler, fetchers, provisioner, carrier, local API, CLI. ADRs 006, 008, 009, 010, 011. |
| Logging (`packages/telemetry`) | Typed logfmt over `logger`; OTP's reports are rebuilt from their shape; send payloads and invitation files travel as `Secret` (ADR-012). |
| Tor (`packages/tor`, `native/pondline-tor`) | Arti sidecar over an Erlang port (ADR-001). |
| Shell DST (`packages/sim`) | Real daemons and mailbox, exact replay. Judged; see item 1 below and `docs/architecture/sim.md`. |
| Packaging | Self-contained release, install, dist (ADR-003). macOS arm64 tested; Linux never run. |
| Formal (`docs/formal/README.md`) | Lean, P, TLA+ (18 configurations) and ProVerif (30 rows). Mutants fail as expected in each. |
| Docs | Every package has an architecture `README.md`; `docs/architecture/system.md` covers the whole. The top README and `docs/quickstart.md` are for outside readers. |

## In flight

Nothing. Branches `logging`, `formal-tla`, `formal-crypto`, `join-secret`,
`crypto-findings`, `dst-judge`, `pkg-docs` and `gleam-latest` are all merged, and
their worktrees under `.worktrees/` can go.

## What to do next

In order.

1. **Make the swarm exercise what it claims.**
   `docs/review/2026-11-02-dst-harness-review.md` has the findings, and
   `docs/architecture/sim.md` the measurements (recall 7 of 10, core mutation 29
   of 44, 70.7% of the runtime). The model says about 86% of swarm seeds never
   send a message, because `setup` doesn't pair. Start with the pairing prefix in
   `swarm.draw`, then narrow the excuses and the `Ok`-versus-store check, then the
   heal soak that reaches retransmit, then the quarantine op. Add a nonzero exit
   to `sim/swarm`. **Before fixing each false pass, build the mutant that shows
   it**; those scenarios are read from the code and unconfirmed. **Exit:**
   measured sends per seed reported by the swarm; retransmit and quarantine have
   non-zero calls under coverage; recall, mutation and coverage rerun and written
   into the arch doc. *Cut:* no driving of the real carrier or mist in the swarm,
   and no nightly job. Expect new production bugs; triage each as production,
   harness or policy.
2. **Test the processed id-and-digest rule.** Reverting it passes the daemon's
   whole suite and the swarm, so nothing defends it. Write the test directly
   (one envelope id, different bytes, after its `Processed` row), mutation-checked.
   **Exit:** the digest revert fails a daemon test.
3. **Close the core test gaps** the survivors name: the `<=` limits on payload,
   description and content type (R-class refusal exactly at a limit passes), the
   receipt in `AwaitingAccept`, `raise_budget`'s ceiling, `offer.expire`,
   `redeem`'s deadline, `recognise_retry`, `check_names`. Note that 18 of 62 written
   mutants were cut unrun. **Exit:** those mutants die in `packages/core`.
4. **Fix docs the code contradicts**, found while writing the READMEs.
   `packages/lint/CLAUDE.md`, the `lint` module doc, `lint/cli` usage and
   `scripts/lint.sh` describe a gating set, package counts and modules from another
   repository; `packages/primitives/CLAUDE.md` overstates which wrappers catch
   exceptions (`sha256` and the unkeyed functions don't, by design); the comment on
   `primitives.openssl_version` says a release checks it at startup and nothing
   calls it, which is either stale or a missing check; `relationship` and
   `plan.DeliveryStatus` say an expired message is recorded and it isn't.
   **Exit:** each corrected, or the missing check added.
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
transcript; initiator deniability is given up for now; Ed25519 verification
stays OpenSSL's, accepting small-order keys** (ADR-005 and its addendum;
Roasbeef/pondline#2).
**End-to-end retransmit of the same committed bytes under a fresh envelope
id** (ADR-006).
**SQL is generated by parrot from checked-in `.sql`; its runtime is vendored; a
shipped migration never changes** (ADR-007).
**A sender's retention deadline sits one hour below the mailbox maximum and
`BadDeadline` is retried with shorter offers** (ADR-008).
**Short `pl1` tickets carry the mailbox and a 32-byte key; the invitation is
sealed at the inviter's mailbox; fetching does not consume it** (ADR-009).
**A repeated message id is ignored and recorded; an envelope that fails five
times is quarantined; a repeat served after its ack is acknowledged again**
(ADR-010).
**A retried accept returns the first relationship; `send` takes an optional
idempotency key** (ADR-011).
**Logs are typed logfmt on standard error; foreign reports are rebuilt from their
shape; the formatter must not raise** (ADR-012).
**The invitation embeds the bundle and there is no join secret** (ADR-013).
**One agent per daemon, a per-pairing message budget, a plaintext audit log, HTTP
for the demo** (`docs/review/2026-10-31-design-review.md`).
**DST policy: exact replay, dedup and quarantine, sender slack and retry**
(`docs/dst/plan.md`, Rulings).
**Group signatures in the Pond style are out of scope**: pairwise queues give the
admission control, and PQ schemes aren't practical or standardised
(`docs/design-intent.md`, design review §3.5).

## Deliberately open

None of these is unfinished work somebody forgot.

- **License and security contact.** The repository has neither. The owner's call,
  and needed before it is an open source project in any legal sense.
- **CI.** Undecided: Ubuntu's OTP links OpenSSL 3.0 (no ML-KEM), and macOS minutes
  cost more. Needs the owner's call before a nightly swarm or a `make check` job.
- **Weft on Hex.** Weft 0.4.7 is on GitHub; `gleam publish` needs the owner. Until
  then the packages pin weft by git ref.
- **Hybrid PAKE for spoken codes** (Roasbeef/pondline#1): researched, unbuilt.
- **Initiator deniability** (Roasbeef/pondline#2): sketched for a CryptoProfileV2,
  which is also where `CT || PQSPK` goes into the HKDF info
  (`docs/crypto-profile-v1.md` §10).
- **Queue provisioning linkability.** Queues from one account link at the mailbox.
  Anonymous provisioning tokens are the likely shape if this becomes a priority.
- **Release signing and Linux.** No signing or notarization; the Linux recipe has
  never run.
- **Known operational gaps.** `raise_budget` is relative, so retrying it after a
  lost answer doubles the grant (ADR-011); `incidents` and `attempts` rows are never
  pruned (ADR-010); blobs have no `DeleteBlob` (ADR-009); the ticket's onion path is
  unit-tested only; a clock that jumps back stalls retries until it catches up
  (ADR-008). Gleam's generated entry module prints a main-process panic outside the
  handler, guarded only by the no-panics rule (ADR-012).

## How to verify

`make check` is the full gate: `gleam format --check`, a warning-free build, every
package's tests, `make lint` (errors gate) and `make doc-check`. Set
`PONDLINE_TOR_BIN` to a built sidecar and run `make -o sidecar check` to skip the
cargo build in a worktree. `make formal` runs the formal checks (they need Lean, P,
TLC and ProVerif; ProVerif is at `~/tools/proverif-2.05` on this machine, not on
`PATH` by default, and the TLA+ and ProVerif runs take about 25 minutes each).
`make release release-smoke` checks the shipped tree.

Hazards that have cost real time here:

- **`gleam` on this machine's `PATH` may be Loom's older copy**, which now refuses
  the tree with a version error. Put `~/tools/gleam-1.19.2` first. Don't
  `brew upgrade gleam` casually: it also moves Erlang and OpenSSL for every project.
- **`sim/swarm` exits 0 whatever it finds.** Read its census, until item 1 fixes it.
- **doc-check's citation resolver accepts any line that mentions a symbol.** It moved
  `repeat` to a comment line, and a citation "fix" taken from its message was wrong.
  Check the target. It also doesn't scan `.tla` comments, so re-check those after
  a merge moves engine or scheduler lines.
- **Run `scripts/doc_check.sh` before pushing any merge, docs-only included.**
- **Verify a gate by its own exit code.** A `| tail` inside an `&&` chain hid a
  failing doc-check; a mutant that fails to compile looks like a killed mutant, so
  read why it failed.
- **Concurrent test suites make the daemon's timing tests flaky.** Run DST campaigns
  alone.
- **Adding a package means three lint tables**: `qualified.project_roots`,
  `policy.literate_packages`, and the pinned assertions in `lint_test.gleam`.
- **After editing any `.sql`, run `make gen-sql`**; never edit a shipped migration.
- **A worker stopped by a usage limit leaves uncommitted work.** Read the worktree's
  status before assuming a branch is what its log says.
- **A formal row can pass vacuously.** `no_ct_weak_kem` passed until its events
  carried the term the attack changes. A broken variant with no attack is a finding.

`docs/execution.md` is the rest: how a wave is planned, how sub-agents are briefed
and monitored, the standard of proof.
