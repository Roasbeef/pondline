# Execution

How work gets done in this repository when an agent is driving it: how a
wave is planned, how sub-agents are briefed and monitored, how their output
is verified before it lands, and the failure modes that have already cost
real time here.

This is not a style guide (`docs/gleam-style.md`) or a plan (`docs/spec.md`,
`docs/next.md`). It is the operational layer between them. It was carried
over from loom, where every rule earned its place by something going wrong
first; §8 starts empty here and grows by incident, never speculatively.

---

## 1. The shape: one orchestrator, disjoint slices

The pattern that works is a root orchestrator that plans, dispatches,
verifies and commits, and sub-agents that each own **one slice on a
disjoint file set**, doing no git operations at all.

A wave is three or four slices dispatched at once. The slices are chosen so
their file sets do not overlap, because sub-agents share one working tree.
Two agents in one package is survivable if they touch different files; two
agents in one *file* is not.

The orchestrator's job is the part that cannot be delegated:

- deciding what the slices are and why they are disjoint,
- writing briefs dense enough that the agent does not have to guess,
- **verifying the work independently** rather than believing the report,
- staging and committing atomically, in the repo's own commit style,
- and holding the cross-slice picture nobody else has.

The orchestrator should not also be implementing a slice. It will be
interrupted by notifications, and half-finished edits in the shared tree are
exactly what breaks the other agents.

### What to delegate, and what never to

Delegate: an implementation slice with a clear boundary; a broad read-only
survey where you want the conclusion, not the file dumps; a design ruling on
a contested decision; mechanical work over many items.

Never delegate: the decision about what the slices *are*; the final
verification; the commit messages; anything requiring the whole-tree
picture. An agent that only sees one package will write a commit message
that is true about that package and wrong about the change.

---

## 2. Briefing

A brief that produces good work is long. Cheapness in the brief is paid back
with interest in wrong work. Every brief should carry:

**The required reading, in order.** `CLAUDE.md`, then the package docs, then
the specific files with line numbers, then the spec sections the slice
implements (`docs/spec.md` §N).

**The issue, restated with evidence, not just its number.** Quote the
load-bearing part, with `file.gleam:line` citations you have checked
yourself. Agents believe an issue's framing.

**The ownership list and the no-touch list.** Name the files this slice owns
and the files other agents are live in.

**The cut list.** Say explicitly what *not* to build. This is the single
highest-value paragraph in a brief. Agents over-deliver by default: they will
add a config knob, a second mechanism, a metric. Naming the things you do
not want is what keeps a change small. `docs/design-intent.md` §13 is the
project-wide cut list; quote the part that applies.

**The standard of proof.** Mutation testing (§4), a green
`make check-<package>`, and the relevant gate (`make lint`,
`make doc-check`). For protocol code, name the spec invariant
(`docs/spec.md` §13.1) the slice must demonstrate and the crash points
(§13.2) its tests must stop at.

**The house rules that are not in the code.** Commit authorship, the commit
message format, no AI-tool names in any repository artifact, generated
files get their own commit, and **never run `git checkout <file>`**, which
destroys another agent's uncommitted work.

### Give the ruling, not the question

If a design decision has already been made, put the decision *and its
reasoning* in the brief. An agent handed an open question will re-derive
it, usually differently, and you will discover the divergence at commit
time.

---

## 3. Monitoring

Sub-agents run in the background and notify on completion. Between dispatch
and that notification:

- **Do not poll the agent's transcript file.** It floods your own context.
- **Do useful, non-conflicting work**: read-only scoping for the next phase,
  issue triage. Not edits.
- Watch `git status --porcelain` and `git log --oneline` to see the tree
  moving.
- Never claim or predict a running agent's results.

**A completed-agent notification is not proof the work is good.** It is
notice that verification can start.

---

## 4. Verification: the part that is not optional

**Do not trust an agent's report of its own gates.** Reports are sincere and
stale, sincere and mis-scoped, or correct, and the three are
indistinguishable from the text. Re-run the gate yourself on the real tree.

### Capture the exit code of the thing you care about

```sh
make check > log 2>&1; echo "EXIT=$?"; tail log     # reports tail's status
make check > log 2>&1; echo "MAKE_EXIT=$?"          # then read MAKE_EXIT
```

A gate launched as a background command finishes with the wrapper's status.
A background gate whose recorded exit line was never read is a gate that did
not run, whatever the notification said. Then read the log for `failures`,
not just the summary line.

### An incremental build cache can lie

A deterministic failure in a package the diff does not touch is not
automatically a flake. Check a fresh worktree of the same commit first: it
separates "my tree is poisoned" from "this commit is broken". The fix for a
poisoned tree is `rm -rf packages/<pkg>/build`, then re-run.

### Verify on a clean checkout

To check a commit independently of other agents' uncommitted edits, use a
git worktree beside the repository, and remove it when done.

### Mutation testing is the standard of proof

A passing test proves nothing about whether it *would* have caught the bug.
Every fix is validated by breaking the code under it and observing the
intended test fail, and by observing that *only* the intended tests fail,
which is how you learn a test is over-broad.

Property and model-based tests follow three rules
(`docs/gleam-style.md` Part III, "Property and model-based tests"). Every
randomized test runs on a fixed, named qcheck seed, so a red property is
the same red property on every machine. The proof is one mutation for each
invariant family, each failing under its own violation. And a property that
fails on unmodified code is a finding: do not weaken it to make the gate
pass.

This matters more here than in most repositories. The core claims of
`docs/spec.md` §13.1 (no send before commit, no delete before commit, no
double consumption, no replay-driven redelivery) are exactly the kind a
happy-path test passes while the property is false.

### Verify the claim, not the vicinity

Match the check to the property claimed. "The outbox survives a crash" is
proved by killing the process between commit and send and observing the
retry, not by a unit test of the outbox insert.

---

## 5. Landing the work

The orchestrator commits: atomically by concern, not by agent. Generated
files get their own commit. Stage by path, never `git add -A` during a wave.
Scan diffs for tool names. Write the message about the why. Before pushing,
`git log --oneline <old>..origin/main` to catch the push race.

---

## 6. The recurring lesson: measure before you build

When an issue's diagnosis and the code disagree, the code is right and the
issue gets a comment saying so. Quantify before mechanising, and prefer a
documented bound with a test over a knob. The design intent asks for
progress reported as **implemented, tested, or still assumed**
(`docs/design-intent.md` §18); keep those three apart in every report,
commit body and handoff.

---

## 7. Advisors

Before code on a contested or security-relevant decision (the crypto
profile, the NIF boundary, a change to a spec MUST), consult a read-only
advisor. Demand a decision with its cost, not a survey; ask for the cut list
and for the cheapest thing that would prove the ruling wrong. Tell it other
agents are live and it must not write. Record the ruling in an ADR.

---

## 8. Hazards specific to this repository

Empty at the start. Add one bold sentence per incident, with what it cost
and the fix, when a hazard costs real time.

---

## 9. A wave, end to end

1. Read `docs/next.md`; audit it against the tree if anything looks off.
2. Consult an advisor on anything contested; record the ruling.
3. Plan disjoint slices; write the briefs.
4. Dispatch; do read-only work; do not poll transcripts.
5. Verify each slice by its own gate's exit code, on a clean checkout.
6. Commit atomically by concern. Scan for tool names. Check doc mirrors.
7. Push; diff what actually went out against what you verified.
8. Close the issues with a comment saying what was decided and why.
9. Rewrite `docs/next.md` for the next session.
