# Architecture decision records

One file per decision whose consequences outlive one change:
`NNN-short-slug.md`, numbered in order. An accepted ADR is amended by an
addendum inside it, never by a silent edit, so the record shows what was
believed and when it changed.

Write an ADR when a feasibility spike ends, when a spec MUST changes, or
when an open question in `docs/design-intent.md` §17 is answered.

## Format

```markdown
# ADR-NNN — <the decision as a sentence>

**Status**: proposed | accepted | superseded by ADR-MMM · **Date**: YYYY-MM-DD · **Spec ref**: §N

## Decision

What was decided, concretely enough that code can be checked against it.

## Why

The problem, what was considered, and the evidence: measurements,
versions, licenses. Say what is implemented, tested, or still assumed.

## Consequences

What this costs, what it rules out, and what would make us revisit it.
```
