# Lab notebook

Dated entries, newest last, appended rather than rewritten. Each records
the state found, what was tried, what was measured, and what it means.
`docs/next.md` is the summary; this is the evidence behind it.

---

## 2026-10-31 — scaffold

### State

An empty directory, the core specification (`docs/spec.md`) and the design
intent (`docs/design-intent.md`).

### What landed

Loom's house lint, style guide, execution guide, handoff structure and
documentation gate, carried over and retargeted. The lint's loom-specific
tables were replaced rather than deleted: `core` is the one package held to
the portable subset (R6), the harness and import-wall tables are empty, and
R16's roots are `core` and `lint`. The tests that read those tables now use
local fixtures, so the mechanisms stay covered while the tables are empty.
Loom's `affected` change-selection tool was left behind; it was built around
loom's package graph and is not worth carrying until this tree has more
than two packages.

`core/limits` records the spec's §11.3 provisional limits in one place, with
a property test that padding always picks the smallest holding bucket.
