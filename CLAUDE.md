# Reedwire

Reedwire is a standalone, Tor-first, end-to-end encrypted messaging
substrate for independently operated agents. Gleam/BEAM owns the
application protocol, durable state, policy and supervision; Rust provides
the Arti integration and a narrowly scoped cryptographic implementation.
The name is provisional.

## Start here

**`docs/next.md`** is the handoff: where the tree actually is, what to work
on next, the design rulings already made, and what is deliberately left
open. Read it before planning anything, and rewrite it when you finish a
body of work; it is worth more than any status comment.

**`docs/execution.md`** is how work gets done here: planning a wave,
briefing and monitoring sub-agents, the verification standard, and the
hazards that have already cost real time. Read it before dispatching a
sub-agent or trusting a green gate.

## Required reading

Before writing any code, read these in order:

1. **`docs/gleam-style.md`**: code style, idiomatic Gleam, and a brief
   language tour. Gleam is a new language; do not carry habits over from
   other languages. Part III (idioms: error handling, type design, actors,
   FFI) and Part IV (Reedwire policy: total decoders, no panics outside
   tests, FFI confinement, purity layering, secrets out of output) matter
   most.
2. **`docs/design-intent.md`**: why the system exists, what is settled and
   what is open (§4), and the implementation sequence (§15). It is the
   intent; read it before the mechanics.
3. **`docs/spec.md`**: the core system specification, v0.1. Objects,
   pairing, the crypto contract, the mailbox protocol, persistence, and the
   Gleam/BEAM architecture. Where the spec and the design intent conflict,
   the spec wins on mechanics and the design intent on why.

## Literate code

Comments are part of the design, not decoration added after the code. A
reader should be able to follow a module's ownership model, state
transitions, and failure behavior by reading its prose in order. Start
every module with `////` documentation that explains why the boundary
exists and how work moves through it. Document every public type,
constructor field, variant, and function with `///`, including an
`## Examples` section for functions.

Write the reasoning the syntax cannot show. Explain the invariant being
preserved, the failure or race which shaped the code, and why this
mechanism owns the responsibility. Before a selector, recursive loop, or
subtle `case` arm, state what event or transition it represents. Do not
narrate the next line: `// Send the envelope` above a send adds nothing.
Prefer `// The outbox row commits before the send, so a crash here retries
the same ciphertext`, which tells the reader what ordering would break if
the send moved.

Prose a reader cannot find is prose that was not written, so the layout is
part of the rule. **A comment has a blank line above it**, inside a
function body, between `case` arms, and between the variants of a custom
type. **R10 gates**, so a welded comment fails the build. And **a body does
not run more than about eight statements without a break** (R11, also an
error). `docs/gleam-style.md` Part II, "Stanzas: how code breathes", has
the two places `gleam format` deletes a blank line and so exempts.

## Ground rules

- Design priorities, in order: security, correctness, durability,
  robustness, performance, capability.
- Gleam >= 1.19.2, Erlang/OTP >= 29. All code passes `gleam format --check`
  and compiles warning-free before commit. `make check` is the gate.
- `core` is pure: no I/O, no `@external` of any target, and no
  `gleam_erlang` or `gleam_otp`, in source or in `gleam.toml`. Lint R6
  gates on it. The protocol is `transition(model, event)` with time,
  randomness, network and storage outcomes arriving as events
  (`docs/spec.md` §10.1); that is what makes every interleaving and crash
  point property-testable without spawning processes.
- Every durability and wire boundary uses total decoders. Untrusted bytes
  never become atoms and are never decoded as Erlang terms.
- Secrets never reach logs, trace attributes, command-line arguments,
  error messages or diagnostic exports. Wrap them in opaque types.
- Limits live in `core/limits` and are imported, never restated.
- The test crypto provider must never be selectable in a production build
  (`docs/spec.md` §13.3).
- **No naked `Bool`** in a function parameter or a record field; model the
  question with a two-variant type named for the domain. Lint R9 counts
  them.
- **Custom FFI is a last resort.** The Rust NIF bridge is the planned
  exception, behind one package with a Gleam-first API. Anything else
  foreign lives in an `internal/ffi_*.gleam` module with a comment saying
  why no pure alternative exists.
- Chain fallible steps with `use` + `result.try`; `case` is for ADT
  dispatch, never for stacking `Result`s, and never buy a shallower shape
  with a catch-all `_ ->`. Watch the eager fallbacks (`bool.guard`'s
  `return:`, every `unwrap`); R1 flags them.

## Where decisions live

A decision is only settled once it is written where the next reader will
look for it:

- **`docs/adr/NNN-*.md`**: architecture decisions with consequences that
  outlive one change (the crypto library, the NIF approach, the SQLite
  driver). An ADR is amended by an addendum inside it, never by a silent
  edit. `docs/adr/README.md` has the format.
- **`docs/spec.md`**: the protocol and state transitions. A change to a
  MUST is recorded in an ADR first and then reflected in the spec, never
  edited in silently (`docs/design-intent.md` §4).
- **The issue itself**: when measurement contradicts an issue's diagnosis,
  the correction goes on the issue as a comment.
- **The code**: a rule that can be checked belongs in `make lint`,
  `make doc-check` or a test, not in prose.

## Per-package docs

Each package with source carries a `CLAUDE.md`: purpose, key types, real
dependency edges, traffic, and the invariants that break things when
violated. Read the one for the package you are about to change.

`AGENTS.md` beside it is a byte-identical mirror, produced by `cp`, never
hand-edited. `make doc-check` enforces coverage and the mirror, and warns
when a package's source has been committed more recently than its docs.

## Commits

Make incremental, atomic commits that each tell one part of the story.
Every commit is authored by the repository owner, never by a tool or agent
identity, and commit messages carry no AI co-author trailers. Format:
`subsystem: imperative summary under 50 chars`, then a body in natural
prose explaining the why more than the what. Prefixes: package name for
single-package changes (`core:`), `multi:` across packages, `docs:`,
`build:`, `ci:`, `test:`. Lock files, generated files, and vendored code
get their own commits.
