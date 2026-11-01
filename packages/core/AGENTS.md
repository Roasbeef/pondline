# core

## Purpose

The pure protocol core. Domain types and `transition(model, event)`
functions for pairing, delivery and relationship lifecycle will live here
(`docs/spec.md` §10.1), with time, randomness, network and storage outcomes
arriving as events rather than reached for. Today it holds one module:
the provisional limits.

`core` is held to the portable subset by lint R6: no `@external` of any
target, and no `gleam_erlang` or `gleam_otp`, in source or in
`gleam.toml`. That is what lets a property test enumerate states,
interleavings and crash points without spawning a process.

## Key Types

- `core/limits`: the spec's §11.3 provisional limits as named constants
  (sizes in bytes, durations in seconds), and `padded_size`, which picks
  the smallest padding bucket that holds a ciphertext or refuses one larger
  than every bucket.

## Relationships

Depends on `gleam_stdlib` alone. Nothing depends on it yet; every future
package will.

## Traffic

None. `core` sends no messages and owns no processes.

## Invariants

- The largest padding bucket equals `max_ciphertext_bytes`, so padding
  never admits a ciphertext the mailbox would refuse
  (`test/core/limits_test.gleam`).
- Every limit is named here and imported elsewhere; a literal restating one
  at a call site is a review finding (`docs/gleam-style.md` Part IV §8).

## Deep Docs

- `docs/spec.md` §10.1 (functional core), §11.3 (limits), §13 (invariants
  and test strategy).
- `docs/gleam-style.md` Part IV §5 (purity layering).
