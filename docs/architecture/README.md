# Architecture

One document per subsystem, each describing the code at the commit named
in its introduction: who owns which state, which process touches it, and
how a request moves to a durable result. Diagrams are Mermaid and render
on GitHub.

- [system.md](system.md): how the packages, operating-system processes and
  supervisor trees fit together, the lifecycle of one message from the
  local API to a receipt, and where crash safety comes from. Start here.
- [mailbox.md](mailbox.md): the mailbox service, from an HTTP request to
  a committed SQLite row, the long poll, the envelope and ticket blob
  lifecycles, the spoken-code rendezvous slot and the schema.
- [sim.md](sim.md): the shell DST, from a seed to a verdict: the runner's
  event loop, the seams, the faults, the oracle, and the recall, mutation
  and coverage measurements that judge it.

Other places to look, so this directory does not repeat them:

- Protocol and state transitions: [../spec.md](../spec.md).
- Why the system exists and what is open:
  [../design-intent.md](../design-intent.md).
- Decisions with lasting consequences: [../adr/README.md](../adr/README.md).
- The process primitives every actor and state machine uses:
  [../weft.md](../weft.md).
- One package: `packages/<name>/README.md` for `core`, `primitives`,
  `telemetry`, `tor`, `daemon`, `mailbox`, `lint` and `sim`, and the
  package's invariants file beside it. Pairing by spoken code
  ([ADR-016](../adr/016-spoken-pairing-codes.md)) spans four of them:
  `core` (the code, the PAKE layers and the run's steps), `primitives`
  (SHA-512, the draft-vector tests and the test-only ML-KEM reference),
  `mailbox` (the rendezvous slot) and `daemon` (the run drivers, the
  registry and the guess cap); `system.md` says what of it is verified.
