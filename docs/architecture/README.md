# Architecture

One document per subsystem, each describing the code at the commit named
in its introduction: who owns which state, which process touches it, and
how a request moves to a durable result. Diagrams are Mermaid and render
on GitHub.

- [mailbox.md](mailbox.md): the mailbox service, from an HTTP request to
  a committed SQLite row, the long poll, the envelope lifecycle and the
  schema.
- [sim.md](sim.md): the shell DST, from a seed to a verdict: the runner's
  event loop, the seams, the faults, the oracle, and the recall, mutation
  and coverage measurements that judge it.
