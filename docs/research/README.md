# Research notes

Design notes for questions that are not scheduled work: a survey of the
literature, a comparison of candidate constructions, and a recommendation,
written so the decision can be taken once with the evidence in one place.
A note settles nothing by itself. When one is acted on, the decision goes
where `CLAUDE.md` says decisions live: an ADR, then the spec, then the
profile.

Each note states its date and the issue it tracks, verifies every citation
against a primary source (eprint, an RFC or CFRG draft, a repository), says
which citations it corrected, and ends with the open questions and what
should go to outside review.

| Note | Tracks | Question | Recommendation in one line |
| --- | --- | --- | --- |
| [`hybrid-pake.md`](hybrid-pake.md) | issue #1 | A human-typable pairing code, bootstrapped by a hybrid PAKE over the mailbox | Adopt the sequential CPace-then-OQUAKE composition of `draft-vos-cfrg-pqpake`, not an in-house combination; concrete rendezvous flow in §5 |
| [`initiator-deniability.md`](initiator-deniability.md) | issue #2 | What the joiner's hybrid transcript signature gives up, and what a `CryptoProfileV2` would change to get it back | Not now; the V2 shape that restores it with no new primitives is a join-secret MAC plus KEM-based implicit authentication of the joiner, and the decision is cheapest before the profile freezes |
