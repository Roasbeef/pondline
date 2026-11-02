# Formal checks

Each check lives in `formal/<tool>/` with a `check.sh` that exits non-zero if
a proof fails or a property does not behave as stated. `make formal` runs them
all. They need tools `make check` does not, so they are not part of that gate.

| Document | Tool | What it covers | Run time |
| --- | --- | --- | --- |
| [`lean.md`](lean.md) | Lean 4 | TLV canonicality, padding, retention offers and the retransmit schedule, tied to the Gleam code by conformance vectors that `core`'s tests replay | see the document |
| [`p.md`](p.md) | P | End-to-end delivery across two daemons and a mailbox, with faults and crash points | see the document |
| [`tla.md`](tla.md) | PlusCal, TLC | The scheduler's per-run claims and `Held` pacing, and the fetcher's acknowledgement rule | about 25 minutes |
| [`crypto.md`](crypto.md) | ProVerif | The pairing handshake and the sealed ticket, under broken-primitive and leaked-invitation adversaries; also the Wycheproof and ACVP vectors run through `primitives` | about 23 minutes |

Every model is judged the same way: its checker must pass on the design, and
each property must fail on a broken variant, so a property that cannot fail
does not count. All of these results hold within each document's stated model
and bounds, which that document lists. They do not prove the implementation
correct as a whole.
