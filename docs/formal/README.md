# Formal checks

Each check lives in `formal/<tool>/` with a `check.sh` that exits non-zero if
a proof fails or a property does not behave as stated. `make formal` runs them
all. They need tools `make check` does not, so they are not part of that gate.

| Document | Tool | What it covers | Run time |
| --- | --- | --- | --- |
| [`lean.md`](lean.md) | Lean 4 | TLV canonicality, padding, retention offers, the retransmit schedule, and the spoken-code arithmetic (Kemeleon's round trip and totality, nameplate spelling, word-index slicing, PAKE framing, Elligator 2's reduced output), tied to the Gleam code by conformance vectors that `core`'s tests replay | about 12 seconds cold |
| [`p.md`](p.md) | P | End-to-end delivery across two daemons and a mailbox, with faults and crash points | see the document |
| [`tla.md`](tla.md) | PlusCal, TLC | The scheduler's per-run claims and `Held` pacing, and the fetcher's acknowledgement rule | about 25 minutes |
| [`crypto.md`](crypto.md) | ProVerif | The pairing handshake, the sealed ticket, and pairing by spoken code (CPaceOQUAKE and the ticket hand-off), under broken-primitive and leaked-secret adversaries; also the Wycheproof and ACVP vectors run through `primitives` | about 24 minutes |

Every model is judged the same way: its checker must pass on the design, and
each property must fail on a broken variant, so a property that cannot fail
does not count. All of these results hold within each document's stated model
and bounds, which that document lists. They do not prove the implementation
correct as a whole.
