# sim

`sim` is the deterministic simulation test of the real shell. It runs two
`daemon/node` trees and one `mailbox/node` tree in one VM, against a simulated
network, clock, timer wheel and store faults that a seed drives. The same seed
replays the same run exactly, which is what makes a found failure debuggable.
No production package depends on `sim`, so its fake crypto can't reach a
release.

[docs/architecture/sim.md](../../docs/architecture/sim.md) is the architecture
document for this package: who owns which state, how a seed becomes a run, what
the oracle checks, and the measurements that judge the harness (blind recall,
mutation score, coverage). [docs/dst/plan.md](../../docs/dst/plan.md) has the
plan and its rulings, and `CLAUDE.md` here lists what is real and what is
simulated.

## Running it

```bash
cd packages/sim
gleam test                                                  # corpus and regression seeds, each run twice
gleam run -m sim/swarm -- --seed 1 --runs 1000 --keep-going # a campaign
```

Read a campaign's result from its printed census, not its exit status:
`sim/swarm` exits 0 even when it finds a violation. Run campaigns alone on the
machine, since other test suites running alongside make the daemon's
wall-clock tests flaky.

## What it can't see

The runner has no Tor sidecar, no HTTP server, and runs last at most a few hours
of virtual time. So the carrier, `mailbox/http`, and anything that needs a
message or an offer to expire are out of its reach, and the end-to-end
retransmit paths weren't called in the measured 500 seeds. Those paths rely on
their unit and integration tests. The "Known gaps" section of the architecture
document has the full list.
