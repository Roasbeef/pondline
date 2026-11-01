# ADR-001 — Arti runs as a sidecar process behind an Erlang port, not as a NIF

**Status**: accepted · **Date**: 2026-10-31 · **Spec ref**: §6.1, §10.3, §10.4, §10.5, §13.1

## Decision

Tor is provided by `reedwire-tor` (`native/reedwire-tor`), a Rust binary on
`arti-client` that runs as a separate OS process. The BEAM starts it from an
Erlang port (`{packet, 4}`, binary, `exit_status`) owned by one actor in the
`tor` package (`packages/tor`), and the sidecar exits when its stdin reaches
end of file. This replaces the NIF of spec §10.3.

Two channels connect them:

- **Control frames** on the port: `Bootstrap`, `HostOnion(nickname,
  local_port)`, `Shutdown` out; `Ready`, `Bootstrapped`, `OnionReady`,
  `Failed`, `ServiceStatus` back. A small tag-and-length binary encoding with
  total decoding on both sides, documented in `tor/internal/codec` and
  `src/frame.rs`.
- **Streams** on sockets. Outbound: one unix-socket connection per stream to
  `<state-dir>/connect.sock`, opened with `CONNECT <v3>.onion:<port> <group>`
  and answered `OK` or `ERR <code>`, then raw bytes. The group selects an Arti
  `IsolationToken`: same group may share circuits, different groups never do.
  Inbound: the onion service forwards every accepted stream to
  `127.0.0.1:local_port`. The sidecar refuses any non-v3-onion target with
  `ERR not-onion` before touching Tor, and the Gleam `connect` takes an
  `OnionAddress`, so clearnet is unrepresentable on one side and refused on
  the other (spec §13.1).

The Gleam streams are passive-mode sockets (`{active, false}`). The spec's
read-credit machinery (§10.4, "Read credit") is not built.

## Why

A NIF is inside the VM, so a crash, abort or stall in Arti takes the BEAM
with it (spec §10.5). A process boundary makes that failure an `exit_status`
message the owner can restart from. Bytes that cross a real socket also give
ordinary backpressure: when the Gleam side stops calling `recv`, the kernel
buffer fills, the sidecar's write waits, `copy_bidirectional` stops reading
from Arti, and Arti's stream window stops granting the far end credit.

Evidence from the spike, run on the development machine (macOS, Rust 1.98,
OTP 29) against the live Tor network, with `REEDWIRE_TOR_NETWORK=1 gleam test`
in `packages/tor` (passed on both runs; the second run, with all events
logged, is the source of the numbers below, and the first run agreed on the
rest):

| Measurement | Value |
|---|---|
| Release binary size | 16.9 MB |
| Bootstrap, cold state directory | 5.1 s and 6.3 s (host, client; an earlier run: 1.5 s, 8.1 s) |
| Bootstrap, warm state directory after restart | 0.2 s |
| `host_onion` returned | under 0.1 s (before the service is reachable) |
| Onion service launch to first successful stream | 10.6 s |
| First connect after a sidecar restart | 8.5 s (earlier run: 5.9 s) |
| Sidecar RSS (`ps -o rss=`), idle, one service or one stream | 38 to 45 MB |
| Round trip of bytes through two sidecars and Tor to a local echo server | ok |
| `kill -9` of the client sidecar with a stream open | BEAM survived; `recv` returned `Error(Closed)` at once; the actor restarted the sidecar and notified subscribers; a re-bootstrap and a new connection to the same onion succeeded |
| Slow reader (sink that never reads) | sender stalled with `send` timeout after 851,968 bytes accepted, and the next send succeeded once the sink drained |
| Sidecar exits when the owner dies without `Shutdown` | pid gone within 5 s (test) |

Versions and licenses: `arti-client`, `tor-hsservice`, `tor-cell`,
`tor-rtcompat` 0.47.0, `safelog` 0.10 (Arti crates are MIT OR Apache-2.0);
`tokio` 1.54; `rustls` 0.23 with the `ring` provider, installed explicitly
because Arti's `rustls` feature selects none (without it the sidecar panics
at its first TLS use).

Implemented and tested: the codec (Gleam and Rust, with shared golden
vectors), the port actor with bounded restarts, the unix-socket stream
handshake, clearnet refusal, onion hosting, and the crash and backpressure
behaviour above. Without the network flag the package's tests cover the
codec, the sidecar's refusals, EOF exit, `Shutdown`, and `kill -9` recovery
with no network.

## Consequences

- **Packaging**: the release bundle carries a second binary (16.9 MB). The
  Gleam tests need it built (`make sidecar`, or `REEDWIRE_TOR_BIN`).
- **State directory**: holds Arti's keystore, so it is the secret. It is
  created mode 0700, must be unique per sidecar, and must be short enough
  for a unix socket path (about 100 bytes on macOS). Onion service identity
  keys live under it keyed by nickname; the same nickname is expected to
  give the same address after a restart, but the spike restarted only the
  client sidecar, so that is assumed, not shown.
- **Restart semantics**: a restarted sidecar is not bootstrapped and hosts no
  services; the owner re-bootstraps and re-hosts. The actor bounds
  consecutive restarts without a successful bootstrap (default 3).
- **Onion service hosting in Arti is newer than its client**, and its status
  reporting is not reliable: the service reported `DegradedUnreachable`
  throughout a run in which it was reachable within 10.6 s, and never
  reported `Running`. Callers must establish reachability by connecting, not
  by the status events.
- **Unmeasured**: long-running memory, circuit and descriptor churn over
  hours, many concurrent streams, and throughput. The sidecar bounds
  concurrent outbound streams (64), inbound streams (256), services (4) and
  isolation groups (1024); none was stress-tested. Vanguards, client
  authorization and multi-service management are not built.
- **Backpressure** here is the socket path only. A stalled stream holds a
  sidecar slot until closed, so the owner must close streams it abandons.
- **Revisit** if sustained hosting proves unstable, if the unreachable
  status persists in a way that breaks operations tooling, if Arti's
  onion-service API changes shape, or if the 16.9 MB binary or 40 MB idle
  footprint matters for the target deployments. A NIF is not an option to
  return to without a separate process-level crash story.
