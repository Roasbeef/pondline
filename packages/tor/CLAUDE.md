# tor

## Purpose

Tor for Reedwire: outbound onion streams and onion-service hosting through
`reedwire-tor`, a separate OS process running Arti (`native/reedwire-tor`).
The sidecar replaces the NIF of spec §10.3. A crash in Arti cannot take the
BEAM down, and because stream bytes cross a real socket, the BEAM's
passive-mode socket buffers give backpressure end to end, so this package
builds no read-credit machinery (spec §10.4).

## Key Types

- `tor`: `start(Config)` returns a `Tor`; `bootstrap`, `host_onion`,
  `connect`, `subscribe`, `sidecar_pid`, `shutdown`. `TorError`, `Event` and
  `OnionHost` are the typed outcomes; the actor owns the port and the
  restart policy.
- `tor/stream`: the opaque passive `Stream` (`send`, `recv`, `close`) and
  the handshake that opens one over the sidecar's unix socket, with
  `OpenError` and `Refusal` for typed failures.
- `tor/address`: `OnionAddress` and `Port`, mirroring `core/endpoint`
  because `tor` must not depend on `core`. There is no constructor for a
  clearnet host.
- `tor/internal/codec`: the control protocol, requests out and events back,
  with total decoding. The wire format is documented in its module doc and
  in `native/reedwire-tor/src/frame.rs`.
- `tor/internal/ffi_port`, `tor/internal/ffi_socket`, `src/tor_ffi.erl`:
  the externals and the one Erlang shim; every function catches every
  exception.

## Relationships

Depends on `gleam_stdlib`, `gleam_erlang`, `gleam_otp`. Does not depend on
`core` or any other Reedwire package. Consumed later by the mailbox
(hosting) and the delivery path (outbound streams). The binary it drives is
`native/reedwire-tor` (`make sidecar`); the tests find it through
`REEDWIRE_TOR_BIN`, defaulting to the release build in the repository.

## Traffic

- Control frames over an Erlang port, `{packet, 4}`, 4-byte big-endian
  length prefix: `Bootstrap`, `HostOnion`, `Shutdown` out; `Ready`,
  `Bootstrapped`, `OnionReady`, `Failed`, `ServiceStatus` back. Requests
  carry an id echoed by the reply.
- Messages to the actor: one `Subject` message per call, a reply `Subject`
  per request, and `Abandon*` when a caller times out. Subscribers receive
  `Event`s.
- One unix-socket connection per outbound stream, to
  `<state-dir>/connect.sock`: a `CONNECT` line, `OK` or `ERR <code>`, then
  raw bytes. These never pass through the actor.

## Invariants

- The sidecar exits when its stdin closes, so a dead owner never leaves an
  orphan (`test/tor/sidecar_test.gleam`, owner killed without `Shutdown`).
- A killed sidecar (`kill -9`) does not affect the VM: the actor fails
  pending requests, tells subscribers, and restarts it within
  `max_restarts` consecutive restarts without a successful bootstrap. A
  restarted sidecar is not bootstrapped; the owner re-bootstraps and
  re-hosts.
- No clearnet connect path: `connect` takes an `OnionAddress`, and the
  sidecar independently refuses a non-v3-onion host with `ERR not-onion`
  before any Tor work (spec §13.1).
- Decoding is total on both sides; an undecodable control frame closes the
  sidecar rather than being guessed at.
- Streams are passive. A reader that stops calling `recv` stops the
  sender through the socket; a `send` timeout means stalled, not failed.
- Secrets never appear in argv (only `--state-dir`) or logs. The state
  directory is mode 0700 and holds Arti's keys, so it is the secret.
- The state directory path must be short enough for a unix socket
  (about 100 bytes on macOS) and unique to one sidecar.

## Deep Docs

- `docs/adr/001-tor-sidecar.md` (the decision, measurements, limits).
- `docs/spec.md` §6.1, §10.3–10.5, §11.1, §13.1.
- `docs/gleam-style.md` Part III (actors, FFI) and Part IV.
