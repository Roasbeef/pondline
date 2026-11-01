# daemon

## Purpose

The client side of Reedwire: what an agent's machine runs to talk to
mailboxes. Today it holds only the mailbox HTTP client of spec §6.1, a
carrier-neutral transport and the one call that sends a typed `Request` and
returns a typed `Response`. This package will grow into the client daemon of
spec §10.2 (delivery scheduler, relationship supervision, the command
boundary), which is why it owns the effects that `core` may not: sockets,
the monotonic clock and, later, processes.

## Key Types

- `daemon/transport`: `Connection` (three functions over one open byte
  stream: `send`, `receive`, `close`), `Dialer` (the daemon's
  `CarrierPolicy` plus an injected `dial_onion`), `dial`, and
  `TransportError`. The loopback carrier is a `mug` TCP socket to
  `127.0.0.1`.
- `daemon/mailbox_client`: `call(dialer, endpoint, isolation_group, request,
  timeout_ms) -> Result(Response, ClientError)`, `effective_timeout` (a
  long-poll `Fetch` gets its wait plus `long_poll_margin_ms`), and
  `ClientError`.
- `daemon/internal/ffi_clock`: the one monotonic clock read, used for call
  deadlines.

## Relationships

Depends on `core` (the codec, the typed protocol, `core/http1` framing,
endpoints and limits), `gleam_stdlib`, `gleam_erlang`, `gleam_otp` and
`mug` (loopback TCP). Dev: `glisten` runs the test fake server. It does not
depend on `tor`: the onion carrier arrives as the `dial_onion` function
given to `transport.new_dialer`. Nothing depends on it yet.

## Traffic

Outbound only. One `call` opens one connection, writes one `POST
/v1/mailbox` (`Connection: close`), reads one response and closes. No
process is spawned and no message is sent; the call blocks its caller up to
the deadline. The isolation group passed to the onion dialer is the queue id
in hex, one circuit group per queue.

## Invariants

- `dial` checks `endpoint.admit` against the policy before doing anything,
  so a loopback endpoint under `TorOnly` opens no socket
  (`test/daemon/mailbox_client_test.gleam`, `transport_test.gleam`).
- The client never follows a redirect, never reads a proxy setting and
  reaches the network only through its `Dialer`.
- One deadline covers the dial, the send and every read; each read gets only
  the time that remains. The connection closes on every path.
- A `ClientError` holds a status code or a typed parse or codec error, never
  a capability, a ciphertext or peer bytes.
- No retries here; the delivery scheduler owns retry policy.
- Known gaps: one connection per call (no keep-alive pool); the loopback
  carrier cannot bound a single read by `max_bytes` (the HTTP parser's bounds
  are the limit); a send has no deadline of its own.

## Deep Docs

- `docs/spec.md` §6.1 (transport), §6.2, §13.1 (no silent downgrade).
- `packages/core/src/core/http1.gleam` (framing and bounds) and
  `core/mailbox/codec.gleam` (the body).
