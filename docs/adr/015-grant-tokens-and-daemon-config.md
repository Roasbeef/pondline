# ADR-015: Copy-pasteable plg1 grant tokens, ~/.pondline config, and sidecar auto-discovery

**Status**: accepted · **Date**: 2026-11-11 · **Spec ref**: §3.2, §9.2, §12.3

## Decision

1. **Provisioning grant tokens (`plg1...`, `core/grant`).** A mailbox operator
   can issue a provisioning capability bundled with its mailbox endpoint as one
   checksummed ASCII string using BIP-93's 15-symbol codex32 BCH code under the
   human-readable prefix `"plg"`:
   - Format `0` (onion): 35-byte decoded v3 onion label, 2-byte big-endian port,
     32-byte `Capability(Provision)` -> 131 characters.
   - Format `1` (loopback): 2-byte big-endian port, 32-byte `Capability(Provision)`
     -> 75 characters.
   `pondline-mailbox serve` persists `<tor-state>/onion` (`0600`) after hosting
   its onion service, and `pondline-mailbox grant --token` accepts either
   `--mailbox HOST:PORT` or `--tor-state DIR`. Tokens never enter `argv`:
   `pondline init` and `pondline daemon` read them only from `--stdin` /
   `--grant-stdin` or `--file` / `--grant-file`, and parser errors never echo
   positional words.

2. **Default `~/.pondline` state directory and persisted daemon config.**
   `pondline` defaults `--state-dir` to `$PONDLINE_STATE_DIR` or
   `$HOME/.pondline` (without ever borrowing `~/.pondline/operator.cred` when an
   explicit `--socket` is passed without `--state-dir`). `pondline init` (and
   `pondline daemon` when given setup flags) materializes `<state-dir>/provision.cap`
   (`0600`) and `<state-dir>/config.json` (`0600`, schema `v: 1` carrying
   `mailbox`, `carrier` and optional `tor_bin`), so subsequent restarts run as
   `pondline daemon` with zero flags.

3. **`pondline-tor` auto-discovery and fail-fast.** Release launchers export
   `PONDLINE_TOR_BIN=${PONDLINE_TOR_BIN:-$REL/bin/pondline-tor}`. Both
   `pondline daemon` (under `--carrier tor`) and `pondline-mailbox serve` (under
   `--tor-state`) resolve the sidecar across `--tor-bin`, `PONDLINE_TOR_BIN`,
   `PATH`, and checkout build paths, failing before opening state if no sidecar
   binary exists. `pondline-mailbox serve` defaults `--port` to `0`.

4. **Operator inspection and CLI ergonomics.** `pondline-mailbox status` reports
   aggregate grant, queue, envelope, blob and tombstone counts without exposing
   capability hashes or queue identifiers. `pondline` resolves `--contact`
   petnames and `>= 4`-digit hex prefixes via the local `contacts` op (failing
   closed on ambiguity), and `pondline invite accept` accepts `--budget N` to
   override `default_accept_budget`.

## Why

Onboarding external operators to a live mailbox previously had three sharp
edges:

- Omitting `--tor-bin` on `pondline daemon` left `daemon/carrier` in `Unused`
  with no startup warning, failing every onion dial forever, while
  `pondline-mailbox serve` required passing `--tor-bin` into the release's
  internal `lib/pondline/current/bin/pondline-tor` path by hand.
- `pondline-mailbox grant` wrote 32 raw binary bytes to `--out`, forcing
  operators to transfer a binary file plus a separate 56-character `.onion:80`
  string out of band. Reusing `core/codex32` under the `"plg"` prefix gives the
  same eight-character error detection as `pl1` invitation tickets while keeping
  the two codewords cryptographically domain-separated at the BCH residue.
- `pondline daemon` required `--state-dir`, `--mailbox`, and `--provision-file`
  on every restart, and client commands required `--state-dir` and 32-digit hex
  contact ids on every call.

All four changes are implemented and unit-tested across `core`, `mailbox`, and
`daemon`, and exercised through `make release release-smoke`.

## Consequences

- `<state-dir>/config.json` and `<state-dir>/provision.cap` sit beside
  `daemon.db` and the credentials under `0700` / `0600` OS permissions (still
  unencrypted at rest, matching `daemon.db`).
- Loopback carrier admission remains an explicit `--carrier loopback` operator
  choice (spec §13.1): passing a loopback `plg1` token without `--carrier
  loopback` is refused before writing `config.json`.
- Petname/prefix `--contact` resolution adds one local Unix-socket `contacts`
  round trip only when `--contact` is not already 32 hex digits.
