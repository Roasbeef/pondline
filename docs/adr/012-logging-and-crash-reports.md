# ADR-012 — Logs are typed logfmt on standard error, and OTP's crash reports are rebuilt from their shape

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §5.4, §12.4

## Decision

**One logging layer, `packages/telemetry`, over Erlang `logger`.** Every
line Reedwire writes, and every line OTP or a library writes into the same
VM, goes through one handler: OTP's stock `logger_std_h` (its overload
protection unchanged) writing to **standard error**, formatted by
`telemetry_ffi:format/2`. The daemon (`reedwire`) and the mailbox install it
as the first thing their `main` does, for every command, and refuse to run
if `logger` will not take it. No library installs it, so the simulation's
own silencing of `logger` is untouched.

**Our lines carry typed fields and nothing else.** A call is
`log.info(component, event, fields)` (also `debug`, `warning`, `error`).
The component and event are literal words. A field is one of four kinds
(`telemetry/field`):

- `id(key, Id(kind))`: the first 8 hex characters of a typed identifier,
  for correlating one contact, queue, envelope or message;
- `count(key, Int)` and `millis(key, Int)` (rendered `key_ms=`);
- `tag(key, value)`: the name of the value's constructor and nothing it
  holds, so `Refused(detail)` is `refused`, a `Secret` is `secret`, and a
  `String` or `BitArray` passed by mistake is `<binary>`.

There is no free-form string or bytes kind, so a payload, a key, a
capability or an invitation cannot be logged by any call site.

**Levels.** `error`: nothing will retry it (every OTP crash and supervisor
report). `warning`: degraded but progressing (a lost version check, a
failed storage operation, a refused queue creation, a send outcome the
engine could not record). `info`, the default: lifecycle (`node started`,
`mailbox serving`) and the mailbox's access log. `debug`: per-message steps
and OTP's progress reports, which are dropped below `debug`.
`REEDWIRE_LOG_LEVEL` sets the threshold (`debug`, `info`, `warning` or
`warn`, `error` or `err`); anything else is `info`.

**Format: logfmt**, one event per line:

```
time=2026-11-01T23:43:27.890Z level=info component=http event=request method=post status=200 response=queue_created elapsed_ms=8
time=2026-11-01T23:43:28.004Z level=error component=otp event=crash_report pid=<0.240.0> process=daemon_engine$4614 initial_call=weft@actor:-start/1-anonymous-1-/0 class=error reason=badarg at=crypto:crypto_one_time_aead/7:1783,daemon_test_ffi:seal_or_crash/5:62,core@crypto@ratchet:-seal/5-anonymous-0-/5:489
```

**Foreign events are rebuilt from their shape, never printed as given.**
The formatter keeps: the report kind; a process's registered name, its
label's tag, or its initial call as `module:function/arity`; a reason's tag
(an atom, a tuple's first atom, a Gleam panic's kind, module, function and
line); up to three stack frames as `module:function/arity:line`; a format
string with each argument replaced by its shape; the literal prefix of a
`weft` warning; and, for a discarded message, the constructor that opens
its inspected text. It never prints a process's state, last message,
mailbox, dictionary or neighbours, a stack frame's arguments, the data
inside a reason, a Gleam panic's `message` or `value`, or a library's free
text (only its byte count). Shapes covered: `proc_lib` crash reports
(including `weft` actors and run workers), supervisor
`child_terminated`/`start_error`/`shutdown_error` and progress reports
(static and factory supervisors), `gen_server`/`gen_statem`/`gen_event`
terminations, application start and exit, the emulator's own "Error in
process" report, `weft` and `gleam_otp` discarded-message warnings, and
free text from `logging.log` (mist, glisten). A body the formatter cannot
build becomes `event=unformattable`. The formatter must not raise, because
OTP answers a raising formatter by printing the event's raw message through
its own (`logger_h_common:try_format`).

**Plaintext travels as a `Secret` between processes.** The send payload is
a `core/secret.Secret` from the local API's decode, through
`Backend.send`, `api.send`/`send_with_key` and `engine.send`, and is
exposed only inside the engine's job, where the core seals it. The engine's
`invitation_file` answer, the one actor message that carried an invitation
file, is a `Secret` too. Delivered payloads already were.

## Why

The no-secrets rule of §12.4 held for the lines Reedwire wrote and failed
for the lines OTP wrote. Reproduced before this change
(`test/daemon/crash_report_test.gleam`): a daemon whose ChaCha20-Poly1305
seal fails inside the engine's send job (OpenSSL handed a key one byte
short) crashes the engine, and OTP's crash report and the supervisor's
`child_terminated` report both printed the NIF's argument list: 31 bytes of
the message key, the nonce, the associated data and the padded frame with
the payload in it, the payload as a decimal byte list
(`67,82,65,83,72,45,80,65,89,...`). A search for the payload's text does
not find that spelling, which is why the old `secrets_test` passed.

The diagnosis we started from was partly wrong. It held that the engine's
actor message carried the plaintext. It does not: an engine message is
`Run(kind, job)` and the job is a closure, which a report prints as
`#Fun<...>`, and the receive path already carried `Secret`s. The leak was
the stack frame's arguments, which no wrapping can cover, because the
primitive must be called with the bytes. `primitives_ffi` already guards
its own `crypto` calls for this reason; a test suite, a future primitive,
or any BIF raised with key material in reach is not guarded. So the fix
that closes the class is the formatter, and the `Secret` wrapping is
defence in depth for the values that cross a process boundary as data: a
late reply in a caller's mailbox is printed by a crash report's `messages`
field or by an actor's "discarding unexpected message" warning.

Standard error because standard output is a protocol: the mailbox prints
`listening` and `onion` lines a launcher reads, `reedwire daemon` prints
`ready <socket>`, and `reedwire receive --raw` writes payload bytes. OTP's
default handler writes to standard output.

logfmt rather than JSON lines: every value is one scalar with no nesting
(the no-free-form rule forbids nesting anyway), an operator of a one-host
daemon reads the stream in a terminal, `grep event=crash_report` and the
usual collectors (Loki, Vector) parse it, and the package needs no JSON
dependency. A global `log.info` rather than an injected logger: the
processes are few and each call site names its component; loom's
session/strand context has no counterpart here.

Implemented and tested: the layer and its pure rendering
(`telemetry/test/telemetry/render_test.gleam`); the formatter against
reports produced by real crashes of a supervised `weft` actor (a BIF raise
and a failed `let assert`), a `weft` run worker, a `proc_lib` process with
the secret in its mailbox and dictionary, a raw `spawn`, a `gen_server`
with the secret as state, last message and reason, a `weft` actor's
discarded message, a library's free text, and the factory-supervisor report
a failed mist handler produces (`scrub_test`); the engine crash
(`crash_report_test`); and a run with three injected crashes (the engine
mid-send, the scheduler while recording a send, a mailbox request process
while calling the coordinator), each with a secret in its arguments, after
which the message is still delivered (`secrets_test`). Mutation-checked:
installing OTP's own `logger_formatter` in place of ours fails
`crash_report_test` on the planted secret; returning the invitation file
from the engine as plain bytes fails `secrets_test` on its rendering.

## Consequences

- A crash report says what crashed, why and where, and no longer shows
  the failing call's arguments or the process's state. Debugging a crash
  that needs a value means reproducing it in a test, not reading the log.
- A library's free-text line (mist's report of a failed request handler,
  its date-cache warning) is withheld down to its size. If one of those
  ever matters, the fix is a typed log line at our call site, not a looser
  formatter.
- The literal-only rule for components and events is a convention, as it
  was for `daemon/log`; the values are what the type system closes.
- The sidecar's own diagnostics (`reedwire-tor: ...`) reach standard error
  directly from the Rust process and are not in logfmt. They are fixed
  phrases.
- A failure of the program's main process is printed by Gleam's generated
  entry module, which writes to standard error without going through
  `logger`, and shows a panic's message and a failed match's value (not
  stack arguments). No handler can cover it. What guards it is the rule that
  source does not panic (`docs/gleam-style.md` Part IV); a review found no
  `let assert` or `panic` on that path in the entry points.
- The handler is per VM. A host that embeds the daemon without calling
  `handler.install` keeps OTP's formatter and loses the scrubbing; the
  `Secret` wrapping is what remains then.
- Revisit if a structured export (OpenTelemetry) is wanted: it would attach
  as a second handler with the same formatter rules.
