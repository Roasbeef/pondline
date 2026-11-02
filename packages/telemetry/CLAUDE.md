# telemetry

## Purpose

Structured logging for every Pondline program, and the rule that no log
line carries a secret (spec §12.4, `docs/gleam-style.md` Part IV §7),
enforced rather than asked for (ADR-012). Two halves: a typed API for our
own lines, which admits no free-form value, and a `logger` formatter that
rebuilds every line OTP or a library writes (crash, supervisor and
termination reports, warnings) from its shape, never printing a process's
state, mailbox, a stack frame's arguments or a reason's data. One logfmt
stream on standard error.

## Key Types

- `telemetry/level.Level`: `Debug | Info | Warning | Error`, exactly
  `logger`'s atoms. `name`, `parse` (case-insensitive, `warn`/`err`). The
  module doc is the level policy; read it before adding a call site.
- `telemetry/field.Field` (opaque): `id(key, Id(kind))` (first
  `id_prefix_chars` = 8 hex), `count(key, Int)`, `millis(key, Int)`
  (rendered `key_ms=`), `tag(key, value)` (the constructor's name only:
  `Refused(x)` is `refused`, a `Secret` `secret`, a string `<binary>`);
  `render`.
- `telemetry/logfmt`: `word` (a key as one `[a-z0-9_]` token) and `quote`
  (bare or quoted-and-escaped value). The only escaping rule; the Erlang
  formatter calls `quote` too.
- `telemetry/line.render(component, event, fields)`: pure, the body of one
  of our lines.
- `telemetry/log.{debug, info, warning, error}(component, event, fields)`:
  the call sites. Component and event are literal words.
- `telemetry/handler`: `install(level) -> Result(Nil, Nil)`,
  `install_from_env()` (reads `PONDLINE_LOG_LEVEL`, default `info`),
  `threshold_named`, `level_variable`. Entry points only.
- `telemetry/internal/ffi_logger` over `src/telemetry_ffi.erl`: `install`,
  `enabled` (`logger:allow/2`), `emit` (`logger:log/3` with the report
  `#{pondline => Line}`), `constructor_name`, `getenv`; and `format/2`,
  the handler's formatter.

## Relationships

Depends on `core` (`core/id` for the typed identifier field) and
`gleam_stdlib`. Dev: `gleeunit`, `gleam_erlang`, `gleam_otp`, `weft` (the
tests crash real actors, runs and supervisors). Depended on by `daemon` and
`mailbox`, whose entry points (`pondline.main`, `mailbox.main`) install the
handler; `tor` does not log and does not depend on it.

## Traffic

No process, no message. A log call runs in its caller: `logger:allow/2`,
then, if allowed, a pure render and `logger:log/3`. `logger` hands the event
to the `default` handler (`logger_std_h`, type `standard_error`), whose
process calls `telemetry_ffi:format/2` and writes one line to standard
error. Every line starts `time=<RFC 3339 UTC ms> level=<level>`.

## Invariants

- No field kind holds a free-form string or bytes, so no call site can log
  a payload, key, capability or invitation. `tag` reads only an atom or a
  tuple's first atom (`render_test`).
- A foreign event keeps only: the report kind; a registered name, a
  label's tag or an initial call as `m:f/arity`; a reason's tag (a Gleam
  panic's kind, module, function, line); up to three frames as
  `m:f/arity:line`; a format string with each argument's shape; a `weft`
  warning's literal prefix; a discarded message's leading constructor.
  Free text is reduced to `bytes=N`. Atoms, names, lines and format strings
  come from code; no untrusted byte becomes an atom.
- `scrub_test` crashes real processes (a supervised `weft` actor by a BIF
  raise and by a `let assert`, a `weft` run worker, a `proc_lib` process
  with the secret in its mailbox and dictionary, a raw `spawn`, a
  `gen_server` with the secret as state, last message and reason, a
  discarded message, a library's free text) and a captured factory
  supervisor report, and checks the secret appears in no spelling (text,
  decimal byte list, hex) while the line names what failed. Mutation:
  `daemon/test/daemon/crash_report_test.gleam` fails when OTP's
  `logger_formatter` is installed in place of `format/2`.
- The formatter never raises: anything it cannot build is
  `event=unformattable`, because when a formatter raises, OTP's
  `logger_h_common` prints the event's raw message through its own
  formatter, secrets included.
- Each event is one line; a report's newlines never reach the output.
- Only an entry point installs the handler. Installing replaces OTP's
  `default` handler (standard output) with one on standard error, because
  standard output carries the programs' own protocol lines and payloads.
  Below `debug`, progress reports are filtered out. Installing again keeps
  the running handler and replaces its formatter and filters.
- A line carries no timestamp of its own; the handler stamps `logger`'s.

## Deep Docs

- `docs/adr/012-logging-and-crash-reports.md` (the decision, the
  reproduction, the formatter's rules).
- `docs/spec.md` §5.4, §12.4; `docs/gleam-style.md` Part IV §4, §7.
