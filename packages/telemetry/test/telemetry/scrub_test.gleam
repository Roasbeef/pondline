//// The formatter against the reports OTP really writes.
////
//// Each test makes a real process fail with a planted secret in every
//// place OTP's own formatter would print it (the reason, a stack frame's
//// arguments, the mailbox, the dictionary, a `gen_server`'s state and last
//// message, a library's free text), captures the events `logger` was
//// given, and runs them through `telemetry_ffi:format/2`. The secret must
//// appear in no rendering of the output (as text, as Erlang's decimal byte
//// list, or as hex), while the line still names what failed.

import gleam/bit_array
import gleam/dynamic.{type Dynamic}
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/otp/static_supervisor as supervisor
import gleam/string
import weft
import weft/actor

/// Printable, so OTP's formatter would print it as text, and long enough
/// that no innocent line contains it.
const secret = "PLANTED-SECRET-c41d2e"

@external(erlang, "telemetry_test_ffi", "capture_start")
fn capture_start() -> Nil

@external(erlang, "telemetry_test_ffi", "capture_stop")
fn capture_stop() -> List(Dynamic)

@external(erlang, "telemetry_test_ffi", "format")
fn format(event: Dynamic) -> String

@external(erlang, "telemetry_test_ffi", "spawn_crasher")
fn spawn_crasher(secret: BitArray) -> Nil

@external(erlang, "telemetry_test_ffi", "raw_crasher")
fn raw_crasher(secret: BitArray) -> Nil

@external(erlang, "telemetry_test_ffi", "gen_server_crasher")
fn gen_server_crasher(secret: BitArray) -> Nil

@external(erlang, "telemetry_test_ffi", "string_event")
fn string_event(text: String) -> Nil

@external(erlang, "telemetry_test_ffi", "bif_crash")
fn bif_crash(secret: BitArray) -> BitArray

/// Every way the secret could be spelled in a formatted line.
fn spellings() -> List(String) {
  let bytes = <<secret:utf8>>
  let decimal =
    byte_list(bytes)
    |> list.map(int.to_string)
    |> string.join(",")

  [secret, decimal, string.lowercase(bit_array.base16_encode(bytes))]
}

fn byte_list(bytes: BitArray) -> List(Int) {
  case bytes {
    <<byte, rest:bytes>> -> [byte, ..byte_list(rest)]
    _ -> []
  }
}

/// The formatted lines of every captured event, with the whitespace OTP's
/// pretty printer would put inside a byte list removed.
fn lines(events: List(Dynamic)) -> List(String) {
  list.map(events, format)
}

/// Asserts no line spells the secret, and returns the lines.
fn clean(lines: List(String)) -> List(String) {
  list.each(lines, fn(line) {
    let flat = string.replace(string.replace(line, " ", ""), "\n", "")
    list.each(spellings(), fn(spelling) {
      assert !string.contains(flat, spelling)
    })
  })
  lines
}

/// The line that contains every one of `parts`.
fn find(lines: List(String), parts: List(String)) -> String {
  let assert Ok(found) =
    list.find(lines, fn(line) {
      list.all(parts, fn(part) { string.contains(line, part) })
    })
  found
}

/// An `Error` the compiler cannot see through, so a `let assert` on it is a
/// runtime failure carrying `bytes` as its unmatched value.
fn refuse(bytes: BitArray) -> Result(Nil, BitArray) {
  Error(bytes)
}

type Probe {
  Raise(BitArray)
  Assert(BitArray)
}

/// A named weft actor under a static supervisor that raises from a BIF, or
/// fails a `let assert`, with the secret in reach.
pub fn a_supervised_weft_actor_crash_keeps_names_and_drops_values_test() {
  capture_start()
  let name = process.new_name("scrub_probe")
  let child =
    actor.new(Nil)
    |> actor.named(name)
    |> actor.on_message(fn(state, probe) {
      case probe {
        Raise(bytes) -> {
          let _ = bif_crash(bytes)
          actor.continue(state)
        }
        Assert(bytes) -> {
          let assert Ok(_) = refuse(bytes)
          actor.continue(state)
        }
      }
    })
    |> actor.supervised
  let assert Ok(started) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(child)
    |> supervisor.start
  process.unlink(started.pid)

  process.send(process.named_subject(name), Raise(<<secret:utf8>>))
  process.sleep(100)
  process.send(process.named_subject(name), Assert(<<secret:utf8>>))
  process.sleep(100)
  let lines = capture_stop() |> lines |> clean
  process.kill(started.pid)

  let raised =
    find(lines, ["level=error", "component=otp", "event=crash_report"])
  assert string.contains(raised, "process=scrub_probe$")
  assert string.contains(raised, "class=error reason=badarg")
  assert string.contains(raised, "at=binary:part/3")

  let asserted = find(lines, ["event=crash_report", "reason=let_assert"])
  assert string.contains(asserted, "module=telemetry/scrub_test")

  let supervised =
    find(lines, ["event=supervisor_report", "context=child_terminated"])
  assert string.contains(supervised, "reason=badarg")
}

/// A `weft` run whose task raises: the worker's own crash report.
pub fn a_weft_run_crash_drops_the_arguments_test() {
  capture_start()
  let outcomes =
    weft.new([fn() { Ok(bif_crash(<<secret:utf8>>)) }])
    |> weft.start
  let lines = capture_stop() |> lines |> clean

  let assert [weft.Crashed(..)] = outcomes
  let line = find(lines, ["event=crash_report", "reason=badarg"])
  assert string.contains(line, "at=binary:part/3")
}

/// A `proc_lib` process with the secret in its mailbox, its dictionary and
/// its failing call's arguments.
pub fn a_crash_report_prints_no_mailbox_dictionary_or_arguments_test() {
  capture_start()
  spawn_crasher(<<secret:utf8>>)
  let lines = capture_stop() |> lines |> clean

  let line = find(lines, ["event=crash_report", "class=error"])
  assert string.contains(line, "initial_call=")
  assert !string.contains(line, "messages")
  assert !string.contains(line, "dictionary")
}

/// A plain spawned process, which the emulator reports itself.
pub fn an_emulator_error_keeps_only_the_tag_test() {
  capture_start()
  raw_crasher(<<secret:utf8>>)
  let lines = capture_stop() |> lines |> clean

  let line = find(lines, ["event=process_crashed", "reason=badmatch"])
  assert string.contains(line, "pid=<")
}

/// A `gen_server` stopping with its state, last message and reason all
/// the secret.
pub fn a_gen_server_termination_drops_state_and_last_message_test() {
  capture_start()
  gen_server_crasher(<<secret:utf8>>)
  let lines = capture_stop() |> lines |> clean

  let line = find(lines, ["event=server_terminated", "behaviour=gen_server"])
  assert string.contains(line, "reason=refused")
}

/// A weft actor sent a message it does not select for warns with the
/// message `string.inspect`ed; only its constructor survives.
pub fn a_discarded_message_keeps_only_its_constructor_test() {
  capture_start()
  let assert Ok(started) =
    actor.new(Nil)
    |> actor.on_message(fn(state, _message: Nil) { actor.continue(state) })
    |> actor.start
  let pid = started.pid
  send_raw(pid, Ok(<<secret:utf8>>))
  process.sleep(100)
  let lines = capture_stop() |> lines |> clean

  let line = find(lines, ["event=discarded_message", "level=warning"])
  assert string.contains(line, "source=weft/actor")
  assert string.contains(line, "message=Ok")
}

/// A library's free text is withheld: only its size is printed.
pub fn foreign_text_is_withheld_test() {
  capture_start()
  string_event("handler crashed: " <> secret)
  let lines = capture_stop() |> lines |> clean

  let line = find(lines, ["event=foreign_text"])
  assert string.contains(line, "bytes=")
}

/// Each line is one line: a report's newlines never reach the output.
pub fn every_line_is_one_line_test() {
  capture_start()
  spawn_crasher(<<secret:utf8>>)
  gen_server_crasher(<<secret:utf8>>)
  let lines = capture_stop() |> lines

  list.each(lines, fn(line) {
    assert string.ends_with(line, "\n")
    assert !string.contains(string.drop_end(line, 1), "\n")
    assert string.starts_with(line, "time=")
  })
}

/// Sends `message` to `pid` as a bare term, which no weft actor selects
/// for.
@external(erlang, "telemetry_test_ffi", "send_raw")
fn send_raw(pid: process.Pid, message: a) -> Nil

@external(erlang, "telemetry_test_ffi", "factory_child_report")
fn factory_child_report(reason: BitArray) -> Dynamic

/// The report a mist connection's factory supervisor writes when a
/// request handler fails, whose offender has no argument list: it renders,
/// and the inspected exception in its reason does not.
pub fn a_factory_child_report_renders_without_its_reason_text_test() {
  let line =
    format(factory_child_report(<<"Errored(":utf8, secret:utf8, ")":utf8>>))
  let _ = clean([line])

  assert string.contains(line, "event=supervisor_report")
  assert string.contains(line, "supervisor=glisten_connection_supervisor$19078")
  assert string.contains(
    line,
    "start=gleam@otp@factory_supervisor:start_child_callback ",
  )
  assert string.contains(line, "reason=<binary>")
}
