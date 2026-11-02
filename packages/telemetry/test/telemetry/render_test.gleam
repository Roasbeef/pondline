//// Our own lines: the field kinds, the level names and the escaping.

import core/id
import core/secret
import gleam/option.{None, Some}
import telemetry/field
import telemetry/handler
import telemetry/level
import telemetry/line
import telemetry/logfmt

type Reason {
  Busy
  Refused(detail: String)
}

pub fn an_identifier_renders_as_its_prefix_test() {
  let assert Ok(queue) = id.from_hex("3fa2c1d0aabbccddeeff001122334455")
  assert field.render(field.id("queue", queue)) == "queue=3fa2c1d0"
}

pub fn numbers_and_durations_render_bare_test() {
  assert field.render(field.count("status", 200)) == "status=200"
  assert field.render(field.millis("elapsed", 12)) == "elapsed_ms=12"
}

/// A tag is the constructor's name and never what it holds: not a field's
/// text, not a `Secret`, not a bare string or bytes.
pub fn a_tag_names_the_constructor_only_test() {
  assert field.render(field.tag("reason", Busy)) == "reason=busy"
  assert field.render(field.tag("reason", Refused("PLANTED")))
    == "reason=refused"
  assert field.render(field.tag("reason", secret.new(<<"PLANTED">>)))
    == "reason=secret"
  assert field.render(field.tag("reason", Some("PLANTED"))) == "reason=some"
  assert field.render(field.tag("reason", None)) == "reason=none"
  assert field.render(field.tag("reason", "PLANTED")) == "reason=<binary>"
  assert field.render(field.tag("reason", <<"PLANTED">>)) == "reason=<binary>"
  assert field.render(field.tag("reason", ["PLANTED"])) == "reason=<list>"
  assert field.render(field.tag("reason", 7)) == "reason=<integer>"
}

pub fn a_line_is_component_event_and_fields_test() {
  assert line.render("http", "request", [field.count("status", 200)])
    == "component=http event=request status=200"
}

/// A key or word that is not one bare token cannot split the line.
pub fn keys_and_words_stay_one_token_test() {
  assert line.render("Fetch Manager", "a=b", [])
    == "component=_etch__anager event=a_b"
  assert field.render(field.count("queue id", 1)) == "queue_id=1"
}

pub fn quoting_escapes_what_would_split_a_line_test() {
  assert logfmt.quote("busy") == "busy"
  assert logfmt.quote("") == "\"\""
  assert logfmt.quote("two words") == "\"two words\""
  assert logfmt.quote("a=b") == "\"a=b\""
  assert logfmt.quote("say \"hi\"") == "\"say \\\"hi\\\"\""
  assert logfmt.quote("back\\slash") == "\"back\\\\slash\""
  assert logfmt.quote("one\ntwo") == "\"one\\ntwo\""
  assert logfmt.quote("bell\u{07}") == "\"bell\\u{7}\""
}

pub fn levels_parse_as_operators_type_them_test() {
  assert level.parse("debug") == Ok(level.Debug)
  assert level.parse(" Info ") == Ok(level.Info)
  assert level.parse("WARN") == Ok(level.Warning)
  assert level.parse("err") == Ok(level.Error)
  assert level.parse("loud") == Error(Nil)
  assert level.name(level.Warning) == "warning"
  assert handler.threshold_named(Ok("debug")) == level.Debug
  assert handler.threshold_named(Ok("loud")) == level.Info
  assert handler.threshold_named(Error(Nil)) == level.Info
}
