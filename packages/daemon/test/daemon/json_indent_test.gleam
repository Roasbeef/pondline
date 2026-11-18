//// Tests for `daemon/json_indent`: the layout, and that indenting only adds
//// whitespace between tokens and never changes what the JSON says.

import daemon/json_indent
import gleam/dynamic/decode
import gleam/json
import qcheck

pub fn an_object_is_indented_two_spaces_a_level_test() {
  assert json_indent.indent("{\"ok\":true,\"result\":{\"n\":1,\"xs\":[1,2]}}")
    == "{\n  \"ok\": true,\n  \"result\": {\n    \"n\": 1,\n    \"xs\": [\n      1,\n      2\n    ]\n  }\n}"
}

pub fn empty_containers_stay_whole_test() {
  assert json_indent.indent("{\"a\":{},\"b\":[]}")
    == "{\n  \"a\": {},\n  \"b\": []\n}"
}

pub fn a_trailing_newline_survives_test() {
  assert json_indent.indent("{\"a\":1}\n") == "{\n  \"a\": 1\n}\n"
}

pub fn structure_characters_inside_a_string_are_data_test() {
  // The comma, colon, braces and the escaped quote all sit inside one string.
  let compact = "{\"k\":\"a,b:{c}[d]\\\"e,f\"}"

  assert json_indent.indent(compact) == "{\n  \"k\": \"a,b:{c}[d]\\\"e,f\"\n}"
}

pub fn an_escaped_backslash_before_a_quote_ends_the_string_test() {
  // `\\` is one backslash, so the quote after it closes the string and the
  // comma after that is structure again.
  let compact = "{\"k\":\"x\\\\\",\"j\":1}"

  assert json_indent.indent(compact) == "{\n  \"k\": \"x\\\\\",\n  \"j\": 1\n}"
}

pub fn text_with_no_structure_is_unchanged_test() {
  assert json_indent.indent("") == ""
  assert json_indent.indent("true\n") == "true\n"
}

pub fn indenting_never_changes_the_value_test() {
  // Any string, however hostile, must decode to itself after indenting.
  qcheck.default_config()
  |> qcheck.with_test_count(200)
  |> qcheck.with_seed(qcheck.seed(809))
  |> qcheck.run(qcheck.string(), fn(text) {
    let compact =
      json.object([
        #("k", json.string(text)),
        #("xs", json.array([text, "{", "\\"], json.string)),
        #("n", json.int(7)),
      ])
      |> json.to_string

    let indented = json_indent.indent(compact)
    let decoder = {
      use k <- decode.field("k", decode.string)
      use xs <- decode.field("xs", decode.list(decode.string))
      use n <- decode.field("n", decode.int)

      decode.success(#(k, xs, n))
    }

    assert json.parse(indented, decoder) == Ok(#(text, [text, "{", "\\"], 7))
  })
}
