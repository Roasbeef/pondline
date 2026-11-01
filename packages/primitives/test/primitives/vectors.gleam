//// The loader the vector tests share: reads one trimmed vector file from
//// `test/vectors/` and hands each test case back as its identifier and a
//// bag of named fields, so a test module decides for itself which fields
//// the primitive under test consumes.
////
//// The files are produced by `test/vectors/trim.py` from the upstream
//// Wycheproof and NIST ACVP repositories at the commit each file records,
//// and each keeps the upstream `tcId`, so a failure names a case that can
//// be looked up upstream. Every lookup here uses `let assert`: a vector
//// file that does not decode is a broken fixture, and a test should stop
//// on it rather than pass vacuously.

import gleam/bit_array
import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/string
import simplifile

/// One test case: the upstream identifier and every field the case
/// carries, including the group-level fields `trim.py` copied onto it.
pub type Vector {
  Vector(id: Int, fields: Dict(String, Dynamic))
}

/// Reads and decodes `test/vectors/<name>.json`.
///
/// ## Examples
///
/// ```gleam
/// vectors.load("wycheproof_x25519")
/// // -> [Vector(id: 1, ..), ..]
/// ```
pub fn load(name: String) -> List(Vector) {
  let path = "test/vectors/" <> name <> ".json"
  let assert Ok(text) = simplifile.read(path) as "the vector file is present"
  let test_decoder = {
    use id <- decode.field("tcId", decode.int)
    use fields <- decode.then(decode.dict(decode.string, decode.dynamic))
    decode.success(Vector(id:, fields:))
  }
  let file_decoder = {
    use tests <- decode.field("tests", decode.list(test_decoder))
    decode.success(tests)
  }
  let assert Ok(tests) = json.parse(text, file_decoder)
    as "the vector file decodes"
  tests
}

fn field(vector: Vector, key: String, decoder: decode.Decoder(a)) -> a {
  let assert Ok(raw) = dict.get(vector.fields, key)
    as "the vector carries the field"
  let assert Ok(value) = decode.run(raw, decoder)
    as "the field has the expected type"
  value
}

/// Whether the case carries the named field at all.
///
/// ## Examples
///
/// ```gleam
/// vectors.has(vector, "context")
/// ```
pub fn has(vector: Vector, key: String) -> Bool {
  dict.has_key(vector.fields, key)
}

/// A hex-encoded byte field.
///
/// ## Examples
///
/// ```gleam
/// vectors.hex(vector, "public")
/// ```
pub fn hex(vector: Vector, key: String) -> BitArray {
  let assert Ok(bytes) =
    field(vector, key, decode.string)
    |> string.uppercase
    |> bit_array.base16_decode
    as "the field is well-formed hex"
  bytes
}

/// A string field.
///
/// ## Examples
///
/// ```gleam
/// vectors.text(vector, "result")
/// ```
pub fn text(vector: Vector, key: String) -> String {
  field(vector, key, decode.string)
}

/// An integer field.
///
/// ## Examples
///
/// ```gleam
/// vectors.int(vector, "size")
/// ```
pub fn int(vector: Vector, key: String) -> Int {
  field(vector, key, decode.int)
}

/// A boolean field.
///
/// ## Examples
///
/// ```gleam
/// vectors.bool(vector, "testPassed")
/// ```
pub fn bool(vector: Vector, key: String) -> Bool {
  field(vector, key, decode.bool)
}

/// The Wycheproof `flags` list, empty for a case without one.
///
/// ## Examples
///
/// ```gleam
/// vectors.flags(vector)
/// // -> ["LowOrderPublic", "ZeroSharedSecret"]
/// ```
pub fn flags(vector: Vector) -> List(String) {
  case dict.has_key(vector.fields, "flags") {
    True -> field(vector, "flags", decode.list(decode.string))
    False -> []
  }
}

/// Whether the case carries the Wycheproof flag.
///
/// ## Examples
///
/// ```gleam
/// vectors.flagged(vector, "ZeroSharedSecret")
/// ```
pub fn flagged(vector: Vector, flag: String) -> Bool {
  list.contains(flags(vector), flag)
}

/// The cases whose named field equals `value`.
///
/// ## Examples
///
/// ```gleam
/// vectors.where(tests, "function", "decapsulation")
/// ```
pub fn where(tests: List(Vector), key: String, value: String) -> List(Vector) {
  list.filter(tests, fn(vector) {
    has(vector, key) && text(vector, key) == value
  })
}

/// Runs `check` over every case and returns the identifiers of those for
/// which it returned `False`, so an assertion on the empty list names
/// every failing upstream case at once.
///
/// ## Examples
///
/// ```gleam
/// vectors.failing(tests, fn(v) { primitives.x25519(..) == Ok(..) })
/// // -> []
/// ```
pub fn failing(tests: List(Vector), check: fn(Vector) -> Bool) -> List(Int) {
  tests
  |> list.filter(fn(vector) { !check(vector) })
  |> list.map(fn(vector) { vector.id })
}
