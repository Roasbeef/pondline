//// The generated SQL modules against the files they are generated from
//// (ADR-007).
////
//// `make gen-sql` downloads sqlc, so `make check` cannot regenerate and
//// compare. It can read the sources, though, and check that the generated
//// text still holds them: a `.sql` file edited without a `make gen-sql`
//// fails here. The check is of SQL text only: a hand edit to a generated
//// parameter list or decoder passes it, and only `make gen-sql` followed by
//// `git diff --exit-code` catches that. The tests run from
//// `packages/daemon`, so the paths are relative to it.

import daemon/schema
import gleam/bit_array
import gleam/int
import gleam/list
import gleam/string
import primitives
import simplifile

/// The migration files, in the order the embedder reads them.
fn migration_files() -> List(String) {
  let assert Ok(names) = simplifile.read_directory("sql")

  names
  |> list.filter(string.ends_with(_, ".sql"))
  |> list.sort(string.compare)
}

/// `daemon/schema` holds exactly the migration files, in number order, and
/// its version is how many there are. The numbers run from `001` without a
/// gap, because migration `n` is applied to a database at version `n - 1`.
pub fn embedded_migrations_match_the_sql_files_test() {
  let names = migration_files()

  let texts =
    list.map(names, fn(name) {
      let assert Ok(text) = simplifile.read("sql/" <> name)
      text
    })

  assert texts == schema.migrations
  assert schema.version == list.length(names)

  let prefixes = list.map(names, string.slice(_, 0, 4))

  let expected =
    list.index_map(names, fn(_, index) {
      string.pad_start(int.to_string(index + 1), 3, "0") <> "_"
    })

  assert prefixes == expected
  assert list.all(texts, is_ascii)
}

/// The SHA-256 of every migration that has shipped. A database already at
/// version `n` never runs migration `n` again, so editing a shipped file
/// (and regenerating) would leave new and old installs on different
/// schemas. A new migration is a new file; add its line here when it ships.
const shipped = [
  #(
    "001_initial.sql",
    "C96E2F0BA54ABC259712C9115416CDA6D09F5A2BDB2CA606EA804369E6BE4716",
  ),
  #(
    "002_retransmit.sql",
    "3DA8D149D8BFD9368A787E4A087303585DB80286F14E0EB3DC9DDA6CE9444084",
  ),
]

pub fn shipped_migrations_never_change_test() {
  list.each(shipped, fn(pin) {
    let #(name, digest) = pin
    let assert Ok(text) = simplifile.read("sql/" <> name)

    assert bit_array.base16_encode(primitives.sha256(<<text:utf8>>)) == digest
  })
}

/// Every named query in `src/daemon/sql/` has its function in `daemon/sql`,
/// and that function's SQL text is the query as sqlc emits it. A query file
/// edited, added to or renamed in without a `make gen-sql` fails here.
pub fn generated_queries_match_the_query_files_test() {
  let directory = "src/daemon/sql"
  let assert Ok(generated) = simplifile.read("src/daemon/sql.gleam")
  let assert Ok(names) = simplifile.read_directory(directory)

  let files =
    names
    |> list.filter(string.ends_with(_, ".sql"))
    |> list.sort(string.compare)

  assert files != []

  // The generated module imports the trimmed copy of parrot's runtime, not
  // parrot (a dev dependency), so a parameter of any type the copy lacks is
  // a compile error rather than something to search for here.
  assert string.contains(generated, "import daemon/internal/sql_param as dev")

  list.each(files, fn(file) {
    let assert Ok(text) = simplifile.read(directory <> "/" <> file)
    assert is_ascii(text)

    list.each(named_queries(text), fn(query) {
      let #(name, body) = query
      assert string.contains(generated, "pub fn " <> snake_case(name) <> "(")
      assert holds_literal(generated, emitted(body))
    })
  })
}

/// The named queries of one file, as each name and the statement after its
/// `-- name:` line up to the `;` that ends it. The text before the first
/// name is the file's header comment, and a comment after a statement's `;`
/// belongs to no statement, as sqlc reads it.
fn named_queries(text: String) -> List(#(String, String)) {
  let assert [_header, ..chunks] = string.split(text, "-- name: ")

  list.map(chunks, fn(chunk) {
    let assert Ok(#(heading, rest)) = string.split_once(chunk, "\n")
    let assert [name, ..] = string.split(heading, " ")
    let assert Ok(#(statement, _)) = string.split_once(rest, ";")
    #(name, statement)
  })
}

/// A statement as sqlc emits it: each `sqlc.arg(name)` and `sqlc.narg(name)`
/// becomes `?N`, numbered by where its name first appears.
fn emitted(statement: String) -> String {
  rewrite(statement, [], "")
}

/// Rewrites the named parameters left in `text`, given the names already
/// numbered, appending the result to `done`.
fn rewrite(text: String, numbered: List(String), done: String) -> String {
  // Each pass takes the text up to the next macro; none left ends the walk.
  case string.split_once(text, "sqlc.") {
    Error(Nil) -> done <> text

    Ok(#(before, after)) -> {
      let assert Ok(#(_macro, rest)) = string.split_once(after, "(")
      let assert Ok(#(name, rest)) = string.split_once(rest, ")")

      let numbered = case list.contains(numbered, name) {
        True -> numbered
        False -> list.append(numbered, [name])
      }

      let position =
        list.take_while(numbered, fn(known) { known != name })
        |> list.length

      rewrite(
        rest,
        numbered,
        done <> before <> "?" <> int.to_string(position + 1),
      )
    }
  }
}

/// Whether the generated source holds `statement` as one whole string
/// literal. Parrot keeps a newline at the front of a statement that a comment
/// preceded, so either opening is accepted.
fn holds_literal(generated: String, statement: String) -> Bool {
  let escaped =
    statement
    |> string.replace("\\", "\\\\")
    |> string.replace("\"", "\\\"")

  string.contains(generated, "\"" <> escaped <> "\"")
  || string.contains(generated, "\"\n" <> escaped <> "\"")
}

/// The function parrot names a query: `CopyForRetransmit` is
/// `copy_for_retransmit`.
fn snake_case(name: String) -> String {
  name
  |> string.to_graphemes
  |> list.index_map(fn(grapheme, index) {
    let lower = string.lowercase(grapheme)

    case lower == grapheme, index {
      True, _ | False, 0 -> lower
      False, _ -> "_" <> lower
    }
  })
  |> string.concat
}

/// Whether every codepoint of a string is below 128. Parrot counts bytes as
/// characters, so a multi-byte character corrupts what it generates.
fn is_ascii(text: String) -> Bool {
  text
  |> string.to_utf_codepoints
  |> list.all(fn(codepoint) { string.utf_codepoint_to_int(codepoint) < 128 })
}
