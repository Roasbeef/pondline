//// The generated SQL modules against the files they are generated from
//// (ADR-007).
////
//// `make gen-sql` downloads sqlc, so `make check` cannot regenerate and
//// compare. It can read the sources, though, and check that the generated
//// text still holds them: a `.sql` file edited without a `make gen-sql`
//// fails here. The tests run from `packages/mailbox`, so the paths are
//// relative to it.

import gleam/int
import gleam/list
import gleam/string
import mailbox/schema
import simplifile

/// The migration files, in the order the embedder reads them.
fn migration_files() -> List(String) {
  let assert Ok(names) = simplifile.read_directory("sql")

  names
  |> list.filter(string.ends_with(_, ".sql"))
  |> list.sort(string.compare)
}

/// `mailbox/schema` holds exactly the migration files, in number order, and
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

/// Whether every codepoint of a string is below 128. Parrot counts bytes as
/// characters, so a multi-byte character corrupts what it generates.
fn is_ascii(text: String) -> Bool {
  text
  |> string.to_utf_codepoints
  |> list.all(fn(codepoint) { string.utf_codepoint_to_int(codepoint) < 128 })
}
