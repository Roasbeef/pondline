//// Embeds the mailbox's migrations, the checked-in files under `sql/`, into
//// the generated module `src/mailbox/schema.gleam` (ADR-007).
////
//// Run from `packages/mailbox`, through `make gen-sql`:
////
//// ```text
//// gleam run -m embed_schema
//// ```
////
//// ## Why the migrations are embedded
////
//// The `.sql` files are the source of truth, and the store needs the same
//// text to build a database. Reading the files at startup would make a
//// running mailbox depend on a source tree it does not ship, so the text is
//// copied into a module holding `version` and `migrations`, which the store
//// imports. The module is generated, committed and never edited by hand, and
//// `test/mailbox/sql_drift_test.gleam` fails when it and the files disagree.
////
//// ## How work moves through this module
////
//// 1. `migration_files` lists `sql/` and keeps the files named
////    `NNN_<name>.sql`, sorted by name, which is version order because the
////    prefix has a fixed width.
//// 2. `numbered` checks that the prefixes run `001`, `002`, ... with no gap,
////    since migration `n` is applied to a database at version `n - 1` and a
////    gap would leave a version nothing describes.
//// 3. `literal` refuses any character outside ASCII and escapes the text as
////    a Gleam string, and `module_source` lays the module out.
////
//// ## Why a failure panics
////
//// A generator must exit non-zero when it fails, and the standard library
//// has no process exit. `main` therefore turns a `Failure` into a `panic`
//// carrying its description, which is the one place this module crashes on
//// purpose. `scripts/gen-sql.sh` stops on the exit status.

import gleam/bool
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import simplifile.{type FileError}

/// Where the migrations live, relative to `packages/mailbox`.
const schema_directory = "sql"

/// The module this program writes.
const output_path = "src/mailbox/schema.gleam"

/// The width of a migration file's number prefix.
const prefix_width = 3

/// Everything that can stop the generator, each with enough context to act on.
pub type Failure {
  /// The schema directory could not be listed.
  CouldNotList(path: String, reason: FileError)

  /// A migration file could not be read.
  CouldNotRead(path: String, reason: FileError)

  /// The generated module could not be written.
  CouldNotWrite(path: String, reason: FileError)

  /// A `.sql` file's name does not start with a three-digit number and `_`.
  Unnumbered(path: String)

  /// The numbers do not run from `001` without a gap: `expected` is the
  /// number the file at `path` should have had.
  OutOfSequence(path: String, expected: Int)

  /// A migration holds a character outside ASCII. Parrot counts bytes as
  /// characters, so the file must be fixed rather than embedded.
  NotAscii(path: String, line: Int)
}

/// Embeds every migration and panics if that fails.
pub fn main() -> Nil {
  case embed() {
    Ok(count) ->
      io.println(
        "embed_schema: wrote "
        <> output_path
        <> " ("
        <> int.to_string(count)
        <> " migrations)",
      )

    // The exit status is the only channel `gen-sql.sh` reads, and a panic is
    // the one way to set it without an `@external`.
    Error(failure) -> panic as { "embed_schema: " <> describe(failure) }
  }
}

/// Explains a failure in a sentence a developer can act on.
///
/// ## Examples
///
/// ```gleam
/// embed_schema.describe(Unnumbered("sql/initial.sql"))
/// // -> "sql/initial.sql must be named NNN_<name>.sql"
/// ```
pub fn describe(failure: Failure) -> String {
  case failure {
    CouldNotList(path:, reason:) ->
      "cannot list " <> path <> ": " <> simplifile.describe_error(reason)

    CouldNotRead(path:, reason:) ->
      "cannot read " <> path <> ": " <> simplifile.describe_error(reason)

    CouldNotWrite(path:, reason:) ->
      "cannot write " <> path <> ": " <> simplifile.describe_error(reason)

    Unnumbered(path:) -> path <> " must be named NNN_<name>.sql"

    OutOfSequence(path:, expected:) ->
      path
      <> " is out of sequence; the next migration is number "
      <> int.to_string(expected)

    NotAscii(path:, line:) ->
      path
      <> " line "
      <> int.to_string(line)
      <> " is not ASCII; parrot corrupts byte offsets on multi-byte text"
  }
}

/// Reads, checks and embeds every migration, returning how many there are.
fn embed() -> Result(Int, Failure) {
  use paths <- result.try(migration_files())
  use Nil <- result.try(numbered(paths, 1))
  use texts <- result.try(list.try_map(paths, read))
  use literals <- result.try(
    list.zip(paths, texts)
    |> list.try_map(fn(pair) { literal(pair.0, pair.1) }),
  )

  simplifile.write(output_path, module_source(literals))
  |> result.map_error(CouldNotWrite(output_path, _))
  |> result.replace(list.length(literals))
}

/// Every `.sql` file in the schema directory, as a path, sorted by name.
///
/// Sorting makes the result independent of directory order, which the
/// operating system does not define, and the fixed-width prefix makes name
/// order version order.
fn migration_files() -> Result(List(String), Failure) {
  use names <- result.try(
    simplifile.read_directory(schema_directory)
    |> result.map_error(CouldNotList(schema_directory, _)),
  )

  names
  |> list.filter(string.ends_with(_, ".sql"))
  |> list.sort(string.compare)
  |> list.map(fn(name) { schema_directory <> "/" <> name })
  |> Ok
}

/// Checks that the files are numbered `expected`, `expected + 1`, ... in
/// order.
fn numbered(paths: List(String), expected: Int) -> Result(Nil, Failure) {
  // Each file must carry the next number; the empty list ends the check.
  case paths {
    [] -> Ok(Nil)

    [path, ..rest] -> {
      use number <- result.try(file_number(path))
      use <- bool.guard(
        when: number != expected,
        return: Error(OutOfSequence(path:, expected:)),
      )

      numbered(rest, expected + 1)
    }
  }
}

/// The number a migration file's name starts with.
fn file_number(path: String) -> Result(Int, Failure) {
  let name = string.drop_start(path, string.length(schema_directory) + 1)
  let prefix = string.slice(name, 0, prefix_width)
  let separator = string.slice(name, prefix_width, 1)

  int.parse(prefix)
  |> result.try(fn(number) {
    case separator {
      "_" -> Ok(number)
      _ -> Error(Nil)
    }
  })
  |> result.replace_error(Unnumbered(path))
}

/// Reads a migration, naming the path if that fails.
fn read(path: String) -> Result(String, Failure) {
  simplifile.read(path)
  |> result.map_error(CouldNotRead(path, _))
}

/// A migration's text as a Gleam string literal, refusing non-ASCII text.
///
/// Newlines stay literal, so the generated module reads like the SQL it
/// holds; only the quote and the backslash need escaping.
///
/// ## Examples
///
/// ```gleam
/// embed_schema.literal("sql/001_a.sql", "a\n\"b\"")
/// // -> Ok("\"a\n\\\"b\\\"\"")
/// ```
pub fn literal(path: String, sql: String) -> Result(String, Failure) {
  let offender =
    sql
    |> string.split("\n")
    |> list.index_map(fn(line, index) { #(index + 1, line) })
    |> list.find(fn(numbered) { !is_ascii(numbered.1) })

  // The first line holding a non-ASCII character is the one to report.
  case offender {
    Ok(#(line, _)) -> Error(NotAscii(path:, line:))

    Error(Nil) -> {
      let escaped =
        sql
        |> string.replace("\\", "\\\\")
        |> string.replace("\"", "\\\"")

      Ok("\"" <> escaped <> "\"")
    }
  }
}

/// Whether every codepoint of a string is below 128.
fn is_ascii(text: String) -> Bool {
  text
  |> string.to_utf_codepoints
  |> list.all(fn(codepoint) { string.utf_codepoint_to_int(codepoint) < 128 })
}

/// The generated module around the migrations' literals, in version order.
///
/// `gen-sql.sh` runs `gleam format` over the result, so the layout here only
/// has to be valid Gleam.
fn module_source(literals: List(String)) -> String {
  let count = int.to_string(list.length(literals))

  "//// Generated by packages/mailbox/dev/embed_schema.gleam. DO NOT EDIT.\n"
  <> "//// The files under packages/mailbox/sql/ are the schema's source of\n"
  <> "//// truth; run `make gen-sql` after changing one.\n\n"
  <> "/// The schema version the migrations reach.\n"
  <> "pub const version = "
  <> count
  <> "\n\n"
  <> "/// The migrations in order: entry `n` (from zero) is `sql/` file number\n"
  <> "/// `n + 1` and moves a database from version `n` to version `n + 1`.\n"
  <> "pub const migrations = [\n"
  <> string.join(
    list.map(literals, fn(literal) { "  " <> literal <> ",\n" }),
    "",
  )
  <> "]\n"
}
