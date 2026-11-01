# ADR-007 — Generate the stores' static SQL with parrot, and keep the schema in checked-in SQL files

**Status**: accepted · **Date**: 2026-11-01 · **Spec ref**: §8.1, §10.2

## Decision

The daemon's and the mailbox's SQLite stores stop holding hand-written SQL
strings and hand-written row decoders for their static statements. Both
come from `parrot` 2.x, which runs a pinned `sqlc` over named queries and
writes a typed Gleam module.

Per package (`daemon`, `mailbox`):

- `sql/NNN_<name>.sql` holds one migration each. Migration `NNN` moves a
  database from version `NNN - 1` to `NNN`. The files that existed when
  this ADR was written are byte for byte the strings the stores applied
  before it, so a shipped migration does exactly what it did.
- `dev/embed_schema.gleam` copies those files, in number order, into the
  generated module `src/<pkg>/schema.gleam` (`schema.version` and
  `schema.migrations`). The store's `schema_version` and its migration list
  are those constants, so the version and the list cannot disagree.
- `src/<pkg>/sql/*.sql` holds the named queries (`-- name: X :one|:many|:exec`),
  grouped by concern, and parrot writes `src/<pkg>/sql.gleam` from them.
- Both generated modules carry a `DO NOT EDIT.` header, are committed, and
  are rewritten only by `make gen-sql` (`scripts/gen-sql.sh`), which must
  be run after any `.sql` file changes.
- The store calls each generated function and hands the result to a small
  bridge (`query` and `write`) that binds parrot's parameters as sqlight
  values. sqlight stays the driver.

What stays hand-written, because it is not a static named statement: the
pragmas (`configure`, `settings`, `PRAGMA user_version=N`), `BEGIN
IMMEDIATE`, `COMMIT` and `ROLLBACK`, and the migration runner that `exec`s
each embedded migration. Nothing in either store composes a statement at
run time apart from those pragmas.

The `.sql` files are ASCII only.

## Why

The two stores held about sixty SQL strings, each paired by hand with a
positional decoder and a positional parameter list. A column added to a
`SELECT` and not to its decoder, or two parameters swapped, compiles and
fails only at run time, and only on the path that runs it. Generated code
types every parameter by its column and names every result field, so those
mistakes become compile errors at the call site.

### The pilot

Before converting anything we ran parrot 2.3.0 (which pins sqlc 1.31.1)
over the real schema and over the statements most likely to defeat it, in
a scratch project. It parsed and typed all of the following, and emitted
each statement as written:

- `STRICT` tables, `STRICT, WITHOUT ROWID` tables, the partial index
  `outbox_retransmit ... WHERE retransmit_at IS NOT NULL`, `AUTOINCREMENT`,
  and the mailbox's `REFERENCES ... ON DELETE CASCADE`. sqlc reads the
  schema that `sqlite3 <db> .schema` prints, which keeps `STRICT`, and at
  run time the store applies its own embedded DDL, so the runtime schema is
  `STRICT` exactly as before. sqlc never touches a database the stores
  open.
- `UPDATE ... RETURNING`, `INSERT OR REPLACE`, `INSERT ... SELECT ...
  RETURNING`, a correlated `EXISTS` column, a scalar subquery in a `WHERE`,
  `UNION ALL`, `GROUP BY` with aggregates, `ORDER BY rowid`, `LIMIT ?`, and
  `BLOB` parameters and results (typed `BitArray`, and `Option(BitArray)`
  for a nullable column).

"As written" means byte for byte the query file's text with the trailing
`;` dropped and each `sqlc.arg(name)` or `sqlc.narg(name)` replaced by a
numbered `?N`. Comments between queries are not emitted.

Four statements needed rewording, none of them in what they do:

- **An `INSERT ... SELECT` from the table it inserts into** (`copy_row`).
  sqlc reports an unqualified column as ambiguous, so the source is aliased
  (`FROM outbox AS replaced`) and its columns qualified. The statement also
  binds two envelope identifiers; positional `?` named both parameters
  `envelope`, which is a duplicate label in Gleam, so it uses
  `sqlc.arg(fresh)` and `sqlc.arg(replaces)`.
- **An optional filter** (`?1 IS NULL OR contact = ?1`). Parrot crashes on
  numbered parameters, which have no name. With `sqlc.narg(contact) IS NULL`
  first, sqlc cannot type the parameter and parrot falls back to
  `Dynamic`. Putting the typed comparison first, `(contact =
  sqlc.narg(contact) OR sqlc.narg(contact) IS NULL)`, types it
  `Option(BitArray)`.
- **`SUM` over an integer column.** sqlc types `SUM(size)` as
  `Option(Float)`, and SQLite returns an integer, which `decode.float`
  rejects at run time. `COALESCE` types it `Dynamic`. `CAST(SUM(size) AS
  INTEGER)` types it `Int`.
- **Unnamed result columns** (`EXISTS (...)`, `COUNT(*)`) are aliased so the
  generated field has a meaningful name.

One typing rule surfaced in the retrofit rather than the pilot: sqlc types
a parameter by the column it is compared with or assigned to, so one bound
against a nullable column (`outbox.receipt`, `outbox.retransmit_at`,
`outbox.message_id`) is generated as an `Option`, and the store passes it
wrapped in `Some`.

Two behaviours of the tool shape the script. Parrot prints most failures in
red and still exits 0, so `scripts/gen-sql.sh` requires its success line
rather than trusting the exit status. And parrot slices query files by byte
offset while counting characters, as loom's pilot found (loom ADR-004), so
a multi-byte character silently corrupts every later query in the file.
The embedder refuses non-ASCII schema files for the same reason, and the
drift tests assert ASCII.

### What `make check` verifies without the network

Regenerating needs the sqlc download, so `make check` cannot rerun the
generator. Each package instead has a drift test that reads the `.sql`
files from disk: the embedded migrations must equal `sql/NNN_*.sql` in
order, with numbering contiguous from `001`, and every query file's
statement, rewritten the way sqlc rewrites it, must appear verbatim in
`sql.gleam`. An edited `.sql` file without a `make gen-sql` therefore fails
`make check`. What the test cannot see is a parameter or column type that
sqlc would now infer differently for an unchanged statement, which only a
schema change can cause, and a schema change is a new migration file,
after which the query text is regenerated anyway.

## Consequences

- **A single-maintainer dependency.** Parrot has one maintainer and thin
  unit tests. Loom has used it since its ADR-004, on more statements than
  ours, which is most of the evidence.
- **A runtime dependency.** Generated code imports `parrot/dev` (the
  `Param` type and a boolean decoder), so parrot becomes a full dependency
  of `daemon` and `mailbox`, and its code-generation dependencies
  (`gleam_httpc`, `tom`, `envoy` and others) enter both resolution trees
  and the mailbox release, unused at run time. Because starting an
  application starts every application its `.app` file names, starting the
  mailbox now also starts OTP's `inets` (parrot names `gleam_httpc`, which
  names `inets`), so `scripts/release.sh` bundles it. Nothing calls it.
- **A network fetch at generation time.** `make gen-sql` downloads sqlc
  1.31.1 into `<pkg>/build/.parrot/sqlc` on first use. The version and a
  per-platform SHA-256 are pinned in parrot's source, the binary is
  re-hashed on every run, and a mismatch stops the generator. A machine
  without network access can pre-provision the binary at that path. It
  also needs the `sqlite3` command, which parrot uses to dump the schema.
- **The bridge has an error arm no query reaches.** Parrot's `Param` also
  has timestamp, date, list and dynamic variants, which sqlight cannot
  bind. Our tables are `STRICT` over `INTEGER`, `TEXT` and `BLOB`, so sqlc
  never produces them, but the bridge must still say what it does: it
  returns a `Mismatch` SQLite error rather than crash.
- **The escape hatch.** If the dependency weight or the maintainer risk
  becomes unacceptable, the runtime module is about a hundred lines and can
  be vendored, with the generated module's `import parrot/dev` rewritten
  after generation. The query files, the embedder and the drift tests stay
  as they are.
- **Revisit** if parrot fixes the byte-offset bug (the ASCII rule can go),
  if a store needs a statement composed at run time (it stays hand-written
  beside the generated ones, and this ADR gets an addendum), or if sqlc's
  SQLite parser stops accepting a construct we use.

## Addendum (2026-11-01): the runtime module is vendored

The owner chose the escape hatch above before the first merge. Parrot's
`.app` file starts `gleam_httpc` and with it OTP's `inets` in every daemon
and mailbox, an HTTP client stack in a node whose only network path is
meant to be its `Dialer` and the Tor sidecar. Nothing called it, but the
security priority puts code that ships and starts without a use above the
cost of a copy.

- `parrot` is a dev dependency of `daemon` and `mailbox`, used only by
  `make gen-sql`, and the release bundles the same OTP applications it did
  before this ADR (no `inets`).
- Each package carries `<pkg>/internal/sql_param`: parrot 2.3.0's `Param`
  trimmed to `ParamInt`, `ParamString`, `ParamBitArray` and
  `ParamNullable`, plus `bool_decoder` (Apache-2.0, attributed in the
  module doc). `scripts/gen-sql.sh` rewrites the generated
  `import parrot/dev` to `import <pkg>/internal/sql_param as dev`, so the
  rest of the generated text is parrot's own.
- The bridge's `Mismatch` arm is gone: a statement needing a timestamp,
  date, list, float, boolean or dynamic parameter does not compile, so
  `bind` is total. The drift test checks the rewritten import instead of
  searching for those variants.
- A parrot upgrade that changes `parrot/dev`'s shape (a variant renamed,
  a new decoder the generated code calls) fails to compile here; the copy
  is updated by hand then.
