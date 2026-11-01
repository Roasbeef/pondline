#!/usr/bin/env bash
# Regenerate the generated SQL modules (docs/adr/007-parrot-sql-codegen.md).
#
# Run it, through `make gen-sql`, after editing any .sql file, then review
# and commit the diff. `make check` cannot regenerate (this needs the
# network), but each package's sql_drift_test fails when a .sql file and its
# generated module disagree.
#
# For every package with a dev/embed_schema.gleam:
#
#   packages/<pkg>/sql/NNN_<name>.sql   the migrations, one per version
#     -> src/<pkg>/schema.gleam         (dev/embed_schema.gleam)
#   packages/<pkg>/src/<pkg>/sql/*.sql  the named queries
#     -> src/<pkg>/sql.gleam            (parrot, through sqlc)
#
# Parrot reads the schema from a database, so the migrations are loaded in
# order into a scratch SQLite file first. It runs a pinned sqlc (the version
# and a per-platform SHA-256 live in parrot's source), downloading it on
# first use to <pkg>/build/.parrot/sqlc and re-hashing it on every run; a
# machine without network access can pre-provision the binary at that path.
#
# Requirements: gleam, and the sqlite3 command (parrot dumps the schema with
# it).
#
# Both the embedder and parrot run through `gleam run`, which compiles the
# whole package first, tests included. Regenerate while the package still
# builds: change the .sql file, run this, then change the Gleam that calls
# the new or renamed query.
#
# Known constraints of parrot 2.3.0 (ADR-007 has the pilot that found them):
#   * Query and schema files must be ASCII. Parrot slices by byte offset
#     while counting characters, so one multi-byte character silently
#     corrupts every later query in the file.
#   * Name a parameter with sqlc.arg(name) when positional `?` would give two
#     parameters the same name, and never use a numbered `?1`: parrot cannot
#     name it. For an optional filter write
#     `(col = sqlc.narg(col) OR sqlc.narg(col) IS NULL)`, typed comparison
#     first, or the parameter is typed Dynamic.
#   * SUM over an integer column is typed Float; write
#     CAST(SUM(col) AS INTEGER). Alias every computed column.
#   * Parrot prints most failures and still exits 0, so this script requires
#     its success line, and refuses an unknown column type and a Dynamic
#     parameter (which parrot generates with a warning, or none at all).
set -euo pipefail
cd "$(dirname "$0")/.."

command -v sqlite3 >/dev/null || {
	echo "gen-sql: the sqlite3 command is required (parrot dumps the schema with it)" >&2
	exit 1
}

# One scratch directory for every package's database and log, removed however
# the script ends.
scratch="$(mktemp -d -t reedwire-gen-sql-XXXXXX)"
trap 'rm -rf "$scratch"' EXIT

gen_package() {
	local pkg="$1"
	local dir="packages/$pkg"
	echo "==> $pkg"

	# The migrations first: the scratch database below is built from the same
	# files the embedded module holds.
	(cd "$dir" && gleam run -m embed_schema)
	(cd "$dir" && gleam format "src/$pkg/schema.gleam")

	if ! compgen -G "$dir/src/$pkg/sql/*.sql" >/dev/null; then
		echo "    no queries under src/$pkg/sql; parrot skipped"
		return
	fi

	local tmpdb="$scratch/$pkg.db" log="$scratch/$pkg.log"

	# The glob sorts by name, and the fixed-width prefix makes that version
	# order, which matters because a later migration alters an earlier table.
	local file
	for file in "$dir"/sql/[0-9][0-9][0-9]_*.sql; do
		sqlite3 "$tmpdb" <"$file"
	done

	(cd "$dir" && gleam run --module parrot -- --sqlite "$tmpdb") >"$log" 2>&1 || {
		cat "$log" >&2
		echo "gen-sql: parrot failed for $pkg" >&2
		exit 1
	}

	if ! grep -q "SQL successfully generated!" "$log"; then
		cat "$log" >&2
		echo "gen-sql: parrot reported an error for $pkg" >&2
		exit 1
	fi

	if grep -q "unknown column type" "$log"; then
		grep "unknown column type" "$log" >&2
		echo "gen-sql: parrot could not type a column in $pkg; alias or cast it" >&2
		exit 1
	fi

	# A parameter sqlc cannot type becomes Dynamic without any warning, and
	# the bridge cannot bind one, so it is refused here rather than at run
	# time.
	if grep -q "Dynamic" "$dir/src/$pkg/sql.gleam"; then
		grep -n "Dynamic" "$dir/src/$pkg/sql.gleam" >&2
		echo "gen-sql: sqlc could not type a parameter in $pkg; see the constraints above" >&2
		exit 1
	fi

	echo "    wrote src/$pkg/schema.gleam and src/$pkg/sql.gleam"
}

for embedder in packages/*/dev/embed_schema.gleam; do
	pkg="${embedder#packages/}"
	gen_package "${pkg%%/*}"
done

echo "generated SQL modules are up to date; review and commit the diff"
