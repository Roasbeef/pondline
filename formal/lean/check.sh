#!/usr/bin/env bash
# check.sh: the gate for the Lean proofs (docs/formal/lean.md).
#
# Usage: formal/lean/check.sh [--write]
#
# 1. Refuses any proof escape hatch in the sources: `sorry`, `admit`, a
#    declared `axiom`, `native_decide`, or an `implemented_by`/`extern`
#    that would let compiled code stand in for a definition.
# 2. Builds the library and the vector generator with `lake build`.
# 3. Prints the axioms of every main theorem (Axioms.lean) and fails unless
#    each depends only on Lean's standard axioms: propext,
#    Classical.choice and Quot.sound.
# 4. Regenerates the conformance vectors and diffs them against the
#    committed packages/core/test/core/formal_vectors.txt. With --write it
#    replaces the committed file instead, which is what a deliberate change
#    to a transcription does before the Gleam test is rerun.
#
# Exits non-zero on any failure.
set -euo pipefail
cd "$(dirname "$0")"

vectors=../../packages/core/test/core/formal_vectors.txt
mode=check
case "${1:-}" in
--write) mode=write ;;
"") ;;
*)
	echo "usage: $0 [--write]" >&2
	exit 2
	;;
esac

sources=(Pondline.lean Pondline/*.lean GenVectors.lean Axioms.lean)

echo "== escape hatches"
if grep -nE '\bsorry\b|\badmit\b|^[[:space:]]*(private[[:space:]]+)?axiom[[:space:]]|native_decide|implemented_by|@\[extern' \
	"${sources[@]}"; then
	echo "check.sh: a proof escape hatch is present" >&2
	exit 1
fi

echo "== lake build"
lake build

echo "== axioms"
axioms=$(lake env lean Axioms.lean)
printf '%s\n' "$axioms"
expected=$(grep -c '^#print axioms' Axioms.lean)
reported=$(printf '%s\n' "$axioms" | grep -c "depends on axioms\|does not depend on any axioms" || true)
if [ "$reported" -ne "$expected" ]; then
	echo "check.sh: $expected theorems listed, $reported reported" >&2
	exit 1
fi
if printf '%s\n' "$axioms" | grep 'depends on axioms' |
	sed 's/.*depends on axioms: \[\(.*\)\]/\1/' | tr ',' '\n' | tr -d ' ' |
	grep -vxE 'propext|Classical\.choice|Quot\.sound'; then
	echo "check.sh: a theorem depends on a non-standard axiom" >&2
	exit 1
fi

echo "== vectors"
generated=$(mktemp)
trap 'rm -f "$generated"' EXIT
lake exe gen-vectors >"$generated"
echo "$(grep -vc '^#' "$generated") vectors generated"
if [ "$mode" = write ]; then
	cp "$generated" "$vectors"
	echo "wrote $vectors"
elif ! diff -u "$vectors" "$generated" >/dev/null; then
	diff -u "$vectors" "$generated" | head -40 >&2
	echo "check.sh: the committed vectors differ from the Lean definitions; rerun with --write after updating the transcription" >&2
	exit 1
else
	echo "committed vectors match"
fi
