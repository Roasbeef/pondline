#!/bin/sh
# Translates the PlusCal models and runs TLC on every configuration, then
# compares each result with what that configuration is meant to show. A
# model of the current design must pass; a mutant must fail on the named
# invariant; the pre-ef9d5c2 fetcher must fail its liveness property
# (closed_queue_unacked).
# Anything else (an unexpected violation, a deadlock, a TLC error) fails
# the script.
#
# Usage: formal/tla/check.sh [config ...]
# TLA2TOOLS names the jar (default /Users/roasbeef/tools/tla2tools.jar) and
# TLC_WORKERS the worker count (default 2).

set -u

jar=${TLA2TOOLS:-/Users/roasbeef/tools/tla2tools.jar}
workers=${TLC_WORKERS:-2}
here=$(cd "$(dirname "$0")" && pwd)
meta=$(mktemp -d "${TMPDIR:-/tmp}/pondline-tla.XXXXXX")
trap 'rm -rf "$meta"' EXIT INT TERM

cd "$here" || exit 2

# Each line: spec, configuration, expected result. The expected result is
# "pass", "liveness" (a temporal property is violated), or the name of the
# invariant that must be violated.
plan='
Scheduler Scheduler pass
Scheduler SchedulerCopies pass
Scheduler SchedulerLive pass
Scheduler SchedulerMutBatch NoDoubleSend
Scheduler SchedulerMutBatchOwner OneOwner
Scheduler SchedulerMutBatchStale NoStaleRelease
Scheduler SchedulerMutAnyEnd NoDoubleSend
Scheduler SchedulerMutImmediate HeldUntilTick
Scheduler SchedulerMutStorm NoBusyLoop
Scheduler SchedulerMutSticky liveness
Scheduler SchedulerMutPlan SendCommitted
Fetcher Fetcher pass
Fetcher FetcherMutBeforeAck liveness
Fetcher FetcherMutBeforeAckRest NothingOwedAtRest
Fetcher FetcherMutNoDrain NothingOwedAtRest
Fetcher FetcherMutDrainOnly liveness
Fetcher FetcherMutBatch NoAckBeforeCommit
Fetcher FetcherMutBatchStore StoreAckConsistent
'

for spec in Scheduler Fetcher; do
    if ! java -cp "$jar" pcal.trans -nocfg "$spec.tla" > "$meta/$spec.pcal" 2>&1; then
        cat "$meta/$spec.pcal"
        echo "FAIL: PlusCal translation of $spec.tla"
        exit 1
    fi
    rm -f "$spec.old"
done

# What TLC concluded, from its output.
classify() {
    if grep -q '^Error: Invariant .* is violated' "$1"; then
        sed -n 's/^Error: Invariant \(.*\) is violated.*/\1/p' "$1" | head -1
    elif grep -q 'Temporal properties were violated' "$1"; then
        echo liveness
    elif grep -q 'Deadlock reached' "$1"; then
        echo deadlock
    elif grep -q 'Model checking completed. No error has been found.' "$1"; then
        echo pass
    else
        echo error
    fi
}

echo "$plan" | while read -r spec cfg expect; do
    [ -z "$spec" ] && continue

    # Run only the configurations named on the command line, if any.
    if [ $# -gt 0 ]; then
        wanted=no
        for name in "$@"; do
            [ "$name" = "$cfg" ] && wanted=yes
        done
        [ "$wanted" = no ] && continue
    fi

    out="$meta/$cfg.out"
    java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -workers "$workers" \
        -metadir "$meta/$cfg" -config "$cfg.cfg" "$spec.tla" > "$out" 2>&1

    got=$(classify "$out")
    states=$(sed -n 's/.* \([0-9][0-9]*\) distinct states found.*/\1/p' "$out" | tail -1)
    depth=$(sed -n 's/^The depth of the complete state graph search is \([0-9]*\).*/\1/p' "$out" | tail -1)
    trace=$(grep -c '^State [0-9]*:' "$out")
    time=$(sed -n 's/^Finished in \(.*\) at.*/\1/p' "$out" | tail -1)

    if [ "$got" = "$expect" ]; then
        verdict=ok
    else
        verdict=FAIL
    fi

    if [ "$got" = pass ]; then
        detail="distinct=$states depth=$depth"
    else
        detail="distinct=$states depth=$depth trace=$trace"
    fi

    printf '%-4s %-24s expect=%-18s got=%-18s %s time=%s\n' \
        "$verdict" "$cfg" "$expect" "$got" "$detail" "$time"

    if [ "$verdict" = FAIL ]; then
        grep -E '^Error|violated|Deadlock' "$out" | head -5
        echo FAIL > "$meta/failed"
    fi
done

if [ -f "$meta/failed" ]; then
    echo "check.sh: at least one configuration did not give its expected result"
    exit 1
fi

echo "check.sh: every configuration gave its expected result"
