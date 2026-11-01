#!/usr/bin/env bash
# The judge for the P model: every mutant, recall, calibration and
# counterexample test case (PTst/judge.p) must make the checker report a
# bug, and the bug must come from the expected monitor. Exits non-zero if
# any case survives its budget or trips the wrong monitor.
#
# Prints, per case, the schedule on which the first bug was found (the
# checker stops at the first bug), which is the number docs/formal/p.md
# tabulates.
#
# Usage: formal/p/judge.sh [--no-compile]

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

export PATH="$PATH:$HOME/.dotnet/tools"
if [ -z "${DOTNET_ROOT:-}" ] && [ -d "$HOME/.dotnet" ]; then
  export DOTNET_ROOT="$HOME/.dotnet"
fi

seed=20261101
dll="PGenerated/PChecker/net8.0/Reedwire.dll"

# Case, schedule budget, and the report that must come back: a liveness
# monitor's name, or the assertion text of the safety monitor (P reports a
# failed spec assertion by its message, not its monitor's name).
cases=(
  "mutReencrypt 2000 delivered to the agent twice"
  "mutSendBeforeCommit 200 sent before it was committed"
  "mutAckBeforeCommit 200 acknowledged before its processing committed"
  "mutReceiptForExpired 3000 which was never stored"
  "mutIgnoreExpiry 3000 delivered after the receiver saw it expire"
  "mutTightAnswers 5000 DeliveredAndReceipted"
  "recallNoRetransmit 3000 DeliveredAndReceipted"
  "recallNoFingerprint 3000 DeliveredAndReceipted"
  "recallPreH2 3000 DeliveredAndReceipted|QueuesDrain"
  "recallNoImplicitAccept 3000 DeliveredAndReceipted"
  "calibSpoils 5000 DeliveredAndReceipted"
  "calibQuarantine 5000 DeliveredAndReceipted"
  "cxGeneric 5000 QueuesDrain|DeliveredAndReceipted"
  "cxRestore 3000 DeliveredAndReceipted|QueuesDrain"
  "cxBlock 3000 DeliveredAndReceipted"
  "cxLateRetry 5000 QueuesDrain|DeliveredAndReceipted"
)

if [ "${1:-}" != "--no-compile" ]; then
  echo "== compiling"
  p compile >"$here/out.compile.log" 2>&1 || {
    cat "$here/out.compile.log"
    exit 1
  }
fi

failed=0
for entry in "${cases[@]}"; do
  read -r tc budget monitor <<<"$entry"
  log="$here/out/judge/$tc.log"
  mkdir -p "$(dirname "$log")"
  rm -rf "$here/out/judge/$tc"
  p check "$dll" -tc "$tc" -s "$budget" --seed "$seed" \
    -o "$here/out/judge/$tc" >"$log" 2>&1 || true

  error="$(grep -h "ErrorLog" "$here/out/judge/$tc"/BugFinding/*.txt 2>/dev/null | head -1 || true)"
  schedules="$(grep -Eo 'Explored [0-9]+ schedules?' "$log" | grep -Eo '[0-9]+' | head -1 || true)"

  if grep -q "Found 1 bug" "$log" && echo "$error" | grep -Eq "$monitor"; then
    printf '%-24s caught at schedule %-5s %s\n' "$tc" "$schedules" "$error"
  else
    printf '%-24s NOT CAUGHT as %s within %s schedules %s\n' "$tc" "$monitor" "$budget" "$error"
    failed=1
  fi
done

exit "$failed"
