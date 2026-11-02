#!/usr/bin/env bash
# Compiles the P model and checks every design test case at a fixed
# schedule budget and seed. Exits non-zero if compilation fails or if any
# test case reports a bug. The mutants and recalls live in judge.sh, which
# expects the opposite.
#
# Usage: formal/p/check.sh [scale]
#   scale multiplies every schedule budget (default 1).
#
# Runs one checker process at a time. Needs P 3.0.4 (`p`) on PATH or in
# ~/.dotnet/tools.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

export PATH="$PATH:$HOME/.dotnet/tools"
if [ -z "${DOTNET_ROOT:-}" ] && [ -d "$HOME/.dotnet" ]; then
  export DOTNET_ROOT="$HOME/.dotnet"
fi

scale="${1:-1}"
seed=20261101
dll="PGenerated/PChecker/net8.0/Pondline.dll"

# Each design test case and its schedule budget. The random strategy and a
# PCT pass are both run; PCT favours long delays of one machine, which is how
# a receiver offline for a day or a slow receipt shows up in this model.
cases=(
  "tcHappy 200"
  "tcNetwork 1000"
  "tcCrash 1000"
  "tcMailbox 1500"
  "tcReplay 1000"
  "tcBoundReplay 1500"
  "tcQuarantine 1000"
  "tcForger 800"
  "tcH2Off 800"
  "tcExpiry 1000"
  "tcAll 2000"
  "tcThreeSpoils 1000"
  "tcCtlTwoLosses 800"
  "tcCtlNoRetransmit 600"
  "tcCtlNoFingerprint 600"
  "tcCtlPreH2 600"
  "tcCtlNoImplicitAccept 200"
  "tcCtlNoReack 1000"
)

echo "== compiling"
p compile >"$here/out.compile.log" 2>&1 || {
  cat "$here/out.compile.log"
  exit 1
}

failed=0
for entry in "${cases[@]}"; do
  read -r tc budget <<<"$entry"
  n=$((budget * scale))

  for strategy in random pct; do
    flags=()
    if [ "$strategy" = pct ]; then
      flags=(--sch-pct 10)
    fi

    log="$here/out/check/$tc.$strategy.log"
    mkdir -p "$(dirname "$log")"
    rm -rf "$here/out/check/$tc.$strategy"
    p check "$dll" -tc "$tc" -s "$n" --seed "$seed" "${flags[@]}" \
      -o "$here/out/check/$tc.$strategy" >"$log" 2>&1 || true

    if grep -q "Found 0 bugs" "$log"; then
      printf '%-22s %-6s %6d schedules  ok\n' "$tc" "$strategy" "$n"
    else
      printf '%-22s %-6s %6d schedules  BUG\n' "$tc" "$strategy" "$n"
      grep -h "ErrorLog" "$here/out/check/$tc.$strategy"/BugFinding/*.txt 2>/dev/null | head -3 || true
      failed=1
    fi
  done
done

exit "$failed"
