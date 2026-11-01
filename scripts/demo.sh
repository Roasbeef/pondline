#!/usr/bin/env bash
#
# The Reedwire demonstration: two daemons, two sandboxed agents, one mailbox,
# end to end (docs/demo.md).
#
#   scripts/demo.sh --carrier=loopback|tor [--messages N] [--skip-build] [--keep]
#
# What runs, and where:
#
#   mailbox   one process with its own database. With --carrier=tor it is also
#             an onion service, so the daemons reach it only through Tor.
#   daemon A  the inviter. Its agent, the *responder*, answers tasks.
#   daemon B  the acceptor. Its agent, the *asker*, sends tasks.
#   agents    two POSIX shell scripts (scripts/agents), each run under
#             sandbox-exec with a copy of its daemon's agent credential and
#             nothing else: no state directory, no network except its
#             daemon's one Unix socket.
#
# The asker is on the acceptor's side because the message budget limits what
# a peer may send to the party that granted it: A invites with a budget of
# ten, so B's tasks to A are what the budget bounds, and the demo can show
# messages held and then released.
#
# The script is a sequence of checks. Each prints one line, and the exit
# status is 0 only if every check passed. Everything it starts is killed on
# exit, whether it finished, failed or was interrupted.

set -euo pipefail

# Job control gives each background job its own process group, so cleanup can
# stop an agent together with the `erl` and `jq` processes it spawned.
set -m

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
AGENTS="$ROOT/scripts/agents"

# ------------------------------------------------------------------ options

CARRIER=""
MESSAGES=6
BUILD=yes
KEEP=no

# The pairing's budget: how many application messages the acceptor may send
# the inviter before the rest are held for the operator.
BUDGET=10

while [ $# -gt 0 ]; do
  case "$1" in
    --carrier=*) CARRIER="${1#--carrier=}" ;;
    --carrier) shift; CARRIER="${1:-}" ;;
    --messages=*) MESSAGES="${1#--messages=}" ;;
    --messages) shift; MESSAGES="${1:-}" ;;
    --skip-build) BUILD=no ;;
    --keep) KEEP=yes ;;
    -h|--help)
      sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "demo.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

case "$CARRIER" in
  loopback|tor) ;;
  *) echo "demo.sh: --carrier=loopback|tor is required" >&2; exit 2 ;;
esac

case "$MESSAGES" in
  ''|*[!0-9]*) echo "demo.sh: --messages takes a number" >&2; exit 2 ;;
esac
if [ "$MESSAGES" -lt 1 ] || [ "$MESSAGES" -gt "$BUDGET" ]; then
  echo "demo.sh: --messages must be from 1 to $BUDGET (the budget)" >&2
  exit 2
fi

# Waits are generous over Tor, where an onion service can take a minute to
# become reachable and a first connection builds a rendezvous circuit.
if [ "$CARRIER" = tor ]; then
  PATIENCE=600
else
  PATIENCE=60
fi

# The agents send one message at a time (see agents/asker.sh). Without it,
# two daemon faults show up when messages are queued in a burst: over Tor
# the receiver drops messages that arrive out of order, and over loopback a
# message over budget was delivered to the agent instead of held. Set
# PACE_SENDS=0 to reproduce them (docs/demo.md, "Known issues").
PACE_SENDS=${PACE_SENDS:-1}

# ------------------------------------------------------------------ output

START=$SECONDS
FAILURES=0

# One line per step, stamped with the seconds since the start.
step() {
  printf '[%4ds] %s\n' $((SECONDS - START)) "$*"
}

# A detail under the current step.
note() {
  printf '         %s\n' "$*"
}

# A check that passed or failed. A failure is counted and the run goes on, so
# one report shows everything that is wrong.
pass() {
  printf '[%4ds]   PASS %s\n' $((SECONDS - START)) "$*"
}

fail() {
  printf '[%4ds]   FAIL %s\n' $((SECONDS - START)) "$*"
  FAILURES=$((FAILURES + 1))
}

# A failure the run cannot continue past: report and exit, which runs the
# cleanup.
die() {
  printf '[%4ds]   FATAL %s\n' $((SECONDS - START)) "$*" >&2
  exit 1
}

# ----------------------------------------------------------------- cleanup

TMP=""
PGIDS=""

# Stops everything started: each job's whole process group, politely and
# then by force. The Tor sidecar exits when its owner's stdin closes, so
# stopping the VMs stops it too.
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  for pgid in $PGIDS; do
    kill -TERM -- "-$pgid" 2>/dev/null || true
  done
  sleep 1
  for pgid in $PGIDS; do
    kill -KILL -- "-$pgid" 2>/dev/null || true
  done
  wait 2>/dev/null || true

  if [ -n "$TMP" ]; then
    if [ "$KEEP" = yes ]; then
      echo "kept $TMP"
    else
      rm -rf "$TMP"
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Starts a background job with its own log and remembers its process group.
# The pid is left in LAST_PID.
spawn() {
  local log=$1
  shift
  "$@" >"$log" 2>&1 &
  LAST_PID=$!
  PGIDS="$PGIDS $LAST_PID"
}

# Polls a command until it succeeds, or gives up after `limit` seconds.
wait_for() {
  local what=$1 limit=$2
  shift 2
  local deadline=$((SECONDS + limit))
  until "$@" >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      return 1
    fi
    sleep 1
  done
}

# ------------------------------------------------------------------- build

if [ "$BUILD" = yes ]; then
  step "building the daemon and mailbox shipments"
  (cd "$ROOT/packages/daemon" && gleam export erlang-shipment) >/dev/null 2>&1 \
    || die "gleam export failed for packages/daemon"
  (cd "$ROOT/packages/mailbox" && gleam export erlang-shipment) >/dev/null 2>&1 \
    || die "gleam export failed for packages/mailbox"

  if [ "$CARRIER" = tor ]; then
    step "building the Tor sidecar"
    make -C "$ROOT" sidecar >/dev/null 2>&1 || die "make sidecar failed"
  fi
fi

DAEMON_SHIP="$ROOT/packages/daemon/build/erlang-shipment"
MAILBOX_SHIP="$ROOT/packages/mailbox/build/erlang-shipment"
SIDECAR="$ROOT/native/reedwire-tor/target/release/reedwire-tor"

[ -d "$DAEMON_SHIP" ] || die "no daemon shipment (run without --skip-build)"
[ -d "$MAILBOX_SHIP" ] || die "no mailbox shipment (run without --skip-build)"
if [ "$CARRIER" = tor ] && [ ! -x "$SIDECAR" ]; then
  die "no Tor sidecar at $SIDECAR (run without --skip-build)"
fi

# Seatbelt matches real paths, so the paths handed to the sandbox have their
# symlinks resolved. `erl` is a symlink into Homebrew's Cellar.
DAEMON_SHIP=$(cd "$DAEMON_SHIP" && pwd -P)
OTP_ROOT=$(dirname "$(dirname "$(readlink -f "$(command -v erl)")")")

# --------------------------------------------------------------- the tools

# The mailbox command (`mailbox serve|grant`).
mailbox() {
  erl -pa "$MAILBOX_SHIP"/*/ebin -eval 'mailbox:main(), erlang:halt(0)' \
    -noshell -extra "$@"
}

# The operator's `reedwire`: it uses <state-dir>/operator.cred by default, so
# the credential variable must not leak in from the caller's environment.
reedwire() {
  env -u REEDWIRE_CREDENTIAL_FILE \
    erl -pa "$DAEMON_SHIP"/*/ebin -eval 'reedwire:main(), erlang:halt(0)' \
    -noshell -extra "$@"
}

# Runs a command inside the agent sandbox. The agent gets a scrubbed
# environment, its own directory as HOME and TMPDIR, and nothing else. It
# changes directory, so callers run it in a subshell.
#   sandboxed AGENT_DIR STATE_DIR COMMAND...
sandboxed() {
  local agent_dir=$1 state_dir=$2
  shift 2

  # The VM refuses to start without a readable current directory, and the
  # agent's own directory is the only one the sandbox lets it read.
  cd "$agent_dir"
  sandbox-exec \
    -D "AGENT_DIR=$agent_dir" \
    -D "API_SOCK=$state_dir/api.sock" \
    -D "STATE_DIR=$state_dir" \
    -D "RUNTIME=$DAEMON_SHIP" \
    -D "OTP_ROOT=$OTP_ROOT" \
    -f "$AGENTS/agent.sb" \
    env -i \
      PATH=/usr/bin:/bin:/opt/homebrew/bin \
      HOME="$agent_dir" TMPDIR="$agent_dir/tmp" \
      AGENT_DIR="$agent_dir" API_SOCK="$state_dir/api.sock" \
      STATE_DIR="$state_dir" REEDWIRE_RUNTIME="$DAEMON_SHIP" \
      ASK_TIMEOUT="${ASK_TIMEOUT:-$((PATIENCE * 2))}" \
      PACE_SENDS="$PACE_SENDS" \
      "$@"
}

# Digest the way a responder computes it, so an answer can be checked.
digest() {
  printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
}

# ------------------------------------------------------------------- setup

# A short path: a Unix socket path is limited to about 100 bytes, and the
# platform temp directory can use most of that.
TMP=$(cd "$(mktemp -d /tmp/rwd.XXXXXX)" && pwd -P)
LOGS="$TMP/logs"
mkdir -p "$LOGS"
A="$TMP/a"
B="$TMP/b"
AGENT_A="$TMP/agent-a"
AGENT_B="$TMP/agent-b"

step "demo: carrier=$CARRIER, $MESSAGES tasks, budget $BUDGET, workspace $TMP"

step "granting two provisioning capabilities"
mailbox grant --db "$TMP/mailbox.db" --queues 20 --out "$TMP/a.cap" >/dev/null \
  || die "grant for A failed"
mailbox grant --db "$TMP/mailbox.db" --queues 20 --out "$TMP/b.cap" >/dev/null \
  || die "grant for B failed"
pass "two grants written (0600 files; the capabilities are never printed)"

# ------------------------------------------------------------------ mailbox

step "starting the mailbox"
if [ "$CARRIER" = tor ]; then
  spawn "$LOGS/mailbox.log" mailbox serve --db "$TMP/mailbox.db" --port 0 \
    --tor-bin "$SIDECAR" --tor-state "$TMP/mt"
else
  spawn "$LOGS/mailbox.log" mailbox serve --db "$TMP/mailbox.db" --port 0
fi
MAILBOX_PID=$LAST_PID

wait_for "the mailbox to listen" 60 grep -q '^listening ' "$LOGS/mailbox.log" \
  || die "the mailbox did not start: $(cat "$LOGS/mailbox.log")"
LOCAL_ADDR=$(sed -n 's/^listening //p' "$LOGS/mailbox.log" | head -n 1)
note "mailbox listening on $LOCAL_ADDR"

if [ "$CARRIER" = tor ]; then
  step "bootstrapping Tor and publishing the mailbox's onion service"
  wait_for "the onion address" "$PATIENCE" grep -q '^onion ' "$LOGS/mailbox.log" \
    || die "the mailbox did not publish an onion service: $(cat "$LOGS/mailbox.log")"
  MAILBOX_ADDR=$(sed -n 's/^onion //p' "$LOGS/mailbox.log" | head -n 1)
  pass "mailbox is an onion service: $MAILBOX_ADDR"
else
  MAILBOX_ADDR="$LOCAL_ADDR"
fi

# ------------------------------------------------------------------ daemons

start_daemon() {
  local name=$1 dir=$2 cap=$3
  mkdir -p "$dir"
  chmod 700 "$dir"
  if [ "$CARRIER" = tor ]; then
    spawn "$LOGS/daemon-$name.log" reedwire daemon --state-dir "$dir" \
      --mailbox "$MAILBOX_ADDR" --provision-file "$cap" \
      --carrier tor --tor-bin "$SIDECAR"
  else
    spawn "$LOGS/daemon-$name.log" reedwire daemon --state-dir "$dir" \
      --mailbox "$MAILBOX_ADDR" --provision-file "$cap" --carrier loopback
  fi
}

step "starting daemon A (inviter) and daemon B (acceptor)"
start_daemon a "$A" "$TMP/a.cap"
start_daemon b "$B" "$TMP/b.cap"

for name in a b; do
  wait_for "daemon $name" 60 grep -q '^ready ' "$LOGS/daemon-$name.log" \
    || die "daemon $name did not start: $(cat "$LOGS/daemon-$name.log")"
done
pass "both daemons are up and serving their local APIs"

if [ "$CARRIER" = tor ]; then
  step "waiting for both daemons' Tor clients to bootstrap"
  tor_ready() { reedwire health --state-dir "$1" | grep -q '^tor=bootstrapped$'; }
  for dir in "$A" "$B"; do
    wait_for "Tor in $dir" "$PATIENCE" tor_ready "$dir" \
      || die "Tor did not bootstrap in $dir"
  done
  pass "both Tor clients are bootstrapped"
fi

# ------------------------------------------------------------------ pairing

step "pairing: A invites with a budget of $BUDGET, B accepts, A approves"
reedwire invite create --state-dir "$A" --description "responder" \
  --budget "$BUDGET" --out "$TMP/invite.bin" >/dev/null \
  || die "invite create failed"
note "invitation written ($(wc -c <"$TMP/invite.bin" | tr -d ' ') bytes, carries the post-quantum key bundle)"

reedwire invite accept --state-dir "$B" --file "$TMP/invite.bin" \
  --description "asker" >/dev/null || die "invite accept failed"

# B's accept is a message through the mailbox; A sees it as a pending
# contact once the message has crossed (and, over Tor, once the onion
# service is reachable).
contact_on() {
  reedwire contacts list --state-dir "$1" | awk -v phase="$2" '$2==phase{print $1; exit}'
}
awaiting_approval() { [ -n "$(contact_on "$A" pending_approval)" ]; }

wait_for "A to see B's accept" "$PATIENCE" awaiting_approval \
  || die "A never saw B's accept"
A_CONTACT=$(contact_on "$A" pending_approval)
reedwire contact approve --state-dir "$A" --contact "$A_CONTACT" >/dev/null \
  || die "approve failed"

both_active() {
  [ -n "$(contact_on "$A" active)" ] && [ -n "$(contact_on "$B" active)" ]
}
wait_for "both sides active" "$PATIENCE" both_active \
  || die "the pairing did not become active on both sides"
B_CONTACT=$(contact_on "$B" active)
pass "paired: both sides are active (A sees B as $A_CONTACT, B sees A as $B_CONTACT)"
note "A: $(reedwire contacts list --state-dir "$A")"
note "B: $(reedwire contacts list --state-dir "$B")"

# ------------------------------------------------------------------- agents

# Each agent's directory holds a copy of its daemon's agent credential and
# copies of the scripts, and nothing of the daemon's. The operator
# credential and the database stay in the state directory, which the
# sandbox denies.
prepare_agent() {
  local dir=$1 state=$2
  mkdir -p "$dir/bin" "$dir/tmp"
  chmod 700 "$dir"
  cp "$AGENTS/reedwire.sh" "$AGENTS/asker.sh" "$AGENTS/responder.sh" \
    "$AGENTS/probe.sh" "$dir/bin/"
  cp "$state/agent.cred" "$dir/agent.cred"
  chmod 600 "$dir/agent.cred"
}

step "preparing the agent sandboxes (agent.cred copied in; nothing else)"
prepare_agent "$AGENT_A" "$A"
prepare_agent "$AGENT_B" "$B"

step "proving the sandbox from inside it"
for side in a b; do
  if [ "$side" = a ]; then dir=$AGENT_A; state=$A; else dir=$AGENT_B; state=$B; fi
  probes=$( (sandboxed "$dir" "$state" sh "$dir/bin/probe.sh") 2>&1) \
    || probes="FAIL the probe script itself failed: $probes"
  while IFS= read -r line; do
    case "$line" in
      ok*) pass "agent-$side: ${line#ok   }" ;;
      *) fail "agent-$side: ${line#FAIL }" ;;
    esac
  done <<EOF
$probes
EOF
done

# The same read, outside the sandbox, is what the operator does. It works,
# which shows the denial above comes from the sandbox and not from the file.
if [ -r "$A/operator.cred" ]; then
  pass "outside the sandbox the operator can read operator.cred (the denial is the sandbox's)"
else
  fail "operator.cred is unreadable even to the operator"
fi

step "starting the responder (agent of A) and the asker's first run (agent of B)"
spawn "$LOGS/responder.log" sandboxed "$AGENT_A" "$A" sh "$AGENT_A/bin/responder.sh"

RUN1=$SECONDS
spawn "$LOGS/asker-1.log" sandboxed "$AGENT_B" "$B" sh "$AGENT_B/bin/asker.sh" \
  "$MESSAGES" task
ASKER_PID=$LAST_PID

# ------------------------------------------------------------------ answers

step "waiting for $MESSAGES answers"
if wait "$ASKER_PID" 2>/dev/null; then
  pass "the asker received all $MESSAGES answers in $((SECONDS - RUN1))s"
else
  fail "the asker did not receive all answers: $(tail -n 3 "$LOGS/asker-1.log")"
fi

# Each answer is checked against a digest computed here, by the script, not
# by the responder.
verify_answers() {
  local want=$1 bad=0 seen=0 input output
  while read -r input output; do
    [ -n "$input" ] || continue
    seen=$((seen + 1))
    if [ "$output" != "$(digest "$input")" ]; then
      bad=$((bad + 1))
      note "wrong digest for $input"
    fi
  done <"$AGENT_B/answers.log"

  if [ "$seen" -eq "$want" ] && [ "$bad" -eq 0 ]; then
    pass "all $want answers equal the locally computed sha256"
  else
    fail "answers: $seen of $want seen, $bad wrong"
  fi
}
verify_answers "$MESSAGES"
note "e.g. $(head -n 1 "$AGENT_B/answers.log")"

# ----------------------------------------------------------------- receipts

# A receipt is the peer's own authenticated message saying a task arrived,
# so `received_by_peer` is evidence from A, not from the mailbox.
all_received() {
  local input id state
  while read -r input id; do
    state=$(reedwire status --state-dir "$B" --message "$id")
    [ "$state" = received_by_peer ] || return 1
  done <"$AGENT_B/sent.log"
}

step "checking delivery receipts on B"
if wait_for "receipts" "$PATIENCE" all_received; then
  pass "every task is received_by_peer (receipt from A)"
else
  fail "some task never reached received_by_peer"
fi
first_id=$(head -n 1 "$AGENT_B/sent.log" | cut -d' ' -f2)
note "status of the first task: $(reedwire status --state-dir "$B" --message "$first_id")"

step "A's audit log (plaintext, outside the agent's reach), newest first"
reedwire audit --state-dir "$A" --limit 6 | cut -c1-150 | while IFS= read -r line; do
  note "$line"
done

# ------------------------------------------------------------------- budget

REMAINING=$((BUDGET - MESSAGES))
BURST=$((REMAINING + 2))

step "budget: the asker sends $BURST more tasks ($REMAINING fit, 2 will not)"
spawn "$LOGS/asker-2.log" sandboxed "$AGENT_B" "$B" sh "$AGENT_B/bin/asker.sh" \
  "$BURST" burst
BURST_PID=$LAST_PID

held_two() {
  reedwire contacts list --state-dir "$A" | grep -q " held=2 "
}
if wait_for "two held messages" "$PATIENCE" held_two; then
  pass "A holds exactly 2 messages over budget"
else
  fail "A never showed 2 held messages: $(reedwire contacts list --state-dir "$A")"
fi
note "A: $(reedwire contacts list --state-dir "$A")"

# The responder answers what fit, and only that. Give it time to settle
# before counting, so a held message that leaked through would show up.
fits_answered() {
  [ "$(grep -c '^burst-' "$AGENT_B/answers.log" 2>/dev/null || true)" -ge "$REMAINING" ]
}
wait_for "the tasks that fit" "$PATIENCE" fits_answered || true
sleep 3
answered=$(grep -c '^burst-' "$AGENT_B/answers.log" 2>/dev/null || true)
if [ "$answered" -eq "$REMAINING" ]; then
  pass "only the $REMAINING tasks within budget were answered; 2 stay held"
else
  fail "expected $REMAINING burst answers while 2 are held, saw $answered"
fi

step "the operator raises A's budget for B by 5"
reedwire contact budget --state-dir "$A" --contact "$A_CONTACT" --add 5 >/dev/null \
  || die "contact budget failed"

if wait "$BURST_PID" 2>/dev/null; then
  pass "the held tasks were released and answered; the asker has all $BURST"
else
  fail "the asker did not finish after the raise: $(tail -n 3 "$LOGS/asker-2.log")"
fi
verify_answers $((MESSAGES + BURST))
note "A: $(reedwire contacts list --state-dir "$A")"

# --------------------------------------------------------------------- done

step "stopping everything"
if [ "$FAILURES" -eq 0 ]; then
  step "RESULT: every check passed (carrier=$CARRIER, total $((SECONDS - START))s)"
  exit 0
fi

step "RESULT: $FAILURES check(s) failed (carrier=$CARRIER, total $((SECONDS - START))s)"
if [ "$KEEP" = no ]; then
  note "logs were in $LOGS; rerun with --keep to inspect them"
fi
exit 1
