#!/usr/bin/env bash
#
# Prove a built (or installed) Reedwire release runs on its own: one
# mailbox and two daemons on loopback, paired, one message sent and
# received, everything through the release's launchers in an environment
# with no Erlang, Gleam, Rust or Homebrew reachable.
#
#   scripts/release-smoke.sh                  # build/release/<platform>/reedwire
#   scripts/release-smoke.sh --release DIR    # another release tree
#   scripts/release-smoke.sh --installed PREFIX
#                                             # the launchers make install put
#                                             # in PREFIX/bin, and their tree
#
# What it checks, in order, one line each:
#
#   1. the tree: BUILD names a version and commit, and no build-time
#      package (parrot, gleam_httpc, inets) shipped (ADR-007);
#   2. `reedwire --version` and `mailbox --version` report exactly BUILD's
#      identity, and the sidecar starts;
#   3. the bundled VM loads the bundled OpenSSL, which is >= 3.5 and runs an
#      ML-KEM-1024 round trip (the reason it is bundled, ADR-002/003);
#   4. `mailbox grant` twice and `mailbox serve` on loopback;
#   5. two `reedwire daemon --carrier loopback` against it, and `health`
#      reporting the build identity;
#   6. pairing: A invites with a ticket (and writes the file), B redeems
#      the ticket from standard input (ADR-009), A approves, both become
#      active;
#   7. B sends one payload from standard input, A receives the same bytes;
#   8. every process stops on SIGTERM.
#
# Every program runs under `env -i` with PATH=/usr/bin:/bin, so neither an
# installed Erlang nor anything from Homebrew can stand in for the bundle.
# The whole run is bounded by SMOKE_TIMEOUT seconds (default 180); on
# expiry, or any failure, everything started is killed and the temporary
# directory removed.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
REL="$ROOT/build/release/$PLATFORM/reedwire"
REEDWIRE=""
MAILBOX=""
TIMEOUT=${SMOKE_TIMEOUT:-180}

while [ $# -gt 0 ]; do
  case "$1" in
    --release) shift; REL=${1:?--release needs a directory} ;;
    --installed)
      shift
      PREFIX=${1:?--installed needs a prefix}
      REL="$PREFIX/lib/reedwire/current"
      REEDWIRE="$PREFIX/bin/reedwire"
      MAILBOX="$PREFIX/bin/reedwire-mailbox"
      ;;
    *) echo "release-smoke: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

[ -d "$REL" ] || { echo "release-smoke: no release at $REL (run make release)" >&2; exit 1; }
REL=$(cd "$REL" && pwd -P)
REEDWIRE=${REEDWIRE:-$REL/bin/reedwire}
MAILBOX=${MAILBOX:-$REL/bin/mailbox}

# ------------------------------------------------------------------ output

START=$SECONDS

step() { printf '[%3ds] %s\n' $((SECONDS - START)) "$*"; }
die() {
  printf '[%3ds] FAIL %s\n' $((SECONDS - START)) "$*" >&2
  exit 1
}

# ----------------------------------------------------------------- cleanup

# A short directory: a Unix socket path is limited to about 100 bytes.
T=$(cd "$(mktemp -d /tmp/rwsmoke.XXXXXX)" && pwd -P)
PIDS=""

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  kill "$WATCHDOG" 2>/dev/null || true
  for pid in $PIDS; do kill -TERM "$pid" 2>/dev/null || true; done
  sleep 1
  for pid in $PIDS; do kill -KILL "$pid" 2>/dev/null || true; done
  if [ "$status" -ne 0 ]; then
    for log in "$T"/*.log; do
      [ -f "$log" ] && { echo "--- $(basename "$log")" >&2; tail -n 20 "$log" >&2; }
    done
  fi
  rm -rf "$T"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 124' TERM
trap 'exit 130' INT

# The deadline. The watchdog signals this shell, then every child it has,
# so a hung foreground command does not keep the trap from running.
# The sleep's output goes nowhere: killing the subshell orphans it, and an
# orphan holding this script's stdout would keep a pipe reader (| tail,
# $(...), CI capture) waiting the full timeout after a pass.
(
  sleep "$TIMEOUT" >/dev/null 2>&1
  echo "release-smoke: timed out after ${TIMEOUT}s" >&2
  kill -TERM $$ 2>/dev/null
  pkill -TERM -P $$ 2>/dev/null
) &
WATCHDOG=$!

# Run a command scrubbed: no PATH entry that holds erl, gleam, cargo or
# anything from Homebrew, and no inherited Erlang or OpenSSL variables.
scrubbed() {
  env -i HOME="$T" PATH=/usr/bin:/bin "$@"
}

# Start a scrubbed background program with its own log; its pid is in
# LAST_PID. `env` is the background command itself, not a call to
# `scrubbed`: a function run with & gets a subshell that forks the program
# as its child, and signalling the subshell would leave the VM running.
# Here env execs the launcher, which execs the VM, so the pid is the VM's.
spawn() {
  local log=$1
  shift
  env -i HOME="$T" PATH=/usr/bin:/bin "$@" >"$T/$log" 2>&1 &
  LAST_PID=$!
  PIDS="$PIDS $LAST_PID"
}

# Poll a command until it succeeds, for at most `limit` seconds.
wait_for() {
  local limit=$1
  shift
  local deadline=$((SECONDS + limit))
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 0.2
  done
}

reedwire() { scrubbed "$REEDWIRE" "$@"; }
mailbox() { scrubbed "$MAILBOX" "$@"; }

# --------------------------------------------------------------- 1. tree

step "release: $REL"
# A distribution Erlang lives in /usr/bin, which the scrubbed PATH keeps.
# That is only worth a note: the launchers name the VM by BINDIR and never
# search PATH, which the VM's own command line shows.
if found=$(scrubbed sh -c 'command -v erl || command -v gleam || command -v cargo'); then
  step "note: the scrubbed PATH has $found; the launchers do not use PATH"
fi

[ -f "$REL/BUILD" ] || die "no BUILD file"
VERSION=$(sed -n 's/^version=//p' "$REL/BUILD")
COMMIT=$(sed -n 's/^commit=//p' "$REL/BUILD")
[ -n "$VERSION" ] && [ -n "$COMMIT" ] || die "BUILD lacks a version or commit"

for name in parrot gleam_httpc inets; do
  if compgen -G "$REL/lib/$name" >/dev/null || compgen -G "$REL/lib/$name-*" >/dev/null; then
    die "$name shipped in lib/"
  fi
done
step "ok   tree: $VERSION $COMMIT, no parrot, gleam_httpc or inets"

# ------------------------------------------------------------ 2. identity

want="reedwire $VERSION (commit $COMMIT)"
got=$(reedwire --version) || die "reedwire --version failed"
[ "$got" = "$want" ] || die "reedwire --version said '$got', want '$want'"

want="mailbox $VERSION (commit $COMMIT)"
got=$(mailbox --version) || die "mailbox --version failed"
[ "$got" = "$want" ] || die "mailbox --version said '$got', want '$want'"

# The sidecar serves its owner over standard input and exits cleanly when
# that closes, so an empty stdin is a full start and stop, which also
# proves its bundled libraries resolve.
scrubbed "$REL/bin/reedwire-tor" --state-dir "$T/tor" </dev/null >/dev/null 2>&1 \
  || die "the sidecar does not start"
step "ok   --version of both launchers is the BUILD identity; the sidecar starts"

# -------------------------------------------------------------- 3. crypto

# The bundled VM with the launchers' environment. An ML-KEM-1024 key pair,
# an encapsulation and a decapsulation must agree, which no OpenSSL older
# than 3.5 can do.
ERTS_BIN=$(echo "$REL"/erts-*/bin)
kem=$(scrubbed OPENSSL_CONF=/dev/null OPENSSL_MODULES="$REL/lib/ossl-modules" \
  ROOTDIR="$REL" BINDIR="$ERTS_BIN" EMU=beam PROGNAME=erl ERL_CRASH_DUMP_SECONDS=0 \
  "$ERTS_BIN/erlexec" -boot "$REL/bin/no_dot_erlang" -noshell -noinput -eval '
    [{_, _, Version}] = crypto:info_lib(),
    true = lists:member(mlkem1024, proplists:get_value(kems, crypto:supports())),
    {Public, Secret} = crypto:generate_key(mlkem1024, []),
    {Shared, Ciphertext} = crypto:encapsulate_key(mlkem1024, Public),
    Shared = crypto:decapsulate_key(mlkem1024, Secret, Ciphertext),
    io:format("~s", [Version]),
    halt().' 2>&1) || die "ML-KEM round trip failed in the bundled VM: $kem"
step "ok   bundled crypto: $kem, ML-KEM-1024 round trip"

# ------------------------------------------------------------- 4. mailbox

mailbox grant --db "$T/mailbox.db" --queues 20 --out "$T/a.cap" >/dev/null || die "grant A"
mailbox grant --db "$T/mailbox.db" --queues 20 --out "$T/b.cap" >/dev/null || die "grant B"
spawn mailbox.log "$MAILBOX" serve --db "$T/mailbox.db" --port 0
wait_for 30 grep -q '^listening ' "$T/mailbox.log" || die "the mailbox did not listen"
ADDR=$(sed -n 's/^listening //p' "$T/mailbox.log" | head -n 1)
step "ok   mailbox: two grants, listening on $ADDR"

# ------------------------------------------------------------- 5. daemons

for side in a b; do
  mkdir -m 700 "$T/$side"
  spawn "daemon-$side.log" "$REEDWIRE" daemon --state-dir "$T/$side" \
    --mailbox "$ADDR" --provision-file "$T/$side.cap" --carrier loopback
done
for side in a b; do
  wait_for 30 grep -q '^ready ' "$T/daemon-$side.log" || die "daemon $side did not start"
done

health=$(reedwire health --state-dir "$T/a") || die "health failed"
echo "$health" | grep -qx "version=$VERSION" || die "health lacks version=$VERSION: $health"
echo "$health" | grep -qx "commit=$COMMIT" || die "health lacks commit=$COMMIT: $health"
step "ok   two daemons ready; health reports version=$VERSION commit=$COMMIT"

# ------------------------------------------------------------- 6. pairing

# The ticket is a bearer secret: it goes from A's standard output to B's
# standard input and is never printed or put in argv.
TICKET=$(reedwire invite create --state-dir "$T/a" --description responder \
  --budget 10 --out "$T/invite.bin" --ticket 2>/dev/null) || die "invite create --ticket"
case "$TICKET" in
  pl1*) ;;
  *) die "invite create --ticket printed no ticket" ;;
esac
[ -s "$T/invite.bin" ] || die "invite create --ticket --out wrote no file"
printf '%s\n' "$TICKET" | reedwire invite accept --state-dir "$T/b" --ticket \
  --stdin --description asker >/dev/null || die "invite accept --ticket"
unset TICKET

contact_on() {
  reedwire contacts list --state-dir "$1" | awk -v phase="$2" '$2 == phase {print $1; exit}'
}
pending() { [ -n "$(contact_on "$T/a" pending_approval)" ]; }
active() { [ -n "$(contact_on "$T/a" active)" ] && [ -n "$(contact_on "$T/b" active)" ]; }

wait_for 60 pending || die "A never saw B's accept"
reedwire contact approve --state-dir "$T/a" --contact "$(contact_on "$T/a" pending_approval)" \
  >/dev/null || die "approve"
wait_for 60 active || die "the pairing did not become active on both sides"
A_SEES_B=$(contact_on "$T/a" active)
B_SEES_A=$(contact_on "$T/b" active)
step "ok   paired: A sees B as $A_SEES_B, B sees A as $B_SEES_A"

# ------------------------------------------------------------- 7. message

PAYLOAD="smoke $VERSION $COMMIT $$"
printf '%s' "$PAYLOAD" | reedwire send --state-dir "$T/b" --contact "$B_SEES_A" --stdin \
  >/dev/null || die "send"
got=$(reedwire receive --state-dir "$T/a" --contact "$A_SEES_B" --raw --wait 30 2>"$T/receive.err") \
  || die "receive"
[ "$got" = "$PAYLOAD" ] || die "A received '$got', B sent '$PAYLOAD'"
step "ok   B sent ${#PAYLOAD} bytes from stdin; A received the same bytes"

# ---------------------------------------------------------------- 8. stop

# A process that exited stays a zombie until this shell reaps it, so
# "stopped" means gone or a zombie, not merely unsignalable.
stopped() {
  local state
  state=$(ps -o stat= -p "$1" 2>/dev/null) || return 0
  case $state in Z*) return 0 ;; *) return 1 ;; esac
}
for pid in $PIDS; do kill -TERM "$pid"; done
for pid in $PIDS; do
  wait_for 10 stopped "$pid" || die "process $pid did not stop on SIGTERM"
done
PIDS=""

# The pids above are the VMs only if the launchers exec'd all the way down;
# a VM still running under this run's directory means one did not.
if ps -axww -o command= | grep -F -- "$T/" | grep -v grep >/dev/null; then
  die "a process using $T outlived the stop"
fi
step "ok   mailbox and both daemons stopped on SIGTERM"
step "PASS release smoke ($((SECONDS - START))s)"
