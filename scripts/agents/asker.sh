#!/bin/sh
#
# A toy asker agent: sends `sha256` tasks to its one contact and waits for
# the answers.
#
#   asker.sh COUNT [PREFIX]
#
# sends COUNT tasks whose inputs are PREFIX-1 ... PREFIX-COUNT (PREFIX
# defaults to `task`), then collects answers until all have arrived or
# ASK_TIMEOUT seconds (default 180) have passed. It records
#
#   $AGENT_DIR/sent.log     one line per task: <input> <message id>
#   $AGENT_DIR/answers.log  one line per answer: <input> <digest>
#
# so the demo can check each answer against a digest it computes itself. Exit
# status 0 means every answer arrived.
#
# Like the responder it holds only the agent credential and the daemon's
# socket (agent.sb). Its one contact is whichever contact is active, which is
# the whole address book of a pairing. The pairing's budget limits how many
# of these tasks the peer will see; the rest are held at the peer until its
# operator raises the budget, and this script simply keeps waiting.
#
# Environment: REEDWIRE_RUNTIME, API_SOCK, AGENT_DIR (see reedwire.sh).

set -u

here=$(dirname "$0")
rw="$here/reedwire.sh"
count=${1:?usage: asker.sh COUNT [PREFIX]}
prefix=${2:-task}
timeout=${ASK_TIMEOUT:-180}
sent="$AGENT_DIR/sent.log"
answers="$AGENT_DIR/answers.log"
payload="$AGENT_DIR/ask.json"
reply="$AGENT_DIR/reply.json"
meta="$AGENT_DIR/reply.meta"

# Optional pacing: with PACE_SENDS=1 a send waits until the daemon reports
# the message stored by the mailbox before the next one starts, so sends
# reach the mailbox in order. Off by default: the daemon handles bursts and
# reordering itself (docs/demo.md, "Burst behavior"), and the knob remains
# for isolating a failure.
pace() {
  [ "${PACE_SENDS:-0}" = 1 ] || return 0
  waited=0
  while [ "$waited" -lt 300 ]; do
    state=$("$rw" status --message "$1" 2>/dev/null || true)
    case "$state" in
      stored_by_mailbox|received_by_peer) return 0 ;;
    esac
    sleep 1
    waited=$((waited + 1))
  done
}

start=$(date +%s)

# The contact is found, not configured: the daemon lists exactly the
# contacts this agent may use. Pairing may still be in flight when the agent
# starts, so wait for the contact to become active.
contact=""
while [ -z "$contact" ]; do
  contact=$("$rw" contacts list 2>/dev/null | awk '$2=="active"{print $1; exit}')
  [ -n "$contact" ] && break
  [ $(($(date +%s) - start)) -lt "$timeout" ] || { echo "no active contact" >&2; exit 1; }
  sleep 1
done

# Send every task first. A send returns once the daemon has durably queued
# the message, long before it is delivered, so this loop does not wait on
# the network. Each task's input is its idempotency key (ADR-011), so a
# rerun of this loop after a send whose answer was lost queues nothing new.
i=1
while [ "$i" -le "$count" ]; do
  input="$prefix-$i"
  jq -nc --arg input "$input" '{task:"sha256",input:$input}' >"$payload"
  id=$("$rw" send --contact "$contact" --content-type application/json \
    --file "$payload" --idempotency-key "$input") ||
    { echo "send failed for $input" >&2; exit 1; }
  echo "$input $id" >>"$sent"
  pace "$id"
  echo "asked $input"
  i=$((i + 1))
done

# Collect the answers. Each is acknowledged once it is recorded, so a crash
# here re-delivers it instead of losing it.
got=0
while [ "$got" -lt "$count" ]; do
  [ $(($(date +%s) - start)) -lt "$timeout" ] || { echo "timed out with $got of $count answers" >&2; exit 1; }

  : >"$reply"
  : >"$meta"
  if ! "$rw" receive --raw --wait 5 >"$reply" 2>"$meta"; then
    sleep 1
    continue
  fi

  [ -s "$meta" ] || continue

  message=$(awk '{print $2}' "$meta")
  input=$(jq -r '.input // empty' "$reply" 2>/dev/null || true)
  output=$(jq -r '.output // empty' "$reply" 2>/dev/null || true)
  echo "$input $output" >>"$answers"
  "$rw" ack --message "$message" >/dev/null
  echo "answered $input"
  got=$((got + 1))
done
