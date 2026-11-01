#!/bin/sh
#
# A toy responder agent: answers `sha256` tasks from its one contact.
#
# It is a stand-in for a real agent and has the same limits. It speaks only
# to the daemon's local socket, with the agent credential, from inside the
# sandbox (agent.sb); it cannot approve a contact, raise a budget or read
# the daemon's database. Each task is a JSON object
#
#   {"task":"sha256","input":"<text>"}
#
# and the answer, sent as a reply to the task's message, is
#
#   {"task":"sha256","input":"<text>","output":"<hex digest>"}
#
# The loop is receive, compute, reply, acknowledge, in that order. The
# acknowledgement comes last so that a crash between the reply and the
# acknowledgement re-delivers the task and answers it twice, which is safe
# for a pure function; the other order could lose a task.
#
# Environment: REEDWIRE_RUNTIME, API_SOCK and AGENT_DIR (see reedwire.sh).
# It runs until it is killed, and appends one line per answered task to
# $AGENT_DIR/responder.log.

set -u

here=$(dirname "$0")
rw="$here/reedwire.sh"
log="$AGENT_DIR/responder.log"
payload="$AGENT_DIR/task.json"
meta="$AGENT_DIR/task.meta"
reply="$AGENT_DIR/answer.json"

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

while :; do
  # A long poll: it returns as soon as a message is ready, or empty after the
  # wait. Raw output puts the payload alone on stdout and
  # `message <id> contact <id>` on stderr. A failed call (the daemon is
  # starting, or restarting) is retried after a pause.
  : >"$payload"
  : >"$meta"
  if ! "$rw" receive --raw --wait 5 >"$payload" 2>"$meta"; then
    sleep 1
    continue
  fi

  # No metadata means no message arrived within the wait.
  [ -s "$meta" ] || continue

  message=$(awk '{print $2}' "$meta")
  contact=$(awk '{print $4}' "$meta")
  task=$(jq -r '.task // empty' "$payload" 2>/dev/null || true)
  input=$(jq -r '.input // empty' "$payload" 2>/dev/null || true)

  # An unknown or malformed task is acknowledged and dropped, so one bad
  # message cannot block the queue behind it.
  if [ "$task" != "sha256" ]; then
    echo "ignored message $message" >>"$log"
    "$rw" ack --message "$message" >/dev/null
    continue
  fi

  output=$(printf '%s' "$input" | shasum -a 256 | cut -d' ' -f1)
  jq -nc --arg input "$input" --arg output "$output" \
    '{task:"sha256",input:$input,output:$output}' >"$reply"

  # The reply is keyed by the message it answers (ADR-011): a crash after
  # this send and before the ack re-delivers the message, and answering it
  # again then names the first reply instead of sending a second one.
  sent=$("$rw" send --contact "$contact" --content-type application/json \
    --file "$reply" --reply-to "$message" --idempotency-key "reply-$message") &&
    pace "$sent"
  "$rw" ack --message "$message" >/dev/null
  echo "answered $input" >>"$log"
done
