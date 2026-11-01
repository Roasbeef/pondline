#!/bin/sh
#
# What a sandboxed agent cannot do. The demo runs this inside the sandbox
# and requires every line to say `ok`.
#
# Each probe attempts something an attacker who controls the agent would
# want, and passes when the attempt fails. One positive control shows the
# sandbox is not simply breaking everything: the agent can reach the daemon
# with its own credential.
#
# Environment: REEDWIRE_RUNTIME, API_SOCK, AGENT_DIR, STATE_DIR.

set -u

here=$(dirname "$0")
rw="$here/reedwire.sh"

# Prints `ok <name>` when the command fails, and `FAIL <name>` when it
# succeeds. Output of the command is discarded.
must_fail() {
  name=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL $name"
  else
    echo "ok   $name"
  fi
}

# The positive control: the agent's credential works over the one socket.
if "$rw" health >/dev/null 2>&1; then
  echo "ok   the agent can use the daemon with its own credential"
else
  echo "FAIL the agent could not reach the daemon"
fi

# The daemon's secrets are unreadable.
must_fail "cannot read operator.cred" cat "$STATE_DIR/operator.cred"
must_fail "cannot read the daemon database" head -c 16 "$STATE_DIR/daemon.db"
must_fail "cannot read the original agent.cred" cat "$STATE_DIR/agent.cred"
must_fail "cannot list the state directory" ls "$STATE_DIR"

# So the operator credential cannot be used: the CLI cannot even open it.
must_fail "cannot use the operator credential" \
  env REEDWIRE_CREDENTIAL_FILE="$STATE_DIR/operator.cred" \
  erl -pa "$REEDWIRE_RUNTIME"/*/ebin -eval 'reedwire:main(), erlang:halt(0)' \
  -noshell -extra health --socket "$API_SOCK"

# The agent's own credential is refused for operator actions, by the daemon.
# Exit status 3 is "unauthorized or forbidden".
"$rw" contact approve --contact 00000000000000000000000000000000 >/dev/null 2>&1
if [ "$?" -eq 3 ]; then
  echo "ok   the daemon refuses operator actions to the agent credential"
else
  echo "FAIL the agent credential was allowed an operator action"
fi

# Nothing outside the agent's directory is writable, and the network is shut.
must_fail "cannot write outside its directory" sh -c "echo x > '$HOME/../escape.$$'"
must_fail "cannot reach the internet" /usr/bin/curl -sS -m 4 http://1.1.1.1/
must_fail "cannot read the user's home directory" ls /Users
