#!/bin/sh
#
# The `pondline` command as an agent sees it: the CLI from the built Erlang
# shipment, with no `gleam` and no repository needed at run time. A real
# deployment would ship a packaged release (docs/next.md); the demo reuses
# the shipment `gleam export erlang-shipment` writes, and the sandbox profile
# lets the agent read that one directory.
#
# PONDLINE_RUNTIME is the shipment directory, or a release tree. The wrapper adds the two
# options every agent command needs, the daemon's socket and the agent's own
# credential, so the agent scripts cannot forget them and never name the
# operator credential.

set -eu

: "${PONDLINE_RUNTIME:?PONDLINE_RUNTIME is not set}"
: "${API_SOCK:?API_SOCK is not set}"
: "${AGENT_DIR:?AGENT_DIR is not set}"

# A release tree (demo.sh --release) has its own launcher, which runs the
# bundled VM; the options are the same.
if [ -x "$PONDLINE_RUNTIME/bin/pondline" ]; then
  exec "$PONDLINE_RUNTIME/bin/pondline" \
    "$@" --socket "$API_SOCK" --credential-file "$AGENT_DIR/agent.cred"
fi

# `erl` starts the VM, runs the CLI's main, and halts with the CLI's own
# exit status (the CLI halts the VM itself on a failure). Standard output is
# raw bytes, since a payload is written unchanged, so nothing else may print
# there. The options come last: the CLI accepts them in any position.
exec erl \
  -pa "$PONDLINE_RUNTIME"/*/ebin \
  -eval 'pondline:main(), erlang:halt(0)' \
  -noshell \
  -extra "$@" --socket "$API_SOCK" --credential-file "$AGENT_DIR/agent.cred"
