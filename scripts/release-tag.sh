#!/usr/bin/env bash
#
# Verify release tag syntax and check that packages/{daemon,mailbox}/gleam.toml
# match the tagged version.
#
#   scripts/release-tag.sh v0.1.0

set -euo pipefail

TAG=${1:?usage: scripts/release-tag.sh <vX.Y.Z>}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

if ! printf '%s\n' "$TAG" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.[1-9][0-9]*)?$'; then
  echo "release-tag.sh: '$TAG' is not a valid release tag (expected vX.Y.Z or vX.Y.Z-rc.N)" >&2
  exit 1
fi

WANT=${TAG#v}

version_of() {
  sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/packages/$1/gleam.toml" | head -n 1
}

for pkg in daemon mailbox; do
  got=$(version_of "$pkg")
  if [ "$got" != "$WANT" ]; then
    echo "release-tag.sh: tag is $TAG (version $WANT), but packages/$pkg/gleam.toml declares $got" >&2
    exit 1
  fi
done

echo "ok: $TAG matches packages/{daemon,mailbox}/gleam.toml ($WANT)"
