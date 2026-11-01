#!/usr/bin/env bash
#
# Package the built release for download: one tarball for this platform and
# its SHA-256.
#
#   scripts/dist.sh        # or `make dist`, which builds and smoke-tests first
#
# writes dist/reedwire-<version>-<platform>.tar.gz, whose one top-level
# directory has the same name and is the release tree (bin/reedwire,
# bin/mailbox, install.sh, ...), and dist/reedwire-<version>-<platform>.tar.gz.sha256
# in the format `shasum -a 256 -c` and `sha256sum -c` read.
#
# The tarball is not signed and its macOS binaries carry ad hoc signatures
# only, so a downloaded copy meets Gatekeeper's quarantine; Developer ID
# signing and notarization are open (ADR-003).

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
REL="$ROOT/build/release/$PLATFORM/reedwire"

[ -f "$REL/BUILD" ] || { echo "dist.sh: no release at $REL; run make release first" >&2; exit 1; }

VERSION=$(sed -n 's/^version=//p' "$REL/BUILD")
STEM="reedwire-$VERSION-$PLATFORM"
DIST="$ROOT/dist"
STAGE="$ROOT/build/dist-stage"

# The tree is staged under its download name, so the archive unpacks into
# one directory that says what it is.
rm -rf "$STAGE"
mkdir -p "$STAGE" "$DIST"
cp -Rp "$REL" "$STAGE/$STEM"
rm -f "$DIST/$STEM.tar.gz" "$DIST/$STEM.tar.gz.sha256"
tar -czf "$DIST/$STEM.tar.gz" -C "$STAGE" "$STEM"
rm -rf "$STAGE"

# The checksum file names the tarball by its bare name, so it verifies from
# inside the directory both are downloaded to.
(
  cd "$DIST"
  if command -v sha256sum >/dev/null; then
    sha256sum "$STEM.tar.gz" > "$STEM.tar.gz.sha256"
  else
    shasum -a 256 "$STEM.tar.gz" > "$STEM.tar.gz.sha256"
  fi
)

echo "==> $DIST/$STEM.tar.gz ($(du -h "$DIST/$STEM.tar.gz" | cut -f1))"
cat "$DIST/$STEM.tar.gz.sha256"
