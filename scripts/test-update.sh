#!/usr/bin/env bash
#
# End-to-end verification of scripts/fetch-release.sh (`pondline-update`) and
# scripts/install.sh atomic side-by-side tree updates:
#
#   1. Fresh installation from a dist tarball + SHA-256 checksum into a scratch
#      PREFIX, verifying `pondline`, `pondline-mailbox` and `pondline-update`.
#   2. Tamper rejection: flipping one byte of the tarball fails SHA-256
#      verification before unpacking and leaves `current` untouched.
#   3. Live-process retention and pruning: while a process holds the 0.1.0 tree
#      on its command line, upgrading to a staged 0.1.1 archive switches
#      `current` atomically to 0.1.1 and keeps the 0.1.0 tree; once that
#      process exits, a reinstall prunes the retired 0.1.0 tree.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
REL="$ROOT/build/release/$PLATFORM/pondline"

[ -f "$REL/BUILD" ] || {
  echo "test-update.sh: no release at $REL; run make release first" >&2
  exit 1
}

VERSION=$(sed -n 's/^version=//p' "$REL/BUILD")
STEM="pondline-$VERSION-$PLATFORM"
TARBALL="$ROOT/dist/$STEM.tar.gz"
SHA_FILE="$ROOT/dist/$STEM.tar.gz.sha256"

if [ ! -f "$TARBALL" ] || [ ! -f "$SHA_FILE" ]; then
  "$ROOT/scripts/dist.sh" >/dev/null
fi

WORK=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/pondline-test-update.XXXXXX")
HOLDER_PID=""
cleanup() {
  if [ -n "$HOLDER_PID" ]; then
    kill -TERM "$HOLDER_PID" 2>/dev/null || true
    wait "$HOLDER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

PREFIX_DIR="$WORK/prefix"

# 1. Fresh install via fetch-release.sh --tarball
"$ROOT/scripts/fetch-release.sh" \
  --prefix "$PREFIX_DIR" \
  --tarball "$TARBALL" \
  --sha256-file "$SHA_FILE" >/dev/null

for cmd in pondline pondline-mailbox pondline-update; do
  [ -L "$PREFIX_DIR/bin/$cmd" ] && [ -x "$PREFIX_DIR/bin/$cmd" ] || {
    echo "FAIL: missing installed command $PREFIX_DIR/bin/$cmd" >&2
    exit 1
  }
done

FIRST_TREE=$(cd "$PREFIX_DIR/lib/pondline/current" && pwd -P)
"$PREFIX_DIR/bin/pondline" --version | grep -q "^pondline $VERSION " || {
  echo "FAIL: installed pondline --version mismatch" >&2
  exit 1
}
echo "ok   1. fresh install verified ($FIRST_TREE)"

# 2. Tamper rejection leaves current untouched
BAD_TARBALL="$WORK/$STEM.tar.gz"
cp "$TARBALL" "$BAD_TARBALL"
printf '\x00' | dd of="$BAD_TARBALL" bs=1 seek=16 conv=notrunc 2>/dev/null
if "$PREFIX_DIR/bin/pondline-update" \
  --tarball "$BAD_TARBALL" \
  --sha256-file "$SHA_FILE" >"$WORK/tamper.out" 2>&1; then
  echo "FAIL: tampered tarball succeeded" >&2
  exit 1
fi
grep -q "SHA-256 mismatch" "$WORK/tamper.out" || {
  echo "FAIL: expected SHA-256 mismatch diagnostic, got:" >&2
  cat "$WORK/tamper.out" >&2
  exit 1
}
AFTER_TAMPER=$(cd "$PREFIX_DIR/lib/pondline/current" && pwd -P)
[ "$AFTER_TAMPER" = "$FIRST_TREE" ] || {
  echo "FAIL: tampered update changed current ($AFTER_TAMPER != $FIRST_TREE)" >&2
  exit 1
}
echo "ok   2. tampered tarball refused before unpack; current unchanged"

# 3. Live-process retention across atomic upgrade, then prune after exit
NEXT_VERSION="0.1.99"
NEXT_STEM="pondline-$NEXT_VERSION-$PLATFORM"
STAGE_NEXT="$WORK/stage/$NEXT_STEM"
mkdir -p "$WORK/stage"
cp -Rp "$REL" "$STAGE_NEXT"
sed -i.bak "s/^version=.*/version=$NEXT_VERSION/" "$STAGE_NEXT/BUILD"
rm -f "$STAGE_NEXT/BUILD.bak"
for launcher in pondline mailbox; do
  sed -i.bak "s/^PONDLINE_BUILD_VERSION=.*/PONDLINE_BUILD_VERSION=$NEXT_VERSION/" "$STAGE_NEXT/bin/$launcher"
  rm -f "$STAGE_NEXT/bin/$launcher.bak"
done
NEXT_TARBALL="$WORK/$NEXT_STEM.tar.gz"
tar -czf "$NEXT_TARBALL" -C "$WORK/stage" "$NEXT_STEM"
(
  cd "$WORK"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$NEXT_STEM.tar.gz" > "$NEXT_STEM.tar.gz.sha256"
  else
    shasum -a 256 "$NEXT_STEM.tar.gz" > "$NEXT_STEM.tar.gz.sha256"
  fi
)

# Hold FIRST_TREE on a live process command line so install.sh sees it in use.
sh -c 'sleep 30' _ "$FIRST_TREE/bin/pondline" &
HOLDER_PID=$!
sleep 0.2

# Invoke via the installed symlink WITHOUT --prefix to prove prefix inference.
"$PREFIX_DIR/bin/pondline-update" \
  --tarball "$NEXT_TARBALL" \
  --sha256-file "$WORK/$NEXT_STEM.tar.gz.sha256" >"$WORK/upgrade.out"

SECOND_TREE=$(cd "$PREFIX_DIR/lib/pondline/current" && pwd -P)
[ "$SECOND_TREE" != "$FIRST_TREE" ] || {
  echo "FAIL: current did not switch to $NEXT_VERSION" >&2
  exit 1
}
[ -d "$FIRST_TREE" ] || {
  echo "FAIL: live tree $FIRST_TREE was deleted while in use" >&2
  exit 1
}
"$PREFIX_DIR/bin/pondline" --version | grep -q "^pondline $NEXT_VERSION " || {
  echo "FAIL: upgraded pondline did not report $NEXT_VERSION" >&2
  exit 1
}
echo "ok   3a. atomic upgrade switched current to $NEXT_VERSION and retained live $VERSION tree"

# Stop the live process and re-run update to prune the retired tree.
kill -TERM "$HOLDER_PID" 2>/dev/null || true
wait "$HOLDER_PID" 2>/dev/null || true
HOLDER_PID=""

"$PREFIX_DIR/bin/pondline-update" \
  --tarball "$NEXT_TARBALL" \
  --sha256-file "$WORK/$NEXT_STEM.tar.gz.sha256" >/dev/null

if ps -axww -o command= >/dev/null 2>&1; then
  [ ! -d "$FIRST_TREE" ] || {
    echo "FAIL: retired tree $FIRST_TREE was not pruned after holder exited" >&2
    exit 1
  }
  echo "ok   3b. retired $VERSION tree pruned once no live process referenced it"
else
  [ -d "$FIRST_TREE" ] || {
    echo "FAIL: retired tree was deleted despite unreadable process table" >&2
    exit 1
  }
  echo "ok   3b. retired $VERSION tree conservatively retained under restricted ps"
fi
echo "PASS test-update"
