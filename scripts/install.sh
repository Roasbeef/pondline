#!/usr/bin/env bash
#
# Install (or remove) a Pondline release under a prefix.
#
#   make install   [PREFIX=$HOME/.local]       # builds the release first
#   make uninstall [PREFIX=$HOME/.local]
#   scripts/install.sh [--from RELEASE_DIR] [--uninstall]
#   <unpacked tarball>/install.sh              # the copy inside a release
#
# What lands where, and why:
#
#   $PREFIX/lib/pondline/<version>-<commit>-<platform>/
#       the release tree, copied whole from build/release/<platform>/pondline
#       (or --from). It is self-contained (its own ERTS, OpenSSL and Tor
#       sidecar; ADR-003), so nothing else is installed anywhere. The name
#       is the build's identity from its BUILD file, so two builds sit side
#       by side and reinstalling the same build finds its own tree.
#   $PREFIX/lib/pondline/current -> <that tree>
#       the one switch between builds. It is replaced by a rename, so a
#       launcher started during an install sees the old tree or the new one,
#       never half of either.
#   $PREFIX/bin/pondline          -> ../lib/pondline/current/bin/pondline
#   $PREFIX/bin/pondline-mailbox  -> ../lib/pondline/current/bin/mailbox
#       the two commands, as relative symlinks. The release launchers
#       resolve their own symlinks to find the tree, so no wrapper script is
#       needed and nothing in the tree records the prefix. The mailbox gets
#       a prefixed name because `mailbox` is too generic for a shared bin.
#   $PREFIX/lib/pondline/.pondline-install
#       a marker that says this directory is ours, so uninstall and later
#       installs can tell it from someone else's `lib/pondline`.
#
# Rules:
#
#   - Idempotent. Reinstalling the same clean commit keeps the tree already
#     installed for it (uninstall first to force a fresh copy); a -dirty
#     build is recopied only when its files differ. The links are rewritten
#     to the same targets.
#   - It refuses to replace anything it did not create: a `bin/pondline` or
#     `bin/pondline-mailbox` that is not exactly the symlink above, or a
#     `lib/pondline` without the marker. It checks all of them before it
#     changes anything.
#   - A running daemon or mailbox loads code from its tree long after it
#     starts, so a tree a live process uses is never deleted or replaced.
#     Older trees nobody uses are removed after the switch. A process uses a
#     tree if its command line names it, which the launchers guarantee: the
#     VM is started with the tree's physical path as its root.
#   - Daemon state (the --state-dir directories) and mailbox databases live
#     wherever the operator put them, never under the prefix, and neither
#     install nor uninstall touches them.

set -euo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
PREFIX=${PREFIX:-$HOME/.local}
FROM=""
MODE=install

while [ $# -gt 0 ]; do
  case "$1" in
    --from) shift; FROM=${1:?--from needs a release directory} ;;
    --uninstall) MODE=uninstall ;;
    -h | --help)
      sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "install.sh: unknown option $1" >&2; exit 2 ;;
  esac
  shift
done

# The release to install: --from, else the tree this script sits in (the
# copy inside a release or an unpacked tarball), else this checkout's build.
if [ -z "$FROM" ]; then
  if [ -f "$SELF_DIR/BUILD" ]; then
    FROM=$SELF_DIR
  else
    PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
    FROM="$(dirname "$SELF_DIR")/build/release/$PLATFORM/pondline"
  fi
fi

# An uninstall never creates the prefix it was asked to clean.
if [ ! -d "$PREFIX" ]; then
  if [ "$MODE" = uninstall ]; then
    echo "nothing is installed under $PREFIX"
    exit 0
  fi
  mkdir -p "$PREFIX"
fi
PREFIX=$(cd "$PREFIX" && pwd -P)
BIN="$PREFIX/bin"

# The lib directory by its physical path. A running VM names its tree by
# the physical path (the launcher resolves it with pwd -P), so if the
# operator's $PREFIX/lib is a symlink to another volume, the in-use check
# below must compare the same spelling or it would miss a live tree.
LIBROOT="$PREFIX/lib"
if [ -d "$LIBROOT" ]; then LIBROOT=$(cd "$LIBROOT" && pwd -P); fi
LIB="$LIBROOT/pondline"
MARKER="$LIB/.pondline-install"

# The installed commands, as "installed name:launcher in the tree".
COMMANDS=("pondline:pondline" "pondline-mailbox:mailbox" "pondline-update:pondline-update")

# The symlink each command must be, relative to $BIN.
link_target() { echo "../lib/pondline/current/bin/$1"; }

# Whether `bin/<name>` is absent or exactly our link.
command_is_ours_or_absent() {
  local path="$BIN/$1" want
  want=$(link_target "$2")
  [ ! -e "$path" ] && [ ! -L "$path" ] && return 0
  [ -L "$path" ] && [ "$(readlink "$path")" = "$want" ]
}

# Every release tree under $LIB: real directories with a BUILD file.
trees() {
  local dir
  for dir in "$LIB"/*/; do
    dir=${dir%/}
    [ -d "$dir" ] && [ ! -L "$dir" ] && [ -f "$dir/BUILD" ] && echo "$dir"
  done
}

# Whether a live process was started from a tree. The launchers start the
# VM with the tree's physical path in its arguments. The process list is
# read whole before it is searched: under pipefail, `ps | grep -q` fails
# whenever grep stops early and ps takes the SIGPIPE, which would read as
# "unused" exactly when a match was found. A process list that cannot be
# read at all also counts as "in use", so a missing answer never deletes.
in_use() {
  local processes
  processes=$(ps -axww -o command= 2>/dev/null) || return 0
  [ -n "$processes" ] || return 0
  case $processes in *"$1/"*) return 0 ;; esac
  return 1
}

# Replace a symlink by renaming a new one over it. GNU mv needs -T and BSD
# mv needs -h to replace a link to a directory instead of moving into it.
switch_link() {
  local target=$1 path=$2 staged
  staged="$(dirname "$path")/.$(basename "$path").$$"
  ln -s "$target" "$staged"
  mv -T -f "$staged" "$path" 2>/dev/null || mv -h -f "$staged" "$path"
}

# --------------------------------------------------------------- preflight

# Everything that could make us refuse is checked before anything changes.
if [ -L "$LIB" ] || { [ -e "$LIB" ] && [ ! -f "$MARKER" ]; }; then
  echo "install.sh: $LIB exists and was not made by this script; refusing to touch it" >&2
  exit 1
fi
for entry in "${COMMANDS[@]}"; do
  name=${entry%%:*}
  launcher=${entry#*:}
  if ! command_is_ours_or_absent "$name" "$launcher"; then
    echo "install.sh: $BIN/$name exists and is not a Pondline link; refusing to replace it" >&2
    exit 1
  fi
done

# --------------------------------------------------------------- uninstall

if [ "$MODE" = uninstall ]; then
  if [ -d "$LIB" ]; then
    while IFS= read -r tree; do
      if in_use "$tree"; then
        echo "install.sh: $tree is in use by a running process; stop it first" >&2
        exit 1
      fi
    done < <(trees)
  fi
  for entry in "${COMMANDS[@]}"; do
    name=${entry%%:*}
    if [ -L "$BIN/$name" ]; then
      rm -f "$BIN/$name"
      echo "removed $BIN/$name"
    fi
  done
  if [ -d "$LIB" ]; then
    rm -rf "$LIB"
    echo "removed $LIB"
  fi

  # The directories an install may have created, only if now empty.
  rmdir "$BIN" "$PREFIX/lib" 2>/dev/null || true
  exit 0
fi

# ----------------------------------------------------------------- install

[ -f "$FROM/BUILD" ] && [ -x "$FROM/bin/pondline" ] && [ -x "$FROM/bin/mailbox" ] || {
  echo "install.sh: no release at $FROM; run make release first" >&2
  exit 1
}
FROM=$(cd "$FROM" && pwd -P)

field() { sed -n "s/^$1=//p" "$FROM/BUILD"; }
VERSION=$(field version)
COMMIT=$(field commit)
PLATFORM=$(field platform)

# The commit is shortened to twelve characters, keeping a -dirty suffix.
SHORT=${COMMIT:0:12}
case $COMMIT in *-dirty) SHORT="$SHORT-dirty" ;; esac
NAME="$VERSION-$SHORT-$PLATFORM"
TREE="$LIB/$NAME"

mkdir -p "$LIB" "$BIN"
touch "$MARKER"

# Copy the release into a staging directory and rename it into place, so a
# tree under its final name is always complete. A tree already there under
# the same name is kept when it is the same build: always for a clean
# commit, whose sources the name pins (a rebuild is not byte-identical,
# since the build re-links the sqlite NIF and copies whatever library the
# host has now), and only when identical for a -dirty or unknown one, whose
# sources the name does not pin. Such a tree that differs is replaced only
# if nothing runs from it.
same_build() {
  [ -d "$TREE" ] || return 1
  case $COMMIT in
    *-dirty | unknown) diff -rq "$FROM" "$TREE" >/dev/null 2>&1 ;;
    *) return 0 ;;
  esac
}
if same_build; then
  echo "unchanged $TREE"
else
  if [ -d "$TREE" ] && in_use "$TREE"; then
    echo "install.sh: $TREE differs from $FROM but a running process uses it; stop it first" >&2
    exit 1
  fi
  STAGE=$(mktemp -d "$LIB/.stage.XXXXXX")
  trap 'rm -rf "$STAGE"' EXIT
  cp -Rp "$FROM/." "$STAGE/"
  rm -rf "$TREE"
  mv "$STAGE" "$TREE"
  trap - EXIT
  echo "installed $TREE"
fi

switch_link "$NAME" "$LIB/current"
for entry in "${COMMANDS[@]}"; do
  name=${entry%%:*}
  launcher=${entry#*:}
  [ -x "$TREE/bin/$launcher" ] || continue
  switch_link "$(link_target "$launcher")" "$BIN/$name"
  echo "linked $BIN/$name -> $(link_target "$launcher")"
done

# Older trees that no link selects and no process uses.
while IFS= read -r tree; do
  [ "$tree" = "$TREE" ] && continue
  if in_use "$tree"; then
    echo "kept $tree (in use)"
  else
    rm -rf "$tree"
    echo "removed $tree"
  fi
done < <(trees)

echo "pondline $VERSION (commit $COMMIT) for $PLATFORM is installed under $PREFIX"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "add $BIN to PATH, or run $BIN/pondline directly" ;;
esac
