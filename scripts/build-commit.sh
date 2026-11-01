#!/bin/sh
#
# Print the commit this source tree was built from, for the build identity
# a release reports (`reedwire --version`, `mailbox --version`, the
# `version` and `commit` fields of `health`; ADR-003 addendum).
#
# A git checkout or worktree answers with its HEAD, followed by `-dirty`
# when a tracked file differs from it, so a release built from an edited
# tree never claims to be the commit it was edited from. Untracked files do
# not count: they are not part of any build input the release copies. A
# tree with no git metadata, or no git, prints `unknown`. The `.git` test
# matters: a tree unpacked inside some other repository must not report
# that repository's HEAD.

root=$(cd "$(dirname "$0")/.." && pwd -P)

if [ -e "$root/.git" ] && commit=$(git -C "$root" rev-parse HEAD 2>/dev/null); then
  if [ -n "$(git -C "$root" status --porcelain --untracked-files=no 2>/dev/null)" ]; then
    commit="$commit-dirty"
  fi
  echo "$commit"
  exit 0
fi

echo unknown
