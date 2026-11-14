#!/usr/bin/env bash
#
# Fetch, verify, and atomically install or update a Pondline release.
#
#   curl -fsSL https://github.com/Roasbeef/pondline/releases/latest/download/install.sh | bash
#   pondline-update                              # update to latest GitHub release
#   pondline-update --check                      # compare installed build against latest release
#   pondline-update --version v0.1.0             # install a pinned release tag
#   pondline-update --prefix /opt/pondline       # override installation prefix
#   pondline-update --tarball FILE --sha256-file FILE
#
# Security and lifecycle rules:
#
#   - Every archive is verified against its 64-hex SHA-256 digest before tar
#     reads a single byte of it.
#   - Updates serialize on $PREFIX/.pondline-update.lock so two concurrent
#     runs cannot race on staging or tree pruning.
#   - Publication delegates to the unpacked tree's bundled install.sh, which
#     stages the new directory beside existing trees, switches `current` by
#     atomic rename, and keeps any older tree still referenced on a live
#     process command line.

set -euo pipefail

REPO=${PONDLINE_RELEASE_REPO:-Roasbeef/pondline}
TAG=""
CHECK_ONLY=0
EXPLICIT_PREFIX=""
LOCAL_TARBALL=""
LOCAL_SHA256_FILE=""
RESTART_USER_SERVICE=0

usage() {
  cat <<'EOF'
Usage: pondline-update [options]

Options:
  --latest                 Install the latest published release (default)
  --version <vX.Y.Z>       Install a specific release tag
  --check                  Report installed vs available release without installing
  --prefix <dir>           Installation prefix (default: inferred from binary or ~/.local)
  --repo <owner/name>      GitHub repository (default: Roasbeef/pondline)
  --tarball <path>         Install from a pre-downloaded release tarball
  --sha256-file <path>     SHA-256 checksum file required with --tarball
  --restart-user-service   Restart active user daemon/mailbox services (launchd / systemd)
  -h, --help               Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --latest) TAG="" ;;
    --version)
      shift
      TAG=${1:?--version needs a tag such as v0.1.0}
      ;;
    --check) CHECK_ONLY=1 ;;
    --prefix)
      shift
      EXPLICIT_PREFIX=${1:?--prefix needs a directory}
      ;;
    --repo)
      shift
      REPO=${1:?--repo needs owner/name}
      ;;
    --tarball)
      shift
      LOCAL_TARBALL=${1:?--tarball needs a file path}
      ;;
    --sha256-file)
      shift
      LOCAL_SHA256_FILE=${1:?--sha256-file needs a file path}
      ;;
    --restart-user-service) RESTART_USER_SERVICE=1 ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "pondline-update: unknown option $1" >&2
      exit 2
      ;;
  esac
  shift
done

# Infer PREFIX when invoked through an installed $PREFIX/bin/pondline-update
# symlink so custom prefixes stay sticky across updates.
infer_prefix() {
  if [ -n "$EXPLICIT_PREFIX" ]; then
    printf '%s\n' "$EXPLICIT_PREFIX"
    return
  fi
  if [ -n "${PREFIX:-}" ]; then
    printf '%s\n' "$PREFIX"
    return
  fi
  local self=${BASH_SOURCE[0]:-}
  if [ -n "$self" ] && [ -L "$self" ]; then
    local bin_dir
    bin_dir=$(cd "$(dirname "$self")" && pwd -P)
    if [ "$(basename "$bin_dir")" = "bin" ]; then
      local candidate
      candidate=$(cd "$bin_dir/.." && pwd -P)
      if [ -f "$candidate/lib/pondline/.pondline-install" ]; then
        printf '%s\n' "$candidate"
        return
      fi
    fi
  fi
  printf '%s\n' "$HOME/.local"
}

TARGET_PREFIX=$(infer_prefix)

# Detect platform using the exact naming scripts/release.sh and scripts/dist.sh emit.
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
  darwin | linux) ;;
  *)
    echo "pondline-update: unsupported operating system: $OS" >&2
    exit 1
    ;;
esac
# Normalize arm64/aarch64 only when needed: Darwin reports arm64, Linux reports
# x86_64 or aarch64, matching `uname -m` in scripts/release.sh on each host.
PLATFORM="${OS}-${ARCH}"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "pondline-update: neither sha256sum nor shasum is installed" >&2
    exit 1
  fi
}

valid_version() {
  case "$1" in
    *[!0-9A-Za-z.-]* | "" | .* | -*) return 1 ;;
  esac
  printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
}

installed_summary() {
  local build_file="$TARGET_PREFIX/lib/pondline/current/BUILD"
  if [ -f "$build_file" ]; then
    local iv ic
    iv=$(sed -n 's/^version=//p' "$build_file")
    ic=$(sed -n 's/^commit=//p' "$build_file")
    printf '%s (commit %s)' "$iv" "${ic:0:12}"
  else
    printf 'none'
  fi
}

installed_version() {
  local build_file="$TARGET_PREFIX/lib/pondline/current/BUILD"
  if [ -f "$build_file" ]; then
    sed -n 's/^version=//p' "$build_file"
  fi
}

resolve_remote_tag() {
  if [ -n "$TAG" ]; then
    case "$TAG" in
      v*) printf '%s\n' "$TAG" ;;
      *) printf 'v%s\n' "$TAG" ;;
    esac
    return
  fi
  local api_url="https://api.github.com/repos/$REPO/releases/latest"
  local json resolved
  json=$(curl -fsSL -H "Accept: application/vnd.github+json" "$api_url") || {
    echo "pondline-update: could not query latest release from $api_url" >&2
    exit 1
  }
  resolved=$(printf '%s\n' "$json" | tr ',' '\n' | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
  if [ -z "$resolved" ]; then
    echo "pondline-update: no published release tag found at $api_url" >&2
    exit 1
  fi
  printf '%s\n' "$resolved"
}

if [ -n "$LOCAL_TARBALL" ] || [ -n "$LOCAL_SHA256_FILE" ]; then
  if [ -z "$LOCAL_TARBALL" ] || [ -z "$LOCAL_SHA256_FILE" ]; then
    echo "pondline-update: --tarball and --sha256-file must be given together" >&2
    exit 2
  fi
  [ -f "$LOCAL_TARBALL" ] || {
    echo "pondline-update: tarball not found: $LOCAL_TARBALL" >&2
    exit 1
  }
  [ -f "$LOCAL_SHA256_FILE" ] || {
    echo "pondline-update: checksum file not found: $LOCAL_SHA256_FILE" >&2
    exit 1
  }
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  REMOTE_TAG=$(resolve_remote_tag)
  REMOTE_VERSION=${REMOTE_TAG#v}
  valid_version "$REMOTE_VERSION" || {
    echo "pondline-update: invalid release version '$REMOTE_VERSION'" >&2
    exit 1
  }
  CURRENT_SUMMARY=$(installed_summary)
  CURRENT_VERSION=$(installed_version)
  echo "installed: $CURRENT_SUMMARY (prefix $TARGET_PREFIX)"
  echo "available: $REMOTE_VERSION ($REMOTE_TAG for $PLATFORM)"
  if [ "$CURRENT_VERSION" = "$REMOTE_VERSION" ]; then
    echo "status: up to date"
  else
    echo "status: update available"
  fi
  exit 0
fi

# Private staging directory cleaned up unconditionally on exit.
STAGE=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/pondline-update.XXXXXX")
LOCK_DIR=""
cleanup() {
  if [ -n "$LOCK_DIR" ] && [ -d "$LOCK_DIR" ]; then
    rm -rf "$LOCK_DIR"
  fi
  rm -rf "$STAGE"
}
trap cleanup EXIT

acquire_lock() {
  mkdir -p "$TARGET_PREFIX"
  local candidate="$TARGET_PREFIX/.pondline-update.lock"
  if mkdir "$candidate" 2>/dev/null; then
    printf '%s\n' "$$" > "$candidate/pid"
    LOCK_DIR="$candidate"
    return
  fi
  echo "pondline-update: lock held at $candidate (remove it if an earlier update crashed)" >&2
  exit 1
}

if [ -n "$LOCAL_TARBALL" ]; then
  ARCHIVE_NAME=$(basename "$LOCAL_TARBALL")
  ARCHIVE_PATH="$STAGE/$ARCHIVE_NAME"
  cp "$LOCAL_TARBALL" "$ARCHIVE_PATH"
  SUMS_PATH="$STAGE/SHA256SUMS"
  cp "$LOCAL_SHA256_FILE" "$SUMS_PATH"
else
  REMOTE_TAG=$(resolve_remote_tag)
  REMOTE_VERSION=${REMOTE_TAG#v}
  valid_version "$REMOTE_VERSION" || {
    echo "pondline-update: invalid release version '$REMOTE_VERSION'" >&2
    exit 1
  }
  STEM="pondline-${REMOTE_VERSION}-${PLATFORM}"
  ARCHIVE_NAME="${STEM}.tar.gz"
  BASE_URL="https://github.com/${REPO}/releases/download/${REMOTE_TAG}"
  ARCHIVE_PATH="$STAGE/$ARCHIVE_NAME"
  SUMS_PATH="$STAGE/SHA256SUMS"

  echo "==> fetching $ARCHIVE_NAME ($REMOTE_TAG)"
  curl -fsSL -o "$ARCHIVE_PATH" "$BASE_URL/$ARCHIVE_NAME"
  if ! curl -fsSL -o "$SUMS_PATH" "$BASE_URL/SHA256SUMS" 2>/dev/null; then
    curl -fsSL -o "$SUMS_PATH" "$BASE_URL/${ARCHIVE_NAME}.sha256"
  fi
fi

# Extract the expected 64-hex SHA-256 for ARCHIVE_NAME (supports both multi-file
# SHA256SUMS and single-file .tar.gz.sha256 formats, with ` ` or ` *` separator).
EXPECTED_SHA=$(awk -v target="$ARCHIVE_NAME" '
  NF >= 2 {
    file = $2
    sub(/^\*/, "", file)
    n = split(file, parts, "/")
    if (parts[n] == target) {
      print tolower($1)
      exit
    }
  }
' "$SUMS_PATH")

if ! printf '%s\n' "$EXPECTED_SHA" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "pondline-update: checksum file carries no valid SHA-256 entry for $ARCHIVE_NAME" >&2
  exit 1
fi

ACTUAL_SHA=$(sha256_of "$ARCHIVE_PATH" | tr '[:upper:]' '[:lower:]')
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "pondline-update: SHA-256 mismatch for $ARCHIVE_NAME (expected $EXPECTED_SHA, got $ACTUAL_SHA)" >&2
  exit 1
fi
echo "==> verified SHA-256: $ACTUAL_SHA"

UNPACK="$STAGE/unpacked"
mkdir -p "$UNPACK"
tar -xzf "$ARCHIVE_PATH" -C "$UNPACK"

# Locate the single extracted release directory holding BUILD and install.sh.
FOUND_REL=""
for dir in "$UNPACK"/*/; do
  dir=${dir%/}
  [ -d "$dir" ] || continue
  if [ -f "$dir/BUILD" ] && [ -x "$dir/install.sh" ]; then
    FOUND_REL="$dir"
    break
  fi
done

if [ -z "$FOUND_REL" ]; then
  echo "pondline-update: archive $ARCHIVE_NAME did not unpack a valid Pondline release tree" >&2
  exit 1
fi

acquire_lock
PREFIX="$TARGET_PREFIX" "$FOUND_REL/install.sh" --from "$FOUND_REL"

if [ "$RESTART_USER_SERVICE" -eq 1 ]; then
  if [ "$OS" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
    if [ -f "$HOME/Library/LaunchAgents/io.pondline.daemon.plist" ]; then
      launchctl kickstart -k "gui/$(id -u)/io.pondline.daemon" 2>/dev/null || true
      echo "==> restarted io.pondline.daemon"
    fi
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl --user try-restart pondline-mailbox.service 2>/dev/null || true
    systemctl --user try-restart pondline.service 2>/dev/null || true
    echo "==> restarted active pondline user services"
  else
    echo "pondline-update: service manager not found; skipping --restart-user-service" >&2
  fi
fi
