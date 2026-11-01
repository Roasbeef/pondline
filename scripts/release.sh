#!/usr/bin/env bash
#
# Build the self-contained Reedwire release (docs/adr/003-packaging.md and
# its addendum).
#
#   scripts/release.sh            # or `make release`
#   REEDWIRE_TOR_BIN=/path/to/reedwire-tor scripts/release.sh
#
# The output is one directory, build/release/<platform>/reedwire/, that
# runs on a machine with no Erlang, Gleam, Rust or Homebrew OpenSSL
# installed. It holds two programs over one runtime:
#
#   bin/reedwire    the daemon and its CLI (`reedwire daemon ...`,
#                   `reedwire send ...`), the daemon package's `reedwire`
#                   module;
#   bin/mailbox     the mailbox server (`mailbox serve|grant`).
#
# and what both need:
#
#   - its own ERTS (the VM executables) and the few OTP applications the
#     programs need, copied from the local OTP install;
#   - the Gleam packages of both programs, from `gleam export
#     erlang-shipment` in packages/daemon and packages/mailbox, merged into
#     one lib/ (the build fails if the two resolved any package to
#     different versions);
#   - its own libcrypto (OpenSSL >= 3.5, which ML-KEM needs), with the
#     bundled crypto NIF rewritten to load it by a path relative to itself;
#   - the reedwire-tor sidecar, with any non-system library it links
#     bundled the same way;
#   - BUILD, the version, commit and platform the launchers report, and
#     install.sh, so an unpacked tarball can install itself.
#
# Why one bundle and not one per program: the two share everything that
# has weight (ERTS, the OTP libraries, libcrypto and the 16 MB sidecar are
# about 45 MB of a 47 MB tree), their dependency versions already have to
# agree because the daemon's tests run a real mailbox in the same VM, and
# one tree means one libcrypto to audit and replace. A mailbox-only host
# carries the daemon's code, about 1 MB, unused.
#
# The script is idempotent: it deletes and rebuilds the release directory
# every run. It builds from the local toolchain, so the release is only as
# portable as the platform it was built on. macOS arm64 is built and tested.
# The Linux branch (uname Linux) follows the ADR-003 recipe and has NEVER
# BEEN RUN: it needs `patchelf`, and its first run must repeat the scrubbed
# proof (`make release-smoke`) before anything built by it is trusted.

set -euo pipefail

# The repository root, so the script works from any directory.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# The lowest OpenSSL the release accepts. The launchers enforce it at every
# start, and this script checks it at build time so a bad bundle fails here.
MIN_OPENSSL_MAJOR=3
MIN_OPENSSL_MINOR=5

# The OTP applications the programs need at run time. The Gleam packages are
# copied in addition to these. Kernel and stdlib are what the boot script
# loads; crypto is the NIF library the primitives package binds; mist and
# glisten (the mailbox's HTTP server) start the ssl application even for
# plain HTTP, which needs public_key and asn1. The daemon needs only the
# first three.
OTP_APPS=(kernel stdlib crypto ssl public_key asn1)

# The Gleam packages whose shipments make up the release, and the program
# each one provides: launcher name, then the Erlang call that runs it.
# `<package>@@main:run(<module>)` is Gleam's own entry wrapper, which runs
# the module's `main` and halts.
PROGRAMS=(
  "daemon reedwire daemon@@main:run(reedwire)"
  "mailbox mailbox mailbox@@main:run(mailbox)"
)

# Packages that must never ship (ADR-007): parrot and its HTTP client are
# build-time tools, and inets is the OTP application the client would pull.
FORBIDDEN=(parrot gleam_httpc inets)

# One directory per platform, so a Linux build never overwrites a macOS one.
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
PLATFORM="${OS}-$(uname -m)"
OUT="$ROOT/build/release/$PLATFORM"
REL="$OUT/reedwire"

case "$OS" in
  darwin) ;;
  linux)
    echo "release.sh: the Linux recipe is untested (ADR-003); verify with make release-smoke" >&2
    command -v patchelf >/dev/null || {
      echo "release.sh: the Linux recipe needs patchelf" >&2
      exit 1
    }
    ;;
  *)
    echo "release.sh: no release recipe for $OS (see ADR-003)" >&2
    exit 1
    ;;
esac

# ---------------------------------------------------------------- identity

# The build identity (ADR-003 addendum). The version is the packages' own;
# both programs carry it, so they must agree. The commit is resolved now and
# written into the launchers, because a release is run on machines with no
# git and no checkout.
version_of() {
  sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/packages/$1/gleam.toml" | head -n 1
}
VERSION=$(version_of daemon)
if [ "$(version_of mailbox)" != "$VERSION" ]; then
  echo "release.sh: packages/daemon is $VERSION but packages/mailbox is $(version_of mailbox);" \
    "one release carries one version" >&2
  exit 1
fi
COMMIT=$("$ROOT/scripts/build-commit.sh")

# --------------------------------------------------------------- toolchain

# The OTP installation whose ERTS and libraries are copied. Asking the
# running VM avoids guessing at Homebrew's directory layout.
OTP_ROOT=$(erl -noshell -eval 'io:format("~s", [code:root_dir()]), halt().')
ERTS_DIR=$(cd "$OTP_ROOT"/erts-* && pwd -P)
ERTS_NAME=$(basename "$ERTS_DIR")

# Echo the lib directory of one OTP application, version suffix included.
otp_lib() {
  erl -noshell -eval "io:format(\"~s\", [code:lib_dir($1)]), halt()."
}

# The physical path of a file, through any symlink to its directory.
real_path() {
  echo "$(cd "$(dirname "$1")" && pwd -P)/$(basename "$1")"
}

# The libraries a binary links, one path per line, without the binary's own
# name or the dynamic loader's annotations.
linked_libs() {
  case "$OS" in
    darwin) otool -L "$1" | awk 'NR > 1 {print $1}' ;;
    linux) ldd "$1" | awk '/=>/ {print $3} !/=>/ && /^\t\// {print $1}' ;;
  esac
}

# Whether a linked library is part of the operating system, which every
# target machine has. On Linux that is glibc and its neighbours under the
# standard library directories; OpenSSL is never treated as one, because
# the floor is the reason it is bundled.
is_system_lib() {
  case "$OS" in
    darwin)
      case $1 in /usr/lib/* | /System/*) return 0 ;; esac
      ;;
    linux)
      case $1 in
        */libcrypto.so* | */libssl.so*) return 1 ;;
        /lib/* | /lib64/* | /usr/lib/* | /usr/lib64/*) return 0 ;;
      esac
      ;;
  esac
  return 1
}

# Copy a library into `dir` and make it findable from `user`, a binary that
# links it as `ref`. On macOS the library's install name and the user's
# reference are rewritten to a path relative to the loader, and both are
# re-signed: editing a load command invalidates the signature, and arm64
# refuses to load unsigned code (this is an ad hoc signature, not
# distribution signing). On Linux the soname is kept and the user's
# RUNPATH points at `dir`, given as `origin_rel`, relative to $ORIGIN.
bundle_lib() {
  local user=$1 ref=$2 dir=$3 origin_rel=$4 macos_prefix=$5
  local base
  base=$(basename "$ref")
  mkdir -p "$dir"
  cp "$(real_path "$ref")" "$dir/$base"
  chmod u+w "$dir/$base"
  case "$OS" in
    darwin)
      install_name_tool -id "@loader_path/$base" "$dir/$base" 2>/dev/null
      codesign --force --sign - "$dir/$base" 2>/dev/null
      install_name_tool -change "$ref" "$macos_prefix/$base" "$user" 2>/dev/null
      codesign --force --sign - "$user" 2>/dev/null
      ;;
    linux)
      patchelf --set-rpath "\$ORIGIN${origin_rel:+/$origin_rel}" "$user"
      ;;
  esac
}

# ------------------------------------------------------------------- build

echo "==> identity: $VERSION $COMMIT $PLATFORM"

# The sidecar: the binary REEDWIRE_TOR_BIN names (the same variable the tor
# tests honour, so a worktree can reuse another checkout's build), or this
# checkout's release build.
if [ -n "${REEDWIRE_TOR_BIN:-}" ]; then
  SIDECAR=$REEDWIRE_TOR_BIN
  echo "==> sidecar: $SIDECAR"
else
  echo "==> sidecar"
  make -C "$ROOT" sidecar >/dev/null
  SIDECAR="$ROOT/native/reedwire-tor/target/release/reedwire-tor"
fi
[ -x "$SIDECAR" ] || { echo "release.sh: no sidecar at $SIDECAR" >&2; exit 1; }

echo "==> assemble $REL"
rm -rf "$REL"
mkdir -p "$REL/bin" "$REL/lib" "$REL/$ERTS_NAME/bin"

# The VM. Only the executables a non-distributed, noshell node starts:
# erlexec execs beam.smp, which spawns erl_child_setup for ports, and
# inet_gethost resolves names. epmd is omitted because nothing here uses
# distribution.
for f in erlexec beam.smp erl_child_setup inet_gethost; do
  cp "$ERTS_DIR/bin/$f" "$REL/$ERTS_NAME/bin/$f"
done

# The boot script that loads only kernel and stdlib and, unlike
# start_clean, does not run the user's ~/.erlang: a CLI whose standard
# output can be a raw payload must not run code it did not ship. It names
# applications by $ROOT-relative path, so it finds the copies under lib/.
cp "$OTP_ROOT/bin/no_dot_erlang.boot" "$REL/bin/no_dot_erlang.boot"

# OTP applications: ebin and priv only. Source, docs and examples are
# development weight.
for app in "${OTP_APPS[@]}"; do
  src=$(otp_lib "$app")
  dst="$REL/lib/$(basename "$src")"
  mkdir -p "$dst"
  cp -R "$src/ebin" "$dst/ebin"
  if [ -d "$src/priv" ]; then cp -R "$src/priv" "$dst/priv"; fi
done

# The application version a package's .app file declares.
app_vsn() {
  sed -n 's/.*{vsn, *"\([^"]*\)"}.*/\1/p' "$1"/ebin/*.app | head -n 1
}

# The Gleam packages of every program. Putting them under lib/ puts their
# ebin directories on the code path with no -pa flags, and makes
# code:priv_dir/1 work for esqlite's NIF. A package both programs use is
# copied once; if the two shipments disagree on its version the build
# stops, because one lib/ can hold only one.
for program in "${PROGRAMS[@]}"; do
  read -r package _ _ <<<"$program"
  echo "==> gleam shipment: $package"
  log="$OUT/export-$package.log"
  (cd "$ROOT/packages/$package" && gleam export erlang-shipment) >"$log" 2>&1 \
    || { cat "$log" >&2; echo "release.sh: gleam export failed in $package" >&2; exit 1; }
  for pkg in "$ROOT/packages/$package/build/erlang-shipment"/*/; do
    name=$(basename "$pkg")
    if [ -d "$REL/lib/$name" ]; then
      if [ "$(app_vsn "$pkg")" != "$(app_vsn "$REL/lib/$name")" ]; then
        echo "release.sh: $name is $(app_vsn "$REL/lib/$name") in one shipment and" \
          "$(app_vsn "$pkg") in $package's" >&2
        exit 1
      fi
      continue
    fi
    mkdir -p "$REL/lib/$name"
    cp -R "$pkg/ebin" "$REL/lib/$name/ebin"
    if [ -d "$pkg/priv" ]; then cp -R "$pkg/priv" "$REL/lib/$name/priv"; fi
  done
done

# ----------------------------------------------------------------- openssl

# OTP's crypto NIF names the libcrypto it was linked against by absolute
# path. Take that file (not whatever is first on a search path) as the one
# to bundle, so the bundle matches what the NIF was built for. It sits
# beside the NIF, which finds it relative to its own location, so the
# release can be moved or renamed freely.
CRYPTO_DIR=$(echo "$REL"/lib/crypto-*/priv/lib)
CRYPTO_SO="$CRYPTO_DIR/crypto.so"
LIBCRYPTO_REF=$(linked_libs "$CRYPTO_SO" | grep libcrypto | head -n 1)
[ -n "$LIBCRYPTO_REF" ] || {
  echo "release.sh: $CRYPTO_SO links no libcrypto" >&2
  exit 1
}
bundle_lib "$CRYPTO_SO" "$LIBCRYPTO_REF" "$CRYPTO_DIR" "" "@loader_path"

# The deliberately empty provider directory the launchers point OpenSSL at.
mkdir -p "$REL/lib/ossl-modules"

# The test engine is an OTP test fixture that also links libcrypto and is
# never loaded by the program.
rm -f "$CRYPTO_DIR/otp_test_engine.so"

# ----------------------------------------------------------------- sidecar

# The sidecar is a plain executable in bin/. On this Mac it links a
# Homebrew liblzma, so any non-system library it names is bundled into
# bin/lib and repointed relative to the executable.
TOR="$REL/bin/reedwire-tor"
cp "$SIDECAR" "$TOR"
chmod u+w "$TOR"
linked_libs "$TOR" | while read -r dep; do
  is_system_lib "$dep" && continue
  bundle_lib "$TOR" "$dep" "$REL/bin/lib" lib "@executable_path/lib"
done
rmdir "$REL/bin/lib" 2>/dev/null || true

# The sqlite NIF records its build-tree path as its install name. The VM
# loads it by file path so this is harmless, but the leak check below
# would rightly flag it, so make it relative.
if [ "$OS" = darwin ]; then
  for nif in "$REL"/lib/esqlite/priv/*.so; do
    install_name_tool -id "@loader_path/$(basename "$nif")" "$nif" 2>/dev/null
    codesign --force --sign - "$nif" 2>/dev/null
  done
fi

# ---------------------------------------------------------------- identity

# What the release is, for the launchers and for scripts/install.sh, which
# names the installed tree after it.
printf 'version=%s\ncommit=%s\nplatform=%s\n' "$VERSION" "$COMMIT" "$PLATFORM" \
  > "$REL/BUILD"

# The installer travels with the release, so an unpacked tarball installs
# itself (`<tree>/install.sh`, PREFIX in the environment).
cp "$ROOT/scripts/install.sh" "$REL/install.sh"

# --------------------------------------------------------------- launchers

# The OpenSSL floor, checked inside the program's own VM before its main
# runs. crypto:info_lib/0 reports the version number OpenSSL itself
# compiled in as an integer (major in the top nibble, minor in the next
# byte), so this checks the library actually loaded, not a file name. A
# library that fails to load is refused the same way, instead of crashing
# the boot and leaving an erl_crash.dump behind. Exit 78 is EX_CONFIG.
openssl_check() {
  local name=$1
  cat <<CHECK
try crypto:info_lib() of
    [{_, Num, _}] when {Num bsr 28, (Num bsr 20) band 255} >= {$MIN_OPENSSL_MAJOR, $MIN_OPENSSL_MINOR} -> ok;
    [{_, _, Str}] ->
      io:format(standard_error, "$name: bundled crypto is ~s; OpenSSL >= $MIN_OPENSSL_MAJOR.$MIN_OPENSSL_MINOR is required~n", [Str]),
      halt(78)
  catch _:_ ->
    io:format(standard_error, "$name: the bundled crypto library did not load~n", []),
    halt(78)
  end
CHECK
}

# A launcher is generated per program so the ERTS directory name, the
# version floor and the build identity are written once, here. Before the
# program runs it points the VM at the release directory, scrubs the
# Erlang and OpenSSL configuration the host might supply, and exports the
# build identity; the VM then checks the OpenSSL floor and runs the
# program, in one boot.
write_launcher() {
  local name=$1 entry=$2
  cat > "$REL/bin/$name" <<LAUNCHER
#!/bin/sh
# Reedwire $name launcher, generated by scripts/release.sh.
# Build: $VERSION $COMMIT $PLATFORM
set -eu

# Resolve the release directory from this script's own location, through
# any symlink (an installed \$PREFIX/bin link included), so nothing depends
# on the caller's working directory.
SELF=\$0
while [ -h "\$SELF" ]; do
  LINK=\$(readlink "\$SELF")
  case \$LINK in /*) SELF=\$LINK ;; *) SELF=\$(dirname "\$SELF")/\$LINK ;; esac
done
REL=\$(cd "\$(dirname "\$SELF")/.." && pwd -P)

# erlexec locates the VM from these. With them set, the release never
# consults an installed Erlang, \$ERL_ROOTDIR or the PATH. The variables a
# host Erlang setup might leave behind are removed: ERL_LIBS would put
# foreign code ahead of the release's, and the ERL_*FLAGS variables add
# emulator arguments.
ROOTDIR=\$REL
BINDIR=\$REL/$ERTS_NAME/bin
EMU=beam
PROGNAME=erl
export ROOTDIR BINDIR EMU PROGNAME
unset ERL_LIBS ERL_FLAGS ERL_AFLAGS ERL_ZFLAGS

# A crash dump is a copy of every process heap, credentials and keys
# included, written to the working directory. It is off unless the
# operator asks for one.
ERL_CRASH_DUMP_SECONDS=\${ERL_CRASH_DUMP_SECONDS:-0}
export ERL_CRASH_DUMP_SECONDS

# The host's OpenSSL must not leak into the process. /dev/null is an empty
# configuration. OTP's crypto asks OpenSSL for its legacy provider (md4,
# rc4 and similar) at load time, and OpenSSL finds it in the host's module
# directory, whose legacy module links the host's own libcrypto. That maps
# a second, different libcrypto into the VM. Pointing the module directory
# at an empty one in the release removes the second copy and costs only
# the legacy digests, which the protocol never uses.
OPENSSL_CONF=/dev/null
OPENSSL_MODULES=\$REL/lib/ossl-modules
export OPENSSL_CONF OPENSSL_MODULES

# The build identity the program reports (daemon/build, mailbox/build).
REEDWIRE_BUILD_VERSION=$VERSION
REEDWIRE_BUILD_COMMIT=$COMMIT
export REEDWIRE_BUILD_VERSION REEDWIRE_BUILD_COMMIT

# The OpenSSL floor, then the program, with every argument after -extra.
# -noinput keeps the VM from reading standard input itself, so a command
# that reads a payload from /dev/stdin is its only reader.
exec "\$BINDIR/erlexec" -boot "\$REL/bin/no_dot_erlang" -noshell -noinput \\
  -eval '$(openssl_check "$name"),
  $entry.' -extra "\$@"
LAUNCHER
  chmod +x "$REL/bin/$name"
}

for program in "${PROGRAMS[@]}"; do
  read -r _ name entry <<<"$program"
  write_launcher "$name" "$entry"
done

# ------------------------------------------------------------ build checks

# Checks against the bundle itself, so a bad build fails here and not on a
# user's machine.

# No build-time tool ships (ADR-007).
for name in "${FORBIDDEN[@]}"; do
  if compgen -G "$REL/lib/$name" >/dev/null || compgen -G "$REL/lib/$name-*" >/dev/null; then
    echo "release.sh: $name must not ship, but lib/ has it" >&2
    exit 1
  fi
done

# Load crypto in the bundled VM with the launcher's environment and list
# every libcrypto mapped into it. Exactly one may be present, and it must
# live inside the release.
case "$OS" in
  darwin) MAPS='"/usr/sbin/lsof -p " ++ os:getpid() ++ " | grep libcrypto"' ;;
  linux) MAPS='"grep libcrypto /proc/" ++ os:getpid() ++ "/maps | sort -u -k6"' ;;
esac
vmcheck=$(env -i PATH=/usr/bin:/bin OPENSSL_CONF=/dev/null \
  OPENSSL_MODULES="$REL/lib/ossl-modules" ROOTDIR="$REL" \
  BINDIR="$REL/$ERTS_NAME/bin" EMU=beam PROGNAME=erl \
  "$REL/$ERTS_NAME/bin/erlexec" -boot "$REL/bin/no_dot_erlang" -noshell \
  -noinput -eval "
    [{_, _, Str}] = crypto:info_lib(),
    Maps = os:cmd($MAPS),
    io:format(\"~s~n~s\", [Str, Maps]),
    halt().")
echo "$vmcheck"
if [ "$(echo "$vmcheck" | grep -c 'libcrypto')" -ne 1 ] \
  || echo "$vmcheck" | grep libcrypto | grep -qv "$REL"; then
  echo "release.sh: the VM mapped a libcrypto from outside the release" >&2
  exit 1
fi

# No binary in the release may link a library outside the system and the
# release itself.
case "$OS" in
  darwin)
    leaks=$(find "$REL" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) \
      -exec otool -L {} \; 2>/dev/null \
      | awk '/^\t/ {print $1}' \
      | grep -vE '^(/usr/lib/|/System/|@loader_path/|@executable_path/)' \
      || true)
    ;;
  linux)
    leaks=$(find "$REL" -type f \( -name '*.so*' -o -perm -u+x \) \
      -exec sh -c 'ldd "$1" 2>/dev/null' _ {} \; \
      | awk '/not found/ {print} /=>/ {print $3}' \
      | grep -v "^$REL/" \
      | while read -r lib; do is_system_lib "$lib" || echo "$lib"; done \
      || true)
    ;;
esac
if [ -n "$leaks" ]; then
  echo "release.sh: libraries outside the release are referenced:" >&2
  echo "$leaks" >&2
  exit 1
fi

echo "==> size: $(du -sh "$REL" | cut -f1)"
echo "==> done: $REL"
