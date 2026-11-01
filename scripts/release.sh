#!/usr/bin/env bash
#
# Build the self-contained mailbox release (docs/adr/003-packaging.md).
#
# The output is one directory, build/release/<platform>/reedwire-mailbox/,
# that runs on a machine with no Erlang, Gleam, Rust or Homebrew OpenSSL
# installed. It carries:
#
#   - its own ERTS (the VM executables) and the few OTP applications the
#     program needs, copied from the local OTP install;
#   - the Gleam application, from `gleam export erlang-shipment`;
#   - its own libcrypto (OpenSSL >= 3.5, which ML-KEM needs), with the
#     bundled crypto.so rewritten to load it by a path relative to itself;
#   - the reedwire-tor sidecar, with any non-system library it links
#     bundled the same way;
#   - bin/mailbox, a launcher that refuses to start if the bundled crypto
#     library is older than 3.5.
#
# The script is idempotent: it deletes and rebuilds the release directory
# every run. It builds from the local toolchain, so the release is only as
# portable as the platform it was built on (macOS arm64 is the tested one;
# the Linux recipe is in the ADR and is not implemented here).

set -euo pipefail

# The repository root, so the script works from any directory.
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

# The lowest OpenSSL the release accepts. The launcher enforces it at every
# start, and this script checks it at build time so a bad bundle fails here.
MIN_OPENSSL_MAJOR=3
MIN_OPENSSL_MINOR=5

# The OTP applications the mailbox needs at run time. The Gleam packages are
# copied in addition to these. Kernel and stdlib are what the boot script
# loads; crypto is the NIF library the primitives package binds; mist and
# glisten start the ssl application (even for plain HTTP), which needs
# public_key and asn1. inets is there only because the generated SQL module's
# parrot dependency lists gleam_httpc, which lists inets, and starting the
# mailbox starts every application it names (ADR-007); nothing calls it.
OTP_APPS=(kernel stdlib crypto ssl public_key asn1 inets)

# One directory per platform, so a Linux build never overwrites a macOS one.
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
PLATFORM="${OS}-$(uname -m)"
OUT="$ROOT/build/release/$PLATFORM"
REL="$OUT/reedwire-mailbox"

if [ "$OS" != "darwin" ]; then
  echo "release.sh: only the macOS build is implemented (see ADR-003)" >&2
  exit 1
fi

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

# Rewrite one Mach-O dependency and re-sign. Editing a load command
# invalidates the signature, and arm64 refuses to load unsigned code, so
# an ad-hoc signature is required (this is not distribution signing).
repoint() {
  local file=$1 old=$2 new=$3
  install_name_tool -change "$old" "$new" "$file" 2>/dev/null
  codesign --force --sign - "$file" 2>/dev/null
}

# ------------------------------------------------------------------- build

echo "==> sidecar"
make -C "$ROOT" sidecar >/dev/null

echo "==> gleam shipment"
(cd "$ROOT/packages/mailbox" && gleam export erlang-shipment >/dev/null)
SHIPMENT="$ROOT/packages/mailbox/build/erlang-shipment"

echo "==> assemble $REL"
rm -rf "$REL"
mkdir -p "$REL/bin" "$REL/lib" "$REL/$ERTS_NAME/bin"

# The VM. Only the executables a non-distributed, noshell node starts:
# erlexec execs beam.smp, which spawns erl_child_setup for ports, and
# inet_gethost resolves names. epmd is omitted because nothing here uses
# distribution. None of these link anything outside /usr/lib or /System.
for f in erlexec beam.smp erl_child_setup inet_gethost; do
  cp "$ERTS_DIR/bin/$f" "$REL/$ERTS_NAME/bin/$f"
done

# The boot script that loads only kernel and stdlib. It names applications
# by $ROOT-relative path, so it finds the copies under $REL/lib.
cp "$OTP_ROOT/bin/start_clean.boot" "$REL/bin/start_clean.boot"

# OTP applications: ebin and priv only. Source, docs and examples are
# development weight.
for app in "${OTP_APPS[@]}"; do
  src=$(otp_lib "$app")
  dst="$REL/lib/$(basename "$src")"
  mkdir -p "$dst"
  cp -R "$src/ebin" "$dst/ebin"
  if [ -d "$src/priv" ]; then cp -R "$src/priv" "$dst/priv"; fi
done

# The Gleam packages. Putting them under lib/ puts their ebin directories
# on the code path with no -pa flags, and makes code:priv_dir/1 work for
# esqlite's NIF.
for pkg in "$SHIPMENT"/*/; do
  name=$(basename "$pkg")
  mkdir -p "$REL/lib/$name"
  cp -R "$pkg/ebin" "$REL/lib/$name/ebin"
  if [ -d "$pkg/priv" ]; then cp -R "$pkg/priv" "$REL/lib/$name/priv"; fi
done

# ----------------------------------------------------------------- openssl

# OTP's crypto.so names the libcrypto it was linked against by absolute
# path. Take that file (not whatever is first on a search path) as the one
# to bundle, so the bundle matches what the NIF was built for.
CRYPTO_DIR=$(echo "$REL"/lib/crypto-*/priv/lib)
CRYPTO_SO="$CRYPTO_DIR/crypto.so"
LIBCRYPTO_REF=$(otool -L "$CRYPTO_SO" | awk '/libcrypto/ {print $1; exit}')
LIBCRYPTO_REAL=$(cd "$(dirname "$LIBCRYPTO_REF")" && pwd -P)/$(basename "$LIBCRYPTO_REF")
LIBCRYPTO_NAME=$(basename "$LIBCRYPTO_REF")

# The dylib sits beside crypto.so, and crypto.so finds it relative to its
# own location, so the directory can be moved or renamed freely. The
# bundled library depends on nothing but libSystem.
cp "$LIBCRYPTO_REAL" "$CRYPTO_DIR/$LIBCRYPTO_NAME"
chmod u+w "$CRYPTO_DIR/$LIBCRYPTO_NAME"
install_name_tool -id "@loader_path/$LIBCRYPTO_NAME" "$CRYPTO_DIR/$LIBCRYPTO_NAME" 2>/dev/null
codesign --force --sign - "$CRYPTO_DIR/$LIBCRYPTO_NAME" 2>/dev/null
repoint "$CRYPTO_SO" "$LIBCRYPTO_REF" "@loader_path/$LIBCRYPTO_NAME"

# The deliberately empty provider directory the launcher points OpenSSL at.
mkdir -p "$REL/lib/ossl-modules"

# The test engine is an OTP test fixture that also links libcrypto and is
# never loaded by the program.
rm -f "$CRYPTO_DIR/otp_test_engine.so"

# ----------------------------------------------------------------- sidecar

# The sidecar is a plain executable in bin/. It links a Homebrew liblzma
# on this machine, so any non-system dylib it names is bundled into
# bin/lib and repointed relative to the executable.
TOR="$REL/bin/reedwire-tor"
cp "$ROOT/native/reedwire-tor/target/release/reedwire-tor" "$TOR"
mkdir -p "$REL/bin/lib"
otool -L "$TOR" | awk 'NR > 1 {print $1}' \
  | grep -vE '^(/usr/lib/|/System/)' | while read -r dep; do
  base=$(basename "$dep")
  cp "$(cd "$(dirname "$dep")" && pwd -P)/$base" "$REL/bin/lib/$base"
  chmod u+w "$REL/bin/lib/$base"
  install_name_tool -id "@loader_path/$base" "$REL/bin/lib/$base" 2>/dev/null
  codesign --force --sign - "$REL/bin/lib/$base" 2>/dev/null
  repoint "$TOR" "$dep" "@executable_path/lib/$base"
done
rmdir "$REL/bin/lib" 2>/dev/null || true

# The sqlite NIF records its build-tree path as its install name. The VM
# loads it by file path so this is harmless, but the leak check below
# would rightly flag it, so make it relative.
for nif in "$REL"/lib/esqlite/priv/*.so; do
  install_name_tool -id "@loader_path/$(basename "$nif")" "$nif" 2>/dev/null
  codesign --force --sign - "$nif" 2>/dev/null
done

# ---------------------------------------------------------------- launcher

# The launcher is generated here so the ERTS directory name and version
# floor are written once. It does three things before the program runs:
# it points the VM at the release directory, it scrubs the OpenSSL
# configuration the host might supply, and it refuses to continue if the
# bundled libcrypto is older than the floor.
cat > "$REL/bin/mailbox" <<LAUNCHER
#!/bin/sh
# Reedwire mailbox launcher. Usage: mailbox serve|grant [options].
set -eu

# Resolve the release directory from this script's own location, through
# any symlink, so nothing depends on the caller's working directory.
SELF=\$0
while [ -h "\$SELF" ]; do
  LINK=\$(readlink "\$SELF")
  case \$LINK in /*) SELF=\$LINK ;; *) SELF=\$(dirname "\$SELF")/\$LINK ;; esac
done
REL=\$(cd "\$(dirname "\$SELF")/.." && pwd -P)

# erlexec locates the VM from these. With them set, the release never
# consults an installed Erlang, \$ERL_ROOTDIR or the PATH.
ROOTDIR=\$REL
BINDIR=\$REL/$ERTS_NAME/bin
EMU=beam
PROGNAME=erl
export ROOTDIR BINDIR EMU PROGNAME

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

# Run the bundled VM with the given Erlang expression and no shell.
vm() {
  "\$BINDIR/erlexec" -boot "\$REL/bin/start_clean" -noshell -noinput \\
    -eval "\$1"
}

# Refuse to start on an OpenSSL older than the floor. crypto:info_lib/0
# reports the version number OpenSSL itself compiled in as an integer
# (major in the top nibble, minor in the next byte), so this checks the
# library actually loaded, not a file name.
vm '
  [{_, Num, Str}] = crypto:info_lib(),
  Major = Num bsr 28,
  Minor = (Num bsr 20) band 255,
  case {Major, Minor} >= {$MIN_OPENSSL_MAJOR, $MIN_OPENSSL_MINOR} of
    true -> halt(0);
    false ->
      io:format(standard_error,
        "mailbox: bundled crypto is ~s; OpenSSL >= $MIN_OPENSSL_MAJOR.$MIN_OPENSSL_MINOR is required~n",
        [Str]),
      halt(78)
  end.' || { echo "mailbox: refusing to start" >&2; exit 78; }

# The mailbox's own main, with every argument forwarded after -extra.
exec "\$BINDIR/erlexec" -boot "\$REL/bin/start_clean" -noshell -noinput \\
  -eval 'mailbox@@main:run(mailbox)' -extra "\$@"
LAUNCHER
chmod +x "$REL/bin/mailbox"

# ------------------------------------------------------------ build checks

# Checks against the bundle itself, so a bad build fails here and not on a
# user's machine.
# Load crypto in the bundled VM with the launcher's environment and list
# every libcrypto mapped into it. Exactly one may be present, and it must
# live inside the release.
vmcheck=$(env -i PATH=/usr/bin:/bin OPENSSL_CONF=/dev/null \
  OPENSSL_MODULES="$REL/lib/ossl-modules" ROOTDIR="$REL" \
  BINDIR="$REL/$ERTS_NAME/bin" EMU=beam PROGNAME=erl \
  "$REL/$ERTS_NAME/bin/erlexec" -boot "$REL/bin/start_clean" -noshell \
  -noinput -eval '
    [{_, _, Str}] = crypto:info_lib(),
    Maps = os:cmd("/usr/sbin/lsof -p " ++ os:getpid() ++ " | grep libcrypto"),
    io:format("~s~n~s", [Str, Maps]),
    halt().')
echo "$vmcheck"
if [ "$(echo "$vmcheck" | grep -c 'libcrypto')" -ne 1 ] \
  || echo "$vmcheck" | grep libcrypto | grep -qv "$REL"; then
  echo "release.sh: the VM mapped a libcrypto from outside the release" >&2
  exit 1
fi

# No file in the release may reference a path outside the system and the
# release itself.
leaks=$(find "$REL" -type f \( -name '*.so' -o -name '*.dylib' -o -perm -u+x \) \
  -exec otool -L {} \; 2>/dev/null \
  | awk '/^\t/ {print $1}' \
  | grep -vE '^(/usr/lib/|/System/|@loader_path/|@executable_path/)' \
  || true)
if [ -n "$leaks" ]; then
  echo "release.sh: libraries outside the release are referenced:" >&2
  echo "$leaks" >&2
  exit 1
fi

echo "==> size: $(du -sh "$REL" | cut -f1)"
echo "==> done: $REL"
