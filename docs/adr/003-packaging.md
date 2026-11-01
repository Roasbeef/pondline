# ADR-003 — Ship one directory per platform with its own ERTS, OpenSSL and sidecar

**Status**: accepted · **Date**: 2026-10-31 · **Spec ref**: §12.3

Accepted for macOS arm64, where it was built and run. The Linux recipe is
written down below but was not run, so the Linux half is an assumption.

## Decision

A release is one directory (`reedwire-mailbox/`, tarred per platform) built
by `scripts/release.sh`, which `make release` runs. It needs no Erlang,
Gleam, Rust, Tor or OpenSSL on the target machine. The build uses no tool
beyond the ones the repository already needs (`gleam`, `erl`, `cargo`,
and on macOS `install_name_tool`, `codesign` and `lsof` from the system).
No `rebar3`, `relx` or `reltool`.

Layout:

```
reedwire-mailbox/
  bin/mailbox            launcher (sh): sets the VM environment, checks OpenSSL, execs
  bin/start_clean.boot   OTP's own boot script, loads kernel and stdlib only
  bin/reedwire-tor       the Arti sidecar
  bin/lib/liblzma.5.dylib   a library the sidecar links (see below)
  erts-17.0.5/bin/       erlexec, beam.smp, erl_child_setup, inet_gethost
  lib/<otp app>-<vsn>/   kernel stdlib crypto ssl public_key asn1 (ebin, priv only)
  lib/<gleam pkg>/       every package in `gleam export erlang-shipment` (ebin, priv)
  lib/crypto-*/priv/lib/libcrypto.3.dylib   bundled OpenSSL, beside crypto.so
  lib/ossl-modules/      deliberately empty
```

How each requirement is met:

- **Own ERTS, no release tooling.** `gleam export erlang-shipment` gives
  compiled Gleam packages. The release copies the VM executables and the
  six OTP applications from the local OTP install, and the launcher sets
  `ROOTDIR`, `BINDIR`, `EMU` and `PROGNAME` and execs the bundled
  `erlexec` with OTP's `start_clean.boot`. The VM adds `$ROOTDIR/lib/*/ebin`
  to the code path by itself, so putting the Gleam packages under `lib/`
  needs no `-pa` flags, and `code:priv_dir/1` finds esqlite's NIF.
- **Own libcrypto.** OTP's `crypto.so` names its libcrypto by absolute
  Homebrew path. The script copies that dylib next to `crypto.so`, sets its
  install name to `@loader_path/libcrypto.3.dylib`, and rewrites
  `crypto.so`'s reference to the same. arm64 refuses unsigned code and
  editing a load command invalidates the signature, so each edited file is
  re-signed ad hoc. This is not distribution signing.
- **Host OpenSSL kept out.** The launcher sets `OPENSSL_CONF=/dev/null` and
  `OPENSSL_MODULES` to the empty `lib/ossl-modules`. Without the second,
  OTP's `crypto` loads OpenSSL's legacy provider at start, OpenSSL finds
  the host's module directory, and the host's `legacy.dylib` pulls the
  host's libcrypto into the same process beside the bundled one (found by
  `lsof`, see Evidence). The cost is the legacy digests (md4 and similar),
  which the protocol does not use; `crypto:hash(md4, ...)` fails with
  `notsup` in a release.
- **Startup version floor.** The launcher starts the bundled VM once, reads
  `crypto:info_lib/0` (the integer version OpenSSL compiled in, major in
  the top nibble, minor in the next byte), and exits 78 with a message if
  it is below 3.5. The floor is checked against the library actually
  loaded, not a file name. Run against a launcher whose floor was raised
  to 3.7 it printed `bundled crypto is OpenSSL 3.6.3 ...; OpenSSL >= 3.5 is
  required` and exited 78. This check does not use Gleam code or
  `primitives.openssl_version()`, which wraps the same call.
- **Sidecar.** `make sidecar` builds it; it is copied to `bin/`.
- **Build-time proof.** The script ends by failing the build if the
  bundled VM maps any libcrypto outside the release, or if any Mach-O
  file in the release references a path outside `/usr/lib`, `/System` and
  `@loader_path`/`@executable_path`.

## Why

The question was whether one self-contained directory can run the Gleam
application with its own ERTS, OpenSSL at least 3.5 and the sidecar, on a
machine with none of the build toolchain. On macOS arm64 it can, with
four findings the plan did not anticipate:

1. **The sidecar links a Homebrew library.** `reedwire-tor` links
   `/opt/homebrew/opt/xz/lib/liblzma.5.dylib`. A release that copied only
   the binary would fail to start on a machine without Homebrew xz. The
   script now bundles any non-system dylib the sidecar names into
   `bin/lib` and repoints it with `@executable_path`. On Linux the better
   fix is to build `lzma-sys` statically in the sidecar build.
2. **The legacy provider leak** described above. It would have been
   invisible on a clean machine (the provider simply would not be found)
   and loud on one with a different OpenSSL installed (two libcryptos in
   one process).
3. **Mist and glisten start the `ssl` application** even for plain HTTP, so
   `ssl`, `public_key` and `asn1` ship even though the mailbox serves no
   TLS. The first run failed with `Ssl("ssl.app")` until they were added.
4. **Ad hoc re-signing is mandatory on arm64** after any `install_name_tool`
   edit.

The environment was OTP 29.0.5 (ERTS 17.0.5), OpenSSL 3.6.3 (Homebrew
`openssl@3`, which the `openssl@3.5` and `openssl@3.6` opt links also
resolve to), macOS 27.2 on arm64.
Homebrew's OTP links OpenSSL 3.6.3, so the 3.5 floor holds with margin.

### Evidence

Clean build, from an empty `build/release`:

```
$ rm -rf build/release; make release
==> sidecar
==> gleam shipment
==> assemble .../build/release/darwin-arm64/reedwire-mailbox
OpenSSL 3.6.3 9 Jun 2026
beam.smp ... txt REG ... .../reedwire-mailbox/lib/crypto-5.9.2/priv/lib/libcrypto.3.dylib
==> size:  46M
make_exit=0
```

Scrubbed run of the bundled release. `env -i` leaves only `HOME` and
`PATH=/usr/bin:/bin`, so no Erlang, Gleam, cargo or Homebrew is reachable
by name:

```
$ env -i HOME=$T PATH=/usr/bin:/bin reedwire-mailbox/bin/mailbox grant \
      --db $T/m.db --queues 3 --out $T/g.cap
$T/g.cap                                    (exit 0, g.cap mode 0600, 32 bytes)

$ env -i HOME=$T PATH=/usr/bin:/bin reedwire-mailbox/bin/mailbox serve \
      --db $T/m.db --port 0
listening 127.0.0.1:49600                   (0.29 s from exec, includes the version check)
```

`reedwire-tor` also starts in the same scrubbed environment (it printed its
usage line, exit 0), so the repointed liblzma resolves.

The libcrypto proof. `serve` does not load `crypto` until something uses
it, so the proof loads `crypto` in the bundled VM (same environment as the
launcher) and lists mapped libcrypto files with `lsof -p`. Before the
`OPENSSL_MODULES` fix, with `crypto:hash(md4, ...)` forcing the provider:

```
beam.smp  txt  /opt/homebrew/Cellar/openssl@3/3.6.3/lib/ossl-modules/legacy.dylib
beam.smp  txt  <REL>/lib/crypto-5.9.2/priv/lib/libcrypto.3.dylib
beam.smp  txt  /opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib      <- the leak
```

After the fix (this is also what `release.sh` asserts on every build):

```
OpenSSL 3.6.3 9 Jun 2026
beam.smp  txt  REG  1,17  4842528  ...  <REL>/lib/crypto-5.9.2/priv/lib/libcrypto.3.dylib
```

`otool -L` of the release's `crypto.so` shows only
`@loader_path/libcrypto.3.dylib` and libSystem. The sidecar shows
`@executable_path/lib/liblzma.5.dylib`, libiconv and system frameworks.

Size and timing (macOS arm64):

| Part | Size |
|---|---|
| Whole directory | 46 MB (532 files) |
| Tarball (`tar czf`) | 24.4 MB (25,583,411 bytes) |
| `bin/` (sidecar 16.4 MB, liblzma 0.2 MB) | 16.6 MB |
| `lib/` | 25.0 MB |
| of which stdlib 7.1, crypto 5.1 (libcrypto 4.7), kernel 3.2, public_key 2.9, ssl 2.5, asn1 1.3, esqlite 1.3, all Gleam packages about 1.2 | |
| `erts-17.0.5/` | 5.1 MB |

The sidecar and the OTP libraries dominate. Startup: 0.29 to 0.43 s from
exec to `listening`, of which the launcher's separate version-check VM is
about 0.15 to 0.2 s; an unknown subcommand returns in 0.19 s.

OTP applications included: kernel 11.0.3, stdlib 8.0.3, crypto 5.9.2,
ssl 11.7.4, public_key 1.21.4, asn1 5.5. Gleam packages: argv, core,
esqlite, exception, filepath, gleam_crypto, gleam_erlang, gleam_http,
gleam_otp, gleam_stdlib, glisten, gramps, hpack, logging, mailbox, mist,
primitives, simplifile, splitter, sqlight.

### Linux recipe (not run)

Assumed, not tested:

- Build in an environment whose OTP links an OpenSSL of at least 3.5
  (ADR-002: Ubuntu 24.04 ships 3.0, so bundling is required, not optional).
- Copy `libcrypto.so.3` next to `crypto.so` and set `RUNPATH` with
  `patchelf --set-rpath '$ORIGIN' crypto.so`; keep the soname. The same
  `OPENSSL_MODULES` guard applies and matters more, because a distribution
  `legacy.so` links the system `libcrypto.so.3` and could clash with the
  bundled one. The sidecar and `beam.smp` need `ldd` review for glibc
  version floor; build on the oldest supported distribution, or use musl.
- Alternative that removes the library question: build OTP from source with
  `--with-ssl=<prefix> --disable-dynamic-ssl-lib`, statically linking
  OpenSSL into `crypto.so`. This costs a custom OTP build in CI.
- Build `lzma-sys` statically so the sidecar has no runtime dependency.

## Consequences

- The release is built from the developer's local OTP and Homebrew
  libraries, so its contents depend on that toolchain. Release builds must
  eventually run in a pinned environment, with OTP and OpenSSL versions
  recorded.
- The package exists only for macOS arm64. A Linux build needs the recipe
  above and a run of the same scrubbed-environment proof. The script exits
  with an error on other platforms rather than producing a half-working
  directory.
- Not done, and still needed before shipping: Developer ID signing and
  notarization (the ad hoc signatures here will not satisfy Gatekeeper on
  a downloaded tarball), signed artifacts and a dependency inventory
  (§12.3), reproducible builds, an installer, and updates.
- The legacy OpenSSL algorithms are unavailable. If a future dependency
  needs one, ship the matching `legacy` module inside the release, never
  the host's.
- The daemon CLI does not exist yet. It will be packaged the same way:
  the OTP application list, launcher and `-eval` entry point change, the
  assembly steps do not. If it adds a dependency that starts another OTP
  application, the first scrubbed run fails with a missing `<app>.app`
  error, as `ssl` did here.
- Revisit if OTP ships a relocatable release tool that handles the NIF
  library rewrite, or if the release grows large enough that dropping `ssl`
  (by configuring mist without it) is worth the effort; that would save
  about 7 MB.

## Addendum (2026-11-01): the daemon release, install, and build identity

### One tree, two programs

The release is now `build/release/<platform>/reedwire/`, and it carries
the daemon beside the mailbox: `bin/reedwire` (the CLI and `reedwire
daemon`) and `bin/mailbox`, over one ERTS, one bundled libcrypto and one
`reedwire-tor`. `scripts/release.sh` exports both Gleam shipments and
merges them into one `lib/`; it fails the build if the two resolved any
package to different versions, and if the two packages' `gleam.toml`
versions differ. The assembly steps of the original decision are
unchanged and now run once, as shared functions.

One tree rather than one per program, because nearly all the weight is
shared: of 47 MB, the ERTS (5 MB), the OTP libraries, libcrypto and the
16 MB sidecar serve both. What only the mailbox needs is about 7 MB (mist
and its packages, and `ssl`, `public_key` and `asn1`, which mist starts),
and what only the daemon needs is about 0.5 MB. The versions already
have to agree, since the daemon's tests run a real mailbox in one VM, and
one tree is one OpenSSL to audit and replace. The cost is that a host
that runs only one program carries the other's code, unused. Revisit if
the mailbox becomes a separately versioned service.

Layout additions:

```
reedwire/
  BUILD                  version=, commit=, platform= (what install.sh and the smoke test read)
  install.sh             the installer, so an unpacked tarball installs itself
  bin/reedwire           launcher for the daemon package's `reedwire` module
  bin/mailbox            launcher for the mailbox
  bin/no_dot_erlang.boot replaces start_clean.boot
```

### Launcher changes

- **One boot, not two.** The OpenSSL floor is checked inside the
  program's own VM, as the first expression of its `-eval`, instead of in
  a separate VM before it. `reedwire --version` takes 0.10 s from exec to
  exit, where the old launcher spent 0.15 to 0.2 s on the check alone. A
  crypto library that fails to load is refused with exit 78 and one
  line, where it used to crash the boot. Checked by raising the floor to
  3.7 (`bundled crypto is OpenSSL 3.6.3 ...; OpenSSL >= 3.5 is required`,
  exit 78) and by moving the bundled dylib away (`the bundled crypto
  library did not load`, exit 78, no crash dump).
- **`no_dot_erlang.boot`.** `start_clean` runs the user's `~/.erlang`. A
  CLI whose standard output can be a raw payload must not run code it did
  not ship.
- **Host Erlang and loader variables removed.** `ERL_LIBS` would put
  foreign code ahead of the release's on the code path; `ERL_FLAGS`,
  `ERL_AFLAGS` and `ERL_ZFLAGS` add emulator arguments. `DYLD_LIBRARY_PATH`
  (and on Linux `LD_LIBRARY_PATH`) is searched by leaf name before the
  NIF's `@loader_path` (or `$ORIGIN`) reference: with it pointing at
  Homebrew's OpenSSL, `lsof` showed the host's libcrypto mapped instead of
  the bundled one, and the floor check accepts any foreign 3.5 or newer.
  The launcher unsets these and `DYLD_INSERT_LIBRARIES` and `LD_PRELOAD`.
  `release.sh` also applies the launchers' floor check at build time, so a
  host whose OTP links an older OpenSSL fails the build.
- **No crash dumps by default.** A dump is every process heap, keys and
  credentials included, written to the working directory. The launcher
  sets `ERL_CRASH_DUMP_SECONDS=0` unless the operator set it.
- **`-noinput`** for both programs, so `reedwire send --stdin`, which
  reads `/dev/stdin` directly, is the only reader of standard input.

### Build identity

The version is the packages' `gleam.toml` version. The commit is
`scripts/build-commit.sh`: `git rev-parse HEAD`, with `-dirty` appended
when a tracked file differs from it (untracked files are not build
inputs), or `unknown` outside a git tree. `release.sh` writes both into
each launcher, which exports them as `REEDWIRE_BUILD_VERSION` and
`REEDWIRE_BUILD_COMMIT`, and into `BUILD`. They are baked in rather than
read at run time because a release runs on machines with no checkout.
`daemon/build` and `mailbox/build` read them back (two small copies,
since the packages share nothing but the pure `core`, which reads no
environment); `reedwire --version` prints `reedwire 0.1.0 (commit <sha>)`,
`mailbox --version` the same with `mailbox`, and `health` gains `version`
and `commit` fields. A build run from source reports `dev` and `unknown`.

### Install layout (`make install`, `scripts/install.sh`)

```
$PREFIX/bin/reedwire          -> ../lib/reedwire/current/bin/reedwire
$PREFIX/bin/reedwire-mailbox  -> ../lib/reedwire/current/bin/mailbox
$PREFIX/lib/reedwire/current  -> 0.1.0-<commit12>[-dirty]-darwin-arm64
$PREFIX/lib/reedwire/0.1.0-<commit12>[-dirty]-darwin-arm64/   the release tree
$PREFIX/lib/reedwire/.reedwire-install                        ownership marker
```

`PREFIX` defaults to `$HOME/.local`. The commands are relative symlinks:
the launchers resolve their own links to find the tree, so no wrapper is
generated and nothing records the prefix. The tree is copied under a
staging name and renamed into place, and `current` is switched by a
rename. A tree a running process uses (its physical path is on the VM's
command line) is never replaced or pruned, and `uninstall` refuses while
one runs; `$PREFIX/lib` is compared by its physical path, since a VM
names its tree that way. The script refuses to replace a `bin/` entry that is not
exactly its own link, or a `lib/reedwire` without its marker, and checks
both before changing anything. Reinstalling a clean commit keeps its
tree (a `-dirty` or `unknown` one is recopied when its files differ): a
rebuild is not byte-identical (the sqlite NIF is re-linked, and
the bundled liblzma is whatever Homebrew has that day; it changed between
two builds minutes apart while this was written). State directories and
mailbox databases are never under the prefix and never touched.

`make dist` writes `dist/reedwire-<version>-<platform>.tar.gz` (25 MB,
688 entries) and a `.sha256` beside it; the archive unpacks into one
directory of that name, whose `install.sh` installs it.

### Evidence (macOS arm64, OTP 29.0.5, OpenSSL 3.6.3)

`make release release-smoke` builds the tree in about 22 s with the
sidecar already built, then runs `scripts/release-smoke.sh`: everything
under `env -i PATH=/usr/bin:/bin`, the tree free of `parrot`,
`gleam_httpc` and `inets`, both `--version`s equal to `BUILD`, the sidecar
started and stopped, an ML-KEM-1024 round trip in the bundled VM, a
mailbox granted and served on loopback, two `reedwire daemon --carrier
loopback`, `health` reporting the identity, invite, accept and approve,
one payload sent from stdin and received byte for byte, and all three VMs
stopped by SIGTERM, with no process left that names the run's directory.
It takes 3 to 4 s, bounded by `SMOKE_TIMEOUT` (180 s). The same script
passed with `--installed <scratch prefix>` against the launchers
`make install` put there, and with `--release` against an unpacked
`make dist` tarball installed by its own `install.sh`. `scripts/demo.sh
--carrier=loopback --release <tree>` passed every check, sandbox probes
included, in 15 s. `make uninstall` left the prefix empty.

Size: 47 MB in 614 files (`bin/` 16 MB, `lib/` 25 MB, ERTS 5 MB); the
original mailbox-only tree was 46 MB.

### Linux

`release.sh` now has a Linux branch, selected by `uname`, that follows the
recipe above: `ldd` for dependencies, the bundled `libcrypto.so.3` beside
`crypto.so` with `patchelf --set-rpath '$ORIGIN'`, non-system sidecar
libraries in `bin/lib` with `$ORIGIN/lib`, `/proc/<pid>/maps` for the
one-libcrypto proof, and a leak check that treats only `/lib`, `/lib64`,
`/usr/lib` and `/usr/lib64` (never OpenSSL) as system. **It has never run.**
The script says so on every Linux build and needs `patchelf`. The first
Linux build must pass `make release-smoke` before anything from it is
trusted; the glibc floor of `beam.smp` and the sidecar is still unchecked.
`install.sh` and `release-smoke.sh` use POSIX tools plus `mv -T` or
`mv -h`, whichever the platform's `mv` accepts, and are expected to work
there unchanged; that is also unverified.
