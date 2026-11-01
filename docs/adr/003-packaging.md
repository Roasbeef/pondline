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
