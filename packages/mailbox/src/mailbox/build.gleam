//// Which build of the mailbox is running: its version and source commit.
////
//// A release is unpacked on machines with no git and no checkout, so the
//// identity cannot be discovered at run time. `scripts/release.sh` writes
//// both values into the release's launcher, which exports them as
//// `PONDLINE_BUILD_VERSION` and `PONDLINE_BUILD_COMMIT` before the VM
//// starts; this module reads them back. A build run from source
//// (`gleam run -m mailbox`) has neither variable and says so, as `dev` and
//// `unknown`, rather than guessing.
////
//// The identity is reported by `mailbox --version`. The daemon's copy,
//// `daemon/build`, is the same shape; the two packages share no module
//// that could hold it except `core`, and it stays out of `core`,
//// which reads no environment.

import mailbox/internal/ffi_system

/// The version reported by a build that was not made by the release script.
pub const dev_version = "dev"

/// The commit reported when the build does not know its own.
pub const unknown_commit = "unknown"

/// A build's identity.
pub type Identity {
  Identity(
    /// The package version from `gleam.toml`, or `dev`.
    version: String,
    /// The full git commit the release was built from, with `-dirty` when
    /// the tree had uncommitted changes, or `unknown`.
    commit: String,
  )
}

/// The identity of the running build, read from the environment the
/// release launcher set.
///
/// ## Examples
///
/// ```gleam
/// build.current()
/// // -> Identity("0.1.0", "15b927e...")   under a release launcher
/// // -> Identity("dev", "unknown")         under `gleam run`
/// ```
pub fn current() -> Identity {
  from_lookup(ffi_system.getenv)
}

/// The identity found through `lookup`, which answers an environment
/// variable's value. An absent or empty variable gives the default.
///
/// ## Examples
///
/// ```gleam
/// build.from_lookup(fn(_) { Error(Nil) })
/// // -> Identity("dev", "unknown")
/// ```
pub fn from_lookup(lookup: fn(String) -> Result(String, Nil)) -> Identity {
  Identity(
    version: read(lookup, "PONDLINE_BUILD_VERSION", dev_version),
    commit: read(lookup, "PONDLINE_BUILD_COMMIT", unknown_commit),
  )
}

/// One variable's value, or `default` when it is absent or empty. An empty
/// value is treated as absent so that a launcher which exported a blank
/// field never reports a blank identity.
fn read(
  lookup: fn(String) -> Result(String, Nil),
  name: String,
  default: String,
) -> String {
  case lookup(name) {
    Ok("") | Error(Nil) -> default
    Ok(value) -> value
  }
}

/// The one line `mailbox --version` prints.
///
/// ## Examples
///
/// ```gleam
/// build.describe(Identity("0.1.0", "15b927e"))
/// // -> "mailbox 0.1.0 (commit 15b927e)"
/// ```
pub fn describe(identity: Identity) -> String {
  "mailbox " <> identity.version <> " (commit " <> identity.commit <> ")"
}
