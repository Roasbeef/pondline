import daemon/build.{Identity}
import daemon/cli
import gleam/option.{None}

pub fn a_release_reports_what_its_launcher_exported_test() {
  let lookup = fn(name) {
    case name {
      "REEDWIRE_BUILD_VERSION" -> Ok("0.1.0")
      "REEDWIRE_BUILD_COMMIT" -> Ok("15b927e")
      _ -> Error(Nil)
    }
  }

  assert build.from_lookup(lookup) == Identity("0.1.0", "15b927e")
  assert build.describe(build.from_lookup(lookup))
    == "reedwire 0.1.0 (commit 15b927e)"
}

pub fn a_build_from_source_says_dev_and_unknown_test() {
  assert build.from_lookup(fn(_) { Error(Nil) })
    == Identity(build.dev_version, build.unknown_commit)

  // A launcher that exported an empty field reports the default, never a
  // blank identity.
  assert build.from_lookup(fn(_) { Ok("") })
    == Identity(build.dev_version, build.unknown_commit)
}

pub fn version_is_a_command_of_its_own_test() {
  assert cli.parse(["--version"], None) == Ok(cli.Version)
  assert cli.parse(["version"], None) == Ok(cli.Version)
  assert cli.parse(["--version", "--json"], None) == Error("unknown command")
}
