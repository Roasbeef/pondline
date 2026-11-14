//// User-level background service installation for `pondline daemon`.
////
//// On macOS (`launchd`) and Linux (`systemd --user`), operators should not
//// have to background `pondline daemon &` by hand or edit home-directory paths
//// in XML/INI unit templates. This module renders the per-user service
//// definition from a resolved `pondline` executable path and absolute state
//// directory, writes it into the user's service directory (`0600`), and drives
//// `launchctl` or `systemctl --user` through `spawn_executable` with no shell
//// expansion.
////
//// ## Invariants
////
//// 1. **Initialized state directory required.** `install` callers validate
////    `<state_dir>/config.json` and `<state_dir>/provision.cap` before calling
////    `install`, so a missing `pondline init` is refused upfront instead of
////    installing a service that crash-loops.
//// 2. **Socket-path ceiling enforced.** Both `<state_dir>/api.sock` and Arti's
////    `<state_dir>/tor/connect.sock` are `AF_UNIX` paths bounded near 100
////    bytes on macOS and 108 bytes on Linux; `check_socket_length` refuses an
////    overlong state directory before writing a unit file.
//// 3. **No shell expansion, no secrets.** Unit files carry only the `pondline`
////    executable path, `daemon --state-dir <abs_dir>`, and log file paths;
////    `launchctl` and `systemctl` receive explicit argument lists.
//// 4. **Uninstall preserves state.** `uninstall` stops the service and removes
////    only the unit file, never `<state_dir>`.

import daemon/internal/ffi_local_system
import daemon/lock
import daemon/node
import gleam/int
import gleam/json
import gleam/list
import gleam/result
import gleam/string
import simplifile

/// The `launchd` job label for the user daemon on macOS.
pub const launchd_label = "io.pondline.daemon"

/// The `systemd --user` unit file name on Linux.
pub const systemd_unit_name = "pondline.service"

/// Maximum byte length of `<abs_state_dir>/tor/connect.sock` accepted so
/// `AF_UNIX` binds succeed on both macOS (104 bytes) and Linux (108 bytes).
pub const max_unix_socket_bytes = 100

/// Timeout in milliseconds for one `launchctl` or `systemctl` invocation.
const manager_timeout_ms = 15_000

/// Supported user-service platforms.
pub type Platform {
  /// macOS `launchd` (`~/Library/LaunchAgents/io.pondline.daemon.plist`).
  MacOs

  /// Linux `systemd --user` (`~/.config/systemd/user/pondline.service`).
  Linux
}

/// Whether the user unit file exists on disk.
pub type UnitPresence {
  Installed
  NotInstalled
}

/// Whether `<state_dir>/lock.db` is currently held by a live daemon process.
pub type RuntimeState {
  DaemonRunning
  DaemonStopped
}

/// Snapshot returned by `install`, `uninstall`, and `status`.
pub type Report {
  Report(
    platform: Platform,
    unit_path: String,
    state_dir: String,
    unit: UnitPresence,
    runtime: RuntimeState,
  )
}

/// Injectable operating-system boundary so unit tests exercise `install`,
/// `status`, and `uninstall` across both platforms without calling the host's
/// real `launchctl` or `systemctl`.
pub type Effects {
  Effects(
    platform: fn() -> Result(Platform, String),
    home_dir: fn() -> Result(String, String),
    pondline_bin: fn(String) -> Result(String, String),
    absolute_path: fn(String) -> String,
    uid: fn() -> Result(Int, String),
    make_dir: fn(String) -> Result(Nil, String),
    write_unit: fn(String, String) -> Result(Nil, String),
    delete_file: fn(String) -> Result(Nil, String),
    unit_presence: fn(String) -> UnitPresence,
    is_locked: fn(String) -> RuntimeState,
    exec: fn(String, List(String)) -> Result(#(Int, String), String),
  )
}

/// Production operating-system effects backed by `ffi_local_system` and `simplifile`.
///
/// ## Examples
///
/// ```gleam
/// let _fx = service.default_effects()
/// ```
pub fn default_effects() -> Effects {
  Effects(
    platform: detect_platform,
    home_dir: resolve_home_dir,
    pondline_bin: resolve_pondline_bin,
    absolute_path: ffi_local_system.absolute_path,
    uid: ffi_local_system.current_uid,
    make_dir: fn(dir) {
      simplifile.create_directory_all(dir)
      |> result.map_error(simplifile.describe_error)
    },
    write_unit: fn(path, contents) {
      ffi_local_system.write_private_file(path, <<contents:utf8>>)
    },
    delete_file: delete_if_exists,
    unit_presence: fn(path) {
      case simplifile.is_file(path) {
        Ok(True) -> Installed
        _ -> NotInstalled
      }
    },
    is_locked: probe_lock,
    exec: run_manager,
  )
}

/// Path to the user service file on `platform` under `home`.
///
/// ## Examples
///
/// ```gleam
/// service.unit_path(service.MacOs, "/Users/alice")
/// // -> "/Users/alice/Library/LaunchAgents/io.pondline.daemon.plist"
/// ```
pub fn unit_path(platform: Platform, home: String) -> String {
  case platform {
    MacOs -> home <> "/Library/LaunchAgents/" <> launchd_label <> ".plist"
    Linux -> home <> "/.config/systemd/user/" <> systemd_unit_name
  }
}

/// Directory holding `unit_path(platform, home)`.
fn unit_dir(platform: Platform, home: String) -> String {
  case platform {
    MacOs -> home <> "/Library/LaunchAgents"
    Linux -> home <> "/.config/systemd/user"
  }
}

/// Canonical wire name of a `Platform`.
///
/// ## Examples
///
/// ```gleam
/// service.platform_name(service.Linux)
/// // -> "systemd"
/// ```
pub fn platform_name(platform: Platform) -> String {
  case platform {
    MacOs -> "launchd"
    Linux -> "systemd"
  }
}

/// Renders the macOS `launchd` property list for `binary_path` and `state_dir`,
/// XML-escaping every dynamic path segment.
///
/// ## Examples
///
/// ```gleam
/// string.contains(
///   service.render_launchd_plist("/Users/a/.local/bin/pondline", "/Users/a/.pondline"),
///   "<string>io.pondline.daemon</string>",
/// )
/// // -> True
/// ```
pub fn render_launchd_plist(binary_path: String, state_dir: String) -> String {
  let bin = xml_escape(binary_path)
  let dir = xml_escape(state_dir)
  let out_log = xml_escape(state_dir <> "/daemon.out.log")
  let err_log = xml_escape(state_dir <> "/daemon.log")

  string.join(
    [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
      "<plist version=\"1.0\">",
      "<dict>",
      "  <key>Label</key>",
      "  <string>" <> launchd_label <> "</string>",
      "  <key>ProgramArguments</key>",
      "  <array>",
      "    <string>" <> bin <> "</string>",
      "    <string>daemon</string>",
      "    <string>--state-dir</string>",
      "    <string>" <> dir <> "</string>",
      "  </array>",
      "  <key>EnvironmentVariables</key>",
      "  <dict>",
      "    <key>PONDLINE_LOG_LEVEL</key>",
      "    <string>info</string>",
      "  </dict>",
      "  <key>RunAtLoad</key>",
      "  <true/>",
      "  <key>KeepAlive</key>",
      "  <true/>",
      "  <key>SoftResourceLimits</key>",
      "  <dict>",
      "    <key>NumberOfFiles</key>",
      "    <integer>16384</integer>",
      "  </dict>",
      "  <key>StandardOutPath</key>",
      "  <string>" <> out_log <> "</string>",
      "  <key>StandardErrorPath</key>",
      "  <string>" <> err_log <> "</string>",
      "</dict>",
      "</plist>",
      "",
    ],
    "\n",
  )
}

/// Renders the Linux `systemd --user` unit file for `binary_path` and `state_dir`.
///
/// ## Examples
///
/// ```gleam
/// string.contains(
///   service.render_systemd_unit("/home/a/.local/bin/pondline", "/home/a/.pondline"),
///   "ExecStart=",
/// )
/// // -> True
/// ```
pub fn render_systemd_unit(binary_path: String, state_dir: String) -> String {
  let exec_line =
    systemd_quote(binary_path)
    <> " daemon --state-dir "
    <> systemd_quote(state_dir)

  string.join(
    [
      "[Unit]",
      "Description=Pondline client daemon (user service)",
      "Documentation=https://github.com/Roasbeef/pondline",
      "After=network-online.target",
      "Wants=network-online.target",
      "",
      "[Service]",
      "Type=simple",
      "Environment=PONDLINE_LOG_LEVEL=info",
      "ExecStart=" <> exec_line,
      "Restart=on-failure",
      "RestartSec=5",
      "LimitNOFILE=65536",
      "NoNewPrivileges=yes",
      "UMask=0077",
      "",
      "[Install]",
      "WantedBy=default.target",
      "",
    ],
    "\n",
  )
}

/// Installs and starts the user background service for `state_dir`.
///
/// ## Examples
///
/// ```gleam
/// // Refuses an overlong socket path before writing any unit file.
/// ```
pub fn install(fx: Effects, state_dir: String) -> Result(Report, String) {
  use platform <- result.try(fx.platform())
  use home <- result.try(fx.home_dir())
  let abs_dir = fx.absolute_path(state_dir)
  use Nil <- result.try(check_socket_length(abs_dir))
  use bin <- result.try(fx.pondline_bin(home))
  use Nil <- result.try(fx.make_dir(unit_dir(platform, home)))

  let path = unit_path(platform, home)

  // Render the platform-specific user service definition.
  let body = case platform {
    MacOs -> render_launchd_plist(bin, abs_dir)
    Linux -> render_systemd_unit(bin, abs_dir)
  }

  use Nil <- result.try(fx.write_unit(path, body))
  use Nil <- result.map(activate_unit(fx, platform, path))

  Report(
    platform:,
    unit_path: path,
    state_dir: abs_dir,
    unit: Installed,
    runtime: fx.is_locked(abs_dir),
  )
}

/// Stops and removes the user background service, leaving `state_dir` intact.
///
/// ## Examples
///
/// ```gleam
/// // Succeeds idempotently even when the unit file was already absent.
/// ```
pub fn uninstall(fx: Effects, state_dir: String) -> Result(Report, String) {
  use platform <- result.try(fx.platform())
  use home <- result.try(fx.home_dir())
  let abs_dir = fx.absolute_path(state_dir)
  let path = unit_path(platform, home)

  // Stop the loaded service if present, then remove the unit file.
  let _ = deactivate_unit(fx, platform, path)
  use Nil <- result.map(fx.delete_file(path))

  Report(
    platform:,
    unit_path: path,
    state_dir: abs_dir,
    unit: NotInstalled,
    runtime: fx.is_locked(abs_dir),
  )
}

/// Inspects whether the user service unit is installed and whether `state_dir` is running.
///
/// ## Examples
///
/// ```gleam
/// // Reports `Installed` or `NotInstalled` alongside `DaemonRunning` or `DaemonStopped`.
/// ```
pub fn status(fx: Effects, state_dir: String) -> Result(Report, String) {
  use platform <- result.try(fx.platform())
  use home <- result.map(fx.home_dir())
  let abs_dir = fx.absolute_path(state_dir)
  let path = unit_path(platform, home)

  let unit = fx.unit_presence(path)

  Report(
    platform:,
    unit_path: path,
    state_dir: abs_dir,
    unit:,
    runtime: fx.is_locked(abs_dir),
  )
}

/// Renders a `Report` as human-readable `key=value` lines.
///
/// ## Examples
///
/// ```gleam
/// service.format_human(report)
/// ```
pub fn format_human(report: Report) -> String {
  string.join(
    [
      "manager=" <> platform_name(report.platform),
      "unit=" <> unit_state_name(report.unit),
      "daemon=" <> runtime_state_name(report.runtime),
      "unit_path=" <> report.unit_path,
      "state_dir=" <> report.state_dir,
    ],
    "\n",
  )
  <> "\n"
}

/// Renders a `Report` as a `{"ok":true,"result":{...}}` JSON line.
///
/// ## Examples
///
/// ```gleam
/// service.format_json(report)
/// ```
pub fn format_json(report: Report) -> String {
  json.object([
    #("ok", json.bool(True)),
    #(
      "result",
      json.object([
        #("manager", json.string(platform_name(report.platform))),
        #("unit", json.string(unit_state_name(report.unit))),
        #("daemon", json.string(runtime_state_name(report.runtime))),
        #("unit_path", json.string(report.unit_path)),
        #("state_dir", json.string(report.state_dir)),
      ]),
    ),
  ])
  |> json.to_string
  |> string.append("\n")
}

/// Checks that Arti's `tor/connect.sock` under `abs_dir` fits `AF_UNIX`.
fn check_socket_length(abs_dir: String) -> Result(Nil, String) {
  let deepest_socket = abs_dir <> "/tor/connect.sock"

  // Refuse paths carrying control characters or exceeding `max_unix_socket_bytes`.
  case
    string.contains(abs_dir, "\n") || string.contains(abs_dir, "\r"),
    string.byte_size(deepest_socket) > max_unix_socket_bytes
  {
    True, _ -> Error("--state-dir must not contain newline characters")
    False, True ->
      Error(
        "state directory path is too long for Unix domain sockets ("
        <> int.to_string(string.byte_size(deepest_socket))
        <> " > "
        <> int.to_string(max_unix_socket_bytes)
        <> " bytes); choose a shorter --state-dir",
      )
    False, False -> Ok(Nil)
  }
}

/// Reloads and starts the newly written service file.
fn activate_unit(
  fx: Effects,
  platform: Platform,
  path: String,
) -> Result(Nil, String) {
  case platform {
    MacOs -> activate_launchd(fx, path)
    Linux -> activate_systemd(fx)
  }
}

/// Loads `path` into the user's `gui/<uid>` `launchd` domain, falling back to
/// `launchctl load -w` on headless SSH sessions that have no GUI domain.
fn activate_launchd(fx: Effects, path: String) -> Result(Nil, String) {
  use uid <- result.try(fx.uid())
  let domain = "gui/" <> int.to_string(uid)
  let _ = fx.exec("launchctl", ["bootout", domain, path])

  // Prefer modern `bootstrap`; fall back to `load -w` when `gui/<uid>` is absent.
  case fx.exec("launchctl", ["bootstrap", domain, path]) {
    Ok(#(0, _)) -> {
      let _ =
        fx.exec("launchctl", ["kickstart", "-k", domain <> "/" <> launchd_label])
      Ok(Nil)
    }

    _ -> {
      let _ = fx.exec("launchctl", ["unload", path])
      require_zero(fx.exec("launchctl", ["load", "-w", path]), "launchctl load")
    }
  }
}

/// Reloads `systemd --user` and enables + starts `pondline.service`.
fn activate_systemd(fx: Effects) -> Result(Nil, String) {
  use Nil <- result.try(require_zero(
    fx.exec("systemctl", ["--user", "daemon-reload"]),
    "systemctl --user daemon-reload",
  ))

  require_zero(
    fx.exec("systemctl", ["--user", "enable", "--now", systemd_unit_name]),
    "systemctl --user enable --now " <> systemd_unit_name,
  )
}

/// Stops and unloads the user service on `uninstall`.
fn deactivate_unit(
  fx: Effects,
  platform: Platform,
  path: String,
) -> Result(Nil, String) {
  // Unload the active service manager entry for this platform.
  case platform {
    MacOs -> {
      use uid <- result.map(fx.uid())
      let domain = "gui/" <> int.to_string(uid)
      let _ = fx.exec("launchctl", ["bootout", domain, path])
      let _ = fx.exec("launchctl", ["unload", path])
      Nil
    }

    Linux -> {
      let _ =
        fx.exec("systemctl", ["--user", "disable", "--now", systemd_unit_name])
      let _ = fx.exec("systemctl", ["--user", "daemon-reload"])
      Ok(Nil)
    }
  }
}

/// Requires exit code 0 from a service manager command.
fn require_zero(
  ran: Result(#(Int, String), String),
  label: String,
) -> Result(Nil, String) {
  case ran {
    Ok(#(0, _)) -> Ok(Nil)
    Ok(#(code, output)) ->
      Error(
        label
        <> " exited with status "
        <> int.to_string(code)
        <> format_manager_detail(output),
      )
    Error(reason) -> Error(label <> " failed: " <> reason)
  }
}

/// Formats trimmed command output when non-empty.
fn format_manager_detail(output: String) -> String {
  case string.trim(output) {
    "" -> ""
    detail -> ": " <> detail
  }
}

/// Detects `MacOs` or `Linux` from `ffi_local_system.host_os()`.
fn detect_platform() -> Result(Platform, String) {
  case ffi_local_system.host_os() {
    Ok("darwin") -> Ok(MacOs)
    Ok("linux") -> Ok(Linux)
    Ok(other) -> Error("pondline service is unsupported on " <> other)
    Error(Nil) -> Error("could not determine operating system")
  }
}

/// Reads `$HOME` for locating user service directories.
fn resolve_home_dir() -> Result(String, String) {
  case ffi_local_system.getenv("HOME") {
    Ok("") | Error(Nil) -> Error("HOME is not set")
    Ok(home) -> Ok(home)
  }
}

/// Locates the installed `pondline` launcher, checking `$HOME/.local/bin/pondline`
/// first and then `PATH` so `service install` works even before `$HOME/.local/bin`
/// is exported in the user's login profile.
fn resolve_pondline_bin(home: String) -> Result(String, String) {
  let default_bin = home <> "/.local/bin/pondline"

  // Prefer `~/.local/bin/pondline` when present, falling back to `PATH`.
  case
    simplifile.is_file(default_bin),
    ffi_local_system.find_executable("pondline")
  {
    Ok(True), _ -> Ok(default_bin)
    _, Ok(path) -> Ok(path)
    _, Error(Nil) ->
      Error(
        "could not locate an installed pondline binary; install Pondline into ~/.local/bin or add pondline to PATH first",
      )
  }
}

/// Deletes `path` if present, treating `Enoent` as success.
fn delete_if_exists(path: String) -> Result(Nil, String) {
  case simplifile.delete(path) {
    Ok(Nil) | Error(simplifile.Enoent) -> Ok(Nil)
    Error(err) ->
      Error(
        "could not remove " <> path <> ": " <> simplifile.describe_error(err),
      )
  }
}

/// Checks whether `<state_dir>/lock.db` is currently held by a live daemon.
fn probe_lock(state_dir: String) -> RuntimeState {
  let lock_path = state_dir <> "/" <> node.lock_file

  // An absent or free lock means no daemon currently holds `state_dir`.
  case simplifile.is_file(lock_path) {
    Ok(True) ->
      case lock.is_free(lock_path) {
        True -> DaemonStopped
        False -> DaemonRunning
      }
    _ -> DaemonStopped
  }
}

/// Resolves `name` on `PATH` (with standard system fallbacks) and runs it via `spawn_executable`.
fn run_manager(
  name: String,
  args: List(String),
) -> Result(#(Int, String), String) {
  use executable <- result.try(resolve_system_tool(name))
  ffi_local_system.run_program(executable, args, manager_timeout_ms)
}

/// Finds `launchctl` or `systemctl` on `PATH` or standard OS paths.
fn resolve_system_tool(name: String) -> Result(String, String) {
  // Check PATH first before falling back to standard system binary directories.
  case ffi_local_system.find_executable(name) {
    Ok(path) -> Ok(path)
    Error(Nil) -> {
      let fallbacks = ["/bin/" <> name, "/usr/bin/" <> name]
      list.find(fallbacks, fn(candidate) {
        simplifile.is_file(candidate) == Ok(True)
      })
      |> result.map_error(fn(_) { name <> " was not found on PATH" })
    }
  }
}

/// Wire string for `UnitPresence`.
fn unit_state_name(unit: UnitPresence) -> String {
  case unit {
    Installed -> "installed"
    NotInstalled -> "not_installed"
  }
}

/// Wire string for `RuntimeState`.
fn runtime_state_name(runtime: RuntimeState) -> String {
  case runtime {
    DaemonRunning -> "running"
    DaemonStopped -> "stopped"
  }
}

/// Escapes XML special characters in `launchd` plist string elements.
fn xml_escape(text: String) -> String {
  text
  |> string.replace("&", "&amp;")
  |> string.replace("<", "&lt;")
  |> string.replace(">", "&gt;")
  |> string.replace("\"", "&quot;")
  |> string.replace("'", "&apos;")
}

/// Quotes one argument for a `systemd` `ExecStart=` line, escaping `\` and `"`
/// and `%` (`%%` prevents `systemd` specifier expansion inside user paths).
fn systemd_quote(arg: String) -> String {
  let escaped =
    arg
    |> string.replace("\\", "\\\\")
    |> string.replace("\"", "\\\"")
    |> string.replace("%", "%%")
  "\"" <> escaped <> "\""
}
