//// Tests for `pondline service install|uninstall|status` across macOS
//// `launchd` and Linux `systemd --user` without touching host services.

import core/endpoint
import core/grant
import core/secret
import daemon/cli.{
  Environment, HumanOutput, InstallService, JsonOutput, ManageService,
  ServiceCommand, ServiceStatus, UninstallService,
}
import daemon/cli_run
import daemon/service
import daemon/support
import gleam/bit_array
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/otp/actor
import gleam/string
import simplifile

type Recorded {
  Recorded(calls: List(#(String, List(String))))
}

type RecorderMsg {
  Push(name: String, args: List(String))
  Read(reply_with: process.Subject(List(#(String, List(String)))))
}

fn start_recorder() -> process.Subject(RecorderMsg) {
  let assert Ok(started) =
    actor.new(Recorded(calls: []))
    |> actor.on_message(fn(state, msg) {
      case msg {
        Push(name:, args:) ->
          actor.continue(Recorded(calls: [#(name, args), ..state.calls]))
        Read(reply_with:) -> {
          process.send(reply_with, list.reverse(state.calls))
          actor.continue(state)
        }
      }
    })
    |> actor.start
  started.data
}

fn fake_effects(
  platform: service.Platform,
  home: String,
  recorder: process.Subject(RecorderMsg),
) -> service.Effects {
  service.Effects(
    platform: fn() { Ok(platform) },
    home_dir: fn() { Ok(home) },
    pondline_bin: fn(h) { Ok(h <> "/.local/bin/pondline") },
    absolute_path: fn(p) {
      case string.starts_with(p, "/aaaa") {
        True -> p
        False -> "/Users/test/.pondline"
      }
    },
    uid: fn() { Ok(501) },
    make_dir: fn(dir) {
      case simplifile.create_directory_all(dir) {
        Ok(Nil) -> Ok(Nil)
        Error(e) -> Error(simplifile.describe_error(e))
      }
    },
    write_unit: fn(path, body) {
      case simplifile.write(path, body) {
        Ok(Nil) -> Ok(Nil)
        Error(e) -> Error(simplifile.describe_error(e))
      }
    },
    delete_file: fn(path) {
      case simplifile.delete(path) {
        Ok(Nil) | Error(simplifile.Enoent) -> Ok(Nil)
        Error(e) -> Error(simplifile.describe_error(e))
      }
    },
    unit_presence: fn(path) {
      case simplifile.is_file(path) {
        Ok(True) -> service.Installed
        _ -> service.NotInstalled
      }
    },
    is_locked: fn(_) { service.DaemonRunning },
    exec: fn(name, args) {
      process.send(recorder, Push(name, args))
      Ok(#(0, ""))
    },
  )
}

fn init_state_dir(dir: String) {
  let assert Ok(onion) =
    endpoint.parse_onion(
      "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
    )
  let assert Ok(port) = endpoint.port(80)
  let assert Ok(token) =
    grant.from_parts(endpoint.Onion(onion, port), <<1:256>>)
  let token_bits = secret.expose(grant.encode(token))
  let assert Ok(cli.InitDaemon(cmd)) =
    cli.parse(["init", "--state-dir", dir, "--stdin"], None)
  let file = dir <> ".grant"
  let assert Ok(Nil) = simplifile.write_bits(file, token_bits)
  let cmd_file =
    cli.InitCommand(..cmd, setup: cli.GrantMailbox(cli.InputFile(file)))
  let out = cli_run.run(cli.InitDaemon(cmd_file))
  assert out.status == cli.exit_ok
}

pub fn cli_parses_service_commands_with_default_state_dir_test() {
  let env =
    Environment(credential_file: None, default_state_dir: Some("/tmp/pl"))
  assert cli.parse_with_env(["service", "install"], env)
    == Ok(ManageService(ServiceCommand(InstallService, "/tmp/pl", HumanOutput)))
  assert cli.parse_with_env(["service", "status", "--json"], env)
    == Ok(ManageService(ServiceCommand(ServiceStatus, "/tmp/pl", JsonOutput)))
  assert cli.parse_with_env(
      ["service", "uninstall", "--state-dir", "/tmp/other"],
      env,
    )
    == Ok(
      ManageService(ServiceCommand(UninstallService, "/tmp/other", HumanOutput)),
    )
}

pub fn service_install_refuses_uninitialized_or_overlong_state_dir_test() {
  let home = support.fresh("svc_home")
  let uninit = support.fresh("svc_uninit")
  let recorder = start_recorder()
  let fx = fake_effects(service.MacOs, home, recorder)

  let refused =
    cli_run.run_service_with(
      fx,
      ServiceCommand(InstallService, uninit, HumanOutput),
    )
  assert refused.status == cli.exit_unavailable
  assert string.contains(refused.stderr, "pondline init")

  let overlong = "/" <> string.repeat("a", 95)
  assert result_is_err(service.install(fx, overlong))
}

fn result_is_err(res: Result(a, b)) -> Bool {
  case res {
    Ok(_) -> False
    Error(_) -> True
  }
}

pub fn launchd_and_systemd_lifecycle_and_escaping_test() {
  let plist =
    service.render_launchd_plist(
      "/Users/a&b/.local/bin/pondline",
      "/Users/a&b/.pondline",
    )
  assert string.contains(plist, "/Users/a&amp;b/.local/bin/pondline")

  let unit =
    service.render_systemd_unit(
      "/home/a%b/.local/bin/pondline",
      "/home/a%b/.pondline",
    )
  assert string.contains(
    unit,
    "ExecStart=\"/home/a%%b/.local/bin/pondline\" daemon --state-dir \"/home/a%%b/.pondline\"",
  )

  // macOS launchd install -> status -> uninstall
  let mac_home = support.fresh("svc_mac")
  let mac_state = support.fresh("svc_st_mac")
  init_state_dir(mac_state)
  let mac_rec = start_recorder()
  let mac_fx = fake_effects(service.MacOs, mac_home, mac_rec)

  let installed =
    cli_run.run_service_with(
      mac_fx,
      ServiceCommand(InstallService, mac_state, HumanOutput),
    )
  assert installed.status == cli.exit_ok
  let assert Ok(stdout) = bit_array.to_string(installed.stdout)
  assert string.contains(stdout, "manager=launchd")
  assert string.contains(stdout, "unit=installed")

  let status_out =
    cli_run.run_service_with(
      mac_fx,
      ServiceCommand(ServiceStatus, mac_state, JsonOutput),
    )
  assert status_out.status == cli.exit_ok
  let assert Ok(json_str) = bit_array.to_string(status_out.stdout)
  assert string.contains(json_str, "\"unit\":\"installed\"")

  let removed =
    cli_run.run_service_with(
      mac_fx,
      ServiceCommand(UninstallService, mac_state, HumanOutput),
    )
  assert removed.status == cli.exit_ok
  assert simplifile.is_file(mac_state <> "/config.json") == Ok(True)
  let _ = simplifile.delete_all([mac_state, mac_state <> ".grant"])

  // Linux systemd --user install -> uninstall
  let lin_home = support.fresh("svc_lin")
  let lin_state = support.fresh("svc_st_lin")
  init_state_dir(lin_state)
  let lin_rec = start_recorder()
  let lin_fx = fake_effects(service.Linux, lin_home, lin_rec)

  let lin_inst =
    cli_run.run_service_with(
      lin_fx,
      ServiceCommand(InstallService, lin_state, HumanOutput),
    )
  assert lin_inst.status == cli.exit_ok
  let calls = actor.call(lin_rec, 1000, Read)
  assert list.contains(calls, #("systemctl", ["--user", "daemon-reload"]))
  assert list.contains(
    calls,
    #("systemctl", ["--user", "enable", "--now", "pondline.service"]),
  )
  let _ =
    cli_run.run_service_with(
      lin_fx,
      ServiceCommand(UninstallService, lin_state, HumanOutput),
    )
  let _ = simplifile.delete_all([lin_state, lin_state <> ".grant"])
}
