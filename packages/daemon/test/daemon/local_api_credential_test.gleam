import core/secret
import daemon/credential.{Agent, Operator}
import daemon/internal/ffi_local_system
import daemon/local_api_fixture as fixture
import gleam/bit_array
import gleam/result
import gleam/string
import simplifile

fn with_dir(body: fn(String) -> Nil) -> Nil {
  let dir = fixture.scratch_dir()
  body(dir)
  let _ = simplifile.delete(dir)
  Nil
}

pub fn ensure_creates_private_distinct_files_test() {
  use dir <- with_dir

  let assert Ok(credentials) = credential.ensure(dir)

  assert ffi_local_system.file_mode(dir) == Ok(0o700)
  assert ffi_local_system.file_mode(dir <> "/operator.cred") == Ok(0o600)
  assert ffi_local_system.file_mode(dir <> "/agent.cred") == Ok(0o600)

  assert secret.byte_size(credentials.operator) == credential.credential_bytes
  assert secret.byte_size(credentials.agent) == credential.credential_bytes
  assert credentials.operator != credentials.agent
}

pub fn ensure_keeps_existing_credentials_test() {
  use dir <- with_dir

  let assert Ok(first) = credential.ensure(dir)
  let assert Ok(second) = credential.ensure(dir)

  assert first == second
}

pub fn ensure_never_overwrites_an_existing_file_test() {
  use dir <- with_dir

  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let mine = <<7:256>>
  let assert Ok(Nil) = simplifile.write_bits(dir <> "/agent.cred", mine)

  let assert Ok(credentials) = credential.ensure(dir)

  assert secret.expose(credentials.agent) == mine
  assert simplifile.read_bits(dir <> "/agent.cred") == Ok(mine)
}

pub fn the_exclusive_create_refuses_a_second_writer_test() {
  use dir <- with_dir

  let assert Ok(Nil) = ffi_local_system.make_private_dir(dir)
  let path = dir <> "/once"

  assert ffi_local_system.create_private_file(path, <<1>>) == Ok(Nil)
  assert ffi_local_system.create_private_file(path, <<2>>) == Error("eexist")
  assert simplifile.read_bits(path) == Ok(<<1>>)
}

pub fn a_wrong_length_file_is_an_error_that_does_not_echo_it_test() {
  use dir <- with_dir

  let assert Ok(Nil) = simplifile.create_directory_all(dir)
  let assert Ok(Nil) = simplifile.write(dir <> "/operator.cred", "SECRETSECRET")

  let assert Error(message) = credential.ensure(dir)

  assert !string.contains(message, "SECRETSECRET")
  assert string.contains(message, "operator.cred")
}

pub fn credentials_do_not_print_test() {
  use dir <- with_dir

  let assert Ok(credentials) = credential.ensure(dir)
  let assert Ok(bytes) = simplifile.read_bits(dir <> "/operator.cred")
  let shown = string.inspect(credentials)

  assert !string.contains(shown, bit_array.base64_encode(bytes, True))
  assert !string.contains(shown, bit_array.base16_encode(bytes))
}

pub fn authenticate_names_the_scope_test() {
  use dir <- with_dir

  let assert Ok(credentials) = credential.ensure(dir)
  let operator = secret.expose(credentials.operator)
  let agent = secret.expose(credentials.agent)

  assert credential.authenticate(credentials, operator) == Ok(Operator)
  assert credential.authenticate(credentials, agent) == Ok(Agent)
  assert credential.authenticate(credentials, <<0:256>>) == Error(Nil)
  assert credential.authenticate(credentials, <<>>) == Error(Nil)

  // One byte short of a real credential is not a real credential.
  let assert Ok(short) = bit_array.slice(operator, 0, 31)
  assert credential.authenticate(credentials, short) == Error(Nil)
}

pub fn permits_gives_the_agent_only_agent_ops_test() {
  assert credential.permits(Operator, required: Operator)
  assert credential.permits(Operator, required: Agent)
  assert credential.permits(Agent, required: Agent)
  assert !credential.permits(Agent, required: Operator)
}

pub fn read_rejects_a_missing_file_test() {
  let result = credential.read("/nonexistent/path/agent.cred")

  assert result.is_error(result)
}
