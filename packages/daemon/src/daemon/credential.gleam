//// The two credentials that guard the local API (spec §9).
////
//// An agent adapter runs inside a sandbox and the operator runs outside it,
//// so the daemon recognizes two scopes. `Agent` may list contacts, send,
//// receive, acknowledge and read status and health. `Operator` may do all
//// of that and also invite, accept, approve, decline, close, raise a budget
//// and read the audit log. The split is what stops a compromised agent
//// from approving its own contact or reading the plaintext audit trail.
////
//// Each scope has one credential: 32 random bytes in a file in the state
//// directory, `operator.cred` and `agent.cred`, mode 0600. `ensure` creates
//// a missing file with an exclusive create and reads an existing one, so a
//// restart keeps the same credentials. The operator copies `agent.cred`
//// into the agent's sandbox and keeps the other.
////
//// ## Flow
////
//// 1. The daemon calls `ensure` on its state directory at start and hands
////    the result to the local API server.
//// 2. For each request the server calls `authenticate` with the presented
////    bytes and gets back a `Scope` or nothing.
//// 3. It then asks `permits` whether that scope may run the operation.
////
//// A credential is wrapped in `Secret` and never appears in an error
//// message; failures name a path or a POSIX reason only.

import core/secret.{type Secret}
import daemon/internal/ffi_local_system
import gleam/bit_array
import gleam/result
import primitives
import simplifile

/// How many random bytes a credential holds.
pub const credential_bytes = 32

/// The file name of the operator credential in the state directory.
pub const operator_file = "operator.cred"

/// The file name of the agent credential in the state directory.
pub const agent_file = "agent.cred"

/// What a credential allows.
pub type Scope {
  /// Every operation, including approval, invitations and the audit log.
  Operator

  /// Contacts, send, receive, acknowledge, status and health.
  Agent
}

/// The credentials a running daemon accepts.
pub type Credentials {
  Credentials(operator: Secret, agent: Secret)
}

/// Creates the state directory if needed, and a credential file for each
/// scope that has none, then returns the credentials on disk. An existing
/// file is kept as long as it holds exactly `credential_bytes` bytes.
///
/// ## Examples
///
/// ```gleam
/// credential.ensure("/var/lib/pondline")
/// // -> Ok(Credentials(operator: _, agent: _))
/// ```
pub fn ensure(state_dir: String) -> Result(Credentials, String) {
  use Nil <- result.try(
    ffi_local_system.make_private_dir(state_dir)
    |> result.map_error(fn(reason) {
      "could not prepare " <> state_dir <> ": " <> reason
    }),
  )
  use operator <- result.try(ensure_file(state_dir <> "/" <> operator_file))
  use agent <- result.try(ensure_file(state_dir <> "/" <> agent_file))

  Ok(Credentials(operator:, agent:))
}

/// Reads a credential file, creating it first when it does not exist.
fn ensure_file(path: String) -> Result(Secret, String) {
  // The exclusive create is the arbiter: of two daemons starting together
  // exactly one writes the file, and the other reads what it wrote.
  case
    ffi_local_system.create_private_file(
      path,
      primitives.random_bytes(credential_bytes),
    )
  {
    Ok(Nil) -> read(path)
    Error("eexist") -> read(path)
    Error(reason) -> Error("could not create " <> path <> ": " <> reason)
  }
}

/// Reads a credential file and checks its length.
///
/// ## Examples
///
/// ```gleam
/// credential.read("/var/lib/pondline/agent.cred")
/// // -> Ok(_)
/// ```
pub fn read(path: String) -> Result(Secret, String) {
  use bytes <- result.try(
    simplifile.read_bits(path)
    |> result.map_error(fn(error) {
      "could not read " <> path <> ": " <> simplifile.describe_error(error)
    }),
  )

  // The length is checked, never the content, so the error cannot leak it.
  case bit_array.byte_size(bytes) == credential_bytes {
    True -> Ok(secret.new(bytes))
    False -> Error(path <> " is not a credential file")
  }
}

/// The scope a presented credential grants, if any. Both comparisons always
/// run, so the time taken does not say which one matched.
///
/// ## Examples
///
/// ```gleam
/// credential.authenticate(credentials, presented)
/// // -> Ok(Agent)
/// ```
pub fn authenticate(
  credentials: Credentials,
  presented: BitArray,
) -> Result(Scope, Nil) {
  // Key material is compared and dropped here; nothing is printed.
  let is_operator =
    primitives.constant_time_equal(
      secret.expose(credentials.operator),
      presented,
    )
  let is_agent =
    primitives.constant_time_equal(secret.expose(credentials.agent), presented)

  // The operator scope wins when both match, and neither matching is a failure.
  case is_operator, is_agent {
    True, _ -> Ok(Operator)
    False, True -> Ok(Agent)
    False, False -> Error(Nil)
  }
}

/// Whether a scope may run an operation that needs `required`. The operator
/// may run everything; an agent only what needs `Agent`.
///
/// ## Examples
///
/// ```gleam
/// credential.permits(Agent, required: Operator)
/// // -> False
/// ```
pub fn permits(held: Scope, required required: Scope) -> Bool {
  case held, required {
    Operator, _ -> True
    Agent, Agent -> True
    Agent, Operator -> False
  }
}
