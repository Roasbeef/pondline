//! `pondline-tor`: Arti as a separate OS process.
//!
//! Why a sidecar and not a NIF: a crash or stall inside Arti must not take
//! the BEAM down, and bytes that cross a real socket give the BEAM ordinary
//! passive-mode backpressure end to end, so Pondline builds no read-credit
//! machinery of its own (`docs/adr/001-tor-sidecar.md`).
//!
//! The Erlang side starts this binary as a port with `{packet, 4}`. Two
//! channels connect them:
//!
//! - Control frames on stdin and stdout (`frame`): bootstrap, host an onion
//!   service, shut down, and the replies and status events.
//! - A Unix socket, `<state-dir>/connect.sock`, for outbound onion streams
//!   (`connect`), and loopback TCP to a local port for inbound ones
//!   (`host`).
//!
//! Stdout belongs to the frame channel, so every diagnostic goes to stderr,
//! and none of them includes a key, an onion address or a stream payload.
//!
//! Lifetime: when stdin reaches end of file the port owner is gone, so the
//! process exits at once. A dead BEAM therefore never leaves an orphan, and
//! the only state that survives is what Arti persisted in the state
//! directory, which is built to be restarted from.

mod connect;
mod frame;
mod host;

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use arti_client::config::TorClientConfigBuilder;
use arti_client::{BootstrapBehavior, TorClient};
use tokio::io::{stdin, stdout};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

use frame::{read_frame, write_frame, Event, FailCode, FrameError, Request};

/// How many events may wait for the stdout writer. Events beyond this wait
/// in the task that produced them, so an unread port slows the sidecar down
/// instead of growing its memory.
const EVENT_QUEUE: usize = 64;

/// The exit status for a command line or startup problem.
const EXIT_SETUP: u8 = 2;

/// The exit status for a protocol violation on the control channel.
const EXIT_PROTOCOL: u8 = 3;

/// Creates a directory, and its parents, readable by the owner only. Arti
/// refuses to use a state directory that other users can reach, and the
/// outbound socket inside it relies on the same property for access control.
fn private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Parses `--state-dir <dir>`, the only option. Secrets never come from the
/// command line, which other users can read in the process table.
fn state_dir_arg() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next(), args.next()) {
        (Some("--state-dir"), Some(dir), None) => Some(PathBuf::from(dir)),
        _ => None,
    }
}

/// Drains the event channel into stdout frames. It is the only writer of
/// stdout, so frames never interleave.
async fn write_events(mut events: mpsc::Receiver<Event>) {
    let mut out = stdout();
    while let Some(event) = events.recv().await {
        if write_frame(&mut out, &event.encode()).await.is_err() {
            // The port owner closed our stdout; stdin will hit end of file
            // next and end the process.
            return;
        }
    }
}

/// Runs the control loop until stdin closes or a shutdown request arrives.
/// The returned code is the process exit status.
async fn control_loop(
    client: std::sync::Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    services: std::sync::Arc<host::Services>,
    events: mpsc::Sender<Event>,
) -> ExitCode {
    let mut input = stdin();
    loop {
        let payload = match read_frame(&mut input).await {
            Ok(payload) => payload,
            // End of file is the normal way a port owner leaves.
            Err(FrameError::Closed) => return ExitCode::SUCCESS,
            Err(FrameError::TooLarge(len)) => {
                eprintln!("pondline-tor: control frame of {len} bytes refused");
                return ExitCode::from(EXIT_PROTOCOL);
            }
        };

        // A frame we cannot decode means the two ends disagree about the
        // protocol. Guessing would risk acting on the wrong request, so we
        // exit and let the owner restart a fresh sidecar.
        let request = match Request::decode(&payload) {
            Ok(request) => request,
            Err(e) => {
                eprintln!("pondline-tor: undecodable control frame: {e:?}");
                return ExitCode::from(EXIT_PROTOCOL);
            }
        };

        match request {
            Request::Shutdown => return ExitCode::SUCCESS,
            Request::Bootstrap { id } => {
                tokio::spawn(bootstrap(client.clone(), events.clone(), id));
            }
            Request::HostOnion {
                id,
                nickname,
                local_port,
            } => {
                tokio::spawn(services.clone().host(id, nickname, local_port));
            }
        }
    }
}

/// Bootstraps Arti and reports the outcome. Concurrent requests are safe:
/// Arti makes bootstrapping idempotent.
async fn bootstrap(
    client: std::sync::Arc<TorClient<tor_rtcompat::PreferredRuntime>>,
    events: mpsc::Sender<Event>,
    id: u32,
) {
    let reply = match client.bootstrap().await {
        Ok(()) => Event::Bootstrapped { id },
        Err(e) => Event::Failed {
            id,
            code: FailCode::Bootstrap,
            text: e.to_string(),
        },
    };
    let _ = events.send(reply).await;
}

/// Builds the unbootstrapped client. Bootstrap behaviour is manual so that
/// nothing touches the network until the owner sends `Bootstrap`, and a
/// connect before then fails with `not-bootstrapped` instead of starting a
/// bootstrap as a side effect.
fn build_client(
    state_dir: &Path,
) -> Result<std::sync::Arc<TorClient<tor_rtcompat::PreferredRuntime>>, String> {
    let arti_state = state_dir.join("arti-state");
    let arti_cache = state_dir.join("arti-cache");
    private_dir(&arti_state).map_err(|e| e.to_string())?;
    private_dir(&arti_cache).map_err(|e| e.to_string())?;

    let config = TorClientConfigBuilder::from_directories(arti_state, arti_cache)
        .build()
        .map_err(|e| e.to_string())?;
    TorClient::builder()
        .config(config)
        .bootstrap_behavior(BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .map_err(|e| e.to_string())
}

/// Binds the outbound socket, replacing a stale file left by a sidecar that
/// died without cleaning up. The state directory is private, so no other
/// user can have put anything there.
fn bind_outbound(state_dir: &Path) -> std::io::Result<(UnixListener, PathBuf)> {
    let path = state_dir.join("connect.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, path))
}

#[tokio::main]
async fn main() -> ExitCode {
    // Arti's TLS needs a process-wide crypto provider and selects none
    // itself. Installing one is idempotent in effect: the only possible
    // error is that a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let Some(state_dir) = state_dir_arg() else {
        eprintln!("usage: pondline-tor --state-dir <dir>");
        return ExitCode::from(EXIT_SETUP);
    };
    if let Err(e) = private_dir(&state_dir) {
        eprintln!("pondline-tor: cannot create the state directory: {e}");
        return ExitCode::from(EXIT_SETUP);
    }

    let client = match build_client(&state_dir) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("pondline-tor: cannot create the Tor client: {e}");
            return ExitCode::from(EXIT_SETUP);
        }
    };
    let (listener, socket_path) = match bind_outbound(&state_dir) {
        Ok(bound) => bound,
        Err(e) => {
            eprintln!("pondline-tor: cannot bind the outbound socket: {e}");
            return ExitCode::from(EXIT_SETUP);
        }
    };

    let (events, receiver) = mpsc::channel(EVENT_QUEUE);
    tokio::spawn(write_events(receiver));
    tokio::spawn(connect::accept_loop(
        connect::Outbound::new(client.clone()),
        listener,
    ));

    // `Ready` goes out last: once the owner has seen it, the outbound
    // socket is accepting and a request on stdin will be served.
    let _ = events.send(Event::Ready).await;
    let services = host::Services::new(client.clone(), events.clone());
    let code = control_loop(client, services, events).await;

    // Best effort: a stale socket file is replaced on the next start, so a
    // failure here costs nothing.
    let _ = std::fs::remove_file(&socket_path);
    code
}
