//! Outbound onion streams, offered to the BEAM over a Unix domain socket.
//!
//! Why a socket per stream rather than multiplexing streams over the control
//! channel: the BEAM then holds an ordinary passive-mode socket for each
//! stream. When the Gleam side stops calling `recv`, the kernel buffer on its
//! end fills, this process's write blocks, `copy_bidirectional` stops reading
//! from Arti, and Arti's own stream window stops granting credit to the far
//! end. Backpressure crosses the whole path with no credit protocol of our
//! own (spec section 10.4). The socket lives in the state directory, which is
//! mode 0700, so only the owning user can reach it.
//!
//! # Handshake
//!
//! A client connects and sends one line of at most [`MAX_LINE`] bytes:
//!
//! ```text
//! CONNECT <56-char-v3>.onion:<port> <isolation-group>\n
//! ```
//!
//! The reply is `OK\n` followed by raw bytes in both directions, or
//! `ERR <code>\n` and a close. The codes are `not-onion`, `bad-request`,
//! `busy`, `too-many-groups`, `not-bootstrapped`, `onion-invalid`,
//! `onion-not-found`,
//! `onion-unreachable`, `timeout` and `connect-failed`.
//!
//! Every refusal that depends only on the request line happens before the
//! Tor client is touched, so a clearnet target is refused the same way
//! whether or not Tor has bootstrapped (spec section 13.1: no silent
//! transport downgrade). There is no code path from this module to a
//! non-onion destination.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arti_client::{ErrorKind, HasKind, IsolationToken, StreamPrefs, TorClient};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tor_rtcompat::PreferredRuntime;

/// The longest handshake line, in bytes, including the newline.
pub const MAX_LINE: usize = 256;

/// The most outbound streams open at once. Excess connections are refused
/// with `ERR busy`, never queued.
pub const MAX_STREAMS: usize = 64;

/// The most distinct isolation groups remembered at once. Each group costs
/// one token in a map, so the map is bounded.
pub const MAX_GROUPS: usize = 1024;

/// How long a client may take to send its handshake line.
const LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long Arti may take to open the onion stream. Onion connects involve
/// a descriptor fetch and a rendezvous, so this is generous.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(180);

/// Shared state for the outbound listener.
pub struct Outbound {
    client: Arc<TorClient<PreferredRuntime>>,
    slots: Arc<Semaphore>,
    groups: Mutex<HashMap<String, IsolationToken>>,
}

impl Outbound {
    /// Builds the listener state around a Tor client.
    pub fn new(client: Arc<TorClient<PreferredRuntime>>) -> Arc<Outbound> {
        Arc::new(Outbound {
            client,
            slots: Arc::new(Semaphore::new(MAX_STREAMS)),
            groups: Mutex::new(HashMap::new()),
        })
    }

    /// The isolation token for a group name. The same name always yields the
    /// same token, so those streams may share circuits; different names get
    /// different tokens, which Arti never lets share a circuit.
    fn token_for(&self, group: &str) -> Option<IsolationToken> {
        let mut groups = self.groups.lock().ok()?;
        if let Some(token) = groups.get(group) {
            return Some(*token);
        }
        if groups.len() >= MAX_GROUPS {
            return None;
        }
        let token = IsolationToken::new();
        groups.insert(group.to_owned(), token);
        Some(token)
    }
}

/// A parsed, validated connect request.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    /// The v3 onion hostname.
    pub host: String,
    /// The destination port.
    pub port: u16,
    /// The isolation group name.
    pub group: String,
}

/// Why a request line was refused. The `Display` text is the `ERR` code.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The host is not a v3 onion address.
    NotOnion,
    /// The line is malformed in any other way.
    BadRequest,
}

impl Refusal {
    fn code(&self) -> &'static str {
        match self {
            Refusal::NotOnion => "not-onion",
            Refusal::BadRequest => "bad-request",
        }
    }
}

/// True for a lowercase v3 onion hostname: 56 base32 characters, the last
/// being `d` (version 3 always encodes to it), then `.onion`. Arti verifies
/// the embedded checksum when it connects; this guarantees the shape, which
/// is all that is needed to rule out clearnet.
pub fn is_v3_onion(host: &str) -> bool {
    match host.strip_suffix(".onion") {
        Some(label) => {
            label.len() == 56
                && label.ends_with('d')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        }
        None => false,
    }
}

/// Parses a handshake line, without its newline.
///
/// The host is judged before the other fields, so a clearnet target is
/// reported as `not-onion` even when the rest of the line is also wrong.
pub fn parse_line(line: &str) -> Result<Target, Refusal> {
    let tokens: Vec<&str> = line.split(' ').collect();
    if tokens.first() != Some(&"CONNECT") {
        return Err(Refusal::BadRequest);
    }

    let (host, port) = tokens
        .get(1)
        .and_then(|t| t.rsplit_once(':'))
        .ok_or(Refusal::BadRequest)?;
    if !is_v3_onion(host) {
        return Err(Refusal::NotOnion);
    }

    let group = match tokens.as_slice() {
        [_, _, group] => *group,
        _ => return Err(Refusal::BadRequest),
    };
    let port: u16 = port.parse().map_err(|_| Refusal::BadRequest)?;
    let group_ok = !group.is_empty() && group.bytes().all(|b| b.is_ascii_graphic());
    if port == 0 || !group_ok {
        return Err(Refusal::BadRequest);
    }

    Ok(Target {
        host: host.to_owned(),
        port,
        group: group.to_owned(),
    })
}

/// Reads the handshake line one byte at a time, so no byte after the
/// newline is consumed here and lost to the splice that follows.
async fn read_line(sock: &mut UnixStream) -> Option<String> {
    let mut line = Vec::with_capacity(MAX_LINE);
    loop {
        let byte = sock.read_u8().await.ok()?;
        if byte == b'\n' {
            return String::from_utf8(line).ok();
        }
        if line.len() + 1 >= MAX_LINE {
            return None;
        }
        line.push(byte);
    }
}

/// Maps an Arti error to the closed set of `ERR` codes. Nothing from the
/// error's text reaches the client, because it can name the onion address.
fn error_code(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::BootstrapRequired => "not-bootstrapped",
        ErrorKind::OnionServiceAddressInvalid => "onion-invalid",
        ErrorKind::OnionServiceNotFound => "onion-not-found",
        ErrorKind::OnionServiceNotRunning | ErrorKind::OnionServiceConnectionFailed => {
            "onion-unreachable"
        }
        _ => "connect-failed",
    }
}

/// Serves one client connection from handshake to close.
async fn serve(outbound: Arc<Outbound>, mut sock: UnixStream) {
    let line = tokio::time::timeout(LINE_TIMEOUT, read_line(&mut sock)).await;
    let parsed = match line {
        Ok(Some(line)) => parse_line(&line),
        _ => Err(Refusal::BadRequest),
    };

    // Everything above ran with no reference to the Tor client; only a
    // validated onion target gets past this point.
    let target = match parsed {
        Ok(target) => target,
        Err(refusal) => return refuse(&mut sock, refusal.code()).await,
    };
    let Some(token) = outbound.token_for(&target.group) else {
        return refuse(&mut sock, "too-many-groups").await;
    };

    let mut prefs = StreamPrefs::new();
    prefs.connect_to_onion_services(arti_client::config::BoolOrAuto::Explicit(true));
    prefs.set_isolation(token);

    let attempt = tokio::time::timeout(
        CONNECT_TIMEOUT,
        outbound
            .client
            .connect_with_prefs((target.host.as_str(), target.port), &prefs),
    )
    .await;
    let mut stream = match attempt {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => return refuse(&mut sock, error_code(e.kind())).await,
        Err(_) => return refuse(&mut sock, "timeout").await,
    };

    if sock.write_all(b"OK\n").await.is_err() {
        return;
    }

    // From here the two ends are spliced. Each side's write waits when the
    // other side is not reading, which is the backpressure described above.
    let _ = copy_bidirectional(&mut sock, &mut stream).await;
}

/// Replies `ERR <code>` and closes the connection.
async fn refuse(sock: &mut UnixStream, code: &str) {
    let _ = sock.write_all(format!("ERR {code}\n").as_bytes()).await;
    let _ = sock.shutdown().await;
}

/// Accepts connections until the listener fails. Each connection holds one
/// of [`MAX_STREAMS`] slots for its lifetime; with none free it is refused
/// at once.
pub async fn accept_loop(outbound: Arc<Outbound>, listener: UnixListener) {
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            // The listener only fails when the socket file is gone or the
            // process is out of descriptors; neither is recoverable here.
            eprintln!("pondline-tor: outbound listener failed");
            return;
        };

        let Ok(permit) = outbound.slots.clone().try_acquire_owned() else {
            tokio::spawn(async move { refuse(&mut sock, "busy").await });
            continue;
        };

        let outbound = outbound.clone();
        tokio::spawn(async move {
            serve(outbound, sock).await;
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion";

    #[test]
    fn accepts_a_v3_onion() {
        let line = format!("CONNECT {ONION}:80 group-a");
        let target = parse_line(&line).expect("valid line");
        assert_eq!(target.port, 80);
        assert_eq!(target.group, "group-a");
    }

    #[test]
    fn refuses_clearnet_as_not_onion() {
        assert_eq!(
            parse_line("CONNECT example.com:80 g"),
            Err(Refusal::NotOnion)
        );
        assert_eq!(parse_line("CONNECT 1.2.3.4:80 g"), Err(Refusal::NotOnion));
        assert_eq!(parse_line("CONNECT example.com:80"), Err(Refusal::NotOnion));
        assert_eq!(
            parse_line("CONNECT abcdefghijklmnop.onion:80 g"),
            Err(Refusal::NotOnion)
        );
    }

    #[test]
    fn refuses_malformed_lines() {
        for line in [
            "",
            "GET / HTTP/1.1",
            "CONNECT",
            &format!("CONNECT {ONION} g"),
            &format!("CONNECT {ONION}:0 g"),
            &format!("CONNECT {ONION}:99999 g"),
            &format!("CONNECT {ONION}:80"),
            &format!("CONNECT {ONION}:80 a b"),
            &format!("CONNECT {ONION}:80 "),
        ] {
            assert_eq!(parse_line(line), Err(Refusal::BadRequest), "{line:?}");
        }
    }
}
