//! The control protocol between the Erlang port owner and this sidecar.
//!
//! Why a hand-written binary encoding: the channel carries a handful of
//! message shapes, each with a few small fields. A serialization framework
//! would add a dependency and a second decoder to audit for a format this
//! small, and both ends need *total* decoding (every byte string either
//! decodes to a value or to a typed error, never a panic and never a
//! partial result). Writing it out by hand keeps that property visible.
//!
//! # Framing
//!
//! The Erlang port is opened with `{packet, 4}`, so every message in either
//! direction is a 4-byte big-endian length followed by that many payload
//! bytes. Frames above [`MAX_FRAME`] are a protocol violation: the peer is
//! broken or hostile, and the sidecar exits rather than guess.
//!
//! # Payload
//!
//! A payload is one tag byte followed by the fields of that message, in
//! order. All integers are big-endian. A `str` is a `u16` byte length and
//! that many bytes of UTF-8. A payload with trailing bytes after its last
//! field is malformed.
//!
//! Requests, Erlang to sidecar:
//!
//! ```text
//! 0x01 Bootstrap   id:u32
//! 0x02 HostOnion   id:u32 nickname:str local_port:u16
//! 0x03 Shutdown
//! ```
//!
//! Events, sidecar to Erlang:
//!
//! ```text
//! 0x81 Bootstrapped  id:u32
//! 0x82 OnionReady    id:u32 nickname:str hostname:str
//! 0x83 Failed        id:u32 code:u16 text:str
//! 0x90 Ready         version:u8
//! 0x91 ServiceStatus nickname:str state:u8
//! ```
//!
//! The `id` is chosen by the requester and echoed by the reply, so a reply
//! that arrives after its caller gave up can be recognised and dropped.
//! `Ready` is sent once, after the outbound socket is listening. `Failed`
//! codes and `ServiceStatus` states are the constants below; the Gleam
//! package `tor` mirrors them in `tor/internal/codec.gleam`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The largest frame, in bytes, either side may send.
pub const MAX_FRAME: usize = 64 * 1024;

/// The longest error text, in bytes, carried by a `Failed` event.
const MAX_TEXT: usize = 1024;

/// The protocol version announced in the `Ready` event.
pub const VERSION: u8 = 1;

/// Why a request could not be served. The numeric values are wire format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FailCode {
    /// Arti could not bootstrap.
    Bootstrap = 1,
    /// The nickname is not a valid onion service nickname.
    InvalidNickname = 2,
    /// A service with this nickname is already running.
    AlreadyHosting = 3,
    /// The sidecar already hosts as many services as it allows.
    TooManyServices = 4,
    /// Arti refused to launch the service.
    Launch = 5,
    /// The local forwarding port is zero.
    InvalidPort = 6,
    /// The service has no onion address in its keystore.
    NoAddress = 7,
}

/// A request from the port owner.
#[derive(Debug, PartialEq, Eq)]
pub enum Request {
    /// Bootstrap the Tor client.
    Bootstrap { id: u32 },
    /// Launch an onion service forwarding to `127.0.0.1:local_port`.
    HostOnion {
        id: u32,
        nickname: String,
        local_port: u16,
    },
    /// Exit cleanly.
    Shutdown,
}

/// An event for the port owner.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The sidecar is listening for outbound connections.
    Ready,
    /// The Tor client finished bootstrapping.
    Bootstrapped { id: u32 },
    /// An onion service is launched and has this address.
    OnionReady {
        id: u32,
        nickname: String,
        hostname: String,
    },
    /// A request failed.
    Failed {
        id: u32,
        code: FailCode,
        text: String,
    },
    /// An onion service changed state; `state` is Arti's state enum
    /// flattened by [`crate::host::state_code`].
    ServiceStatus { nickname: String, state: u8 },
}

/// Why a payload did not decode.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The payload ended inside a field.
    Truncated,
    /// The tag byte names no request.
    UnknownTag(u8),
    /// A string field is not UTF-8.
    BadUtf8,
    /// Bytes remain after the last field.
    Trailing,
}

/// A cursor over a payload whose every read is bounds-checked.
struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.rest.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn string(&mut self) -> Result<String, DecodeError> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::BadUtf8)
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Trailing)
        }
    }
}

impl Request {
    /// Decodes one frame payload. Total: any byte string yields a request
    /// or a [`DecodeError`].
    pub fn decode(payload: &[u8]) -> Result<Request, DecodeError> {
        let mut c = Cursor { rest: payload };
        let request = match c.u8()? {
            0x01 => Request::Bootstrap { id: c.u32()? },
            0x02 => Request::HostOnion {
                id: c.u32()?,
                nickname: c.string()?,
                local_port: c.u16()?,
            },
            0x03 => Request::Shutdown,
            tag => return Err(DecodeError::UnknownTag(tag)),
        };
        c.finish()?;
        Ok(request)
    }
}

/// Appends a `str` field. Strings longer than `u16::MAX` bytes are cut at
/// a character boundary; callers only pass short ones.
fn put_string(out: &mut Vec<u8>, text: &str, limit: usize) {
    let limit = limit.min(usize::from(u16::MAX));
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    out.extend_from_slice(&u16::try_from(end).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&text.as_bytes()[..end]);
}

impl Event {
    /// Encodes the event as a frame payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Event::Ready => {
                out.push(0x90);
                out.push(VERSION);
            }
            Event::Bootstrapped { id } => {
                out.push(0x81);
                out.extend_from_slice(&id.to_be_bytes());
            }
            Event::OnionReady {
                id,
                nickname,
                hostname,
            } => {
                out.push(0x82);
                out.extend_from_slice(&id.to_be_bytes());
                put_string(&mut out, nickname, MAX_TEXT);
                put_string(&mut out, hostname, MAX_TEXT);
            }
            Event::Failed { id, code, text } => {
                out.push(0x83);
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&(*code as u16).to_be_bytes());
                put_string(&mut out, text, MAX_TEXT);
            }
            Event::ServiceStatus { nickname, state } => {
                out.push(0x91);
                put_string(&mut out, nickname, MAX_TEXT);
                out.push(*state);
            }
        }
        out
    }
}

/// Why reading a frame stopped.
#[derive(Debug)]
pub enum FrameError {
    /// The stream ended or failed. For stdin this is the signal to exit.
    Closed,
    /// The length prefix exceeds [`MAX_FRAME`].
    TooLarge(usize),
}

/// Reads one length-prefixed frame. The length is checked before any
/// allocation, so a hostile prefix cannot make the sidecar reserve memory.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header)
        .await
        .map_err(|_| FrameError::Closed)?;

    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }

    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)
        .await
        .map_err(|_| FrameError::Closed)?;
    Ok(payload)
}

/// Writes one length-prefixed frame and flushes it, so the port owner sees
/// the event now rather than when a buffer fills.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let mut bytes = vec![0x02, 0, 0, 0, 7, 0, 3];
        bytes.extend_from_slice(b"mbx");
        bytes.extend_from_slice(&8080u16.to_be_bytes());
        assert_eq!(
            Request::decode(&bytes),
            Ok(Request::HostOnion {
                id: 7,
                nickname: "mbx".into(),
                local_port: 8080
            })
        );
        assert_eq!(
            Request::decode(&[0x01, 0, 0, 1, 0]),
            Ok(Request::Bootstrap { id: 256 })
        );
        assert_eq!(Request::decode(&[0x03]), Ok(Request::Shutdown));
    }

    #[test]
    fn garbage_never_panics() {
        assert_eq!(Request::decode(&[]), Err(DecodeError::Truncated));
        assert_eq!(Request::decode(&[0x7f]), Err(DecodeError::UnknownTag(0x7f)));
        assert_eq!(Request::decode(&[0x01, 0, 0]), Err(DecodeError::Truncated));
        assert_eq!(Request::decode(&[0x03, 0]), Err(DecodeError::Trailing));
        assert_eq!(
            Request::decode(&[0x02, 0, 0, 0, 1, 0, 1, 0xff, 0, 80]),
            Err(DecodeError::BadUtf8)
        );
        assert_eq!(
            Request::decode(&[0x02, 0, 0, 0, 1, 0xff, 0xff]),
            Err(DecodeError::Truncated)
        );
        for seed in 0..=255u8 {
            let bytes: Vec<u8> = (0..32)
                .map(|i| seed.wrapping_mul(31).wrapping_add(i))
                .collect();
            let _ = Request::decode(&bytes);
        }
    }

    #[test]
    fn failed_event_text_is_bounded() {
        let long = "é".repeat(2000);
        let bytes = Event::Failed {
            id: 1,
            code: FailCode::Launch,
            text: long,
        }
        .encode();
        let len = usize::from(u16::from_be_bytes([bytes[7], bytes[8]]));
        assert!(len <= MAX_TEXT);
        assert_eq!(bytes.len(), 9 + len);
        assert!(std::str::from_utf8(&bytes[9..]).is_ok());
    }
}
