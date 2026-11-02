//! Hosting an onion service whose streams are forwarded to a local port.
//!
//! Why forwarding rather than handing streams to the BEAM one by one: the
//! mailbox is an ordinary HTTP server on a loopback port, and the same
//! splice used for outbound streams (see `connect`) carries backpressure
//! from that server back into Tor. This module owns the service's lifetime,
//! the accept loop, and the translation of Arti's status stream into the
//! bounded `ServiceStatus` events.
//!
//! The service's identity key lives in Arti's keystore under the state
//! directory, keyed by nickname, so the same nickname yields the same
//! `.onion` address across restarts. Nothing here ever logs or transmits
//! the key; the only secret-adjacent value that leaves the process is the
//! public hostname, in `OnionReady`.
//!
//! The service accepts a `BEGIN` to any virtual port and forwards it to the
//! one local port given in `HostOnion`. Arti's onion-service circuits
//! deliver only `BEGIN` requests, so no other request kind reaches us.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arti_client::TorClient;
use futures::StreamExt;
use safelog::DisplayRedacted;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_hsservice::status::State;
use tor_hsservice::{
    handle_rend_requests, HsNickname, OnionServiceConfig, RunningOnionService, StreamRequest,
};
use tor_rtcompat::PreferredRuntime;

use crate::frame::{Event, FailCode};

/// The most onion services one sidecar will host.
pub const MAX_SERVICES: usize = 4;

/// The most inbound streams forwarded at once, across all services.
/// Excess streams are rejected with `END`, never queued.
pub const MAX_INBOUND: usize = 256;

/// The running services, which must stay alive for the service to stay up:
/// dropping the last handle shuts the service down.
pub struct Services {
    client: Arc<TorClient<PreferredRuntime>>,
    running: Mutex<HashMap<String, Arc<RunningOnionService>>>,
    inbound: Arc<Semaphore>,
    events: mpsc::Sender<Event>,
}

/// Flattens Arti's service state into the wire constant. The numbers are
/// wire format; `0` is also what a state this build does not know maps to,
/// since an unknown state must not look reachable.
pub fn state_code(state: State) -> u8 {
    match state {
        State::Bootstrapping => 1,
        State::DegradedReachable => 2,
        State::DegradedUnreachable => 3,
        State::Running => 4,
        State::Recovering => 5,
        State::Broken => 6,
        State::Shutdown => 7,
        _ => 0,
    }
}

impl Services {
    /// Builds the registry around a Tor client and the event channel.
    pub fn new(client: Arc<TorClient<PreferredRuntime>>, events: mpsc::Sender<Event>) -> Arc<Self> {
        Arc::new(Services {
            client,
            running: Mutex::new(HashMap::new()),
            inbound: Arc::new(Semaphore::new(MAX_INBOUND)),
            events,
        })
    }

    /// Launches the service and answers the request with `OnionReady` or
    /// `Failed`. The launch itself is synchronous, so the registry lock is
    /// held across it without an await point, which makes the duplicate
    /// check and the insert one step.
    pub async fn host(self: Arc<Self>, id: u32, nickname: String, local_port: u16) {
        let reply = match self.launch(&nickname, local_port) {
            Ok(hostname) => Event::OnionReady {
                id,
                nickname,
                hostname,
            },
            Err((code, text)) => Event::Failed { id, code, text },
        };
        let _ = self.events.send(reply).await;
    }

    fn launch(
        self: &Arc<Self>,
        nickname: &str,
        local_port: u16,
    ) -> Result<String, (FailCode, String)> {
        if local_port == 0 {
            return Err((FailCode::InvalidPort, "local port is zero".into()));
        }
        let hs_nickname = HsNickname::new(nickname.to_owned())
            .map_err(|e| (FailCode::InvalidNickname, e.to_string()))?;
        let config = OnionServiceConfig::builder()
            .nickname(hs_nickname)
            .build()
            .map_err(|e| (FailCode::Launch, e.to_string()))?;

        let mut running = self
            .running
            .lock()
            .map_err(|_| (FailCode::Launch, "service registry poisoned".to_owned()))?;
        if running.contains_key(nickname) {
            return Err((FailCode::AlreadyHosting, "nickname already hosted".into()));
        }
        if running.len() >= MAX_SERVICES {
            return Err((FailCode::TooManyServices, "service limit reached".into()));
        }

        let (service, rend_requests) = self
            .client
            .launch_onion_service(config)
            .map_err(|e| (FailCode::Launch, e.to_string()))?
            .ok_or((FailCode::Launch, "service disabled".to_owned()))?;
        let address = service
            .onion_address()
            .ok_or((FailCode::NoAddress, "no onion address".to_owned()))?;
        let hostname = address.display_unredacted().to_string();

        running.insert(nickname.to_owned(), service.clone());
        drop(running);

        tokio::spawn(forward_loop(self.clone(), rend_requests, local_port));
        tokio::spawn(report_status(
            self.events.clone(),
            nickname.to_owned(),
            service,
        ));
        Ok(hostname)
    }
}

/// Pulls stream requests from the service and forwards each to the local
/// port. This loop must keep running or the service stalls, since Arti's
/// request queue is only drained here.
async fn forward_loop<S>(services: Arc<Services>, rend_requests: S, local_port: u16)
where
    S: futures::Stream<Item = tor_hsservice::RendRequest> + Send + 'static,
{
    let mut requests = Box::pin(handle_rend_requests(rend_requests));
    while let Some(request) = requests.next().await {
        let Ok(permit) = services.inbound.clone().try_acquire_owned() else {
            tokio::spawn(async move {
                let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
            });
            continue;
        };

        tokio::spawn(async move {
            forward_one(request, local_port).await;
            drop(permit);
        });
    }
}

/// Forwards one inbound stream. The local connection is made before the
/// stream is accepted, so a dead local server shows the client an `END`
/// rather than an open stream that never answers.
async fn forward_one(request: StreamRequest, local_port: u16) {
    let Ok(mut local) = TcpStream::connect(("127.0.0.1", local_port)).await else {
        let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
        return;
    };
    let Ok(mut stream) = request.accept(Connected::new_empty()).await else {
        return;
    };

    let _ = copy_bidirectional(&mut local, &mut stream).await;
}

/// Reports each distinct state the service moves through. Consecutive
/// repeats are dropped, so the event rate is bounded by the number of real
/// transitions rather than by how often Arti republishes its status.
async fn report_status(
    events: mpsc::Sender<Event>,
    nickname: String,
    service: Arc<RunningOnionService>,
) {
    let mut last = None;
    let mut status = service.status_events();
    while let Some(update) = status.next().await {
        let state = state_code(update.state());
        if last == Some(state) {
            continue;
        }
        last = Some(state);

        let event = Event::ServiceStatus {
            nickname: nickname.clone(),
            state,
        };
        if events.send(event).await.is_err() {
            return;
        }
    }
}
