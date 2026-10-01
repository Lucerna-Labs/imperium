//! The mesh daemon: one UDP socket, a receive loop, and the handshake driver.
//!
//! Before this module the mesh had no runtime. `MeshTransport` held no socket,
//! `process_incoming` required the caller to already know the session, and the
//! handshake primitives (`verify_hello`, `initiator_encapsulate`,
//! `create_session`/`adopt_session`/`establish_session`) were never chained in
//! running code. This daemon is the thing that was missing: it owns the
//! socket, classifies each datagram, resolves the session from the source
//! address, drives the handshake, and emits cover traffic on a timer.
//!
//! It carries opaque bytes and never inspects their CONTENT — but it does read
//! the IPv4 destination of an outbound payload, because with several peers the
//! destination is what selects the peer. Everything else about the payload is
//! opaque to this layer; interpreting packets as packets is `imperium-net-host`'s
//! job.
//!
//! ## The handshake gate
//!
//! A hybrid Ed25519 + ML-DSA-65 verification is the expensive part of accepting
//! a peer, and it must not be reachable by an arbitrary datagram. Two cheap
//! mechanisms stand in front of it (see [`crate::gate`]):
//!
//! 1. an ungated Hello earns a **cookie** and nothing else — no JSON parsing, no
//!    signature work;
//! 2. a Hello that returns the cookie's MAC is checked against the **source
//!    address** it arrived from, and only then verified.
//!
//! A per-source **token bucket** bounds how much of that work one address can
//! compel, because a cookie cannot stop a flood from a real address.
//!
//! ## What a live listener still exposes (measured, not asserted)
//!
//! - [`DaemonStats::handshake_datagram_bytes`] records the largest handshake
//!   datagram seen. Hybrid post-quantum material is multi-kilobyte and
//!   routinely exceeds a 1500-byte path MTU, so it fragments on a real network.
//!   The gate does not change this: the cookie round trip doubles the number of
//!   such datagrams rather than replacing them.
//! - A session key rotates when `session_max_bytes` is spent, by
//!   re-handshaking rather than by an in-session rekey message, so a rotation
//!   is a brief link interruption. Set it to `None` and the key does live for
//!   the life of the session. [`DaemonStats::sessions_rekeyed`] is the counter
//!   that reflects real rotation.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use imperium_net_crypto::{
    HybridEd25519Mldsa, HybridEncapsulation, HybridKexPublicKey, HybridKexSecretKey,
    HybridSigningKey, HybridVerifyingKey, HybridX25519Mlkem,
};
use imperium_net_observer::{decode, decode_mesh_datagram, decode_raw_ip};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    ClusterId, KillSwitchState, LeakGuardStatus, LightconeFrameFormat, LightconeStructure,
    MeshHello, MeshHelloResponse, Message, PeerId, SessionId,
};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use spiderweb::BusPublisher;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::destination::Destination;
use crate::gate::{HandshakeGate, COOKIE_LEN};
use crate::handshake::{
    encode_identity_vk, hello_signed_payload, hello_transcript_hash, response_signed_payload,
    verify_hello, verify_hello_response, HandshakeError, IdentityBinding,
};
use crate::peer::PeerManager;
use crate::session::{SessionError, SessionManager};
use crate::transport::{MeshTransport, TransportError};
use crate::wire::{self, DatagramKind, HandshakeKind, Reassembler, WireError};
use crate::world_lightcone::WireDirection;

/// Exact bytes are retained only until this daemon's bounded observer worker
/// has derived structural context and a digest. They never enter the bus.
struct LightconeWireFrame {
    direction: u8,
    format: LightconeFrameFormat,
    bytes: Vec<u8>,
}

/// Rejected HelloResponses tolerated for one handshake attempt before it is
/// abandoned. Without a cap, no longer destroying the handshake on a bad
/// response would let a flood compel repeated hybrid verifications.
const MAX_RESPONSE_ATTEMPTS: u32 = 4;

/// How often the loop wakes to run retransmit, cover-traffic and expiry
/// timers. Independent of socket readiness.
const TICK: Duration = Duration::from_millis(250);

/// Re-run the session-expiry sweep every N ticks.
const EXPIRY_TICKS: u64 = 20;

/// Largest datagram we will read. Hybrid handshake material is multi-kilobyte,
/// so this is the UDP maximum rather than the frame ceiling.
const MAX_DATAGRAM: usize = 65_535;

/// Bytes we will accept into the delivery queue before dropping. A slow
/// consumer must never stall the receive loop.
const INBOUND_QUEUE: usize = 1024;

/// The topic operator kill-switch commands arrive on.
const KILLSWITCH_TOPIC: &str = "net.transport.killswitch.command";

/// Exact UDP payload bytes offered to the supervised passive observer.
const LIGHTCONE_FRAME_TOPIC: &str = "net.lightcone.frame";
const LIGHTCONE_OBSERVER_QUEUE: usize = 256;
const LIGHTCONE_INBOUND: u8 = 0;
const LIGHTCONE_OUTBOUND: u8 = 1;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
    #[error("handshake rejected: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("session error: {0}")]
    Session(#[from] SessionError),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("no established session")]
    NoSession,
    /// The kill switch is engaged, so nothing was sent. Distinct from success:
    /// reporting `Ok` here made the host bridge count suppressed packets as
    /// delivered, so the health report showed traffic flowing while the data
    /// path was stopped.
    #[error("kill switch engaged: nothing was sent")]
    SuppressedByKillSwitch,
    #[error("session has no known peer address")]
    NoPeerAddress,
    #[error("expected peer identity does not match the responder")]
    ResponderNotExpected,
}

/// One configured peer.
///
/// A node may have several. The routes are what decide which peer a packet goes
/// to: a payload's IPv4 destination is matched against every peer's prefixes,
/// longest prefix first.
#[derive(Clone)]
pub struct PeerConfig {
    pub peer_id: PeerId,
    /// Where to dial this peer.
    ///
    /// `None` means accept-only: this node expects the peer but does not dial
    /// it, which is the usual responder shape. The address it will be reached
    /// at is learned from the handshake, so a responder never needs one.
    pub addr: Option<SocketAddr>,
    /// Pin this peer's identity key.
    ///
    /// `verify_hello_response` now checks the responder's own operator-signed
    /// binding, so the identity is authoritative without this. A pin remains
    /// an operator's way to require one specific key.
    pub pinned_identity_vk: Option<HybridVerifyingKey>,
    /// Destination prefixes reachable through this peer.
    pub routes: Vec<Destination>,
}

/// Everything one node needs to run a live mesh link.
///
/// `identity_*` signs this node's handshake messages; `operator_*` is the
/// cluster trust anchor that binds a peer id to an identity key. In a real
/// cluster one operator keypair is shared by every node while each node holds
/// its own identity keypair.
pub struct MeshNodeConfig {
    pub peer_id: PeerId,
    pub cluster_id: ClusterId,
    /// Local UDP bind address.
    pub bind_addr: SocketAddr,
    /// Configured peers.
    ///
    /// Empty makes this node a pure responder that accepts any peer whose
    /// identity is operator-bound. Non-empty restricts membership to exactly
    /// these peer ids and, for the ones with an address, dials them.
    pub peers: Vec<PeerConfig>,
    pub identity_signing_key: HybridSigningKey,
    pub identity_verifying_key: HybridVerifyingKey,
    pub operator_signing_key: HybridSigningKey,
    pub operator_verifying_key: HybridVerifyingKey,
    /// Lifetime of the identity binding this node mints for itself.
    pub identity_ttl: chrono::Duration,
    /// How long a handshake may sit unanswered before it is retransmitted.
    pub handshake_retry: Duration,
    /// Attempts before the link is reported failed.
    pub max_handshake_attempts: u32,
    /// Idle seconds after which a session is expired.
    pub session_idle_secs: i64,
    /// Plaintext bytes a session may seal before its key must rotate.
    ///
    /// `None` means the key never rotates, which is what every deployment did
    /// before this existed: the session key lived for the life of the session
    /// however much data crossed it. Rotation is done by re-handshaking, so it
    /// establishes a genuinely fresh key rather than relabelling the old one.
    pub session_max_bytes: Option<u64>,
}

impl MeshNodeConfig {
    /// Mint the operator-signed identity binding for `peer_id`.
    pub fn identity_binding_for(
        operator_signing_key: &HybridSigningKey,
        peer_id: &PeerId,
        identity_vk: &HybridVerifyingKey,
        cluster_id: &ClusterId,
        ttl: chrono::Duration,
    ) -> IdentityBinding {
        let unsigned = IdentityBinding {
            peer_id_bytes: *peer_id.0.as_bytes(),
            identity_vk_bytes: encode_identity_vk(identity_vk),
            cluster_id_bytes: *cluster_id.0.as_bytes(),
            expires_at_unix: (Utc::now() + ttl).timestamp(),
            operator_signature: Vec::new(),
        };
        let signature = HybridEd25519Mldsa::sign(operator_signing_key, &unsigned.signed_payload());
        IdentityBinding {
            operator_signature: signature.to_bytes(),
            ..unsigned
        }
    }
}

/// A decrypted payload handed up by the daemon.
#[derive(Clone, Debug)]
pub struct MeshInbound {
    pub peer_id: PeerId,
    pub session_id: SessionId,
    pub counter: u64,
    pub payload: Vec<u8>,
}

/// Live counters, so a running daemon can be inspected rather than assumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DaemonStats {
    pub datagrams_received: u64,
    pub datagrams_unclassified: u64,
    /// Every inbound Hello that reached a full hybrid signature verification.
    pub handshake_verifications: u64,
    pub handshake_failures: u64,
    /// Cookies handed out in place of doing any verification work.
    pub handshake_cookies_sent: u64,
    /// Hellos dropped by the per-source token bucket before any work was done.
    pub handshake_rate_limited: u64,
    /// Handshake datagrams rebuilt from fragments.
    pub handshake_datagrams_reassembled: u64,
    /// Fragment sets abandoned or refused.
    pub handshake_fragments_rejected: u64,
    pub handshakes_completed: u64,
    pub handshake_retransmits: u64,
    pub frames_opened: u64,
    pub frames_failed: u64,
    pub cover_frames_sent: u64,
    pub cover_frames_received: u64,
    pub payloads_delivered: u64,
    pub payloads_dropped: u64,
    pub sessions_expired: u64,
    /// Sessions torn down and re-established because the byte budget was spent.
    pub sessions_rekeyed: u64,
    /// Sessions rebound to a new source address because the peer's address
    /// changed (NAT).
    pub nat_rebinds: u64,
    /// Largest handshake **message** seen, in bytes, before fragmentation.
    ///
    /// This is the size of the Hello or HelloResponse itself, not of any
    /// datagram on the wire: messages this large are split into
    /// `FRAGMENT_CHUNK`-sized datagrams, which is what makes them survivable.
    pub handshake_datagram_bytes: u64,
    /// Exact UDP datagrams accepted into the bounded passive observer queue.
    /// A queued frame is not proof that a Lightcone receipt was emitted.
    pub lightcone_observations_queued: u64,
    /// Frames published onto the bus, whether or not a strand received them.
    pub lightcone_observations_published: u64,
    /// Frames dropped because the observer queue was full or closed.
    pub lightcone_observations_dropped: u64,
    /// Bus publication errors after a frame left the observer queue.
    pub lightcone_publish_errors: u64,
}

struct Stats {
    datagrams_received: AtomicU64,
    datagrams_unclassified: AtomicU64,
    handshake_verifications: AtomicU64,
    handshake_failures: AtomicU64,
    handshake_cookies_sent: AtomicU64,
    handshake_rate_limited: AtomicU64,
    handshake_datagrams_reassembled: AtomicU64,
    handshake_fragments_rejected: AtomicU64,
    handshakes_completed: AtomicU64,
    handshake_retransmits: AtomicU64,
    frames_opened: AtomicU64,
    frames_failed: AtomicU64,
    cover_frames_sent: AtomicU64,
    cover_frames_received: AtomicU64,
    payloads_delivered: AtomicU64,
    payloads_dropped: AtomicU64,
    sessions_expired: AtomicU64,
    sessions_rekeyed: AtomicU64,
    nat_rebinds: AtomicU64,
    handshake_datagram_bytes: AtomicU64,
    lightcone_observations_queued: AtomicU64,
    lightcone_observations_published: AtomicU64,
    lightcone_observations_dropped: AtomicU64,
    lightcone_publish_errors: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            datagrams_received: AtomicU64::new(0),
            datagrams_unclassified: AtomicU64::new(0),
            handshake_verifications: AtomicU64::new(0),
            handshake_failures: AtomicU64::new(0),
            handshake_cookies_sent: AtomicU64::new(0),
            handshake_rate_limited: AtomicU64::new(0),
            handshake_datagrams_reassembled: AtomicU64::new(0),
            handshake_fragments_rejected: AtomicU64::new(0),
            handshakes_completed: AtomicU64::new(0),
            handshake_retransmits: AtomicU64::new(0),
            frames_opened: AtomicU64::new(0),
            frames_failed: AtomicU64::new(0),
            cover_frames_sent: AtomicU64::new(0),
            cover_frames_received: AtomicU64::new(0),
            payloads_delivered: AtomicU64::new(0),
            payloads_dropped: AtomicU64::new(0),
            sessions_expired: AtomicU64::new(0),
            sessions_rekeyed: AtomicU64::new(0),
            nat_rebinds: AtomicU64::new(0),
            handshake_datagram_bytes: AtomicU64::new(0),
            lightcone_observations_queued: AtomicU64::new(0),
            lightcone_observations_published: AtomicU64::new(0),
            lightcone_observations_dropped: AtomicU64::new(0),
            lightcone_publish_errors: AtomicU64::new(0),
        }
    }

    fn snapshot(&self) -> DaemonStats {
        DaemonStats {
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            datagrams_unclassified: self.datagrams_unclassified.load(Ordering::Relaxed),
            handshake_verifications: self.handshake_verifications.load(Ordering::Relaxed),
            handshake_failures: self.handshake_failures.load(Ordering::Relaxed),
            handshake_cookies_sent: self.handshake_cookies_sent.load(Ordering::Relaxed),
            handshake_rate_limited: self.handshake_rate_limited.load(Ordering::Relaxed),
            handshake_datagrams_reassembled: self
                .handshake_datagrams_reassembled
                .load(Ordering::Relaxed),
            handshake_fragments_rejected: self.handshake_fragments_rejected.load(Ordering::Relaxed),
            handshakes_completed: self.handshakes_completed.load(Ordering::Relaxed),
            handshake_retransmits: self.handshake_retransmits.load(Ordering::Relaxed),
            frames_opened: self.frames_opened.load(Ordering::Relaxed),
            frames_failed: self.frames_failed.load(Ordering::Relaxed),
            cover_frames_sent: self.cover_frames_sent.load(Ordering::Relaxed),
            cover_frames_received: self.cover_frames_received.load(Ordering::Relaxed),
            payloads_delivered: self.payloads_delivered.load(Ordering::Relaxed),
            payloads_dropped: self.payloads_dropped.load(Ordering::Relaxed),
            sessions_expired: self.sessions_expired.load(Ordering::Relaxed),
            sessions_rekeyed: self.sessions_rekeyed.load(Ordering::Relaxed),
            nat_rebinds: self.nat_rebinds.load(Ordering::Relaxed),
            handshake_datagram_bytes: self.handshake_datagram_bytes.load(Ordering::Relaxed),
            lightcone_observations_queued: self
                .lightcone_observations_queued
                .load(Ordering::Relaxed),
            lightcone_observations_published: self
                .lightcone_observations_published
                .load(Ordering::Relaxed),
            lightcone_observations_dropped: self
                .lightcone_observations_dropped
                .load(Ordering::Relaxed),
            lightcone_publish_errors: self.lightcone_publish_errors.load(Ordering::Relaxed),
        }
    }
}

/// Everything held while a handshake is outstanding. Boxed inside
/// [`LinkState`] because it is far larger than the established variant and
/// would otherwise size the whole enum.
struct OutstandingHandshake {
    hello: MeshHello,
    /// The one-shot KEX secret, consumed exactly once by decapsulation.
    secret: HybridKexSecretKey,
    /// Responses that failed validation for this attempt. A rejected response
    /// no longer destroys the handshake, so a flood could otherwise compel an
    /// unbounded number of hybrid verifications; past the cap the attempt is
    /// abandoned and the link goes idle so the re-dial backoff applies.
    response_attempts: u32,
    /// The cookie the peer handed back. Until this is set the Hello is sent
    /// ungated and the peer will only answer with a cookie; once set, the Hello
    /// is re-sent carrying a gate MAC over its own bytes.
    cookie: Option<[u8; COOKIE_LEN]>,
    attempts: u32,
    last_sent: Instant,
}

/// One peer's link state.
struct Link {
    state: LinkState,
    /// Earliest time this peer may be dialled again. `initiate` pushes this out
    /// on every attempt, so a peer that is down gets one handshake per backoff
    /// rather than one per tick.
    next_dial: Instant,
}

enum LinkState {
    Idle,
    /// A Hello is outstanding.
    HelloSent(Box<OutstandingHandshake>),
    Established {
        session_id: SessionId,
        peer_id: PeerId,
    },
}

pub struct MeshDaemon {
    config: MeshNodeConfig,
    transport: Arc<MeshTransport>,
    socket: Arc<UdpSocket>,
    stats: Arc<Stats>,
    /// Non-blocking handoff keeps inline bus fan-out off the UDP data path.
    observer_tx: mpsc::Sender<LightconeWireFrame>,
    observer_reported_drops: AtomicU64,
    inbound_tx: mpsc::Sender<MeshInbound>,
    /// Set by `net.transport.killswitch.command`; while set, no payload is
    /// sealed or sent. Cover traffic also stops, because cover is traffic.
    killed: AtomicBool,
    kill_switch_state: Mutex<KillSwitchState>,
    /// Source-validating gate in front of the handshake verification.
    gate: HandshakeGate,
    /// Reassembles fragmented handshake datagrams.
    reassembler: Reassembler,
    /// Identifier for the next fragmented handshake message.
    next_message_id: AtomicU32,
    /// Cached operator-signed binding for this node's own identity. Minting
    /// one costs an ML-DSA-65 signature, so it is reused until it nears expiry
    /// rather than re-signed on every handshake.
    own_binding: Mutex<Option<IdentityBinding>>,
    /// Per-peer link state, keyed by peer id.
    ///
    /// A responder has no entry until a Hello arrives, which is why this is a
    /// map built on demand rather than a fixed table from configuration.
    links: Mutex<HashMap<PeerId, Link>>,
    hardening_sub: Mutex<Option<JoinHandle<()>>>,
}

impl MeshDaemon {
    /// Bind the socket and build the daemon, returning it with the receiving
    /// end of its delivery queue.
    pub async fn bind(
        config: MeshNodeConfig,
        bus: Arc<BusPublisher>,
    ) -> Result<(Arc<Self>, mpsc::Receiver<MeshInbound>), DaemonError> {
        let socket = UdpSocket::bind(config.bind_addr).await?;
        Ok(Self::with_socket(config, bus, socket))
    }

    /// Build a daemon over an already-bound socket. Useful for tests that need
    /// the concrete local address before construction.
    pub fn with_socket(
        config: MeshNodeConfig,
        bus: Arc<BusPublisher>,
        socket: UdpSocket,
    ) -> (Arc<Self>, mpsc::Receiver<MeshInbound>) {
        let peer_manager = Arc::new(PeerManager::new());
        let session_manager = Arc::new(SessionManager::new());
        let transport = Arc::new(MeshTransport::new(
            Arc::clone(&bus),
            Arc::clone(&peer_manager),
            Arc::clone(&session_manager),
            config.peer_id.clone(),
        ));
        // Apply hardening profiles from the bus exactly as the rest of the
        // workspace does.
        let hardening_sub = transport.subscribe_hardening_profiles(&bus);

        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE);
        let stats = Arc::new(Stats::new());
        let (observer_tx, mut observer_rx) =
            mpsc::channel::<LightconeWireFrame>(LIGHTCONE_OBSERVER_QUEUE);
        let observer_bus = Arc::clone(&bus);
        let observer_stats = Arc::clone(&stats);
        tokio::spawn(async move {
            while let Some(frame) = observer_rx.recv().await {
                let observation = match frame.format {
                    LightconeFrameFormat::Ethernet => decode(&frame.bytes),
                    LightconeFrameFormat::RawIp => decode_raw_ip(&frame.bytes),
                    LightconeFrameFormat::MeshDatagram => decode_mesh_datagram(&frame.bytes),
                };
                let structure = LightconeStructure {
                    direction: frame.direction,
                    format: frame.format,
                    observation_kind: observation.kind as u8,
                    seeds: observation.seeds.to_vec(),
                    query_hash: imperium_net_world::hash(&frame.bytes),
                };
                drop(frame);
                match BusEvent::publish(
                    &observer_bus,
                    LIGHTCONE_FRAME_TOPIC,
                    Message::LightconeStructure(structure),
                ) {
                    Ok(()) => {
                        observer_stats
                            .lightcone_observations_published
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(error) => {
                        observer_stats
                            .lightcone_publish_errors
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(%error, "passive Lightcone frame publication failed");
                    }
                }
            }
        });

        let daemon = Arc::new(Self {
            config,
            transport,
            socket: Arc::new(socket),
            links: Mutex::new(HashMap::new()),
            stats,
            observer_tx,
            observer_reported_drops: AtomicU64::new(0),
            inbound_tx,
            killed: AtomicBool::new(false),
            kill_switch_state: Mutex::new(KillSwitchState::Disarmed),
            gate: HandshakeGate::new(),
            reassembler: Reassembler::new(),
            next_message_id: AtomicU32::new(1),
            own_binding: Mutex::new(None),
            hardening_sub: Mutex::new(Some(hardening_sub)),
        });
        // Subscribe to operator kill-switch commands. The daemon owns the data
        // path, so it is the component that can actually stop traffic; the
        // control socket only publishes intent.
        daemon.subscribe_killswitch(&bus);
        daemon.publish_killswitch_status(&bus);
        (daemon, inbound_rx)
    }

    /// Offer the exact UDP payload bytes without waiting for bus fan-out or
    /// causal admission. A full observer queue drops only the observation.
    fn queue_lightcone_frame(
        &self,
        format: LightconeFrameFormat,
        direction: u8,
        bytes: &[u8],
    ) -> bool {
        match self.observer_tx.try_reserve() {
            Ok(permit) => {
                permit.send(LightconeWireFrame {
                    format,
                    direction,
                    bytes: bytes.to_vec(),
                });
                self.stats
                    .lightcone_observations_queued
                    .fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.stats
                    .lightcone_observations_dropped
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Queue an exact host TUN packet for passive structural observation.
    /// `true` means queued, not admitted or receipted; `false` means the
    /// observer was full or closed. Neither result changes packet delivery.
    pub fn observe_raw_ip(&self, direction: WireDirection, bytes: &[u8]) -> bool {
        let direction = match direction {
            WireDirection::Inbound => LIGHTCONE_INBOUND,
            WireDirection::Outbound => LIGHTCONE_OUTBOUND,
        };
        self.queue_lightcone_frame(LightconeFrameFormat::RawIp, direction, bytes)
    }

    /// A successful socket send is the observation boundary. Preparation of
    /// a frame alone must never produce a wire-send observation.
    async fn send_observed(&self, bytes: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        let sent = self.socket.send_to(bytes, target).await?;
        let _ = self.queue_lightcone_frame(
            LightconeFrameFormat::MeshDatagram,
            LIGHTCONE_OUTBOUND,
            &bytes[..sent],
        );
        Ok(sent)
    }

    fn try_send_observed(&self, bytes: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        let sent = self.socket.try_send_to(bytes, target)?;
        let _ = self.queue_lightcone_frame(
            LightconeFrameFormat::MeshDatagram,
            LIGHTCONE_OUTBOUND,
            &bytes[..sent],
        );
        Ok(sent)
    }

    /// This node's operator-signed identity binding, minted once and reused.
    ///
    /// Re-minted when it comes within a quarter of its lifetime of expiry, so a
    /// peer is never handed one that would expire while the handshake is in
    /// flight.
    fn own_binding(&self) -> Result<IdentityBinding, DaemonError> {
        let ttl_secs = self.config.identity_ttl.num_seconds().max(60);
        let refresh_at = Utc::now().timestamp() + ttl_secs / 4;

        let mut cached = self.own_binding.lock();
        if let Some(binding) = cached.as_ref() {
            if binding.expires_at_unix > refresh_at {
                return Ok(binding.clone());
            }
        }
        let binding = MeshNodeConfig::identity_binding_for(
            &self.config.operator_signing_key,
            &self.config.peer_id,
            &self.config.identity_verifying_key,
            &self.config.cluster_id,
            self.config.identity_ttl,
        );
        *cached = Some(binding.clone());
        Ok(binding)
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn stats(&self) -> DaemonStats {
        self.stats.snapshot()
    }

    pub fn config(&self) -> &MeshNodeConfig {
        &self.config
    }

    pub fn transport(&self) -> &Arc<MeshTransport> {
        &self.transport
    }

    pub fn is_established(&self) -> bool {
        self.links
            .lock()
            .values()
            .any(|link| matches!(link.state, LinkState::Established { .. }))
    }

    /// Every peer with an established session, in no particular order.
    pub fn established_peers(&self) -> Vec<(PeerId, SessionId)> {
        self.links
            .lock()
            .values()
            .filter_map(|link| match &link.state {
                LinkState::Established {
                    session_id,
                    peer_id,
                } => Some((peer_id.clone(), session_id.clone())),
                _ => None,
            })
            .collect()
    }

    /// Record a rejected HelloResponse for an outstanding handshake.
    fn note_bad_response(&self, peer_id: &PeerId) {
        let mut links = self.links.lock();
        let Some(link) = links.get_mut(peer_id) else {
            return;
        };
        if let LinkState::HelloSent(state) = &mut link.state {
            state.response_attempts = state.response_attempts.saturating_add(1);
            if state.response_attempts > MAX_RESPONSE_ATTEMPTS {
                tracing::warn!(
                    peer = %peer_id.0,
                    attempts = state.response_attempts,
                    "too many rejected responses; abandoning this handshake attempt"
                );
                link.state = LinkState::Idle;
            }
        }
    }

    /// Whether a handshake toward this peer is outstanding (we dialled and are
    /// waiting). Used to resolve mutual dial.
    fn has_outstanding_hello(&self, peer_id: &PeerId) -> bool {
        self.links
            .lock()
            .get(peer_id)
            .is_some_and(|link| matches!(link.state, LinkState::HelloSent(_)))
    }

    pub fn is_peer_established(&self, peer_id: &PeerId) -> bool {
        self.links
            .lock()
            .get(peer_id)
            .is_some_and(|link| matches!(link.state, LinkState::Established { .. }))
    }

    /// The first established link. Convenient for a single-peer node; use
    /// [`Self::established_peers`] when there may be several.
    pub fn linked_peer(&self) -> Option<(SessionId, PeerId)> {
        self.links
            .lock()
            .values()
            .find_map(|link| match &link.state {
                LinkState::Established {
                    session_id,
                    peer_id,
                } => Some((session_id.clone(), peer_id.clone())),
                _ => None,
            })
    }

    /// Replace a peer's link state, preserving its dial backoff.
    fn set_link(&self, peer_id: &PeerId, state: LinkState) {
        let mut links = self.links.lock();
        let next_dial = links
            .get(peer_id)
            .map(|link| link.next_dial)
            .unwrap_or_else(Instant::now);
        links.insert(peer_id.clone(), Link { state, next_dial });
    }

    /// Push a peer's next dial out, so a peer that is down is retried on a
    /// schedule rather than once per tick.
    fn arm_backoff(&self, peer_id: &PeerId) {
        let backoff = self.config.handshake_retry * self.config.max_handshake_attempts.max(1);
        if let Some(link) = self.links.lock().get_mut(peer_id) {
            link.next_dial = Instant::now() + backoff;
        }
    }

    pub fn kill(&self) {
        self.killed.store(true, Ordering::SeqCst);
        *self.kill_switch_state.lock() = KillSwitchState::Engaged;
    }

    pub fn unkill(&self) {
        self.killed.store(false, Ordering::SeqCst);
        *self.kill_switch_state.lock() = KillSwitchState::Disarmed;
    }

    pub fn is_killed(&self) -> bool {
        self.killed.load(Ordering::SeqCst)
    }

    /// React to operator kill-switch commands published on
    /// `net.transport.killswitch.command`.
    ///
    /// Mapping to what this component can actually do:
    ///
    /// - **Engaged** stops the data path. Nothing is sealed or sent, and cover
    ///   traffic stops with it, because cover is traffic.
    /// - **Armed** is recorded and traffic continues. It does not install a
    ///   host firewall or automatically engage when a link drops.
    /// - **Disarmed** resumes mesh traffic.
    ///
    /// This is the mesh's contribution to a kill switch, not a whole one: it
    /// stops what the mesh carries. Keeping non-tunnel traffic off the wire
    /// when the tunnel is down needs route and firewall state this component
    /// does not own.
    pub fn subscribe_killswitch(self: &Arc<Self>, publisher: &Arc<BusPublisher>) {
        // Apply the safety command inline on the publisher's thread. A bounded
        // async queue could discard ENGAGE under load while reporting success.
        let daemon = Arc::downgrade(self);
        let status_bus = Arc::downgrade(publisher);
        publisher.subscribe_exact(
            KILLSWITCH_TOPIC,
            Box::new(move |_socket, payload| {
                let Ok(event) = payload.downcast::<BusEvent>() else {
                    return;
                };
                let Message::KillSwitchCommand(command) = event.message else {
                    return;
                };
                let (Some(daemon), Some(bus)) = (daemon.upgrade(), status_bus.upgrade()) else {
                    return;
                };
                match command.state {
                    KillSwitchState::Engaged => {
                        daemon.kill();
                        tracing::warn!(reason = %command.reason, "mesh data path stopped");
                    }
                    KillSwitchState::Armed => {
                        daemon.unkill();
                        *daemon.kill_switch_state.lock() = KillSwitchState::Armed;
                        tracing::info!(reason = %command.reason, "mesh kill switch armed");
                    }
                    KillSwitchState::Disarmed => {
                        daemon.unkill();
                        tracing::info!(reason = %command.reason, "mesh data path resumed");
                    }
                }
                daemon.publish_killswitch_status(&bus);
            }),
        );
    }

    fn publish_killswitch_status(&self, publisher: &BusPublisher) {
        let state = self.kill_switch_state.lock().clone();
        let _ = BusEvent::publish(
            publisher,
            "net.transport.leak_guard.status",
            Message::LeakGuardStatus(LeakGuardStatus {
                dns_guard_enabled: false,
                route_guard_enabled: false,
                kill_switch: state,
                last_violation: None,
                timestamp: Utc::now(),
            }),
        );
    }

    /// Dial every configured peer that has an address. Called once at startup;
    /// the tick re-dials from there.
    pub async fn initiate_all(&self) -> Result<(), DaemonError> {
        let peers: Vec<PeerId> = self
            .config
            .peers
            .iter()
            .map(|peer| peer.peer_id.clone())
            .collect();
        for peer_id in peers {
            self.initiate(&peer_id).await?;
        }
        Ok(())
    }

    /// Begin a handshake toward one configured peer. Safe to call repeatedly;
    /// does nothing if the peer is unknown or its link is not idle.
    pub async fn initiate(&self, peer_id: &PeerId) -> Result<(), DaemonError> {
        let Some(peer) = self
            .config
            .peers
            .iter()
            .find(|peer| &peer.peer_id == peer_id)
            .cloned()
        else {
            return Ok(());
        };
        let Some(peer_addr) = peer.addr else {
            // Accept-only peer: nothing to dial.
            return Ok(());
        };
        let peer_id = peer.peer_id;

        // Arm the backoff before doing any work, so a peer that never answers
        // is retried on a schedule instead of once per tick.
        self.arm_backoff(&peer_id);

        // Fresh KEX keypair per handshake. The public half goes in the Hello;
        // the secret is held until the response arrives.
        let mut rng = OsRng;
        let (secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);

        let session_manager = self.transport.session_manager();
        // A previous session for this peer (or a retry) must be replaced.
        if let Some(existing) = session_manager.get_session_for_peer(&peer_id) {
            session_manager.remove_session(&existing);
        }
        let session_id = session_manager.create_session(peer_id.clone(), peer_addr, true)?;

        let binding = MeshNodeConfig::identity_binding_for(
            &self.config.operator_signing_key,
            &self.config.peer_id,
            &self.config.identity_verifying_key,
            &self.config.cluster_id,
            self.config.identity_ttl,
        );

        let (classical_pubkey, pqc_pubkey) = public.encode_split();
        let hello = MeshHello {
            peer_id: self.config.peer_id.clone(),
            endpoint: self.config.bind_addr,
            classical_pubkey,
            pqc_pubkey,
            session_id: session_id.clone(),
            identity_vk: encode_identity_vk(&self.config.identity_verifying_key),
            identity_grant: binding.encode(),
            handshake_signature: Vec::new(),
        };
        let signature = HybridEd25519Mldsa::sign(
            &self.config.identity_signing_key,
            &hello_signed_payload(&hello),
        );
        let hello = MeshHello {
            handshake_signature: signature.to_bytes(),
            ..hello
        };

        let datagram = wire::encode_hello(&hello)?;
        self.stats
            .handshake_datagram_bytes
            .fetch_max(datagram.len() as u64, Ordering::Relaxed);
        self.send_handshake(&datagram, peer_addr).await;

        self.set_link(
            &peer_id,
            LinkState::HelloSent(Box::new(OutstandingHandshake {
                hello,
                secret,
                cookie: None,
                response_attempts: 0,
                attempts: 1,
                last_sent: Instant::now(),
            })),
        );
        Ok(())
    }

    /// Run until `shutdown` is notified. Never returns on its own.
    pub async fn run(self: Arc<Self>, shutdown: Arc<Notify>) -> Result<(), DaemonError> {
        // Dial every configured peer.
        self.initiate_all().await?;

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut tick = tokio::time::interval(TICK);
        let mut tick_count: u64 = 0;

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    tracing::info!("mesh daemon shutting down");
                    if let Some(handle) = self.hardening_sub.lock().take() {
                        handle.abort();
                    }
                    return Ok(());
                }
                received = self.socket.recv_from(&mut buf) => {
                    match received {
                        Ok((len, source)) => {
                            self.stats.datagrams_received.fetch_add(1, Ordering::Relaxed);
                            let _ = self.queue_lightcone_frame(
                                LightconeFrameFormat::MeshDatagram,
                                LIGHTCONE_INBOUND,
                                &buf[..len],
                            );
                            self.handle_datagram(source, &buf[..len]).await;
                        }
                        Err(error) => {
                            // A UDP receive error is per-datagram on some
                            // platforms; log and keep the loop alive.
                            tracing::warn!(%error, "mesh recv failed");
                        }
                    }
                }
                _ = tick.tick() => {
                    tick_count += 1;
                    self.on_tick(tick_count).await;
                }
            }
        }
    }

    async fn on_tick(&self, tick_count: u64) {
        if tick_count % 4 == 0 {
            let dropped = self
                .stats
                .lightcone_observations_dropped
                .load(Ordering::Relaxed);
            let reported = self
                .observer_reported_drops
                .swap(dropped, Ordering::Relaxed);
            if dropped > reported {
                tracing::warn!(
                    new_drops = dropped - reported,
                    total_drops = dropped,
                    "passive Lightcone observer queue dropped frames"
                );
            }
        }
        // Rotate the gate's cookie secret so a captured cookie is only useful
        // for one epoch.
        if self.gate.rotate_if_due(Instant::now()) {
            tracing::debug!("mesh handshake gate secret rotated");
        }

        // Self-healing, per peer: a link that fell to idle — never started,
        // gave up retransmitting, or lost its session to expiry — is dialled
        // again once its backoff has elapsed. Without this a link that dropped
        // once stayed down until the process was restarted.
        let configured: Vec<PeerId> = self
            .config
            .peers
            .iter()
            .map(|peer| peer.peer_id.clone())
            .collect();
        for peer_id in &configured {
            self.retransmit_if_due(peer_id).await;

            let idle = {
                let links = self.links.lock();
                match links.get(peer_id) {
                    Some(link) => matches!(link.state, LinkState::Idle),
                    // Never dialled: treat a missing entry as idle.
                    None => true,
                }
            };
            if idle {
                let due = self
                    .links
                    .lock()
                    .get(peer_id)
                    .map(|link| Instant::now() >= link.next_dial)
                    .unwrap_or(true);
                if due {
                    if let Err(error) = self.initiate(peer_id).await {
                        tracing::debug!(%error, peer = %peer_id.0, "mesh re-initiate failed");
                    }
                }
            }
        }

        if self.is_established() && !self.is_killed() {
            self.emit_cover_if_due().await;
        }

        if tick_count.is_multiple_of(EXPIRY_TICKS) {
            let expired = self
                .transport
                .session_manager()
                .expire_stale_sessions(self.config.session_idle_secs);
            if !expired.is_empty() {
                self.stats
                    .sessions_expired
                    .fetch_add(expired.len() as u64, Ordering::Relaxed);
                // Any session we were relying on is gone; go back to idle and
                // let the handshake timer rebuild the link.
                for session_id in &expired {
                    let owner = self
                        .links
                        .lock()
                        .iter()
                        .find(|(_, link)| {
                            matches!(&link.state,
                                LinkState::Established { session_id: current, .. }
                                    if current == session_id)
                        })
                        .map(|(peer, _)| peer.clone());
                    if let Some(peer) = owner {
                        self.set_link(&peer, LinkState::Idle);
                    }
                }
            }
        }
    }

    async fn retransmit_if_due(&self, peer_id: &PeerId) {
        let Some(peer_addr) = self
            .config
            .peers
            .iter()
            .find(|peer| &peer.peer_id == peer_id)
            .and_then(|peer| peer.addr)
        else {
            return;
        };

        // Build the datagram while holding the lock, then RELEASE it before
        // awaiting the send: a parking_lot guard is not Send and holding one
        // across an await makes the whole daemon future non-Send.
        let datagram = {
            let mut links = self.links.lock();
            let Some(link) = links.get_mut(peer_id) else {
                return;
            };
            let LinkState::HelloSent(state) = &mut link.state else {
                return;
            };

            if state.last_sent.elapsed() < self.config.handshake_retry {
                return;
            }
            if state.attempts >= self.config.max_handshake_attempts {
                tracing::warn!(
                    attempts = state.attempts,
                    peer = %peer_id.0,
                    "mesh handshake gave up; link returns to idle"
                );
                link.state = LinkState::Idle;
                return;
            }
            match wire::encode_hello(&state.hello) {
                Ok(plain) => match state.cookie {
                    // Once the peer has issued a cookie, every retransmit
                    // carries the gate MAC. Re-sending the plain Hello would
                    // only earn another cookie and waste a round trip.
                    Some(cookie) => {
                        let mac = HandshakeGate::mac_for(&cookie, &plain);
                        match wire::encode_gated_hello(&plain, &mac) {
                            Ok(gated) => gated,
                            Err(_) => {
                                link.state = LinkState::Idle;
                                return;
                            }
                        }
                    }
                    None => plain,
                },
                Err(_) => {
                    link.state = LinkState::Idle;
                    return;
                }
            }
        };

        self.send_handshake(&datagram, peer_addr).await;
        {
            let mut links = self.links.lock();
            if let Some(Link {
                state: LinkState::HelloSent(state),
                ..
            }) = links.get_mut(peer_id)
            {
                state.attempts += 1;
                state.last_sent = Instant::now();
            }
        }
        self.stats
            .handshake_retransmits
            .fetch_add(1, Ordering::Relaxed);
    }

    async fn emit_cover_if_due(&self) {
        // Per link, not once per tick: emitting on only one link while others
        // carried real traffic would leave those others distinguishable by
        // their silence, which is the property cover traffic exists to remove.
        // The hardener's budget is consulted per link, so each gets its chance.
        for (peer_id, session_id) in self.established_peers() {
            let Some(peer_addr) = self
                .transport
                .session_manager()
                .session_remote_addr(&session_id)
            else {
                continue;
            };
            let Some(frame) = self
                .transport
                .take_cover_frame(&session_id, crate::peer::peer_token(&peer_id))
            else {
                continue;
            };
            // Honour the profile's jitter. Nothing did before: the hardener
            // computed a delay in `build_frame` and no send path ever slept on
            // it, so the traffic-morph profile was partly cosmetic.
            if !frame.delay.is_zero() {
                tokio::time::sleep(frame.delay).await;
            }
            match self.send_observed(&frame.bytes, peer_addr).await {
                Ok(_) => {
                    self.stats.cover_frames_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(error) => {
                    tracing::debug!(%error, peer = %peer_id.0, "cover frame send failed")
                }
            }
        }
    }

    async fn handle_datagram(&self, source: SocketAddr, bytes: &[u8]) {
        let Some(kind) = wire::classify(bytes) else {
            self.stats
                .datagrams_unclassified
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        if kind == DatagramKind::Handshake(HandshakeKind::Fragment) {
            self.on_fragment(source, bytes).await;
            return;
        }
        self.dispatch(source, bytes, kind).await;
    }

    /// Dispatch a datagram that is known NOT to be a fragment.
    ///
    /// Kept separate from `handle_datagram` on purpose: reassembled bytes are
    /// attacker-controlled, so a reassembled datagram that was itself a
    /// fragment would recurse without bound and overflow the stack. This path
    /// refuses fragments outright, which makes that impossible rather than
    /// merely unlikely.
    async fn dispatch(&self, source: SocketAddr, bytes: &[u8], kind: DatagramKind) {
        match kind {
            // An ungated Hello is never verified. It only earns a cookie.
            DatagramKind::Handshake(HandshakeKind::Hello) => self.on_plain_hello(source),
            DatagramKind::Handshake(HandshakeKind::GatedHello) => {
                self.on_gated_hello(source, bytes).await
            }
            DatagramKind::Handshake(HandshakeKind::Cookie) => self.on_cookie(source, bytes).await,
            DatagramKind::Handshake(HandshakeKind::HelloResponse) => {
                self.on_hello_response(source, bytes).await
            }
            DatagramKind::Frame => self.on_frame(source, bytes),
            DatagramKind::Handshake(HandshakeKind::Fragment) => {
                self.stats
                    .handshake_fragments_rejected
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%source, "reassembled datagram was itself a fragment; refused");
            }
        }
    }

    /// Reassemble a handshake fragment and process the message it completes.
    ///
    /// NOT rate limited by the handshake token bucket, deliberately. A
    /// handshake message is ~12 KB of hybrid post-quantum material, which is
    /// ten-odd fragments, and charging a token per fragment meant one legitimate
    /// handshake spent more than the whole burst and starved itself. The cost
    /// here is bounded structurally instead: the reassembly table caps partial
    /// messages per source and in total, each chunk is bounded, and an
    /// incomplete message is swept on a timeout. The expensive path — the
    /// signature verification — is still gated, because that happens at
    /// dispatch of the completed message, not here.
    async fn on_fragment(&self, source: SocketAddr, bytes: &[u8]) {
        let Ok((message_id, index, count, chunk)) = wire::split_fragment(bytes) else {
            self.stats
                .handshake_fragments_rejected
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(complete) =
            self.reassembler
                .accept(source, message_id, index, count, chunk, Instant::now())
        else {
            return;
        };
        self.stats
            .handshake_datagrams_reassembled
            .fetch_add(1, Ordering::Relaxed);

        // Dispatch, never re-enter `handle_datagram`: see `dispatch`.
        let Some(kind) = wire::classify(&complete) else {
            self.stats
                .handshake_fragments_rejected
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.dispatch(source, &complete, kind).await;
    }

    /// Send a handshake datagram, fragmenting it when it exceeds the fragment
    /// size.
    ///
    /// Hybrid post-quantum material makes a handshake datagram far larger than
    /// any path MTU, and relying on IP fragmentation means relying on
    /// middleboxes that drop it.
    async fn send_handshake(&self, datagram: &[u8], target: SocketAddr) {
        let message_id = self.next_message_id.fetch_add(1, Ordering::Relaxed);
        match wire::fragment(datagram, message_id) {
            Ok(pieces) => {
                for piece in pieces {
                    if let Err(error) = self.send_observed(&piece, target).await {
                        tracing::warn!(%error, %target, "handshake send failed");
                        return;
                    }
                }
            }
            Err(error) => tracing::warn!(%error, "handshake datagram could not be fragmented"),
        }
    }

    /// First half of the gate: answer an ungated Hello with a cookie and do
    /// nothing else. No JSON parsing, no signature work, no per-source state —
    /// one HMAC and one datagram out.
    ///
    /// The rate limit is checked first so a flood is dropped before even the
    /// cookie HMAC is spent.
    fn on_plain_hello(&self, source: SocketAddr) {
        if !self.gate.admit(source.ip(), Instant::now()) {
            self.stats
                .handshake_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%source, "mesh hello rate limited");
            return;
        }
        let cookie = self.gate.cookie(source);
        let wire_cookie = wire::encode_cookie(&cookie);
        if let Err(error) = self.try_send_observed(&wire_cookie, source) {
            // A refused send needs no reply; UDP has no session to preserve.
            tracing::debug!(%error, %source, "cookie send failed");
            return;
        }
        self.stats
            .handshake_cookies_sent
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Second half of the gate: a Hello claiming a completed cookie round trip.
    /// The gate MAC is checked against the source address before anything
    /// expensive runs, so a spoofed source never reaches verification.
    async fn on_gated_hello(&self, source: SocketAddr, bytes: &[u8]) {
        if !self.gate.admit(source.ip(), Instant::now()) {
            self.stats
                .handshake_rate_limited
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let Ok((hello_datagram, gate_mac)) = wire::split_gated_hello(bytes) else {
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%source, "mesh gated hello is malformed");
            return;
        };
        // Cheap: an HMAC over the exact bytes. This is what stands between an
        // arbitrary datagram and a post-quantum signature verification.
        if !self
            .gate
            .mac_valid_for_source(source, hello_datagram, gate_mac)
        {
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            // Warn, not debug: the gate admits before this check, so a
            // rejection here is rare enough to be worth seeing, and a
            // handshake that never completes is otherwise invisible.
            tracing::warn!(%source, "mesh gated hello failed the source gate");
            return;
        }

        let Ok(hello) = wire::decode_hello(hello_datagram) else {
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%source, "mesh gated hello does not decode");
            return;
        };

        // Past the gate, and only now is the expensive path reachable: a hybrid
        // Ed25519 + ML-DSA-65 verification, from an address that has proven it
        // can receive where it claims to be.
        self.stats
            .handshake_verifications
            .fetch_add(1, Ordering::Relaxed);

        // The membership predicate captures our own id and the expected id,
        // never the received Hello, so the Hello stays borrowable below.
        // Membership is the configured peer list. Empty means accept any peer
        // whose identity the operator has bound, which is a responder that has
        // not been told who to expect.
        let configured: Vec<PeerId> = self
            .config
            .peers
            .iter()
            .map(|peer| peer.peer_id.clone())
            .collect();
        let claimed_peer = hello.peer_id.clone();
        let is_member =
            move || configured.is_empty() || configured.iter().any(|peer| peer == &claimed_peer);
        let binding = match verify_hello(
            &hello,
            &self.config.operator_verifying_key.clone(),
            &self.config.cluster_id,
            Utc::now().timestamp(),
            is_member,
        ) {
            Ok(binding) => binding,
            Err(error) => {
                tracing::warn!(%error, %source, "mesh hello rejected");
                self.stats
                    .handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let _ = binding;

        // The Hello carries the initiator's packed KEX public key, split at
        // the x25519 boundary, so we can encapsulate toward it.
        let Ok(initiator_kex) =
            HybridKexPublicKey::decode_split(&hello.classical_pubkey, &hello.pqc_pubkey)
        else {
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            return;
        };

        let mut rng = OsRng;
        let (encapsulation, session_key) = HybridX25519Mlkem::encapsulate(&mut rng, &initiator_kex);

        // MUTUAL DIAL. If both nodes dialled each other, both have a handshake
        // outstanding, and adopting unconditionally here would leave each side
        // holding the session the OTHER created: both links report Established,
        // the HelloResponse each sent is discarded (its own link is no longer
        // HelloSent), and nothing can be decrypted. Measured as a total silent
        // black hole before this check existed.
        //
        // The tie-break is the peer ids, which BOTH sides can compare without
        // negotiation: the LOWER id keeps initiating and ignores the incoming
        // Hello, the higher defers and adopts. Exactly one handshake survives,
        // and both sides compute the same answer.
        if self.has_outstanding_hello(&hello.peer_id)
            && self.config.peer_id.0.as_bytes() < hello.peer_id.0.as_bytes()
        {
            tracing::debug!(
                %source,
                peer = %hello.peer_id.0,
                "mutual dial: keeping our own handshake as the lower peer id"
            );
            return;
        }

        let session_manager = self.transport.session_manager();
        // Re-handshake for a peer we already know must replace the session.
        if let Some(existing) = session_manager.get_session_for_peer(&hello.peer_id) {
            session_manager.remove_session(&existing);
        }
        // Bind the session to the address the datagram ACTUALLY came from, not
        // the endpoint the initiator advertised: behind NAT those differ, and
        // the live source is the only one that reaches back.
        if let Err(error) = session_manager.adopt_session(
            hello.session_id.clone(),
            hello.peer_id.clone(),
            source,
            false,
        ) {
            tracing::debug!(%error, "mesh session adopt failed");
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Bind the direction keys to the two operator-certified identities, in
        // the role-fixed order both sides know: initiator first, responder
        // second. `verify_hello` above proved the initiator's identity is bound
        // to the peer id it claimed, so these bytes are operator-certified.
        let our_identity = encode_identity_vk(&self.config.identity_verifying_key);
        if let Err(error) = session_manager.establish_session(
            &hello.session_id,
            session_key,
            &hello.identity_vk,
            &our_identity,
        ) {
            tracing::debug!(%error, "mesh session establish failed");
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        session_manager.touch_session(&hello.session_id);

        let peer_manager = self.transport.peer_manager();
        peer_manager.add_peer(hello.peer_id.clone(), vec![source]);
        peer_manager.set_session(&hello.peer_id, hello.session_id.clone());

        // Reply, signed by our identity key over the transcript hash so the
        // response is bound to this exact Hello.
        // Our own operator-signed binding goes in the response, so the peer can
        // check that the identity key answering belongs to the peer id claiming
        // it. Without this the response's identity is self-asserted.
        let Ok(own_binding) = self.own_binding() else {
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            return;
        };

        let (classical_pubkey, pqc_ciphertext) = encapsulation.encode_split();
        let response = MeshHelloResponse {
            peer_id: self.config.peer_id.clone(),
            endpoint: self.config.bind_addr,
            classical_pubkey,
            pqc_ciphertext,
            session_id: hello.session_id.clone(),
            identity_vk: encode_identity_vk(&self.config.identity_verifying_key),
            identity_grant: own_binding.encode(),
            handshake_signature: Vec::new(),
        };
        let signed = response_signed_payload(&response, &hello_transcript_hash(&hello));
        let signature = HybridEd25519Mldsa::sign(&self.config.identity_signing_key, &signed);
        let response = MeshHelloResponse {
            handshake_signature: signature.to_bytes(),
            ..response
        };

        let Ok(datagram) = wire::encode_hello_response(&response) else {
            return;
        };
        self.send_handshake(&datagram, source).await;

        self.stats
            .handshakes_completed
            .fetch_add(1, Ordering::Relaxed);
        let peer_id = hello.peer_id.clone();
        self.set_link(
            &peer_id,
            LinkState::Established {
                session_id: hello.session_id,
                peer_id: peer_id.clone(),
            },
        );
    }

    /// The responder handed us a cookie. Store it and immediately re-send the
    /// Hello carrying a gate MAC over its own bytes, so the responder can check
    /// the source address before doing any verification work.
    ///
    /// This is one extra round trip per handshake, paid once, and only when the
    /// peer asks for it.
    async fn on_cookie(&self, source: SocketAddr, bytes: &[u8]) {
        let Ok(cookie) = wire::decode_cookie(bytes) else {
            return;
        };
        if cookie.len() != COOKIE_LEN {
            return;
        }
        let mut cookie_bytes = [0u8; COOKIE_LEN];
        cookie_bytes.copy_from_slice(cookie);

        // Build under the lock, send outside it: a parking_lot guard is not
        // Send, so holding one across an await would make this future non-Send.
        // A cookie answers the Hello we sent to this address, so the peer is
        // the one configured at it.
        let Some(peer_id) = self
            .config
            .peers
            .iter()
            .find(|peer| peer.addr == Some(source))
            .map(|peer| peer.peer_id.clone())
        else {
            tracing::debug!(%source, "cookie from an address no peer is configured at");
            return;
        };

        let gated = {
            let mut links = self.links.lock();
            let Some(Link {
                state: LinkState::HelloSent(state),
                ..
            }) = links.get_mut(&peer_id)
            else {
                // A cookie with no hello outstanding is either late (the
                // handshake already completed) or unsolicited. Neither needs
                // an answer.
                return;
            };
            state.cookie = Some(cookie_bytes);
            let Ok(plain) = wire::encode_hello(&state.hello) else {
                return;
            };
            let mac = HandshakeGate::mac_for(&cookie_bytes, &plain);
            match wire::encode_gated_hello(&plain, &mac) {
                Ok(gated) => gated,
                Err(_) => return,
            }
        };
        self.send_handshake(&gated, source).await;
    }

    /// Initiator side: complete the handshake with the responder's reply.
    async fn on_hello_response(&self, source: SocketAddr, bytes: &[u8]) {
        let Ok(response) = wire::decode_hello_response(bytes) else {
            return;
        };

        // A response answers the Hello we sent to this address. Falling back to
        // "the only peer with a handshake outstanding" covers a peer whose
        // address moved between the Hello and the response.
        let peer_id = match self
            .config
            .peers
            .iter()
            .find(|peer| peer.addr == Some(source))
            .map(|peer| peer.peer_id.clone())
        {
            Some(peer_id) => peer_id,
            None => {
                let outstanding: Vec<PeerId> = self
                    .links
                    .lock()
                    .iter()
                    .filter(|(_, link)| matches!(link.state, LinkState::HelloSent(_)))
                    .map(|(peer, _)| peer.clone())
                    .collect();
                if outstanding.len() == 1 {
                    outstanding[0].clone()
                } else {
                    tracing::debug!(%source, "response from an address no peer is configured at");
                    return;
                }
            }
        };

        // BORROW the outstanding Hello to verify against, rather than taking it
        // first. Taking it destroyed the handshake before it had been checked, so
        // any structurally valid HelloResponse — which needs no crypto to forge —
        // aborted a handshake still in flight, and the one-shot secret went with
        // it. A bad response now leaves the attempt intact; the secret is taken
        // only after every check has passed.
        let hello = {
            let links = self.links.lock();
            match links.get(&peer_id) {
                Some(Link {
                    state: LinkState::HelloSent(state),
                    ..
                }) => state.hello.clone(),
                _ => return,
            }
        };

        // The response must come from the peer we dialled, not merely from some
        // configured peer.
        if response.peer_id != peer_id {
            tracing::warn!(
                %source,
                expected = %peer_id.0,
                claimed = %response.peer_id.0,
                "response is not from the peer that was dialled"
            );
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let operator_vk = self.config.operator_verifying_key.clone();
        if let Err(error) = verify_hello_response(
            &response,
            &hello,
            &operator_vk,
            &self.config.cluster_id,
            Utc::now().timestamp(),
        ) {
            tracing::debug!(%error, %source, "mesh hello response rejected");
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            self.note_bad_response(&peer_id);
            return;
        }

        // The responder must be one we are configured to talk to, when we are
        // configured at all. `verify_hello_response` above already proved the
        // identity is operator-bound to this peer id; this checks that the peer
        // id is one we asked for.
        if !self.config.peers.is_empty()
            && !self
                .config
                .peers
                .iter()
                .any(|peer| peer.peer_id == response.peer_id)
        {
            tracing::warn!(
                claimed = %response.peer_id.0,
                "responder is not a configured peer"
            );
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            self.note_bad_response(&peer_id);
            return;
        }
        // Belt and braces: an operator may require one specific identity key.
        // The binding above makes the identity authoritative without this, and
        // the comparison covers the whole encoded key — both halves.
        if let Some(expected_vk) = self
            .config
            .peers
            .iter()
            .find(|peer| peer.peer_id == response.peer_id)
            .and_then(|peer| peer.pinned_identity_vk.as_ref())
        {
            let Ok(responder_vk) = crate::handshake::decode_identity_vk(&response.identity_vk)
            else {
                self.stats
                    .handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            if encode_identity_vk(&responder_vk) != encode_identity_vk(expected_vk) {
                tracing::warn!(%source, "responder identity does not match the pinned key");
                self.stats
                    .handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                self.note_bad_response(&peer_id);
                return;
            }
        }

        // Rebuild the encapsulation from the response's two fields and
        // decapsulate exactly once.
        let Ok(encapsulation) =
            HybridEncapsulation::decode_split(&response.classical_pubkey, &response.pqc_ciphertext)
        else {
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            self.note_bad_response(&peer_id);
            return;
        };
        // Every check has passed. NOW take the one-shot secret, which
        // decapsulation consumes. Taking it earlier meant a forged response
        // could destroy a handshake that was still in flight.
        let secret = {
            let mut links = self.links.lock();
            let Some(link) = links.get_mut(&peer_id) else {
                return;
            };
            match std::mem::replace(&mut link.state, LinkState::Idle) {
                LinkState::HelloSent(state) => state.secret,
                other => {
                    link.state = other;
                    return;
                }
            }
        };

        let session_key = match HybridX25519Mlkem::decapsulate(secret, &encapsulation) {
            Ok(key) => key,
            Err(error) => {
                tracing::debug!(%error, "mesh decapsulation failed");
                self.stats
                    .handshake_failures
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        let session_manager = self.transport.session_manager();
        // Role-fixed order, same as the responder: the initiator's identity
        // first. Here that is OUR identity from the Hello, then the responder's
        // from the response.
        if let Err(error) = session_manager.establish_session(
            &hello.session_id,
            session_key,
            &hello.identity_vk,
            &response.identity_vk,
        ) {
            tracing::debug!(%error, "mesh session establish failed");
            self.stats
                .handshake_failures
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Learn the address the responder is actually reachable at.
        session_manager.rebind_session_addr(&hello.session_id, source);
        session_manager.touch_session(&hello.session_id);

        self.transport
            .peer_manager()
            .add_peer(response.peer_id.clone(), vec![source]);
        self.transport
            .peer_manager()
            .set_session(&response.peer_id, hello.session_id.clone());

        self.stats
            .handshakes_completed
            .fetch_add(1, Ordering::Relaxed);
        let peer_id = response.peer_id.clone();
        self.set_link(
            &peer_id,
            LinkState::Established {
                session_id: hello.session_id,
                peer_id: peer_id.clone(),
            },
        );
        tracing::info!(%source, peer = %peer_id.0, "mesh handshake complete");
    }

    /// Data frame: resolve the session from the source address, then decrypt.
    fn on_frame(&self, source: SocketAddr, bytes: &[u8]) {
        let session_manager = self.transport.session_manager();

        // Decide which session this belongs to, and OPEN IT EXACTLY ONCE.
        //
        // That constraint shapes this function: opening a frame consumes its
        // counter into the replay window, so a "try it and then open it
        // properly" shape fails on the second attempt with a replay error.
        // Whichever path succeeds therefore hands its result forward.
        let (session_id, recovered, rebound) =
            if let Some(session) = session_manager.session_for_addr(&source) {
                // Fast path: the address already associated with a session.
                match self.transport.process_incoming(&session, bytes) {
                    Ok(recovered) => (session, recovered, false),
                    Err(error) => {
                        self.stats.frames_failed.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(%error, %source, "mesh frame rejected");
                        return;
                    }
                }
            } else {
                // NAT path. A session is keyed to the address the peer was last
                // reachable at, and behind NAT that changes mid-session, so the
                // fast path cannot match. Every established session is a candidate
                // and the AEAD decides: a wrong one fails to open, which costs a
                // symmetric decryption rather than a signature check.
                //
                // Rate limited, because an unmatched datagram compels that work:
                // one token buys a bounded number of attempts.
                if !self.gate.admit(source.ip(), Instant::now()) {
                    self.stats.frames_failed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let mut opened = None;
                for candidate in self.fallback_sessions() {
                    if let Ok(recovered) = self.transport.process_incoming(&candidate, bytes) {
                        opened = Some((candidate, recovered));
                        break;
                    }
                }
                match opened {
                    Some((session, recovered)) => (session, recovered, true),
                    None => {
                        self.stats.frames_failed.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(%source, "mesh frame opened with no session");
                        return;
                    }
                }
            };

        self.stats.frames_opened.fetch_add(1, Ordering::Relaxed);
        session_manager.touch_session(&session_id);
        if rebound {
            // The peer's address changed and this frame authenticated, so the
            // new address is real. Rebind and the fast path resumes for
            // everything that follows.
            session_manager.rebind_session_addr(&session_id, source);
            self.stats.nat_rebinds.fetch_add(1, Ordering::Relaxed);
            tracing::info!(%source, "peer address changed; session rebound (NAT)");
        }
        if recovered.cover || recovered.payload.is_empty() {
            self.stats
                .cover_frames_received
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.is_killed() {
            // A kill switch must suppress inbound payloads too; otherwise an
            // authenticated peer can still inject packets into the host TUN.
            self.stats.payloads_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let peer_id = session_manager
            .session_peer_id(&session_id)
            .unwrap_or_else(|| self.config.peer_id.clone());
        let inbound = MeshInbound {
            peer_id,
            session_id,
            counter: recovered.counter,
            payload: recovered.payload,
        };
        match self.inbound_tx.try_send(inbound) {
            Ok(_) => {
                self.stats
                    .payloads_delivered
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                // Never block the network loop on a slow consumer.
                self.stats.payloads_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Seal a payload into a wire frame WITHOUT sending it.
    ///
    /// Separated from sending so the frame can be inspected, and so a test can
    /// tamper with a real frame and prove the live receive path rejects it.
    pub async fn seal_payload_frame(&self, payload: &[u8]) -> Result<Vec<u8>, DaemonError> {
        let peer = self
            .peer_for_payload(payload)
            .ok_or(DaemonError::NoSession)?;
        self.seal_for_peer(&peer, payload).await
    }

    /// Seal a payload for a specific peer, without sending it.
    pub async fn seal_for_peer(
        &self,
        peer_id: &PeerId,
        payload: &[u8],
    ) -> Result<Vec<u8>, DaemonError> {
        let session_manager = self.transport.session_manager();
        let session_id = session_manager
            .get_session_for_peer(peer_id)
            .filter(|session_id| session_manager.session_belongs_to_peer(session_id, peer_id))
            .filter(|_| self.is_peer_established(peer_id))
            .ok_or(DaemonError::NoSession)?;
        let (counter, ciphertext) = match session_manager.seal_for_session(
            &session_id,
            payload,
            self.config.session_max_bytes,
        ) {
            Ok(sealed) => sealed,
            Err(SessionError::RekeyRequired) => {
                // The budget is spent. Rotate by tearing the session down and
                // letting the tick re-handshake, which establishes a genuinely
                // new key. The payload that tripped the limit is dropped: it is
                // one packet, and holding it would need a queue whose own
                // bounds would be the next bug.
                if let Some(peer) = self
                    .transport
                    .session_manager()
                    .session_peer_id(&session_id)
                {
                    self.rotate_session(&peer, &session_id);
                }
                return Err(DaemonError::Session(SessionError::RekeyRequired));
            }
            Err(other) => return Err(DaemonError::Session(other)),
        };
        let frame = self.transport.harden_payload_for_send(counter, ciphertext);
        if !frame.delay.is_zero() {
            tokio::time::sleep(frame.delay).await;
        }
        Ok(frame.bytes)
    }

    /// Seal and send a payload to whichever peer its destination belongs to.
    pub async fn send_payload(&self, payload: &[u8]) -> Result<(), DaemonError> {
        let peer = self
            .peer_for_payload(payload)
            .ok_or(DaemonError::NoSession)?;
        self.send_payload_to(&peer, payload).await
    }

    /// Seal and send a payload to a named peer.
    pub async fn send_payload_to(
        &self,
        peer_id: &PeerId,
        payload: &[u8],
    ) -> Result<(), DaemonError> {
        if self.is_killed() {
            // NOT `Ok(())`: see `SuppressedByKillSwitch`.
            return Err(DaemonError::SuppressedByKillSwitch);
        }
        let session_manager = self.transport.session_manager();
        let session_id = session_manager
            .get_session_for_peer(peer_id)
            .filter(|session_id| session_manager.session_belongs_to_peer(session_id, peer_id))
            .ok_or(DaemonError::NoSession)?;
        let Some(peer_addr) = session_manager.session_remote_addr(&session_id) else {
            return Err(DaemonError::NoPeerAddress);
        };
        let frame = self.seal_for_peer(peer_id, payload).await?;
        self.send_observed(&frame, peer_addr).await?;
        Ok(())
    }

    /// The one session an unmatched datagram may be tried against.
    ///
    /// Prefers the configured peer. With no peer configured — a responder that
    /// accepts any operator-bound peer — it uses the only session there is,
    /// which is unambiguous while this daemon holds a single link. Returns
    /// `None` rather than guessing when several sessions exist, because trying
    /// each in turn would multiply the work an unmatched datagram can compel.
    fn fallback_sessions(&self) -> Vec<SessionId> {
        const MAX_ATTEMPTS: usize = 8;
        let established = self.established_peers();

        // Configured peers first, so resolution follows the operator's order
        // rather than a hash order.
        let mut ordered: Vec<SessionId> = Vec::new();
        for peer in &self.config.peers {
            if let Some((_, session)) = established.iter().find(|(id, _)| id == &peer.peer_id) {
                ordered.push(session.clone());
            }
        }
        // A responder has no configured peers, so anything established is a
        // candidate.
        for (_, session) in &established {
            if !ordered.contains(session) {
                ordered.push(session.clone());
            }
        }
        ordered.truncate(MAX_ATTEMPTS);
        ordered
    }

    /// Which peer a payload should go to.
    ///
    /// The payload is an IP packet, so the decision is the packet's own
    /// destination: each peer's configured prefixes are searched longest-prefix
    /// first, and the most specific match wins. That is what makes a node with
    /// several peers behave like a router rather than a hub that must be told
    /// which way to send.
    ///
    /// Falls back to the only established peer when nothing matches, because
    /// with one peer there is nothing to choose between. With several peers and
    /// no matching route it returns `None` rather than guessing: sending a
    /// packet to a peer that has no route to its destination is worse than
    /// dropping it, because it leaks the packet to the wrong network.
    pub fn peer_for_payload(&self, payload: &[u8]) -> Option<PeerId> {
        let established = self.established_peers();
        if established.is_empty() {
            return None;
        }

        if let Some(destination) = ipv4_destination(payload) {
            let mut best: Option<(u8, PeerId)> = None;
            for peer in &self.config.peers {
                if !established.iter().any(|(id, _)| id == &peer.peer_id) {
                    continue;
                }
                for route in &peer.routes {
                    if route.contains(destination)
                        && best.as_ref().is_none_or(|(len, _)| route.prefix > *len)
                    {
                        best = Some((route.prefix, peer.peer_id.clone()));
                    }
                }
            }
            if let Some((_, peer)) = best {
                return Some(peer);
            }
        }

        // Fall back only when there is genuinely nothing to choose between:
        // exactly one CONFIGURED peer, and it is up. The previous condition was
        // "exactly one established session", which is a different question — on
        // a two-peer hub with one peer down or mid-rekey it sent that peer's
        // traffic to the other one, which is the leak this function's own
        // comment says it exists to prevent.
        if let [only] = self.config.peers.as_slice() {
            return established
                .iter()
                .any(|(id, _)| id == &only.peer_id)
                .then(|| only.peer_id.clone());
        }

        // A responder has no configured peers, so it cannot know what any peer
        // serves. With exactly one link there is nothing to choose between.
        if self.config.peers.is_empty() {
            if let [(peer, _)] = established.as_slice() {
                return Some(peer.clone());
            }
        }
        None
    }

    /// Tear a session down so the link rebuilds with a fresh key.
    ///
    /// The tick re-dials an idle link, so this needs no separate retry path.
    /// The session is removed rather than rekeyed in place because there is no
    /// in-session rekey message; re-handshaking is what actually produces new
    /// key material.
    fn rotate_session(&self, peer_id: &PeerId, session_id: &SessionId) {
        tracing::info!(
            session = %session_id.0,
            peer = %peer_id.0,
            budget = ?self.config.session_max_bytes,
            "session key budget spent; rotating by re-handshake"
        );
        self.transport.session_manager().remove_session(session_id);
        self.set_link(peer_id, LinkState::Idle);
        // Let the next tick dial immediately rather than waiting out a backoff.
        if let Some(link) = self.links.lock().get_mut(peer_id) {
            link.next_dial = Instant::now();
        }
        self.stats.sessions_rekeyed.fetch_add(1, Ordering::Relaxed);
    }

    /// Install a hardening profile directly (equivalent to publishing one on
    /// `net.transport.hardening.apply`).
    pub fn apply_hardening_profile(&self, profile: imperium_protocol::ProtocolHardeningProfile) {
        self.transport.apply_hardening_profile(profile);
    }

    /// The currently active hardener, if a profile is applied. Exposed so a
    /// caller can read the profile id and stats.
    pub fn hardening_active(&self) -> bool {
        self.transport.hardening_active()
    }

    /// Wait until a session is established, up to `timeout`.
    pub async fn wait_established(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.is_established() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.is_established()
    }
}

/// The IPv4 destination of a packet, if it is one.
///
/// Deliberately minimal: a version check and four bytes. A full parser belongs
/// in `imperium-net-observer`, which has one; this only needs enough to choose
/// a peer, and anything it cannot parse falls back to the single-peer path.
fn ipv4_destination(payload: &[u8]) -> Option<Ipv4Addr> {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        payload[16],
        payload[17],
        payload[18],
        payload[19],
    ))
}
