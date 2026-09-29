use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use imperium_protocol::BusEvent;
use imperium_protocol::{MeshPing, MeshPong, Message, PeerId, ProtocolHardeningProfile};
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::handshake::{verify_hello, HandshakeError, IdentityBinding};
use crate::hardening::{fallback_frame, HardenedPayload, MeshHardener, RecoveredFrame};
use crate::peer::PeerManager;
use crate::session::SessionManager;
use crate::world_lightcone::{NetworkWorldObservation, NetworkWorldTap, WireDirection};

/// Depth of a consumer-owned subscription queue.
///
/// Matches the depth the deleted shim gave every subscription, so a consumer
/// that kept up before keeps up now.
const SUBSCRIPTION_QUEUE: usize = 1024;

/// The topic applied hardening profiles are published on — the prefix this
/// consumer's own queue is fed from.
const HARDENING_APPLY_TOPIC: &str = "net.transport.hardening.apply";

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
    #[error("no session for peer")]
    NoSession,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("session error: {0}")]
    Session(#[from] crate::session::SessionError),
    #[error("handshake rejected: {0}")]
    Handshake(#[from] HandshakeError),
}

pub struct MeshTransport {
    bus: Arc<BusPublisher>,
    peer_manager: Arc<PeerManager>,
    session_manager: Arc<SessionManager>,
    local_peer_id: PeerId,
    hardener: Arc<RwLock<Option<MeshHardener>>>,
    network_world: Arc<RwLock<NetworkWorldTap>>,
}

impl MeshTransport {
    pub fn new(
        bus: Arc<BusPublisher>,
        peer_manager: Arc<PeerManager>,
        session_manager: Arc<SessionManager>,
        local_peer_id: PeerId,
    ) -> Self {
        let network_world =
            NetworkWorldTap::embedded().expect("embedded RTX network world must verify");
        Self {
            bus,
            peer_manager,
            session_manager,
            local_peer_id,
            hardener: Arc::new(RwLock::new(None)),
            network_world: Arc::new(RwLock::new(network_world)),
        }
    }

    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    pub fn apply_hardening_profile(&self, profile: ProtocolHardeningProfile) {
        *self.hardener.write() = Some(MeshHardener::new(profile));
    }

    pub fn clear_hardening_profile(&self) {
        *self.hardener.write() = None;
    }

    /// Whether a hardening profile is currently applied.
    pub fn hardening_active(&self) -> bool {
        self.hardener.read().is_some()
    }

    /// Cover frame per the active profile's `cover_traffic_ppm` rate:
    /// an encrypted empty payload framed exactly like real traffic, so
    /// cover frames are indistinguishable from data frames on the wire.
    /// `None` when no hardener is applied or the budget has not accrued.
    pub fn take_cover_frame(
        &self,
        session_id: &imperium_protocol::SessionId,
        link: u64,
    ) -> Option<HardenedPayload> {
        let mut hardener = self.hardener.write();
        let hardener = hardener.as_mut()?;
        if !hardener.should_emit_cover_for(link) {
            return None;
        }
        let (counter, ciphertext) = self
            .session_manager
            .seal_for_session(session_id, &[], None)
            .ok()?;
        let frame = hardener.harden_payload(counter, ciphertext, true);
        self.observe_wire(WireDirection::Outbound, &frame.bytes);
        Some(frame)
    }

    /// Recover and decrypt a wire frame for a session: length-normalization
    /// first, then AEAD open with replay checking. Returns the plaintext
    /// payload; cover frames decrypt to an empty payload with `cover` set.
    pub fn process_incoming(
        &self,
        session_id: &imperium_protocol::SessionId,
        bytes: &[u8],
    ) -> Result<RecoveredFrame, TransportError> {
        self.observe_wire(WireDirection::Inbound, bytes);
        let frame = MeshHardener::recover_frame(bytes)
            .ok_or_else(|| TransportError::Serialization("not a v3 frame".to_string()))?;
        let payload = self
            .session_manager
            .open_for_session(session_id, frame.counter, &frame.payload)
            .map_err(|e| TransportError::Serialization(e.to_string()))?;
        Ok(RecoveredFrame {
            payload,
            cover: frame.cover,
            counter: frame.counter,
        })
    }

    /// Frame ciphertext (from `seal_for_session`) for the wire. With a
    /// hardener this quantizes the frame shape; without one it still emits a
    /// valid (unpadded) v3 frame.
    pub fn harden_payload_for_send(&self, counter: u64, ciphertext: Vec<u8>) -> HardenedPayload {
        let frame = if let Some(ref mut hardener) = *self.hardener.write() {
            hardener.harden_payload(counter, ciphertext, false)
        } else {
            HardenedPayload {
                bytes: fallback_frame(counter, &ciphertext, false),
                delay: std::time::Duration::ZERO,
                cover: false,
            }
        };
        self.observe_wire(WireDirection::Outbound, &frame.bytes);
        frame
    }

    fn observe_wire(&self, direction: WireDirection, bytes: &[u8]) {
        if let Err(error) = self.network_world.write().observe(direction, bytes) {
            tracing::error!(?error, "passive network-world observation failed");
        }
    }

    pub fn network_world_snapshot(&self) -> Vec<NetworkWorldObservation> {
        self.network_world.read().snapshot()
    }

    pub fn network_world_hash(&self) -> [u8; 32] {
        self.network_world.read().world().digest
    }

    /// Best-effort cover frame emission: same shape as real frames, empty
    /// payload, failures logged and swallowed so cover traffic never fails
    /// the primary send.
    async fn send_cover_frame(
        &self,
        socket: &UdpSocket,
        target: SocketAddr,
        session_id: &imperium_protocol::SessionId,
        link: u64,
    ) {
        let Some(cover) = self.take_cover_frame(session_id, link) else {
            return;
        };
        if !cover.delay.is_zero() {
            tokio::time::sleep(cover.delay).await;
        }
        if let Err(e) = socket.send_to(&cover.bytes, target).await {
            tracing::warn!(error = %e, "cover frame send failed");
        }
    }

    pub fn subscribe_hardening_profiles(
        self: &Arc<Self>,
        publisher: &BusPublisher,
    ) -> tokio::task::JoinHandle<()> {
        // This consumer owns its own bounded queue. Native delivery is
        // push-based and the kernel keeps no per-subscriber queue, so the
        // callback — which runs on the publisher's thread — does one
        // non-blocking send and nothing else. A full queue drops THIS event and
        // counts it; the loop below reports the count before the next event, so
        // a slow consumer still observes its own gap rather than silently
        // skipping past it. The queue closing (every sender gone) ends the loop.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BusEvent>(SUBSCRIPTION_QUEUE);
        let dropped = Arc::new(AtomicU64::new(0));
        let drops = Arc::clone(&dropped);
        publisher.subscribe_prefix(
            HARDENING_APPLY_TOPIC,
            Box::new(move |_socket, payload| {
                if let Ok(event) = payload.downcast::<BusEvent>() {
                    if tx.try_send(*event).is_err() {
                        drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }),
        );

        let transport = Arc::clone(self);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let lagged = dropped.swap(0, Ordering::Relaxed);
                if lagged > 0 {
                    tracing::warn!(
                        lagged,
                        "hardening-profile subscription queue overflowed; events were dropped"
                    );
                }
                if let Message::ProtocolHardeningProfile(profile) = event.message {
                    transport.apply_hardening_profile(profile);
                }
            }
        })
    }

    pub async fn send_ping(
        &self,
        socket: &UdpSocket,
        peer_id: &PeerId,
    ) -> Result<(), TransportError> {
        let session_id = self
            .session_manager
            .get_session_for_peer(peer_id)
            .ok_or(TransportError::NoSession)?;

        let endpoints = self
            .peer_manager
            .get_endpoints(peer_id)
            .ok_or(TransportError::NoSession)?;

        let ping = MeshPing {
            peer_id: self.local_peer_id.clone(),
            session_id: session_id.clone(),
            seq: 0,
            sent_at: chrono::Utc::now(),
        };

        let payload =
            serde_json::to_vec(&ping).map_err(|e| TransportError::Serialization(e.to_string()))?;

        if let Some(addr) = endpoints.first() {
            let (counter, ciphertext) = self
                .session_manager
                .seal_for_session(&session_id, &payload, None)
                .map_err(TransportError::Session)?;
            let hardened = self.harden_payload_for_send(counter, ciphertext);
            if !hardened.delay.is_zero() {
                tokio::time::sleep(hardened.delay).await;
            }
            socket.send_to(&hardened.bytes, addr).await?;
            self.send_cover_frame(socket, *addr, &session_id, crate::peer::peer_token(peer_id))
                .await;
        }

        BusEvent::publish(&self.bus, "net.mesh.ping.sent", Message::MeshPing(ping))?;

        Ok(())
    }

    pub async fn send_pong(
        &self,
        socket: &UdpSocket,
        target: SocketAddr,
        ping: &MeshPing,
    ) -> Result<(), TransportError> {
        let pong = MeshPong {
            peer_id: self.local_peer_id.clone(),
            session_id: ping.session_id.clone(),
            seq: ping.seq,
            received_at: chrono::Utc::now(),
        };

        let payload =
            serde_json::to_vec(&pong).map_err(|e| TransportError::Serialization(e.to_string()))?;

        let (counter, ciphertext) = self
            .session_manager
            .seal_for_session(&ping.session_id, &payload, None)
            .map_err(TransportError::Session)?;
        let hardened = self.harden_payload_for_send(counter, ciphertext);
        if !hardened.delay.is_zero() {
            tokio::time::sleep(hardened.delay).await;
        }
        socket.send_to(&hardened.bytes, target).await?;
        self.send_cover_frame(
            socket,
            target,
            &ping.session_id,
            crate::peer::peer_token(&ping.peer_id),
        )
        .await;

        BusEvent::publish(&self.bus, "net.mesh.pong.sent", Message::MeshPong(pong))?;

        Ok(())
    }

    pub fn handle_pong(&self, pong: &MeshPong) {
        let now = chrono::Utc::now();
        let rtt_ms = (now - pong.received_at).num_milliseconds().unsigned_abs();
        self.session_manager.record_pong(&pong.session_id, rtt_ms);
        self.session_manager.touch_session(&pong.session_id);
    }

    /// Authenticated handshake entry point (Item 6): verify the inbound
    /// Hello's operator identity binding, then its identity signature over
    /// the ephemeral KEX keys, then cluster membership — in that order.
    /// On success returns the decoded identity binding; the caller proceeds
    /// to KEX encapsulate/decapsulate and session establish/adopt.
    ///
    /// `operator_vk` is the cluster trust anchor (thesis #9: operator keys
    /// are the only authority). `is_member` should close over
    /// `MembershipManager::is_member(&hello.peer_id)`.
    pub fn handle_hello(
        &self,
        hello: &imperium_protocol::MeshHello,
        operator_vk: &imperium_net_crypto::HybridVerifyingKey,
        cluster_id: &imperium_protocol::ClusterId,
        is_member: impl FnOnce() -> bool,
    ) -> Result<IdentityBinding, TransportError> {
        let now_unix = chrono::Utc::now().timestamp();
        Ok(verify_hello(
            hello,
            operator_vk,
            cluster_id,
            now_unix,
            is_member,
        )?)
    }

    pub fn peer_manager(&self) -> &PeerManager {
        &self.peer_manager
    }

    pub fn session_manager(&self) -> &SessionManager {
        &self.session_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use imperium_protocol::{
        FecPolicy, PaddingDistribution, PathHoppingPolicy, ProbeDeceptionMode,
        ProbeDeceptionPolicy, ProbeFailureMode, ProbeResistancePolicy, RekeyPolicy,
        TrafficMorphProfile,
    };

    #[test]
    fn transport_construction() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let pm = Arc::new(PeerManager::new());
        let sm = Arc::new(SessionManager::new());
        let peer_id = PeerId::new();

        let transport = MeshTransport::new(bus, pm, sm, peer_id.clone());
        assert_eq!(transport.local_peer_id(), &peer_id);
    }

    fn test_profile() -> ProtocolHardeningProfile {
        ProtocolHardeningProfile {
            profile_id: "mesh-live-test".to_string(),
            protocol_name: Some("mesh".to_string()),
            traffic_morph: TrafficMorphProfile {
                profile_id: "mesh-live-test-morph".to_string(),
                padding: PaddingDistribution::Bucketed {
                    buckets: vec![64, 256],
                },
                max_padding_overhead_ppm: 500_000,
                jitter_floor_ms: 0,
                jitter_ceiling_ms: 0,
                cover_traffic_ppm: 0,
                packet_batching_window_ms: 0,
            },
            rekey: RekeyPolicy {
                max_key_age_seconds: 600,
                max_key_bytes: 1_048_576,
                threat_triggered: true,
                stagger_window_ms: 0,
            },
            probe_resistance: ProbeResistancePolicy {
                authenticated_first_packet_required: true,
                unauthenticated_failure_mode: ProbeFailureMode::ConstantShapeReject,
                min_response_delay_ms: 0,
                max_response_delay_ms: 0,
                decoy_response_budget_per_hour: 0,
            },
            probe_deception: ProbeDeceptionPolicy {
                enabled: false,
                mode: ProbeDeceptionMode::Disabled,
                min_confidence: 1.0,
                response_budget_per_source_per_hour: 0,
                min_delay_ms: 0,
                max_delay_ms: 0,
                max_transcript_bytes: 0,
                persona_rotation_seconds: 3_600,
                log_transcripts: false,
            },
            path_hopping: PathHoppingPolicy {
                enabled: true,
                min_dwell_seconds: 60,
                max_dwell_seconds: 300,
                burn_score_threshold: 0.8,
                packet_loss_threshold_ppm: 50_000,
                jitter_threshold_ms: 80,
            },
            fec: FecPolicy {
                enabled: true,
                data_shards: 8,
                parity_shards: 2,
                loss_threshold_ppm: 20_000,
                max_overhead_ppm: 250_000,
            },
            applied_at: Utc::now(),
            reason: "test profile".to_string(),
        }
    }

    use imperium_net_crypto::HybridX25519Mlkem;
    use rand::rngs::OsRng;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9000))
    }

    /// Build an initiator/responder transport pair sharing one established,
    /// real-KEX session (same session id on both sides). Frames the initiator
    /// seals are openable only by the responder, and vice versa.
    fn established_pair() -> (MeshTransport, MeshTransport, imperium_protocol::SessionId) {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let initiator = MeshTransport::new(
            Arc::clone(&bus),
            Arc::new(PeerManager::new()),
            Arc::new(SessionManager::new()),
            PeerId::new(),
        );
        let responder = MeshTransport::new(
            bus,
            Arc::new(PeerManager::new()),
            Arc::new(SessionManager::new()),
            PeerId::new(),
        );

        let peer_id = PeerId::new();
        let session_id = initiator
            .session_manager()
            .create_session(peer_id.clone(), test_addr(), true)
            .unwrap();
        responder
            .session_manager()
            .adopt_session(session_id.clone(), peer_id, test_addr(), false)
            .unwrap();

        let mut rng = OsRng;
        let (responder_secret, responder_public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (encapsulation, initiator_key) =
            HybridX25519Mlkem::encapsulate(&mut rng, &responder_public);
        let responder_key =
            HybridX25519Mlkem::decapsulate(responder_secret, &encapsulation).unwrap();
        initiator
            .session_manager()
            .establish_session(&session_id, initiator_key, &[], &[])
            .unwrap();
        responder
            .session_manager()
            .establish_session(&session_id, responder_key, &[], &[])
            .unwrap();

        (initiator, responder, session_id)
    }

    #[test]
    fn encrypted_frames_round_trip_and_hide_plaintext() {
        let (initiator, responder, session_id) = established_pair();
        initiator.apply_hardening_profile(test_profile());

        let original = br#"{"mesh":"ping"}"#.to_vec();
        let (counter, ciphertext) = initiator
            .session_manager()
            .seal_for_session(&session_id, &original, None)
            .unwrap();
        let hardened = initiator.harden_payload_for_send(counter, ciphertext);

        // Quantized shape (the 64-byte bucket), and no trace of the
        // plaintext on the wire.
        assert_eq!(hardened.bytes.len(), 64);
        assert!(!hardened.bytes.windows(6).any(|w| w == br#""mesh""#));

        let recovered = responder
            .process_incoming(&session_id, &hardened.bytes)
            .unwrap();
        assert_eq!(recovered.payload, original);
        assert!(!recovered.cover);

        // The initiator cannot decrypt its own outgoing frame (direction
        // keys), and the responder rejects a replayed frame.
        assert!(initiator
            .process_incoming(&session_id, &hardened.bytes)
            .is_err());
        assert!(responder
            .process_incoming(&session_id, &hardened.bytes)
            .is_err());
    }

    #[tokio::test]
    async fn hardening_subscription_updates_send_path() {
        // The initiator's transport subscribes to hardening profiles on the
        // shared bus; profiles arrive via the subscription, not manual apply.
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let initiator = Arc::new(MeshTransport::new(
            Arc::clone(&bus),
            Arc::new(PeerManager::new()),
            Arc::new(SessionManager::new()),
            PeerId::new(),
        ));
        let _sub = initiator.subscribe_hardening_profiles(&bus);

        let responder = MeshTransport::new(
            Arc::new(spiderweb::Bus::open().publisher()),
            Arc::new(PeerManager::new()),
            Arc::new(SessionManager::new()),
            PeerId::new(),
        );
        let peer_id = PeerId::new();
        let session_id = initiator
            .session_manager()
            .create_session(peer_id.clone(), test_addr(), true)
            .unwrap();
        responder
            .session_manager()
            .adopt_session(session_id.clone(), peer_id, test_addr(), false)
            .unwrap();
        let mut rng = OsRng;
        let (responder_secret, responder_public) = HybridX25519Mlkem::generate_keypair(&mut rng);
        let (encapsulation, initiator_key) =
            HybridX25519Mlkem::encapsulate(&mut rng, &responder_public);
        let responder_key =
            HybridX25519Mlkem::decapsulate(responder_secret, &encapsulation).unwrap();
        initiator
            .session_manager()
            .establish_session(&session_id, initiator_key, &[], &[])
            .unwrap();
        responder
            .session_manager()
            .establish_session(&session_id, responder_key, &[], &[])
            .unwrap();

        let original = br#"{"mesh":"ping"}"#.to_vec();

        // Before any profile arrives: encrypted but unpadded frames.
        let (counter, ciphertext) = initiator
            .session_manager()
            .seal_for_session(&session_id, &original, None)
            .unwrap();
        let plain = initiator.harden_payload_for_send(counter, ciphertext);
        assert!(plain.bytes.len() > original.len());
        assert_eq!(
            responder
                .process_incoming(&session_id, &plain.bytes)
                .unwrap()
                .payload,
            original
        );

        // The envelope is what carries the fan-out registration; a bare
        // `Message` payload is not a registered clone type, which is why every
        // publisher in the workspace mints a `BusEvent`.
        BusEvent::publish(
            &bus,
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(test_profile()),
        )
        .unwrap();
        // The subscription task applies the profile asynchronously; poll
        // instead of sleeping a fixed interval (flaky under load).
        for _ in 0..200 {
            if initiator.hardening_active() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            initiator.hardening_active(),
            "hardening profile never arrived via subscription"
        );

        let (counter, ciphertext) = initiator
            .session_manager()
            .seal_for_session(&session_id, &original, None)
            .unwrap();
        let hardened = initiator.harden_payload_for_send(counter, ciphertext);
        assert!(hardened.bytes.len() > plain.bytes.len());
        assert_eq!(
            responder
                .process_incoming(&session_id, &hardened.bytes)
                .unwrap()
                .payload,
            original
        );
    }
}
