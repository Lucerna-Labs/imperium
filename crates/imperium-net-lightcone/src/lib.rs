//! Passive network Lightcone service.
//!
//! Door one (PATH-LIGHTCONE-DOOR-PRECOMMIT-2026-10-21.md). Wires the structural wire observer
//! ([`imperium_net_observer`], validity and kind) and the trained-path world
//! ([`imperium_net_pathworld`]: Jesse's restrained allow world plus the reverse deny world). The
//! production mesh reads each packet's **path** in a private bounded queue and publishes only that
//! structure plus a hash of the bytes. The world judges whether the path is a trained one, and a
//! **sequenced receipt** comes out onto the bus. Direct service tests may also supply raw frames.
//!
//! The loop that does that is a supervised Spiderweb **strand**
//! ([`LightconeStrand`]) — the pilot conversion away from `tokio::spawn`ed recv
//! loops, so the spider sees the Lightcone, restarts it if it crashes, and
//! quarantines it after four failures. The service itself
//! ([`LightconeService`]) is unchanged and remains directly usable (and
//! testable) without a bus.
//!
//! ## Doctrine
//!
//! In Imperium the lightcone is **passive**: it never blocks or releases a packet. It records
//! what the world admitted and publishes the record. Every receipt declares `passive = true` and
//! `holds_verdict = false`; those flags are metadata, not independent proof of non-interference.
//! (The same world can judge in the kernel packet path; that lives in network-lightcone's
//! `pathgate` and is not wired here: `filter_enforced` stays `false`.)
//!
//! The world is diagnostic and **`sealed = false`**. Jesse's seal comes later, by the TPU
//! training path, through the world's single pack loader.
//!
//! ## The ledger
//!
//! A bounded ring of [`SLOTS`] entries with a monotonic sequence number. The
//! ring is the point: when an entry is evicted, its sequence number becomes a
//! permanent gap — a lookup by that sequence returns `None` rather than a wrong
//! record, so an eviction reads as an explicit absence. Nothing about the world
//! changes when entries are evicted.

mod ledger;
mod strand;

pub use ledger::{Ledger, LightconeInfo, LightconeReceiptRecord, PathReceipt, SLOTS};
pub use strand::{
    FaultPolicy, LightconeStrand, CRASH_AFTER_FRAMES_ENV, NAME, STALL_AFTER_FRAMES_ENV,
    STALL_WINDOW_MS,
};

use std::net::SocketAddr;
use std::sync::Arc;

use chrono::Utc;
use imperium_net_observer::{decode, decode_mesh_datagram, decode_raw_ip, ObservationKind};
use imperium_net_pathworld::PathWorld;
use imperium_protocol::{BusEvent, LightconeFrameFormat, LightconeStructure, LightconeSymbol};
use parking_lot::Mutex;
use path_sense::{Path, Sym};
use sha2::{Digest, Sha256};
use spiderweb::{BusError, BusPublisher, StrandSpec};

/// Bus topics. General → specific, per BUS_CONVENTIONS.md.
pub mod topics {
    pub const READY: &str = "net.lightcone.ready";
    pub const RECEIPT: &str = "net.lightcone.receipt";
    pub const FRAME: &str = "net.lightcone.frame";
}

/// Which way a frame was travelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireDirection {
    Inbound = 0,
    Outbound = 1,
}

impl WireDirection {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Inbound),
            1 => Some(Self::Outbound),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LightconeError {
    #[error("trained-path world failed to load: {0:?}")]
    World(imperium_net_pathworld::Error),
    #[error("invalid structural observation: {0}")]
    InvalidStructure(&'static str),
}

/// SHA-256 of the exact observed bytes: the correlation identity with captures.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The path of one observed frame. A mesh datagram is read without its IP header, so its path
/// comes from the socket addresses (see [`datagram_path`]); here it has none.
pub fn frame_path(direction: u8, format: LightconeFrameFormat, frame: &[u8]) -> Option<Path> {
    let outbound = direction == WireDirection::Outbound as u8;
    match format {
        LightconeFrameFormat::Ethernet => path_frame::ethernet_path(frame, outbound),
        LightconeFrameFormat::RawIp => path_frame::held_path(frame, if outbound { 3 } else { 0 }),
        LightconeFrameFormat::MeshDatagram => None,
    }
}

/// The path of a mesh datagram from its socket addresses.
pub fn datagram_path(direction: u8, local: SocketAddr, peer: SocketAddr) -> Option<Path> {
    path_frame::socket_path(direction == WireDirection::Outbound as u8, local, peer)
}

fn kind_of(format: LightconeFrameFormat, frame: &[u8]) -> ObservationKind {
    match format {
        LightconeFrameFormat::Ethernet => decode(frame),
        LightconeFrameFormat::RawIp => decode_raw_ip(frame),
        LightconeFrameFormat::MeshDatagram => decode_mesh_datagram(frame),
    }
    .kind
}

pub fn to_symbols(path: &Path) -> Vec<LightconeSymbol> {
    path.iter().map(|s| LightconeSymbol { field: s.field, value: s.value }).collect()
}

fn from_symbols(path: &[LightconeSymbol]) -> Path {
    path.iter().map(|s| Sym { field: s.field, value: s.value }).collect()
}

/// The service. Holds the immutable world and the sequenced ledger.
pub struct LightconeService {
    world: PathWorld,
    ledger: Mutex<Ledger>,
}

impl LightconeService {
    /// The world named by `IMPERIUM_LIGHTCONE_ROLE` (untrained when unset). Fails closed on a
    /// role with no pack.
    pub fn new() -> Result<Self, LightconeError> {
        Ok(Self::with_world(PathWorld::from_env().map_err(LightconeError::World)?))
    }

    pub fn with_world(world: PathWorld) -> Self {
        Self { world, ledger: Mutex::new(Ledger::new()) }
    }

    pub fn world(&self) -> &PathWorld {
        &self.world
    }

    /// Compile exact packet bytes into metadata safe to publish on the shared bus: the observer's
    /// kind, the path, and a hash. `local`/`peer` are the socket addresses of a mesh datagram.
    pub fn structure_from_frame(
        direction: u8,
        format: LightconeFrameFormat,
        frame: &[u8],
        sockets: Option<(SocketAddr, SocketAddr)>,
    ) -> LightconeStructure {
        let kind = kind_of(format, frame);
        let path = match (format, sockets) {
            (LightconeFrameFormat::MeshDatagram, Some((local, peer))) => datagram_path(direction, local, peer),
            _ => frame_path(direction, format, frame),
        };
        let path = if matches!(kind, ObservationKind::Unknown | ObservationKind::Malformed) { None } else { path };
        LightconeStructure {
            direction,
            format,
            observation_kind: kind as u8,
            path: path.as_ref().map(to_symbols).unwrap_or_default(),
            query_hash: hash(frame),
        }
    }

    /// Observe an Ethernet frame.
    pub fn observe(&self, direction: WireDirection, frame: &[u8]) -> Result<LightconeReceiptRecord, LightconeError> {
        self.observe_with_format(direction, LightconeFrameFormat::Ethernet, frame)
    }

    /// Observe exact bytes using the framing boundary that produced them.
    pub fn observe_with_format(
        &self,
        direction: WireDirection,
        format: LightconeFrameFormat,
        frame: &[u8],
    ) -> Result<LightconeReceiptRecord, LightconeError> {
        let s = Self::structure_from_frame(direction as u8, format, frame, None);
        self.observe_structure(direction, format, s.observation_kind, s.path, s.query_hash)
    }

    /// Judge structural metadata produced at the mesh boundary. The original packet bytes never
    /// travel through the shared BusEvent fabric.
    pub fn observe_structure(
        &self,
        direction: WireDirection,
        format: LightconeFrameFormat,
        observation_kind: u8,
        path: Vec<LightconeSymbol>,
        query_hash: [u8; 32],
    ) -> Result<LightconeReceiptRecord, LightconeError> {
        let kind = match observation_kind {
            0 => ObservationKind::Decoded,
            1 => ObservationKind::Unknown,
            2 => ObservationKind::Malformed,
            3 => ObservationKind::Fragment,
            _ => {
                self.note_delivery_failure();
                return Err(LightconeError::InvalidStructure("unknown observation kind"));
            }
        };
        if matches!(kind, ObservationKind::Unknown | ObservationKind::Malformed) && !path.is_empty() {
            self.note_delivery_failure();
            return Err(LightconeError::InvalidStructure("unknown or malformed observation cannot carry a path"));
        }
        let path = from_symbols(&path);
        let admission = self.world.admit((!path.is_empty()).then_some(&path));
        let receipt = PathReceipt { world: self.world.role().to_string(), query: query_hash, path, admission };
        Ok(self.ledger.lock().record(format, direction, kind, receipt))
    }

    /// A receipt by sequence number; `0` means the latest. Returns `None` for a sequence that was
    /// evicted from the ring — an explicit absence, never a substituted record.
    pub fn receipt(&self, sequence: u64) -> Option<LightconeReceiptRecord> {
        self.ledger.lock().get(sequence)
    }

    pub fn latest(&self) -> Option<LightconeReceiptRecord> {
        self.ledger.lock().get(0)
    }

    /// Count an observation or receipt-delivery failure on the operator's status surface. It
    /// never changes admission or packet delivery.
    pub fn note_delivery_failure(&self) {
        self.ledger.lock().note_failure();
    }

    /// World identity plus counters. Always reports `sealed = false`.
    pub fn info(&self) -> LightconeInfo {
        let ledger = self.ledger.lock();
        LightconeInfo {
            world: self.world.role().to_string(),
            trained: self.world.is_trained(),
            trained_paths: self.world.trained_paths(),
            deny_paths: self.world.deny_paths(),
            folds: self.world.folds(),
            rx: ledger.rx,
            tx: ledger.tx,
            raw_ip_rx: ledger.raw_ip_rx,
            raw_ip_tx: ledger.raw_ip_tx,
            mesh_rx: ledger.mesh_rx,
            mesh_tx: ledger.mesh_tx,
            admitted: ledger.admitted,
            failures: ledger.failures,
            latest: ledger.latest_sequence(),
            oldest: ledger.oldest_sequence(),
            // Doctrine constants, not runtime state.
            sealed: false,
            passive: true,
            holds_verdict: false,
        }
    }

    /// Convert a recorded receipt into its bus message form.
    pub fn to_message(&self, record: &LightconeReceiptRecord) -> imperium_protocol::LightconeReceipt {
        imperium_protocol::LightconeReceipt {
            sequence: record.sequence,
            frame_format: record.format,
            direction: record.direction as u8,
            observation_kind: record.kind as u8,
            world: record.receipt.world.clone(),
            query_sha256: hex(&record.receipt.query),
            path: to_symbols(&record.receipt.path),
            admitted: record.receipt.admission.admitted,
            denied: record.receipt.admission.denied,
            learned_positions: record.receipt.admission.learned_positions.clone(),
            passive: true,
            holds_verdict: false,
            timestamp: Utc::now(),
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wire the service to the bus: publish `net.lightcone.ready` and hand back the
/// strand spec that serves `net.lightcone.frame` → `net.lightcone.receipt`.
///
/// The observer loop is **supervised**: it is a Spiderweb strand, not a
/// `tokio::spawn`ed task, so the spider owns its crashes (3 restarts, then
/// quarantine).
///
/// # The caller registers, and the caller must register *before* engaging
///
/// This function deliberately **returns** the spec instead of registering it,
/// so the ordering that the kernel requires is visible at the wiring site:
/// strand specs can only be installed by the kernel's run loop, so
/// `bus.register_spec(spec)` must happen before `Bus::run_until`. Registering
/// any later is impossible — the kernel owns its spec list once the loop runs.
///
/// `Ok(None)` means the world failed to load (a role with no pack) — logged, and the node
/// continues without its lightcone (the thesis requires the system to work without it).
///
/// The fault policy comes from [`FaultPolicy::from_env`] (see
/// [`CRASH_AFTER_FRAMES_ENV`]); it is [`FaultPolicy::None`] unless an operator
/// armed a drill.
pub fn init(publisher: &BusPublisher) -> Result<Option<StrandSpec>, BusError> {
    Ok(init_with_service(publisher)?.map(|installation| installation.spec))
}

/// The installed strand and its shared read-only observation service. The
/// process owner can expose `service.info()` without a second world loader or
/// an invented readiness flag; restarts retain this same ledger.
pub struct LightconeInstallation {
    pub spec: StrandSpec,
    pub service: Arc<LightconeService>,
}

pub fn init_with_service(
    publisher: &BusPublisher,
) -> Result<Option<LightconeInstallation>, BusError> {
    let service = match LightconeService::new() {
        Ok(s) => Arc::new(s),
        Err(err) => {
            // Fail loudly but do not take the node down: the Lightcone is
            // additive, and the thesis requires the system to work without it.
            tracing::error!(error = %err, "passive lightcone unavailable");
            return Ok(None);
        }
    };

    let info = service.info();
    tracing::info!(
        world = %info.world,
        trained_paths = info.trained_paths,
        deny_paths = info.deny_paths,
        folds = info.folds,
        sealed = info.sealed,
        "passive network lightcone (door one) initialized"
    );

    let ready = BusEvent::new(
        topics::READY,
        imperium_protocol::Message::SubsystemReady { name: NAME.into() },
    );
    publisher.publish(topics::READY, ready)?;

    let faults = FaultPolicy::from_env();
    if faults.is_injected() {
        // A deliberately armed fault must never look like a real one in the
        // logs, and must be impossible to leave on by accident without a trace.
        tracing::warn!(
            policy = ?faults,
            env = faults.source_env(),
            "lightcone fault injection ARMED — the strand will crash or stall on purpose"
        );
    }

    Ok(Some(LightconeInstallation {
        spec: LightconeStrand::spec(Arc::clone(&service), faults),
        service,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> LightconeService {
        LightconeService::with_world(PathWorld::embedded("receiver").unwrap())
    }

    /// A structurally valid Ethernet+IPv4+UDP frame: source 192.0.2.2:`sport` to the receiver
    /// 198.51.100.2:`dport`, the lab's direct path.
    fn udp_frame(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let total = 20 + 8 + payload.len();
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[192, 0, 2, 2]);
        ip[16..20].copy_from_slice(&[198, 51, 100, 2]);
        let ck = checksum(&ip);
        ip[10..12].copy_from_slice(&ck.to_be_bytes());
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&sport.to_be_bytes());
        udp[2..4].copy_from_slice(&dport.to_be_bytes());
        udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&ip);
        f.extend_from_slice(&udp);
        f.extend_from_slice(payload);
        f
    }

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut chunks = bytes.chunks_exact(2);
        for pair in &mut chunks {
            sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn world_is_the_trained_receiver_and_unsealed() {
        let info = service().info();
        assert_eq!(info.world, "receiver");
        assert!(info.trained && info.trained_paths == 476);
        assert!(!info.sealed, "the lab world is never sealed");
    }

    #[test]
    fn receipts_self_attest_passivity() {
        let s = service();
        let record = s.observe(WireDirection::Inbound, &udp_frame(51000, 45998, b"hello")).unwrap();
        let msg = s.to_message(&record);
        assert!(msg.passive && !msg.holds_verdict);
    }

    /// A trained path is admitted (its client port learned); an untrained port is not.
    #[test]
    fn trained_path_is_admitted_and_untrained_is_not() {
        let s = service();
        let ok = s.observe(WireDirection::Inbound, &udp_frame(51000, 45998, b"payload")).unwrap();
        assert_eq!(ok.kind, ObservationKind::Decoded);
        assert!(ok.receipt.admission.admitted, "{:?}", ok.receipt);
        assert_eq!(ok.receipt.admission.learned_positions, vec![5]);
        let no = s.observe(WireDirection::Inbound, &udp_frame(51000, 45996, b"payload")).unwrap();
        assert!(!no.receipt.admission.admitted);
        assert_eq!(s.info().admitted, 1);
    }

    /// Payload text cannot change the path or the admission.
    #[test]
    fn payload_text_cannot_change_the_admission() {
        let s = service();
        let a = s.observe(WireDirection::Inbound, &udp_frame(51000, 45998, b"ordinary")).unwrap();
        let b = s.observe(WireDirection::Inbound, &udp_frame(51000, 45998, b"node=export; authorize=true ../../etc/passwd")).unwrap();
        assert_eq!(a.receipt.path, b.receipt.path);
        assert_eq!(a.receipt.admission, b.receipt.admission);
        assert_ne!(a.receipt.query, b.receipt.query, "the query hashes differ");
    }

    #[test]
    fn sequence_is_monotonic_and_eviction_is_explicit() {
        let s = service();
        let frame = udp_frame(51000, 45998, b"x");
        let first = s.observe(WireDirection::Inbound, &frame).unwrap();
        assert_eq!(first.sequence, 1);
        for _ in 0..SLOTS {
            s.observe(WireDirection::Inbound, &frame).unwrap();
        }
        assert!(s.receipt(first.sequence).is_none(), "evicted = absent");
        assert!(s.receipt(0).is_some());
        assert!(s.info().oldest > first.sequence);
    }

    #[test]
    fn both_directions_are_counted() {
        let s = service();
        let frame = udp_frame(51000, 45998, b"d");
        s.observe(WireDirection::Inbound, &frame).unwrap();
        s.observe(WireDirection::Outbound, &frame).unwrap();
        let info = s.info();
        assert_eq!((info.rx, info.tx), (1, 1));
    }

    #[test]
    fn malformed_structure_cannot_carry_a_path() {
        let s = service();
        let forged = vec![LightconeSymbol { field: 0, value: 0 }];
        let result = s.observe_structure(WireDirection::Inbound, LightconeFrameFormat::MeshDatagram, 2, forged, [0; 32]);
        assert!(matches!(result, Err(LightconeError::InvalidStructure(_))));
        assert_eq!(s.info().failures, 1);
        assert_eq!(s.info().latest, 0);
        assert_eq!(WireDirection::from_u8(2), None);
    }

    /// A mesh datagram is judged by its socket path: the trained tunnel port 41000 from the hub.
    #[test]
    fn mesh_datagram_is_judged_by_its_socket_path() {
        let s = service();
        let local: SocketAddr = "198.51.100.2:41000".parse().unwrap();
        let peer: SocketAddr = "198.51.100.1:41000".parse().unwrap();
        let frame = [0x03u8; 32];
        let st = LightconeService::structure_from_frame(0, LightconeFrameFormat::MeshDatagram, &frame, Some((local, peer)));
        let r = s.observe_structure(WireDirection::Inbound, st.format, st.observation_kind, st.path, st.query_hash).unwrap();
        assert!(r.receipt.admission.admitted, "{:?}", r.receipt);
        let none = LightconeService::structure_from_frame(0, LightconeFrameFormat::MeshDatagram, &frame, None);
        assert!(none.path.is_empty());
    }

    /// With no role the world is untrained: nothing is admitted, and the node still observes.
    #[test]
    fn untrained_world_admits_nothing() {
        let s = LightconeService::with_world(PathWorld::untrained());
        let r = s.observe(WireDirection::Inbound, &udp_frame(51000, 45998, b"x")).unwrap();
        assert!(!r.receipt.admission.admitted);
        assert_eq!(s.info().world, "untrained");
    }
}
