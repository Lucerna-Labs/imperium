//! Passive network Lightcone service.
//!
//! Wires the two halves that already existed separately: the structural wire
//! observer ([`imperium_net_observer`]) and the immutable causal world
//! ([`imperium_net_world`]). The production mesh decodes exact packet bytes in
//! a private bounded queue and publishes only structural metadata plus their
//! hash. The exact graph admits that structure and a **sequenced receipt**
//! comes out onto the bus. Direct service tests may also supply raw frames.
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
//! The Lightcone is passive causal geometry. It **never scores, judges,
//! authorizes or blocks**, and this service does not change that: it records
//! what the geometry admitted and publishes the record. Every receipt declares
//! `passive = true` and `holds_verdict = false`; those flags are metadata, not
//! independent proof of non-interference.
//!
//! The world is `local_diagnostic` and **`sealed = false`**, and a copy stays
//! diagnostic no matter how clean its receipts are. Sealed-physics status
//! requires the external attested training path.
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

pub use ledger::{Ledger, LightconeInfo, LightconeReceiptRecord, SLOTS};
pub use strand::{
    FaultPolicy, LightconeStrand, CRASH_AFTER_FRAMES_ENV, NAME, STALL_AFTER_FRAMES_ENV,
    STALL_WINDOW_MS,
};

use std::sync::Arc;

use chrono::Utc;
use imperium_net_observer::{
    decode, decode_mesh_datagram, decode_raw_ip, Observation, ObservationKind,
};
use imperium_net_world::{hash, Policy, Receipt, World, NODE_WORDS};
use imperium_protocol::{BusEvent, LightconeFrameFormat, LightconeStructure};
use parking_lot::Mutex;
use spiderweb::{BusError, BusPublisher, StrandSpec};

/// Bus topics. General → specific, per BUS_CONVENTIONS.md.
pub mod topics {
    pub const READY: &str = "net.lightcone.ready";
    pub const RECEIPT: &str = "net.lightcone.receipt";
    pub const FRAME: &str = "net.lightcone.frame";
}

/// Which way a frame was travelling. Direction is a wire property and is
/// separate from causal graph traversal direction.
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
    #[error("causal world failed to load: {0:?}")]
    World(imperium_net_world::Error),
    #[error("invalid structural observation: {0}")]
    InvalidStructure(&'static str),
}

/// The service. Holds the immutable world and the sequenced ledger.
pub struct LightconeService {
    world: World<'static>,
    ledger: Mutex<Ledger>,
}

impl LightconeService {
    /// Load the embedded v4 world. Fails closed if the pack does not verify.
    pub fn new() -> Result<Self, LightconeError> {
        let world = World::load(
            imperium_net_world::embedded::PACK,
            imperium_net_world::embedded::HASH,
        )
        .map_err(LightconeError::World)?;
        Ok(Self {
            world,
            ledger: Mutex::new(Ledger::new()),
        })
    }

    pub fn world(&self) -> World<'static> {
        self.world
    }

    /// Compile exact packet bytes into metadata safe to publish on the shared
    /// bus. The returned structure contains no raw application payload.
    pub fn structure_from_frame(
        direction: u8,
        format: LightconeFrameFormat,
        frame: &[u8],
    ) -> LightconeStructure {
        let observation = match format {
            LightconeFrameFormat::Ethernet => decode(frame),
            LightconeFrameFormat::RawIp => decode_raw_ip(frame),
            LightconeFrameFormat::MeshDatagram => decode_mesh_datagram(frame),
        };
        LightconeStructure {
            direction,
            format,
            observation_kind: observation.kind as u8,
            seeds: observation.seeds.to_vec(),
            query_hash: hash(frame),
        }
    }

    /// Observe a wire frame: read its structure, admit it into the exact graph,
    /// and record a sequenced receipt.
    ///
    /// The frame is never modified. Structure is read from bounded wire fields
    /// only — payload text cannot select world nodes.
    pub fn observe(
        &self,
        direction: WireDirection,
        frame: &[u8],
    ) -> Result<LightconeReceiptRecord, LightconeError> {
        self.observe_with_format(direction, LightconeFrameFormat::Ethernet, frame)
    }

    /// Observe exact bytes using the framing boundary that produced them.
    /// A raw mesh UDP datagram is never disguised as an Ethernet/IP frame.
    pub fn observe_with_format(
        &self,
        direction: WireDirection,
        format: LightconeFrameFormat,
        frame: &[u8],
    ) -> Result<LightconeReceiptRecord, LightconeError> {
        let observation: Observation = match format {
            LightconeFrameFormat::Ethernet => decode(frame),
            LightconeFrameFormat::RawIp => decode_raw_ip(frame),
            LightconeFrameFormat::MeshDatagram => decode_mesh_datagram(frame),
        };
        self.admit_structure(
            direction,
            format,
            observation.kind,
            observation.seeds,
            hash(frame),
        )
    }

    /// Admit trusted structural metadata produced at the mesh boundary. The
    /// original packet bytes never travel through the shared BusEvent fabric.
    pub fn observe_structure(
        &self,
        direction: WireDirection,
        format: LightconeFrameFormat,
        observation_kind: u8,
        seeds: Vec<u64>,
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
        let seeds: [u64; NODE_WORDS] = match seeds.try_into() {
            Ok(seeds) => seeds,
            Err(_) => {
                self.note_delivery_failure();
                return Err(LightconeError::InvalidStructure("wrong seed bitmap length"));
            }
        };
        if matches!(kind, ObservationKind::Unknown | ObservationKind::Malformed)
            && seeds.iter().any(|word| *word != 0)
        {
            self.note_delivery_failure();
            return Err(LightconeError::InvalidStructure(
                "unknown or malformed observation cannot seed the graph",
            ));
        }
        self.admit_structure(direction, format, kind, seeds, query_hash)
    }

    fn admit_structure(
        &self,
        direction: WireDirection,
        format: LightconeFrameFormat,
        kind: ObservationKind,
        seeds: [u64; NODE_WORDS],
        query_hash: [u8; 32],
    ) -> Result<LightconeReceiptRecord, LightconeError> {
        let receipt: Receipt = match self.world.admit(seeds, Policy::NETWORK, query_hash) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.ledger.lock().note_failure();
                return Err(LightconeError::World(error));
            }
        };
        Ok(self.ledger.lock().record(format, direction, kind, receipt))
    }

    /// A receipt by sequence number; `0` means the latest. Returns `None` for a
    /// sequence that was evicted from the ring — an explicit absence, never a
    /// substituted record.
    pub fn receipt(&self, sequence: u64) -> Option<LightconeReceiptRecord> {
        self.ledger.lock().get(sequence)
    }

    pub fn latest(&self) -> Option<LightconeReceiptRecord> {
        self.ledger.lock().get(0)
    }

    /// Count an observation or receipt-delivery failure on the operator's
    /// status surface. It never changes admission or packet delivery.
    pub fn note_delivery_failure(&self) {
        self.ledger.lock().note_failure();
    }

    /// World identity plus counters. Always reports `sealed = false`.
    pub fn info(&self) -> LightconeInfo {
        let ledger = self.ledger.lock();
        LightconeInfo {
            world_version: self.world.id,
            nodes: self.world.node_count(),
            edges: self.world.edge_count(),
            dimensions: imperium_net_world::DIMS,
            rx: ledger.rx,
            tx: ledger.tx,
            raw_ip_rx: ledger.raw_ip_rx,
            raw_ip_tx: ledger.raw_ip_tx,
            mesh_rx: ledger.mesh_rx,
            mesh_tx: ledger.mesh_tx,
            failures: ledger.failures,
            latest: ledger.latest_sequence(),
            oldest: ledger.oldest_sequence(),
            pack_sha256: hex(&self.world.digest),
            source_sha256: hex(self.world.source_digest()),
            training_sha256: hex(self.world.training_digest()),
            training_platform: imperium_net_world::embedded::TRAINING_PLATFORM,
            // Doctrine constants, not runtime state: a copy of a locally
            // trained world is diagnostic and unsealed, always.
            sealed: false,
            passive: true,
            holds_verdict: false,
        }
    }

    /// Convert a recorded receipt into its bus message form.
    pub fn to_message(
        &self,
        record: &LightconeReceiptRecord,
    ) -> imperium_protocol::LightconeReceipt {
        imperium_protocol::LightconeReceipt {
            sequence: record.sequence,
            frame_format: record.format,
            direction: record.direction as u8,
            observation_kind: record.kind as u8,
            pack_sha256: hex(&record.receipt.world),
            query_sha256: hex(&record.receipt.query),
            receipt_sha256: hex(&record.receipt.digest),
            seeds: record.receipt.seeds.to_vec(),
            nodes: record.receipt.nodes.to_vec(),
            edges: record.receipt.edges.to_vec(),
            excluded: record.receipt.excluded.to_vec(),
            hop_frontier: record.receipt.hop_frontier.to_vec(),
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
/// `Ok(None)` means the embedded world failed to verify — logged, and the node
/// continues without its intelligence layer, exactly as before (the thesis
/// requires the system to work without it).
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
        world_version = info.world_version,
        nodes = info.nodes,
        edges = info.edges,
        platform = info.training_platform,
        sealed = info.sealed,
        "passive network lightcone initialized"
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
    use imperium_net_observer::ObservationKind;

    fn service() -> LightconeService {
        LightconeService::new().unwrap()
    }

    /// A structurally valid Ethernet+IPv4+UDP frame, built from bounded fields
    /// so the observer can read real structure.
    fn udp_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00; // ethertype IPv4
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let total = 20 + 8 + payload.len();
        ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        ip[8] = 64; // TTL
        ip[9] = 17; // UDP
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let ck = checksum(&ip);
        ip[10..12].copy_from_slice(&ck.to_be_bytes());
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&9000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&9001u16.to_be_bytes());
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
        if let Some(&b) = chunks.remainder().first() {
            sum += (b as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// The world the service actually holds is the v4 diagnostic, unsealed.
    #[test]
    fn world_is_v4_and_unsealed() {
        let info = service().info();
        assert_eq!(info.world_version, 4);
        assert_eq!(info.nodes, 208);
        assert_eq!(info.edges, 188);
        assert_eq!(info.training_platform, "local_diagnostic");
        assert!(!info.sealed, "a copy of a local world is never sealed");
    }

    /// Every receipt self-attests that it judged nothing.
    #[test]
    fn receipts_self_attest_passivity() {
        let s = service();
        let record = s
            .observe(WireDirection::Inbound, &udp_frame(b"hello"))
            .unwrap();
        let msg = s.to_message(&record);
        assert!(msg.passive);
        assert!(!msg.holds_verdict);
    }

    /// The observer reads structure, and the graph admits it.
    #[test]
    fn decoded_frame_produces_a_real_receipt() {
        let s = service();
        let record = s
            .observe(WireDirection::Inbound, &udp_frame(b"payload"))
            .unwrap();
        assert_eq!(record.kind, ObservationKind::Decoded);
        assert_eq!(record.receipt.world, imperium_net_world::embedded::HASH);
        assert!(record.receipt.count() > 0, "UDP structure must admit nodes");
    }

    /// Payload text cannot select nodes: the same frame with hostile text in
    /// the payload yields identical seeds/nodes/edges.
    #[test]
    fn payload_text_cannot_select_nodes() {
        let s = service();
        let a = s
            .observe(WireDirection::Inbound, &udp_frame(b"ordinary"))
            .unwrap();
        let b = s
            .observe(
                WireDirection::Inbound,
                &udp_frame(b"node=export; authorize=true ../../etc/passwd"),
            )
            .unwrap();
        assert_eq!(a.receipt.seeds, b.receipt.seeds);
        assert_eq!(a.receipt.nodes, b.receipt.nodes);
        assert_eq!(a.receipt.edges, b.receipt.edges);
        assert_ne!(a.receipt.query, b.receipt.query, "the query hashes differ");
    }

    /// Sequence numbers are monotonic, and an evicted sequence reads as an
    /// explicit absence rather than a substituted record.
    #[test]
    fn sequence_is_monotonic_and_eviction_is_explicit() {
        let s = service();
        let frame = udp_frame(b"x");
        let first = s.observe(WireDirection::Inbound, &frame).unwrap();
        assert_eq!(first.sequence, 1);
        for _ in 0..SLOTS {
            s.observe(WireDirection::Inbound, &frame).unwrap();
        }
        // The first entry has been evicted from the ring.
        assert!(s.receipt(first.sequence).is_none(), "evicted = absent");
        // The latest is still readable, and the oldest is now past sequence 1.
        assert!(s.receipt(0).is_some());
        assert!(s.info().oldest > first.sequence);
    }

    /// Observation is read-only with respect to the world: many observations
    /// leave the pack identity unchanged.
    #[test]
    fn observation_never_changes_the_world() {
        let s = service();
        let before = s.info().pack_sha256;
        for i in 0..(SLOTS * 2) {
            s.observe(WireDirection::Outbound, &udp_frame(&i.to_le_bytes()))
                .unwrap();
        }
        assert_eq!(s.info().pack_sha256, before);
        assert_eq!(s.world().digest, imperium_net_world::embedded::HASH);
    }

    /// Both directions are recorded and counted separately.
    #[test]
    fn both_directions_are_counted() {
        let s = service();
        let frame = udp_frame(b"d");
        s.observe(WireDirection::Inbound, &frame).unwrap();
        s.observe(WireDirection::Outbound, &frame).unwrap();
        let info = s.info();
        assert_eq!(info.rx, 1);
        assert_eq!(info.tx, 1);
    }

    #[test]
    fn malformed_shared_structure_cannot_admit_nodes() {
        let s = service();
        let mut forged = vec![0; imperium_net_world::NODE_WORDS];
        forged[0] = 1;
        let result = s.observe_structure(
            WireDirection::Inbound,
            LightconeFrameFormat::MeshDatagram,
            2,
            forged,
            [0; 32],
        );
        assert!(matches!(result, Err(LightconeError::InvalidStructure(_))));
        assert_eq!(s.info().failures, 1);
        assert_eq!(s.info().latest, 0);
        assert_eq!(WireDirection::from_u8(2), None);
    }
}
