use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PeerId(pub Uuid);

impl PeerId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for PeerId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ClusterId(pub Uuid);

impl ClusterId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for ClusterId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventId(pub Uuid);

impl EventId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EventId {
    fn default() -> Self {
        Self::new()
    }
}

// --- Phase 1: Mesh ---

/// Initiator's authenticated handshake opening. Identity fields are APPENDED
/// (existing fields unchanged): `identity_vk` is the initiator's long-term
/// peer-identity verifying key (operator-certified out of band via grant or
/// token binding peer_id -> identity VK -> cluster_id + expiry);
/// `identity_grant` carries that operator binding; `handshake_signature` is
/// the identity key's HybridSignature over
/// (session_id/nonce || classical_pubkey || pqc_pubkey || peer_id || grant).
/// `session_id` doubles as the handshake nonce (fresh per attempt).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshHello {
    pub peer_id: PeerId,
    pub endpoint: SocketAddr,
    pub classical_pubkey: Vec<u8>,
    pub pqc_pubkey: Vec<u8>,
    pub session_id: SessionId,
    pub identity_vk: Vec<u8>,
    pub identity_grant: Vec<u8>,
    pub handshake_signature: Vec<u8>,
}

/// Responder's authenticated handshake reply. `handshake_signature` is the
/// responder identity key's HybridSignature over (session_id ||
/// pqc_ciphertext || classical_pubkey || transcript-hash-of-Hello).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshHelloResponse {
    pub peer_id: PeerId,
    pub endpoint: SocketAddr,
    pub classical_pubkey: Vec<u8>,
    pub pqc_ciphertext: Vec<u8>,
    pub session_id: SessionId,
    pub identity_vk: Vec<u8>,
    /// Operator-signed binding of the responder's own peer_id to its identity
    /// key. Without this the response's `identity_vk` is self-asserted: the
    /// signature over it proves only that the responder holds *some* key, not
    /// that the key belongs to the peer id it claims. Covered by
    /// `handshake_signature`, so it cannot be swapped.
    pub identity_grant: Vec<u8>,
    pub handshake_signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshPing {
    pub peer_id: PeerId,
    pub session_id: SessionId,
    pub seq: u64,
    pub sent_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshPong {
    pub peer_id: PeerId,
    pub session_id: SessionId,
    pub seq: u64,
    pub received_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MeshPeerAnnouncement {
    pub peer_id: PeerId,
    pub endpoints: Vec<SocketAddr>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatTraversalMode {
    DirectUdp,
    StunMappedAddress,
    LimitedCoordinatedProbing,
    RelayThroughPeer,
    AggressiveBirthdayProbe,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NatTraversalPolicy {
    pub allowed_modes: Vec<NatTraversalMode>,
    pub aggressive_probe_opt_in: bool,
    pub max_probe_sockets: u16,
    pub probes_per_socket: u16,
    pub probe_window_ms: u64,
    pub relay_fallback_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NatProbePlan {
    pub peer_id: PeerId,
    pub modes: Vec<NatTraversalMode>,
    pub socket_count: u16,
    pub probes_per_socket: u16,
    pub estimated_probe_count: u32,
    pub relay_fallback_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayFallbackRequest {
    pub peer_id: PeerId,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayFallbackSelected {
    pub peer_id: PeerId,
    pub relay_peer: PeerId,
    pub selected_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum VpnDeploymentRole {
    Operator,
    Client,
    Relay,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnDeploymentNodeSpec {
    pub label: String,
    pub role: VpnDeploymentRole,
    pub peer_id: Option<PeerId>,
    pub endpoint: Option<SocketAddr>,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnDeploymentPlan {
    pub deployment_id: Uuid,
    pub cluster_id: Option<ClusterId>,
    pub nodes: Vec<VpnDeploymentNodeSpec>,
    pub hardening_preset: String,
    pub nat_aggressive: bool,
    pub relay_auto: bool,
    pub config_blob: Vec<u8>,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnDeploymentStatus {
    pub deployment_id: Uuid,
    pub accepted: bool,
    pub reason: String,
    pub planned_nodes: usize,
    pub approved_nodes: usize,
    pub config_version: u64,
    pub established_sessions: usize,
    pub relay_fallbacks_selected: usize,
    pub hardening_profiles_accepted: usize,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnDeploymentStatusRequest {
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
}

// --- Phase 1: Cluster ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BootstrapTokenPayload {
    pub token_id: Uuid,
    pub cluster_id: ClusterId,
    pub issued_by: PeerId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipGrant {
    pub cluster_id: ClusterId,
    pub peer_id: PeerId,
    pub granted_by: PeerId,
    pub granted_at: DateTime<Utc>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipApprovalRequest {
    pub cluster_id: ClusterId,
    pub requesting_peer: PeerId,
    pub bootstrap_token: BootstrapTokenPayload,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipGossip {
    pub cluster_id: ClusterId,
    pub members: Vec<PeerId>,
    pub lamport_clock: u64,
    pub from_peer: PeerId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationVersion {
    pub cluster_id: ClusterId,
    pub version: u64,
    pub lamport_clock: u64,
    pub config_hash: Vec<u8>,
    pub updated_by: PeerId,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationFetchRequest {
    pub cluster_id: ClusterId,
    pub from_peer: PeerId,
    pub known_version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigurationFetchResponse {
    pub cluster_id: ClusterId,
    pub version: u64,
    pub config_data: Vec<u8>,
    pub signature: Vec<u8>,
}

// --- Phase 2: Transport & Orchestrator ---

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolRole {
    Active,
    Standby,
    Quarantined,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProtocolCommandKind {
    Start,
    Stop,
    PromoteToActive,
    DemoteToStandby,
    Quarantine,
    Heal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolCommand {
    pub protocol_name: String,
    pub command: ProtocolCommandKind,
    pub issued_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtocolStatus {
    Starting,
    Running,
    Degraded,
    Failed,
    Stopped,
    Healing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProtocolEventKind {
    Started,
    Stopped,
    Crashed {
        reason: String,
    },
    Fingerprinted {
        details: String,
    },
    ThresholdCrossed {
        metric: String,
        value: f64,
        threshold: f64,
    },
    HealingStarted,
    HealingSucceeded,
    HealingFailed {
        reason: String,
    },
    SelfTestPassed,
    SelfTestFailed {
        reason: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolEvent {
    pub protocol_name: String,
    pub role: ProtocolRole,
    pub status: ProtocolStatus,
    pub event: ProtocolEventKind,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum OrchestratorState {
    Steady,
    Failover,
    Healing,
    Emergency,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OrchestratorDecision {
    PromoteStandby {
        protocol_name: String,
    },
    QuarantineActive {
        protocol_name: String,
        reason: String,
    },
    BeginHealing {
        protocol_name: String,
    },
    EmergencyShutdown {
        reason: String,
    },
    RestoreFromHealing {
        protocol_name: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmergencyShutdown {
    pub reason: String,
    pub triggered_at: DateTime<Utc>,
    pub active_protocol: Option<String>,
    pub standby_protocol: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProfileRotationRequest {
    pub protocol_name: Option<String>,
    pub reason: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportActiveRequest {
    pub protocol_name: String,
    pub requested_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportControlOperation {
    RuntimeReady,
    RotateProfile,
    SetActive,
    HealthCheck,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportControlOutcome {
    Applied,
    Rejected,
}

/// Confirmed outcome from a live, explicitly configured protocol controller.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportControlStatus {
    pub request_event_id: Option<EventId>,
    pub operation: TransportControlOperation,
    pub outcome: TransportControlOutcome,
    pub runtime_ready: bool,
    pub active_protocol: Option<String>,
    pub active_profile_id: Option<String>,
    pub target_protocol: Option<String>,
    pub target_profile_id: Option<String>,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyApplyRequest {
    pub policy_id: String,
    pub config_blob: Vec<u8>,
    pub requested_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MasqueTunnelKind {
    ConnectUdp,
    ConnectIp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasqueTunnelConfig {
    pub tunnel_id: String,
    pub proxy_authority: String,
    pub target_authority: String,
    pub kind: MasqueTunnelKind,
    pub inner_mtu: u16,
    pub use_quic_datagrams: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum MasqueTunnelState {
    Configured,
    Active,
    Degraded,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MasqueTunnelStatus {
    pub tunnel_id: String,
    pub state: MasqueTunnelState,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathMetrics {
    pub path_id: String,
    pub rtt_ms: u64,
    pub jitter_ms: u64,
    pub loss_ppm: u32,
    pub burn_score: f64,
    pub handshake_success_ppm: u32,
    pub relay_required: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathSelection {
    pub selected_path_id: String,
    pub score: f64,
    pub reason: String,
    pub selected_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaddingDistribution {
    None,
    Fixed { bytes: u16 },
    Bucketed { buckets: Vec<u16> },
    Envelope { min_bytes: u16, max_bytes: u16 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficMorphProfile {
    pub profile_id: String,
    pub padding: PaddingDistribution,
    pub max_padding_overhead_ppm: u32,
    pub jitter_floor_ms: u16,
    pub jitter_ceiling_ms: u16,
    pub cover_traffic_ppm: u32,
    pub packet_batching_window_ms: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RekeyPolicy {
    pub max_key_age_seconds: u64,
    pub max_key_bytes: u64,
    pub threat_triggered: bool,
    pub stagger_window_ms: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeFailureMode {
    AuthenticatedDrop,
    ConstantShapeReject,
    RetryWithPuzzle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeResistancePolicy {
    pub authenticated_first_packet_required: bool,
    pub unauthenticated_failure_mode: ProbeFailureMode,
    pub min_response_delay_ms: u16,
    pub max_response_delay_ms: u16,
    pub decoy_response_budget_per_hour: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeDeceptionMode {
    Disabled,
    SilentDrop,
    ConstantShapeReject,
    ShadowEndpoint,
    Tarpit,
    PuzzleGate,
    DecoyTranscript,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeDeceptionPolicy {
    pub enabled: bool,
    pub mode: ProbeDeceptionMode,
    pub min_confidence: f64,
    pub response_budget_per_source_per_hour: u32,
    pub min_delay_ms: u16,
    pub max_delay_ms: u16,
    pub max_transcript_bytes: u32,
    pub persona_rotation_seconds: u64,
    pub log_transcripts: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeDeceptionDecision {
    pub source: Option<SocketAddr>,
    pub mode: ProbeDeceptionMode,
    pub persona_id: String,
    pub response_delay_ms: u16,
    pub transcript_bytes: u32,
    pub routed_to_real_endpoint: bool,
    pub reason: String,
    pub decided_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PathHoppingPolicy {
    pub enabled: bool,
    pub min_dwell_seconds: u64,
    pub max_dwell_seconds: u64,
    pub burn_score_threshold: f64,
    pub packet_loss_threshold_ppm: u32,
    pub jitter_threshold_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FecPolicy {
    pub enabled: bool,
    pub data_shards: u8,
    pub parity_shards: u8,
    pub loss_threshold_ppm: u32,
    pub max_overhead_ppm: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolHardeningProfile {
    pub profile_id: String,
    pub protocol_name: Option<String>,
    pub traffic_morph: TrafficMorphProfile,
    pub rekey: RekeyPolicy,
    pub probe_resistance: ProbeResistancePolicy,
    pub probe_deception: ProbeDeceptionPolicy,
    pub path_hopping: PathHoppingPolicy,
    pub fec: FecPolicy,
    pub applied_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolHardeningStatus {
    pub profile_id: String,
    pub protocol_name: Option<String>,
    pub accepted: bool,
    pub reason: String,
    pub active_at: DateTime<Utc>,
}

// --- Phase 3: Strainer ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrainerRejection {
    pub strainer_id: String,
    pub stack_id: String,
    pub shape_failed: String,
    pub source_identifier: Option<SocketAddr>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrainerStageConfig {
    pub strainer_name: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub order: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrainerStackComposition {
    pub name: String,
    pub protocol_context: String,
    pub stages: Vec<StrainerStageConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RoutingDecision {
    Allow,
    Deny { reason: String },
    Degrade { method: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityCapabilityGrant {
    pub identity_id: PeerId,
    pub capabilities: Vec<String>,
    pub issued_by: PeerId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityAccessDecision {
    pub identity_id: PeerId,
    pub capability: String,
    pub allowed: bool,
    pub reason: String,
    pub decided_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KillSwitchState {
    Disarmed,
    Armed,
    Engaged,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KillSwitchCommand {
    pub state: KillSwitchState,
    pub reason: String,
    pub issued_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeakGuardStatus {
    pub dns_guard_enabled: bool,
    pub route_guard_enabled: bool,
    pub kill_switch: KillSwitchState,
    pub last_violation: Option<String>,
    pub timestamp: DateTime<Utc>,
}

// --- No-pass guard -> illusion seam ---
//
// `AvalanchedSource` is the ONLY credential the illusion interior accepts.
// It is minted by the no-pass guard when a source is avalanched into a face;
// the illusion crate never mints it (constructor is guard-side). `serve()`
// takes this type by value, so a raw source id or socket address cannot
// structurally reach the interior: the seam is type-level, not a runtime
// string check.
//
// The lie contract: same `face_id` replays the same synthetic transcript
// forever (deterministic per face); different `face_id`s are uncorrelated
// (anti-linkability). `since` records when the avalanche happened and is
// informational only — it never seeds fakery, so replays stay identical.

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AvalanchedSource {
    /// Opaque source key, as labeled by the guard (e.g. socket addr string).
    /// Never interpreted by the illusion; only used as a budget ledger key.
    pub source: String,
    /// Face this source was avalanched into. Seeds ALL synthetic output.
    pub face_id: u64,
    /// Wall-clock time of the avalanche. Informational; not a PRNG seed.
    pub since: DateTime<Utc>,
}

impl AvalanchedSource {
    /// Guard-side mint. The illusion crate treats this as an opaque token:
    /// it validates shape (`face_id != 0`, non-empty source, `since` not in
    /// the future) but never constructs one itself.
    pub fn minted_by_guard(source: impl Into<String>, face_id: u64, since: DateTime<Utc>) -> Self {
        Self {
            source: source.into(),
            face_id,
            since,
        }
    }

    /// Shape validation applied at every `serve()` entry point. Fails closed:
    /// empty source label, face 0 (reserved: "no face assigned"), or a
    /// `since` timestamp in the future all refuse.
    pub fn validate(&self) -> Result<(), String> {
        if self.source.is_empty() {
            return Err("avalanched source label is empty".to_string());
        }
        if self.face_id == 0 {
            return Err("face_id 0 is reserved (no face assigned)".to_string());
        }
        if self.since > Utc::now() + chrono::Duration::seconds(60) {
            return Err("avalanche timestamp is in the future".to_string());
        }
        Ok(())
    }
}

/// Gray-zone knock the guard could not classify as forcing yet. Sunk into a
/// cheap holding face (minimal interaction) rather than rejected: over-sink
/// is visible and recoverable, under-sink leaks invisibly and permanently.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HoldingFaceAdmission {
    pub source: String,
    pub holding_face_id: u64,
    pub shape_hint: String,
    pub admitted_at: DateTime<Utc>,
}

/// Dispute shape logged for operator review. Feeds future signature
/// extraction (closed-loop thesis 7): unknown shapes accumulate here until
/// an operator promotes one to a signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IllusionDispute {
    pub source: String,
    pub shape_hint: String,
    pub detail: String,
    pub logged_at: DateTime<Utc>,
}

/// Emitted when a source's cover-traffic emission budget runs dry. The
/// interior goes silent for that source; silence is the safe failure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IllusionBudgetExhausted {
    pub source: String,
    pub face_id: u64,
    pub bytes_emitted: u64,
    pub exhausted_at: DateTime<Utc>,
}

// --- Phase 4: Sensors ---

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatSource {
    Classifier { model_name: String },
    SignatureEngine,
    Heuristic { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatAssessment {
    pub source: ThreatSource,
    pub confidence: f64,
    pub description: String,
    pub remote_addr: Option<SocketAddr>,
    pub timestamp: DateTime<Utc>,
    pub suggested_action: SuggestedAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SensorFeature {
    pub name: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}

/// A per-source characterisation of *how* a prober probes: five separate
/// dimensions of behaviour, one profile per source, published on
/// `net.sensors.probe_profile` by the probe sensor in
/// `crates/imperium-net-sensors/src/probe.rs`.
///
/// **This is a sensor reading, not a verdict.** It deliberately has no
/// `confidence`, no `suggested_action`, and no field that combines the six
/// dimensions: structural facts and statistical scores are separate epistemic
/// classes here and are never fused into one number (see
/// `crates/imperium-net-sensors/src/fusion.rs` for the same law applied to
/// assessments). A single fused score would also be useless to the responder,
/// which has to react to *which* dimension moved.
///
/// Every dimension is a plain `f64` in `[0, 1]` except [`Self::rate_per_sec`],
/// and each one moves for its own reason:
///
/// * [`Self::rhythm_pe`] — permutation entropy (Bandt-Pompe, order 3,
///   position-stable ties) over the inter-arrival gaps of this source's
///   probes. `0.0` = metronomic, `1.0` = maximally varied. The E30
///   chaos-organ instrument, ported from
///   `quantum-network/experiments/e30_chaos.rs`.
/// * [`Self::drift`] — the *trend* of those same gaps: the total relative
///   change in gap across the window. `0.0` = steady cadence, `1.0` = the gap
///   more than doubled (or fell by half). It exists precisely because
///   `rhythm_pe` reads *arrangement* and is blind to a smooth ramp, which
///   reads `0.0` — indistinguishable from a metronome. The two are separate
///   readings of one series and a consumer must consult both.
/// * [`Self::repeat_ratio`] — fraction of the window's probes whose shape this
///   source had already sent before (against a bounded shape memory). A
///   driller repeats; a first-pass sweeper does not.
/// * [`Self::exploration`] — distinct shapes in the window divided by probes in
///   the window (coverage): is it sweeping a space or drilling one point.
/// * [`Self::convergence`] — `1 −` total-variation distance between the last
///   two completed shape-distribution windows. `1.0` = the distribution has
///   settled, `0.0` = it is still changing on every window.
/// * [`Self::rate_per_sec`] — probes per second over the window (budget burn).
///
/// The windowed dimension semantics (including when a `0.0` means "not yet
/// measurable" rather than "measured as zero") are documented in
/// `crates/imperium-net-sensors/src/probe.rs`; [`Self::sufficiency`] carries
/// the counts a consumer needs to tell those two cases apart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeProfile {
    /// Source identity as the observer saw it. The sensor does not normalise
    /// it: `10.0.0.5:41022` and `10.0.0.5:41023` are two sources, so the
    /// calling stack chooses the granularity it records.
    pub source: SocketAddr,
    /// Permutation entropy of inter-arrival gaps, order 3, normalised to
    /// `[0, 1]` (E30's chaos organ). Moves with the *arrangement* of the
    /// probes' cadence: `0.0` for a metronome or a burst cadence, `≈1.0` for
    /// organic gaps.
    ///
    /// It is **blind to a smooth trend**: a prober whose gaps rise monotonically
    /// (2000, 2016, 2032, …) presents the same ordinal pattern on every triple
    /// and reads exactly `0.0`, the same as a metronome. Read
    /// [`Self::drift`] as well; neither column substitutes for the other.
    pub rhythm_pe: f64,
    /// Magnitude of the smooth change in cadence across the window, in `[0, 1]`:
    /// `|least-squares slope × (n − 1)| / mean_gap`, i.e. the gap's change over
    /// the window as a fraction of the mean gap. **`0.0` = the cadence is steady
    /// across the window; the reading saturates at `1.0` once the cadence has
    /// travelled the whole mean gap** (for a smooth ramp: a gap that tripled, or
    /// fell to a third — `g → 2g` reads `2/3`). Moves when a prober steadily
    /// speeds up or slows down, which [`Self::rhythm_pe`] cannot see
    /// (arrangement vs trend).
    ///
    /// It is a **magnitude, not a direction**: accelerating and decelerating
    /// probers read the same value. The direction is deliberately not smuggled
    /// in as a sign — a signed trend reading would be a further *separate*
    /// dimension if one is ever wanted.
    ///
    /// Computed from two gaps upward (unlike `rhythm_pe`, which needs a minimum
    /// count), so read [`Self::sufficiency`]'s `gaps_in_window` before acting on
    /// a thin window's reading.
    pub drift: f64,
    /// Fraction of the window's probes whose shape the source had already sent
    /// before that probe. Moves when a prober re-uses a probe it has used
    /// before (drilling, replaying, a beacon with one payload shape).
    pub repeat_ratio: f64,
    /// Distinct shapes in the window / probes in the window. Moves when a
    /// prober widens or narrows the set of probe shapes it tries (coverage).
    pub exploration: f64,
    /// `1 − TV(last window, previous window)` over shape distributions.
    /// Moves while a prober's picture of us is still changing; settles at
    /// `1.0` when successive windows look the same (the fingerprinting tell).
    pub convergence: f64,
    /// Probes per second over the window. The only dimension not bounded by
    /// `1.0`: it is a physical rate, not a normalised reading. Moves with the
    /// prober's budget burn rate.
    pub rate_per_sec: f64,
    /// How many observations each dimension above is entitled to claim. These
    /// counts are *not* dimensions and must not be folded into any score; they
    /// exist so a consumer can distinguish "measured as 0.0" from "not yet
    /// measurable".
    pub sufficiency: ProbeSufficiency,
    /// Timestamp of the most recent probe in this profile's window, in the
    /// sensor's own microsecond clock (the timestamps the caller supplied, not
    /// a wall clock — the sensor never reads one, so a profile is a pure
    /// function of its input events).
    pub last_seen_micros: u64,
}

/// Observation counts behind a [`ProbeProfile`], so each dimension's `0.0` can
/// be read correctly. Deliberately a separate struct from the dimensions: it is
/// the part of the reading that says *how much the reading is entitled to
/// claim*, not what the reading is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeSufficiency {
    /// Probes currently in the sliding window (bounded by the sensor's window
    /// size, so this never grows without limit).
    pub probes_in_window: u32,
    /// Inter-arrival gaps currently in the window. Below the sensor's minimum,
    /// `rhythm_pe` is reported as `0.0` **because it is not measurable yet**,
    /// not because the source was metronomic.
    pub gaps_in_window: u32,
    /// Lifetime probes observed from this source (a counter, not a buffer).
    pub probes_seen: u64,
    /// Completed consecutive-window comparisons. Below `1`,
    /// `convergence` is `0.0` because nothing has been compared yet.
    pub epochs_compared: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SuggestedAction {
    None,
    IncreaseMonitoring,
    ActivateStrainer { strainer_name: String },
    TriggerFailover,
    EmergencyShutdown,
}

// --- Phase 6: Signatures ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureCandidate {
    pub id: Uuid,
    pub rule_text: String,
    pub description: String,
    pub source_events: Vec<EventId>,
    pub extracted_at: DateTime<Utc>,
    pub confidence: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureApproved {
    pub candidate_id: Uuid,
    pub approved_by: PeerId,
    pub approved_at: DateTime<Utc>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRejected {
    pub candidate_id: Uuid,
    pub rejected_by: PeerId,
    pub rejected_at: DateTime<Utc>,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractedSignatureActivated {
    pub candidate_id: Uuid,
    pub signature_id: Uuid,
    pub activated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureActivationFailed {
    pub candidate_id: Uuid,
    pub compile_error: String,
    pub failed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractionRequest {
    pub triggering_event_ids: Vec<EventId>,
    pub reason: String,
    pub requested_by: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureCandidatePending {
    pub candidate_id: Uuid,
    pub requested_by: String,
    pub ready_at: DateTime<Utc>,
}

/// Operator approval request for a staged signature candidate. The approval
/// itself (with operator signature) is produced by the staging area; this
/// message only carries the candidate ID from a control surface (CLI, GUI)
/// to the approving subscriber.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureApprovalRequest {
    pub candidate_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractionFailed {
    pub triggering_event_ids: Vec<EventId>,
    pub reason: String,
    pub failed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractedSignatureRollback {
    pub candidate_id: Uuid,
    pub rolled_back_at: DateTime<Utc>,
    pub reason: String,
}

// --- Phase 7: Toolkit ---

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ToolState {
    Dormant,
    Armed,
    Active,
    Cooldown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolStateChange {
    pub tool_name: String,
    pub from: ToolState,
    pub to: ToolState,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolActivationRequest {
    pub tool_name: String,
    pub trigger: String,
    pub context: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolBudget {
    pub tool_name: String,
    pub max_activations_per_hour: u32,
    pub cooldown_seconds: u64,
    pub remaining_activations: u32,
}

/// One structural symbol of a packet's path (network lightcone, door one): which field, and its
/// value. Fields: direction 0, link 1, L4 protocol 2, source 3, destination 4, source port 5,
/// destination port 6, TCP flags 7, ICMP type/code 8, ARP operation 9, fragment 10.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightconeSymbol {
    pub field: u8,
    pub value: u128,
}

/// A passive Lightcone admission receipt, published for observation only.
///
/// It records what the trained-path world admitted for one observed packet: whether the allow
/// world matched and the deny world did not, and which positions matched through learning rather
/// than an exact trained value. It carries no authority: `passive` and `holds_verdict` are
/// self-attesting doctrine flags, and this receipt never blocks or releases anything.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightconeReceipt {
    /// Monotonic sequence number. Entries are evicted from a bounded ring, so a
    /// gap in the sequence is an explicit eviction, not a lost event.
    pub sequence: u64,
    /// 0 = inbound observation, 1 = outbound.
    pub direction: u8,
    /// Framing boundary the path was read from.
    #[serde(default)]
    pub frame_format: LightconeFrameFormat,
    /// Structural observation kind (0 decoded, 1 unknown, 2 malformed, 3 fragment).
    pub observation_kind: u8,
    /// The world that judged it: its role, or "untrained".
    pub world: String,
    /// SHA-256 of the observed bytes: the identity that correlates a receipt with captures.
    pub query_sha256: String,
    pub path: Vec<LightconeSymbol>,
    /// The allow world matched the path and the deny world did not.
    pub admitted: bool,
    /// The deny world matched the path.
    pub denied: bool,
    /// Path positions matched through a learned wildcard.
    pub learned_positions: Vec<u8>,
    /// Self-attesting doctrine flags — every receipt proves it judged nothing.
    pub passive: bool,
    pub holds_verdict: bool,
    pub timestamp: DateTime<Utc>,
}

/// The framing boundary for a passive Lightcone observation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LightconeFrameFormat {
    /// Layer 2 Ethernet frame, retained for existing adapters and tests.
    #[default]
    Ethernet,
    /// Layer 3 IP packet read from or written to the Linux TUN interface.
    RawIp,
    /// Imperium's own encrypted UDP datagram bytes, without invented headers.
    MeshDatagram,
}

/// Parsed packet structure and a digest of the exact bytes observed by the
/// owner. Raw packet bytes stay in the owner's private bounded queue and are
/// never published on the shared bus.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightconeStructure {
    /// 0 = inbound, 1 = outbound.
    pub direction: u8,
    pub format: LightconeFrameFormat,
    /// Structural observation kind (0 decoded, 1 unknown, 2 malformed, 3 fragment).
    pub observation_kind: u8,
    /// The packet's path, read only from bounded structural fields (never payload).
    pub path: Vec<LightconeSymbol>,
    /// SHA-256 of the complete original packet/datagram bytes.
    pub query_hash: [u8; 32],
}

// --- Master message enum ---

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Message {
    // Infrastructure
    SubsystemReady {
        name: String,
    },
    SubsystemStopping {
        name: String,
        reason: String,
    },

    // Phase 1: Mesh
    MeshHello(MeshHello),
    MeshHelloResp(MeshHelloResponse),
    MeshPing(MeshPing),
    MeshPong(MeshPong),
    MeshPeerAnnouncement(MeshPeerAnnouncement),
    NatTraversalPolicy(NatTraversalPolicy),
    NatProbePlan(NatProbePlan),
    RelayFallbackRequest(RelayFallbackRequest),
    RelayFallbackSelected(RelayFallbackSelected),
    VpnDeploymentPlan(VpnDeploymentPlan),
    VpnDeploymentStatus(VpnDeploymentStatus),
    VpnDeploymentStatusRequest(VpnDeploymentStatusRequest),

    // Phase 1: Cluster
    BootstrapToken(BootstrapTokenPayload),
    MembershipGrant(MembershipGrant),
    MembershipApprovalReq(MembershipApprovalRequest),
    MembershipGossip(MembershipGossip),
    ConfigVersion(ConfigurationVersion),
    ConfigFetchReq(ConfigurationFetchRequest),
    ConfigFetchResp(ConfigurationFetchResponse),

    // Phase 2: Transport & Orchestrator
    ProtocolCmd(ProtocolCommand),
    ProtocolEvt(ProtocolEvent),
    OrchestratorDecision(OrchestratorDecision),
    EmergencyShutdown(EmergencyShutdown),
    ProfileRotationRequest(ProfileRotationRequest),
    TransportActiveRequest(TransportActiveRequest),
    TransportControlStatus(TransportControlStatus),
    PolicyApplyRequest(PolicyApplyRequest),
    MasqueTunnelConfig(MasqueTunnelConfig),
    MasqueTunnelStatus(MasqueTunnelStatus),
    PathMetrics(PathMetrics),
    PathSelection(PathSelection),
    ProtocolHardeningProfile(ProtocolHardeningProfile),
    ProtocolHardeningStatus(ProtocolHardeningStatus),
    ProbeDeceptionDecision(ProbeDeceptionDecision),

    // Phase 3: Strainer
    StrainerRejection(StrainerRejection),
    StrainerStackComposition(StrainerStackComposition),
    RoutingDecision(RoutingDecision),
    IdentityCapabilityGrant(IdentityCapabilityGrant),
    IdentityAccessDecision(IdentityAccessDecision),
    KillSwitchCommand(KillSwitchCommand),
    LeakGuardStatus(LeakGuardStatus),
    IllusionAdmission(HoldingFaceAdmission),
    IllusionDisputeLogged(IllusionDispute),
    IllusionBudgetExhausted(IllusionBudgetExhausted),

    // Passive network Lightcone (observation only — no release authority)
    LightconeReceipt(LightconeReceipt),
    LightconeStructure(LightconeStructure),

    // Phase 4: Sensors
    ThreatAssessment(ThreatAssessment),
    SensorFeature(SensorFeature),
    /// Windowed probe-behaviour characterisation. Deliberately NOT a
    /// [`ThreatAssessment`]: no confidence, no action, one message per source
    /// with the five dimensions kept separate.
    ProbeProfile(ProbeProfile),

    // Phase 6: Signatures
    SignatureApprovalRequest(SignatureApprovalRequest),
    SignatureCandidate(SignatureCandidate),
    SignatureApproved(SignatureApproved),
    SignatureRejected(SignatureRejected),
    SignatureActivated(ExtractedSignatureActivated),
    SignatureActivationFailed(SignatureActivationFailed),
    SignatureRollback(ExtractedSignatureRollback),
    ExtractionRequest(ExtractionRequest),
    SignatureCandidatePending(SignatureCandidatePending),
    ExtractionFailed(ExtractionFailed),

    // Phase 7: Toolkit
    ToolStateChange(ToolStateChange),
    ToolActivationReq(ToolActivationRequest),
    ToolBudget(ToolBudget),
}

#[derive(Clone, Debug)]
pub struct BusEvent {
    pub id: EventId,
    pub topic: Arc<str>,
    pub message: Message,
    pub timestamp: DateTime<Utc>,
}

/// Teach Spiderweb's process-global fan-out clone registry about [`BusEvent`],
/// exactly once per process.
///
/// Spiderweb's kernel hands every matching subscriber a *clone* of the payload,
/// looking the clone function up by `TypeId` in a registry it pre-populates with
/// `String`, the primitives and its own system types. A type it does not know
/// panics at delivery time — not at registration — so every publisher of a
/// `BusEvent` must have registered it *before* the first publish.
///
/// This belongs to the type rather than to any bus facade: [`BusEvent`] is
/// Imperium's wire envelope and Spiderweb is the bus that carries it, so the
/// envelope makes itself fan-out-able. The call is a `Once` plus an idempotent
/// `HashMap::insert` in the kernel, which is what lets it sit on the
/// `BusEvent::new` path without a measurable cost.
fn register_fanout_once() {
    static REGISTER: std::sync::Once = std::sync::Once::new();
    REGISTER.call_once(|| spiderweb::register_clone_type::<BusEvent>());
}

impl BusEvent {
    pub fn new(topic: impl Into<Arc<str>>, message: Message) -> Self {
        register_fanout_once();
        Self {
            id: EventId::new(),
            topic: topic.into(),
            message,
            timestamp: Utc::now(),
        }
    }

    /// Mint the envelope on `socket` and hand it to Spiderweb, in one step.
    ///
    /// The routing key and the envelope's topic are two strings that must agree:
    /// Spiderweb routes to *named* subscribers by the socket name, while a
    /// subscriber that reads `event.topic` (every strand, and every consumer
    /// that filters on the topic) sees the envelope's. Passing the socket once
    /// and deriving both from it makes disagreeing impossible.
    ///
    /// This is the envelope's own publishing step, not a bus: it holds no
    /// kernel, does no routing, keeps no subscriber list and has no state. The
    /// bus is `spiderweb::BusPublisher`, taken directly from the kernel.
    ///
    /// A caller whose socket name must differ from the envelope topic — the two
    /// families that build their topic at runtime, `net.transport.event.{kind}`
    /// and `runtime.subsystem.ready.{name}` — calls
    /// `publisher.publish(socket, BusEvent::new(topic, message))` itself, which
    /// is the whole of what this function does.
    pub fn publish(
        publisher: &spiderweb::BusPublisher,
        socket: &'static str,
        message: Message,
    ) -> Result<(), spiderweb::BusError> {
        publisher.publish(socket, BusEvent::new(socket, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug>(val: &T) {
        let json = serde_json::to_string(val).expect("serialize failed");
        let _: T = serde_json::from_str(&json).expect("deserialize failed");
    }

    fn roundtrip_message(msg: Message) {
        let json = serde_json::to_string(&msg).expect("serialize Message");
        let back: Message = serde_json::from_str(&json).expect("deserialize Message");
        let json2 = serde_json::to_string(&back).expect("re-serialize Message");
        assert_eq!(json, json2);
    }

    #[test]
    fn id_types_unique() {
        let a = PeerId::new();
        let b = PeerId::new();
        assert_ne!(a, b);

        let s1 = SessionId::new();
        let s2 = SessionId::new();
        assert_ne!(s1, s2);

        let c1 = ClusterId::new();
        let c2 = ClusterId::new();
        assert_ne!(c1, c2);
    }

    #[test]
    fn id_types_serde_roundtrip() {
        roundtrip(&PeerId::new());
        roundtrip(&SessionId::new());
        roundtrip(&ClusterId::new());
        roundtrip(&EventId::new());
    }

    #[test]
    fn id_hash_and_eq() {
        let id = PeerId::new();
        let clone = id.clone();
        assert_eq!(id, clone);

        let mut set = std::collections::HashSet::new();
        set.insert(id.clone());
        assert!(set.contains(&clone));
    }

    #[test]
    fn mesh_hello_roundtrip() {
        let msg = Message::MeshHello(MeshHello {
            peer_id: PeerId::new(),
            endpoint: "127.0.0.1:9000".parse().unwrap(),
            classical_pubkey: vec![1, 2, 3],
            pqc_pubkey: vec![4, 5, 6],
            session_id: SessionId::new(),
            identity_vk: vec![7, 8, 9],
            identity_grant: vec![10, 11],
            handshake_signature: vec![12, 13, 14],
        });
        roundtrip_message(msg);
    }

    #[test]
    fn mesh_hello_response_roundtrip() {
        let msg = Message::MeshHelloResp(MeshHelloResponse {
            peer_id: PeerId::new(),
            endpoint: "10.0.0.1:8080".parse().unwrap(),
            classical_pubkey: vec![7, 8, 9],
            pqc_ciphertext: vec![10, 11, 12],
            session_id: SessionId::new(),
            identity_vk: vec![13, 14],
            identity_grant: vec![18, 19, 20],
            handshake_signature: vec![15, 16, 17],
        });
        roundtrip_message(msg);
    }

    #[test]
    fn mesh_ping_pong_roundtrip() {
        let peer = PeerId::new();
        let session = SessionId::new();

        roundtrip_message(Message::MeshPing(MeshPing {
            peer_id: peer.clone(),
            session_id: session.clone(),
            seq: 42,
            sent_at: Utc::now(),
        }));

        roundtrip_message(Message::MeshPong(MeshPong {
            peer_id: peer,
            session_id: session,
            seq: 42,
            received_at: Utc::now(),
        }));
    }

    #[test]
    fn nat_traversal_messages_roundtrip() {
        let peer = PeerId::new();
        roundtrip_message(Message::NatTraversalPolicy(NatTraversalPolicy {
            allowed_modes: vec![
                NatTraversalMode::DirectUdp,
                NatTraversalMode::StunMappedAddress,
                NatTraversalMode::LimitedCoordinatedProbing,
                NatTraversalMode::RelayThroughPeer,
            ],
            aggressive_probe_opt_in: false,
            max_probe_sockets: 4,
            probes_per_socket: 8,
            probe_window_ms: 1_500,
            relay_fallback_enabled: true,
        }));

        roundtrip_message(Message::NatProbePlan(NatProbePlan {
            peer_id: peer.clone(),
            modes: vec![
                NatTraversalMode::DirectUdp,
                NatTraversalMode::RelayThroughPeer,
            ],
            socket_count: 4,
            probes_per_socket: 8,
            estimated_probe_count: 32,
            relay_fallback_enabled: true,
        }));

        roundtrip_message(Message::RelayFallbackRequest(RelayFallbackRequest {
            peer_id: peer.clone(),
            reason: "symmetric nat".into(),
            requested_at: Utc::now(),
        }));

        roundtrip_message(Message::RelayFallbackSelected(RelayFallbackSelected {
            peer_id: peer,
            relay_peer: PeerId::new(),
            selected_at: Utc::now(),
        }));

        roundtrip_message(Message::VpnDeploymentPlan(VpnDeploymentPlan {
            deployment_id: Uuid::new_v4(),
            cluster_id: Some(ClusterId::new()),
            nodes: vec![
                VpnDeploymentNodeSpec {
                    label: "operator".into(),
                    role: VpnDeploymentRole::Operator,
                    peer_id: Some(PeerId::new()),
                    endpoint: Some("127.0.0.1:31000".parse().unwrap()),
                    capabilities: vec!["vpn.cluster.admin".into()],
                },
                VpnDeploymentNodeSpec {
                    label: "relay".into(),
                    role: VpnDeploymentRole::Relay,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:31001".parse().unwrap()),
                    capabilities: vec!["vpn.relay".into()],
                },
            ],
            hardening_preset: "fortress".into(),
            nat_aggressive: false,
            relay_auto: true,
            config_blob: br#"{"deployment":"auto"}"#.to_vec(),
            requested_by: "test".into(),
            requested_at: Utc::now(),
        }));

        roundtrip_message(Message::VpnDeploymentStatus(VpnDeploymentStatus {
            deployment_id: Uuid::new_v4(),
            accepted: true,
            reason: "deployment converged".into(),
            planned_nodes: 2,
            approved_nodes: 2,
            config_version: 1,
            established_sessions: 2,
            relay_fallbacks_selected: 1,
            hardening_profiles_accepted: 2,
            updated_at: Utc::now(),
        }));

        roundtrip_message(Message::VpnDeploymentStatusRequest(
            VpnDeploymentStatusRequest {
                requested_by: "operator".into(),
                requested_at: Utc::now(),
            },
        ));
    }

    #[test]
    fn cluster_messages_roundtrip() {
        let cluster = ClusterId::new();
        let peer = PeerId::new();
        let now = Utc::now();

        roundtrip_message(Message::BootstrapToken(BootstrapTokenPayload {
            token_id: Uuid::new_v4(),
            cluster_id: cluster.clone(),
            issued_by: peer.clone(),
            issued_at: now,
            expires_at: now,
            signature: vec![0xDE, 0xAD],
        }));

        roundtrip_message(Message::MembershipGrant(MembershipGrant {
            cluster_id: cluster.clone(),
            peer_id: peer.clone(),
            granted_by: PeerId::new(),
            granted_at: now,
            signature: vec![0xBE, 0xEF],
        }));

        roundtrip_message(Message::MembershipGossip(MembershipGossip {
            cluster_id: cluster.clone(),
            members: vec![peer.clone(), PeerId::new()],
            lamport_clock: 7,
            from_peer: peer.clone(),
        }));

        roundtrip_message(Message::ConfigVersion(ConfigurationVersion {
            cluster_id: cluster.clone(),
            version: 3,
            lamport_clock: 5,
            config_hash: vec![1, 2, 3],
            updated_by: peer.clone(),
            updated_at: now,
        }));

        roundtrip_message(Message::ConfigFetchReq(ConfigurationFetchRequest {
            cluster_id: cluster.clone(),
            from_peer: peer.clone(),
            known_version: 2,
        }));

        roundtrip_message(Message::ConfigFetchResp(ConfigurationFetchResponse {
            cluster_id: cluster,
            version: 3,
            config_data: vec![10, 20, 30],
            signature: vec![40, 50],
        }));
    }

    #[test]
    fn protocol_event_variants_roundtrip() {
        let kinds = vec![
            ProtocolEventKind::Started,
            ProtocolEventKind::Stopped,
            ProtocolEventKind::Crashed {
                reason: "oom".into(),
            },
            ProtocolEventKind::Fingerprinted {
                details: "tls mismatch".into(),
            },
            ProtocolEventKind::ThresholdCrossed {
                metric: "rtt".into(),
                value: 150.0,
                threshold: 100.0,
            },
            ProtocolEventKind::HealingStarted,
            ProtocolEventKind::HealingSucceeded,
            ProtocolEventKind::HealingFailed {
                reason: "timeout".into(),
            },
            ProtocolEventKind::SelfTestPassed,
            ProtocolEventKind::SelfTestFailed {
                reason: "port blocked".into(),
            },
        ];

        for kind in kinds {
            roundtrip_message(Message::ProtocolEvt(ProtocolEvent {
                protocol_name: "xray".into(),
                role: ProtocolRole::Active,
                status: ProtocolStatus::Running,
                event: kind,
                timestamp: Utc::now(),
            }));
        }
    }

    #[test]
    fn orchestrator_decision_variants_roundtrip() {
        let decisions = vec![
            OrchestratorDecision::PromoteStandby {
                protocol_name: "amneziawg".into(),
            },
            OrchestratorDecision::QuarantineActive {
                protocol_name: "xray".into(),
                reason: "fingerprinted".into(),
            },
            OrchestratorDecision::BeginHealing {
                protocol_name: "xray".into(),
            },
            OrchestratorDecision::EmergencyShutdown {
                reason: "double crash".into(),
            },
            OrchestratorDecision::RestoreFromHealing {
                protocol_name: "xray".into(),
            },
        ];

        for decision in decisions {
            roundtrip_message(Message::OrchestratorDecision(decision));
        }
    }

    #[test]
    fn emergency_shutdown_roundtrip() {
        roundtrip_message(Message::EmergencyShutdown(EmergencyShutdown {
            reason: "both protocols down".into(),
            triggered_at: Utc::now(),
            active_protocol: Some("xray".into()),
            standby_protocol: None,
        }));
    }

    #[test]
    fn transport_extension_messages_roundtrip() {
        roundtrip_message(Message::ProfileRotationRequest(ProfileRotationRequest {
            protocol_name: Some("xray".into()),
            reason: "operator requested".into(),
            requested_at: Utc::now(),
        }));

        roundtrip_message(Message::TransportActiveRequest(TransportActiveRequest {
            protocol_name: "masque".into(),
            requested_at: Utc::now(),
        }));

        roundtrip_message(Message::PolicyApplyRequest(PolicyApplyRequest {
            policy_id: "default-zero-trust".into(),
            config_blob: vec![1, 2, 3],
            requested_at: Utc::now(),
        }));

        roundtrip_message(Message::MasqueTunnelConfig(MasqueTunnelConfig {
            tunnel_id: "masque-1".into(),
            proxy_authority: "proxy.example:443".into(),
            target_authority: "target.example:443".into(),
            kind: MasqueTunnelKind::ConnectUdp,
            inner_mtu: 1_280,
            use_quic_datagrams: true,
        }));

        roundtrip_message(Message::MasqueTunnelStatus(MasqueTunnelStatus {
            tunnel_id: "masque-1".into(),
            state: MasqueTunnelState::Configured,
            reason: None,
            timestamp: Utc::now(),
        }));

        roundtrip_message(Message::PathMetrics(PathMetrics {
            path_id: "direct-udp".into(),
            rtt_ms: 20,
            jitter_ms: 2,
            loss_ppm: 10,
            burn_score: 0.0,
            handshake_success_ppm: 999_000,
            relay_required: false,
            observed_at: Utc::now(),
        }));

        roundtrip_message(Message::PathSelection(PathSelection {
            selected_path_id: "direct-udp".into(),
            score: 20.0,
            reason: "lowest deterministic score".into(),
            selected_at: Utc::now(),
        }));

        roundtrip_message(Message::ProtocolHardeningProfile(
            ProtocolHardeningProfile {
                profile_id: "balanced-rf-inspired".into(),
                protocol_name: Some("masque".into()),
                traffic_morph: TrafficMorphProfile {
                    profile_id: "balanced-morph".into(),
                    padding: PaddingDistribution::Bucketed {
                        buckets: vec![64, 256, 768, 1_200],
                    },
                    max_padding_overhead_ppm: 80_000,
                    jitter_floor_ms: 2,
                    jitter_ceiling_ms: 20,
                    cover_traffic_ppm: 5_000,
                    packet_batching_window_ms: 5,
                },
                rekey: RekeyPolicy {
                    max_key_age_seconds: 600,
                    max_key_bytes: 1_073_741_824,
                    threat_triggered: true,
                    stagger_window_ms: 500,
                },
                probe_resistance: ProbeResistancePolicy {
                    authenticated_first_packet_required: true,
                    unauthenticated_failure_mode: ProbeFailureMode::ConstantShapeReject,
                    min_response_delay_ms: 5,
                    max_response_delay_ms: 25,
                    decoy_response_budget_per_hour: 0,
                },
                probe_deception: ProbeDeceptionPolicy {
                    enabled: true,
                    mode: ProbeDeceptionMode::ShadowEndpoint,
                    min_confidence: 0.6,
                    response_budget_per_source_per_hour: 20,
                    min_delay_ms: 10,
                    max_delay_ms: 80,
                    max_transcript_bytes: 512,
                    persona_rotation_seconds: 3_600,
                    log_transcripts: true,
                },
                path_hopping: PathHoppingPolicy {
                    enabled: true,
                    min_dwell_seconds: 120,
                    max_dwell_seconds: 900,
                    burn_score_threshold: 0.7,
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
                reason: "operator selected balanced hardening".into(),
            },
        ));

        roundtrip_message(Message::ProtocolHardeningStatus(ProtocolHardeningStatus {
            profile_id: "balanced-rf-inspired".into(),
            protocol_name: Some("masque".into()),
            accepted: true,
            reason: "profile accepted".into(),
            active_at: Utc::now(),
        }));

        roundtrip_message(Message::ProbeDeceptionDecision(ProbeDeceptionDecision {
            source: Some("203.0.113.10:443".parse().unwrap()),
            mode: ProbeDeceptionMode::ShadowEndpoint,
            persona_id: "shadow-1234".into(),
            response_delay_ms: 25,
            transcript_bytes: 256,
            routed_to_real_endpoint: false,
            reason: "unauthenticated high-confidence probe".into(),
            decided_at: Utc::now(),
        }));
    }

    #[test]
    fn strainer_messages_roundtrip() {
        roundtrip_message(Message::StrainerRejection(StrainerRejection {
            strainer_id: "auth_shape_outer".into(),
            stack_id: "xray_probe_stack".into(),
            shape_failed: "oversized".into(),
            source_identifier: Some("1.2.3.4:5678".parse().unwrap()),
            timestamp: Utc::now(),
        }));

        let mut params = HashMap::new();
        params.insert("jitter_ms".into(), serde_json::json!(50));
        roundtrip_message(Message::StrainerStackComposition(
            StrainerStackComposition {
                name: "xray_probe".into(),
                protocol_context: "xray".into(),
                stages: vec![StrainerStageConfig {
                    strainer_name: "timing".into(),
                    parameters: params,
                    order: 0,
                }],
            },
        ));

        roundtrip_message(Message::RoutingDecision(RoutingDecision::Deny {
            reason: "suspect source".into(),
        }));
    }

    #[test]
    fn access_and_leak_guard_messages_roundtrip() {
        let identity = PeerId::new();
        roundtrip_message(Message::IdentityCapabilityGrant(IdentityCapabilityGrant {
            identity_id: identity.clone(),
            capabilities: vec!["vpn.health".into()],
            issued_by: PeerId::new(),
            issued_at: Utc::now(),
            expires_at: None,
            signature: vec![1, 2, 3],
        }));

        roundtrip_message(Message::IdentityAccessDecision(IdentityAccessDecision {
            identity_id: identity,
            capability: "vpn.health".into(),
            allowed: true,
            reason: "capability granted".into(),
            decided_at: Utc::now(),
        }));

        roundtrip_message(Message::KillSwitchCommand(KillSwitchCommand {
            state: KillSwitchState::Engaged,
            reason: "dns leak".into(),
            issued_at: Utc::now(),
        }));

        roundtrip_message(Message::LeakGuardStatus(LeakGuardStatus {
            dns_guard_enabled: true,
            route_guard_enabled: true,
            kill_switch: KillSwitchState::Armed,
            last_violation: None,
            timestamp: Utc::now(),
        }));
    }

    #[test]
    fn illusion_seam_messages_roundtrip() {
        let now = Utc::now();
        let src = AvalanchedSource::minted_by_guard("10.9.9.9:443", 7, now);
        assert!(src.validate().is_ok());
        roundtrip(&src);
        assert!(AvalanchedSource::minted_by_guard("", 7, now)
            .validate()
            .is_err());
        assert!(AvalanchedSource::minted_by_guard("x", 0, now)
            .validate()
            .is_err());
        assert!(
            AvalanchedSource::minted_by_guard("x", 1, now + chrono::Duration::hours(2))
                .validate()
                .is_err()
        );
        roundtrip_message(Message::IllusionAdmission(HoldingFaceAdmission {
            source: "gray-knock".into(),
            holding_face_id: 1,
            shape_hint: "unknown-handshake".into(),
            admitted_at: now,
        }));
        roundtrip_message(Message::IllusionDisputeLogged(IllusionDispute {
            source: "gray-knock".into(),
            shape_hint: "unknown-handshake".into(),
            detail: "first 8 bytes unrecognized".into(),
            logged_at: now,
        }));
        roundtrip_message(Message::IllusionBudgetExhausted(IllusionBudgetExhausted {
            source: "10.9.9.9:443".into(),
            face_id: 7,
            bytes_emitted: 4096,
            exhausted_at: now,
        }));
    }

    #[test]
    fn sensor_messages_roundtrip() {
        roundtrip_message(Message::ThreatAssessment(ThreatAssessment {
            source: ThreatSource::Classifier {
                model_name: "threat_v1".into(),
            },
            confidence: 0.87,
            description: "suspicious timing".into(),
            remote_addr: Some("10.0.0.5:443".parse().unwrap()),
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::ActivateStrainer {
                strainer_name: "byte_jitter".into(),
            },
        }));

        roundtrip_message(Message::ThreatAssessment(ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 1.0,
            description: "yara match".into(),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        }));
    }

    #[test]
    fn probe_profile_roundtrip() {
        roundtrip_message(Message::ProbeProfile(ProbeProfile {
            source: "10.0.0.5:41022".parse().unwrap(),
            rhythm_pe: 0.329,
            drift: 0.402_555_910_543_131,
            repeat_ratio: 1.0,
            exploration: 0.015625,
            convergence: 0.5,
            rate_per_sec: 40_000.0,
            sufficiency: ProbeSufficiency {
                probes_in_window: 64,
                gaps_in_window: 63,
                probes_seen: 128,
                epochs_compared: 3,
            },
            last_seen_micros: 1_234_567,
        }));

        // Every dimension is its own number: re-serialising a profile with one
        // dimension moved must not disturb the others.
        let profile = ProbeProfile {
            source: "10.0.0.5:41022".parse().unwrap(),
            rhythm_pe: 0.0,
            drift: 0.0,
            repeat_ratio: 0.0,
            exploration: 0.0,
            convergence: 0.0,
            rate_per_sec: 0.0,
            sufficiency: ProbeSufficiency::default(),
            last_seen_micros: 0,
        };
        let json = serde_json::to_string(&profile).expect("serialize profile");
        assert!(
            !json.contains("confidence") && !json.contains("suggested_action"),
            "a probe profile must not carry a score or a verdict field: {json}"
        );
        // The wire form carries the trend reading as its own column, beside the
        // arrangement reading it deliberately does not replace.
        assert!(
            json.contains("\"drift\"") && json.contains("\"rhythm_pe\""),
            "both cadence readings must reach the wire separately: {json}"
        );
        assert!(
            !json.contains("\"score\"") && !json.contains("\"combined\""),
            "no field may combine the dimensions: {json}"
        );
    }

    #[test]
    fn signature_messages_roundtrip() {
        let id = Uuid::new_v4();
        let now = Utc::now();

        roundtrip_message(Message::SignatureApprovalRequest(
            SignatureApprovalRequest { candidate_id: id },
        ));

        roundtrip_message(Message::SignatureCandidate(SignatureCandidate {
            id,
            rule_text: r#"rule probe { strings: $a = { DE AD BE EF } condition: $a }"#.into(),
            description: "suspicious probe pattern".into(),
            source_events: vec![EventId::new(), EventId::new()],
            extracted_at: now,
            confidence: 0.85,
        }));

        roundtrip_message(Message::SignatureApproved(SignatureApproved {
            candidate_id: id,
            approved_by: PeerId::new(),
            approved_at: now,
            signature: vec![1, 2, 3],
        }));

        roundtrip_message(Message::SignatureRejected(SignatureRejected {
            candidate_id: id,
            rejected_by: PeerId::new(),
            rejected_at: now,
            reason: "false positive".into(),
        }));

        roundtrip_message(Message::SignatureActivated(ExtractedSignatureActivated {
            candidate_id: id,
            signature_id: Uuid::new_v4(),
            activated_at: now,
        }));

        roundtrip_message(Message::SignatureActivationFailed(
            SignatureActivationFailed {
                candidate_id: id,
                compile_error: "invalid YARA syntax".into(),
                failed_at: now,
            },
        ));

        roundtrip_message(Message::ExtractionRequest(ExtractionRequest {
            triggering_event_ids: vec![EventId::new(), EventId::new()],
            reason: "suspicious pattern".into(),
            requested_by: "operator".into(),
        }));

        roundtrip_message(Message::SignatureCandidatePending(
            SignatureCandidatePending {
                candidate_id: id,
                requested_by: "operator".into(),
                ready_at: now,
            },
        ));

        roundtrip_message(Message::ExtractionFailed(ExtractionFailed {
            triggering_event_ids: vec![EventId::new()],
            reason: "event not found".into(),
            failed_at: now,
        }));

        roundtrip_message(Message::SignatureRollback(ExtractedSignatureRollback {
            candidate_id: id,
            rolled_back_at: now,
            reason: "fp in production".into(),
        }));
    }

    #[test]
    fn toolkit_messages_roundtrip() {
        roundtrip_message(Message::ToolStateChange(ToolStateChange {
            tool_name: "suricata".into(),
            from: ToolState::Dormant,
            to: ToolState::Armed,
            reason: "operator armed".into(),
            timestamp: Utc::now(),
        }));

        let mut ctx = HashMap::new();
        ctx.insert("severity".into(), "high".into());
        roundtrip_message(Message::ToolActivationReq(ToolActivationRequest {
            tool_name: "suricata".into(),
            trigger: "threat > 0.8".into(),
            context: ctx,
            timestamp: Utc::now(),
        }));

        roundtrip_message(Message::ToolBudget(ToolBudget {
            tool_name: "suricata".into(),
            max_activations_per_hour: 5,
            cooldown_seconds: 60,
            remaining_activations: 3,
        }));
    }

    #[test]
    fn infrastructure_messages_roundtrip() {
        roundtrip_message(Message::SubsystemReady {
            name: "sensors".into(),
        });
        roundtrip_message(Message::SubsystemStopping {
            name: "transport".into(),
            reason: "shutdown".into(),
        });
    }

    #[test]
    fn bus_event_has_unique_id_and_timestamp() {
        let msg = Message::SubsystemReady {
            name: "test".into(),
        };
        let e1 = BusEvent::new("test.topic", msg.clone());
        let e2 = BusEvent::new("test.topic", msg);

        assert_ne!(e1.id.0, e2.id.0);
        assert_eq!(&*e1.topic, "test.topic");
    }

    #[test]
    fn bus_event_topic_stored_correctly() {
        let event = BusEvent::new(
            "net.cluster.join",
            Message::SubsystemReady {
                name: "cluster".into(),
            },
        );
        assert_eq!(&*event.topic, "net.cluster.join");
    }

    #[test]
    fn suggested_action_enum_coverage() {
        let actions = vec![
            SuggestedAction::None,
            SuggestedAction::IncreaseMonitoring,
            SuggestedAction::ActivateStrainer {
                strainer_name: "timing".into(),
            },
            SuggestedAction::TriggerFailover,
            SuggestedAction::EmergencyShutdown,
        ];
        for action in actions {
            roundtrip(&action);
        }
    }

    #[test]
    fn threat_source_enum_coverage() {
        let sources = vec![
            ThreatSource::Classifier {
                model_name: "v1".into(),
            },
            ThreatSource::SignatureEngine,
            ThreatSource::Heuristic {
                name: "timing".into(),
            },
        ];
        for source in sources {
            roundtrip(&source);
        }
    }

    #[test]
    fn routing_decision_enum_coverage() {
        let decisions = vec![
            RoutingDecision::Allow,
            RoutingDecision::Deny {
                reason: "blocked".into(),
            },
            RoutingDecision::Degrade {
                method: "truncate".into(),
            },
        ];
        for decision in decisions {
            roundtrip(&decision);
        }
    }

    #[test]
    fn orchestrator_state_eq() {
        assert_eq!(OrchestratorState::Steady, OrchestratorState::Steady);
        assert_ne!(OrchestratorState::Steady, OrchestratorState::Emergency);
    }

    #[test]
    fn tool_state_eq() {
        assert_eq!(ToolState::Dormant, ToolState::Dormant);
        assert_ne!(ToolState::Dormant, ToolState::Active);
    }

    #[test]
    fn socket_addr_survives_serde() {
        let addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let rejection = StrainerRejection {
            strainer_id: "test".into(),
            stack_id: "stack_test".into(),
            shape_failed: "test".into(),
            source_identifier: Some(addr),
            timestamp: Utc::now(),
        };
        let json = serde_json::to_string(&rejection).unwrap();
        let back: StrainerRejection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.source_identifier, Some(addr));
    }

    #[test]
    fn empty_collections_roundtrip() {
        roundtrip_message(Message::MeshPeerAnnouncement(MeshPeerAnnouncement {
            peer_id: PeerId::new(),
            endpoints: vec![],
            capabilities: vec![],
        }));

        roundtrip_message(Message::ToolActivationReq(ToolActivationRequest {
            tool_name: "empty".into(),
            trigger: "manual".into(),
            context: HashMap::new(),
            timestamp: Utc::now(),
        }));
    }
}

#[cfg(test)]
mod lightcone_symbol_tests {
    use super::LightconeSymbol;

    #[test]
    fn a_full_ipv6_value_survives_json() {
        let s = LightconeSymbol { field: 3, value: 0xfe80_0000_0000_0000_5054_00ff_fe78_0001 };
        let text = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<LightconeSymbol>(&text).unwrap(), s);
        let max = LightconeSymbol { field: 4, value: u128::MAX };
        assert_eq!(serde_json::from_str::<LightconeSymbol>(&serde_json::to_string(&max).unwrap()).unwrap(), max);
    }
}
