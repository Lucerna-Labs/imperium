//! Operator console for the Imperium runtime.
//!
//! The console shares the node's typed bus for status and ordinary operator
//! requests. Kill-switch actions use the owner-only local control socket so
//! the control service coordinates optional host blocking with mesh state.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use imperium_net_transport::HardeningController;
use imperium_protocol::{
    BusEvent, EmergencyShutdown, KillSwitchState, Message, OrchestratorDecision, OrchestratorState,
    PeerId, ProtocolHardeningProfile, ProtocolHardeningStatus, SignatureRejected, SuggestedAction,
    ThreatSource, VpnDeploymentStatus,
};
use parking_lot::RwLock;
use spiderweb::BusPublisher;

mod app;
mod control_socket;
mod theme;
mod views;

pub use app::{run, run_with_state, run_with_state_and_control};

/// Shared state created before subsystem startup so the console sees initial
/// status events even though the native window is opened later.
pub type SharedUiState = Arc<RwLock<UiState>>;

const THREAT_HISTORY: usize = 400;
const ACTIVITY_HISTORY: usize = 250;
/// One bucket per second, two minutes of rate telemetry.
const RATE_WINDOW: usize = 120;

fn embedded_lightcone_pack_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        imperium_net_world::embedded::HASH
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    })
    .as_str()
}

#[derive(Clone, Debug)]
pub struct ThreatRow {
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub confidence: f64,
    pub description: String,
    pub action: String,
}

#[derive(Clone, Debug)]
pub struct ActivityRow {
    pub timestamp: DateTime<Utc>,
    pub topic: Arc<str>,
    pub label: String,
    pub emergency: bool,
}

/// View-model for the console. The bus pump is the only writer; the GUI
/// thread only reads, so a single RwLock is the whole synchronization story.
pub struct UiState {
    pub started_at: DateTime<Utc>,
    pub orchestrator: Option<OrchestratorState>,
    pub active_protocol: Option<String>,
    pub standby_protocol: Option<String>,
    pub last_decision: Option<String>,
    pub kill_switch: Option<KillSwitchState>,
    pub pending_kill_switch: Option<KillSwitchState>,
    pub last_hardening: Option<ProtocolHardeningStatus>,
    pub last_deployment: Option<VpnDeploymentStatus>,
    pub threats: VecDeque<ThreatRow>,
    pub threat_rate: VecDeque<u32>,
    last_rate_second: i64,
    pub activity: VecDeque<ActivityRow>,
    pub events_total: u64,
    pub namespace_counts: BTreeMap<String, u64>,
    pub subsystems: BTreeMap<String, DateTime<Utc>>,
    /// Receipts seen by this console. These are not counts of all wire frames.
    pub lightcone_inbound_receipts: u64,
    pub lightcone_outbound_receipts: u64,
    pub lightcone_latest_sequence: Option<u64>,
    pub lightcone_v4_receipt_seen: bool,
}

impl Default for UiState {
    fn default() -> Self {
        Self::new()
    }
}

impl UiState {
    pub fn new() -> Self {
        Self {
            started_at: Utc::now(),
            orchestrator: None,
            active_protocol: None,
            standby_protocol: None,
            last_decision: None,
            kill_switch: None,
            pending_kill_switch: None,
            last_hardening: None,
            last_deployment: None,
            threats: VecDeque::with_capacity(THREAT_HISTORY),
            threat_rate: VecDeque::from(vec![0; RATE_WINDOW]),
            last_rate_second: Utc::now().timestamp(),
            activity: VecDeque::with_capacity(ACTIVITY_HISTORY),
            events_total: 0,
            namespace_counts: BTreeMap::new(),
            subsystems: BTreeMap::new(),
            lightcone_inbound_receipts: 0,
            lightcone_outbound_receipts: 0,
            lightcone_latest_sequence: None,
            lightcone_v4_receipt_seen: false,
        }
    }

    pub fn apply(&mut self, event: BusEvent) {
        let is_threat = matches!(event.message, Message::ThreatAssessment(_));

        match &event.message {
            Message::ThreatAssessment(t) => {
                let source = match &t.source {
                    ThreatSource::Classifier { model_name } => {
                        format!("classifier · {model_name}")
                    }
                    ThreatSource::SignatureEngine => "signature engine".to_string(),
                    ThreatSource::Heuristic { name } => format!("heuristic · {name}"),
                };
                let action = match &t.suggested_action {
                    SuggestedAction::None => "none".to_string(),
                    SuggestedAction::IncreaseMonitoring => "increase monitoring".to_string(),
                    SuggestedAction::ActivateStrainer { strainer_name } => {
                        format!("activate strainer · {strainer_name}")
                    }
                    SuggestedAction::TriggerFailover => "trigger failover".to_string(),
                    SuggestedAction::EmergencyShutdown => "emergency shutdown".to_string(),
                };
                let row = ThreatRow {
                    timestamp: t.timestamp,
                    source,
                    confidence: t.confidence,
                    description: t.description.clone(),
                    action,
                };
                self.threats.push_back(row);
                while self.threats.len() > THREAT_HISTORY {
                    self.threats.pop_front();
                }
            }
            Message::LeakGuardStatus(s) => {
                self.kill_switch = Some(s.kill_switch.clone());
                self.pending_kill_switch = None;
            }
            Message::KillSwitchCommand(c) => {
                // This is a request. The mesh data plane publishes status only
                // after it has applied the request.
                self.pending_kill_switch = Some(c.state.clone());
            }
            Message::OrchestratorDecision(d) => {
                let (label, state) = match d {
                    OrchestratorDecision::PromoteStandby { protocol_name } => {
                        self.active_protocol = Some(protocol_name.clone());
                        (
                            format!("promote standby · {protocol_name}"),
                            Some(OrchestratorState::Failover),
                        )
                    }
                    OrchestratorDecision::QuarantineActive { protocol_name, .. } => (
                        format!("quarantine {protocol_name}"),
                        Some(OrchestratorState::Healing),
                    ),
                    OrchestratorDecision::BeginHealing { protocol_name } => (
                        format!("begin healing · {protocol_name}"),
                        Some(OrchestratorState::Healing),
                    ),
                    other => (decision_label(other), None),
                };
                self.last_decision = Some(label);
                if let Some(state) = state {
                    self.orchestrator = Some(state);
                }
            }
            Message::EmergencyShutdown(_) => self.orchestrator = Some(OrchestratorState::Emergency),
            Message::ProtocolHardeningStatus(s) => self.last_hardening = Some(s.clone()),
            Message::VpnDeploymentStatus(s) => self.last_deployment = Some(s.clone()),
            Message::LightconeReceipt(receipt) => {
                match receipt.direction {
                    0 => {
                        self.lightcone_inbound_receipts =
                            self.lightcone_inbound_receipts.saturating_add(1)
                    }
                    1 => {
                        self.lightcone_outbound_receipts =
                            self.lightcone_outbound_receipts.saturating_add(1)
                    }
                    other => tracing::debug!(
                        direction = other,
                        "ignored Lightcone receipt with unknown direction"
                    ),
                }
                if receipt.direction <= 1 {
                    self.lightcone_latest_sequence = Some(
                        self.lightcone_latest_sequence
                            .unwrap_or(0)
                            .max(receipt.sequence),
                    );
                    if receipt.sequence > 0
                        && receipt.passive
                        && !receipt.holds_verdict
                        && receipt
                            .pack_sha256
                            .eq_ignore_ascii_case(embedded_lightcone_pack_hash())
                    {
                        self.lightcone_v4_receipt_seen = true;
                    }
                }
            }
            Message::SubsystemReady { name } => {
                self.subsystems.entry(name.clone()).or_insert_with(Utc::now);
            }
            Message::SubsystemStopping { name, .. } => {
                self.subsystems.remove(name);
            }
            _ => {}
        }

        self.advance_rate_window(event.timestamp, is_threat);
        self.events_total += 1;
        let namespace: String = event.topic.split('.').take(2).collect::<Vec<_>>().join(".");
        *self.namespace_counts.entry(namespace).or_insert(0) += 1;

        let emergency = event.topic.starts_with("emergency");
        self.activity.push_back(ActivityRow {
            timestamp: event.timestamp,
            topic: Arc::clone(&event.topic),
            label: summarize(&event.message),
            emergency,
        });
        while self.activity.len() > ACTIVITY_HISTORY {
            self.activity.pop_front();
        }
    }

    fn advance_rate_window(&mut self, timestamp: DateTime<Utc>, is_threat: bool) {
        let sec = timestamp.timestamp();
        if sec > self.last_rate_second {
            let gap = (sec - self.last_rate_second).min(RATE_WINDOW as i64);
            for _ in 0..gap {
                self.threat_rate.push_back(0);
            }
            while self.threat_rate.len() > RATE_WINDOW {
                self.threat_rate.pop_front();
            }
            self.last_rate_second = sec;
        } else if sec < self.last_rate_second {
            // Out-of-order timestamps keep the current bucket.
            return;
        }
        if is_threat {
            if let Some(bucket) = self.threat_rate.back_mut() {
                *bucket += 1;
            }
        }
    }

    pub fn threats_last_minute(&self) -> u32 {
        self.threats_last_minute_at(Utc::now())
    }

    fn threats_last_minute_at(&self, now: DateTime<Utc>) -> u32 {
        let idle_seconds = now.timestamp().saturating_sub(self.last_rate_second).max(0) as usize;
        self.threat_rate
            .iter()
            .rev()
            .take(60usize.saturating_sub(idle_seconds))
            .sum()
    }

    /// A current two-minute series for plotting, including the quiet seconds
    /// since the most recent bus event. Reading it does not mutate bus state.
    pub fn current_threat_series(&self) -> Vec<u32> {
        self.threat_series_at(Utc::now())
    }

    fn threat_series_at(&self, now: DateTime<Utc>) -> Vec<u32> {
        let mut series: Vec<u32> = self.threat_rate.iter().copied().collect();
        let idle_seconds = (now.timestamp().saturating_sub(self.last_rate_second).max(0) as usize)
            .min(series.len());
        series.rotate_left(idle_seconds);
        if idle_seconds > 0 {
            let len = series.len();
            series[len - idle_seconds..].fill(0);
        }
        series
    }
}

fn decision_label(decision: &OrchestratorDecision) -> String {
    let debug = format!("{decision:?}");
    debug
        .split([' ', '{', '('])
        .next()
        .unwrap_or("decision")
        .to_string()
}

/// One-line human label for any bus message, used by the activity feed.
pub fn summarize(message: &Message) -> String {
    match message {
        Message::SubsystemReady { name } => format!("subsystem ready · {name}"),
        Message::SubsystemStopping { name, reason } => {
            format!("subsystem stopping · {name} ({reason})")
        }
        Message::ThreatAssessment(t) => format!("threat · {}", t.description),
        Message::OrchestratorDecision(d) => decision_label(d),
        Message::EmergencyShutdown(s) => format!("emergency shutdown · {}", s.reason),
        Message::ProtocolHardeningStatus(s) => format!(
            "hardening {} · {}",
            if s.accepted { "accepted" } else { "rejected" },
            s.profile_id
        ),
        Message::VpnDeploymentStatus(s) => format!(
            "deployment · {}/{} nodes approved",
            s.approved_nodes, s.planned_nodes
        ),
        Message::LightconeReceipt(receipt) => {
            let direction = match receipt.direction {
                0 => "inbound",
                1 => "outbound",
                _ => "unknown direction",
            };
            format!("lightcone receipt #{} · {direction}", receipt.sequence)
        }
        Message::KillSwitchCommand(c) => format!("kill switch · {:?}", c.state),
        Message::LeakGuardStatus(s) => format!("leak guard · kill switch {:?}", s.kill_switch),
        Message::SignatureCandidate(c) => {
            format!("signature candidate · {}", c.description)
        }
        Message::SignatureApproved(a) => format!("signature approved · {}", a.candidate_id),
        Message::SignatureRejected(r) => format!("signature rejected · {}", r.candidate_id),
        Message::ProfileRotationRequest(r) => {
            format!(
                "profile rotation · {}",
                r.protocol_name.as_deref().unwrap_or("all")
            )
        }
        other => variant_name(other),
    }
}

fn variant_name(message: &Message) -> String {
    let debug = format!("{message:?}");
    debug
        .split([' ', '{', '('])
        .next()
        .unwrap_or("Message")
        .to_string()
}

/// Spawns the bus pump onto the current Tokio runtime and returns the shared
/// view-model the GUI thread reads each frame. Must be called from async
/// context (the runtime handle is required).
pub fn spawn_pump(publisher: Arc<BusPublisher>) -> SharedUiState {
    let state = Arc::new(RwLock::new(UiState::new()));
    let pump_state = Arc::clone(&state);

    // The console owns its own bounded queue. Native delivery is push-based and
    // the kernel keeps no per-subscriber queue, so this pump is NOT protected by
    // the bus — the queue below is what protects it. The callback runs on the
    // publisher's thread and only does a non-blocking send; a full queue drops
    // the event and counts it, and the pump reports the count before the next
    // event so a burst that overflowed is visible.
    //
    // Depth is deliberately larger than the shim's per-subscription depth: a
    // console is a monitoring surface, so dropping less is worth the memory.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<BusEvent>(UI_PUMP_QUEUE);
    let dropped = Arc::new(AtomicU64::new(0));
    let drops = Arc::clone(&dropped);
    publisher.subscribe_all(Box::new(move |_socket, payload| {
        if let Ok(event) = payload.downcast::<BusEvent>() {
            if tx.try_send(*event).is_err() {
                drops.fetch_add(1, Ordering::Relaxed);
            }
        }
    }));

    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            // Lag drops are expected on a UI subscriber; the console is a
            // monitoring surface, not part of the auditable substrate.
            let lagged = dropped.swap(0, Ordering::Relaxed);
            if lagged > 0 {
                tracing::warn!(lagged, "gui bus queue overflowed; events were dropped");
            }
            pump_state.write().apply(event);
        }
    });
    state
}

/// Depth of the console's own bus queue. Larger than the deleted shim's
/// per-subscription depth, because a console would rather hold memory than drop
/// an event a human is watching for.
const UI_PUMP_QUEUE: usize = 4096;

/// Operator commands. Host-affecting kill-switch changes go through the
/// node's ordered control service; other requests retain their typed bus path.
pub mod commands {
    use super::*;

    pub(crate) fn kill_switch(
        runtime: &tokio::runtime::Handle,
        endpoint: &str,
        state: KillSwitchState,
        reason: &str,
    ) -> tokio::sync::oneshot::Receiver<Result<crate::control_socket::ControlReply, String>> {
        let mode = match state {
            KillSwitchState::Disarmed => "disarm",
            KillSwitchState::Armed => "arm",
            KillSwitchState::Engaged => "engage",
        };
        let command = format!("vpn killswitch {mode} {reason}");
        let endpoint = endpoint.to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        runtime.spawn(async move {
            let result = crate::control_socket::request(&endpoint, &command).await;
            let _ = tx.send(result);
        });
        rx
    }

    pub fn apply_hardening(
        bus: &BusPublisher,
        profile: ProtocolHardeningProfile,
    ) -> Result<(), String> {
        HardeningController::validate(&profile)
            .map_err(|e| format!("invalid hardening profile: {e}"))?;
        BusEvent::publish(
            bus,
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(profile),
        )
        .map_err(|error| format!("hardening request failed: {error}"))
    }

    pub fn hardening_preset(
        bus: &BusPublisher,
        preset: &str,
        protocol: Option<String>,
    ) -> Result<(), String> {
        let profile = match preset {
            "balanced" => HardeningController::balanced_profile(protocol),
            "resilience" => HardeningController::resilience_profile(protocol),
            "fortress" => HardeningController::fortress_profile(protocol),
            other => return Err(format!("unknown preset: {other}")),
        };
        apply_hardening(bus, profile)
    }

    pub fn approve_signature(bus: &BusPublisher, candidate_id: uuid::Uuid) {
        let _ = BusEvent::publish(
            bus,
            "net.signatures.approve_request",
            Message::SignatureApprovalRequest(imperium_protocol::SignatureApprovalRequest {
                candidate_id,
            }),
        );
    }

    pub fn reject_signature(bus: &BusPublisher, candidate_id: uuid::Uuid, reason: &str) {
        let _ = BusEvent::publish(
            bus,
            "net.signatures.reject_request",
            Message::SignatureRejected(SignatureRejected {
                candidate_id,
                rejected_by: PeerId::new(),
                rejected_at: Utc::now(),
                reason: reason.to_string(),
            }),
        );
    }

    pub fn shutdown(bus: &BusPublisher, reason: &str) {
        let _ = BusEvent::publish(
            bus,
            "emergency.cli.operator_shutdown",
            Message::EmergencyShutdown(EmergencyShutdown {
                reason: reason.to_string(),
                triggered_at: Utc::now(),
                active_protocol: None,
                standby_protocol: None,
            }),
        );
    }
}

/// Per-candidate UI bookkeeping owned by the app (not bus state).
#[derive(Default)]
pub struct SignatureDrafts {
    pub reject_reasons: HashMap<uuid::Uuid, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A named subscription feeding an owned bounded queue — the shape an async
    /// consumer outside a strand must have now that delivery is push-based.
    fn subscribe_queue(
        publisher: &BusPublisher,
        prefix: &'static str,
        capacity: usize,
    ) -> tokio::sync::mpsc::Receiver<BusEvent> {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        publisher.subscribe_prefix(
            prefix,
            Box::new(move |_socket, payload| {
                if let Ok(event) = payload.downcast::<BusEvent>() {
                    let _ = tx.try_send(*event);
                }
            }),
        );
        rx
    }
    use chrono::TimeDelta;

    fn event(topic: &str, message: Message) -> BusEvent {
        BusEvent::new(topic, message)
    }

    fn lightcone_receipt(
        sequence: u64,
        direction: u8,
        pack_sha256: &str,
    ) -> imperium_protocol::LightconeReceipt {
        imperium_protocol::LightconeReceipt {
            sequence,
            direction,
            frame_format: imperium_protocol::LightconeFrameFormat::MeshDatagram,
            observation_kind: 0,
            pack_sha256: pack_sha256.into(),
            query_sha256: "test-query".into(),
            receipt_sha256: "test-receipt".into(),
            seeds: Vec::new(),
            nodes: Vec::new(),
            edges: Vec::new(),
            excluded: Vec::new(),
            hop_frontier: Vec::new(),
            passive: true,
            holds_verdict: false,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn threat_events_fill_rows_and_rate_buckets() {
        let mut state = UiState::new();
        state.apply(event(
            "net.sensors.threat",
            Message::ThreatAssessment(imperium_protocol::ThreatAssessment {
                source: ThreatSource::SignatureEngine,
                confidence: 0.9,
                description: "probe burst".into(),
                remote_addr: None,
                timestamp: Utc::now(),
                suggested_action: SuggestedAction::IncreaseMonitoring,
            }),
        ));

        assert_eq!(state.threats.len(), 1);
        assert_eq!(state.threats[0].source, "signature engine");
        assert_eq!(state.threats[0].action, "increase monitoring");
        assert_eq!(*state.threat_rate.back().unwrap(), 1);
        assert_eq!(state.threats_last_minute(), 1);
    }

    #[test]
    fn kill_switch_tracks_commands_and_leak_guard() {
        let mut state = UiState::new();
        state.apply(event(
            "net.transport.killswitch.command",
            Message::KillSwitchCommand(imperium_protocol::KillSwitchCommand {
                state: KillSwitchState::Armed,
                reason: "test".into(),
                issued_at: Utc::now(),
            }),
        ));
        assert_eq!(state.kill_switch, None);
        assert_eq!(state.pending_kill_switch, Some(KillSwitchState::Armed));

        state.apply(event(
            "net.transport.leakguard",
            Message::LeakGuardStatus(imperium_protocol::LeakGuardStatus {
                dns_guard_enabled: true,
                route_guard_enabled: true,
                kill_switch: KillSwitchState::Engaged,
                last_violation: None,
                timestamp: Utc::now(),
            }),
        ));
        assert_eq!(state.kill_switch, Some(KillSwitchState::Engaged));
        assert_eq!(state.pending_kill_switch, None);
    }

    #[test]
    fn lightcone_counts_only_observed_directions_and_keeps_latest_sequence() {
        let mut state = UiState::new();
        assert_eq!(state.lightcone_latest_sequence, None);

        for (sequence, direction) in [(4, 0), (5, 1), (3, 0), (6, 9)] {
            state.apply(event(
                "net.lightcone.receipt",
                Message::LightconeReceipt(lightcone_receipt(sequence, direction, "test-pack")),
            ));
        }

        assert_eq!(state.lightcone_inbound_receipts, 2);
        assert_eq!(state.lightcone_outbound_receipts, 1);
        assert_eq!(state.lightcone_latest_sequence, Some(5));
        assert!(!state.lightcone_v4_receipt_seen);

        state.apply(event(
            "net.lightcone.receipt",
            Message::LightconeReceipt(lightcone_receipt(7, 0, embedded_lightcone_pack_hash())),
        ));
        assert_eq!(state.lightcone_inbound_receipts, 3);
        assert_eq!(state.lightcone_latest_sequence, Some(7));
        assert!(state.lightcone_v4_receipt_seen);
    }

    #[test]
    fn orchestrator_decision_updates_state_and_active_protocol() {
        let mut state = UiState::new();
        state.apply(event(
            "net.transport.decision",
            Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby {
                protocol_name: "masque".into(),
            }),
        ));
        assert_eq!(state.orchestrator, Some(OrchestratorState::Failover));
        assert_eq!(state.active_protocol.as_deref(), Some("masque"));
        assert!(state.last_decision.as_deref().unwrap().contains("promote"));
    }

    #[test]
    fn rate_window_capped_and_zeros_gap_seconds() {
        let mut state = UiState::new();
        let base = Utc::now();
        state.last_rate_second = base.timestamp();
        state.apply(event_at(
            "net.sensors.threat",
            Message::ThreatAssessment(threat_at(base + TimeDelta::seconds(3))),
            base + TimeDelta::seconds(3),
        ));
        assert_eq!(state.threat_rate.len(), RATE_WINDOW);
        // Three gap seconds pushed zeros, the landing bucket holds the threat.
        let tail: Vec<u32> = state.threat_rate.iter().rev().take(4).copied().collect();
        assert_eq!(tail, vec![1, 0, 0, 0]);
    }

    #[test]
    fn rate_window_ages_while_bus_is_quiet() {
        let mut state = UiState::new();
        let base = Utc::now();
        state.last_rate_second = base.timestamp();
        state.apply(event_at(
            "net.sensors.threat",
            Message::ThreatAssessment(threat_at(base)),
            base,
        ));

        assert_eq!(state.threats_last_minute_at(base), 1);
        assert_eq!(
            state.threats_last_minute_at(base + TimeDelta::seconds(59)),
            1
        );
        assert_eq!(
            state.threats_last_minute_at(base + TimeDelta::seconds(60)),
            0
        );
        assert_eq!(
            state.threat_series_at(base + TimeDelta::seconds(120)),
            vec![0; RATE_WINDOW]
        );
    }

    #[test]
    fn subsystem_readiness_and_namespace_counts() {
        let mut state = UiState::new();
        state.apply(event(
            "net.sensors.ready",
            Message::SubsystemReady {
                name: "sensors".into(),
            },
        ));
        state.apply(event(
            "net.sensors.threat",
            Message::ThreatAssessment(threat_at(Utc::now())),
        ));
        assert!(state.subsystems.contains_key("sensors"));
        assert_eq!(state.namespace_counts.get("net.sensors"), Some(&2));
        assert_eq!(state.events_total, 2);
        assert_eq!(state.activity.len(), 2);
    }

    #[test]
    fn summarize_known_and_fallback() {
        assert_eq!(
            summarize(&Message::SubsystemReady {
                name: "mesh".into()
            }),
            "subsystem ready · mesh"
        );
        let label = summarize(&Message::MeshPing(imperium_protocol::MeshPing {
            peer_id: PeerId::new(),
            session_id: imperium_protocol::SessionId::new(),
            seq: 1,
            sent_at: Utc::now(),
        }));
        assert_eq!(label, "MeshPing");
    }

    #[tokio::test]
    async fn approve_signature_publishes_typed_request() {
        // A publisher-only kernel plus an owned queue: the GUI tests never run
        // a supervision loop, and a named subscription now feeds a queue the
        // consumer owns.
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mut sub = subscribe_queue(&bus, "net.signatures.approve_request", 32);
        let id = uuid::Uuid::new_v4();
        commands::approve_signature(&bus, id);
        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .expect("typed approve request published")
            .unwrap();
        assert!(
            matches!(event.message, Message::SignatureApprovalRequest(req) if req.candidate_id == id)
        );
    }

    fn threat_at(ts: DateTime<Utc>) -> imperium_protocol::ThreatAssessment {
        imperium_protocol::ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.5,
            description: "test".into(),
            remote_addr: None,
            timestamp: ts,
            suggested_action: SuggestedAction::None,
        }
    }

    fn event_at(topic: &str, message: Message, ts: DateTime<Utc>) -> BusEvent {
        let mut ev = BusEvent::new(topic, message);
        ev.timestamp = ts;
        ev
    }
}
