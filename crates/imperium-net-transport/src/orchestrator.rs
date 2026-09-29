use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use imperium_net_sensors::{FusionPolicy, SensorFusion};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    EmergencyShutdown, Message, OrchestratorDecision, OrchestratorState, ProtocolCommand,
    ProtocolCommandKind, ProtocolEvent, ProtocolEventKind, ProtocolRole, ProtocolStatus,
    SuggestedAction, ThreatAssessment, ToolActivationRequest,
};
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;

use crate::hardening::HardeningController;

#[derive(Debug, Error)]
pub enum OrchestratorError {
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
    #[error("invalid state transition: {from:?} -> {to:?}")]
    InvalidTransition {
        from: OrchestratorState,
        to: OrchestratorState,
    },
    #[error("no active protocol")]
    NoActiveProtocol,
}

#[derive(Clone, Debug)]
pub struct OrchestratorPolicy {
    pub health_check_interval: Duration,
    pub health_failure_threshold: u32,
    pub burn_threshold: f64,
    pub double_degraded_policy: DoubleDegradedPolicy,
    pub toolkit_enabled: bool,
    pub toolkit_activation_threshold: f64,
    pub threat_tool_name: Option<String>,
    pub emergency_tool_name: Option<String>,
    pub adaptive_hardening_enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DoubleDegradedPolicy {
    EmergencyShutdown,
    SafeModeLock,
}

impl Default for OrchestratorPolicy {
    fn default() -> Self {
        Self {
            health_check_interval: Duration::from_secs(5),
            health_failure_threshold: 3,
            burn_threshold: 0.8,
            double_degraded_policy: DoubleDegradedPolicy::EmergencyShutdown,
            toolkit_enabled: true,
            toolkit_activation_threshold: 0.8,
            threat_tool_name: Some("transport.diagnostics".to_string()),
            emergency_tool_name: Some("forensics.emergency.snapshot".to_string()),
            adaptive_hardening_enabled: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OrchestratorConfig {
    pub active_protocol: String,
    pub standby_protocol: String,
    pub policy: OrchestratorPolicy,
}

impl Default for OrchestratorConfig {
    /// The node's deployment pair: `xray` active, `amneziawg` standby, default
    /// policy — the same wiring `imperium-cli` uses. It exists so
    /// [`register_strands`](crate::register_strands) can be the one-line
    /// composition-root call the conversion recipe asks for; callers with a
    /// different deployment (or a test) construct the config explicitly.
    fn default() -> Self {
        Self {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        }
    }
}

struct ProtocolState {
    name: String,
    role: ProtocolRole,
    status: ProtocolStatus,
    healing_in_progress: bool,
}

/// One windowed threat assessment: the sensor advisory plus its arrival time
/// for TTL eviction.
type WindowedAssessment = (ThreatAssessment, Instant);
/// Per-remote fusion window: bounded deque of recent assessments.
type FusionWindow = HashMap<Option<SocketAddr>, VecDeque<WindowedAssessment>>;

pub struct Orchestrator {
    config: OrchestratorConfig,
    state: Arc<RwLock<OrchestratorState>>,
    active: Arc<RwLock<ProtocolState>>,
    standby: Arc<RwLock<ProtocolState>>,
    bus: Arc<BusPublisher>,
    fusion: SensorFusion,
    /// Windowed threat assessments keyed by remote address, evicted on read.
    ///
    /// Window choice: 5s TTL, 64 entries per remote, 256 remotes max. Short
    /// enough that a fused decision still precedes protocol burn-out, long
    /// enough for classifier + signature + heuristic sensors (which publish
    /// on independent schedules) to land on the same remote. Bounded so a
    /// hostile remote cannot grow memory without bound; strainers never see
    /// this window — it holds sensor advisory metadata, not user traffic.
    fusion_window: RwLock<FusionWindow>,
}

impl Orchestrator {
    /// Fusion window: construction-time constants (THESIS: no threshold
    /// drift — policy values never mutate at runtime).
    const FUSION_WINDOW_TTL: Duration = Duration::from_secs(5);
    const FUSION_WINDOW_MAX: usize = 64;
    const FUSION_MAX_REMOTES: usize = 256;

    pub fn new(config: OrchestratorConfig, bus: Arc<BusPublisher>) -> Self {
        let active = ProtocolState {
            name: config.active_protocol.clone(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Running,

            healing_in_progress: false,
        };

        let standby = ProtocolState {
            name: config.standby_protocol.clone(),
            role: ProtocolRole::Standby,
            status: ProtocolStatus::Running,

            healing_in_progress: false,
        };

        Self {
            config,
            state: Arc::new(RwLock::new(OrchestratorState::Steady)),
            active: Arc::new(RwLock::new(active)),
            standby: Arc::new(RwLock::new(standby)),
            bus,
            fusion: SensorFusion::new(FusionPolicy::default()),
            fusion_window: RwLock::new(HashMap::new()),
        }
    }

    pub fn state(&self) -> OrchestratorState {
        self.state.read().clone()
    }

    pub fn active_protocol(&self) -> String {
        self.active.read().name.clone()
    }

    pub fn standby_protocol(&self) -> String {
        self.standby.read().name.clone()
    }

    pub fn handle_protocol_event(
        &self,
        event: &ProtocolEvent,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        match &event.event {
            ProtocolEventKind::Crashed { reason } => {
                self.handle_crash(&event.protocol_name, reason)
            }
            ProtocolEventKind::Fingerprinted { details } => {
                self.handle_fingerprinted(&event.protocol_name, details)
            }
            ProtocolEventKind::HealingSucceeded => {
                self.handle_healing_success(&event.protocol_name)
            }
            ProtocolEventKind::HealingFailed { reason } => {
                self.handle_healing_failure(&event.protocol_name, reason)
            }
            ProtocolEventKind::SelfTestPassed => self.handle_self_test_passed(&event.protocol_name),
            ProtocolEventKind::SelfTestFailed { reason } => {
                self.handle_self_test_failed(&event.protocol_name, reason)
            }
            _ => Ok(None),
        }
    }

    fn handle_crash(
        &self,
        protocol_name: &str,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let current_state = self.state();

        let is_active = self.active.read().name == protocol_name;

        match current_state {
            OrchestratorState::Steady if is_active => {
                *self.state.write() = OrchestratorState::Failover;

                let standby_name = self.standby.read().name.clone();
                let active_name = self.active.read().name.clone();

                {
                    let mut active = self.active.write();
                    let mut standby = self.standby.write();
                    std::mem::swap(&mut active.name, &mut standby.name);
                    active.role = ProtocolRole::Active;
                    active.status = ProtocolStatus::Running;
                    standby.role = ProtocolRole::Quarantined;
                    standby.status = ProtocolStatus::Failed;
                    standby.healing_in_progress = false;
                }

                self.emit_command(&standby_name, ProtocolCommandKind::PromoteToActive)?;
                self.emit_command(&active_name, ProtocolCommandKind::Quarantine)?;

                *self.state.write() = OrchestratorState::Healing;

                let decision = OrchestratorDecision::PromoteStandby {
                    protocol_name: standby_name,
                };
                self.emit_decision(&decision)?;

                let quarantine_decision = OrchestratorDecision::QuarantineActive {
                    protocol_name: active_name.clone(),
                    reason: reason.to_string(),
                };
                self.emit_decision(&quarantine_decision)?;

                let heal_decision = OrchestratorDecision::BeginHealing {
                    protocol_name: active_name,
                };
                self.emit_decision(&heal_decision)?;

                Ok(Some(decision))
            }

            OrchestratorState::Healing if is_active => self.trigger_emergency_shutdown(&format!(
                "active protocol {} crashed during healing",
                protocol_name
            )),

            OrchestratorState::Healing if !is_active => Ok(None),

            _ => Ok(None),
        }
    }

    fn handle_fingerprinted(
        &self,
        protocol_name: &str,
        details: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let is_active = self.active.read().name == protocol_name;
        if !is_active {
            return Ok(None);
        }

        self.handle_crash(protocol_name, &format!("fingerprinted: {}", details))
    }

    fn handle_healing_success(
        &self,
        protocol_name: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let is_standby = self.standby.read().name == protocol_name;
        if !is_standby || self.state() != OrchestratorState::Healing {
            return Ok(None);
        }

        {
            let mut standby = self.standby.write();
            standby.status = ProtocolStatus::Running;
            standby.role = ProtocolRole::Standby;
            standby.healing_in_progress = false;
        }

        self.emit_command(protocol_name, ProtocolCommandKind::DemoteToStandby)?;

        *self.state.write() = OrchestratorState::Steady;

        let decision = OrchestratorDecision::RestoreFromHealing {
            protocol_name: protocol_name.to_string(),
        };
        self.emit_decision(&decision)?;

        Ok(Some(decision))
    }

    fn handle_healing_failure(
        &self,
        protocol_name: &str,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        let is_standby = self.standby.read().name == protocol_name;
        if !is_standby {
            return Ok(None);
        }

        match self.config.policy.double_degraded_policy {
            DoubleDegradedPolicy::EmergencyShutdown => self.trigger_emergency_shutdown(&format!(
                "healing failed for {}: {}",
                protocol_name, reason
            )),
            DoubleDegradedPolicy::SafeModeLock => {
                tracing::warn!("safe mode lock: healing failed for {}", protocol_name);
                Ok(None)
            }
        }
    }

    fn handle_self_test_passed(
        &self,
        protocol_name: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        self.handle_healing_success(protocol_name)
    }

    fn handle_self_test_failed(
        &self,
        protocol_name: &str,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        self.handle_healing_failure(protocol_name, reason)
    }

    pub fn handle_threat_assessment(
        &self,
        assessment: &ThreatAssessment,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        if self.config.policy.toolkit_enabled
            && assessment.confidence >= self.config.policy.toolkit_activation_threshold
        {
            if let Some(tool_name) = &self.config.policy.threat_tool_name {
                let active_name = self.active.read().name.clone();
                let mut context = HashMap::new();
                context.insert("source".to_string(), format!("{:?}", assessment.source));
                context.insert(
                    "confidence".to_string(),
                    format!("{:.4}", assessment.confidence),
                );
                context.insert("description".to_string(), assessment.description.clone());
                context.insert("active_protocol".to_string(), active_name);
                context.insert(
                    "suggested_action".to_string(),
                    format!("{:?}", assessment.suggested_action),
                );

                self.emit_tool_request(tool_name, "orchestrator.high_confidence_threat", context)?;
            }
        }

        // Sensor-fusion tier: aggregate assessments over a short window keyed
        // by remote address, then act on the fused SuggestedAction IN ADDITION
        // to the per-assessment burn logic below (which is unchanged). Fusion
        // adds the agreement/ground-truth/strainer-routing tiers: failover
        // only on agreement or signature ground truth, strainer routing on a
        // lone high classifier. Disagreement is logged but never acts.
        let fused_action = {
            let mut window = self.fusion_window.write();
            // Bound the map: evict one arbitrary remote if over capacity.
            if window.len() >= Self::FUSION_MAX_REMOTES
                && !window.contains_key(&assessment.remote_addr)
            {
                if let Some(key) = window.keys().next().cloned() {
                    window.remove(&key);
                }
            }
            let entry = window.entry(assessment.remote_addr).or_default();
            entry.push_back((assessment.clone(), Instant::now()));
            while entry.len() > Self::FUSION_WINDOW_MAX {
                entry.pop_front();
            }
            let now = Instant::now();
            while entry
                .front()
                .is_some_and(|(_, t)| now.duration_since(*t) > Self::FUSION_WINDOW_TTL)
            {
                entry.pop_front();
            }
            let set: Vec<ThreatAssessment> = entry.iter().map(|(a, _)| a.clone()).collect();
            if self.fusion.disagrees(&set) {
                let sources: Vec<String> = set
                    .iter()
                    .map(|a| format!("{:?}:{:.2}", a.source, a.confidence))
                    .collect();
                tracing::warn!(
                    remote = ?assessment.remote_addr,
                    sources = ?sources,
                    "sensor disagreement: windowed sources below agreement, no action taken"
                );
            }
            self.fusion.fuse(&set)
        };

        match &fused_action {
            SuggestedAction::TriggerFailover => {
                let active_name = self.active.read().name.clone();
                // Reuse the established burn-path reason string so existing
                // hardening consumers (HardeningController, toolkit triggers)
                // see one stable namespace; fusion vs burn origin is in logs.
                if self.config.policy.adaptive_hardening_enabled {
                    self.emit_hardening_profile(
                        &active_name,
                        "orchestrator.high_confidence_threat",
                    )?;
                }
                tracing::warn!(
                    remote = ?assessment.remote_addr,
                    "fused threat assessment reached agreement/ground-truth; failing over"
                );
                return self.handle_crash(
                    &active_name,
                    &format!(
                        "fused threat agreement against {:?}",
                        assessment.remote_addr
                    ),
                );
            }
            SuggestedAction::ActivateStrainer { strainer_name } => {
                self.route_strainer(assessment, strainer_name);
            }
            SuggestedAction::IncreaseMonitoring => {
                if self.config.policy.toolkit_enabled {
                    if let Some(tool_name) = &self.config.policy.threat_tool_name {
                        let mut context = HashMap::new();
                        context.insert("source".to_string(), format!("{:?}", assessment.source));
                        context.insert(
                            "confidence".to_string(),
                            format!("{:.4}", assessment.confidence),
                        );
                        context.insert(
                            "remote".to_string(),
                            format!("{:?}", assessment.remote_addr),
                        );
                        self.emit_tool_request(
                            tool_name,
                            "orchestrator.fused_monitoring",
                            context,
                        )?;
                    }
                }
            }
            SuggestedAction::None | SuggestedAction::EmergencyShutdown => {}
        }

        if assessment.confidence >= self.config.policy.burn_threshold {
            let active_name = self.active.read().name.clone();
            if self.config.policy.adaptive_hardening_enabled {
                self.emit_hardening_profile(&active_name, "orchestrator.high_confidence_threat")?;
            }

            tracing::warn!(
                "high-confidence threat ({:.2}) against active protocol {}",
                assessment.confidence,
                active_name
            );

            return self.handle_crash(
                &active_name,
                &format!("burned: threat confidence {:.2}", assessment.confidence),
            );
        }

        Ok(None)
    }

    /// Strainer-routing hookup for fused `ActivateStrainer` decisions.
    ///
    /// The established pattern in this transport layer is toolkit requests
    /// via `emit_tool_request` (there is no strainer-control consumer on the
    /// bus and no `OrchestratorDecision` strainer variant), so the fused
    /// strainer decision is published as a toolkit activation request whose
    /// tool name is the fused strainer name and whose trigger carries the
    /// `orchestrator.fused_strainer` namespace. The toolkit manager routes
    /// by tool name; strainer stacks consume the effect client-side.
    fn route_strainer(&self, assessment: &ThreatAssessment, strainer_name: &str) {
        if !self.config.policy.toolkit_enabled {
            return;
        }
        let mut context = HashMap::new();
        context.insert("source".to_string(), format!("{:?}", assessment.source));
        context.insert(
            "confidence".to_string(),
            format!("{:.4}", assessment.confidence),
        );
        context.insert(
            "remote".to_string(),
            format!("{:?}", assessment.remote_addr),
        );
        context.insert("description".to_string(), assessment.description.clone());
        tracing::info!(
            remote = ?assessment.remote_addr,
            strainer = %strainer_name,
            "fused decision routes flow through strainer stack"
        );
        if let Err(e) =
            self.emit_tool_request(strainer_name, "orchestrator.fused_strainer", context)
        {
            tracing::error!(error = %e, "failed to route fused strainer decision");
        }
    }

    fn trigger_emergency_shutdown(
        &self,
        reason: &str,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        *self.state.write() = OrchestratorState::Emergency;

        if self.config.policy.toolkit_enabled {
            if let Some(tool_name) = &self.config.policy.emergency_tool_name {
                let mut context = HashMap::new();
                context.insert("reason".to_string(), reason.to_string());
                context.insert(
                    "active_protocol".to_string(),
                    self.active.read().name.clone(),
                );
                context.insert(
                    "standby_protocol".to_string(),
                    self.standby.read().name.clone(),
                );

                self.emit_tool_request(tool_name, "orchestrator.emergency_shutdown", context)?;
            }
        }

        let shutdown = EmergencyShutdown {
            reason: reason.to_string(),
            triggered_at: Utc::now(),
            active_protocol: Some(self.active.read().name.clone()),
            standby_protocol: Some(self.standby.read().name.clone()),
        };

        BusEvent::publish(
            &self.bus,
            "emergency.transport.double_degraded",
            Message::EmergencyShutdown(shutdown),
        )?;

        let decision = OrchestratorDecision::EmergencyShutdown {
            reason: reason.to_string(),
        };
        self.emit_decision(&decision)?;

        tracing::error!("EMERGENCY SHUTDOWN: {}", reason);
        Ok(Some(decision))
    }

    fn emit_command(
        &self,
        protocol_name: &str,
        command: ProtocolCommandKind,
    ) -> Result<(), OrchestratorError> {
        let cmd = ProtocolCommand {
            protocol_name: protocol_name.to_string(),
            command,
            issued_at: Utc::now(),
        };

        BusEvent::publish(
            &self.bus,
            "net.transport.command",
            Message::ProtocolCmd(cmd),
        )?;

        Ok(())
    }

    fn emit_tool_request(
        &self,
        tool_name: &str,
        trigger: &str,
        context: HashMap<String, String>,
    ) -> Result<(), OrchestratorError> {
        let request = ToolActivationRequest {
            tool_name: tool_name.to_string(),
            trigger: trigger.to_string(),
            context,
            timestamp: Utc::now(),
        };

        BusEvent::publish(
            &self.bus,
            "net.toolkit.request",
            Message::ToolActivationReq(request),
        )?;

        Ok(())
    }

    fn emit_hardening_profile(
        &self,
        protocol_name: &str,
        reason: &str,
    ) -> Result<(), OrchestratorError> {
        let mut profile = HardeningController::resilience_profile(Some(protocol_name.to_string()));
        profile.reason = reason.to_string();

        BusEvent::publish(
            &self.bus,
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(profile),
        )?;

        Ok(())
    }

    fn emit_decision(&self, decision: &OrchestratorDecision) -> Result<(), OrchestratorError> {
        BusEvent::publish(
            &self.bus,
            "net.transport.decision",
            Message::OrchestratorDecision(decision.clone()),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strand::{queue_lane, FaultPolicy, Lane};
    use imperium_protocol::{SuggestedAction, ThreatSource};
    use spiderweb::Bus;

    fn test_orchestrator() -> Orchestrator {
        let (_bus, publisher) = crate::test_supervision::open();
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        };
        Orchestrator::new(config, Arc::clone(&publisher))
    }

    #[test]
    fn starts_in_steady_state() {
        let orch = test_orchestrator();
        assert_eq!(orch.state(), OrchestratorState::Steady);
        assert_eq!(orch.active_protocol(), "xray");
        assert_eq!(orch.standby_protocol(), "amneziawg");
    }

    #[test]
    fn active_crash_triggers_failover() {
        let orch = test_orchestrator();

        let event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "segfault".into(),
            },
            timestamp: Utc::now(),
        };

        let decision = orch.handle_protocol_event(&event).unwrap();
        assert!(decision.is_some());

        assert_eq!(orch.state(), OrchestratorState::Healing);
        assert_eq!(orch.active_protocol(), "amneziawg");
    }

    #[test]
    fn healing_success_returns_to_steady() {
        let orch = test_orchestrator();

        let crash_event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash".into(),
            },
            timestamp: Utc::now(),
        };
        orch.handle_protocol_event(&crash_event).unwrap();
        assert_eq!(orch.state(), OrchestratorState::Healing);

        let heal_event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Quarantined,
            status: ProtocolStatus::Running,
            event: ProtocolEventKind::HealingSucceeded,
            timestamp: Utc::now(),
        };
        let decision = orch.handle_protocol_event(&heal_event).unwrap();
        assert!(decision.is_some());
        assert_eq!(orch.state(), OrchestratorState::Steady);
    }

    #[test]
    fn double_crash_triggers_emergency() {
        let orch = test_orchestrator();

        let crash1 = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash 1".into(),
            },
            timestamp: Utc::now(),
        };
        orch.handle_protocol_event(&crash1).unwrap();
        assert_eq!(orch.state(), OrchestratorState::Healing);

        let crash2 = ProtocolEvent {
            protocol_name: "amneziawg".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash 2".into(),
            },
            timestamp: Utc::now(),
        };
        let decision = orch.handle_protocol_event(&crash2).unwrap();
        assert!(decision.is_some());
        assert_eq!(orch.state(), OrchestratorState::Emergency);
    }

    /// A kernel, its shared publisher, and an orchestrator over both.
    ///
    /// The orchestrator holds only the publisher; registering its lanes needs
    /// the kernel, which is why all three travel together here.
    fn open_orchestrator() -> (Bus, Arc<BusPublisher>, Arc<Orchestrator>) {
        let (bus, publisher) = crate::test_supervision::open();
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        };
        let orchestrator = Arc::new(Orchestrator::new(config, Arc::clone(&publisher)));
        (bus, publisher, orchestrator)
    }

    #[tokio::test]
    async fn subscribe_threat_assessment_triggers_failover() {
        let (mut bus, publisher, orch) = open_orchestrator();
        // Queue the lane on the kernel, then engage: the run loop is what
        // installs the spec, and it consumes the bus.
        queue_lane(
            &mut bus,
            &publisher,
            Lane::ThreatAssessments,
            &orch,
            FaultPolicy::None,
        );
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        let assessment = ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.95,
            description: "test threat".into(),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        };

        // The envelope is what carries the fan-out registration; a bare
        // `Message` payload is not a registered clone type.
        BusEvent::publish(
            &publisher,
            "net.sensors.signature_match",
            Message::ThreatAssessment(assessment),
        )
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_eq!(orch.state(), OrchestratorState::Healing);
        supervision.shutdown();
    }

    #[tokio::test]
    async fn subscribe_protocol_events_processes_crash() {
        let (mut bus, publisher, orch) = open_orchestrator();
        queue_lane(
            &mut bus,
            &publisher,
            Lane::ProtocolEvents,
            &orch,
            FaultPolicy::None,
        );
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        let event = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "bus crash".into(),
            },
            timestamp: Utc::now(),
        };

        BusEvent::publish(
            &publisher,
            "net.transport.event",
            Message::ProtocolEvt(event),
        )
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_eq!(orch.state(), OrchestratorState::Healing);
        supervision.shutdown();
    }

    #[tokio::test]
    async fn high_threat_requests_diagnostics_tool() {
        let (_bus, publisher) = crate::test_supervision::open();
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        };
        let orch = Orchestrator::new(config, Arc::clone(&publisher));
        let mut toolkit_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.toolkit.request", 64);

        let assessment = ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.95,
            description: "signature match".into(),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        };

        orch.handle_threat_assessment(&assessment).unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), toolkit_sub.recv())
            .await
            .expect("toolkit request")
            .unwrap();

        match event.message {
            Message::ToolActivationReq(request) => {
                assert_eq!(request.tool_name, "transport.diagnostics");
                assert_eq!(request.trigger, "orchestrator.high_confidence_threat");
                assert_eq!(request.context.get("active_protocol").unwrap(), "xray");
            }
            _ => panic!("expected toolkit activation request"),
        }
    }

    #[tokio::test]
    async fn high_threat_requests_adaptive_hardening() {
        let (_bus, publisher) = crate::test_supervision::open();
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        };
        let orch = Orchestrator::new(config, Arc::clone(&publisher));
        let mut hardening_sub = crate::test_supervision::subscribe_queue(
            &publisher,
            "net.transport.hardening.apply",
            64,
        );

        let assessment = ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.95,
            description: "signature match".into(),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        };

        orch.handle_threat_assessment(&assessment).unwrap();

        let event =
            tokio::time::timeout(std::time::Duration::from_millis(100), hardening_sub.recv())
                .await
                .expect("hardening request")
                .unwrap();

        match event.message {
            Message::ProtocolHardeningProfile(profile) => {
                assert_eq!(profile.profile_id, "resilience-rf-inspired");
                assert_eq!(profile.protocol_name.as_deref(), Some("xray"));
                assert_eq!(profile.reason, "orchestrator.high_confidence_threat");
            }
            _ => panic!("expected hardening profile"),
        }
    }

    #[tokio::test]
    async fn emergency_shutdown_requests_snapshot_tool() {
        let (_bus, publisher) = crate::test_supervision::open();
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        };
        let orch = Orchestrator::new(config, Arc::clone(&publisher));
        let mut toolkit_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.toolkit.request", 64);

        let crash1 = ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash 1".into(),
            },
            timestamp: Utc::now(),
        };
        orch.handle_protocol_event(&crash1).unwrap();

        let crash2 = ProtocolEvent {
            protocol_name: "amneziawg".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "crash 2".into(),
            },
            timestamp: Utc::now(),
        };
        orch.handle_protocol_event(&crash2).unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), toolkit_sub.recv())
            .await
            .expect("toolkit request")
            .unwrap();

        match event.message {
            Message::ToolActivationReq(request) => {
                assert_eq!(request.tool_name, "forensics.emergency.snapshot");
                assert_eq!(request.trigger, "orchestrator.emergency_shutdown");
                assert!(request.context.contains_key("reason"));
            }
            _ => panic!("expected toolkit activation request"),
        }
    }

    #[test]
    fn standby_crash_does_not_trigger_failover() {
        let orch = test_orchestrator();

        let event = ProtocolEvent {
            protocol_name: "amneziawg".into(),
            role: ProtocolRole::Standby,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "standby crash".into(),
            },
            timestamp: Utc::now(),
        };

        let decision = orch.handle_protocol_event(&event).unwrap();
        assert!(decision.is_none());
        assert_eq!(orch.state(), OrchestratorState::Steady);
    }

    fn fused_test_orchestrator() -> Orchestrator {
        // Burn/toolkit thresholds pushed above 1.0 so ONLY the fused tier
        // can act: the per-assessment burn path is disabled for these tests.
        // threat_tool_name=None silences the monitoring-request emission so
        // tests observe exactly one bus message per fused decision.
        let (_bus, publisher) = crate::test_supervision::open();
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy {
                burn_threshold: 2.0,
                toolkit_activation_threshold: 2.0,
                threat_tool_name: None,
                ..OrchestratorPolicy::default()
            },
        };
        Orchestrator::new(config, Arc::clone(&publisher))
    }

    fn classifier_assessment(
        remote: Option<std::net::SocketAddr>,
        confidence: f64,
    ) -> ThreatAssessment {
        ThreatAssessment {
            source: ThreatSource::Classifier {
                model_name: "detector".into(),
            },
            confidence,
            description: "test".into(),
            remote_addr: remote,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::None,
        }
    }

    #[test]
    fn lone_classifier_below_agreement_does_not_failover() {
        // Behavior pin: a lone 0.8 classifier assessment fuses to
        // IncreaseMonitoring (below the 0.85 single-classifier-high tier),
        // NEVER failover. Failover requires agreement or signature
        // ground truth.
        let orch = fused_test_orchestrator();
        let remote: std::net::SocketAddr = "203.0.113.7:443".parse().unwrap();
        let decision = orch
            .handle_threat_assessment(&classifier_assessment(Some(remote), 0.8))
            .unwrap();
        assert!(decision.is_none());
        assert_eq!(orch.state(), OrchestratorState::Steady);
        assert_eq!(orch.active_protocol(), "xray");
    }

    #[tokio::test]
    async fn lone_high_classifier_routes_strainer_not_failover() {
        // A lone 0.9 classifier (above the 0.85 single-classifier tier)
        // routes through the named strainer stack via the toolkit-request
        // pattern — still no failover without agreement or ground truth.
        let (_bus, publisher) = crate::test_supervision::open();
        let config = OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy {
                burn_threshold: 2.0,
                toolkit_activation_threshold: 2.0,
                threat_tool_name: None,
                ..OrchestratorPolicy::default()
            },
        };
        let orch = Orchestrator::new(config, Arc::clone(&publisher));
        let mut toolkit_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.toolkit.request", 64);

        let remote: std::net::SocketAddr = "203.0.113.7:443".parse().unwrap();
        let decision = orch
            .handle_threat_assessment(&classifier_assessment(Some(remote), 0.9))
            .unwrap();
        assert!(decision.is_none());
        assert_eq!(orch.state(), OrchestratorState::Steady);
        assert_eq!(orch.active_protocol(), "xray");

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), toolkit_sub.recv())
            .await
            .expect("strainer route request")
            .expect("bus event");
        match event.message {
            Message::ToolActivationReq(request) => {
                assert_eq!(request.tool_name, "probe_response");
                assert_eq!(request.trigger, "orchestrator.fused_strainer");
            }
            other => panic!("expected strainer route request, got {other:?}"),
        }
    }

    #[test]
    fn fused_agreement_triggers_failover() {
        let orch = fused_test_orchestrator();
        let remote: std::net::SocketAddr = "203.0.113.8:443".parse().unwrap();

        let first = orch
            .handle_threat_assessment(&classifier_assessment(Some(remote), 0.6))
            .unwrap();
        assert!(first.is_none());
        assert_eq!(orch.state(), OrchestratorState::Steady);

        let heuristic = ThreatAssessment {
            source: ThreatSource::Heuristic {
                name: "timing".into(),
            },
            confidence: 0.7,
            description: "timing anomaly".into(),
            remote_addr: Some(remote),
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::None,
        };
        let second = orch.handle_threat_assessment(&heuristic).unwrap();
        assert!(second.is_some());
        assert_eq!(orch.state(), OrchestratorState::Healing);
        assert_eq!(orch.active_protocol(), "amneziawg");
    }

    #[test]
    fn fused_signature_ground_truth_triggers_failover() {
        let orch = fused_test_orchestrator();
        let remote: std::net::SocketAddr = "203.0.113.9:443".parse().unwrap();

        let sig = ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.4,
            description: "sig match below burn".into(),
            remote_addr: Some(remote),
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        };
        let decision = orch.handle_threat_assessment(&sig).unwrap();
        assert!(decision.is_some());
        assert_eq!(orch.state(), OrchestratorState::Healing);
    }

    #[test]
    fn legacy_burn_path_still_fires_without_fusion() {
        // Existing behavior preserved: a 0.95 assessment on a fresh remote
        // still burns even before any windowed agreement exists.
        let orch = test_orchestrator();
        let assessment = classifier_assessment(None, 0.95);
        let decision = orch.handle_threat_assessment(&assessment).unwrap();
        assert!(decision.is_some());
        assert_eq!(orch.state(), OrchestratorState::Healing);
    }
}
