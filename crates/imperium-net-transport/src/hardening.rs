use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    FecPolicy, Message, PaddingDistribution, PathHoppingPolicy, ProbeDeceptionDecision,
    ProbeDeceptionMode, ProbeDeceptionPolicy, ProbeFailureMode, ProbeResistancePolicy,
    ProtocolHardeningProfile, ProtocolHardeningStatus, RekeyPolicy, TrafficMorphProfile,
};
use parking_lot::RwLock;
use spiderweb::{Bus, BusPublisher};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HardeningError {
    #[error("profile id cannot be empty")]
    EmptyProfileId,
    #[error("traffic morph profile id cannot be empty")]
    EmptyTrafficMorphProfileId,
    #[error("invalid traffic morph policy: {0}")]
    InvalidTrafficMorph(String),
    #[error("invalid rekey policy: {0}")]
    InvalidRekey(String),
    #[error("invalid probe resistance policy: {0}")]
    InvalidProbeResistance(String),
    #[error("invalid probe deception policy: {0}")]
    InvalidProbeDeception(String),
    #[error("invalid path hopping policy: {0}")]
    InvalidPathHopping(String),
    #[error("invalid FEC policy: {0}")]
    InvalidFec(String),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

pub struct HardeningController {
    bus: Arc<BusPublisher>,
    active_profile: RwLock<Option<ProtocolHardeningProfile>>,
}

pub struct ProbeDeceptionEngine {
    bus: Arc<BusPublisher>,
    profile: RwLock<ProtocolHardeningProfile>,
    source_counts: RwLock<HashMap<String, u32>>,
}

impl ProbeDeceptionEngine {
    pub fn new(bus: Arc<BusPublisher>, profile: ProtocolHardeningProfile) -> Self {
        Self {
            bus,
            profile: RwLock::new(profile),
            source_counts: RwLock::new(HashMap::new()),
        }
    }

    pub fn apply_profile(&self, profile: ProtocolHardeningProfile) {
        *self.profile.write() = profile;
        self.source_counts.write().clear();
    }

    pub fn decide_probe(
        &self,
        source: Option<SocketAddr>,
        confidence: f64,
        authenticated: bool,
    ) -> Result<ProbeDeceptionDecision, HardeningError> {
        let profile = self.profile.read().clone();
        let policy = &profile.probe_deception;

        let decision = if authenticated {
            ProbeDeceptionDecision {
                source,
                mode: ProbeDeceptionMode::Disabled,
                persona_id: "real-endpoint".to_string(),
                response_delay_ms: 0,
                transcript_bytes: 0,
                routed_to_real_endpoint: true,
                reason: "authenticated probe may continue to real endpoint".to_string(),
                decided_at: Utc::now(),
            }
        } else if !policy.enabled || confidence < policy.min_confidence {
            ProbeDeceptionDecision {
                source,
                mode: ProbeDeceptionMode::ConstantShapeReject,
                persona_id: "reject-only".to_string(),
                response_delay_ms: profile.probe_resistance.min_response_delay_ms,
                transcript_bytes: 0,
                routed_to_real_endpoint: false,
                reason: "unauthenticated probe below deception threshold".to_string(),
                decided_at: Utc::now(),
            }
        } else {
            let source_key = source
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            let mut counts = self.source_counts.write();
            let count = counts.entry(source_key.clone()).or_insert(0);
            let within_budget = *count < policy.response_budget_per_source_per_hour;
            *count = count.saturating_add(1);
            drop(counts);

            let mode = if within_budget {
                policy.mode.clone()
            } else {
                ProbeDeceptionMode::SilentDrop
            };
            let now = Utc::now();
            let seed = stable_seed(&source_key, now, policy.persona_rotation_seconds);
            let transcript_bytes = if within_budget {
                bounded_transcript_bytes(policy.max_transcript_bytes, seed)
            } else {
                0
            };

            ProbeDeceptionDecision {
                source,
                mode,
                persona_id: format!("shadow-{seed:016x}"),
                response_delay_ms: deterministic_delay(
                    policy.min_delay_ms,
                    policy.max_delay_ms,
                    seed,
                ),
                transcript_bytes,
                routed_to_real_endpoint: false,
                reason: "unauthenticated probe routed to illusion space".to_string(),
                decided_at: now,
            }
        };

        BusEvent::publish(
            &self.bus,
            "net.transport.probe_deception.decision",
            Message::ProbeDeceptionDecision(decision.clone()),
        )?;

        Ok(decision)
    }
}

impl HardeningController {
    pub fn new(bus: Arc<BusPublisher>) -> Self {
        Self {
            bus,
            active_profile: RwLock::new(None),
        }
    }

    pub fn balanced_profile(protocol_name: Option<String>) -> ProtocolHardeningProfile {
        ProtocolHardeningProfile {
            profile_id: "balanced-rf-inspired".to_string(),
            protocol_name,
            traffic_morph: TrafficMorphProfile {
                profile_id: "balanced-morph".to_string(),
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
            reason: "balanced hardening preset".to_string(),
        }
    }

    pub fn resilience_profile(protocol_name: Option<String>) -> ProtocolHardeningProfile {
        let mut profile = Self::balanced_profile(protocol_name);
        profile.profile_id = "resilience-rf-inspired".to_string();
        profile.traffic_morph.profile_id = "resilience-morph".to_string();
        profile.traffic_morph.padding = PaddingDistribution::Envelope {
            min_bytes: 256,
            max_bytes: 1_280,
        };
        profile.traffic_morph.max_padding_overhead_ppm = 160_000;
        profile.traffic_morph.jitter_floor_ms = 5;
        profile.traffic_morph.jitter_ceiling_ms = 50;
        profile.rekey.max_key_age_seconds = 300;
        profile.rekey.stagger_window_ms = 1_000;
        profile.probe_deception.enabled = true;
        profile.probe_deception.mode = ProbeDeceptionMode::ShadowEndpoint;
        profile.probe_deception.min_confidence = 0.65;
        profile.probe_deception.response_budget_per_source_per_hour = 32;
        profile.probe_deception.min_delay_ms = 15;
        profile.probe_deception.max_delay_ms = 90;
        profile.probe_deception.max_transcript_bytes = 512;
        profile.probe_deception.log_transcripts = true;
        profile.path_hopping.min_dwell_seconds = 60;
        profile.path_hopping.max_dwell_seconds = 300;
        profile.fec.data_shards = 10;
        profile.fec.parity_shards = 4;
        profile.reason = "resilience hardening preset".to_string();
        profile
    }

    pub fn fortress_profile(protocol_name: Option<String>) -> ProtocolHardeningProfile {
        let mut profile = Self::resilience_profile(protocol_name);
        profile.profile_id = "fortress-rf-inspired".to_string();
        profile.traffic_morph.profile_id = "fortress-morph".to_string();
        profile.traffic_morph.padding = PaddingDistribution::Bucketed {
            buckets: vec![128, 256, 512, 768, 1_024, 1_280],
        };
        profile.traffic_morph.max_padding_overhead_ppm = 200_000;
        profile.traffic_morph.jitter_floor_ms = 10;
        profile.traffic_morph.jitter_ceiling_ms = 80;
        profile.traffic_morph.cover_traffic_ppm = 10_000;
        profile.rekey.max_key_age_seconds = 120;
        profile.rekey.max_key_bytes = 268_435_456;
        profile.rekey.stagger_window_ms = 2_000;
        profile.probe_resistance.min_response_delay_ms = 10;
        profile.probe_resistance.max_response_delay_ms = 80;
        profile.probe_deception.mode = ProbeDeceptionMode::DecoyTranscript;
        profile.probe_deception.min_confidence = 0.4;
        profile.probe_deception.response_budget_per_source_per_hour = 64;
        profile.probe_deception.min_delay_ms = 25;
        profile.probe_deception.max_delay_ms = 150;
        profile.probe_deception.max_transcript_bytes = 1_024;
        profile.probe_deception.persona_rotation_seconds = 7_200;
        profile.path_hopping.min_dwell_seconds = 30;
        profile.path_hopping.max_dwell_seconds = 180;
        profile.path_hopping.burn_score_threshold = 0.5;
        profile.path_hopping.packet_loss_threshold_ppm = 20_000;
        profile.path_hopping.jitter_threshold_ms = 50;
        profile.fec.data_shards = 8;
        profile.fec.parity_shards = 6;
        profile.fec.loss_threshold_ppm = 10_000;
        profile.fec.max_overhead_ppm = 450_000;
        profile.reason = "fortress hardening preset".to_string();
        profile
    }

    pub fn validate(profile: &ProtocolHardeningProfile) -> Result<(), HardeningError> {
        if profile.profile_id.trim().is_empty() {
            return Err(HardeningError::EmptyProfileId);
        }
        if profile.traffic_morph.profile_id.trim().is_empty() {
            return Err(HardeningError::EmptyTrafficMorphProfileId);
        }

        validate_traffic_morph(&profile.traffic_morph)?;
        validate_rekey(&profile.rekey)?;
        validate_probe_resistance(&profile.probe_resistance)?;
        validate_probe_deception(&profile.probe_deception)?;
        validate_path_hopping(&profile.path_hopping)?;
        validate_fec(&profile.fec)?;

        Ok(())
    }

    pub fn apply(&self, profile: ProtocolHardeningProfile) -> Result<(), HardeningError> {
        match Self::validate(&profile) {
            Ok(()) => {
                *self.active_profile.write() = Some(profile.clone());
                self.emit_status(&profile, true, "profile accepted")?;
                Ok(())
            }
            Err(e) => {
                self.emit_status(&profile, false, &e.to_string())?;
                Err(e)
            }
        }
    }

    pub fn active_profile(&self) -> Option<ProtocolHardeningProfile> {
        self.active_profile.read().clone()
    }

    /// Queue this controller's `net.transport.hardening.apply` loop — the
    /// supervised Spiderweb strand [`HardeningStrand`](crate::HardeningStrand) —
    /// on `bus`, logging loudly when a fault drill is armed.
    ///
    /// This is the way a composition root that already owns this controller
    /// wires the loop, so the strand applies profiles to *this* controller (and
    /// a later `active_profile()` reflects them). It is idempotent per bus; the
    /// first registration for the strand name wins, so calling it alongside
    /// [`register_strands`](crate::register_strands) is safe.
    ///
    /// Call it before the kernel's run loop:
    /// a spec queued after engage can never be installed, and
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec) says so
    /// instead of dropping it.
    pub fn register_strand(self: &Arc<Self>, bus: &mut Bus, publisher: &Arc<BusPublisher>) {
        let faults = crate::strand::HardeningFaultPolicy::from_env();
        if faults.is_injected() {
            // A deliberately armed fault must never look like a real one in the
            // logs, and must be impossible to leave on by accident without a
            // trace.
            tracing::warn!(
                policy = ?faults,
                env = crate::strand::HARDENING_CRASH_AFTER_PROFILES_ENV,
                "transport hardening strand fault drill ARMED — the lane will crash on purpose"
            );
        }
        crate::strand::queue_hardening(bus, publisher, self, faults)
    }

    fn emit_status(
        &self,
        profile: &ProtocolHardeningProfile,
        accepted: bool,
        reason: &str,
    ) -> Result<(), HardeningError> {
        BusEvent::publish(
            &self.bus,
            "net.transport.hardening.status",
            Message::ProtocolHardeningStatus(ProtocolHardeningStatus {
                profile_id: profile.profile_id.clone(),
                protocol_name: profile.protocol_name.clone(),
                accepted,
                reason: reason.to_string(),
                active_at: Utc::now(),
            }),
        )?;

        Ok(())
    }
}

fn validate_traffic_morph(profile: &TrafficMorphProfile) -> Result<(), HardeningError> {
    match &profile.padding {
        PaddingDistribution::None => {}
        PaddingDistribution::Fixed { bytes } if *bytes <= 1_500 => {}
        PaddingDistribution::Bucketed { buckets }
            if !buckets.is_empty() && buckets.iter().all(|bucket| *bucket <= 1_500) => {}
        PaddingDistribution::Envelope {
            min_bytes,
            max_bytes,
        } if min_bytes <= max_bytes && *max_bytes <= 1_500 => {}
        _ => {
            return Err(HardeningError::InvalidTrafficMorph(
                "padding shape must fit a conservative packet envelope".to_string(),
            ))
        }
    }

    if profile.max_padding_overhead_ppm > 500_000 {
        return Err(HardeningError::InvalidTrafficMorph(
            "padding overhead must be at or below 50%".to_string(),
        ));
    }
    if profile.jitter_floor_ms > profile.jitter_ceiling_ms || profile.jitter_ceiling_ms > 1_000 {
        return Err(HardeningError::InvalidTrafficMorph(
            "jitter window must be ordered and at most 1000ms".to_string(),
        ));
    }
    if profile.cover_traffic_ppm > 100_000 {
        return Err(HardeningError::InvalidTrafficMorph(
            "cover traffic budget must be at or below 10%".to_string(),
        ));
    }
    if profile.packet_batching_window_ms > 100 {
        return Err(HardeningError::InvalidTrafficMorph(
            "packet batching window must be at most 100ms".to_string(),
        ));
    }

    Ok(())
}

fn validate_rekey(policy: &RekeyPolicy) -> Result<(), HardeningError> {
    if policy.max_key_age_seconds == 0 {
        return Err(HardeningError::InvalidRekey(
            "max key age must be nonzero".to_string(),
        ));
    }
    if policy.max_key_bytes < 1_048_576 {
        return Err(HardeningError::InvalidRekey(
            "max key bytes must be at least 1MiB".to_string(),
        ));
    }
    if policy.stagger_window_ms > 10_000 {
        return Err(HardeningError::InvalidRekey(
            "stagger window must be at most 10s".to_string(),
        ));
    }

    Ok(())
}

fn validate_probe_resistance(policy: &ProbeResistancePolicy) -> Result<(), HardeningError> {
    if policy.min_response_delay_ms > policy.max_response_delay_ms
        || policy.max_response_delay_ms > 5_000
    {
        return Err(HardeningError::InvalidProbeResistance(
            "response delay window must be ordered and at most 5s".to_string(),
        ));
    }
    if !policy.authenticated_first_packet_required
        && matches!(
            policy.unauthenticated_failure_mode,
            ProbeFailureMode::RetryWithPuzzle
        )
    {
        return Err(HardeningError::InvalidProbeResistance(
            "retry puzzles require authenticated first-packet gating".to_string(),
        ));
    }
    if policy.decoy_response_budget_per_hour > 1_000 {
        return Err(HardeningError::InvalidProbeResistance(
            "decoy response budget must be at most 1000/hour".to_string(),
        ));
    }

    Ok(())
}

fn validate_probe_deception(policy: &ProbeDeceptionPolicy) -> Result<(), HardeningError> {
    if !policy.enabled {
        return Ok(());
    }
    if matches!(policy.mode, ProbeDeceptionMode::Disabled) {
        return Err(HardeningError::InvalidProbeDeception(
            "enabled deception requires a non-disabled mode".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&policy.min_confidence) {
        return Err(HardeningError::InvalidProbeDeception(
            "minimum confidence must be between 0.0 and 1.0".to_string(),
        ));
    }
    if policy.min_delay_ms > policy.max_delay_ms || policy.max_delay_ms > 5_000 {
        return Err(HardeningError::InvalidProbeDeception(
            "deception delay window must be ordered and at most 5s".to_string(),
        ));
    }
    if policy.response_budget_per_source_per_hour > 1_000 {
        return Err(HardeningError::InvalidProbeDeception(
            "response budget must be at most 1000/source/hour".to_string(),
        ));
    }
    if policy.max_transcript_bytes > 4_096 {
        return Err(HardeningError::InvalidProbeDeception(
            "decoy transcript must be at most 4096 bytes".to_string(),
        ));
    }
    if policy.persona_rotation_seconds == 0 {
        return Err(HardeningError::InvalidProbeDeception(
            "persona rotation must be nonzero".to_string(),
        ));
    }

    Ok(())
}

fn stable_seed(source_key: &str, now: DateTime<Utc>, rotation_seconds: u64) -> u64 {
    let epoch = now.timestamp().max(0) as u64 / rotation_seconds.max(1);
    source_key
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64 ^ epoch, |hash, byte| {
            hash.wrapping_mul(0x100_0000_01b3)
                .wrapping_add(u64::from(byte))
        })
}

fn deterministic_delay(min_delay_ms: u16, max_delay_ms: u16, seed: u64) -> u16 {
    if min_delay_ms >= max_delay_ms {
        return min_delay_ms;
    }

    let span = u64::from(max_delay_ms - min_delay_ms) + 1;
    min_delay_ms + ((seed >> 17) % span) as u16
}

fn bounded_transcript_bytes(max_transcript_bytes: u32, seed: u64) -> u32 {
    if max_transcript_bytes == 0 {
        return 0;
    }

    let floor = max_transcript_bytes.min(64);
    floor + ((seed >> 23) as u32 % (max_transcript_bytes - floor + 1))
}

fn validate_path_hopping(policy: &PathHoppingPolicy) -> Result<(), HardeningError> {
    if policy.min_dwell_seconds > policy.max_dwell_seconds {
        return Err(HardeningError::InvalidPathHopping(
            "dwell window must be ordered".to_string(),
        ));
    }
    if !(0.0..=1.0).contains(&policy.burn_score_threshold) {
        return Err(HardeningError::InvalidPathHopping(
            "burn threshold must be between 0.0 and 1.0".to_string(),
        ));
    }
    if policy.enabled && policy.min_dwell_seconds == 0 {
        return Err(HardeningError::InvalidPathHopping(
            "enabled path hopping requires nonzero dwell".to_string(),
        ));
    }

    Ok(())
}

fn validate_fec(policy: &FecPolicy) -> Result<(), HardeningError> {
    if !policy.enabled {
        return Ok(());
    }
    if policy.data_shards == 0 || policy.parity_shards == 0 {
        return Err(HardeningError::InvalidFec(
            "enabled FEC requires data and parity shards".to_string(),
        ));
    }
    if u16::from(policy.data_shards) + u16::from(policy.parity_shards) > 32 {
        return Err(HardeningError::InvalidFec(
            "FEC shard count must be at most 32".to_string(),
        ));
    }
    if policy.max_overhead_ppm > 500_000 {
        return Err(HardeningError::InvalidFec(
            "FEC overhead must be at or below 50%".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_profile_is_valid() {
        let profile = HardeningController::balanced_profile(Some("masque".to_string()));
        HardeningController::validate(&profile).unwrap();
    }

    #[test]
    fn resilience_profile_is_valid() {
        let profile = HardeningController::resilience_profile(None);
        HardeningController::validate(&profile).unwrap();
    }

    #[test]
    fn fortress_profile_is_valid() {
        let profile = HardeningController::fortress_profile(Some("masque".to_string()));
        HardeningController::validate(&profile).unwrap();
    }

    #[tokio::test]
    async fn deception_routes_unauthenticated_probe_to_illusion_space() {
        let (_bus, publisher) = crate::test_supervision::open();
        let mut sub = crate::test_supervision::subscribe_queue(
            &publisher,
            "net.transport.probe_deception.decision",
            64,
        );
        let profile = HardeningController::fortress_profile(Some("xray".to_string()));
        let engine = ProbeDeceptionEngine::new(Arc::clone(&publisher), profile);

        let decision = engine
            .decide_probe(Some("203.0.113.10:443".parse().unwrap()), 0.9, false)
            .unwrap();

        assert_eq!(decision.mode, ProbeDeceptionMode::DecoyTranscript);
        assert!(!decision.routed_to_real_endpoint);
        assert!(decision.transcript_bytes > 0);

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .expect("deception decision")
            .unwrap();
        assert!(matches!(
            event.message,
            Message::ProbeDeceptionDecision(ProbeDeceptionDecision {
                routed_to_real_endpoint: false,
                ..
            })
        ));
    }

    #[test]
    fn deception_budget_degrades_to_silent_drop() {
        let (_bus, publisher) = crate::test_supervision::open();
        let mut profile = HardeningController::fortress_profile(Some("xray".to_string()));
        profile.probe_deception.response_budget_per_source_per_hour = 1;
        let engine = ProbeDeceptionEngine::new(Arc::clone(&publisher), profile);
        let source = Some("203.0.113.10:443".parse().unwrap());

        let first = engine.decide_probe(source, 0.9, false).unwrap();
        let second = engine.decide_probe(source, 0.9, false).unwrap();

        assert_eq!(first.mode, ProbeDeceptionMode::DecoyTranscript);
        assert_eq!(second.mode, ProbeDeceptionMode::SilentDrop);
        assert!(!first.routed_to_real_endpoint);
        assert!(!second.routed_to_real_endpoint);
    }

    #[test]
    fn rejects_excessive_cover_traffic() {
        let mut profile = HardeningController::balanced_profile(None);
        profile.traffic_morph.cover_traffic_ppm = 200_000;

        assert!(matches!(
            HardeningController::validate(&profile),
            Err(HardeningError::InvalidTrafficMorph(_))
        ));
    }

    #[test]
    fn rejects_unbounded_fec() {
        let mut profile = HardeningController::balanced_profile(None);
        profile.fec.data_shards = 30;
        profile.fec.parity_shards = 10;

        assert!(matches!(
            HardeningController::validate(&profile),
            Err(HardeningError::InvalidFec(_))
        ));
    }

    #[tokio::test]
    async fn apply_publishes_status() {
        let (_bus, publisher) = crate::test_supervision::open();
        let mut sub = crate::test_supervision::subscribe_queue(
            &publisher,
            "net.transport.hardening.status",
            64,
        );
        let controller = HardeningController::new(Arc::clone(&publisher));
        let profile = HardeningController::balanced_profile(Some("xray".to_string()));

        controller.apply(profile).unwrap();
        let event = tokio::time::timeout(std::time::Duration::from_millis(100), sub.recv())
            .await
            .expect("status event")
            .unwrap();

        match event.message {
            Message::ProtocolHardeningStatus(status) => {
                assert_eq!(status.profile_id, "balanced-rf-inspired");
                assert!(status.accepted);
            }
            _ => panic!("expected hardening status"),
        }
    }
}
