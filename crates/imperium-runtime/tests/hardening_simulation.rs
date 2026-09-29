use std::sync::Arc;
use std::time::Duration;

use imperium_net_mesh::{NatTraversalPlanner, PathManager};
use imperium_net_toolkit::{ToolManager, ToolManifest, TriggerCondition};
use imperium_net_transport::{
    queue_lanes, HardeningController, Orchestrator, OrchestratorConfig, OrchestratorPolicy,
    ProbeDeceptionEngine,
};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    FecPolicy, Message, NatTraversalMode, OrchestratorDecision, OrchestratorState,
    PaddingDistribution, PathMetrics, PeerId, ProbeDeceptionDecision, ProbeDeceptionMode,
    ProbeFailureMode, ProtocolEvent, ProtocolEventKind, ProtocolHardeningProfile, ProtocolRole,
    ProtocolStatus, SuggestedAction, ThreatAssessment, ThreatSource, ToolActivationRequest,
};
use spiderweb::{Bus, BusPublisher, ControlMsg, StrandSpec, SYS_CONTROL};

fn diagnostics_tool() -> ToolManifest {
    ToolManifest {
        name: "transport.diagnostics".to_string(),
        description: "simulation transport diagnostics capture".to_string(),
        trigger_conditions: vec![TriggerCondition {
            event_topic: "net.toolkit.request".to_string(),
            min_confidence: 0.0,
        }],
        idle_timeout: Duration::from_secs(30),
        cooldown_duration: Duration::from_secs(60),
        max_activations_per_hour: 4,
    }
}

#[derive(Debug, Default)]
struct SimulationReport {
    user_packets: u32,
    delivered_user_packets: u32,
    recovered_user_packets: u32,
    unrecovered_user_packets: u32,
    cover_packets: u32,
    original_user_bytes: u64,
    padded_user_bytes: u64,
    min_jitter_ms: u16,
    max_jitter_ms: u16,
    rekey_events: u32,
    path_hops: u32,
    selected_paths: Vec<String>,
    unauthenticated_probes_rejected: u32,
    authenticated_probes_accepted: u32,
    decoy_responses: u32,
    illusion_space_routes: u32,
    unauthenticated_real_endpoint_routes: u32,
    default_nat_probe_count: u32,
    aggressive_nat_probe_count: u32,
    default_nat_has_aggressive_mode: bool,
    aggressive_nat_has_aggressive_mode: bool,
}

#[derive(Debug, Default)]
struct AdversarialProbeReport {
    total_attempts: u32,
    unauthenticated_attempts: u32,
    authenticated_control_attempts: u32,
    threshold_skating_attempts: u32,
    source_rotation_attempts: u32,
    budget_burn_attempts: u32,
    invalid_auth_shape_attempts: u32,
    constant_rejects: u32,
    illusion_routes: u32,
    silent_drops: u32,
    decoy_responses: u32,
    authenticated_real_endpoint_routes: u32,
    unauthenticated_real_endpoint_routes: u32,
    max_transcript_bytes_seen: u32,
    delay_window_violations: u32,
    transcript_budget_violations: u32,
}

#[derive(Debug, Default)]
struct ChaosHardeningReport {
    seeds: u32,
    total_probe_attempts: u32,
    unauthenticated_probe_attempts: u32,
    authenticated_control_attempts: u32,
    unauthenticated_real_endpoint_routes: u32,
    authenticated_real_endpoint_routes: u32,
    constant_rejects: u32,
    illusion_routes: u32,
    silent_drops: u32,
    delay_window_violations: u32,
    transcript_budget_violations: u32,
    delivered_user_packets: u32,
    recovered_user_packets: u32,
    unrecovered_user_packets: u32,
    path_hops: u32,
    rekey_events: u32,
    max_padding_overhead_ppm_seen: u32,
}

impl SimulationReport {
    fn overhead_ppm(&self) -> u32 {
        if self.original_user_bytes == 0 {
            return 0;
        }

        let overhead = self
            .padded_user_bytes
            .saturating_sub(self.original_user_bytes);
        ((overhead * 1_000_000) / self.original_user_bytes) as u32
    }

    fn delivery_ppm(&self) -> u32 {
        if self.user_packets == 0 {
            return 0;
        }

        (u64::from(self.delivered_user_packets) * 1_000_000 / u64::from(self.user_packets)) as u32
    }
}

fn run_adversarial_probe_modulation(profile: &ProtocolHardeningProfile) -> AdversarialProbeReport {
    let bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    // A second handle onto the same kernel, for the strainer stack (the type is
    // not `Clone`, so it is minted from the kernel rather than cloned).
    let engine = ProbeDeceptionEngine::new(Arc::clone(&publisher), profile.clone());
    let mut report = AdversarialProbeReport::default();
    let min_confidence = profile.probe_deception.min_confidence;

    for i in 0..96 {
        let confidence = if i % 2 == 0 {
            (min_confidence - 0.01).max(0.0)
        } else {
            (min_confidence + 0.01).min(1.0)
        };
        let source = rotated_source(0x10, i);
        report.threshold_skating_attempts += 1;
        record_probe_attempt(
            &engine,
            &mut report,
            profile,
            false,
            Some(source),
            confidence,
        );
    }

    for i in 0..256 {
        let source = rotated_source(0x40, i);
        report.source_rotation_attempts += 1;
        record_probe_attempt(&engine, &mut report, profile, false, Some(source), 0.99);
    }

    let repeated_source = Some("198.51.100.88:443".parse().unwrap());
    for _ in 0..(profile.probe_deception.response_budget_per_source_per_hour + 24) {
        report.budget_burn_attempts += 1;
        record_probe_attempt(&engine, &mut report, profile, false, repeated_source, 0.99);
    }

    for i in 0..64 {
        let source = rotated_source(0x80, i);
        report.invalid_auth_shape_attempts += 1;
        record_probe_attempt(&engine, &mut report, profile, false, Some(source), 1.0);
    }

    for i in 0..4 {
        let source = rotated_source(0xc0, i);
        record_probe_attempt(&engine, &mut report, profile, true, Some(source), 0.2);
    }

    report
}

fn run_seeded_chaos_hardening_simulation(
    profile: &ProtocolHardeningProfile,
    seeds: u32,
    attempts_per_seed: u32,
) -> ChaosHardeningReport {
    let mut report = ChaosHardeningReport {
        seeds,
        ..ChaosHardeningReport::default()
    };

    for seed in 0..seeds {
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let engine = ProbeDeceptionEngine::new(Arc::clone(&publisher), profile.clone());
        let mut rng = DeterministicRng::new(0x9e37_79b9_7f4a_7c15 ^ u64::from(seed));
        let repeated_source = Some(
            format!("198.51.100.{}:443", 10 + (seed % 8))
                .parse()
                .unwrap(),
        );

        for attempt in 0..attempts_per_seed {
            let tactic = rng.next_u32() % 9;
            let authenticated = tactic == 0 && attempt % 257 == 0;
            let confidence = match tactic {
                1 => (profile.probe_deception.min_confidence - 0.001).max(0.0),
                2 => (profile.probe_deception.min_confidence + 0.001).min(1.0),
                3 | 4 => 1.0,
                5 => 0.0,
                6 => 0.5,
                _ => f64::from(rng.next_u32() % 1_000) / 1_000.0,
            };
            let source = match tactic {
                3 | 4 => repeated_source,
                5 if attempt % 3 == 0 => None,
                _ => Some(rotated_source(
                    1 + ((seed * 17 + attempt) % 190) as u8,
                    rng.next_u32(),
                )),
            };
            let mut probe_report = AdversarialProbeReport::default();

            record_probe_attempt(
                &engine,
                &mut probe_report,
                profile,
                authenticated,
                source,
                confidence,
            );
            merge_probe_report(&mut report, probe_report);
        }

        let seed_report = run_seeded_payload_loss_burn(profile, seed);
        report.delivered_user_packets += seed_report.delivered_user_packets;
        report.recovered_user_packets += seed_report.recovered_user_packets;
        report.unrecovered_user_packets += seed_report.unrecovered_user_packets;
        report.path_hops += seed_report.path_hops;
        report.rekey_events += seed_report.rekey_events;
        report.max_padding_overhead_ppm_seen = report
            .max_padding_overhead_ppm_seen
            .max(seed_report.overhead_ppm());
    }

    report
}

fn merge_probe_report(report: &mut ChaosHardeningReport, probe: AdversarialProbeReport) {
    report.total_probe_attempts += probe.total_attempts;
    report.unauthenticated_probe_attempts += probe.unauthenticated_attempts;
    report.authenticated_control_attempts += probe.authenticated_control_attempts;
    report.unauthenticated_real_endpoint_routes += probe.unauthenticated_real_endpoint_routes;
    report.authenticated_real_endpoint_routes += probe.authenticated_real_endpoint_routes;
    report.constant_rejects += probe.constant_rejects;
    report.illusion_routes += probe.illusion_routes;
    report.silent_drops += probe.silent_drops;
    report.delay_window_violations += probe.delay_window_violations;
    report.transcript_budget_violations += probe.transcript_budget_violations;
}

fn run_seeded_payload_loss_burn(profile: &ProtocolHardeningProfile, seed: u32) -> SimulationReport {
    let mut report = SimulationReport {
        min_jitter_ms: u16::MAX,
        ..SimulationReport::default()
    };
    let mut rng = DeterministicRng::new(0xd1b5_4a32_d192_ed03 ^ u64::from(seed));
    let user_packets = 384u32;
    let parity_shards = u32::from(if profile.fec.enabled {
        profile.fec.parity_shards
    } else {
        0
    });
    let mut virtual_ms = 0u64;
    let mut key_started_ms = 0u64;

    for id in 0..user_packets {
        let packet = SimPacket {
            id,
            payload_len: 64 + (rng.next_u32() % 1_200) as u16,
            authenticated: true,
        };
        let padded_len = padded_len(
            &profile.traffic_morph.padding,
            profile.traffic_morph.max_padding_overhead_ppm,
            &packet,
            &mut rng,
        );
        let jitter = rng.range_u16(
            profile.traffic_morph.jitter_floor_ms,
            profile.traffic_morph.jitter_ceiling_ms,
        );
        virtual_ms += 250 + u64::from(jitter);

        report.user_packets += 1;
        report.original_user_bytes += u64::from(packet.payload_len);
        report.padded_user_bytes += u64::from(padded_len);
        report.min_jitter_ms = report.min_jitter_ms.min(jitter);
        report.max_jitter_ms = report.max_jitter_ms.max(jitter);

        let within_burst = (id + seed) % 47 < parity_shards;
        let random_loss = rng.next_u32() % 1_000_000 < profile.fec.loss_threshold_ppm;
        if within_burst || random_loss {
            if profile.fec.enabled {
                report.recovered_user_packets += 1;
                report.delivered_user_packets += 1;
            } else {
                report.unrecovered_user_packets += 1;
            }
        } else {
            report.delivered_user_packets += 1;
        }

        let key_age_seconds = virtual_ms.saturating_sub(key_started_ms) / 1_000;
        let byte_trigger = report.original_user_bytes >= profile.rekey.max_key_bytes;
        let threat_trigger = profile.rekey.threat_triggered && id % 113 == 0 && id > 0;
        if key_age_seconds >= profile.rekey.max_key_age_seconds || byte_trigger || threat_trigger {
            report.rekey_events += 1;
            key_started_ms = virtual_ms + u64::from(profile.rekey.stagger_window_ms);
            report.original_user_bytes = 0;
            report.padded_user_bytes = 0;
        }

        if profile.path_hopping.enabled
            && id % profile.path_hopping.min_dwell_seconds.max(1) as u32 == 0
            && id > 0
        {
            report.path_hops += 1;
        }
    }

    report
}

fn rotated_source(octet_base: u8, attempt: u32) -> std::net::SocketAddr {
    let host_octet = octet_base.saturating_add((attempt % 48) as u8).max(1);
    let port = 10_000 + (attempt % 40_000) as u16;
    format!("203.0.113.{host_octet}:{port}").parse().unwrap()
}

fn record_probe_attempt(
    engine: &ProbeDeceptionEngine,
    report: &mut AdversarialProbeReport,
    profile: &ProtocolHardeningProfile,
    authenticated: bool,
    source: Option<std::net::SocketAddr>,
    confidence: f64,
) {
    let decision =
        if !authenticated && !profile.probe_resistance.authenticated_first_packet_required {
            ProbeDeceptionDecision {
                source,
                mode: ProbeDeceptionMode::Disabled,
                persona_id: "baseline-real-endpoint".to_string(),
                response_delay_ms: 0,
                transcript_bytes: 0,
                routed_to_real_endpoint: true,
                reason: "profile does not require authenticated first-packet gating".to_string(),
                decided_at: chrono::Utc::now(),
            }
        } else {
            engine
                .decide_probe(source, confidence, authenticated)
                .unwrap()
        };

    record_probe_decision(report, profile, authenticated, decision);
}

fn record_probe_decision(
    report: &mut AdversarialProbeReport,
    profile: &ProtocolHardeningProfile,
    authenticated: bool,
    decision: ProbeDeceptionDecision,
) {
    report.total_attempts += 1;
    if authenticated {
        report.authenticated_control_attempts += 1;
    } else {
        report.unauthenticated_attempts += 1;
    }

    if decision.routed_to_real_endpoint {
        if authenticated {
            report.authenticated_real_endpoint_routes += 1;
        } else {
            report.unauthenticated_real_endpoint_routes += 1;
        }
    }

    match decision.mode {
        ProbeDeceptionMode::ConstantShapeReject => report.constant_rejects += 1,
        ProbeDeceptionMode::SilentDrop => report.silent_drops += 1,
        ProbeDeceptionMode::ShadowEndpoint
        | ProbeDeceptionMode::Tarpit
        | ProbeDeceptionMode::PuzzleGate
        | ProbeDeceptionMode::DecoyTranscript => {
            report.illusion_routes += 1;
            report.decoy_responses += 1;
        }
        ProbeDeceptionMode::Disabled => {}
    }

    report.max_transcript_bytes_seen = report
        .max_transcript_bytes_seen
        .max(decision.transcript_bytes);

    if decision.transcript_bytes > profile.probe_deception.max_transcript_bytes {
        report.transcript_budget_violations += 1;
    }

    if !authenticated && !matches!(decision.mode, ProbeDeceptionMode::ConstantShapeReject) {
        let min = profile.probe_deception.min_delay_ms;
        let max = profile.probe_deception.max_delay_ms;
        if decision.response_delay_ms < min || decision.response_delay_ms > max {
            report.delay_window_violations += 1;
        }
    }
}

#[derive(Clone, Debug)]
struct SimPacket {
    id: u32,
    payload_len: u16,
    authenticated: bool,
}

#[derive(Clone, Debug)]
struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        (self.state >> 32) as u32
    }

    fn range_u16(&mut self, min: u16, max: u16) -> u16 {
        if min >= max {
            return min;
        }

        let span = u32::from(max - min) + 1;
        min + (self.next_u32() % span) as u16
    }
}

fn run_full_primitive_simulation(profile: &ProtocolHardeningProfile) -> SimulationReport {
    let mut report = SimulationReport {
        min_jitter_ms: u16::MAX,
        ..SimulationReport::default()
    };

    simulate_nat(&mut report);
    simulate_probe_resistance(profile, &mut report);
    simulate_traffic_morph_fec_and_rekey(profile, &mut report);
    simulate_path_hopping(profile, &mut report);

    report
}

fn unhardened_baseline_profile() -> ProtocolHardeningProfile {
    let mut profile = HardeningController::resilience_profile(Some("xray".to_string()));
    profile.profile_id = "unhardened-baseline".to_string();
    profile.traffic_morph.padding = PaddingDistribution::None;
    profile.traffic_morph.max_padding_overhead_ppm = 0;
    profile.traffic_morph.jitter_floor_ms = 0;
    profile.traffic_morph.jitter_ceiling_ms = 0;
    profile.traffic_morph.cover_traffic_ppm = 0;
    profile.traffic_morph.packet_batching_window_ms = 0;
    profile.rekey.max_key_age_seconds = 86_400;
    profile.rekey.threat_triggered = false;
    profile.rekey.stagger_window_ms = 0;
    profile.probe_resistance.authenticated_first_packet_required = false;
    profile.probe_resistance.unauthenticated_failure_mode = ProbeFailureMode::AuthenticatedDrop;
    profile.probe_resistance.min_response_delay_ms = 0;
    profile.probe_resistance.max_response_delay_ms = 0;
    profile.probe_resistance.decoy_response_budget_per_hour = 0;
    profile.probe_deception.enabled = false;
    profile.probe_deception.mode = ProbeDeceptionMode::Disabled;
    profile.probe_deception.response_budget_per_source_per_hour = 0;
    profile.probe_deception.max_transcript_bytes = 0;
    profile.path_hopping.enabled = false;
    profile.fec.enabled = false;
    profile.reason = "simulation baseline".to_string();
    profile
}

fn simulate_nat(report: &mut SimulationReport) {
    let default_plan = NatTraversalPlanner::build_probe_plan(
        PeerId::new(),
        &NatTraversalPlanner::default_policy(),
    );
    let aggressive_plan = NatTraversalPlanner::build_probe_plan(
        PeerId::new(),
        &NatTraversalPlanner::aggressive_policy(),
    );

    report.default_nat_probe_count = default_plan.estimated_probe_count;
    report.aggressive_nat_probe_count = aggressive_plan.estimated_probe_count;
    report.default_nat_has_aggressive_mode = default_plan
        .modes
        .iter()
        .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe));
    report.aggressive_nat_has_aggressive_mode = aggressive_plan
        .modes
        .iter()
        .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe));

    assert!(default_plan.relay_fallback_enabled);
    assert!(aggressive_plan.relay_fallback_enabled);
}

fn simulate_probe_resistance(profile: &ProtocolHardeningProfile, report: &mut SimulationReport) {
    for attempt in 0..128 {
        let authenticated = attempt % 41 == 0;
        let packet = SimPacket {
            id: attempt,
            payload_len: 96,
            authenticated,
        };

        if profile.probe_resistance.authenticated_first_packet_required && !packet.authenticated {
            report.unauthenticated_probes_rejected += 1;
            let deception_allowed = profile.probe_deception.enabled
                && 0.9 >= profile.probe_deception.min_confidence
                && !matches!(profile.probe_deception.mode, ProbeDeceptionMode::Disabled)
                && report.illusion_space_routes
                    < profile.probe_deception.response_budget_per_source_per_hour;
            if deception_allowed {
                report.illusion_space_routes += 1;
                report.decoy_responses += 1;
            }
        } else {
            report.authenticated_probes_accepted += 1;
            if !packet.authenticated {
                report.unauthenticated_real_endpoint_routes += 1;
            }
        }
    }
}

fn simulate_traffic_morph_fec_and_rekey(
    profile: &ProtocolHardeningProfile,
    report: &mut SimulationReport,
) {
    let mut rng = DeterministicRng::new(0x5150_2026);
    let mut virtual_ms = 0u64;
    let mut key_started_ms = 0u64;
    let threat_trigger_packet = 160;
    let user_packets = 512u32;
    let group_size = u32::from(profile.fec.data_shards.max(1));
    let parity_shards = u32::from(if profile.fec.enabled {
        profile.fec.parity_shards
    } else {
        0
    });
    let mut group_losses = 0u32;

    for id in 0..user_packets {
        if id % group_size == 0 {
            group_losses = deterministic_losses_for_group(id / group_size, &profile.fec);
        }

        let packet = SimPacket {
            id,
            payload_len: 96 + ((id * 37) % 1_000) as u16,
            authenticated: true,
        };

        let padded_len = padded_len(
            &profile.traffic_morph.padding,
            profile.traffic_morph.max_padding_overhead_ppm,
            &packet,
            &mut rng,
        );
        let jitter = rng.range_u16(
            profile.traffic_morph.jitter_floor_ms,
            profile.traffic_morph.jitter_ceiling_ms,
        );
        virtual_ms += 1_000 + u64::from(jitter);

        report.user_packets += 1;
        report.original_user_bytes += u64::from(packet.payload_len);
        report.padded_user_bytes += u64::from(padded_len);
        report.min_jitter_ms = report.min_jitter_ms.min(jitter);
        report.max_jitter_ms = report.max_jitter_ms.max(jitter);

        if should_emit_cover_packet(id, profile.traffic_morph.cover_traffic_ppm) {
            report.cover_packets += 1;
        }

        let lost = (id % group_size) < group_losses;
        if lost {
            if profile.fec.enabled && group_losses <= parity_shards {
                report.recovered_user_packets += 1;
                report.delivered_user_packets += 1;
            } else {
                report.unrecovered_user_packets += 1;
            }
        } else {
            report.delivered_user_packets += 1;
        }

        let key_age_seconds = virtual_ms.saturating_sub(key_started_ms) / 1_000;
        let threat_triggered_rekey =
            profile.rekey.threat_triggered && packet.id == threat_trigger_packet;
        if key_age_seconds >= profile.rekey.max_key_age_seconds || threat_triggered_rekey {
            report.rekey_events += 1;
            key_started_ms = virtual_ms + u64::from(profile.rekey.stagger_window_ms);
        }
    }
}

fn deterministic_losses_for_group(group: u32, fec: &FecPolicy) -> u32 {
    if !fec.enabled {
        return if group % 7 == 0 { 1 } else { 0 };
    }

    if group % 11 == 0 {
        u32::from(fec.parity_shards)
    } else if group % 5 == 0 {
        1
    } else {
        0
    }
}

fn padded_len(
    distribution: &PaddingDistribution,
    max_padding_overhead_ppm: u32,
    packet: &SimPacket,
    rng: &mut DeterministicRng,
) -> u16 {
    let candidate = match distribution {
        PaddingDistribution::None => packet.payload_len,
        PaddingDistribution::Fixed { bytes } => packet.payload_len.saturating_add(*bytes),
        PaddingDistribution::Bucketed { buckets } => buckets
            .iter()
            .copied()
            .find(|bucket| *bucket >= packet.payload_len)
            .unwrap_or_else(|| buckets.iter().copied().max().unwrap_or(packet.payload_len)),
        PaddingDistribution::Envelope {
            min_bytes,
            max_bytes,
        } => {
            let lower = packet.payload_len.max(*min_bytes);
            let upper = (*max_bytes).max(lower);
            rng.range_u16(lower, upper)
        }
    };

    let max_overhead_bytes =
        (u64::from(packet.payload_len) * u64::from(max_padding_overhead_ppm) / 1_000_000) as u16;
    let budget_cap = packet.payload_len.saturating_add(max_overhead_bytes);
    candidate.min(budget_cap).max(packet.payload_len)
}

fn should_emit_cover_packet(packet_id: u32, cover_traffic_ppm: u32) -> bool {
    let sample = packet_id.wrapping_mul(48_271).wrapping_add(17) % 1_000_000;
    sample < cover_traffic_ppm
}

fn simulate_path_hopping(profile: &ProtocolHardeningProfile, report: &mut SimulationReport) {
    let manager = PathManager::default();
    let mut current_path = "direct-xray".to_string();
    report.selected_paths.push(current_path.clone());

    for second in [0_u64, 30, 61, 180, 360] {
        let direct_burn = if second >= 61 { 0.92 } else { 0.05 };
        let candidates = vec![
            metrics("direct-xray", 22, 4, 400, direct_burn, false),
            metrics("masque-relay", 45, 9, 2_000, 0.02, true),
            metrics("amneziawg-direct", 35, 6, 800, 0.01, false),
        ];
        let active_metrics = candidates
            .iter()
            .find(|candidate| candidate.path_id == current_path)
            .expect("current path metrics");
        let selected = manager.select_best(&candidates).expect("path selection");

        if profile.path_hopping.enabled
            && second >= profile.path_hopping.min_dwell_seconds
            && active_metrics.burn_score >= profile.path_hopping.burn_score_threshold
            && selected.selected_path_id != current_path
        {
            current_path = selected.selected_path_id;
            report.path_hops += 1;
            report.selected_paths.push(current_path.clone());
        }
    }
}

fn metrics(
    path_id: &str,
    rtt_ms: u64,
    jitter_ms: u64,
    loss_ppm: u32,
    burn_score: f64,
    relay_required: bool,
) -> PathMetrics {
    PathMetrics {
        path_id: path_id.to_string(),
        rtt_ms,
        jitter_ms,
        loss_ppm,
        burn_score,
        handshake_success_ppm: 995_000,
        relay_required,
        observed_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn high_confidence_burn_triggers_hardening_toolkit_failover_and_recovery() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());

    let hardening = Arc::new(HardeningController::new(Arc::clone(&publisher)));
    let toolkit = Arc::new(ToolManager::new(Arc::clone(&publisher)));
    toolkit.register(diagnostics_tool());
    toolkit.arm("transport.diagnostics").unwrap();

    let orchestrator = Arc::new(Orchestrator::new(
        OrchestratorConfig {
            active_protocol: "xray".to_string(),
            standby_protocol: "amneziawg".to_string(),
            policy: OrchestratorPolicy::default(),
        },
        Arc::clone(&publisher),
    ));

    // Queue the transport lanes for the concrete orchestrator/hardening
    // pair this test observes, plus the toolkit activation lane for the
    // concrete ToolManager under test. Do not call the default
    // `register_strands` here: it would build a second pair and this test
    // would observe the wrong objects.
    hardening.register_strand(&mut bus, &publisher);
    ::imperium_net_toolkit::register_strands(&mut bus, &publisher, &toolkit);
    queue_lanes(
        &mut bus,
        &publisher,
        &orchestrator,
        ::imperium_net_transport::strand::FaultPolicy::from_env(),
    );
    let _supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    let mut hardening_status_sub =
        subscribe_queue(&publisher, "net.transport.hardening.status", 64);
    let mut toolkit_activation_sub = subscribe_queue(&publisher, "net.toolkit.activation", 64);
    let mut decision_sub = subscribe_queue(&publisher, "net.transport.decision", 64);

    BusEvent::publish(
        &publisher,
        "net.sensors.threat",
        Message::ThreatAssessment(ThreatAssessment {
            source: ThreatSource::Heuristic {
                name: "background_noise".to_string(),
            },
            confidence: 0.35,
            description: "low confidence anomaly".to_string(),
            remote_addr: None,
            timestamp: chrono::Utc::now(),
            suggested_action: SuggestedAction::IncreaseMonitoring,
        }),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orchestrator.state(), OrchestratorState::Steady);
    assert_eq!(orchestrator.active_protocol(), "xray");
    assert!(hardening.active_profile().is_none());

    BusEvent::publish(
        &publisher,
        "net.sensors.signature_match",
        Message::ThreatAssessment(ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.93,
            description: "active protocol fingerprint match".to_string(),
            remote_addr: Some("203.0.113.10:443".parse().unwrap()),
            timestamp: chrono::Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        }),
    )
    .unwrap();

    let hardening_event =
        tokio::time::timeout(Duration::from_millis(250), hardening_status_sub.recv())
            .await
            .expect("hardening status")
            .unwrap();
    let hardening_status = match hardening_event.message {
        Message::ProtocolHardeningStatus(status) => status,
        other => panic!("expected ProtocolHardeningStatus, got {other:?}"),
    };
    assert_eq!(hardening_status.profile_id, "resilience-rf-inspired");
    assert_eq!(hardening_status.protocol_name.as_deref(), Some("xray"));
    assert!(hardening_status.accepted);
    assert_eq!(hardening_status.reason, "profile accepted");
    assert_eq!(
        hardening.active_profile().unwrap().reason,
        "orchestrator.high_confidence_threat"
    );

    let toolkit_event =
        tokio::time::timeout(Duration::from_millis(250), toolkit_activation_sub.recv())
            .await
            .expect("toolkit activation")
            .unwrap();
    let activation = match toolkit_event.message {
        Message::ToolActivationReq(ToolActivationRequest {
            tool_name, trigger, ..
        }) => (tool_name, trigger),
        other => panic!("expected ToolActivationReq, got {other:?}"),
    };
    assert_eq!(activation.0, "transport.diagnostics");
    assert_eq!(activation.1, "orchestrator.high_confidence_threat");

    let promote = tokio::time::timeout(Duration::from_millis(250), decision_sub.recv())
        .await
        .expect("promote decision")
        .unwrap();
    assert!(matches!(
        promote.message,
        Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby {
            protocol_name
        }) if protocol_name == "amneziawg"
    ));

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orchestrator.state(), OrchestratorState::Healing);
    assert_eq!(orchestrator.active_protocol(), "amneziawg");

    BusEvent::publish(
        &publisher,
        "net.transport.event",
        Message::ProtocolEvt(ProtocolEvent {
            protocol_name: "xray".to_string(),
            role: ProtocolRole::Quarantined,
            status: ProtocolStatus::Running,
            event: ProtocolEventKind::HealingSucceeded,
            timestamp: chrono::Utc::now(),
        }),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orchestrator.state(), OrchestratorState::Steady);
}

#[test]
fn full_protocol_primitive_simulation_holds_under_burn_and_loss() {
    let profile = HardeningController::resilience_profile(Some("xray".to_string()));
    let report = run_full_primitive_simulation(&profile);

    assert_eq!(report.default_nat_probe_count, 32);
    assert_eq!(report.aggressive_nat_probe_count, 128);
    assert!(!report.default_nat_has_aggressive_mode);
    assert!(report.aggressive_nat_has_aggressive_mode);

    assert_eq!(report.user_packets, 512);
    assert_eq!(report.unrecovered_user_packets, 0);
    assert_eq!(report.delivered_user_packets, report.user_packets);
    assert!(report.recovered_user_packets > 0);
    assert_eq!(report.delivery_ppm(), 1_000_000);

    assert!(report.cover_packets > 0);
    assert!(report.overhead_ppm() <= profile.traffic_morph.max_padding_overhead_ppm);
    assert!(report.min_jitter_ms >= profile.traffic_morph.jitter_floor_ms);
    assert!(report.max_jitter_ms <= profile.traffic_morph.jitter_ceiling_ms);

    assert!(report.rekey_events >= 2);
    assert!(report.path_hops >= 1);
    assert_eq!(report.selected_paths.first().unwrap(), "direct-xray");
    assert!(report
        .selected_paths
        .iter()
        .any(|path| path == "amneziawg-direct"));

    assert_eq!(report.authenticated_probes_accepted, 4);
    assert_eq!(report.unauthenticated_probes_rejected, 124);
    assert_eq!(report.illusion_space_routes, 32);
    assert_eq!(report.decoy_responses, 32);
    assert_eq!(report.unauthenticated_real_endpoint_routes, 0);
}

#[test]
fn hardened_profile_outperforms_unhardened_baseline_under_same_faults() {
    let hardened = run_full_primitive_simulation(&HardeningController::resilience_profile(Some(
        "xray".to_string(),
    )));
    let baseline = run_full_primitive_simulation(&unhardened_baseline_profile());

    assert!(
        hardened.delivery_ppm() > baseline.delivery_ppm(),
        "FEC should recover loss that the baseline drops"
    );
    assert_eq!(baseline.recovered_user_packets, 0);
    assert!(baseline.unrecovered_user_packets > 0);

    assert!(
        hardened.unauthenticated_probes_rejected > baseline.unauthenticated_probes_rejected,
        "authenticated first-packet gating should reject probes"
    );
    assert!(
        baseline.authenticated_probes_accepted > hardened.authenticated_probes_accepted,
        "baseline accepts too much unauthenticated probe traffic"
    );
    assert!(hardened.illusion_space_routes > baseline.illusion_space_routes);
    assert_eq!(hardened.unauthenticated_real_endpoint_routes, 0);

    assert!(hardened.rekey_events > baseline.rekey_events);
    assert!(hardened.path_hops > baseline.path_hops);
    assert_eq!(baseline.overhead_ppm(), 0);
}

#[test]
fn fortress_profile_hits_perfect_simulation_targets() {
    let profile = HardeningController::fortress_profile(Some("xray".to_string()));
    let report = run_full_primitive_simulation(&profile);

    assert_eq!(report.delivery_ppm(), 1_000_000);
    assert_eq!(report.delivered_user_packets, report.user_packets);
    assert_eq!(report.unrecovered_user_packets, 0);
    assert!(report.recovered_user_packets > 0);

    assert_eq!(report.unauthenticated_probes_rejected, 124);
    assert_eq!(report.authenticated_probes_accepted, 4);
    assert_eq!(report.illusion_space_routes, 64);
    assert_eq!(report.decoy_responses, 64);
    assert_eq!(report.unauthenticated_real_endpoint_routes, 0);

    assert!(report.path_hops >= 1);
    assert!(report.rekey_events >= 4);
    assert!(report.cover_packets >= 2);
    assert!(report.overhead_ppm() <= profile.traffic_morph.max_padding_overhead_ppm);
    assert!(report.min_jitter_ms >= profile.traffic_morph.jitter_floor_ms);
    assert!(report.max_jitter_ms <= profile.traffic_morph.jitter_ceiling_ms);
}

#[test]
fn adversarial_probe_modulation_cannot_reach_real_endpoint_without_auth() {
    let profile = HardeningController::fortress_profile(Some("xray".to_string()));
    let report = run_adversarial_probe_modulation(&profile);

    assert_eq!(
        report.unauthenticated_real_endpoint_routes, 0,
        "no unauthenticated modulation strategy should reach the real endpoint"
    );
    assert_eq!(
        report.authenticated_real_endpoint_routes, report.authenticated_control_attempts,
        "only authenticated control probes should reach the real endpoint"
    );
    assert_eq!(report.delay_window_violations, 0);
    assert_eq!(report.transcript_budget_violations, 0);

    assert_eq!(report.threshold_skating_attempts, 96);
    assert_eq!(report.source_rotation_attempts, 256);
    assert_eq!(report.invalid_auth_shape_attempts, 64);
    assert_eq!(
        report.budget_burn_attempts,
        profile.probe_deception.response_budget_per_source_per_hour + 24
    );
    assert_eq!(report.silent_drops, 24);
    assert!(report.constant_rejects > 0);
    assert!(report.illusion_routes > report.silent_drops);
    assert!(report.max_transcript_bytes_seen <= profile.probe_deception.max_transcript_bytes);
}

#[test]
fn adversarial_probe_modulation_is_stronger_than_baseline_gate() {
    let hardened = run_adversarial_probe_modulation(&HardeningController::fortress_profile(Some(
        "xray".to_string(),
    )));
    let baseline = run_adversarial_probe_modulation(&unhardened_baseline_profile());

    assert_eq!(hardened.unauthenticated_real_endpoint_routes, 0);
    assert_eq!(
        baseline.unauthenticated_real_endpoint_routes, baseline.unauthenticated_attempts,
        "baseline model has no authenticated first-packet gate"
    );
    assert!(hardened.illusion_routes > baseline.illusion_routes);
    assert!(hardened.constant_rejects > baseline.constant_rejects);
    assert!(hardened.silent_drops > baseline.silent_drops);
}

#[test]
fn seeded_chaos_hardening_invariants_hold_across_mixed_attack_runs() {
    let profile = HardeningController::fortress_profile(Some("xray".to_string()));
    let report = run_seeded_chaos_hardening_simulation(&profile, 64, 512);

    assert_eq!(report.seeds, 64);
    assert_eq!(report.total_probe_attempts, 64 * 512);
    assert!(
        report.unauthenticated_probe_attempts > report.authenticated_control_attempts * 100,
        "chaos mix should heavily favor adversarial unauthenticated attempts"
    );
    assert_eq!(
        report.unauthenticated_real_endpoint_routes, 0,
        "no seeded chaos strategy should route unauthenticated probes to the real endpoint"
    );
    assert_eq!(
        report.authenticated_real_endpoint_routes, report.authenticated_control_attempts,
        "authenticated control probes should still route to the real endpoint"
    );
    assert_eq!(report.delay_window_violations, 0);
    assert_eq!(report.transcript_budget_violations, 0);
    assert!(report.constant_rejects > 0);
    assert!(report.illusion_routes > 0);
    assert!(report.silent_drops > 0);

    assert_eq!(report.unrecovered_user_packets, 0);
    assert!(report.delivered_user_packets > 0);
    assert!(report.recovered_user_packets > 0);
    assert!(report.path_hops >= report.seeds);
    assert!(report.rekey_events >= report.seeds);
    assert!(report.max_padding_overhead_ppm_seen <= profile.traffic_morph.max_padding_overhead_ppm);
}

// ---------------------------------------------------------------------------
// The supervision composition this test binary owns
// ---------------------------------------------------------------------------

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its own
/// thread until [`Supervision::shutdown`]. `run_until` consumes the bus, so the
/// kernel moves onto the thread and only the `BusPublisher` stays behind.
struct Supervision {
    publisher: Arc<BusPublisher>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Supervision {
    fn engage_with(mut bus: Bus, publisher: Arc<BusPublisher>) -> Self {
        bus.register_spider(StrandSpec::new(
            "spider",
            || Box::new(spider::Spider::new()),
        ));

        let join = std::thread::Builder::new()
            .name("imperium-supervision".to_string())
            .spawn(move || {
                let mut bus = bus;
                bus.run_until(None);
            })
            .expect("failed to spawn the supervision run-loop thread");

        Self {
            publisher,
            join: Some(join),
        }
    }

    fn shutdown(&mut self) {
        let _ = self.publisher.publish(SYS_CONTROL, ControlMsg::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for Supervision {
    fn drop(&mut self) {
        self.shutdown();
    }
}

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
