//! End-to-end supervision proof for the transport orchestrator conversion.
//!
//! `imperium-net-transport`'s orchestrator held two `tokio::spawn`ed recv loops
//! (`net.sensors.` → `handle_threat_assessment`, `net.transport.event` →
//! `handle_protocol_event`). Both are Spiderweb **strands** now — see
//! [`imperium_net_transport::strand`] and the pilot (`imperium-net-lightcone`).
//! The unit tests in `orchestrator.rs` cover the *state machine*; these
//! integration tests cover the part only a real kernel can prove:
//!
//! 1. [`orchestrator_lanes_serve_their_topics_and_decisions_arrive_in_order`] —
//!    behaviour preservation, including the ordering property
//!    `crates/imperium-runtime/tests/integration.rs` pins: one crash produces
//!    `PromoteStandby`, `QuarantineActive`, `BeginHealing` **in that order**,
//!    both through the shim's `Bus::subscribe` surface and through a peer
//!    strand.
//! 2. [`queued_specs_are_not_started_until_engage`] — a spec is queued, not
//!    started; engagement installs both lanes (and re-queueing is idempotent,
//!    because the kernel *panics* on a duplicate strand name).
//! 3. [`crashed_threat_lane_is_quarantined_while_the_failover_lane_serves`] —
//!    the crash policy, driven through the real threat lane with an injected
//!    fault: crashes become `LifecycleEvent::Crashed`, the spider restarts
//!    three times, the fourth crash quarantines — while the *other* lane is
//!    never crashed, never restarted, and still produces its three ordered
//!    decisions afterwards.
//! 4. [`replayed_tail_is_deduped_not_reprocessed`] — the recipe's §5.4 hazard
//!    for a non-idempotent consumer. A restarted generation is replayed the
//!    recent tail; the lane's durable `SeenIds` history refuses it, so the
//!    orchestrator's state transitions run exactly once (a replayed
//!    ground-truth threat would otherwise fail over a second time and, from
//!    `Healing`, escalate to emergency shutdown).
//!
//! Everything here runs the production path: a real `Bus::new()`, real
//! `queue_lane`/`Bus::register_strand(spec)`, real `Bus::engage_supervision()`
//! (kernel run loop + spider on their own OS threads), real strand workers, and
//! the real [`OrchestratorStrand`]. Nothing is simulated and nothing is stubbed.
//!
//! # The instruments: recorder strands
//!
//! Supervision is invisible to `Bus::subscribe` — that surface carries
//! `BusEvent`s only, while lifecycle events travel on `sys.lifecycle` — so the
//! instrument is a second strand that records what it feels, exactly as the
//! pilot's test file does. [`LifecycleRecorder`] records the kernel's lifecycle
//! stream (and survives its neighbour's death); [`EventRecorder`] records a
//! topic prefix of the orchestrator's output, which also proves a strand's
//! publish reaches another strand.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use imperium_net_transport::strand::{
    queue_lane, queue_lanes, FaultPolicy, Lane, DECISION_TOPIC, PROTOCOL_EVENTS_STRAND,
    PROTOCOL_EVENT_TOPIC, SENSOR_TOPIC_PREFIX, THREAT_ASSESSMENTS_STRAND, TOOLKIT_REQUEST_TOPIC,
};
use imperium_net_transport::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};
use imperium_protocol::{
    BusEvent, Message, OrchestratorDecision, OrchestratorState, ProtocolEvent, ProtocolEventKind,
    ProtocolRole, ProtocolStatus, SuggestedAction, ThreatAssessment, ThreatSource,
};
use spiderweb::{Bus, BusPublisher, ControlMsg, SYS_CONTROL};
use spiderweb::{
    BusHandle, LifecycleEvent, Socket, Strand, StrandError, StrandSpec, SYS_LIFECYCLE,
};

// ---------------------------------------------------------------------------
// Recorder strands — the supervision instruments
// ---------------------------------------------------------------------------

/// Shared, test-owned record of every lifecycle event the kernel published.
/// `std::sync::Mutex` so a poisoned lock cannot hide an assertion failure.
type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;
/// Shared, test-owned record of the orchestrator output a recorder strand saw.
type EventLog = Arc<Mutex<Vec<BusEvent>>>;

fn new_lifecycle_log() -> LifecycleLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn new_event_log() -> EventLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn lifecycle_snapshot(log: &LifecycleLog) -> Vec<LifecycleEvent> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn event_snapshot(log: &EventLog) -> Vec<BusEvent> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Count lifecycle events matching `pred`.
fn count(log: &LifecycleLog, pred: impl Fn(&LifecycleEvent) -> bool) -> usize {
    lifecycle_snapshot(log)
        .iter()
        .filter(|event| pred(event))
        .count()
}

/// Count `Registered` events for one strand name. The kernel emits one per
/// *generation*, so a strand that was restarted three times reports four.
fn registered(log: &LifecycleLog, name: &str) -> usize {
    count(
        log,
        |event| matches!(event, LifecycleEvent::Registered { name: n, .. } if n == name),
    )
}

fn crashed(log: &LifecycleLog, name: &str) -> usize {
    count(
        log,
        |event| matches!(event, LifecycleEvent::Crashed { name: n, .. } if n == name),
    )
}

fn restarted(log: &LifecycleLog, name: &str) -> usize {
    count(
        log,
        |event| matches!(event, LifecycleEvent::Restarted { name: n, .. } if n == name),
    )
}

fn quarantined(log: &LifecycleLog, name: &str) -> usize {
    count(
        log,
        |event| matches!(event, LifecycleEvent::Quarantined { name: n, .. } if n == name),
    )
}

/// The crash reasons recorded for one strand name.
fn crash_reasons(log: &LifecycleLog, name: &str) -> Vec<String> {
    lifecycle_snapshot(log)
        .into_iter()
        .filter_map(|event| match event {
            LifecycleEvent::Crashed { name: n, reason } if n == name => Some(reason),
            _ => None,
        })
        .collect()
}

/// Every lifecycle event naming one strand, so "nothing further happened to it"
/// is assertable. (`Buffered`/`ThreadFormed` events for unrelated topics arrive
/// continuously, so the whole stream cannot be compared.)
fn events_for(log: &LifecycleLog, name: &str) -> usize {
    count(log, |event| match event {
        LifecycleEvent::Registered { name: n, .. }
        | LifecycleEvent::Crashed { name: n, .. }
        | LifecycleEvent::Restarted { name: n, .. }
        | LifecycleEvent::Quarantined { name: n, .. }
        | LifecycleEvent::Detached { name: n } => n == name,
        _ => false,
    })
}

/// Block (with a hard deadline) until `pred` holds, so a supervision bug fails
/// the test instead of hanging it.
fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !pred() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A strand that records the kernel's lifecycle stream — who registered, who
/// crashed, who was restarted, who was quarantined.
///
/// Registered as a **spec**, exactly like a converted subsystem, so it starts
/// with the run loop and survives the crash of its neighbour.
struct LifecycleRecorder {
    log: LifecycleLog,
}

impl Strand for LifecycleRecorder {
    fn name(&self) -> &str {
        "test.lifecycle-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        // Routing is by `TypeId`, so this strand feels every `LifecycleEvent`
        // on the web rather than one named socket.
        const SOCKS: [Socket; 1] = [Socket::new::<LifecycleEvent>(SYS_LIFECYCLE)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        for (_socket, event) in bus.recv_all::<LifecycleEvent>()? {
            self.log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event);
        }
        Ok(())
    }
}

/// A strand that records every `BusEvent` whose topic starts with `prefix`.
///
/// Its input type is [`BusEvent`] — the same type the orchestrator lanes
/// declare — because strand routing is by `TypeId`; the prefix filter here is
/// the `Bus::subscribe(prefix)` comparison, moved into the consumer.
struct EventRecorder {
    name: &'static str,
    prefix: &'static str,
    log: EventLog,
}

impl Strand for EventRecorder {
    fn name(&self) -> &str {
        self.name
    }

    fn inputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>("<any>")];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // `recv_all`, not `recv(prefix)`: the inbox is a mailbox, not a filter.
        for (socket, event) in bus.recv_all::<BusEvent>()? {
            if !socket.starts_with(self.prefix) && !event.topic.starts_with(self.prefix) {
                continue;
            }
            self.log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event);
        }
        Ok(())
    }
}

fn lifecycle_recorder_spec(log: LifecycleLog) -> StrandSpec {
    StrandSpec::new("test.lifecycle-recorder", move || -> Box<dyn Strand> {
        Box::new(LifecycleRecorder {
            log: Arc::clone(&log),
        })
    })
}

fn event_recorder_spec(name: &'static str, prefix: &'static str, log: EventLog) -> StrandSpec {
    StrandSpec::new(name, move || -> Box<dyn Strand> {
        Box::new(EventRecorder {
            name,
            prefix,
            log: Arc::clone(&log),
        })
    })
}

/// The decisions a recorder strand saw, in arrival order.
fn recorded_decisions(log: &EventLog) -> Vec<OrchestratorDecision> {
    event_snapshot(log)
        .into_iter()
        .filter_map(|event| match event.message {
            Message::OrchestratorDecision(decision) => Some(decision),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn orchestrator(publisher: &Arc<BusPublisher>) -> Arc<Orchestrator> {
    Arc::new(Orchestrator::new(
        OrchestratorConfig {
            active_protocol: "xray".into(),
            standby_protocol: "amneziawg".into(),
            policy: OrchestratorPolicy::default(),
        },
        Arc::clone(publisher),
    ))
}

/// A crash of the active protocol — the input the failover lane owns.
fn crash_event(protocol_name: &str, reason: &str) -> ProtocolEvent {
    ProtocolEvent {
        protocol_name: protocol_name.into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: reason.into(),
        },
        timestamp: chrono::Utc::now(),
    }
}

fn offer_protocol_crash(bus: &BusPublisher, protocol_name: &str, reason: &str) {
    BusEvent::publish(
        bus,
        PROTOCOL_EVENT_TOPIC,
        Message::ProtocolEvt(crash_event(protocol_name, reason)),
    )
    .expect("publish is fire-and-forget and never fails");
}

/// A quiet assessment for the drill: a lone heuristic at 0.2 fuses to
/// `SuggestedAction::None` (below the 0.5 dual-sensor threshold), so it counts
/// as handled work without touching the state machine. Each call uses a fresh
/// remote and a fresh `BusEvent` id, so it is never deduped as a replay.
fn drill_assessment(index: u32) -> ThreatAssessment {
    ThreatAssessment {
        source: ThreatSource::Heuristic {
            name: "drill".into(),
        },
        confidence: 0.2,
        description: format!("drill message {index}"),
        remote_addr: Some(
            format!("203.0.113.{}:443", (index % 250) + 1)
                .parse()
                .unwrap(),
        ),
        timestamp: chrono::Utc::now(),
        suggested_action: SuggestedAction::None,
    }
}

/// The fixture topic the sensor side publishes on. It must sit inside the
/// threat lane's declared prefix, or the drill would be driving a topic the
/// lane never consumes.
const THREAT_TOPIC: &str = "net.sensors.threat";

fn offer_threat(bus: &BusPublisher, assessment: ThreatAssessment) {
    assert!(
        THREAT_TOPIC.starts_with(SENSOR_TOPIC_PREFIX),
        "the drill's topic must be one the threat lane filters for"
    );
    BusEvent::publish(bus, THREAT_TOPIC, Message::ThreatAssessment(assessment))
        .expect("publish is fire-and-forget and never fails");
}

// ---------------------------------------------------------------------------
// (a) Behaviour preservation, including the ordering property
// ---------------------------------------------------------------------------

/// Both lanes serve their own topics, the threat lane's fused tier still emits
/// its toolkit request, and one protocol crash still produces exactly three
/// decisions **in order** — through the shim's subscription surface (the path
/// every existing consumer uses) and through a peer strand.
#[tokio::test]
async fn orchestrator_lanes_serve_their_topics_and_decisions_arrive_in_order() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let decisions_log = new_event_log();

    // A peer strand consuming the orchestrator's output by TypeId — the same
    // topic the old loop's `Bus::publish` reached.
    bus.register_spec(event_recorder_spec(
        "test.decision-recorder",
        DECISION_TOPIC,
        Arc::clone(&decisions_log),
    ));

    let orchestrator = orchestrator(&publisher);
    // The production policy: no injected fault. The lanes are queued on the
    // kernel directly (the orchestrator holds only the publisher, and strand
    // registration needs `&mut Bus`).
    queue_lanes(&mut bus, &publisher, &orchestrator, FaultPolicy::from_env());

    let mut decision_sub = subscribe_queue(&publisher, DECISION_TOPIC, 64);
    let mut toolkit_sub = subscribe_queue(&publisher, TOOLKIT_REQUEST_TOPIC, 64);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // --- The threat lane owns `net.sensors.` --------------------------------
    // A lone 0.7 classifier: below the 0.8 burn threshold, above the 0.5
    // dual-sensor threshold, so the fused tier answers `IncreaseMonitoring` and
    // the toolkit request goes out — while the active protocol stays put.
    offer_threat(
        &publisher,
        ThreatAssessment {
            source: ThreatSource::Classifier {
                model_name: "detector".into(),
            },
            confidence: 0.7,
            description: "windowed anomaly".into(),
            remote_addr: Some("198.51.100.7:443".parse().unwrap()),
            timestamp: chrono::Utc::now(),
            suggested_action: SuggestedAction::None,
        },
    );

    let request = tokio::time::timeout(Duration::from_secs(10), toolkit_sub.recv())
        .await
        .expect("the threat lane must route a toolkit request")
        .expect("subscription must not lag or close");
    match request.message {
        Message::ToolActivationReq(request) => {
            assert_eq!(request.tool_name, "transport.diagnostics");
            assert_eq!(
                request.trigger, "orchestrator.fused_monitoring",
                "the fused IncreaseMonitoring tier is unchanged by the conversion"
            );
        }
        other => panic!("expected a toolkit activation request, got {other:?}"),
    }
    assert_eq!(orchestrator.state(), OrchestratorState::Steady);
    assert_eq!(orchestrator.active_protocol(), "xray");

    // --- The failover lane owns `net.transport.event` ------------------------
    offer_protocol_crash(&publisher, "xray", "connection reset");

    let d1 = tokio::time::timeout(Duration::from_secs(10), decision_sub.recv())
        .await
        .expect("a promote decision must arrive")
        .expect("subscription must not lag or close");
    assert!(matches!(
        d1.message,
        Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby { .. })
    ));

    let d2 = tokio::time::timeout(Duration::from_secs(10), decision_sub.recv())
        .await
        .expect("a quarantine decision must arrive")
        .expect("subscription must not lag or close");
    assert!(matches!(
        d2.message,
        Message::OrchestratorDecision(OrchestratorDecision::QuarantineActive { .. })
    ));

    let d3 = tokio::time::timeout(Duration::from_secs(10), decision_sub.recv())
        .await
        .expect("a heal decision must arrive")
        .expect("subscription must not lag or close");
    assert!(matches!(
        d3.message,
        Message::OrchestratorDecision(OrchestratorDecision::BeginHealing { .. })
    ));

    assert_eq!(orchestrator.state(), OrchestratorState::Healing);
    assert_eq!(orchestrator.active_protocol(), "amneziawg");

    // --- The same three, seen by a peer strand ------------------------------
    wait_until(
        "the decision recorder strand to see three decisions",
        || recorded_decisions(&decisions_log).len() >= 3,
    );
    let recorded = recorded_decisions(&decisions_log);
    assert!(matches!(
        recorded[0],
        OrchestratorDecision::PromoteStandby { .. }
    ));
    assert!(matches!(
        recorded[1],
        OrchestratorDecision::QuarantineActive { .. }
    ));
    assert!(matches!(
        recorded[2],
        OrchestratorDecision::BeginHealing { .. }
    ));

    supervision.shutdown();
}

// ---------------------------------------------------------------------------
// (b) Specs are queued, not started — and re-queueing cannot collide
// ---------------------------------------------------------------------------

#[test]
fn queued_specs_are_not_started_until_engage() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    let orchestrator = orchestrator(&publisher);
    queue_lanes(&mut bus, &publisher, &orchestrator, FaultPolicy::from_env());
    // Idempotent by contract: the kernel panics on a duplicate strand name, so
    // this must be a no-op rather than a second registration.
    queue_lanes(&mut bus, &publisher, &orchestrator, FaultPolicy::from_env());

    // Nothing has started yet: a spec is queued, not installed. (`register_spec`
    // only appends; only `run_until` installs, and it consumes the bus.)
    assert_eq!(
        registered(&lifecycle, PROTOCOL_EVENTS_STRAND),
        0,
        "queueing the spec must not start the failover lane"
    );
    assert_eq!(
        registered(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        0,
        "queueing the spec must not start the threat lane"
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("both orchestrator lanes to be installed", || {
        registered(&lifecycle, PROTOCOL_EVENTS_STRAND) == 1
            && registered(&lifecycle, THREAT_ASSESSMENTS_STRAND) == 1
    });
    assert!(supervision.is_running(), "the run loop must be live");
    supervision.shutdown();
}

// ---------------------------------------------------------------------------
// (c) The crash-restart-quarantine drill, with failure-domain isolation
// ---------------------------------------------------------------------------

/// The threat lane's full crash policy, driven through the real strand with an
/// injected fault — and the failover lane's independence from it.
///
/// The threat lane is armed to crash after the first message each generation
/// handles, so every restart crashes again and the spider's whole policy runs:
/// four `Crashed` events, three `Restarted` events, one `Quarantined`. The
/// failover lane runs beside it with no fault: it is never crashed, never
/// restarted, and after the quarantine it still produces its three ordered
/// decisions — the property the conversion exists to protect.
#[test]
fn crashed_threat_lane_is_quarantined_while_the_failover_lane_serves() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let decisions_log = new_event_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(event_recorder_spec(
        "test.decision-recorder",
        DECISION_TOPIC,
        Arc::clone(&decisions_log),
    ));

    let orchestrator = orchestrator(&publisher);
    queue_lane(
        &mut bus,
        &publisher,
        Lane::ProtocolEvents,
        &orchestrator,
        FaultPolicy::None,
    );
    queue_lane(
        &mut bus,
        &publisher,
        Lane::ThreatAssessments,
        &orchestrator,
        FaultPolicy::CrashAfterMessages(1),
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    wait_until(
        "the threat lane to be installed and register itself",
        || registered(&lifecycle, THREAT_ASSESSMENTS_STRAND) == 1,
    );

    // Feed new assessments until the fourth crash has been quarantined. Each
    // generation crashes after its own first handled message, so the drill does
    // not depend on replay timing — and because the messages are new, the
    // replay guard never eats them.
    let mut index = 0u32;
    wait_until(
        "the threat lane to be quarantined after its fourth crash",
        || {
            offer_threat(&publisher, drill_assessment(index));
            index = index.saturating_add(1);
            quarantined(&lifecycle, THREAT_ASSESSMENTS_STRAND) >= 1
        },
    );

    assert!(
        supervision.is_running(),
        "the run loop was live for the whole drill"
    );

    // (a) Installed from a queued spec — only a spec is restartable, so the
    // `Restarted` events below are themselves proof the lane arrived as one.
    // `Registered` fires once per generation: initial + 3 restarts.
    assert_eq!(
        registered(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        4,
        "one `Registered` per generation: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    assert_eq!(
        crashed(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        4,
        "every crash must be visible as a lifecycle event: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        3,
        "the spider restarts three times: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        1,
        "the fourth crash quarantines the lane: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The injected fault names itself in every crash reason: a real forensic
    // signal, and proof the crash came from the drill and not from a bug.
    let reasons = crash_reasons(&lifecycle, THREAT_ASSESSMENTS_STRAND);
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("injected fault") && reason.contains("1 message")),
        "the injected fault must name itself in every Crashed reason: {reasons:?}"
    );

    // --- Isolation: the failover lane was never touched by any of that -------
    assert_eq!(
        crashed(&lifecycle, PROTOCOL_EVENTS_STRAND),
        0,
        "the failover lane must not crash because its neighbour did"
    );
    assert_eq!(restarted(&lifecycle, PROTOCOL_EVENTS_STRAND), 0);
    assert_eq!(quarantined(&lifecycle, PROTOCOL_EVENTS_STRAND), 0);
    assert_eq!(
        registered(&lifecycle, PROTOCOL_EVENTS_STRAND),
        1,
        "the failover lane is still the generation it was installed as"
    );

    // …and it still serves: a crash after the quarantine produces the three
    // decisions, in order, through the peer strand.
    offer_protocol_crash(&publisher, "xray", "after the quarantine");
    wait_until("the failover lane to still answer a crash", || {
        recorded_decisions(&decisions_log).len() >= 3
    });
    let recorded = recorded_decisions(&decisions_log);
    assert!(matches!(
        recorded[0],
        OrchestratorDecision::PromoteStandby { .. }
    ));
    assert!(matches!(
        recorded[1],
        OrchestratorDecision::QuarantineActive { .. }
    ));
    assert!(matches!(
        recorded[2],
        OrchestratorDecision::BeginHealing { .. }
    ));
    assert_eq!(orchestrator.state(), OrchestratorState::Healing);
    assert_eq!(orchestrator.active_protocol(), "amneziawg");

    // After quarantine the threat lane is gone for good: further assessments
    // cannot revive it. (Its own events are counted, not the whole stream —
    // unrelated `Buffered`/`ThreadFormed` events keep arriving.)
    supervision.shutdown();
    let before = events_for(&lifecycle, THREAT_ASSESSMENTS_STRAND);
    for offset in 0..5 {
        offer_threat(&publisher, drill_assessment(1_000 + offset));
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        events_for(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        before,
        "a quarantined lane must stay quarantined: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

// ---------------------------------------------------------------------------
// (d) The replayed tail is deduped, never reprocessed
// ---------------------------------------------------------------------------

/// A restarted generation is a late subscriber and is replayed the recent tail
/// (recipe §5.4) — of messages the *previous* generation already handled. The
/// orchestrator's transitions are not idempotent, so the lane's durable
/// [`SeenIds`](imperium_net_transport::strand::SeenIds) history refuses them.
///
/// The proof is exact: one ground-truth threat is published (which fails the
/// active protocol over and emits three decisions), the armed lane crashes once,
/// the restarted generation is replayed that same tail — and then
///   * it does **not** re-run the handler (still exactly three decisions, not
///     six and not an emergency escalation), and
///   * it does **not** re-trip its own fault (one crash, one restart), because
///     the replayed message never counts as handled work.
#[test]
fn replayed_tail_is_deduped_not_reprocessed() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let decisions_log = new_event_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(event_recorder_spec(
        "test.decision-recorder",
        DECISION_TOPIC,
        Arc::clone(&decisions_log),
    ));

    let orchestrator = orchestrator(&publisher);
    queue_lane(
        &mut bus,
        &publisher,
        Lane::ProtocolEvents,
        &orchestrator,
        FaultPolicy::None,
    );
    queue_lane(
        &mut bus,
        &publisher,
        Lane::ThreatAssessments,
        &orchestrator,
        FaultPolicy::CrashAfterMessages(1),
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the threat lane to be installed", || {
        registered(&lifecycle, THREAT_ASSESSMENTS_STRAND) == 1
    });

    // Exactly one message, ever: a signature ground truth at 0.95 (fused
    // `TriggerFailover` + toolkit request). Handling it once is what a replayed
    // tail must not do twice.
    offer_threat(
        &publisher,
        ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 0.95,
            description: "ground truth".into(),
            remote_addr: None,
            timestamp: chrono::Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        },
    );

    wait_until("the first crash (the armed fault)", || {
        crashed(&lifecycle, THREAT_ASSESSMENTS_STRAND) >= 1
    });
    wait_until("the restart", || {
        restarted(&lifecycle, THREAT_ASSESSMENTS_STRAND) >= 1
    });
    wait_until(
        "the kernel to flush the pending tail into the restarted generation",
        || {
            count(&lifecycle, |event| {
                matches!(
                    event,
                    LifecycleEvent::Flushed { to, count, .. }
                        if to == THREAT_ASSESSMENTS_STRAND && *count >= 1
                )
            }) >= 1
        },
    );
    // Let the restarted generation drain whatever it was replayed, and give a
    // broken guard time to crash again.
    std::thread::sleep(Duration::from_millis(400));
    supervision.shutdown();

    // The guard was genuinely exercised: the replay reached the new generation.
    assert!(
        count(&lifecycle, |event| matches!(
            event,
            LifecycleEvent::Flushed { to, count, .. }
                if to == THREAT_ASSESSMENTS_STRAND && *count >= 1
        )) >= 1,
        "the replay must actually have happened for this test to mean anything: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // …and it was refused, exactly as the recipe prescribes.
    assert_eq!(
        crashed(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        1,
        "a deduped replay must not count as handled work: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        1,
        "one crash, one restart: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined(&lifecycle, THREAT_ASSESSMENTS_STRAND),
        0,
        "the restarted generation must survive its replay: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The observable consequence: the non-idempotent handler ran exactly once.
    // Reprocessing the replay would fail the active protocol over a second time
    // and, from `Healing`, escalate to emergency shutdown.
    let recorded = recorded_decisions(&decisions_log);
    assert_eq!(
        recorded.len(),
        3,
        "one handling, three decisions — a replayed handling would add more: {recorded:?}"
    );
    assert!(matches!(
        recorded[0],
        OrchestratorDecision::PromoteStandby { .. }
    ));
    assert!(matches!(
        recorded[1],
        OrchestratorDecision::QuarantineActive { .. }
    ));
    assert!(matches!(
        recorded[2],
        OrchestratorDecision::BeginHealing { .. }
    ));
    assert_eq!(orchestrator.state(), OrchestratorState::Healing);
    assert_eq!(orchestrator.active_protocol(), "amneziawg");
}

// ---------------------------------------------------------------------------
// The supervision composition this test binary owns
// ---------------------------------------------------------------------------

/// Clears the liveness flag when the run-loop thread exits, whether `run_until`
/// returned normally or unwound (`panic = "unwind"` runs the `Drop`).
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its own
/// thread until [`Supervision::shutdown`]. `run_until` consumes the bus, so the
/// kernel moves onto the thread and only the `BusPublisher` stays behind.
struct Supervision {
    publisher: Arc<BusPublisher>,
    running: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Supervision {
    fn engage_with(mut bus: Bus, publisher: Arc<BusPublisher>) -> Self {
        bus.register_spider(StrandSpec::new(
            "spider",
            || Box::new(spider::Spider::new()),
        ));

        let running = Arc::new(AtomicBool::new(false));
        let thread_flag = Arc::clone(&running);
        let join = std::thread::Builder::new()
            .name("imperium-supervision".to_string())
            .spawn(move || {
                thread_flag.store(true, Ordering::SeqCst);
                let _running = RunningGuard(Arc::clone(&thread_flag));
                let mut bus = bus;
                bus.run_until(None);
            })
            .expect("failed to spawn the supervision run-loop thread");

        Self {
            publisher,
            running,
            join: Some(join),
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
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
