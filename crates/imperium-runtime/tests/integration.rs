use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use imperium_protocol::BusEvent;
use imperium_protocol::*;
use spiderweb::{Bus, BusPublisher, ControlMsg, StrandSpec, SYS_CONTROL};

// ---------------------------------------------------------------------------
// Test 1: Emergency shutdown end-to-end
//
// Blueprint acceptance criterion (Phase 2):
//   "If active fails before healing produces a new standby, the orchestrator
//    triggers emergency shutdown: both protocols torn down, vault sealed,
//    operator notified, manual recovery required."
//
// FIXED (Round 4.A): Orchestrator now publishes to
//   "emergency.transport.double_degraded" which matches the coordinator's
//   "emergency" prefix subscription.
//
// FIXED (Round 4.B): Vault is sealed by RuntimeCoordinator::shutdown_all()
//   via the with_vault() hook.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_1_emergency_shutdown_end_to_end() {
    use imperium_net_transport::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};

    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    // A second handle onto the same kernel, for the strainer stack (the type is
    // not `Clone`, so it is minted from the kernel rather than cloned).
    let _strainer_publisher = bus.publisher();

    let config = OrchestratorConfig {
        active_protocol: "xray".into(),
        standby_protocol: "amneziawg".into(),
        policy: OrchestratorPolicy::default(),
    };

    let orch = Arc::new(Orchestrator::new(config, Arc::clone(&publisher)));
    // The orchestrator's lanes are supervised strands now: queue this concrete
    // instance before engaging. Do not call the default `register_strands`
    // here; it would build a second orchestrator/hardening pair and this test
    // would observe the wrong object. Without queued lanes nothing consumes
    // `net.transport.event`.
    imperium_net_transport::queue_lanes(
        &mut bus,
        &publisher,
        &orch,
        imperium_net_transport::FaultPolicy::from_env(),
    );
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    let mut emergency_sub = subscribe_queue(&publisher, "emergency.transport.double_degraded", 64);
    let mut decision_sub = subscribe_queue(&publisher, "net.transport.decision", 64);

    // Drive: crash active protocol → failover, then crash new active → emergency
    let crash_active = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "test crash 1".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    BusEvent::publish(
        &publisher,
        "net.transport.event",
        Message::ProtocolEvt(crash_active),
    )
    .unwrap();

    // Wait for failover to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: orchestrator transitioned to Healing, standby promoted
    assert_eq!(orch.state(), OrchestratorState::Healing);
    assert_eq!(orch.active_protocol(), "amneziawg");

    // Verify decisions were published: PromoteStandby, QuarantineActive, BeginHealing
    let d1 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        d1.message,
        Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby { .. })
    ));

    let d2 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        d2.message,
        Message::OrchestratorDecision(OrchestratorDecision::QuarantineActive { .. })
    ));

    let d3 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        d3.message,
        Message::OrchestratorDecision(OrchestratorDecision::BeginHealing { .. })
    ));

    // Now crash the new active (amneziawg) — triggers double-degraded → emergency
    let crash_new_active = ProtocolEvent {
        protocol_name: "amneziawg".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "test crash 2".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    BusEvent::publish(
        &publisher,
        "net.transport.event",
        Message::ProtocolEvt(crash_new_active),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: orchestrator is now in Emergency state
    assert_eq!(orch.state(), OrchestratorState::Emergency);

    // Verify: EmergencyShutdown event published on "emergency.transport.double_degraded"
    let emergency = tokio::time::timeout(Duration::from_millis(100), emergency_sub.recv())
        .await
        .unwrap()
        .unwrap();
    if let Message::EmergencyShutdown(es) = &emergency.message {
        assert!(es.reason.contains("crashed during healing"));
    } else {
        panic!(
            "expected EmergencyShutdown message, got {:?}",
            emergency.message
        );
    }

    // Verify: topic follows convention and matches coordinator's "emergency" prefix
    let topic = &*emergency.topic;
    assert_eq!(topic, "emergency.transport.double_degraded");
    assert!(
        topic.starts_with("emergency"),
        "topic must match the coordinator's 'emergency' prefix subscription"
    );

    // Verify: vault is sealed when coordinator processes emergency shutdown
    use imperium_runtime::RuntimeCoordinator;
    use std::sync::Mutex;

    let vault = Arc::new(Mutex::new(imperium_secrets_vault::Vault::new(
        imperium_store::Store::in_memory(),
    )));
    assert!(!vault.lock().unwrap().is_sealed());

    let coord = RuntimeCoordinator::new().with_vault(Arc::clone(&vault));

    let coord_bus = coord.bus();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        BusEvent::publish(
            &coord_bus,
            "emergency.transport.double_degraded",
            Message::EmergencyShutdown(EmergencyShutdown {
                reason: "test vault seal".into(),
                triggered_at: chrono::Utc::now(),
                active_protocol: None,
                standby_protocol: None,
            }),
        )
        .unwrap();
    });

    let reason = coord.run().await;
    assert!(matches!(
        reason,
        imperium_runtime::ShutdownReason::EmergencyShutdown { .. }
    ));
    assert!(
        vault.lock().unwrap().is_sealed(),
        "vault must be sealed after emergency shutdown"
    );
    supervision.shutdown();
}

// ---------------------------------------------------------------------------
// Test 2: Two-node cluster formation via bus
//
// Blueprint acceptance criterion (Phase 1):
//   "Operator mints a bootstrap token. New node imports it. Operator approves.
//    MembershipGrant signed and gossiped. New node is a full cluster member."
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_2_cluster_formation_via_bus() {
    use imperium_net_cluster::{MembershipManager, TokenManager};
    use imperium_net_crypto::HybridEd25519Mldsa;
    use rand::rngs::OsRng;

    let bus = Bus::open();
    let publisher = Arc::new(bus.publisher());

    let cluster_id = ClusterId::new();
    let node_a_id = PeerId::new();
    let node_b_id = PeerId::new();

    let mut rng = OsRng;
    let (operator_sk, _operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

    // Node A: operator node with full membership
    let mgr_a = Arc::new(MembershipManager::new(
        cluster_id.clone(),
        node_a_id.clone(),
        HybridEd25519Mldsa::verifying_key(&operator_sk),
    ));
    ::imperium_net_cluster::attach_membership(&publisher, &mgr_a);

    // Node B: joining node
    let mgr_b = Arc::new(MembershipManager::new(
        cluster_id.clone(),
        node_b_id.clone(),
        HybridEd25519Mldsa::verifying_key(&operator_sk),
    ));
    ::imperium_net_cluster::attach_membership(&publisher, &mgr_b);

    // Third observer on the bus to verify gossip propagation
    let mut gossip_sub = subscribe_queue(&publisher, "net.cluster.membership.gossip", 64);

    // Step 1: Operator mints a bootstrap token
    let token_mgr = TokenManager::new(
        cluster_id.clone(),
        HybridEd25519Mldsa::verifying_key(&operator_sk),
    );
    let token = token_mgr.mint_token(&node_a_id, &operator_sk, chrono::Duration::hours(1));

    // Step 2: Token verifies
    assert!(token_mgr.verify_token(&token).is_ok());

    // Step 3: Node B requests membership via bus
    mgr_a
        .request_membership(node_b_id.clone(), &publisher)
        .unwrap();

    // Step 4: Operator approves on Node A
    let grant = mgr_a
        .approve_membership(&node_b_id, &node_a_id, &operator_sk, &publisher)
        .unwrap();

    // Wait for bus propagation
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: grant signature is non-empty (signed by operator)
    assert!(!grant.signature.is_empty());

    // Verify: Node A knows Node B is approved
    assert!(mgr_a.is_member(&node_b_id));
    assert_eq!(mgr_a.member_count(), 2); // self + node_b

    // Verify: Node B received the grant via bus and applied it
    assert!(mgr_b.is_member(&node_b_id));

    // Verify: token is single-use
    token_mgr.consume_token(&token);
    assert!(matches!(token_mgr.verify_token(&token), Err(_)));

    // Verify: gossip propagated — third subscriber sees membership update
    let gossip = tokio::time::timeout(Duration::from_millis(100), gossip_sub.recv())
        .await
        .unwrap()
        .unwrap();
    if let Message::MembershipGossip(g) = &gossip.message {
        assert_eq!(g.members.len(), 2);
        assert!(g.members.contains(&node_a_id));
        assert!(g.members.contains(&node_b_id));
    } else {
        panic!("expected MembershipGossip");
    }
}

// ---------------------------------------------------------------------------
// Test 3: Failover via bus
//
// Blueprint acceptance criterion (Phase 2):
//   "Active crashes → standby promoted → healing begins.
//    No premature Emergency unless healing also fails."
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_3_failover_via_bus() {
    use imperium_net_transport::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};

    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());

    let config = OrchestratorConfig {
        active_protocol: "xray".into(),
        standby_protocol: "amneziawg".into(),
        policy: OrchestratorPolicy::default(),
    };

    let orch = Arc::new(Orchestrator::new(config, Arc::clone(&publisher)));
    // Supervised strands: queue this concrete orchestrator's lanes, then
    // engage (see test_1). Do not call the default `register_strands` here;
    // it would build a second orchestrator/hardening pair.
    imperium_net_transport::queue_lanes(
        &mut bus,
        &publisher,
        &orch,
        imperium_net_transport::FaultPolicy::from_env(),
    );
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    let mut decision_sub = subscribe_queue(&publisher, "net.transport.decision", 64);

    // Drive: active protocol crashes
    let crash = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "connection reset".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    BusEvent::publish(
        &publisher,
        "net.transport.event",
        Message::ProtocolEvt(crash),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: orchestrator transitioned through Failover to Healing
    assert_eq!(orch.state(), OrchestratorState::Healing);

    // Verify: new active is amneziawg (standby was promoted)
    assert_eq!(orch.active_protocol(), "amneziawg");

    // Verify: PromoteStandby decision published
    let d1 = tokio::time::timeout(Duration::from_millis(100), decision_sub.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        d1.message,
        Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby { .. })
    ));

    // Verify: no Emergency state — healing has NOT failed yet
    assert_ne!(orch.state(), OrchestratorState::Emergency);

    // Drive: healing succeeds
    let heal = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Standby,
        status: ProtocolStatus::Running,
        event: ProtocolEventKind::HealingSucceeded,
        timestamp: chrono::Utc::now(),
    };
    BusEvent::publish(
        &publisher,
        "net.transport.event",
        Message::ProtocolEvt(heal),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify: back to Steady
    assert_eq!(orch.state(), OrchestratorState::Steady);
    supervision.shutdown();
}

// ---------------------------------------------------------------------------
// Test 4: Strainer engagement via bus — rejection lands in memory log
//
// Blueprint acceptance criterion (Phase 3):
//   "StrainerRejection events have full provenance (strainer_id, stack_id,
//    shape_failed, source_identifier, timestamp) and are recorded in the
//    memory log."
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_4_strainer_rejection_to_memory_log() {
    use imperium_memory_log::MemoryLog;
    use imperium_net_strainer::{AuthShapeOuterStrainer, StrainerInput, StrainerStack};

    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());

    let log = Arc::new(MemoryLog::new(1000));
    // The log's two recv loops are supervised strands now (their tokio::spawns
    // are gone): queue the specs, then engage — see
    // `imperium_memory_log::register_strands`.
    imperium_memory_log::register_strands(&mut bus, &log);
    let strainer_publisher = bus.publisher();
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // Build a strainer stack with an auth-outer strainer (max 128 bytes)
    let mut stack = StrainerStack::new("auth_stack", "test_protocol").with_bus(strainer_publisher);
    stack.add_stage(Arc::new(AuthShapeOuterStrainer::new(128)));

    // Drive: feed oversized input → triggers rejection
    let input = StrainerInput {
        data: vec![0u8; 256],
        source: Some("192.168.1.100:9999".parse().unwrap()),
        context: HashMap::new(),
        timestamp: chrono::Utc::now(),
    };

    let output = stack.apply(input);
    assert!(output.is_rejected());

    // Wait for bus delivery. The rejection loop is a supervised strand now, so
    // the append lands on its next worker tick (~10ms) instead of inline; poll
    // briefly so this does not depend on tick timing.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while log.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    supervision.shutdown();

    // Verify: memory log recorded the rejection
    let entries = log.entries_since(0);
    assert_eq!(
        entries.len(),
        1,
        "expected one log entry from the rejection"
    );

    let entry = &entries[0];
    if let Message::StrainerRejection(ref rej) = entry.event.message {
        // Verify all five provenance fields are populated
        assert!(!rej.strainer_id.is_empty(), "strainer_id must be populated");
        assert_eq!(rej.stack_id, "auth_stack");
        assert!(
            !rej.shape_failed.is_empty(),
            "shape_failed must be populated"
        );
        assert!(
            rej.source_identifier.is_some(),
            "source_identifier must be populated"
        );
        assert_eq!(
            rej.source_identifier.unwrap().to_string(),
            "192.168.1.100:9999"
        );
        // timestamp is always populated by construction
    } else {
        panic!(
            "expected StrainerRejection in log, got {:?}",
            entry.event.message
        );
    }
}

// ---------------------------------------------------------------------------
// Test 5: Two-phase signature activation
//
// Blueprint acceptance criterion (Phase 6):
//   "Operator reviews and approves signature candidates. Only approved
//    signatures join the active database."
//
// Verifies the full two-phase activation path: candidate persisted in store,
// operator approves via staging, engine fetches from store, compiles YARA rule,
// loads it into the scan pipeline, and publishes SignatureActivated.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_5_signature_approval_triggers_engine_notification() {
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_net_sensors::{FaultPolicy, SignatureEngineSensor};
    use imperium_net_signatures::StagingArea;
    use imperium_store::Store;
    use rand::rngs::OsRng;

    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let store = Store::in_memory();

    // Create and persist the candidate in the store BEFORE approval
    let candidate = SignatureCandidate {
        id: uuid::Uuid::new_v4(),
        rule_text: r#"rule test_sig { strings: $a = { CA FE BA BE } condition: $a }"#.into(),
        description: "test candidate".into(),
        source_events: vec![EventId::new()],
        extracted_at: chrono::Utc::now(),
        confidence: 0.9,
    };
    let candidate_id = candidate.id;
    let key = format!("signature_candidate:{}", candidate_id);
    store
        .put(&key, serde_json::to_vec(&candidate).unwrap())
        .unwrap();

    let mut rng = OsRng;
    let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    let engine = Arc::new(
        SignatureEngineSensor::new(Arc::clone(&publisher))
            .with_store(store)
            .with_operator_verify_key(Arc::new(vk)),
    );
    // The engine's approval loop is a supervised Spiderweb strand now: queue its
    // spec BEFORE the kernel is engaged (`register_strand` refuses a spec once
    // supervision is running, so the ordering here is load-bearing).
    bus.register_spec(engine.strand_spec(FaultPolicy::None));
    // This signature-activation flow does not currently exercise a transport
    // orchestrator state machine, so no orchestrator lanes are queued here.
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    let mut activation_sub = subscribe_queue(&publisher, "net.signatures.activated", 64);

    let staging = StagingArea::new(Arc::clone(&publisher));

    staging.submit(candidate).unwrap();
    assert_eq!(staging.pending_count(), 1);

    // Operator approves with the same key the engine verifies against.
    let operator = PeerId::new();

    let approved = staging.approve(candidate_id, &operator, &sk).unwrap();
    assert_eq!(approved.candidate_id, candidate_id);
    assert_eq!(staging.pending_count(), 0);

    // Verify: engine received the approval and published SignatureActivated
    let activated = tokio::time::timeout(Duration::from_secs(2), activation_sub.recv())
        .await
        .unwrap()
        .unwrap();
    supervision.shutdown();

    if let Message::SignatureActivated(ref act) = activated.message {
        assert_eq!(act.candidate_id, candidate_id);
    } else {
        panic!("expected SignatureActivated, got {:?}", activated.message);
    }

    // Two-phase activation: the engine has compiled and loaded the rule.
    // A scan against CAFEBABE data MUST match.
    let data = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let matches = engine.scan(&data).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "Two-phase activation should load the approved rule into the engine"
    );
}

// ---------------------------------------------------------------------------
// Test 6: System operates normally without adaptive observation
//
// Blueprint acceptance criterion (Phase 5):
//   "Adaptive observation is not load-bearing. The deterministic substrate
//    functions correctly without it."
//
// Runs simplified versions of tests 1-4 with only deterministic components.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_6_system_without_adaptive_observation() {
    use imperium_memory_log::MemoryLog;
    use imperium_net_cluster::MembershipManager;
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_net_strainer::{AuthShapeOuterStrainer, StrainerInput, StrainerStack};
    use imperium_net_transport::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};
    use rand::rngs::OsRng;

    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());

    // --- Orchestrator ---
    let orch_config = OrchestratorConfig {
        active_protocol: "xray".into(),
        standby_protocol: "amneziawg".into(),
        policy: OrchestratorPolicy::default(),
    };
    let orch = Arc::new(Orchestrator::new(orch_config, Arc::clone(&publisher)));
    // Supervised strands: queue this concrete orchestrator's lanes, then
    // engage (see test_1). Do not call the default `register_strands` here;
    // it would build a second orchestrator/hardening pair.
    imperium_net_transport::queue_lanes(
        &mut bus,
        &publisher,
        &orch,
        imperium_net_transport::FaultPolicy::from_env(),
    );

    // --- Cluster ---
    // The membership-grant loop is a supervised strand too (its `tokio::spawn`
    // is gone): the legacy `subscribe_membership_grants` shim queues the spec, so
    // it has to run *before* the engage below — a spec offered afterwards can
    // never be installed.
    let cluster_id = ClusterId::new();
    let local_id = PeerId::new();
    let mut rng = OsRng;
    let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

    let membership = Arc::new(MembershipManager::new(
        cluster_id.clone(),
        local_id.clone(),
        HybridEd25519Mldsa::verifying_key(&sk),
    ));
    ::imperium_net_cluster::attach_membership(&publisher, &membership);

    // --- Memory log ---
    // The log's two recv loops are supervised strands now (their tokio::spawns
    // are gone), so their specs must be queued *before* the engage below too.
    let log = Arc::new(MemoryLog::new(1000));
    imperium_memory_log::register_strands(&mut bus, &log);
    let strainer_publisher = bus.publisher();
    let _supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // --- Strainer ---
    let mut stack = StrainerStack::new("auth_stack", "xray").with_bus(strainer_publisher);
    stack.add_stage(Arc::new(AuthShapeOuterStrainer::new(128)));

    // Test A: Failover works through deterministic protocol events
    let crash = ProtocolEvent {
        protocol_name: "xray".into(),
        role: ProtocolRole::Active,
        status: ProtocolStatus::Failed,
        event: ProtocolEventKind::Crashed {
            reason: "test".into(),
        },
        timestamp: chrono::Utc::now(),
    };
    BusEvent::publish(
        &publisher,
        "net.transport.event",
        Message::ProtocolEvt(crash),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orch.state(), OrchestratorState::Healing);

    // Test B: Cluster formation works
    let joining_peer = PeerId::new();
    membership
        .request_membership(joining_peer.clone(), &publisher)
        .unwrap();
    let _grant = membership
        .approve_membership(&joining_peer, &local_id, &sk, &publisher)
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(membership.is_member(&joining_peer));

    // Test C: Strainer rejection works
    let input = StrainerInput {
        data: vec![0u8; 256],
        source: Some("10.0.0.1:1234".parse().unwrap()),
        context: HashMap::new(),
        timestamp: chrono::Utc::now(),
    };
    let output = stack.apply(input);
    assert!(output.is_rejected());
    // The rejection loop is a supervised strand now: poll for its next tick
    // (~10ms) rather than assuming the append is inline.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while log.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Verify: log has entries (at minimum the strainer rejection)
    let entries = log.entries_since(0);
    assert!(
        !entries.is_empty(),
        "memory log should have recorded deterministic events"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Closed-loop signature extraction end-to-end
//
// Blueprint acceptance criterion (Phase 6):
//   "Extraction → staging → approval → engine activation → traffic match"
//
// Full pipeline: a strainer rejection lands in the memory log. An extraction
// request triggers the extraction loop, which pulls event data, extracts a
// YARA candidate, persists it to the store, and submits to staging. Operator
// approves. Two-phase activation fetches from store, compiles, loads. Scan
// matches.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_7_closed_loop_extraction_to_engine_match() {
    use imperium_memory_log::MemoryLog;
    use imperium_net_crypto::HybridEd25519Mldsa;
    use imperium_net_sensors::{FaultPolicy, SignatureEngineSensor};
    use imperium_net_signatures::{ExtractionLoop, ExtractionStrand, StagingArea};
    use imperium_store::Store;
    use rand::rngs::OsRng;

    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let store = Arc::new(Store::in_memory());
    let memory_log = Arc::new(MemoryLog::new(10_000));
    let staging = Arc::new(StagingArea::new(Arc::clone(&publisher)));

    // Wire the extraction loop. Its request loop is a SUPERVISED STRAND now
    // (the `tokio::spawn`ed recv loop is gone), so it is queued as a spec here
    // and installed by the `engage_supervision()` below, which also installs
    // the engine's approval strand — one run loop for both. Registration must
    // precede that engage: the kernel only grows inside its run loop.
    let extraction_loop = Arc::new(ExtractionLoop::new(
        Arc::clone(&publisher),
        Arc::clone(&store),
        Arc::clone(&memory_log),
        Arc::clone(&staging),
    ));
    bus.register_spec(ExtractionStrand::spec(
        Arc::clone(&extraction_loop),
        // Fully qualified: `FaultPolicy` is also the engine's (sensors') type
        // in this scope, and this one is the signatures strand's.
        imperium_net_signatures::FaultPolicy::None,
    ));

    // The signature engine with two-phase activation. The engine verifies
    // approvals against the persisted operator key, so the test wires the same
    // keypair into the engine up front. It SHARES the extraction store
    // (`with_shared_store`), which is what lets it be built and registered here:
    // every strand spec must be queued before the single `engage_supervision()`
    // below installs them, and the extraction strand has to be live before the
    // request in step 2. The activation path reads the candidate out of that
    // shared store under the same key the extraction wrote it to.
    let mut rng = OsRng;
    let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    let engine = Arc::new(
        SignatureEngineSensor::new(Arc::clone(&publisher))
            .with_shared_store(Arc::clone(&store))
            .with_operator_verify_key(Arc::new(vk)),
    );
    // The engine's approval loop is a supervised strand too; its spec is queued
    // here, beside the extraction strand's, and both are installed by the engage
    // below (a spec queued after supervision starts can never be installed).
    bus.register_spec(engine.strand_spec(FaultPolicy::None));

    // One engage installs BOTH strands (and the spider): the extraction loop is
    // live before the request in step 2, the approval loop before step 5.
    // The concrete orchestrator above is not under test here; queue only the
    // hardening lane needed for default-profile behavior.
    imperium_net_transport::queue_hardening(
        &mut bus,
        &publisher,
        &Arc::new(imperium_net_transport::HardeningController::new(
            Arc::clone(&publisher),
        )),
        imperium_net_transport::HardeningFaultPolicy::from_env(),
    );
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // Step 1: Simulate a strainer rejection entering the memory log
    let rejection_event = BusEvent::new(
        "net.strainer.rejection",
        Message::StrainerRejection(StrainerRejection {
            strainer_id: "auth_outer".into(),
            stack_id: "xray_stack".into(),
            shape_failed: "oversized".into(),
            source_identifier: Some("10.0.0.99:31337".parse().unwrap()),
            timestamp: chrono::Utc::now(),
        }),
    );
    let trigger_event_id = rejection_event.id.clone();
    memory_log.append(rejection_event);

    // Step 2: Publish extraction request (simulating CLI)
    let mut pending_sub = subscribe_queue(&publisher, "net.signatures.candidate_pending", 64);

    BusEvent::publish(
        &publisher,
        "net.signatures.extraction_request",
        Message::ExtractionRequest(ExtractionRequest {
            triggering_event_ids: vec![trigger_event_id],
            reason: "suspicious probe pattern".into(),
            requested_by: "test_operator".into(),
        }),
    )
    .unwrap();

    // Wait for candidate_pending notification
    let pending_event = tokio::time::timeout(Duration::from_millis(500), pending_sub.recv())
        .await
        .unwrap()
        .unwrap();

    let candidate_id =
        if let Message::SignatureCandidatePending(ref pending) = pending_event.message {
            assert_eq!(pending.requested_by, "test_operator");
            pending.candidate_id
        } else {
            panic!(
                "expected SignatureCandidatePending, got {:?}",
                pending_event.message
            );
        };

    // Verify candidate is in the store
    let key = format!("signature_candidate:{}", candidate_id);
    assert!(
        store.exists(&key),
        "candidate must be in store before approval"
    );

    // Step 3 is gone: the engine shares this store (see the wiring above), so
    // the candidate extracted in step 2 is already the one it will activate —
    // no copy into a second store, and no window where the two disagree.

    let mut activated_sub = subscribe_queue(&publisher, "net.signatures.activated", 64);

    // Step 5: Operator approves the candidate with the engine's key.
    let operator = PeerId::new();

    let approved = staging.approve(candidate_id, &operator, &sk).unwrap();
    assert_eq!(approved.candidate_id, candidate_id);

    // Wait for activation
    let activated_event = tokio::time::timeout(Duration::from_secs(2), activated_sub.recv())
        .await
        .unwrap()
        .unwrap();
    supervision.shutdown();

    if let Message::SignatureActivated(ref act) = activated_event.message {
        assert_eq!(act.candidate_id, candidate_id);
    } else {
        panic!(
            "expected SignatureActivated, got {:?}",
            activated_event.message
        );
    }

    // Step 6: Verify the engine loaded the rule and can match traffic
    assert_eq!(
        engine.extracted_count(),
        1,
        "engine should have loaded the extracted rule"
    );

    // The extracted YARA rule contains a hex pattern derived from the serialized
    // event data. The extractor's frequency filter strips common bytes (like `"`
    // in JSON), so the pattern is a subsequence of the original serialization.
    // Construct probe data that contains the pattern bytes contiguously.
    let candidate: SignatureCandidate = serde_json::from_slice(&store.get(&key).unwrap()).unwrap();

    // Extract the hex string from the rule text: `$a = { HEX } condition`
    let hex_start = candidate.rule_text.find("$a = { ").unwrap() + 7;
    let hex_end = candidate.rule_text[hex_start..].find(" }").unwrap() + hex_start;
    let hex_str = &candidate.rule_text[hex_start..hex_end];
    let pattern_bytes: Vec<u8> = hex_str
        .split(' ')
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();

    // Embed the pattern in realistic-looking traffic data
    let mut probe = vec![0x00; 16];
    probe.extend_from_slice(&pattern_bytes);
    probe.extend_from_slice(&[0xFF; 16]);

    let matches = engine.scan(&probe).unwrap();
    assert_eq!(
        matches.len(),
        1,
        "engine should match traffic containing the extracted pattern"
    );
    assert_eq!(matches[0].confidence, 1.0);
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
