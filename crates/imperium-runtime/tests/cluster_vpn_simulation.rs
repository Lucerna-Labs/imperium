use std::sync::Arc;
use std::time::Duration;

use imperium_net_cluster::{AccessPolicy, ConfigManager, MembershipManager, TokenManager};
use imperium_net_crypto::{HybridEd25519Mldsa, HybridX25519Mlkem};
use imperium_net_mesh::{NatTraversalPlanner, PeerManager, PeerState, SessionManager};
use imperium_net_transport::{
    queue_lanes, HardeningController, Orchestrator, OrchestratorConfig, OrchestratorPolicy,
};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    ClusterId, IdentityCapabilityGrant, Message, NatTraversalMode, OrchestratorDecision,
    OrchestratorState, PathMetrics, PeerId, ProtocolEvent, ProtocolEventKind,
    ProtocolHardeningProfile, ProtocolRole, ProtocolStatus, RelayFallbackRequest,
    RelayFallbackSelected, SuggestedAction, ThreatAssessment, ThreatSource,
};
use rand::rngs::OsRng;
use spiderweb::{Bus, BusPublisher, ControlMsg, StrandSpec, SYS_CONTROL};

struct SimClusterNode {
    id: PeerId,
    membership: Arc<MembershipManager>,
    config: Arc<ConfigManager>,
    peers: PeerManager,
    sessions: SessionManager,
}

impl SimClusterNode {
    fn new(
        cluster_id: ClusterId,
        id: PeerId,
        operator_vk: imperium_net_crypto::HybridVerifyingKey,
    ) -> Self {
        Self {
            id: id.clone(),
            membership: Arc::new(MembershipManager::new(
                cluster_id.clone(),
                id.clone(),
                operator_vk.clone(),
            )),
            config: Arc::new(ConfigManager::new(cluster_id, id.clone(), operator_vk)),
            peers: PeerManager::new(),
            sessions: SessionManager::new(),
        }
    }

    fn endpoint(&self, port: u16) -> std::net::SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeploymentRole {
    Operator,
    Client,
    Relay,
}

struct DeploymentNode {
    role: DeploymentRole,
    port: u16,
    node: SimClusterNode,
}

#[derive(Debug, Default)]
struct AutoDeploymentReport {
    planned_nodes: usize,
    approved_nodes: usize,
    config_version: u64,
    established_sessions: usize,
    relay_fallbacks_selected: usize,
    hardening_profiles_accepted: usize,
    denied_shutdown_capabilities: usize,
    default_nat_plans: usize,
    aggressive_nat_plans: usize,
}

fn establish_mesh_session(
    node: &SimClusterNode,
    peer_id: PeerId,
    remote_addr: std::net::SocketAddr,
) {
    let session_id = node
        .sessions
        .create_session(peer_id.clone(), remote_addr, true)
        .unwrap();
    let mut rng = OsRng;
    let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
    let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);

    node.sessions
        .establish_session(&session_id, key, &[], &[])
        .unwrap();
    node.peers.set_session(&peer_id, session_id);
}

fn deployment_capabilities(role: DeploymentRole) -> Vec<String> {
    match role {
        DeploymentRole::Operator => vec![
            "vpn.control".into(),
            "vpn.hardening.apply".into(),
            "vpn.cluster.admin".into(),
        ],
        DeploymentRole::Client => vec!["vpn.control".into(), "vpn.client".into()],
        DeploymentRole::Relay => vec!["vpn.relay".into(), "vpn.client".into()],
    }
}

async fn distribute_latest_config(
    publisher: &Arc<BusPublisher>,
    operator: &DeploymentNode,
    nodes: &[DeploymentNode],
    signing_key: &imperium_net_crypto::HybridSigningKey,
) {
    let mut fetch_sub = subscribe_queue(&publisher, "net.cluster.config.fetch_request", 64);

    for node in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        node.node.config.request_config(publisher).unwrap();
    }

    for _ in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        let fetch_event = tokio::time::timeout(Duration::from_millis(250), fetch_sub.recv())
            .await
            .expect("config fetch request")
            .unwrap();
        if let Message::ConfigFetchReq(req) = fetch_event.message {
            operator
                .node
                .config
                .handle_fetch_request(&req, signing_key, publisher)
                .unwrap();
        } else {
            panic!("expected ConfigFetchReq");
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn run_auto_cluster_deployment() -> AutoDeploymentReport {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    // A second handle onto the same kernel, for the strainer stack (the type is
    // not `Clone`, so it is minted from the kernel rather than cloned).
    let _strainer_publisher = bus.publisher();
    let cluster_id = ClusterId::new();
    let mut rng = OsRng;
    let (operator_sk, _operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    // NOTE: derive the operator VK once and clone it — each verifying_key()
    // call expands the ML-DSA key on the stack, and 7 separate derivations
    // in one frame overflow the test thread stack.
    let operator_vk = HybridEd25519Mldsa::verifying_key(&operator_sk);
    let token_manager = TokenManager::new(cluster_id.clone(), operator_vk.clone());

    let nodes = vec![
        DeploymentNode {
            role: DeploymentRole::Operator,
            port: 31_000,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new(), operator_vk.clone()),
        },
        DeploymentNode {
            role: DeploymentRole::Client,
            port: 31_001,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new(), operator_vk.clone()),
        },
        DeploymentNode {
            role: DeploymentRole::Client,
            port: 31_002,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new(), operator_vk.clone()),
        },
        DeploymentNode {
            role: DeploymentRole::Relay,
            port: 31_003,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new(), operator_vk.clone()),
        },
        DeploymentNode {
            role: DeploymentRole::Relay,
            port: 31_004,
            node: SimClusterNode::new(cluster_id.clone(), PeerId::new(), operator_vk.clone()),
        },
    ];

    for node in &nodes {
        ::imperium_net_cluster::attach_membership(&publisher, &node.node.membership);
        ::imperium_net_cluster::attach_config(&publisher, &node.node.config);
    }

    // Queue cluster and transport lanes BEFORE engaging. This composition does
    // not need its own orchestrator/hardening pair: its assertions read the
    // supervised strands only through published bus events, not through an
    // in-test controller or orchestrator object.
    ::imperium_net_cluster::register_strands(&mut bus, &publisher);
    let _ = ::imperium_net_transport::register_strands(&mut bus, &publisher);
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    let operator_index = nodes
        .iter()
        .position(|node| node.role == DeploymentRole::Operator)
        .unwrap();
    let operator_id = nodes[operator_index].node.id.clone();
    let mut gossip_sub = subscribe_queue(&publisher, "net.cluster.membership.gossip", 64);

    for node in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        let token =
            token_manager.mint_token(&operator_id, &operator_sk, chrono::Duration::minutes(15));
        token_manager.verify_token(&token).unwrap();
        nodes[operator_index]
            .node
            .membership
            .request_membership(node.node.id.clone(), &publisher)
            .unwrap();
        nodes[operator_index]
            .node
            .membership
            .approve_membership(&node.node.id, &operator_id, &operator_sk, &publisher)
            .unwrap();
        token_manager.consume_token(&token);
        assert!(token_manager.verify_token(&token).is_err());
    }

    for _ in nodes
        .iter()
        .filter(|node| node.role != DeploymentRole::Operator)
    {
        let gossip_event = tokio::time::timeout(Duration::from_millis(250), gossip_sub.recv())
            .await
            .expect("membership gossip")
            .unwrap();
        if let Message::MembershipGossip(gossip) = gossip_event.message {
            for node in &nodes {
                node.node.membership.apply_gossip(&gossip);
            }
        } else {
            panic!("expected MembershipGossip");
        }
    }
    // The grant and gossip delivery is asynchronous: the bus hands events to the
    // supervised membership strand inline, but the strand *applies* them on its
    // 10 ms tick, one manager at a time (it verifies each grant against each
    // manager's own operator key — the fail-closed path). Five simulated nodes on
    // one bus therefore converge in a few hundred milliseconds, not in the 50 ms
    // a fixed sleep used to assume, so wait for convergence with a hard deadline
    // instead of guessing a latency.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !nodes.iter().all(|node| {
        nodes
            .iter()
            .all(|candidate| node.node.membership.is_member(&candidate.node.id))
    }) {
        assert!(
            std::time::Instant::now() < deadline,
            "membership did not converge across all simulated nodes"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut report = AutoDeploymentReport {
        planned_nodes: nodes.len(),
        ..AutoDeploymentReport::default()
    };
    report.approved_nodes = nodes
        .iter()
        .filter(|node| {
            nodes
                .iter()
                .all(|candidate| node.node.membership.is_member(&candidate.node.id))
        })
        .count();

    let mut version_sub = subscribe_queue(&publisher, "net.cluster.config.updated", 64);
    report.config_version = nodes[operator_index]
        .node
        .config
        .update_config(
            br#"{"deployment":"auto","vpn":"imperium","profile":"fortress-rf-inspired","nat":"default","relay":"auto"}"#.to_vec(),
            &operator_sk,
            &publisher,
        )
        .unwrap();
    let version_event = tokio::time::timeout(Duration::from_millis(250), version_sub.recv())
        .await
        .expect("config version")
        .unwrap();
    if let Message::ConfigVersion(version) = version_event.message {
        assert_eq!(version.version, report.config_version);
        for node in nodes
            .iter()
            .filter(|node| node.role != DeploymentRole::Operator)
        {
            assert!(node.node.config.handle_version_announcement(&version));
        }
    } else {
        panic!("expected ConfigVersion");
    }

    distribute_latest_config(&publisher, &nodes[operator_index], &nodes, &operator_sk).await;

    for node in &nodes {
        assert_eq!(node.node.config.current_version(), report.config_version);
    }

    let grants = nodes
        .iter()
        .map(|node| IdentityCapabilityGrant {
            identity_id: node.node.id.clone(),
            capabilities: deployment_capabilities(node.role),
            issued_by: operator_id.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            signature: vec![node.port as u8],
        })
        .collect::<Vec<_>>();
    let access = AccessPolicy::new(grants);
    for node in &nodes {
        if !access.decide(&node.node.id, "vpn.shutdown").allowed {
            report.denied_shutdown_capabilities += 1;
        }
        match node.role {
            DeploymentRole::Operator => {
                assert!(access.decide(&node.node.id, "vpn.cluster.admin").allowed);
            }
            DeploymentRole::Client => {
                assert!(access.decide(&node.node.id, "vpn.control").allowed);
                assert!(!access.decide(&node.node.id, "vpn.relay").allowed);
            }
            DeploymentRole::Relay => {
                assert!(access.decide(&node.node.id, "vpn.relay").allowed);
            }
        }
    }

    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            let peer_id = nodes[j].node.id.clone();
            nodes[i]
                .node
                .peers
                .add_peer(peer_id.clone(), vec![nodes[j].node.endpoint(nodes[j].port)]);
        }
    }

    for node in &nodes {
        let default_plan = NatTraversalPlanner::build_probe_plan(
            node.node.id.clone(),
            &NatTraversalPlanner::default_policy(),
        );
        assert!(!default_plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        report.default_nat_plans += 1;

        let aggressive_plan = NatTraversalPlanner::build_probe_plan(
            node.node.id.clone(),
            &NatTraversalPlanner::aggressive_policy(),
        );
        assert!(aggressive_plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        report.aggressive_nat_plans += 1;
    }

    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            establish_mesh_session(
                &nodes[i].node,
                nodes[j].node.id.clone(),
                nodes[j].node.endpoint(nodes[j].port),
            );
        }
    }
    report.established_sessions = nodes
        .iter()
        .map(|node| node.node.sessions.active_session_count())
        .sum();

    let relay_ids = nodes
        .iter()
        .filter(|node| node.role == DeploymentRole::Relay)
        .map(|node| node.node.id.clone())
        .collect::<Vec<_>>();
    let client_ids = nodes
        .iter()
        .filter(|node| node.role == DeploymentRole::Client)
        .map(|node| node.node.id.clone())
        .collect::<Vec<_>>();

    let mut relay_selected_sub = subscribe_queue(&publisher, "net.mesh.relay.selected", 64);
    for (index, client_id) in client_ids.iter().enumerate() {
        BusEvent::publish(
            &publisher,
            "net.mesh.relay.selected",
            Message::RelayFallbackSelected(RelayFallbackSelected {
                peer_id: client_id.clone(),
                relay_peer: relay_ids[index % relay_ids.len()].clone(),
                selected_at: chrono::Utc::now(),
            }),
        )
        .unwrap();
    }
    for _ in &client_ids {
        let selected = tokio::time::timeout(Duration::from_millis(250), relay_selected_sub.recv())
            .await
            .expect("relay selected")
            .unwrap();
        assert!(matches!(
            selected.message,
            Message::RelayFallbackSelected(RelayFallbackSelected { .. })
        ));
        report.relay_fallbacks_selected += 1;
    }

    let mut hardening_status_sub =
        subscribe_queue(&publisher, "net.transport.hardening.status", 64);

    for node in &nodes {
        BusEvent::publish(
            &publisher,
            "net.transport.hardening.apply",
            Message::ProtocolHardeningProfile(ProtocolHardeningProfile {
                protocol_name: Some(format!("auto-vpn-{}", node.port)),
                reason: "auto cluster deployment".into(),
                ..HardeningController::fortress_profile(None)
            }),
        )
        .unwrap();
        let status = tokio::time::timeout(Duration::from_millis(250), hardening_status_sub.recv())
            .await
            .expect("hardening status")
            .unwrap();
        assert!(matches!(
            status.message,
            Message::ProtocolHardeningStatus(status) if status.accepted
        ));
        report.hardening_profiles_accepted += 1;
    }

    supervision.shutdown();
    report
}

#[test]
fn auto_vpn_cluster_deployment_converges_all_nodes() {
    // NOTE: ML-DSA-65 sign/verify frames are large (~8KB+ each, nested
    // several deep during grant/config verification). The default 2 MiB
    // test stack overflows; 64 MiB matches the precedent in imperium-cli
    // operator_key tests and imperium-net-sensors signature_engine tests.
    let report = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_auto_cluster_deployment())
        })
        .unwrap()
        .join()
        .unwrap();

    assert_eq!(report.planned_nodes, 5);
    assert_eq!(report.approved_nodes, report.planned_nodes);
    assert_eq!(report.config_version, 1);
    assert_eq!(report.denied_shutdown_capabilities, report.planned_nodes);
    assert_eq!(report.default_nat_plans, report.planned_nodes);
    assert_eq!(report.aggressive_nat_plans, report.planned_nodes);
    assert_eq!(
        report.established_sessions,
        report.planned_nodes * (report.planned_nodes - 1)
    );
    assert_eq!(report.relay_fallbacks_selected, 2);
    assert_eq!(report.hardening_profiles_accepted, report.planned_nodes);
}

#[tokio::test]
async fn cluster_vpn_three_peer_control_and_relay_simulation_holds() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let cluster_id = ClusterId::new();
    let operator_id = PeerId::new();
    let mobile_id = PeerId::new();
    let relay_id = PeerId::new();

    let mut rng = OsRng;
    let (operator_sk, _operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
    // NOTE: single VK derivation, cloned — see stack note above.
    let sim_vk = HybridEd25519Mldsa::verifying_key(&operator_sk);

    let operator = SimClusterNode::new(cluster_id.clone(), operator_id.clone(), sim_vk.clone());
    let mobile = SimClusterNode::new(cluster_id.clone(), mobile_id.clone(), sim_vk.clone());
    let relay = SimClusterNode::new(cluster_id.clone(), relay_id.clone(), sim_vk.clone());

    ::imperium_net_cluster::attach_membership(&publisher, &operator.membership);
    ::imperium_net_cluster::attach_membership(&publisher, &mobile.membership);
    ::imperium_net_cluster::attach_membership(&publisher, &relay.membership);
    ::imperium_net_cluster::attach_config(&publisher, &mobile.config);
    ::imperium_net_cluster::attach_config(&publisher, &relay.config);

    // Supervised strands: queue every lane's spec first — the membership and
    // config loops above, the transport orchestrator's two lanes, and the
    // hardening lane — then engage once (see `hardening_simulation.rs`).
    let orchestrator = Arc::new(Orchestrator::new(
        OrchestratorConfig {
            active_protocol: "xray-direct".into(),
            standby_protocol: "masque-relay".into(),
            policy: OrchestratorPolicy::default(),
        },
        Arc::clone(&publisher),
    ));
    // The orchestrator lanes are queued by `imperium_net_transport::register_strands`.
    // lanes are queued by `imperium_net_transport::register_strands`
    let hardening = Arc::new(HardeningController::new(Arc::clone(&publisher)));
    // Queue the cluster membership/config lanes and the transport lanes for
    // the concrete orchestrator/hardening instance this test observes.
    // attach_* only wires managers; the applying strands come from these
    // specs. Do not call the default `register_strands` here: it would build
    // a second orchestrator/hardening pair and this test would observe the
    // wrong objects.
    ::imperium_net_cluster::register_strands(&mut bus, &publisher);
    hardening.register_strand(&mut bus, &publisher);
    queue_lanes(
        &mut bus,
        &publisher,
        &orchestrator,
        ::imperium_net_transport::strand::FaultPolicy::from_env(),
    );
    let _supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    let mut decision_sub = subscribe_queue(&publisher, "net.transport.decision", 64);

    let token_manager = TokenManager::new(cluster_id.clone(), sim_vk);
    let token = token_manager.mint_token(&operator_id, &operator_sk, chrono::Duration::minutes(30));
    assert!(token_manager.verify_token(&token).is_ok());

    let mut gossip_sub = subscribe_queue(&publisher, "net.cluster.membership.gossip", 64);

    operator
        .membership
        .request_membership(mobile_id.clone(), &publisher)
        .unwrap();
    operator
        .membership
        .approve_membership(&mobile_id, &operator_id, &operator_sk, &publisher)
        .unwrap();
    let first_gossip = tokio::time::timeout(Duration::from_millis(250), gossip_sub.recv())
        .await
        .expect("first membership gossip")
        .unwrap();

    operator
        .membership
        .request_membership(relay_id.clone(), &publisher)
        .unwrap();
    operator
        .membership
        .approve_membership(&relay_id, &operator_id, &operator_sk, &publisher)
        .unwrap();
    let second_gossip = tokio::time::timeout(Duration::from_millis(250), gossip_sub.recv())
        .await
        .expect("second membership gossip")
        .unwrap();

    for event in [first_gossip, second_gossip] {
        if let Message::MembershipGossip(gossip) = event.message {
            operator.membership.apply_gossip(&gossip);
            mobile.membership.apply_gossip(&gossip);
            relay.membership.apply_gossip(&gossip);
        } else {
            panic!("expected membership gossip");
        }
    }
    // Convergence wait: the grants reach their nodes through the supervised
    // membership strand, which verifies and applies them on its 10 ms tick (see
    // the note in the deployment test), so a fixed sleep would be a race.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let all_members = || {
        [&operator, &mobile, &relay].iter().all(|node| {
            [&operator_id, &mobile_id, &relay_id]
                .iter()
                .all(|id| node.membership.is_member(id))
        })
    };
    while !all_members() {
        assert!(
            std::time::Instant::now() < deadline,
            "membership did not converge across the three simulated nodes"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    for node in [&operator, &mobile, &relay] {
        assert!(node.membership.is_member(&operator_id));
        assert!(node.membership.is_member(&mobile_id));
        assert!(node.membership.is_member(&relay_id));
        assert_eq!(node.membership.member_count(), 3);
    }

    let mut version_sub = subscribe_queue(&publisher, "net.cluster.config.updated", 64);
    let mut fetch_sub = subscribe_queue(&publisher, "net.cluster.config.fetch_request", 64);
    let version = operator
        .config
        .update_config(
            br#"{"vpn":"imperium","profile":"fortress-rf-inspired","relay":"required"}"#.to_vec(),
            &operator_sk,
            &publisher,
        )
        .unwrap();
    assert_eq!(version, 1);

    let version_event = tokio::time::timeout(Duration::from_millis(250), version_sub.recv())
        .await
        .expect("config version")
        .unwrap();
    let version_msg = match version_event.message {
        Message::ConfigVersion(version) => version,
        other => panic!("expected ConfigVersion, got {other:?}"),
    };
    assert!(mobile.config.handle_version_announcement(&version_msg));
    mobile.config.request_config(&publisher).unwrap();

    let fetch_event = tokio::time::timeout(Duration::from_millis(250), fetch_sub.recv())
        .await
        .expect("fetch request")
        .unwrap();
    if let Message::ConfigFetchReq(req) = fetch_event.message {
        operator
            .config
            .handle_fetch_request(&req, &operator_sk, &publisher)
            .unwrap();
    } else {
        panic!("expected ConfigFetchReq");
    }
    // Same convergence wait for the config loop: the fetch response is applied by
    // the supervised config strand, on its tick.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !(mobile.config.current_version() == 1 && relay.config.current_version() == 1) {
        assert!(
            std::time::Instant::now() < deadline,
            "the fetched config did not reach both simulated nodes"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(mobile.config.current_version(), 1);
    assert_eq!(relay.config.current_version(), 1);

    let access = AccessPolicy::new(vec![
        IdentityCapabilityGrant {
            identity_id: mobile_id.clone(),
            capabilities: vec!["vpn.control".into(), "vpn.hardening.apply".into()],
            issued_by: operator_id.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            signature: vec![1, 2, 3],
        },
        IdentityCapabilityGrant {
            identity_id: relay_id.clone(),
            capabilities: vec!["vpn.relay".into()],
            issued_by: operator_id.clone(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            signature: vec![4, 5, 6],
        },
    ]);
    assert!(access.decide(&mobile_id, "vpn.control").allowed);
    assert!(access.decide(&mobile_id, "vpn.hardening.apply").allowed);
    assert!(!access.decide(&mobile_id, "vpn.shutdown").allowed);
    assert!(access.decide(&relay_id, "vpn.relay").allowed);

    operator
        .peers
        .add_peer(mobile_id.clone(), vec![mobile.endpoint(30_001)]);
    operator
        .peers
        .add_peer(relay_id.clone(), vec![relay.endpoint(30_002)]);
    mobile
        .peers
        .add_peer(operator_id.clone(), vec![operator.endpoint(30_000)]);
    mobile
        .peers
        .add_peer(relay_id.clone(), vec![relay.endpoint(30_002)]);
    relay
        .peers
        .add_peer(operator_id.clone(), vec![operator.endpoint(30_000)]);
    relay
        .peers
        .add_peer(mobile_id.clone(), vec![mobile.endpoint(30_001)]);

    establish_mesh_session(&operator, mobile_id.clone(), mobile.endpoint(30_001));
    establish_mesh_session(&operator, relay_id.clone(), relay.endpoint(30_002));
    establish_mesh_session(&mobile, operator_id.clone(), operator.endpoint(30_000));
    establish_mesh_session(&mobile, relay_id.clone(), relay.endpoint(30_002));
    establish_mesh_session(&relay, operator_id.clone(), operator.endpoint(30_000));
    establish_mesh_session(&relay, mobile_id.clone(), mobile.endpoint(30_001));

    assert_eq!(operator.sessions.active_session_count(), 2);
    assert_eq!(mobile.sessions.active_session_count(), 2);
    assert_eq!(relay.sessions.active_session_count(), 2);
    assert_eq!(
        operator.peers.get_state(&mobile_id),
        Some(PeerState::Connected)
    );
    assert_eq!(
        mobile.peers.get_state(&relay_id),
        Some(PeerState::Connected)
    );

    let default_plan = NatTraversalPlanner::build_probe_plan(
        mobile_id.clone(),
        &NatTraversalPlanner::default_policy(),
    );
    assert_eq!(default_plan.estimated_probe_count, 32);
    assert!(default_plan.relay_fallback_enabled);
    assert!(!default_plan
        .modes
        .iter()
        .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));

    let mut relay_request_sub = subscribe_queue(&publisher, "net.mesh.relay.request", 64);
    let mut relay_selected_sub = subscribe_queue(&publisher, "net.mesh.relay.selected", 64);
    BusEvent::publish(
        &publisher,
        "net.mesh.relay.request",
        Message::RelayFallbackRequest(RelayFallbackRequest {
            peer_id: mobile_id.clone(),
            reason: "default NAT traversal exhausted direct UDP/STUN/coordinated probes".into(),
            requested_at: chrono::Utc::now(),
        }),
    )
    .unwrap();
    let relay_request = tokio::time::timeout(Duration::from_millis(250), relay_request_sub.recv())
        .await
        .expect("relay request")
        .unwrap();
    assert!(matches!(
        relay_request.message,
        Message::RelayFallbackRequest(RelayFallbackRequest { .. })
    ));
    BusEvent::publish(
        &publisher,
        "net.mesh.relay.selected",
        Message::RelayFallbackSelected(RelayFallbackSelected {
            peer_id: mobile_id.clone(),
            relay_peer: relay_id.clone(),
            selected_at: chrono::Utc::now(),
        }),
    )
    .unwrap();
    let relay_selected =
        tokio::time::timeout(Duration::from_millis(250), relay_selected_sub.recv())
            .await
            .expect("relay selected")
            .unwrap();
    if let Message::RelayFallbackSelected(selected) = relay_selected.message {
        assert_eq!(selected.peer_id, mobile_id);
        assert_eq!(selected.relay_peer, relay_id);
    } else {
        panic!("expected RelayFallbackSelected");
    }

    let mut hardening_status_sub =
        subscribe_queue(&publisher, "net.transport.hardening.status", 64);
    BusEvent::publish(
        &publisher,
        "net.transport.hardening.apply",
        Message::ProtocolHardeningProfile(ProtocolHardeningProfile {
            reason: "cluster relay path selected".into(),
            ..HardeningController::fortress_profile(Some("cluster-vpn".into()))
        }),
    )
    .unwrap();
    let hardening_status =
        tokio::time::timeout(Duration::from_millis(250), hardening_status_sub.recv())
            .await
            .expect("hardening status")
            .unwrap();
    assert!(matches!(
        hardening_status.message,
        Message::ProtocolHardeningStatus(status)
            if status.accepted && status.profile_id == "fortress-rf-inspired"
    ));
    assert_eq!(
        hardening.active_profile().unwrap().protocol_name.as_deref(),
        Some("cluster-vpn")
    );

    BusEvent::publish(
        &publisher,
        "net.sensors.threat",
        Message::ThreatAssessment(ThreatAssessment {
            source: ThreatSource::Heuristic {
                name: "cluster-path-burn".into(),
            },
            confidence: 0.91,
            description: "direct path fingerprint pressure during relay fallback".into(),
            remote_addr: Some(operator.endpoint(30_000)),
            timestamp: chrono::Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        }),
    )
    .unwrap();
    let promote = tokio::time::timeout(Duration::from_millis(250), decision_sub.recv())
        .await
        .expect("promote decision")
        .unwrap();
    assert!(matches!(
        promote.message,
        Message::OrchestratorDecision(OrchestratorDecision::PromoteStandby { protocol_name })
            if protocol_name == "masque-relay"
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orchestrator.state(), OrchestratorState::Healing);
    assert_eq!(orchestrator.active_protocol(), "masque-relay");

    BusEvent::publish(
        &publisher,
        "net.transport.event",
        Message::ProtocolEvt(ProtocolEvent {
            protocol_name: "xray-direct".into(),
            role: ProtocolRole::Quarantined,
            status: ProtocolStatus::Running,
            event: ProtocolEventKind::HealingSucceeded,
            timestamp: chrono::Utc::now(),
        }),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(orchestrator.state(), OrchestratorState::Steady);

    let path_metrics = PathMetrics {
        path_id: "mobile->relay->operator".into(),
        rtt_ms: 42,
        jitter_ms: 7,
        loss_ppm: 1_000,
        burn_score: 0.02,
        handshake_success_ppm: 995_000,
        relay_required: true,
        observed_at: chrono::Utc::now(),
    };
    assert!(path_metrics.relay_required);
    assert_eq!(path_metrics.path_id, "mobile->relay->operator");
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
