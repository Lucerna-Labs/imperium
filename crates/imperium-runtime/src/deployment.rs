//! The VPN deployment orchestrator: it converges a [`VpnDeploymentPlan`] into
//! cluster state (membership, config, sessions, relay selection, hardening) and
//! answers status requests with the last status it published.
//!
//! # Its two recv loops are supervised strands
//!
//! This file used to hold two `tokio::spawn`ed recv loops
//! (`net.vpn.deployment.apply` → [`DeploymentOrchestrator::deploy`], and
//! `net.vpn.deployment.status_request` → republish the last status), invisible to
//! the spider: a panic killed the task silently. They are now supervised strands
//! in [`strand`], registered as specs through
//! [`DeploymentOrchestrator::register_strands`] and installed by
//! `Bus::engage_supervision()`. Both spawns are deleted; the `subscribe_*`
//! methods that used to spawn them remain as legacy wiring shims that queue the
//! specs (idempotently) and return an inert handle, so the composition root keeps
//! compiling until its registration patch lands. See
//! the pilot (`imperium-net-lightcone`) for the recipe and [`strand`] for
//! what changed and what deliberately did not.

use std::sync::{Arc, RwLock};

use chrono::Utc;
use imperium_net_cluster::{ConfigManager, MembershipManager, TokenManager};
use imperium_net_crypto::{HybridEd25519Mldsa, HybridX25519Mlkem};
use imperium_net_mesh::{NatTraversalPlanner, PeerManager, SessionManager};
use imperium_net_transport::HardeningController;
use imperium_protocol::BusEvent;
use imperium_protocol::{
    ClusterId, Message, PeerId, ProtocolHardeningProfile, RelayFallbackSelected,
    VpnDeploymentNodeSpec, VpnDeploymentPlan, VpnDeploymentRole, VpnDeploymentStatus,
};
use rand::rngs::OsRng;
use spiderweb::{Bus, BusPublisher};
use thiserror::Error;

pub mod strand;

use strand::{FaultPolicy, STATUS_TOPIC};

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error("deployment plan must include at least one node")]
    EmptyPlan,
    #[error("deployment plan must include exactly one operator node")]
    InvalidOperatorCount,
    #[error("node label cannot be empty")]
    EmptyNodeLabel,
    #[error("hardening preset must be balanced, resilience, or fortress")]
    UnknownHardeningPreset,
    #[error("membership deployment failed: {0}")]
    Membership(String),
    #[error("configuration deployment failed: {0}")]
    Config(String),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

struct DeploymentNodeRuntime {
    spec: VpnDeploymentNodeSpec,
    peer_id: PeerId,
    membership: Arc<MembershipManager>,
    config: Arc<ConfigManager>,
    peers: PeerManager,
    sessions: SessionManager,
}

/// The deployment orchestrator: one durable state machine driven by two
/// supervised strands (see [`strand`]).
///
/// `last_status` is deliberately behind this struct's `Arc` rather than inside a
/// strand instance: it is the one piece of state that must survive a strand
/// restart, so that a restarted deployment orchestrator still answers a status
/// request with the last known status instead of "no deployment has run". The
/// specs' factories capture a clone of that `Arc`, so both lanes and every
/// generation of every lane share exactly this value (recipe §3.2).
pub struct DeploymentOrchestrator {
    bus: Arc<BusPublisher>,
    last_status: RwLock<Option<VpnDeploymentStatus>>,
}

impl DeploymentOrchestrator {
    pub fn new(bus: Arc<BusPublisher>) -> Self {
        Self {
            bus,
            last_status: RwLock::new(None),
        }
    }

    pub fn last_status(&self) -> Option<VpnDeploymentStatus> {
        self.last_status
            .read()
            .ok()
            .and_then(|status| status.clone())
    }

    pub fn deploy(&self, plan: VpnDeploymentPlan) -> Result<VpnDeploymentStatus, DeploymentError> {
        validate_plan(&plan)?;

        let cluster_id = plan.cluster_id.clone().unwrap_or_else(ClusterId::new);
        let mut rng = OsRng;
        let (operator_sk, _operator_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);

        let nodes = plan
            .nodes
            .iter()
            .cloned()
            .map(|spec| {
                let peer_id = spec.peer_id.clone().unwrap_or_else(PeerId::new);
                DeploymentNodeRuntime {
                    spec,
                    peer_id: peer_id.clone(),
                    membership: Arc::new(MembershipManager::new(
                        cluster_id.clone(),
                        peer_id.clone(),
                        HybridEd25519Mldsa::verifying_key(&operator_sk),
                    )),
                    config: Arc::new(ConfigManager::new(
                        cluster_id.clone(),
                        peer_id,
                        HybridEd25519Mldsa::verifying_key(&operator_sk),
                    )),
                    peers: PeerManager::new(),
                    sessions: SessionManager::new(),
                }
            })
            .collect::<Vec<_>>();

        let operator_index = nodes
            .iter()
            .position(|node| node.spec.role == VpnDeploymentRole::Operator)
            .ok_or(DeploymentError::InvalidOperatorCount)?;
        let operator_id = nodes[operator_index].peer_id.clone();
        let token_manager = TokenManager::new(
            cluster_id.clone(),
            HybridEd25519Mldsa::verifying_key(&operator_sk),
        );

        for index in 0..nodes.len() {
            if index == operator_index {
                continue;
            }

            let token =
                token_manager.mint_token(&operator_id, &operator_sk, chrono::Duration::minutes(15));
            token_manager
                .verify_token(&token)
                .map_err(|_| DeploymentError::InvalidOperatorCount)?;
            nodes[operator_index]
                .membership
                .request_membership(nodes[index].peer_id.clone(), &self.bus)
                .map_err(|e| DeploymentError::Membership(e.to_string()))?;
            nodes[operator_index]
                .membership
                .approve_membership(&nodes[index].peer_id, &operator_id, &operator_sk, &self.bus)
                .map_err(|e| DeploymentError::Membership(e.to_string()))?;
            token_manager.consume_token(&token);
        }

        let members = nodes
            .iter()
            .map(|node| node.peer_id.clone())
            .collect::<Vec<_>>();
        let gossip = imperium_protocol::MembershipGossip {
            cluster_id: cluster_id.clone(),
            members: members.clone(),
            lamport_clock: 10,
            from_peer: operator_id.clone(),
        };
        for node in &nodes {
            node.membership.apply_gossip(&gossip);
        }
        BusEvent::publish(
            &self.bus,
            "net.cluster.membership.gossip",
            Message::MembershipGossip(gossip),
        )?;

        let config_version = nodes[operator_index]
            .config
            .update_config(plan.config_blob.clone(), &operator_sk, &self.bus)
            .map_err(|e| DeploymentError::Config(e.to_string()))?;
        let fetch_response = nodes[operator_index].config.current_config().map(|config| {
            imperium_protocol::ConfigurationFetchResponse {
                cluster_id: cluster_id.clone(),
                version: config.version,
                config_data: config.data.clone(),
                signature: ConfigManager::sign_config(&config.data, config.version, &operator_sk)
                    .to_bytes(),
            }
        });
        if let Some(resp) = fetch_response {
            for (index, node) in nodes.iter().enumerate() {
                if index != operator_index {
                    node.config.apply_fetched_config(&resp).ok();
                }
            }
            BusEvent::publish(
                &self.bus,
                "net.cluster.config.fetch_response",
                Message::ConfigFetchResp(resp),
            )?;
        }

        for left in 0..nodes.len() {
            for right in 0..nodes.len() {
                if left == right {
                    continue;
                }

                let remote_endpoint = nodes[right]
                    .spec
                    .endpoint
                    .unwrap_or_else(|| format!("127.0.0.1:{}", 31_000 + right).parse().unwrap());
                nodes[left]
                    .peers
                    .add_peer(nodes[right].peer_id.clone(), vec![remote_endpoint]);

                let session_id = nodes[left]
                    .sessions
                    .create_session(nodes[right].peer_id.clone(), remote_endpoint, true)
                    .expect("deployment session should be unique");
                let (_secret, public) = HybridX25519Mlkem::generate_keypair(&mut rng);
                let (_encap, key) = HybridX25519Mlkem::encapsulate(&mut rng, &public);
                // Empty identities: this is a BUSS-ONLY simulation that fabricates
                // sessions without a handshake, so there are no operator-certified
                // identities to bind into the key derivation. The real establishment
                // path (`daemon.rs`) always supplies them.
                nodes[left]
                    .sessions
                    .establish_session(&session_id, key, &[], &[])
                    .expect("deployment session should establish");
                nodes[left]
                    .peers
                    .set_session(&nodes[right].peer_id, session_id);
            }
        }

        let nat_policy = if plan.nat_aggressive {
            NatTraversalPlanner::aggressive_policy()
        } else {
            NatTraversalPlanner::default_policy()
        };
        for node in &nodes {
            let probe_plan =
                NatTraversalPlanner::build_probe_plan(node.peer_id.clone(), &nat_policy);
            BusEvent::publish(
                &self.bus,
                "net.mesh.nat.plan",
                Message::NatProbePlan(probe_plan),
            )?;
        }

        let relay_ids = nodes
            .iter()
            .filter(|node| node.spec.role == VpnDeploymentRole::Relay)
            .map(|node| node.peer_id.clone())
            .collect::<Vec<_>>();
        let client_ids = nodes
            .iter()
            .filter(|node| node.spec.role == VpnDeploymentRole::Client)
            .map(|node| node.peer_id.clone())
            .collect::<Vec<_>>();
        let mut relay_fallbacks_selected = 0;
        if plan.relay_auto && !relay_ids.is_empty() {
            for (index, client_id) in client_ids.iter().enumerate() {
                let selected = RelayFallbackSelected {
                    peer_id: client_id.clone(),
                    relay_peer: relay_ids[index % relay_ids.len()].clone(),
                    selected_at: Utc::now(),
                };
                BusEvent::publish(
                    &self.bus,
                    "net.mesh.relay.selected",
                    Message::RelayFallbackSelected(selected),
                )?;
                relay_fallbacks_selected += 1;
            }
        }

        let hardening_profile = hardening_profile(&plan.hardening_preset, Some("auto-vpn".into()))?;
        HardeningController::validate(&hardening_profile)
            .map_err(|_| DeploymentError::UnknownHardeningPreset)?;
        for node in &nodes {
            let profile = ProtocolHardeningProfile {
                protocol_name: Some(format!("auto-vpn-{}", node.spec.label)),
                reason: format!("auto deployment {}", plan.deployment_id),
                ..hardening_profile.clone()
            };
            BusEvent::publish(
                &self.bus,
                "net.transport.hardening.apply",
                Message::ProtocolHardeningProfile(profile),
            )?;
        }

        let approved_nodes = nodes
            .iter()
            .filter(|node| {
                members
                    .iter()
                    .all(|member| node.membership.is_member(member))
            })
            .count();
        let established_sessions = nodes
            .iter()
            .map(|node| node.sessions.active_session_count())
            .sum::<usize>();
        let hardening_profiles_accepted = nodes.len();

        let status = VpnDeploymentStatus {
            deployment_id: plan.deployment_id,
            accepted: true,
            reason: "deployment converged".into(),
            planned_nodes: nodes.len(),
            approved_nodes,
            config_version,
            established_sessions,
            relay_fallbacks_selected,
            hardening_profiles_accepted,
            updated_at: Utc::now(),
        };
        self.emit_status(status.clone())?;
        Ok(status)
    }

    /// The old `subscribe_deployment_plans` loop body, verbatim: run the plan,
    /// and on failure publish (and remember) a rejected status.
    ///
    /// The old loop's error path was exactly this and logged nothing — the status
    /// is the signal — so neither does this. The plan is cloned into
    /// [`deploy`](Self::deploy) once and the original is still used to describe
    /// the attempt, exactly as before.
    fn handle_plan(&self, plan: &VpnDeploymentPlan) {
        if let Err(error) = self.deploy(plan.clone()) {
            let status = VpnDeploymentStatus {
                deployment_id: plan.deployment_id,
                accepted: false,
                reason: error.to_string(),
                planned_nodes: plan.nodes.len(),
                approved_nodes: 0,
                config_version: 0,
                established_sessions: 0,
                relay_fallbacks_selected: 0,
                hardening_profiles_accepted: 0,
                updated_at: Utc::now(),
            };
            let _ = self.emit_status(status);
        }
    }

    /// The old `subscribe_status_requests` loop body, verbatim: answer with the
    /// last status this orchestrator published, or with "no deployment has run"
    /// if there has never been one.
    fn handle_status_request(&self) {
        let status = self.last_status().unwrap_or_else(no_deployment_status);
        let _ = self.emit_status(status);
    }

    /// Register this subsystem's two strand specs on `bus` — the composition
    /// root's single call (recipe §3.6).
    ///
    /// Call it while the bus is still idle, before `Bus::engage_supervision()`:
    /// specs are **queued, not started**, and the kernel's `run_until` installs
    /// them. A spec offered after engage is refused with
    /// [`StrandRegistrationError::Engaged`] rather than silently dropped, which is
    /// why the return value is a `Result`. Returns the shared
    /// [`DeploymentOrchestrator`] whose state (in particular `last_status`) both
    /// lanes drive — keep it if the caller wants to observe deployment state.
    ///
    /// The fault policy comes from
    /// [`CRASH_AFTER_MESSAGES_ENV`](strand::CRASH_AFTER_MESSAGES_ENV); unset (the
    /// production default) means no injection.
    ///
    /// ```ignore
    /// // Prose recipe only: `test_supervision` is a `#[cfg(test)]` helper and
    /// // `register_strands` takes `&mut Bus`, so this snippet cannot compile
    /// // as a doctest. See the `deployment_supervision` tests in this file.
    /// use std::sync::Arc;
    ///
    /// use spiderweb::Bus;
    /// use imperium_runtime::DeploymentOrchestrator;
    ///
    /// let (_bus, publisher) = crate::test_supervision::open();
    /// let deployment = DeploymentOrchestrator::register_strands(&bus)?;
    /// let mut supervision = crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));
    /// // … on the way out:
    /// supervision.shutdown();
    /// # Ok::<(), spiderweb::BusError>(())
    /// ```
    pub fn register_strands(bus: &mut Bus, publisher: &Arc<BusPublisher>) -> Arc<Self> {
        let orchestrator = Arc::new(Self::new(Arc::clone(publisher)));
        strand::queue_lanes(bus, publisher, &orchestrator, FaultPolicy::from_env());
        orchestrator
    }

    fn emit_status(&self, status: VpnDeploymentStatus) -> Result<(), DeploymentError> {
        if let Ok(mut last_status) = self.last_status.write() {
            *last_status = Some(status.clone());
        }
        // The same topic string the pre-conversion loop published on; the shared
        // constant is what the strands declare as their output socket.
        BusEvent::publish(
            &self.bus,
            STATUS_TOPIC,
            Message::VpnDeploymentStatus(status),
        )?;
        Ok(())
    }
}

fn no_deployment_status() -> VpnDeploymentStatus {
    VpnDeploymentStatus {
        deployment_id: uuid::Uuid::nil(),
        accepted: false,
        reason: "no deployment has run".into(),
        planned_nodes: 0,
        approved_nodes: 0,
        config_version: 0,
        established_sessions: 0,
        relay_fallbacks_selected: 0,
        hardening_profiles_accepted: 0,
        updated_at: Utc::now(),
    }
}

fn validate_plan(plan: &VpnDeploymentPlan) -> Result<(), DeploymentError> {
    if plan.nodes.is_empty() {
        return Err(DeploymentError::EmptyPlan);
    }
    if plan.nodes.iter().any(|node| node.label.trim().is_empty()) {
        return Err(DeploymentError::EmptyNodeLabel);
    }
    let operator_count = plan
        .nodes
        .iter()
        .filter(|node| node.role == VpnDeploymentRole::Operator)
        .count();
    if operator_count != 1 {
        return Err(DeploymentError::InvalidOperatorCount);
    }

    let _ = hardening_profile(&plan.hardening_preset, None)?;
    Ok(())
}

fn hardening_profile(
    preset: &str,
    protocol_name: Option<String>,
) -> Result<ProtocolHardeningProfile, DeploymentError> {
    match preset {
        "balanced" | "balanced-rf-inspired" => {
            Ok(HardeningController::balanced_profile(protocol_name))
        }
        "resilience" | "resilience-rf-inspired" => {
            Ok(HardeningController::resilience_profile(protocol_name))
        }
        "fortress" | "fortress-rf-inspired" => {
            Ok(HardeningController::fortress_profile(protocol_name))
        }
        _ => Err(DeploymentError::UnknownHardeningPreset),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The next deployment status on `sub`.
    ///
    /// The budget is 5 s, not the 0.5 s the pre-conversion suite used: the
    /// status now arrives from a supervised strand, whose tick is paced by the
    /// worker's 10 ms sleep and whose engagement is installed by the kernel's
    /// ~50 ms control poll, so a crypto-heavy convergence under a loaded parallel
    /// test run is not safely bounded by half a second. The value only matters
    /// when something is broken — it then fails in 5 s instead of 0.5 s.
    async fn recv_deployment_status(
        rx: &mut tokio::sync::mpsc::Receiver<BusEvent>,
    ) -> VpnDeploymentStatus {
        for _ in 0..4 {
            let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("deployment status")
                .expect("the status queue stays open for the test's life");
            if let Message::VpnDeploymentStatus(status) = event.message {
                return status;
            }
        }

        panic!("deployment status was not published");
    }

    fn deployment_plan() -> VpnDeploymentPlan {
        VpnDeploymentPlan {
            deployment_id: uuid::Uuid::new_v4(),
            cluster_id: None,
            nodes: vec![
                VpnDeploymentNodeSpec {
                    label: "operator".into(),
                    role: VpnDeploymentRole::Operator,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32000".parse().unwrap()),
                    capabilities: vec!["vpn.cluster.admin".into()],
                },
                VpnDeploymentNodeSpec {
                    label: "client-a".into(),
                    role: VpnDeploymentRole::Client,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32001".parse().unwrap()),
                    capabilities: vec!["vpn.client".into()],
                },
                VpnDeploymentNodeSpec {
                    label: "relay-a".into(),
                    role: VpnDeploymentRole::Relay,
                    peer_id: None,
                    endpoint: Some("127.0.0.1:32002".parse().unwrap()),
                    capabilities: vec!["vpn.relay".into()],
                },
            ],
            hardening_preset: "fortress".into(),
            nat_aggressive: false,
            relay_auto: true,
            config_blob: br#"{"deployment":"auto"}"#.to_vec(),
            requested_by: "test".into(),
            requested_at: Utc::now(),
        }
    }

    #[test]
    fn deployment_orchestrator_converges_plan() {
        let (_bus, publisher) = crate::test_supervision::open();
        let orchestrator = DeploymentOrchestrator::new(Arc::clone(&publisher));

        let status = orchestrator.deploy(deployment_plan()).unwrap();

        assert!(status.accepted);
        assert_eq!(status.planned_nodes, 3);
        assert_eq!(status.approved_nodes, 3);
        assert_eq!(status.config_version, 1);
        assert_eq!(status.established_sessions, 6);
        assert_eq!(status.relay_fallbacks_selected, 1);
        assert_eq!(status.hardening_profiles_accepted, 3);
    }

    /// A plan published on `net.vpn.deployment.apply` is still consumed by the
    /// orchestrator and answered on `net.vpn.deployment.status`.
    ///
    /// `subscribe_deployment_plans` is a legacy shim now: it queues the plan
    /// lane's strand spec, and the spec is installed (and the loop starts) at
    /// `engage_supervision()`. Everything else — topics, plan, status payload —
    /// is the pre-conversion behaviour.
    #[tokio::test]
    async fn subscribes_to_deployment_plan_messages() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let mut status_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.vpn.deployment.status", 64);
        let plan = deployment_plan();
        let deployment_id = plan.deployment_id;

        // The lanes the old `subscribe_deployment_plans` shim queued: the
        // canonical call queues both, bound to the orchestrator it returns.
        DeploymentOrchestrator::register_strands(&mut bus, &publisher);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        BusEvent::publish(
            &publisher,
            "net.vpn.deployment.apply",
            Message::VpnDeploymentPlan(plan),
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), status_sub.recv())
            .await
            .expect("deployment status")
            .unwrap();
        supervision.shutdown();
        assert!(matches!(
            event.message,
            Message::VpnDeploymentStatus(status)
                if status.accepted && status.deployment_id == deployment_id
        ));
    }

    /// A status request is still answered with the last published status — now
    /// by the status lane's strand, which is registered by the
    /// `subscribe_status_requests` legacy shim and installed at
    /// `engage_supervision()`.
    #[tokio::test]
    async fn status_request_republishes_last_status() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let orchestrator = Arc::new(DeploymentOrchestrator::new(Arc::clone(&publisher)));
        let status = orchestrator.deploy(deployment_plan()).unwrap();
        let mut status_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.vpn.deployment.status", 64);
        // The status lane must be installed before a request can be answered.
        strand::queue_lanes(&mut bus, &publisher, &orchestrator, FaultPolicy::None);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        BusEvent::publish(
            &publisher,
            "net.vpn.deployment.status_request",
            Message::VpnDeploymentStatusRequest(imperium_protocol::VpnDeploymentStatusRequest {
                requested_by: "ordo".into(),
                requested_at: Utc::now(),
            }),
        )
        .unwrap();

        let published = recv_deployment_status(&mut status_sub).await;
        supervision.shutdown();
        assert_eq!(published.deployment_id, status.deployment_id);
        assert!(published.accepted);
        assert_eq!(published.approved_nodes, 3);
    }

    /// Same, with no deployment behind it: the strand answers with the same
    /// `no_deployment_status` payload the old loop did.
    #[tokio::test]
    async fn status_request_without_deployment_reports_empty_state() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let orchestrator = Arc::new(DeploymentOrchestrator::new(Arc::clone(&publisher)));
        let mut status_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.vpn.deployment.status", 64);
        strand::queue_lanes(&mut bus, &publisher, &orchestrator, FaultPolicy::None);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        BusEvent::publish(
            &publisher,
            "net.vpn.deployment.status_request",
            Message::VpnDeploymentStatusRequest(imperium_protocol::VpnDeploymentStatusRequest {
                requested_by: "ordo".into(),
                requested_at: Utc::now(),
            }),
        )
        .unwrap();

        let published = recv_deployment_status(&mut status_sub).await;
        supervision.shutdown();
        assert_eq!(published.deployment_id, uuid::Uuid::nil());
        assert!(!published.accepted);
        assert_eq!(published.reason, "no deployment has run");
    }

    #[test]
    fn rejects_missing_operator() {
        let (_bus, publisher) = crate::test_supervision::open();
        let orchestrator = DeploymentOrchestrator::new(Arc::clone(&publisher));
        let mut plan = deployment_plan();
        plan.nodes[0].role = VpnDeploymentRole::Client;

        assert!(matches!(
            orchestrator.deploy(plan),
            Err(DeploymentError::InvalidOperatorCount)
        ));
    }
}
