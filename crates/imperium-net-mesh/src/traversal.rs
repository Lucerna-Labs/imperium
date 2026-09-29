use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use imperium_protocol::{NatProbePlan, NatTraversalMode, NatTraversalPolicy, PeerId};
use thiserror::Error;
use tokio::net::UdpSocket;

/// Hard node-wide limits for one opt-in probe window. A run is serialized by
/// the daemon, so these also bound concurrent socket and datagram work.
pub const MAX_PROBE_SOCKETS: u16 = 8;
pub const MAX_PROBES_PER_SOCKET: u16 = 16;
pub const MAX_PROBE_WINDOW_MS: u64 = 5_000;
pub const MAX_PROBE_CANDIDATES: usize = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NatProbePolicyError {
    #[error("aggressive NAT probing requires explicit opt-in and mode selection")]
    OptInRequired,
    #[error("probe socket budget must be between 1 and {MAX_PROBE_SOCKETS}")]
    SocketBudget,
    #[error("probes per socket must be between 1 and {MAX_PROBES_PER_SOCKET}")]
    ProbeBudget,
    #[error("probe window must be between 250 and {MAX_PROBE_WINDOW_MS} ms")]
    WindowBudget,
    #[error("candidate endpoint count must be between 1 and {MAX_PROBE_CANDIDATES}")]
    CandidateBudget,
    #[error("candidate endpoint is invalid: {0}")]
    InvalidCandidate(SocketAddr),
    #[error("candidate endpoint is duplicated: {0}")]
    DuplicateCandidate(SocketAddr),
}

#[derive(Debug, Error)]
pub enum NatProbeSetupError {
    #[error(transparent)]
    Policy(#[from] NatProbePolicyError),
    #[error("could not bind a probe socket: {0}")]
    Io(#[from] std::io::Error),
}

/// One actual, separately bound UDP socket and its operator-supplied target.
/// Binding alone makes no peer reachability or NAT traversal claim.
pub struct BoundProbeSocket {
    pub socket: Arc<UdpSocket>,
    pub candidate: SocketAddr,
}

pub struct NatTraversalPlanner;

impl NatTraversalPlanner {
    pub fn default_policy() -> NatTraversalPolicy {
        NatTraversalPolicy {
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
        }
    }

    pub fn aggressive_policy() -> NatTraversalPolicy {
        NatTraversalPolicy {
            allowed_modes: vec![
                NatTraversalMode::DirectUdp,
                NatTraversalMode::StunMappedAddress,
                NatTraversalMode::LimitedCoordinatedProbing,
                NatTraversalMode::AggressiveBirthdayProbe,
                NatTraversalMode::RelayThroughPeer,
            ],
            aggressive_probe_opt_in: true,
            max_probe_sockets: MAX_PROBE_SOCKETS,
            probes_per_socket: MAX_PROBES_PER_SOCKET,
            probe_window_ms: 5_000,
            relay_fallback_enabled: true,
        }
    }

    pub fn build_probe_plan(peer_id: PeerId, policy: &NatTraversalPolicy) -> NatProbePlan {
        let aggressive_allowed = policy.aggressive_probe_opt_in
            && policy
                .allowed_modes
                .iter()
                .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe));

        let socket_count = if aggressive_allowed {
            policy.max_probe_sockets
        } else {
            policy.max_probe_sockets.min(4)
        };

        let probes_per_socket = if aggressive_allowed {
            policy.probes_per_socket
        } else {
            policy.probes_per_socket.min(8)
        };

        let modes = policy
            .allowed_modes
            .iter()
            .filter(|mode| {
                aggressive_allowed || !matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)
            })
            .cloned()
            .collect::<Vec<_>>();

        NatProbePlan {
            peer_id,
            modes,
            socket_count,
            probes_per_socket,
            estimated_probe_count: socket_count as u32 * probes_per_socket as u32,
            relay_fallback_enabled: policy.relay_fallback_enabled,
        }
    }

    /// Reject unsafe runtime requests before opening sockets or sending UDP.
    /// The planner alone does not execute or validate an operator request.
    pub fn validate_aggressive(
        peer_id: PeerId,
        policy: &NatTraversalPolicy,
    ) -> Result<NatProbePlan, NatProbePolicyError> {
        if !policy.aggressive_probe_opt_in
            || !policy
                .allowed_modes
                .contains(&NatTraversalMode::AggressiveBirthdayProbe)
        {
            return Err(NatProbePolicyError::OptInRequired);
        }
        if !(1..=MAX_PROBE_SOCKETS).contains(&policy.max_probe_sockets) {
            return Err(NatProbePolicyError::SocketBudget);
        }
        if !(1..=MAX_PROBES_PER_SOCKET).contains(&policy.probes_per_socket) {
            return Err(NatProbePolicyError::ProbeBudget);
        }
        if !(250..=MAX_PROBE_WINDOW_MS).contains(&policy.probe_window_ms) {
            return Err(NatProbePolicyError::WindowBudget);
        }
        Ok(Self::build_probe_plan(peer_id, policy))
    }

    /// Probe only explicitly configured, routable endpoint candidates.
    /// Loopback and private addresses are valid for local and LAN deployments.
    pub fn validate_candidates(candidates: &[SocketAddr]) -> Result<(), NatProbePolicyError> {
        if candidates.is_empty() || candidates.len() > MAX_PROBE_CANDIDATES {
            return Err(NatProbePolicyError::CandidateBudget);
        }
        let mut seen = HashSet::with_capacity(candidates.len());
        for &candidate in candidates {
            let invalid_ip = candidate.ip().is_unspecified()
                || candidate.ip().is_multicast()
                || candidate.ip() == IpAddr::V4(Ipv4Addr::BROADCAST);
            if candidate.port() == 0 || invalid_ip {
                return Err(NatProbePolicyError::InvalidCandidate(candidate));
            }
            if !seen.insert(candidate) {
                return Err(NatProbePolicyError::DuplicateCandidate(candidate));
            }
        }
        Ok(())
    }

    /// Allocate the complete bounded socket pool before any probe packet is
    /// sent. The eventual executor owns these sockets for its finite window.
    pub async fn bind_probe_sockets(
        peer_id: PeerId,
        policy: &NatTraversalPolicy,
        candidates: &[SocketAddr],
        bind_ip: IpAddr,
    ) -> Result<(NatProbePlan, Vec<BoundProbeSocket>), NatProbeSetupError> {
        let plan = Self::validate_aggressive(peer_id, policy)?;
        Self::validate_candidates(candidates)?;
        let mut sockets = Vec::with_capacity(plan.socket_count as usize);
        for index in 0..plan.socket_count as usize {
            let candidate = candidates[index % candidates.len()];
            let local_ip = if bind_ip.is_ipv4() == candidate.is_ipv4() {
                bind_ip
            } else if candidate.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            };
            let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?;
            sockets.push(BoundProbeSocket {
                socket: Arc::new(socket),
                candidate,
            });
        }
        Ok((plan, sockets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_excludes_aggressive_probe() {
        let policy = NatTraversalPlanner::default_policy();
        let plan = NatTraversalPlanner::build_probe_plan(PeerId::new(), &policy);

        assert!(!plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        assert_eq!(plan.estimated_probe_count, 32);
        assert!(plan.relay_fallback_enabled);
    }

    #[test]
    fn aggressive_policy_requires_explicit_opt_in() {
        let policy = NatTraversalPlanner::aggressive_policy();
        let plan = NatTraversalPlanner::build_probe_plan(PeerId::new(), &policy);

        assert!(plan
            .modes
            .iter()
            .any(|mode| matches!(mode, NatTraversalMode::AggressiveBirthdayProbe)));
        assert_eq!(plan.estimated_probe_count, 128);
        assert_eq!(
            NatTraversalPlanner::validate_aggressive(PeerId::new(), &policy)
                .unwrap()
                .estimated_probe_count,
            128
        );
    }

    #[test]
    fn runtime_rejects_unarmed_and_oversized_policies() {
        let peer_id = PeerId::new();
        assert!(matches!(
            NatTraversalPlanner::validate_aggressive(
                peer_id.clone(),
                &NatTraversalPlanner::default_policy()
            ),
            Err(NatProbePolicyError::OptInRequired)
        ));
        let mut policy = NatTraversalPlanner::aggressive_policy();
        policy.max_probe_sockets = MAX_PROBE_SOCKETS + 1;
        assert!(matches!(
            NatTraversalPlanner::validate_aggressive(peer_id.clone(), &policy),
            Err(NatProbePolicyError::SocketBudget)
        ));
        policy.max_probe_sockets = 1;
        policy.probes_per_socket = MAX_PROBES_PER_SOCKET + 1;
        assert!(matches!(
            NatTraversalPlanner::validate_aggressive(peer_id, &policy),
            Err(NatProbePolicyError::ProbeBudget)
        ));
    }

    #[test]
    fn candidate_gate_rejects_ambiguous_or_unsafe_destinations() {
        let endpoint: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert!(NatTraversalPlanner::validate_candidates(&[endpoint]).is_ok());
        assert!(matches!(
            NatTraversalPlanner::validate_candidates(&[]),
            Err(NatProbePolicyError::CandidateBudget)
        ));
        assert!(matches!(
            NatTraversalPlanner::validate_candidates(&[endpoint, endpoint]),
            Err(NatProbePolicyError::DuplicateCandidate(_))
        ));
        assert!(matches!(
            NatTraversalPlanner::validate_candidates(&["0.0.0.0:9000".parse().unwrap()]),
            Err(NatProbePolicyError::InvalidCandidate(_))
        ));
        assert!(matches!(
            NatTraversalPlanner::validate_candidates(&["224.0.0.1:9000".parse().unwrap()]),
            Err(NatProbePolicyError::InvalidCandidate(_))
        ));
    }

    #[tokio::test]
    async fn binds_only_the_declared_budget_of_real_udp_sockets() {
        let mut policy = NatTraversalPlanner::aggressive_policy();
        policy.max_probe_sockets = 3;
        policy.probes_per_socket = 1;
        let candidates: Vec<SocketAddr> = vec![
            "127.0.0.1:9001".parse().unwrap(),
            "127.0.0.1:9002".parse().unwrap(),
        ];
        let (plan, sockets) = NatTraversalPlanner::bind_probe_sockets(
            PeerId::new(),
            &policy,
            &candidates,
            "127.0.0.1".parse().unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(plan.estimated_probe_count, 3);
        assert_eq!(sockets.len(), 3);
        assert_eq!(sockets[0].candidate, candidates[0]);
        assert_eq!(sockets[1].candidate, candidates[1]);
        assert_eq!(sockets[2].candidate, candidates[0]);
        let ports: HashSet<u16> = sockets
            .iter()
            .map(|socket| socket.socket.local_addr().unwrap().port())
            .collect();
        assert_eq!(
            ports.len(),
            3,
            "every probe socket owns a distinct UDP port"
        );
    }
}
