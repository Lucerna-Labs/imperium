use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_net_crypto::{
    HybridEd25519Mldsa, HybridSignature, HybridSigningKey, HybridVerifyingKey,
};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    ClusterId, MembershipApprovalRequest, MembershipGossip, MembershipGrant, Message, PeerId,
};
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MembershipError {
    #[error("peer already a member: {0:?}")]
    AlreadyMember(PeerId),
    #[error("pending approval already exists for peer")]
    ApprovalPending,
    #[error("peer not found: {0:?}")]
    PeerNotFound(PeerId),
    #[error("grant signature invalid (not operator-signed)")]
    InvalidGrantSignature,
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipState {
    PendingApproval,
    Approved,
    Revoked,
}

struct MemberRecord {
    state: MembershipState,
    granted_at: Option<DateTime<Utc>>,
    granted_by: Option<PeerId>,
}

pub struct MembershipManager {
    cluster_id: ClusterId,
    operator_vk: HybridVerifyingKey,
    members: Arc<RwLock<HashMap<PeerId, MemberRecord>>>,
    lamport_clock: Arc<RwLock<u64>>,
    local_peer_id: PeerId,
    /// Grants this manager has *applied* (verified only), for observability.
    ///
    /// The supervised strand uses it to prove the replay guard: a replayed grant
    /// must not move this counter a second time. Nothing in the state machine
    /// reads it.
    applied_grants: AtomicU64,
}

impl MembershipManager {
    pub fn new(
        cluster_id: ClusterId,
        local_peer_id: PeerId,
        operator_vk: HybridVerifyingKey,
    ) -> Self {
        let members = Arc::new(RwLock::new(HashMap::new()));
        let mut initial = members.write();
        initial.insert(
            local_peer_id.clone(),
            MemberRecord {
                state: MembershipState::Approved,
                granted_at: Some(Utc::now()),
                granted_by: None,
            },
        );
        drop(initial);

        Self {
            cluster_id,
            operator_vk,
            members,
            lamport_clock: Arc::new(RwLock::new(0)),
            local_peer_id,
            applied_grants: AtomicU64::new(0),
        }
    }

    pub fn request_membership(
        &self,
        peer_id: PeerId,
        bus: &BusPublisher,
    ) -> Result<(), MembershipError> {
        let mut members = self.members.write();
        if members.contains_key(&peer_id) {
            let record = &members[&peer_id];
            if record.state == MembershipState::Approved {
                return Err(MembershipError::AlreadyMember(peer_id));
            }
            if record.state == MembershipState::PendingApproval {
                return Err(MembershipError::ApprovalPending);
            }
        }

        members.insert(
            peer_id.clone(),
            MemberRecord {
                state: MembershipState::PendingApproval,
                granted_at: None,
                granted_by: None,
            },
        );
        drop(members);

        let request = MembershipApprovalRequest {
            cluster_id: self.cluster_id.clone(),
            requesting_peer: peer_id,
            bootstrap_token: imperium_protocol::BootstrapTokenPayload {
                token_id: uuid::Uuid::new_v4(),
                cluster_id: self.cluster_id.clone(),
                issued_by: self.local_peer_id.clone(),
                issued_at: Utc::now(),
                expires_at: Utc::now(),
                signature: Vec::new(),
            },
        };

        BusEvent::publish(
            bus,
            "net.cluster.membership.request",
            Message::MembershipApprovalReq(request),
        )?;

        Ok(())
    }

    pub fn approve_membership(
        &self,
        peer_id: &PeerId,
        approver: &PeerId,
        signing_key: &HybridSigningKey,
        bus: &BusPublisher,
    ) -> Result<MembershipGrant, MembershipError> {
        let mut members = self.members.write();
        let record = members
            .get_mut(peer_id)
            .ok_or_else(|| MembershipError::PeerNotFound(peer_id.clone()))?;

        let now = Utc::now();
        record.state = MembershipState::Approved;
        record.granted_at = Some(now);
        record.granted_by = Some(approver.clone());
        drop(members);

        let mut payload = Vec::new();
        payload.extend_from_slice(self.cluster_id.0.as_bytes());
        payload.extend_from_slice(peer_id.0.as_bytes());
        payload.extend_from_slice(approver.0.as_bytes());
        payload.extend_from_slice(&now.timestamp().to_le_bytes());

        let sig = HybridEd25519Mldsa::sign(signing_key, &payload);

        let grant = MembershipGrant {
            cluster_id: self.cluster_id.clone(),
            peer_id: peer_id.clone(),
            granted_by: approver.clone(),
            granted_at: now,
            signature: sig.to_bytes(),
        };

        let _ = BusEvent::publish(
            bus,
            "net.cluster.membership.granted",
            Message::MembershipGrant(grant.clone()),
        );

        self.tick_clock();
        self.gossip_membership(bus);

        Ok(grant)
    }

    pub fn apply_grant(&self, grant: &MembershipGrant) -> Result<(), MembershipError> {
        self.verify_grant(grant)?;
        let mut members = self.members.write();
        members
            .entry(grant.peer_id.clone())
            .and_modify(|r| {
                r.state = MembershipState::Approved;
                r.granted_at = Some(grant.granted_at);
                r.granted_by = Some(grant.granted_by.clone());
            })
            .or_insert_with(|| MemberRecord {
                state: MembershipState::Approved,
                granted_at: Some(grant.granted_at),
                granted_by: Some(grant.granted_by.clone()),
            });
        drop(members);
        self.applied_grants.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// How many grants this manager has successfully applied.
    ///
    /// Observability only — the supervised strand [`crate::MembershipGrantStrand`]
    /// and its tests use it to prove that a replayed grant is *not* applied a
    /// second time. No decision reads it.
    pub fn applied_grants(&self) -> u64 {
        self.applied_grants.load(Ordering::Relaxed)
    }

    /// Verify a grant carries the operator's hybrid signature over the
    /// approve_membership payload layout (cluster || peer || approver ||
    /// granted_at). Fail-closed: decode failure or bad signature rejects.
    /// No key material is exposed on failure.
    pub fn verify_grant(&self, grant: &MembershipGrant) -> Result<(), MembershipError> {
        if grant.cluster_id != self.cluster_id {
            return Err(MembershipError::InvalidGrantSignature);
        }
        let mut payload = Vec::new();
        payload.extend_from_slice(grant.cluster_id.0.as_bytes());
        payload.extend_from_slice(grant.peer_id.0.as_bytes());
        payload.extend_from_slice(grant.granted_by.0.as_bytes());
        payload.extend_from_slice(&grant.granted_at.timestamp().to_le_bytes());

        let signature = HybridSignature::from_bytes(&grant.signature)
            .map_err(|_| MembershipError::InvalidGrantSignature)?;
        HybridEd25519Mldsa::verify(&self.operator_vk, &payload, &signature)
            .map_err(|_| MembershipError::InvalidGrantSignature)?;
        Ok(())
    }

    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        self.members
            .read()
            .get(peer_id)
            .map(|r| r.state == MembershipState::Approved)
            .unwrap_or(false)
    }

    pub fn member_count(&self) -> usize {
        self.members
            .read()
            .values()
            .filter(|r| r.state == MembershipState::Approved)
            .count()
    }

    pub fn approved_members(&self) -> Vec<PeerId> {
        self.members
            .read()
            .iter()
            .filter(|(_, r)| r.state == MembershipState::Approved)
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn pending_approvals(&self) -> Vec<PeerId> {
        self.members
            .read()
            .iter()
            .filter(|(_, r)| r.state == MembershipState::PendingApproval)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn tick_clock(&self) {
        let mut clock = self.lamport_clock.write();
        *clock += 1;
    }

    pub fn merge_clock(&self, remote_clock: u64) {
        let mut clock = self.lamport_clock.write();
        *clock = (*clock).max(remote_clock) + 1;
    }

    pub fn current_clock(&self) -> u64 {
        *self.lamport_clock.read()
    }

    fn gossip_membership(&self, bus: &BusPublisher) {
        let members = self.approved_members();
        let clock = self.current_clock();

        let gossip = MembershipGossip {
            cluster_id: self.cluster_id.clone(),
            members,
            lamport_clock: clock,
            from_peer: self.local_peer_id.clone(),
        };

        let _ = BusEvent::publish(
            bus,
            "net.cluster.membership.gossip",
            Message::MembershipGossip(gossip),
        );
    }

    pub fn apply_gossip(&self, gossip: &MembershipGossip) {
        if gossip.lamport_clock < self.current_clock() {
            return;
        }

        self.merge_clock(gossip.lamport_clock);

        for peer_id in &gossip.members {
            if !self.is_member(peer_id) {
                let mut members = self.members.write();
                let known = members.contains_key(peer_id);
                // Merge gossip conservatively: unknown peers can be accepted on
                // equal clocks, but never downgrade/remove known membership.
                if gossip.lamport_clock == self.current_clock() && known {
                    continue;
                }
                members
                    .entry(peer_id.clone())
                    .or_insert_with(|| MemberRecord {
                        state: MembershipState::Approved,
                        granted_at: Some(Utc::now()),
                        granted_by: Some(gossip.from_peer.clone()),
                    });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use spiderweb::Bus;

    #[test]
    fn new_cluster_has_local_member() {
        let cluster_id = ClusterId::new();
        let local_peer = PeerId::new();
        let mut rng = OsRng;
        let (_sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = MembershipManager::new(cluster_id, local_peer.clone(), vk);

        assert!(mgr.is_member(&local_peer));
        assert_eq!(mgr.member_count(), 1);
    }

    #[test]
    fn approve_membership_flow() {
        let cluster_id = ClusterId::new();
        let operator = PeerId::new();
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = MembershipManager::new(cluster_id, operator.clone(), vk);

        let new_peer = PeerId::new();
        mgr.request_membership(new_peer.clone(), &publisher)
            .unwrap();

        assert!(!mgr.is_member(&new_peer));
        assert_eq!(mgr.pending_approvals().len(), 1);

        mgr.approve_membership(&new_peer, &operator, &sk, &publisher)
            .unwrap();

        assert!(mgr.is_member(&new_peer));
        assert_eq!(mgr.member_count(), 2);
    }

    #[test]
    fn apply_grant_rejects_forged_signature() {
        // Regression test: vec![1,2,3] fabrications must be rejected.
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let mut rng = OsRng;
        let (_sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = MembershipManager::new(cluster_id.clone(), local.clone(), vk);

        let new_peer = PeerId::new();
        let grant = MembershipGrant {
            cluster_id: cluster_id.clone(),
            peer_id: new_peer.clone(),
            granted_by: local.clone(),
            granted_at: Utc::now(),
            signature: vec![1, 2, 3],
        };
        assert!(matches!(
            mgr.apply_grant(&grant),
            Err(MembershipError::InvalidGrantSignature)
        ));
        assert!(!mgr.is_member(&new_peer));
    }

    #[test]
    fn apply_grant_accepts_operator_signed_grant() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = MembershipManager::new(cluster_id, local.clone(), vk);

        let new_peer = PeerId::new();
        mgr.request_membership(new_peer.clone(), &publisher)
            .unwrap();
        let grant = mgr
            .approve_membership(&new_peer, &local, &sk, &publisher)
            .unwrap();

        // A second manager trusting the same operator accepts the grant.
        let mut rng = OsRng;
        let (_sk2, vk2) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let _ = vk2;
        let mgr2 = MembershipManager::new(
            grant.cluster_id.clone(),
            PeerId::new(),
            HybridEd25519Mldsa::verifying_key(&sk),
        );
        mgr2.apply_grant(&grant).unwrap();
        assert!(mgr2.is_member(&new_peer));
    }

    /// Poll until `pred` holds, so a strand bug fails the test instead of
    /// hanging it. The strand ticks every 10ms; 20s is a hard ceiling.
    fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !pred() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for: {what}"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// The bus path is the supervised strand now: a fabricated signature must
    /// still be rejected, and the loop must still be doing real work (proved by
    /// a verified grant for another peer being applied on the same strand).
    #[tokio::test]
    async fn supervised_membership_strand_rejects_forged_grants() {
        // The old test injected signature vec![1,2,3] and expected acceptance;
        // forged grants must be rejected on the bus path, and the bus path is
        // now a supervised strand registered through the legacy shim.
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = Arc::new(MembershipManager::new(
            cluster_id.clone(),
            local.clone(),
            vk,
        ));
        let mut bus = Bus::open();
        let publisher = Arc::new(bus.publisher());

        // The old `subscribe_membership_grants` shim did two things: wire this
        // manager into the bus's links registry, and queue the crate's strand
        // specs. Both are explicit now.
        crate::attach_membership(&publisher, &mgr);
        crate::register_strands(&mut bus, &publisher);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        let forged_peer = PeerId::new();
        BusEvent::publish(
            &publisher,
            crate::topics::MEMBERSHIP_GRANTED,
            Message::MembershipGrant(MembershipGrant {
                cluster_id: cluster_id.clone(),
                peer_id: forged_peer.clone(),
                granted_by: local.clone(),
                granted_at: Utc::now(),
                signature: vec![1, 2, 3],
            }),
        )
        .unwrap();

        // The control: a real, operator-signed grant, minted by a second manager
        // standing in for the operator node. It proves the strand is live and
        // that the rejection above was the signature check, not an idle loop.
        let operator = Arc::new(MembershipManager::new(
            cluster_id.clone(),
            local.clone(),
            HybridEd25519Mldsa::verifying_key(&sk),
        ));
        let verified_peer = PeerId::new();
        operator
            .request_membership(verified_peer.clone(), &publisher)
            .unwrap();
        operator
            .approve_membership(&verified_peer, &local, &sk, &publisher)
            .unwrap();

        wait_until("the verified grant to be applied", || {
            mgr.is_member(&verified_peer)
        });

        assert!(!mgr.is_member(&forged_peer), "a forged grant was applied");
        assert_eq!(
            mgr.applied_grants(),
            1,
            "exactly the verified grant may be applied"
        );
        assert_eq!(mgr.member_count(), 2);
        supervision.shutdown();
    }

    /// A verified grant published by another node is applied through the strand —
    /// the applying manager is *not* the approver here, so the state change can
    /// only have come from the bus.
    #[tokio::test]
    async fn supervised_membership_strand_applies_verified_grants() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = Arc::new(MembershipManager::new(
            cluster_id.clone(),
            local.clone(),
            vk,
        ));
        let mut bus = Bus::open();
        let publisher = Arc::new(bus.publisher());

        // The old `subscribe_membership_grants` shim did two things: wire this
        // manager into the bus's links registry, and queue the crate's strand
        // specs. Both are explicit now.
        crate::attach_membership(&publisher, &mgr);
        crate::register_strands(&mut bus, &publisher);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        let operator = Arc::new(MembershipManager::new(
            cluster_id.clone(),
            local.clone(),
            HybridEd25519Mldsa::verifying_key(&sk),
        ));
        let new_peer = PeerId::new();
        operator
            .request_membership(new_peer.clone(), &publisher)
            .unwrap();
        let grant = operator
            .approve_membership(&new_peer, &local, &sk, &publisher)
            .unwrap();
        assert!(!grant.signature.is_empty());

        wait_until("the grant to reach the member node", || {
            mgr.is_member(&new_peer)
        });

        assert_eq!(mgr.member_count(), 2);
        assert_eq!(mgr.applied_grants(), 1);
        assert_eq!(mgr.pending_approvals().len(), 0);
        supervision.shutdown();
    }

    #[test]
    fn gossip_merges_new_members() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let mut rng = OsRng;
        let (_sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = MembershipManager::new(cluster_id.clone(), local.clone(), vk);

        let remote_peer = PeerId::new();
        let new_peer = PeerId::new();

        let gossip = MembershipGossip {
            cluster_id: cluster_id.clone(),
            members: vec![remote_peer.clone(), new_peer.clone()],
            lamport_clock: 5,
            from_peer: remote_peer.clone(),
        };

        mgr.apply_gossip(&gossip);
        assert!(mgr.is_member(&remote_peer));
        assert!(mgr.is_member(&new_peer));
        assert_eq!(mgr.current_clock(), 6);
    }
}
