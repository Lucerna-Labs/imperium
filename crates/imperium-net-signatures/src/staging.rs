use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    Message, PeerId, SignatureApproved, SignatureCandidate, SignatureRejected,
};
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum StagingError {
    #[error("candidate not found: {0}")]
    NotFound(Uuid),
    #[error("candidate already processed: {0}")]
    AlreadyProcessed(Uuid),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateStatus {
    Pending,
    Approved,
    Rejected,
}

struct StagedCandidate {
    candidate: SignatureCandidate,
    status: CandidateStatus,
    rejection_reason: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StagedCandidateSnapshot {
    pub candidate: SignatureCandidate,
    pub status: CandidateStatus,
    pub rejection_reason: Option<String>,
}

pub struct StagingArea {
    candidates: Arc<RwLock<HashMap<Uuid, StagedCandidate>>>,
    bus: Arc<BusPublisher>,
}

impl StagingArea {
    pub fn new(bus: Arc<BusPublisher>) -> Self {
        Self {
            candidates: Arc::new(RwLock::new(HashMap::new())),
            bus,
        }
    }

    pub fn submit(&self, candidate: SignatureCandidate) -> Result<Uuid, StagingError> {
        let id = candidate.id;
        self.candidates.write().insert(
            id,
            StagedCandidate {
                candidate: candidate.clone(),
                status: CandidateStatus::Pending,
                rejection_reason: None,
            },
        );

        BusEvent::publish(
            &self.bus,
            "net.signatures.candidate",
            Message::SignatureCandidate(candidate),
        )?;

        Ok(id)
    }

    pub fn approve(
        &self,
        id: Uuid,
        approver: &PeerId,
        signing_key: &HybridSigningKey,
    ) -> Result<SignatureApproved, StagingError> {
        let mut candidates = self.candidates.write();
        let staged = candidates.get_mut(&id).ok_or(StagingError::NotFound(id))?;

        if staged.status != CandidateStatus::Pending {
            return Err(StagingError::AlreadyProcessed(id));
        }

        staged.status = CandidateStatus::Approved;

        let sig = HybridEd25519Mldsa::sign(signing_key, staged.candidate.rule_text.as_bytes());

        let approved = SignatureApproved {
            candidate_id: id,
            approved_by: approver.clone(),
            approved_at: Utc::now(),
            signature: sig.to_bytes(),
        };

        drop(candidates);

        let _ = BusEvent::publish(
            &self.bus,
            "net.signatures.approved",
            Message::SignatureApproved(approved.clone()),
        );

        Ok(approved)
    }

    pub fn reject(
        &self,
        id: Uuid,
        rejector: &PeerId,
        reason: &str,
    ) -> Result<SignatureRejected, StagingError> {
        let mut candidates = self.candidates.write();
        let staged = candidates.get_mut(&id).ok_or(StagingError::NotFound(id))?;

        if staged.status != CandidateStatus::Pending {
            return Err(StagingError::AlreadyProcessed(id));
        }

        staged.status = CandidateStatus::Rejected;
        staged.rejection_reason = Some(reason.to_string());

        let rejected = SignatureRejected {
            candidate_id: id,
            rejected_by: rejector.clone(),
            rejected_at: Utc::now(),
            reason: reason.to_string(),
        };

        drop(candidates);

        let _ = BusEvent::publish(
            &self.bus,
            "net.signatures.rejected",
            Message::SignatureRejected(rejected.clone()),
        );

        Ok(rejected)
    }

    pub fn pending_count(&self) -> usize {
        self.candidates
            .read()
            .values()
            .filter(|c| c.status == CandidateStatus::Pending)
            .count()
    }

    pub fn pending_candidates(&self) -> Vec<SignatureCandidate> {
        self.candidates
            .read()
            .values()
            .filter(|c| c.status == CandidateStatus::Pending)
            .map(|c| c.candidate.clone())
            .collect()
    }

    pub fn candidate(&self, id: Uuid) -> Option<StagedCandidateSnapshot> {
        self.candidates
            .read()
            .get(&id)
            .map(|staged| StagedCandidateSnapshot {
                candidate: staged.candidate.clone(),
                status: staged.status.clone(),
                rejection_reason: staged.rejection_reason.clone(),
            })
    }
}

pub struct ApprovalFlow {
    staging: Arc<StagingArea>,
}

impl ApprovalFlow {
    pub fn new(staging: Arc<StagingArea>) -> Self {
        Self { staging }
    }

    pub fn review_pending(&self) -> Vec<SignatureCandidate> {
        self.staging.pending_candidates()
    }

    pub fn approve(
        &self,
        id: Uuid,
        approver: &PeerId,
        signing_key: &HybridSigningKey,
    ) -> Result<SignatureApproved, StagingError> {
        self.staging.approve(id, approver, signing_key)
    }

    pub fn reject(
        &self,
        id: Uuid,
        rejector: &PeerId,
        reason: &str,
    ) -> Result<SignatureRejected, StagingError> {
        self.staging.reject(id, rejector, reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::EventId;
    use rand::rngs::OsRng;

    fn test_candidate() -> SignatureCandidate {
        SignatureCandidate {
            id: Uuid::new_v4(),
            rule_text: r#"rule test_cand { strings: $a = { DE AD BE EF } condition: $a }"#.into(),
            description: "test candidate".into(),
            source_events: vec![EventId::new()],
            extracted_at: Utc::now(),
            confidence: 0.8,
        }
    }

    #[test]
    fn submit_and_approve() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = StagingArea::new(bus);

        let candidate = test_candidate();
        let id = staging.submit(candidate).unwrap();
        assert_eq!(staging.pending_count(), 1);

        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let operator = PeerId::new();

        let approved = staging.approve(id, &operator, &sk).unwrap();
        assert_eq!(approved.candidate_id, id);
        assert_eq!(staging.pending_count(), 0);
    }

    #[test]
    fn submit_and_reject() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = StagingArea::new(bus);

        let candidate = test_candidate();
        let id = staging.submit(candidate).unwrap();

        let operator = PeerId::new();
        let rejected = staging.reject(id, &operator, "false positive").unwrap();
        assert_eq!(rejected.candidate_id, id);
        assert_eq!(staging.pending_count(), 0);
    }

    #[test]
    fn candidate_snapshot_reports_status() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = StagingArea::new(bus);

        let candidate = test_candidate();
        let id = staging.submit(candidate.clone()).unwrap();
        let pending = staging.candidate(id).unwrap();
        assert_eq!(pending.candidate.id, candidate.id);
        assert_eq!(pending.status, CandidateStatus::Pending);

        let operator = PeerId::new();
        staging.reject(id, &operator, "false positive").unwrap();

        let rejected = staging.candidate(id).unwrap();
        assert_eq!(rejected.status, CandidateStatus::Rejected);
        assert_eq!(rejected.rejection_reason.as_deref(), Some("false positive"));
    }

    #[test]
    fn double_approve_fails() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let staging = StagingArea::new(bus);

        let candidate = test_candidate();
        let id = staging.submit(candidate).unwrap();

        let mut rng = OsRng;
        let (sk, _vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let operator = PeerId::new();

        staging.approve(id, &operator, &sk).unwrap();
        assert!(staging.approve(id, &operator, &sk).is_err());
    }
}
