use chrono::Utc;
use imperium_protocol::{IdentityAccessDecision, IdentityCapabilityGrant, PeerId};

pub struct AccessPolicy {
    grants: Vec<IdentityCapabilityGrant>,
}

impl AccessPolicy {
    pub fn new(grants: Vec<IdentityCapabilityGrant>) -> Self {
        Self { grants }
    }

    pub fn decide(&self, identity_id: &PeerId, capability: &str) -> IdentityAccessDecision {
        let now = Utc::now();
        let allowed = self.grants.iter().any(|grant| {
            &grant.identity_id == identity_id
                && grant
                    .expires_at
                    .map(|expires_at| expires_at > now)
                    .unwrap_or(true)
                && grant
                    .capabilities
                    .iter()
                    .any(|granted| granted == capability)
        });

        IdentityAccessDecision {
            identity_id: identity_id.clone(),
            capability: capability.to_string(),
            allowed,
            reason: if allowed {
                "capability granted".to_string()
            } else {
                "no active grant for capability".to_string()
            },
            decided_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denies_missing_capability() {
        let identity = PeerId::new();
        let policy = AccessPolicy::new(vec![IdentityCapabilityGrant {
            identity_id: identity.clone(),
            capabilities: vec!["vpn.cluster.status".into()],
            issued_by: PeerId::new(),
            issued_at: Utc::now(),
            expires_at: None,
            signature: vec![1, 2, 3],
        }]);

        assert!(policy.decide(&identity, "vpn.cluster.status").allowed);
        assert!(!policy.decide(&identity, "vpn.shutdown").allowed);
    }
}
