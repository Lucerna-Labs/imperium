use std::collections::HashSet;
use std::sync::Arc;

use chrono::{Duration, Utc};
use imperium_net_crypto::{
    HybridEd25519Mldsa, HybridSignError, HybridSignature, HybridSigningKey, HybridVerifyingKey,
};
use imperium_protocol::{BootstrapTokenPayload, ClusterId, PeerId};
use parking_lot::RwLock;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token expired")]
    Expired,
    #[error("token already consumed")]
    AlreadyConsumed,
    #[error("invalid signature: {0}")]
    InvalidSignature(#[from] HybridSignError),
    #[error("cluster id mismatch")]
    ClusterMismatch,
}

pub struct TokenManager {
    cluster_id: ClusterId,
    operator_vk: HybridVerifyingKey,
    consumed_tokens: Arc<RwLock<HashSet<Vec<u8>>>>,
}

impl TokenManager {
    pub fn new(cluster_id: ClusterId, operator_vk: HybridVerifyingKey) -> Self {
        Self {
            cluster_id,
            operator_vk,
            consumed_tokens: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn mint_token(
        &self,
        operator_peer_id: &PeerId,
        signing_key: &HybridSigningKey,
        expires_in: Duration,
    ) -> BootstrapTokenPayload {
        let now = Utc::now();
        let expires_at = now + expires_in;
        let token_id = Uuid::new_v4();

        let mut payload_bytes = Vec::new();
        payload_bytes.extend_from_slice(token_id.as_bytes());
        payload_bytes.extend_from_slice(self.cluster_id.0.as_bytes());
        payload_bytes.extend_from_slice(operator_peer_id.0.as_bytes());
        payload_bytes.extend_from_slice(&now.timestamp().to_le_bytes());
        payload_bytes.extend_from_slice(&expires_at.timestamp().to_le_bytes());

        let sig = HybridEd25519Mldsa::sign(signing_key, &payload_bytes);
        let signature_bytes = sig.to_bytes();

        BootstrapTokenPayload {
            token_id,
            cluster_id: self.cluster_id.clone(),
            issued_by: operator_peer_id.clone(),
            issued_at: now,
            expires_at,
            signature: signature_bytes,
        }
    }

    pub fn verify_token(&self, token: &BootstrapTokenPayload) -> Result<(), TokenError> {
        if token.cluster_id != self.cluster_id {
            return Err(TokenError::ClusterMismatch);
        }

        if Utc::now() > token.expires_at {
            return Err(TokenError::Expired);
        }

        if self.consumed_tokens.read().contains(&token.signature) {
            return Err(TokenError::AlreadyConsumed);
        }

        // Reconstruct the exact payload layout from mint_token, then verify
        // the operator's hybrid signature over it. Fail-closed: any decode
        // failure or bad signature rejects.
        let mut payload_bytes = Vec::new();
        payload_bytes.extend_from_slice(token.token_id.as_bytes());
        payload_bytes.extend_from_slice(token.cluster_id.0.as_bytes());
        payload_bytes.extend_from_slice(token.issued_by.0.as_bytes());
        payload_bytes.extend_from_slice(&token.issued_at.timestamp().to_le_bytes());
        payload_bytes.extend_from_slice(&token.expires_at.timestamp().to_le_bytes());

        let signature = HybridSignature::from_bytes(&token.signature)?;
        HybridEd25519Mldsa::verify(&self.operator_vk, &payload_bytes, &signature)?;

        Ok(())
    }

    pub fn consume_token(&self, token: &BootstrapTokenPayload) {
        self.consumed_tokens.write().insert(token.signature.clone());
    }

    pub fn is_consumed(&self, token: &BootstrapTokenPayload) -> bool {
        self.consumed_tokens.read().contains(&token.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn mint_and_verify_token() {
        let cluster_id = ClusterId::new();
        let operator_id = PeerId::new();
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = TokenManager::new(cluster_id, vk);

        let token = mgr.mint_token(&operator_id, &sk, Duration::hours(1));
        assert!(mgr.verify_token(&token).is_ok());
    }

    #[test]
    fn consumed_token_rejected() {
        let cluster_id = ClusterId::new();
        let operator_id = PeerId::new();
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = TokenManager::new(cluster_id, vk);

        let token = mgr.mint_token(&operator_id, &sk, Duration::hours(1));
        mgr.consume_token(&token);

        assert!(matches!(
            mgr.verify_token(&token),
            Err(TokenError::AlreadyConsumed)
        ));
    }

    #[test]
    fn rapid_tokens_are_independently_consumable() {
        let cluster_id = ClusterId::new();
        let operator_id = PeerId::new();
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = TokenManager::new(cluster_id, vk);

        let first = mgr.mint_token(&operator_id, &sk, Duration::hours(1));
        let second = mgr.mint_token(&operator_id, &sk, Duration::hours(1));

        assert_ne!(first.token_id, second.token_id);
        assert_ne!(first.signature, second.signature);
        mgr.consume_token(&first);

        assert!(matches!(
            mgr.verify_token(&first),
            Err(TokenError::AlreadyConsumed)
        ));
        assert!(
            mgr.verify_token(&second).is_ok(),
            "consuming one rapidly minted token must not consume another"
        );
    }

    #[test]
    fn expired_token_rejected() {
        let cluster_id = ClusterId::new();
        let operator_id = PeerId::new();
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = TokenManager::new(cluster_id, vk);

        let token = mgr.mint_token(&operator_id, &sk, Duration::seconds(-1));
        assert!(matches!(mgr.verify_token(&token), Err(TokenError::Expired)));
    }

    #[test]
    fn forged_token_rejected() {
        // Any non-empty garbage or a token minted by a different operator key
        // must fail verification — this is the regression test for the old
        // `!signature.is_empty()` acceptance hole.
        let cluster_id = ClusterId::new();
        let operator_id = PeerId::new();
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = TokenManager::new(cluster_id, vk);

        let mut token = mgr.mint_token(&operator_id, &sk, Duration::hours(1));
        token.signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert!(matches!(
            mgr.verify_token(&token),
            Err(TokenError::InvalidSignature(_))
        ));

        let mut token = mgr.mint_token(&operator_id, &sk, Duration::hours(1));
        token.signature.clear();
        assert!(matches!(
            mgr.verify_token(&token),
            Err(TokenError::InvalidSignature(_))
        ));

        let (_other_sk, other_vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let wrong_key_mgr = TokenManager::new(token.cluster_id.clone(), other_vk);
        let token = mgr.mint_token(&operator_id, &sk, Duration::hours(1));
        assert!(matches!(
            wrong_key_mgr.verify_token(&token),
            Err(TokenError::InvalidSignature(_))
        ));
    }
}
