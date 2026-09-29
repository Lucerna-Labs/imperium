use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_net_crypto::{
    HybridEd25519Mldsa, HybridSignature, HybridSigningKey, HybridVerifyingKey,
};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    ClusterId, ConfigurationFetchRequest, ConfigurationFetchResponse, ConfigurationVersion,
    Message, PeerId,
};
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("version conflict: local {local} vs remote {remote}")]
    VersionConflict { local: u64, remote: u64 },
    #[error("stale configuration (version {0})")]
    StaleVersion(u64),
    #[error("config signature invalid (not operator-signed)")]
    InvalidSignature,
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

#[derive(Clone, Debug)]
pub struct ClusterConfig {
    pub cluster_id: ClusterId,
    pub version: u64,
    pub lamport_clock: u64,
    pub data: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub updated_by: PeerId,
    pub updated_at: DateTime<Utc>,
}

pub struct ConfigManager {
    cluster_id: ClusterId,
    local_peer_id: PeerId,
    operator_vk: HybridVerifyingKey,
    current: Arc<RwLock<Option<ClusterConfig>>>,
    lamport_clock: Arc<RwLock<u64>>,
    /// Fetched configs this manager has *applied* (verified only), for
    /// observability. The supervised strand uses it to prove the replay guard:
    /// a replayed fetch response must not move this counter a second time.
    /// Nothing in the state machine reads it.
    applied_configs: AtomicU64,
}

impl ConfigManager {
    pub fn new(
        cluster_id: ClusterId,
        local_peer_id: PeerId,
        operator_vk: HybridVerifyingKey,
    ) -> Self {
        Self {
            cluster_id,
            local_peer_id,
            operator_vk,
            current: Arc::new(RwLock::new(None)),
            lamport_clock: Arc::new(RwLock::new(0)),
            applied_configs: AtomicU64::new(0),
        }
    }

    pub fn update_config(
        &self,
        data: Vec<u8>,
        signing_key: &HybridSigningKey,
        bus: &BusPublisher,
    ) -> Result<u64, ConfigError> {
        // Only the operator key may author configs: verify the provided
        // signing key derives the stored operator VK. Comparison is over
        // public encodings only — no key material in the check.
        let candidate_vk = HybridEd25519Mldsa::verifying_key(signing_key);
        if candidate_vk.ed25519_vk != self.operator_vk.ed25519_vk
            || candidate_vk.mldsa_vk != self.operator_vk.mldsa_vk
        {
            return Err(ConfigError::InvalidSignature);
        }
        let mut clock = self.lamport_clock.write();
        *clock += 1;
        let new_clock = *clock;
        drop(clock);

        let mut current = self.current.write();
        let new_version = current.as_ref().map(|c| c.version + 1).unwrap_or(1);

        let config_hash = sha2_hash(&data);

        let config = ClusterConfig {
            cluster_id: self.cluster_id.clone(),
            version: new_version,
            lamport_clock: new_clock,
            data: data.clone(),
            config_hash: config_hash.clone(),
            updated_by: self.local_peer_id.clone(),
            updated_at: Utc::now(),
        };

        *current = Some(config);
        drop(current);

        let version_msg = ConfigurationVersion {
            cluster_id: self.cluster_id.clone(),
            version: new_version,
            lamport_clock: new_clock,
            config_hash,
            updated_by: self.local_peer_id.clone(),
            updated_at: Utc::now(),
        };

        BusEvent::publish(
            bus,
            "net.cluster.config.updated",
            Message::ConfigVersion(version_msg),
        )?;

        Ok(new_version)
    }

    pub fn current_version(&self) -> u64 {
        self.current.read().as_ref().map(|c| c.version).unwrap_or(0)
    }

    pub fn current_config(&self) -> Option<ClusterConfig> {
        self.current.read().clone()
    }

    pub fn handle_version_announcement(&self, version: &ConfigurationVersion) -> bool {
        let current_version = self.current_version();
        version.version > current_version
    }

    pub fn request_config(&self, bus: &BusPublisher) -> Result<(), ConfigError> {
        let req = ConfigurationFetchRequest {
            cluster_id: self.cluster_id.clone(),
            from_peer: self.local_peer_id.clone(),
            known_version: self.current_version(),
        };

        BusEvent::publish(
            bus,
            "net.cluster.config.fetch_request",
            Message::ConfigFetchReq(req),
        )?;

        Ok(())
    }

    pub fn handle_fetch_request(
        &self,
        req: &ConfigurationFetchRequest,
        signing_key: &HybridSigningKey,
        bus: &BusPublisher,
    ) -> Result<(), ConfigError> {
        if req.known_version >= self.current_version() {
            return Ok(());
        }

        let config = match self.current_config() {
            Some(c) => c,
            None => return Ok(()),
        };

        let sig = Self::sign_config(&config.data, config.version, signing_key);

        let resp = ConfigurationFetchResponse {
            cluster_id: self.cluster_id.clone(),
            version: config.version,
            config_data: config.data,
            signature: sig.to_bytes(),
        };

        BusEvent::publish(
            bus,
            "net.cluster.config.fetch_response",
            Message::ConfigFetchResp(resp),
        )?;

        Ok(())
    }

    pub fn apply_fetched_config(
        &self,
        resp: &ConfigurationFetchResponse,
    ) -> Result<(), ConfigError> {
        if resp.version <= self.current_version() {
            return Err(ConfigError::StaleVersion(resp.version));
        }

        // Verify the operator's hybrid signature over (data || version) —
        // the same payload layout handle_fetch_request signs. Fail-closed.
        let mut payload = Vec::new();
        payload.extend_from_slice(&resp.config_data);
        payload.extend_from_slice(&resp.version.to_le_bytes());
        let signature = HybridSignature::from_bytes(&resp.signature)
            .map_err(|_| ConfigError::InvalidSignature)?;
        HybridEd25519Mldsa::verify(&self.operator_vk, &payload, &signature)
            .map_err(|_| ConfigError::InvalidSignature)?;

        let config_hash = sha2_hash(&resp.config_data);

        let config = ClusterConfig {
            cluster_id: resp.cluster_id.clone(),
            version: resp.version,
            lamport_clock: {
                let mut clock = self.lamport_clock.write();
                *clock += 1;
                *clock
            },
            data: resp.config_data.clone(),
            config_hash,
            updated_by: self.local_peer_id.clone(),
            updated_at: Utc::now(),
        };

        *self.current.write() = Some(config);
        self.applied_configs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// How many fetched configurations this manager has successfully applied.
    ///
    /// Observability only — the supervised strand
    /// [`crate::ConfigResponseStrand`] and its tests use it to prove that a
    /// replayed response is *not* applied a second time. No decision reads it.
    pub fn applied_configs(&self) -> u64 {
        self.applied_configs.load(Ordering::Relaxed)
    }

    /// Sign (data || version) for a fetch response. Shared helper so the
    /// operator node and tests produce exactly the payload layout that
    /// `apply_fetched_config` verifies.
    pub fn sign_config(
        data: &[u8],
        version: u64,
        signing_key: &HybridSigningKey,
    ) -> imperium_net_crypto::HybridSignature {
        let mut payload = Vec::new();
        payload.extend_from_slice(data);
        payload.extend_from_slice(&version.to_le_bytes());
        HybridEd25519Mldsa::sign(signing_key, &payload)
    }
}

fn sha2_hash(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use spiderweb::Bus;

    #[test]
    fn config_versioning() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());

        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = ConfigManager::new(cluster_id, local, vk);

        assert_eq!(mgr.current_version(), 0);

        let v1 = mgr
            .update_config(b"config-v1".to_vec(), &sk, &publisher)
            .unwrap();
        assert_eq!(v1, 1);
        assert_eq!(mgr.current_version(), 1);

        let v2 = mgr
            .update_config(b"config-v2".to_vec(), &sk, &publisher)
            .unwrap();
        assert_eq!(v2, 2);
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

    /// The bus path is the supervised strand now: a verified response is applied,
    /// and the strand is live while doing it (not an idle loop that would make
    /// the assertion below vacuous).
    #[tokio::test]
    async fn supervised_config_strand_applies_verified_responses() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = Arc::new(ConfigManager::new(cluster_id.clone(), local, vk));

        // The old `subscribe_config_responses` shim did two things: wire this
        // manager into the bus's links registry, and queue the crate's strand
        // specs. Both are explicit now.
        crate::attach_config(&publisher, &mgr);
        let mut bus = bus;
        crate::register_strands(&mut bus, &publisher);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        let data = b"new-config".to_vec();
        let resp = ConfigurationFetchResponse {
            cluster_id: cluster_id.clone(),
            version: 1,
            config_data: data.clone(),
            signature: ConfigManager::sign_config(&data, 1, &sk).to_bytes(),
        };

        BusEvent::publish(
            &publisher,
            crate::topics::CONFIG_FETCH_RESPONSE,
            Message::ConfigFetchResp(resp),
        )
        .unwrap();

        wait_until("the fetched config to be applied", || {
            mgr.current_version() == 1
        });

        assert_eq!(mgr.applied_configs(), 1);
        assert_eq!(mgr.current_config().unwrap().data, data);
        supervision.shutdown();
    }

    /// A fabricated signature must still be rejected through the strand: the old
    /// test published signature vec![1,2,3] and expected acceptance, and the
    /// fail-closed path must survive the conversion.
    #[tokio::test]
    async fn supervised_config_strand_rejects_forged_responses() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = Arc::new(ConfigManager::new(cluster_id.clone(), local, vk));

        // The old `subscribe_config_responses` shim did two things: wire this
        // manager into the bus's links registry, and queue the crate's strand
        // specs. Both are explicit now.
        crate::attach_config(&publisher, &mgr);
        let mut bus = bus;
        crate::register_strands(&mut bus, &publisher);
        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        BusEvent::publish(
            &publisher,
            crate::topics::CONFIG_FETCH_RESPONSE,
            Message::ConfigFetchResp(ConfigurationFetchResponse {
                cluster_id: cluster_id.clone(),
                version: 1,
                config_data: b"forged-config".to_vec(),
                signature: vec![1, 2, 3],
            }),
        )
        .unwrap();

        // The control: a real, operator-signed response for the same version.
        // Applying it proves the strand is live, so the forged one was rejected
        // by the signature check rather than skipped by an idle loop.
        let data = b"real-config".to_vec();
        BusEvent::publish(
            &publisher,
            crate::topics::CONFIG_FETCH_RESPONSE,
            Message::ConfigFetchResp(ConfigurationFetchResponse {
                cluster_id: cluster_id.clone(),
                version: 1,
                config_data: data.clone(),
                signature: ConfigManager::sign_config(&data, 1, &sk).to_bytes(),
            }),
        )
        .unwrap();

        wait_until("the verified config to be applied", || {
            mgr.current_version() == 1
        });
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Exactly one application happened, and it was the signed response: the
        // forged data must never have reached the current config.
        assert_eq!(
            mgr.applied_configs(),
            1,
            "only the operator-signed response may be applied"
        );
        assert_eq!(mgr.current_config().unwrap().data, data);
        supervision.shutdown();
    }

    #[test]
    fn stale_config_rejected() {
        let cluster_id = ClusterId::new();
        let local = PeerId::new();
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());

        let mut rng = OsRng;
        let (sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
        let mgr = ConfigManager::new(cluster_id.clone(), local, vk);

        mgr.update_config(b"config-v1".to_vec(), &sk, &publisher)
            .unwrap();

        let stale_resp = ConfigurationFetchResponse {
            cluster_id,
            version: 0,
            config_data: b"old".to_vec(),
            signature: vec![1, 2, 3],
        };

        assert!(mgr.apply_fetched_config(&stale_resp).is_err());
    }
}
