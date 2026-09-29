use std::sync::Arc;

use chrono::Utc;
use imperium_net_crypto::{HybridEd25519Mldsa, HybridSignature, HybridVerifyingKey};
use imperium_net_signatures::{SignatureDatabase, SignatureEntry, SignatureProvenance};
use imperium_protocol::BusEvent;
use imperium_protocol::{
    ExtractedSignatureActivated, Message, SignatureActivationFailed, SignatureApproved,
    SignatureCandidate, SuggestedAction, ThreatAssessment, ThreatSource,
};
use imperium_store::Store;
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SignatureEngineError {
    #[error("no signatures loaded")]
    NoSignatures,
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
    #[error("yara compile error: {0}")]
    YaraCompile(String),
    #[error("yara scan error: {0}")]
    YaraScan(String),
}

#[derive(Clone, Debug)]
pub struct SignatureRule {
    pub id: String,
    pub rule_text: String,
    pub description: String,
    pub layer: SignatureLayer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureLayer {
    Bundled,
    Extracted,
}

pub struct SignatureEngineSensor {
    bundled_rules: Arc<RwLock<Vec<SignatureRule>>>,
    extracted_rules: Arc<RwLock<Vec<SignatureRule>>>,
    bus: Arc<BusPublisher>,
    store: Option<Arc<Store>>,
    operator_verify_key: Option<Arc<HybridVerifyingKey>>,
    database: Option<Arc<SignatureDatabase>>,
}

impl SignatureEngineSensor {
    pub fn new(bus: Arc<BusPublisher>) -> Self {
        Self {
            bundled_rules: Arc::new(RwLock::new(Vec::new())),
            extracted_rules: Arc::new(RwLock::new(Vec::new())),
            bus,
            store: None,
            operator_verify_key: None,
            database: None,
        }
    }

    pub fn with_store(mut self, store: Store) -> Self {
        self.store = Some(Arc::new(store));
        self
    }

    pub fn with_shared_store(mut self, store: Arc<Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Verify key for operator approvals (persisted operator identity from
    /// 1C). Without it the engine refuses activation fail-closed.
    pub fn with_operator_verify_key(mut self, key: Arc<HybridVerifyingKey>) -> Self {
        self.operator_verify_key = Some(key);
        self
    }

    /// Auditable database the activated rule is also routed through, so the
    /// live engine vec and the database cannot diverge.
    pub fn with_database(mut self, database: Arc<SignatureDatabase>) -> Self {
        self.database = Some(database);
        self
    }

    pub fn load_bundled_rules(&self, rules: Vec<SignatureRule>) {
        *self.bundled_rules.write() = rules;
        tracing::info!(
            count = self.bundled_count(),
            "loaded bundled signature rules"
        );
    }

    pub fn load_extracted_rules(&self, rules: Vec<SignatureRule>) {
        *self.extracted_rules.write() = rules;
        tracing::info!(
            count = self.extracted_count(),
            "loaded extracted signature rules"
        );
    }

    pub fn add_extracted_rule(&self, rule: SignatureRule) {
        self.extracted_rules.write().push(rule);
    }

    pub fn remove_extracted_rule(&self, id: &str) -> bool {
        let mut rules = self.extracted_rules.write();
        let before = rules.len();
        rules.retain(|r| r.id != id);
        rules.len() < before
    }

    pub fn scan(&self, data: &[u8]) -> Result<Vec<ThreatAssessment>, SignatureEngineError> {
        let all_rules: Vec<SignatureRule> = {
            let bundled = self.bundled_rules.read();
            let extracted = self.extracted_rules.read();
            bundled.iter().chain(extracted.iter()).cloned().collect()
        };

        if all_rules.is_empty() {
            return Ok(Vec::new());
        }

        let mut compiler = yara_x::Compiler::new();
        let mut rule_map: Vec<(String, String)> = Vec::new();

        for rule in &all_rules {
            if let Err(e) = compiler.add_source(rule.rule_text.as_str()) {
                tracing::warn!(rule_id = %rule.id, error = %e, "failed to compile YARA rule, skipping");
                continue;
            }
            rule_map.push((rule.id.clone(), rule.description.clone()));
        }

        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);
        let scan_results = scanner
            .scan(data)
            .map_err(|e| SignatureEngineError::YaraScan(e.to_string()))?;

        let mut matches = Vec::new();
        for matched_rule in scan_results.matching_rules() {
            let rule_name = matched_rule.identifier();
            let description = rule_map
                .iter()
                .find(|(id, _)| id == rule_name)
                .map(|(_, d)| d.clone())
                .unwrap_or_else(|| format!("YARA match: {}", rule_name));

            let assessment = ThreatAssessment {
                source: ThreatSource::SignatureEngine,
                confidence: 1.0,
                description,
                remote_addr: None,
                timestamp: Utc::now(),
                suggested_action: SuggestedAction::TriggerFailover,
            };

            let _ = BusEvent::publish(
                &self.bus,
                "net.sensors.signature_match",
                Message::ThreatAssessment(assessment.clone()),
            );

            matches.push(assessment);
        }

        Ok(matches)
    }

    pub fn bundled_count(&self) -> usize {
        self.bundled_rules.read().len()
    }

    pub fn extracted_count(&self) -> usize {
        self.extracted_rules.read().len()
    }

    pub fn total_rules(&self) -> usize {
        self.bundled_count() + self.extracted_count()
    }

    /// Verify-before-activate, then compile and load the rule. Called by the
    /// supervised strand (see [`crate::strand`]) for every **new**
    /// `net.signatures.approved` event; unchanged from the `tokio::spawn` days,
    /// including the topics it publishes on.
    pub(crate) fn activate_candidate(&self, approved: &SignatureApproved) {
        let candidate_id = approved.candidate_id;
        let store = match &self.store {
            Some(s) => s,
            None => {
                tracing::error!(
                    candidate_id = %candidate_id,
                    "no store configured — cannot fetch candidate for activation"
                );
                self.publish_activation_failed(candidate_id, "no store configured".into());
                return;
            }
        };

        let key = format!("signature_candidate:{}", candidate_id);
        let raw = match store.get(&key) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(
                    candidate_id = %candidate_id,
                    error = %e,
                    "failed to fetch candidate from store"
                );
                self.publish_activation_failed(candidate_id, format!("store fetch failed: {}", e));
                return;
            }
        };

        let candidate: SignatureCandidate = match serde_json::from_slice(&raw) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    candidate_id = %candidate_id,
                    error = %e,
                    "failed to deserialize candidate"
                );
                self.publish_activation_failed(
                    candidate_id,
                    format!("deserialization failed: {}", e),
                );
                return;
            }
        };

        // Verify-before-activate (1D): the approval signature must cover the
        // stored candidate rule_text under the persisted operator verify key.
        // Fail closed — a forged or unverifiable approval never loads.
        let verify_key = match &self.operator_verify_key {
            Some(k) => k,
            None => {
                tracing::error!(
                    candidate_id = %candidate_id,
                    "no operator verify key configured — refusing activation"
                );
                self.publish_activation_failed(
                    candidate_id,
                    "no operator verify key configured".into(),
                );
                return;
            }
        };
        let signature = match HybridSignature::from_bytes(&approved.signature) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    candidate_id = %candidate_id,
                    error = %e,
                    "approval carries a malformed signature"
                );
                self.publish_activation_failed(
                    candidate_id,
                    format!("malformed approval signature: {}", e),
                );
                return;
            }
        };
        if let Err(e) =
            HybridEd25519Mldsa::verify(verify_key, candidate.rule_text.as_bytes(), &signature)
        {
            tracing::warn!(
                candidate_id = %candidate_id,
                error = %e,
                "approval signature verification failed — refusing activation"
            );
            self.publish_activation_failed(
                candidate_id,
                format!("approval signature verification failed: {}", e),
            );
            return;
        }

        let mut compiler = yara_x::Compiler::new();
        if let Err(e) = compiler.add_source(candidate.rule_text.as_str()) {
            tracing::warn!(
                candidate_id = %candidate_id,
                error = %e,
                "YARA rule failed to compile"
            );
            self.publish_activation_failed(candidate_id, format!("YARA compile error: {}", e));
            return;
        }
        let _rules = compiler.build();

        let signature_id = Uuid::new_v4();
        let rule_id = format!("extracted_{}", candidate_id);
        let rule = SignatureRule {
            id: rule_id.clone(),
            rule_text: candidate.rule_text.clone(),
            description: candidate.description.clone(),
            layer: SignatureLayer::Extracted,
        };
        self.add_extracted_rule(rule);

        // Route through the auditable database too, so the live engine vec
        // and the database cannot diverge. A duplicate (re-approval) is
        // logged, not fatal — the engine already holds the rule.
        if let Some(database) = &self.database {
            let entry = SignatureEntry {
                id: rule_id,
                rule_text: candidate.rule_text,
                description: candidate.description,
                provenance: SignatureProvenance::Extracted {
                    extracted_at: Utc::now(),
                    approved_by: approved.approved_by.0.to_string(),
                },
                added_at: Utc::now(),
                active: true,
            };
            if let Err(e) = database.add_extracted(entry) {
                tracing::warn!(
                    candidate_id = %candidate_id,
                    error = %e,
                    "activated rule already present in signature database"
                );
            }
        }

        tracing::info!(
            candidate_id = %candidate_id,
            signature_id = %signature_id,
            "signature activated — rule loaded into engine"
        );

        let _ = BusEvent::publish(
            &self.bus,
            "net.signatures.activated",
            Message::SignatureActivated(ExtractedSignatureActivated {
                candidate_id,
                signature_id,
                activated_at: Utc::now(),
            }),
        );
    }

    fn publish_activation_failed(&self, candidate_id: Uuid, compile_error: String) {
        let _ = BusEvent::publish(
            &self.bus,
            "net.signatures.activation_failed",
            Message::SignatureActivationFailed(SignatureActivationFailed {
                candidate_id,
                compile_error,
                failed_at: Utc::now(),
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_crypto::{HybridEd25519Mldsa, HybridSigningKey};
    use imperium_protocol::PeerId;
    use rand::rngs::OsRng;

    fn test_engine() -> SignatureEngineSensor {
        // No supervision: this engine only publishes.
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        SignatureEngineSensor::new(bus)
    }

    struct KeyedParts {
        engine: Arc<SignatureEngineSensor>,
        database: Arc<SignatureDatabase>,
        signing_key: HybridSigningKey,
        operator: PeerId,
    }

    /// Build an engine with a real operator keypair + database.
    /// Key generation runs on a 64 MiB-stack thread: ML-DSA-65 keygen
    /// allocates ~8KB+ on the stack and two keypairs in one test overflow
    /// the default 8 MiB test-thread stack.
    fn keyed_engine(bus: Arc<BusPublisher>, store: Store) -> KeyedParts {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let mut rng = OsRng;
                let (signing_key, verify_key) = HybridEd25519Mldsa::generate_keypair(&mut rng);
                let operator = PeerId::new();
                let database = Arc::new(SignatureDatabase::new());
                let engine = Arc::new(
                    SignatureEngineSensor::new(bus)
                        .with_store(store)
                        .with_operator_verify_key(Arc::new(verify_key.clone()))
                        .with_database(Arc::clone(&database)),
                );
                KeyedParts {
                    engine,
                    database,
                    signing_key,
                    operator,
                }
            })
            .unwrap()
            .join()
            .unwrap()
    }

    /// Sign on a big-stack thread too (ML-DSA signing is also stack-heavy).
    fn sign_approval(
        signing_key: HybridSigningKey,
        operator: PeerId,
        candidate_id: Uuid,
        rule_text: &str,
    ) -> SignatureApproved {
        let rule_text = rule_text.to_string();
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let sig = HybridEd25519Mldsa::sign(&signing_key, rule_text.as_bytes());
                SignatureApproved {
                    candidate_id,
                    approved_by: operator,
                    approved_at: chrono::Utc::now(),
                    signature: sig.to_bytes(),
                }
            })
            .unwrap()
            .join()
            .unwrap()
    }

    fn deadbeef_rule() -> SignatureRule {
        SignatureRule {
            id: "deadbeef".into(),
            rule_text: r#"rule deadbeef { strings: $a = { DE AD BE EF } condition: $a }"#.into(),
            description: "deadbeef pattern".into(),
            layer: SignatureLayer::Bundled,
        }
    }

    /// Start the engine's approval loop the way the composition root does: queue
    /// the strand **spec** first, then engage the kernel (a spec queued after
    /// engage could never be installed).
    ///
    /// The policy is explicitly [`FaultPolicy::None`] here, so the crate's tests
    /// never depend on the process environment; the production entry point is
    /// [`SignatureEngineSensor::register_strand`], which reads the drill policy
    /// from the env and warns when one is armed.
    fn supervise(
        engine: &Arc<SignatureEngineSensor>,
        kernel: spiderweb::Bus,
        publisher: Arc<BusPublisher>,
    ) -> crate::test_supervision::Supervision {
        let mut kernel = kernel;
        kernel.register_spec(engine.strand_spec(crate::strand::FaultPolicy::None));
        crate::test_supervision::Supervision::engage_with(kernel, publisher)
    }

    #[test]
    fn loads_bundled_rules() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);
        assert_eq!(engine.bundled_count(), 1);
    }

    #[test]
    fn matches_yara_pattern() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);

        let data = vec![0x00, 0x01, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF];
        let matches = engine.scan(&data).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, 1.0);
    }

    #[test]
    fn no_match_returns_empty() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);

        let matches = engine.scan(&[0x00, 0x01, 0x02]).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn extracted_rules_separate_from_bundled() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![SignatureRule {
            id: "b1".into(),
            rule_text: r#"rule b1 { strings: $a = { AA } condition: $a }"#.into(),
            description: "bundled".into(),
            layer: SignatureLayer::Bundled,
        }]);
        engine.add_extracted_rule(SignatureRule {
            id: "e1".into(),
            rule_text: r#"rule e1 { strings: $a = { BB } condition: $a }"#.into(),
            description: "extracted".into(),
            layer: SignatureLayer::Extracted,
        });

        assert_eq!(engine.bundled_count(), 1);
        assert_eq!(engine.extracted_count(), 1);
        assert_eq!(engine.total_rules(), 2);

        engine.remove_extracted_rule("e1");
        assert_eq!(engine.extracted_count(), 0);
        assert_eq!(engine.bundled_count(), 1);
    }

    #[test]
    fn scan_with_both_rule_layers() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![SignatureRule {
            id: "bundled_rule".into(),
            rule_text: r#"rule bundled_rule { strings: $a = { AA BB } condition: $a }"#.into(),
            description: "bundled match".into(),
            layer: SignatureLayer::Bundled,
        }]);
        engine.add_extracted_rule(SignatureRule {
            id: "extracted_rule".into(),
            rule_text: r#"rule extracted_rule { strings: $a = { CC DD } condition: $a }"#.into(),
            description: "extracted match".into(),
            layer: SignatureLayer::Extracted,
        });

        let data = vec![0xAA, 0xBB, 0x00, 0xCC, 0xDD];
        let matches = engine.scan(&data).unwrap();
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn scan_empty_data_no_matches() {
        let engine = test_engine();
        engine.load_bundled_rules(vec![deadbeef_rule()]);
        let matches = engine.scan(&[]).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn scan_no_rules_returns_empty() {
        let engine = test_engine();
        let matches = engine.scan(&[0xDE, 0xAD]).unwrap();
        assert!(matches.is_empty());
    }

    #[tokio::test]
    async fn two_phase_activation_valid_rule() {
        use imperium_protocol::{EventId, SignatureCandidate};
        use imperium_store::Store;
        use uuid::Uuid;

        let (kernel, bus) = crate::test_supervision::open();
        let store = Store::in_memory();

        let candidate_id = Uuid::new_v4();
        let rule_text =
            r#"rule activated_test { strings: $a = { CA FE } condition: $a }"#.to_string();
        let candidate = SignatureCandidate {
            id: candidate_id,
            rule_text: rule_text.clone(),
            description: "two-phase test".into(),
            source_events: vec![EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.9,
        };
        let key = format!("signature_candidate:{}", candidate_id);
        store
            .put(&key, serde_json::to_vec(&candidate).unwrap())
            .unwrap();

        let parts = keyed_engine(Arc::clone(&bus), store);

        let mut activation_sub =
            crate::test_supervision::subscribe_queue(&bus, "net.signatures.activated", 64);
        // The approval loop is the supervised strand now, started the way the
        // composition root starts it (`register_strand` spec, then engage).
        let mut supervision = supervise(&parts.engine, kernel, Arc::clone(&bus));

        let approval = sign_approval(parts.signing_key, parts.operator, candidate_id, &rule_text);
        BusEvent::publish(
            &bus,
            "net.signatures.approved",
            Message::SignatureApproved(approval),
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), activation_sub.recv())
            .await
            .unwrap()
            .unwrap();
        supervision.shutdown();

        if let Message::SignatureActivated(activated) = event.message {
            assert_eq!(activated.candidate_id, candidate_id);
        } else {
            panic!("expected SignatureActivated message");
        }

        assert_eq!(parts.engine.extracted_count(), 1);
        // Auditable database and live engine vec must agree.
        assert_eq!(parts.database.extracted_count(), 1);

        let data = vec![0xCA, 0xFE];
        let matches = parts.engine.scan(&data).unwrap();
        assert_eq!(matches.len(), 1);
    }

    #[tokio::test]
    async fn activation_rejects_forged_approval() {
        use imperium_protocol::{EventId, PeerId, SignatureApproved, SignatureCandidate};
        use imperium_store::Store;
        use uuid::Uuid;

        let (kernel, bus) = crate::test_supervision::open();
        let store = Store::in_memory();

        let candidate_id = Uuid::new_v4();
        let rule_text = r#"rule forged_test { strings: $a = { DE AD } condition: $a }"#.to_string();
        let candidate = SignatureCandidate {
            id: candidate_id,
            rule_text: rule_text.clone(),
            description: "forged approval test".into(),
            source_events: vec![EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.9,
        };
        let key = format!("signature_candidate:{}", candidate_id);
        store
            .put(&key, serde_json::to_vec(&candidate).unwrap())
            .unwrap();

        let parts = keyed_engine(Arc::clone(&bus), store);

        let mut failure_sub =
            crate::test_supervision::subscribe_queue(&bus, "net.signatures.activation_failed", 64);
        let mut supervision = supervise(&parts.engine, kernel, Arc::clone(&bus));

        // Forge: sign DIFFERENT bytes than the stored rule_text, and also
        // try a raw garbage signature. Both must be refused.
        let forged = sign_approval(
            parts.signing_key,
            parts.operator.clone(),
            candidate_id,
            "rule something_else { strings: $a = { BE EF } condition: $a }",
        );
        BusEvent::publish(
            &bus,
            "net.signatures.approved",
            Message::SignatureApproved(forged),
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), failure_sub.recv())
            .await
            .unwrap()
            .unwrap();
        if let Message::SignatureActivationFailed(failed) = event.message {
            assert_eq!(failed.candidate_id, candidate_id);
            assert!(failed.compile_error.contains("verification failed"));
        } else {
            panic!("expected SignatureActivationFailed for forged approval");
        }
        assert_eq!(parts.engine.extracted_count(), 0);
        assert_eq!(parts.database.extracted_count(), 0);

        // Garbage bytes are equally refused (no rule loaded).
        BusEvent::publish(
            &bus,
            "net.signatures.approved",
            Message::SignatureApproved(SignatureApproved {
                candidate_id,
                approved_by: PeerId::new(),
                approved_at: chrono::Utc::now(),
                signature: vec![0xFF; 16],
            }),
        )
        .unwrap();
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), failure_sub.recv())
            .await
            .unwrap()
            .unwrap();
        supervision.shutdown();
        assert!(matches!(
            event.message,
            Message::SignatureActivationFailed(_)
        ));
        assert_eq!(parts.engine.extracted_count(), 0);
        assert_eq!(parts.database.extracted_count(), 0);
    }

    #[tokio::test]
    async fn activation_without_verify_key_refuses() {
        use imperium_protocol::{EventId, PeerId, SignatureApproved, SignatureCandidate};
        use imperium_store::Store;
        use uuid::Uuid;

        let (kernel, bus) = crate::test_supervision::open();
        let store = Store::in_memory();

        let candidate_id = Uuid::new_v4();
        let candidate = SignatureCandidate {
            id: candidate_id,
            rule_text: r#"rule nokey_test { strings: $a = { AA } condition: $a }"#.into(),
            description: "no verify key".into(),
            source_events: vec![EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.9,
        };
        let key = format!("signature_candidate:{}", candidate_id);
        store
            .put(&key, serde_json::to_vec(&candidate).unwrap())
            .unwrap();

        // No verify key configured: fail closed.
        let engine = Arc::new(SignatureEngineSensor::new(Arc::clone(&bus)).with_store(store));
        let mut failure_sub =
            crate::test_supervision::subscribe_queue(&bus, "net.signatures.activation_failed", 64);
        let mut supervision = supervise(&engine, kernel, Arc::clone(&bus));

        BusEvent::publish(
            &bus,
            "net.signatures.approved",
            Message::SignatureApproved(SignatureApproved {
                candidate_id,
                approved_by: PeerId::new(),
                approved_at: chrono::Utc::now(),
                signature: vec![1, 2, 3],
            }),
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), failure_sub.recv())
            .await
            .unwrap()
            .unwrap();
        supervision.shutdown();
        if let Message::SignatureActivationFailed(failed) = event.message {
            assert_eq!(failed.candidate_id, candidate_id);
            assert!(failed.compile_error.contains("verify key"));
        } else {
            panic!("expected SignatureActivationFailed without verify key");
        }
        assert_eq!(engine.extracted_count(), 0);
    }

    #[tokio::test]
    async fn two_phase_activation_invalid_rule_publishes_failure() {
        use imperium_protocol::{EventId, SignatureCandidate};
        use imperium_store::Store;
        use uuid::Uuid;

        let (kernel, bus) = crate::test_supervision::open();
        let store = Store::in_memory();

        let candidate_id = Uuid::new_v4();
        let rule_text = "rule bad_syntax { this is not valid yara }".to_string();
        let candidate = SignatureCandidate {
            id: candidate_id,
            rule_text: rule_text.clone(),
            description: "bad rule".into(),
            source_events: vec![EventId::new()],
            extracted_at: chrono::Utc::now(),
            confidence: 0.5,
        };
        let key = format!("signature_candidate:{}", candidate_id);
        store
            .put(&key, serde_json::to_vec(&candidate).unwrap())
            .unwrap();

        let parts = keyed_engine(Arc::clone(&bus), store);

        let mut failure_sub =
            crate::test_supervision::subscribe_queue(&bus, "net.signatures.activation_failed", 64);
        let mut supervision = supervise(&parts.engine, kernel, Arc::clone(&bus));

        let approval = sign_approval(parts.signing_key, parts.operator, candidate_id, &rule_text);
        BusEvent::publish(
            &bus,
            "net.signatures.approved",
            Message::SignatureApproved(approval),
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), failure_sub.recv())
            .await
            .unwrap()
            .unwrap();
        supervision.shutdown();

        if let Message::SignatureActivationFailed(failed) = event.message {
            assert_eq!(failed.candidate_id, candidate_id);
            assert!(!failed.compile_error.is_empty());
        } else {
            panic!("expected SignatureActivationFailed message");
        }

        assert_eq!(parts.engine.extracted_count(), 0);
    }

    #[tokio::test]
    async fn two_phase_activation_missing_candidate_publishes_failure() {
        use imperium_protocol::{PeerId, SignatureApproved};
        use imperium_store::Store;
        use uuid::Uuid;

        let (kernel, bus) = crate::test_supervision::open();
        let store = Store::in_memory();
        let engine = Arc::new(SignatureEngineSensor::new(Arc::clone(&bus)).with_store(store));

        let mut failure_sub =
            crate::test_supervision::subscribe_queue(&bus, "net.signatures.activation_failed", 64);
        let mut supervision = supervise(&engine, kernel, Arc::clone(&bus));

        let candidate_id = Uuid::new_v4();
        BusEvent::publish(
            &bus,
            "net.signatures.approved",
            Message::SignatureApproved(SignatureApproved {
                candidate_id,
                approved_by: PeerId::new(),
                approved_at: chrono::Utc::now(),
                signature: vec![],
            }),
        )
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), failure_sub.recv())
            .await
            .unwrap()
            .unwrap();
        supervision.shutdown();

        if let Message::SignatureActivationFailed(failed) = event.message {
            assert_eq!(failed.candidate_id, candidate_id);
            assert!(failed.compile_error.contains("store fetch failed"));
        } else {
            panic!("expected SignatureActivationFailed message");
        }
    }
}
