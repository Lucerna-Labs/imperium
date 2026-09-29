use std::sync::Arc;

use chrono::Utc;
use imperium_memory_log::MemoryLog;
use imperium_protocol::BusEvent;
use imperium_protocol::{
    EventId, ExtractionFailed, Message, SignatureCandidate, SignatureCandidatePending,
};
use imperium_store::Store;
use spiderweb::BusPublisher;
use uuid::Uuid;

use crate::topics;
use crate::StagingArea;

pub struct SignatureExtractor;

impl SignatureExtractor {
    pub fn extract_candidate(
        event_data: &[u8],
        source_events: &[EventId],
        description: &str,
    ) -> Option<SignatureCandidate> {
        let pattern_bytes = Self::extract_pattern(event_data)?;
        let rule_id = format!("extracted_{}", Uuid::new_v4().as_simple());
        let hex_string = pattern_bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let rule_text = format!(
            "rule {} {{ strings: $a = {{ {} }} condition: $a }}",
            rule_id, hex_string
        );

        Some(SignatureCandidate {
            id: Uuid::new_v4(),
            rule_text,
            description: description.to_string(),
            source_events: source_events.to_vec(),
            extracted_at: Utc::now(),
            confidence: Self::estimate_confidence(event_data),
        })
    }

    fn extract_pattern(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 4 {
            return None;
        }

        let mut pattern = Vec::new();
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let threshold = (data.len() as f64 * 0.1) as u32;
        for &byte in data {
            if counts[byte as usize] <= threshold.max(1) {
                pattern.push(byte);
            }
        }

        if pattern.len() >= 2 {
            pattern.truncate(32);
            Some(pattern)
        } else {
            None
        }
    }

    fn estimate_confidence(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let total = data.len() as f64;
        let mut entropy = 0.0f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }

        let max_entropy = (total.min(256.0)).log2();
        if max_entropy > 0.0 {
            (entropy / max_entropy).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

pub struct ExtractionLoop {
    bus: Arc<BusPublisher>,
    store: Arc<Store>,
    memory_log: Arc<MemoryLog>,
    staging: Arc<StagingArea>,
}

impl ExtractionLoop {
    pub fn new(
        bus: Arc<BusPublisher>,
        store: Arc<Store>,
        memory_log: Arc<MemoryLog>,
        staging: Arc<StagingArea>,
    ) -> Self {
        Self {
            bus,
            store,
            memory_log,
            staging,
        }
    }

    /// Handle one extraction request: pull the triggering events from the
    /// memory log, extract a candidate, persist it and stage it for review.
    ///
    /// This is the loop body and nothing else. It used to be driven by
    /// `ExtractionLoop::subscribe_extraction_requests`, a `tokio::spawn`ed recv
    /// loop; that task is gone and the method is now called from
    /// [`ExtractionStrand`](crate::ExtractionStrand), the supervised Spiderweb
    /// strand that replaced it (see `crate::strand` and
    /// the pilot (`imperium-net-lightcone`)). The signature is unchanged —
    /// only its caller is.
    pub(crate) fn handle_extraction_request(
        &self,
        triggering_event_ids: &[EventId],
        reason: &str,
        requested_by: &str,
    ) {
        let mut event_data = Vec::new();
        let mut found_ids = Vec::new();

        for event_id in triggering_event_ids {
            match self.memory_log.get_by_event_id(event_id) {
                Some(entry) => {
                    let serialized = match serde_json::to_vec(&entry.event.message) {
                        Ok(data) => data,
                        Err(e) => {
                            tracing::warn!(
                                event_id = %event_id.0,
                                error = %e,
                                "failed to serialize event message"
                            );
                            continue;
                        }
                    };
                    event_data.extend_from_slice(&serialized);
                    found_ids.push(event_id.clone());
                }
                None => {
                    tracing::warn!(
                        event_id = %event_id.0,
                        "event not found in memory log"
                    );
                }
            }
        }

        if found_ids.is_empty() {
            tracing::error!("no triggering events found in memory log");
            let _ = BusEvent::publish(
                &self.bus,
                topics::EXTRACTION_FAILED,
                Message::ExtractionFailed(ExtractionFailed {
                    triggering_event_ids: triggering_event_ids.to_vec(),
                    reason: "no triggering events found in memory log".into(),
                    failed_at: Utc::now(),
                }),
            );
            return;
        }

        let description = format!("{} (from {} events)", reason, found_ids.len());
        let candidate =
            match SignatureExtractor::extract_candidate(&event_data, &found_ids, &description) {
                Some(c) => c,
                None => {
                    tracing::warn!("extraction produced no candidate from event data");
                    let _ = BusEvent::publish(
                        &self.bus,
                        topics::EXTRACTION_FAILED,
                        Message::ExtractionFailed(ExtractionFailed {
                            triggering_event_ids: triggering_event_ids.to_vec(),
                            reason: "extraction produced no candidate pattern".into(),
                            failed_at: Utc::now(),
                        }),
                    );
                    return;
                }
            };

        let candidate_id = candidate.id;
        let key = format!("signature_candidate:{}", candidate_id);
        if let Err(e) = self
            .store
            .put(&key, serde_json::to_vec(&candidate).unwrap())
        {
            tracing::error!(error = %e, "failed to persist candidate to store");
            let _ = BusEvent::publish(
                &self.bus,
                topics::EXTRACTION_FAILED,
                Message::ExtractionFailed(ExtractionFailed {
                    triggering_event_ids: triggering_event_ids.to_vec(),
                    reason: format!("store persist failed: {}", e),
                    failed_at: Utc::now(),
                }),
            );
            return;
        }

        if let Err(e) = self.staging.submit(candidate) {
            tracing::error!(error = %e, "failed to submit candidate to staging");
            return;
        }

        let _ = BusEvent::publish(
            &self.bus,
            topics::CANDIDATE_PENDING,
            Message::SignatureCandidatePending(SignatureCandidatePending {
                candidate_id,
                requested_by: requested_by.to_string(),
                ready_at: Utc::now(),
            }),
        );

        tracing::info!(
            candidate_id = %candidate_id,
            "extraction complete — candidate persisted and submitted for review"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spiderweb::Bus;

    #[test]
    fn extracts_yara_rule_from_data() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let event_ids = vec![EventId::new()];
        let candidate = SignatureExtractor::extract_candidate(&data, &event_ids, "test pattern");
        assert!(candidate.is_some());
        let c = candidate.unwrap();
        assert!(c.rule_text.contains("rule extracted_"));
        assert!(c.rule_text.contains("strings:"));
        assert!(c.rule_text.contains("condition:"));
        assert!(c.confidence > 0.0);
    }

    #[test]
    fn rejects_too_short_data() {
        let data = vec![0x01, 0x02];
        let event_ids = vec![EventId::new()];
        let candidate = SignatureExtractor::extract_candidate(&data, &event_ids, "too short");
        assert!(candidate.is_none());
    }

    #[test]
    fn confidence_varies_with_entropy() {
        let low_entropy = vec![0u8; 100];
        let high_entropy: Vec<u8> = (0..100).map(|i| (i * 7 + 13) as u8).collect();

        let c_low = SignatureExtractor::estimate_confidence(&low_entropy);
        let c_high = SignatureExtractor::estimate_confidence(&high_entropy);

        assert!(c_high > c_low);
    }

    #[test]
    fn extracted_rule_compiles_in_yara() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let event_ids = vec![EventId::new()];
        let candidate = SignatureExtractor::extract_candidate(&data, &event_ids, "test").unwrap();

        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(candidate.rule_text.as_str())
            .expect("YARA rule should compile");
        let _rules = compiler.build();
    }

    /// Wire the extraction loop exactly as the node does: build the loop over
    /// the shared state, register its strand spec on the idle bus, and engage
    /// supervision (which installs the kernel's run loop, the strand worker and
    /// the spider on their own OS threads). Returns the handle so a test can
    /// stop the loop before its bus is dropped.
    fn supervise(
        bus: Bus,
        publisher: Arc<BusPublisher>,
        store: &Arc<Store>,
        memory_log: &Arc<MemoryLog>,
        staging: &Arc<StagingArea>,
    ) -> crate::test_supervision::Supervision {
        use crate::{ExtractionStrand, FaultPolicy};

        let extraction_loop = Arc::new(ExtractionLoop::new(
            Arc::clone(&publisher),
            Arc::clone(store),
            Arc::clone(memory_log),
            Arc::clone(staging),
        ));
        let mut bus = bus;
        bus.register_spec(ExtractionStrand::spec(extraction_loop, FaultPolicy::None));
        crate::test_supervision::Supervision::engage_with(bus, publisher)
    }

    #[tokio::test]
    async fn extraction_loop_produces_candidate_pending() {
        use imperium_protocol::{BusEvent, ExtractionRequest, StrainerRejection};

        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let store = Arc::new(Store::in_memory());
        let memory_log = Arc::new(MemoryLog::new(1000));
        let staging = Arc::new(StagingArea::new(Arc::clone(&publisher)));

        let event = BusEvent::new(
            "net.strainer.rejection",
            Message::StrainerRejection(StrainerRejection {
                strainer_id: "auth".into(),
                stack_id: "xray".into(),
                shape_failed: "oversized".into(),
                source_identifier: None,
                timestamp: Utc::now(),
            }),
        );
        let event_id = event.id.clone();
        memory_log.append(event);

        let mut pending_sub =
            crate::test_supervision::subscribe_queue(&publisher, topics::CANDIDATE_PENDING, 32);
        let mut supervision = supervise(bus, Arc::clone(&publisher), &store, &memory_log, &staging);

        BusEvent::publish(
            &publisher,
            topics::REQUEST,
            Message::ExtractionRequest(ExtractionRequest {
                triggering_event_ids: vec![event_id],
                reason: "suspicious pattern".into(),
                requested_by: "operator".into(),
            }),
        )
        .unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), pending_sub.recv())
            .await
            .unwrap()
            .unwrap();

        if let Message::SignatureCandidatePending(ref pending) = result.message {
            assert!(store.exists(&format!("signature_candidate:{}", pending.candidate_id)));
            assert_eq!(pending.requested_by, "operator");
            assert_eq!(staging.pending_count(), 1);
        } else {
            panic!(
                "expected SignatureCandidatePending, got {:?}",
                result.message
            );
        }

        supervision.shutdown();
    }

    #[tokio::test]
    async fn extraction_loop_missing_events_publishes_failure() {
        use imperium_protocol::ExtractionRequest;

        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let store = Arc::new(Store::in_memory());
        let memory_log = Arc::new(MemoryLog::new(1000));
        let staging = Arc::new(StagingArea::new(Arc::clone(&publisher)));

        let mut failure_sub =
            crate::test_supervision::subscribe_queue(&publisher, topics::EXTRACTION_FAILED, 32);
        let mut supervision = supervise(bus, Arc::clone(&publisher), &store, &memory_log, &staging);

        BusEvent::publish(
            &publisher,
            topics::REQUEST,
            Message::ExtractionRequest(ExtractionRequest {
                triggering_event_ids: vec![EventId::new()],
                reason: "nonexistent events".into(),
                requested_by: "operator".into(),
            }),
        )
        .unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), failure_sub.recv())
            .await
            .unwrap()
            .unwrap();

        if let Message::ExtractionFailed(ref failed) = result.message {
            assert!(failed.reason.contains("no triggering events"));
        } else {
            panic!("expected ExtractionFailed, got {:?}", result.message);
        }

        supervision.shutdown();
    }
}
