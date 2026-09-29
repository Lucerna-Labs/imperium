use imperium_protocol::{SuggestedAction, ThreatAssessment, ThreatSource};

#[derive(Clone, Debug)]
pub struct FusionPolicy {
    pub dual_sensor_threshold: f64,
    pub single_classifier_high: f64,
}

impl Default for FusionPolicy {
    fn default() -> Self {
        Self {
            dual_sensor_threshold: 0.5,
            single_classifier_high: 0.85,
        }
    }
}

pub struct SensorFusion {
    policy: FusionPolicy,
}

impl SensorFusion {
    pub fn new(policy: FusionPolicy) -> Self {
        Self { policy }
    }

    /// Sensor disagreement detector (clause-review requirement).
    ///
    /// Reports `true` when windowed sources are present but below agreement:
    /// classifier high with no signature corroboration, signature without any
    /// classifier corroboration, or two assessments whose confidences straddle
    /// the dual-sensor threshold (one side sees a threat, the other does not).
    /// Geometric impossibility FACTS and statistical envelope SCORES are
    /// separate epistemic classes and are never fused into one number here;
    /// this operates only on `ThreatAssessment.confidence` values.
    pub fn disagrees(&self, assessments: &[ThreatAssessment]) -> bool {
        if assessments.len() < 2 {
            return false;
        }
        let has_classifier = assessments
            .iter()
            .any(|a| matches!(a.source, ThreatSource::Classifier { .. }));
        let has_sig = assessments
            .iter()
            .any(|a| a.source == ThreatSource::SignatureEngine);
        let above = assessments
            .iter()
            .filter(|a| a.confidence > self.policy.dual_sensor_threshold)
            .count();
        // Corroboration missing on one side: classifier-only or sig-only sets.
        if (has_classifier && !has_sig && above > 0) || (has_sig && !has_classifier) {
            return true;
        }
        // Conflicting readings on the same subject: straddle the threshold.
        above > 0 && above < assessments.len()
    }

    pub fn fuse(&self, assessments: &[ThreatAssessment]) -> SuggestedAction {
        if assessments.is_empty() {
            return SuggestedAction::None;
        }

        let has_sig_match = assessments
            .iter()
            .any(|a| a.source == ThreatSource::SignatureEngine);

        if has_sig_match {
            return SuggestedAction::TriggerFailover;
        }

        let high_confidence: Vec<_> = assessments
            .iter()
            .filter(|a| a.confidence > self.policy.dual_sensor_threshold)
            .collect();

        let distinct_sources: std::collections::HashSet<_> = high_confidence
            .iter()
            .map(|a| std::mem::discriminant(&a.source))
            .collect();

        if distinct_sources.len() >= 2 {
            return SuggestedAction::TriggerFailover;
        }

        let max_confidence = assessments
            .iter()
            .map(|a| a.confidence)
            .fold(0.0f64, f64::max);

        if max_confidence > self.policy.single_classifier_high {
            return SuggestedAction::ActivateStrainer {
                strainer_name: "probe_response".into(),
            };
        }

        if max_confidence > self.policy.dual_sensor_threshold {
            return SuggestedAction::IncreaseMonitoring;
        }

        SuggestedAction::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn classifier_assessment(confidence: f64, name: &str) -> ThreatAssessment {
        ThreatAssessment {
            source: ThreatSource::Classifier {
                model_name: name.into(),
            },
            confidence,
            description: "test".into(),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::None,
        }
    }

    fn sig_assessment() -> ThreatAssessment {
        ThreatAssessment {
            source: ThreatSource::SignatureEngine,
            confidence: 1.0,
            description: "sig match".into(),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action: SuggestedAction::TriggerFailover,
        }
    }

    #[test]
    fn signature_match_always_triggers_failover() {
        let fusion = SensorFusion::new(FusionPolicy::default());
        let action = fusion.fuse(&[sig_assessment()]);
        assert_eq!(action, SuggestedAction::TriggerFailover);
    }

    #[test]
    fn single_high_classifier_activates_strainer() {
        let fusion = SensorFusion::new(FusionPolicy::default());
        let action = fusion.fuse(&[classifier_assessment(0.9, "detector")]);
        assert_eq!(
            action,
            SuggestedAction::ActivateStrainer {
                strainer_name: "probe_response".into(),
            }
        );
    }

    #[test]
    fn dual_sensor_triggers_failover() {
        let fusion = SensorFusion::new(FusionPolicy::default());
        let action = fusion.fuse(&[
            classifier_assessment(0.6, "detector"),
            ThreatAssessment {
                source: ThreatSource::Heuristic {
                    name: "timing".into(),
                },
                confidence: 0.7,
                description: "timing anomaly".into(),
                remote_addr: None,
                timestamp: Utc::now(),
                suggested_action: SuggestedAction::None,
            },
        ]);
        assert_eq!(action, SuggestedAction::TriggerFailover);
    }

    #[test]
    fn low_confidence_returns_none() {
        let fusion = SensorFusion::new(FusionPolicy::default());
        let action = fusion.fuse(&[classifier_assessment(0.2, "detector")]);
        assert_eq!(action, SuggestedAction::None);
    }

    #[test]
    fn disagreement_classifier_high_without_signature() {
        let fusion = SensorFusion::new(FusionPolicy::default());
        assert!(fusion.disagrees(&[
            classifier_assessment(0.9, "detector"),
            classifier_assessment(0.3, "detector"),
        ]));
    }

    #[test]
    fn disagreement_signature_without_classifier() {
        let fusion = SensorFusion::new(FusionPolicy::default());
        assert!(fusion.disagrees(&[
            sig_assessment(),
            ThreatAssessment {
                source: ThreatSource::Heuristic {
                    name: "timing".into(),
                },
                confidence: 0.1,
                description: "quiet".into(),
                remote_addr: None,
                timestamp: Utc::now(),
                suggested_action: SuggestedAction::None,
            },
        ]));
    }

    #[test]
    fn no_disagreement_on_single_or_agreement() {
        let fusion = SensorFusion::new(FusionPolicy::default());
        assert!(!fusion.disagrees(&[classifier_assessment(0.9, "detector")]));
        assert!(!fusion.disagrees(&[]));
        assert!(!fusion.disagrees(&[
            classifier_assessment(0.6, "a"),
            ThreatAssessment {
                source: ThreatSource::Heuristic {
                    name: "timing".into(),
                },
                confidence: 0.7,
                description: "timing anomaly".into(),
                remote_addr: None,
                timestamp: Utc::now(),
                suggested_action: SuggestedAction::None,
            },
            sig_assessment(),
        ]));
    }
}
