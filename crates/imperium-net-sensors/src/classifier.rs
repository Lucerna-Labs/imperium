use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use imperium_protocol::BusEvent;
use imperium_protocol::{Message, SensorFeature, SuggestedAction, ThreatAssessment, ThreatSource};
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClassifierError {
    #[error("model not loaded: {0}")]
    ModelNotLoaded(String),
    #[error("inference timeout")]
    InferenceTimeout,
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

#[derive(Clone, Debug)]
pub struct ClassifierConfig {
    pub model_name: String,
    pub model_hash: String,
    pub latency_budget: Duration,
    pub confidence_threshold: f64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClassifierState {
    Unloaded,
    Loading,
    Ready,
    Failed,
}

pub struct ClassifierSensor {
    config: ClassifierConfig,
    state: Arc<RwLock<ClassifierState>>,
    bus: Arc<BusPublisher>,
}

impl ClassifierSensor {
    pub fn new(config: ClassifierConfig, bus: Arc<BusPublisher>) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(ClassifierState::Unloaded)),
            bus,
        }
    }

    pub fn state(&self) -> ClassifierState {
        self.state.read().clone()
    }

    pub fn load_model(&self) -> Result<(), ClassifierError> {
        *self.state.write() = ClassifierState::Loading;
        *self.state.write() = ClassifierState::Ready;
        tracing::info!(model = %self.config.model_name, "classifier model loaded");
        Ok(())
    }

    pub fn classify(
        &self,
        features: &[SensorFeature],
    ) -> Result<Option<ThreatAssessment>, ClassifierError> {
        if self.state() != ClassifierState::Ready {
            return Err(ClassifierError::ModelNotLoaded(
                self.config.model_name.clone(),
            ));
        }

        let confidence = self.run_inference(features);

        if confidence < self.config.confidence_threshold {
            return Ok(None);
        }

        let suggested_action = if confidence > 0.85 {
            SuggestedAction::ActivateStrainer {
                strainer_name: "probe_response".into(),
            }
        } else if confidence > 0.5 {
            SuggestedAction::IncreaseMonitoring
        } else {
            SuggestedAction::None
        };

        let assessment = ThreatAssessment {
            source: ThreatSource::Classifier {
                model_name: self.config.model_name.clone(),
            },
            confidence,
            description: format!(
                "classifier {} detected potential threat (confidence: {:.2})",
                self.config.model_name, confidence
            ),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action,
        };

        BusEvent::publish(
            &self.bus,
            "net.sensors.threat",
            Message::ThreatAssessment(assessment.clone()),
        )?;

        Ok(Some(assessment))
    }

    fn run_inference(&self, features: &[SensorFeature]) -> f64 {
        if features.is_empty() {
            return 0.0;
        }

        let sum: f64 = features.iter().map(|f| f.value).sum();
        let avg = sum / features.len() as f64;
        avg.clamp(0.0, 1.0)
    }

    pub fn model_name(&self) -> &str {
        &self.config.model_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_classifier() -> ClassifierSensor {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let config = ClassifierConfig {
            model_name: "threat_detector".into(),
            model_hash: "abc123".into(),
            latency_budget: Duration::from_millis(30),
            confidence_threshold: 0.3,
        };
        ClassifierSensor::new(config, bus)
    }

    #[test]
    fn classifier_starts_unloaded() {
        let c = test_classifier();
        assert_eq!(c.state(), ClassifierState::Unloaded);
    }

    #[test]
    fn classifier_loads_model() {
        let c = test_classifier();
        c.load_model().unwrap();
        assert_eq!(c.state(), ClassifierState::Ready);
    }

    #[test]
    fn classifier_requires_loaded_model() {
        let c = test_classifier();
        assert!(c.classify(&[]).is_err());
    }

    #[test]
    fn classifier_emits_threat_for_high_features() {
        let c = test_classifier();
        c.load_model().unwrap();

        let features = vec![SensorFeature {
            name: "entropy".into(),
            value: 0.9,
            timestamp: Utc::now(),
        }];

        let result = c.classify(&features).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().confidence > 0.5);
    }

    #[test]
    fn classifier_ignores_low_features() {
        let c = test_classifier();
        c.load_model().unwrap();

        let features = vec![SensorFeature {
            name: "entropy".into(),
            value: 0.1,
            timestamp: Utc::now(),
        }];

        let result = c.classify(&features).unwrap();
        assert!(result.is_none());
    }
}
