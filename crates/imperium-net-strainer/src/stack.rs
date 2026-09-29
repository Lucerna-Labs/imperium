use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use imperium_protocol::BusEvent;
use imperium_protocol::{Message, StrainerRejection};
use parking_lot::RwLock;
use spiderweb::BusPublisher;

use crate::{Strainer, StrainerEffect, StrainerInput, StrainerOutput};

pub struct StrainerStack {
    name: String,
    protocol_context: String,
    stages: Vec<Arc<dyn Strainer>>,
    bus: Option<BusPublisher>,
}

impl StrainerStack {
    pub fn new(name: impl Into<String>, protocol_context: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            protocol_context: protocol_context.into(),
            stages: Vec::new(),
            bus: None,
        }
    }

    pub fn with_bus(mut self, bus: BusPublisher) -> Self {
        self.bus = Some(bus);
        self
    }

    pub fn add_stage(&mut self, strainer: Arc<dyn Strainer>) {
        self.stages.push(strainer);
    }

    pub fn apply(&self, input: StrainerInput) -> StrainerOutput {
        let (output, _) = self.apply_with_effects(input);
        output
    }

    /// DESIGN DECISION (2C): option A — the stack returns effects to the
    /// caller; the transport-layer consumer owns the wall clock.
    ///
    /// Why A over B (bus-published TimingDelay): the hardened.delay sleep
    /// sites already live in the mesh send path (`send_ping`/`send_pong`/
    /// cover frames), so a return-value channel fits existing wiring with
    /// the smaller change and no new bus topic/subscriber pair. Timing
    /// applies ONLY to probe/decoy responses shaped by strainers — strainers
    /// never touch user traffic (THESIS), and `StrainerEffect` is already
    /// documented as "records the delay synchronously, never sleeps".
    ///
    /// `apply` is kept for backward compatibility and still flattens
    /// Degraded to bytes (documented, not silent): callers that need the
    /// perturbation MUST use `apply_with_effects` and sleep the returned
    /// `TimingDelay`s before sending. Any path that calls `apply` instead
    /// buys zero perturbation — that is the explicitly marked unwired case.
    pub fn apply_with_effects(
        &self,
        input: StrainerInput,
    ) -> (StrainerOutput, Vec<StrainerEffect>) {
        let mut current_data = input.data.clone();
        let mut effects: Vec<StrainerEffect> = Vec::new();

        for stage in &self.stages {
            let stage_input = StrainerInput {
                data: current_data,
                source: input.source,
                context: input.context.clone(),
                timestamp: input.timestamp,
            };

            match stage.apply(stage_input) {
                StrainerOutput::Passed(data) => {
                    current_data = data;
                }
                StrainerOutput::Degraded { data, effect } => {
                    current_data = data;
                    tracing::debug!(
                        strainer = stage.id(),
                        method = %effect,
                        "strainer degraded response"
                    );
                    effects.push(effect);
                }
                StrainerOutput::Rejected { reason } => {
                    self.emit_rejection(stage.id(), &reason, input.source);
                    return (StrainerOutput::Rejected { reason }, effects);
                }
            }
        }

        if effects.is_empty() {
            (StrainerOutput::Passed(current_data), effects)
        } else {
            (
                StrainerOutput::Degraded {
                    data: current_data,
                    effect: effects[0],
                },
                effects,
            )
        }
    }

    fn emit_rejection(
        &self,
        strainer_id: &str,
        reason: &str,
        source: Option<std::net::SocketAddr>,
    ) {
        if let Some(ref bus) = self.bus {
            let rejection = StrainerRejection {
                strainer_id: strainer_id.to_string(),
                stack_id: self.name.clone(),
                shape_failed: reason.to_string(),
                source_identifier: source,
                timestamp: Utc::now(),
            };

            let _ = bus.publish(
                crate::topics::REJECTION,
                BusEvent::new(
                    crate::topics::REJECTION,
                    Message::StrainerRejection(rejection),
                ),
            );
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn protocol_context(&self) -> &str {
        &self.protocol_context
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
}

pub struct StrainerRegistry {
    strainers: Arc<RwLock<HashMap<String, Arc<dyn Strainer>>>>,
}

impl StrainerRegistry {
    pub fn new() -> Self {
        Self {
            strainers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register(&self, strainer: Arc<dyn Strainer>) {
        self.strainers
            .write()
            .insert(strainer.id().to_string(), strainer);
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Strainer>> {
        self.strainers.read().get(id).cloned()
    }

    pub fn build_stack(
        &self,
        name: impl Into<String>,
        protocol_context: impl Into<String>,
        stage_ids: &[&str],
    ) -> Option<StrainerStack> {
        let mut stack = StrainerStack::new(name, protocol_context);

        for id in stage_ids {
            let strainer = self.get(id)?;
            stack.add_stage(strainer);
        }

        Some(stack)
    }
}

impl Default for StrainerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strainers::TruncationStrainer;

    #[test]
    fn stack_applies_stages_in_order() {
        let trunc = Arc::new(TruncationStrainer::new(10));
        let mut stack = StrainerStack::new("test_stack", "test");
        stack.add_stage(trunc);

        let input = StrainerInput {
            data: vec![0u8; 20],
            source: None,
            context: HashMap::new(),
            timestamp: Utc::now(),
        };

        // apply_with_effects surfaces the Truncation effect (2C decision);
        // legacy apply() flattens Degraded to bare bytes (documented).
        let (output, effects) = stack.apply_with_effects(input);
        assert_eq!(output.data().unwrap().len(), 10);
        assert_eq!(effects.len(), 1);
        assert!(matches!(
            effects[0],
            crate::StrainerEffect::Truncation { max_length: 10 }
        ));
    }

    #[test]
    fn registry_builds_stack() {
        let registry = StrainerRegistry::new();
        registry.register(Arc::new(TruncationStrainer::new(10)));

        let stack = registry.build_stack("test", "proto", &["truncation"]);
        assert!(stack.is_some());
        assert_eq!(stack.unwrap().stage_count(), 1);
    }

    #[test]
    fn registry_missing_strainer_returns_none() {
        let registry = StrainerRegistry::new();
        let stack = registry.build_stack("test", "proto", &["nonexistent"]);
        assert!(stack.is_none());
    }

    #[test]
    fn apply_with_effects_surfaces_timing_delay() {
        use crate::strainers::TimingStrainer;
        let timing = Arc::new(TimingStrainer::new(100));
        let mut stack = StrainerStack::new("timing_stack", "test");
        stack.add_stage(timing);

        let input = StrainerInput {
            data: vec![1, 2, 3],
            source: None,
            context: HashMap::new(),
            timestamp: Utc::now(),
        };

        let (output, effects) = stack.apply_with_effects(input);
        // Bytes pass through UNMODIFIED; the perturbation is the effect.
        assert_eq!(output.data().unwrap(), &[1, 2, 3]);
        assert_eq!(effects.len(), 1);
        match effects[0] {
            crate::StrainerEffect::TimingDelay {
                jitter_ms,
                delay_ms,
            } => {
                assert_eq!(jitter_ms, 100);
                assert!((50..=150).contains(&delay_ms));
            }
            other => panic!("expected TimingDelay, got {:?}", other),
        }
        // Legacy apply() still flattens (documented unwired case).
        let flat = stack.apply(StrainerInput {
            data: vec![1, 2, 3],
            source: None,
            context: HashMap::new(),
            timestamp: Utc::now(),
        });
        assert!(flat.data().is_some());
    }

    #[test]
    fn apply_with_effects_empty_when_all_pass() {
        let trunc = Arc::new(TruncationStrainer::new(100));
        let mut stack = StrainerStack::new("pass_stack", "test");
        stack.add_stage(trunc);

        let input = StrainerInput {
            data: vec![0u8; 20],
            source: None,
            context: HashMap::new(),
            timestamp: Utc::now(),
        };

        let (output, effects) = stack.apply_with_effects(input);
        assert!(output.is_passed());
        assert!(effects.is_empty());
    }
}
