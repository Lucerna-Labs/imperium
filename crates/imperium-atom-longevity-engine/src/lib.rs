//! Fixed-order execution, observation, and return for longevity stacks.
//!
//! This orchestrator contains no desired output, verdict, corrective logic,
//! content-dependent routing, policy, or postprocessing toward an answer. It
//! arranges primitives in a stated logical order, executes intrinsic
//! mechanics, observes measurements, and returns them.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use thiserror::Error;

use imperium_atom_longevity_function::{
    BottleneckCode, ChaoticDecay, DecayAccumulator, LongevityBase, LongevityState, LongevityTap,
    ResidualDiffusion,
};

/// Errors in fixed orchestration execution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LongevityEngineError {
    /// Caller supplied a malformed fixed-shape observation.
    #[error("malformed longevity input")]
    MalformedInput,
}

/// One declared logical stack order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LongevityOrder {
    /// Observe → diffusion → chaos.
    DiffuseThenChaos = 0,
    /// Observe → chaos → diffusion.
    ChaosThenDiffuse = 1,
    /// Observe → diffusion and bottleneck independently, then compare.
    SplitCompare = 2,
}

/// Fixed engine configuration: primitives and declared order only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongevityEngine {
    order: LongevityOrder,
    diffusion: ResidualDiffusion,
    decay: ChaoticDecay,
    accumulator: DecayAccumulator,
    code: BottleneckCode,
    base: LongevityBase,
}

/// Observation-only execution receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongevityReceipt {
    /// Declared order used for this run.
    pub order: LongevityOrder,
    /// Base used for measurement columns.
    pub base: LongevityBase,
    /// Persistence column from the composed state.
    pub persistence: imperium_atom_longevity_function::Persistence,
    /// Rotation-pressure column from the composed state.
    pub pressure: imperium_atom_longevity_function::RotationPressure,
    /// Sufficiency/count record.
    pub sufficiency: imperium_atom_longevity_function::LongevitySufficiency,
    /// Bottleneck signature carried for observation only.
    pub bottleneck_signature: u8,
    /// Accumulator residue carried for observation only.
    pub accumulator_residue: u8,
}

impl LongevityEngine {
    /// Create an engine with fixed primitives and one declared order.
    pub fn new(
        order: LongevityOrder,
        diffusion: ResidualDiffusion,
        decay: ChaoticDecay,
        accumulator: DecayAccumulator,
        code: BottleneckCode,
        base: LongevityBase,
    ) -> Self {
        Self {
            order,
            diffusion,
            decay,
            accumulator,
            code,
            base,
        }
    }

    /// Execute the declared composition over fixed tap records and return
    /// measurements. No branching depends on tap content identifying a source,
    /// session, adversary, threat, or desired result.
    pub fn execute(&self, taps: &[LongevityTap]) -> Result<LongevityReceipt, LongevityEngineError> {
        let mut state = LongevityState::new();
        for tap in taps {
            state
                .observe(*tap)
                .map_err(|_| LongevityEngineError::MalformedInput)?;
        }

        let mut diffused = state.clone();
        imperium_atom_longevity_function::interaction::apply_diffusion_then_chaos(
            &mut diffused,
            self.diffusion,
            self.decay,
        );
        let mut chaotic = state.clone();
        imperium_atom_longevity_function::interaction::apply_diffusion_then_chaos(
            &mut chaotic,
            ResidualDiffusion::new(2, 0),
            self.decay,
        );

        let composed = match self.order {
            LongevityOrder::DiffuseThenChaos => diffused,
            LongevityOrder::ChaosThenDiffuse => chaotic,
            LongevityOrder::SplitCompare => state.clone(),
        };

        let (persistence, pressure, sufficiency) =
            imperium_atom_longevity_function::interaction::read_columns(&composed, self.base);
        Ok(LongevityReceipt {
            order: self.order,
            base: self.base,
            persistence,
            pressure,
            sufficiency,
            bottleneck_signature:
                imperium_atom_longevity_function::interaction::bottleneck_signature(
                    &composed, self.code,
                ),
            accumulator_residue:
                imperium_atom_longevity_function::interaction::accumulator_from_evidence(
                    self.accumulator,
                    sufficiency.observations_in_window,
                ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taps(count: u8, step: u8) -> Vec<LongevityTap> {
        (0..count)
            .map(|v| LongevityTap {
                session_epoch: u64::from(v),
                bytes_sealed_bucket: v.wrapping_mul(step),
                idle_bucket: 2,
                rotation_due: false,
                reauth_required: false,
                expiry_reason_code: v % 5,
            })
            .collect()
    }

    #[test]
    fn all_declared_orders_execute_and_report_evidence() {
        for order in [
            LongevityOrder::DiffuseThenChaos,
            LongevityOrder::ChaosThenDiffuse,
            LongevityOrder::SplitCompare,
        ] {
            let engine = LongevityEngine::new(
                order,
                ResidualDiffusion::new(97, 3),
                ChaoticDecay::new(7, 5),
                DecayAccumulator::new(3, 11),
                BottleneckCode::new(8, 3),
                LongevityBase::Plain,
            );
            let receipt = engine.execute(&taps(24, 1)).unwrap();
            assert_eq!(receipt.order, order);
            assert!(receipt.sufficiency.supported);
            assert_eq!(receipt.sufficiency.observations_in_window, 24);
        }
    }

    #[test]
    fn empty_input_reports_unsupported_without_verdict() {
        let engine = LongevityEngine::new(
            LongevityOrder::DiffuseThenChaos,
            ResidualDiffusion::new(97, 3),
            ChaoticDecay::new(7, 5),
            DecayAccumulator::new(3, 11),
            BottleneckCode::new(8, 3),
            LongevityBase::Reversible,
        );
        let receipt = engine.execute(&[]).unwrap();
        assert!(!receipt.sufficiency.supported);
        assert_eq!(receipt.persistence.evidence, 0);
    }

    #[test]
    fn malformed_inputs_are_rejected_not_corrected() {
        let engine = LongevityEngine::new(
            LongevityOrder::DiffuseThenChaos,
            ResidualDiffusion::new(97, 3),
            ChaoticDecay::new(7, 5),
            DecayAccumulator::new(3, 11),
            BottleneckCode::new(8, 3),
            LongevityBase::Plain,
        );
        let taps = [LongevityTap {
            session_epoch: 0,
            bytes_sealed_bucket: 0,
            idle_bucket: 0,
            rotation_due: false,
            reauth_required: false,
            expiry_reason_code: 99,
        }];
        assert_eq!(
            engine.execute(&taps),
            Err(LongevityEngineError::MalformedInput)
        );
    }
}
