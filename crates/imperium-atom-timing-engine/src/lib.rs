//! Fixed-order execution, observation, and return for timing stacks.
//!
//! This orchestrator contains no desired output, verdict, corrective logic,
//! content-dependent routing, policy, or postprocessing toward an answer. It
//! arranges primitives in a stated logical order, executes intrinsic
//! mechanics, observes measurements, and returns them.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use thiserror::Error;

use imperium_atom_timing_function::{
    CatalyticBarrier, ChaoticMixer, HistoryCoupling, TimingBase, TimingState, TimingTap,
    TransportDelay,
};

/// Errors in fixed orchestration execution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TimingEngineError {
    /// Caller supplied a malformed fixed-shape observation.
    #[error("malformed timing input")]
    MalformedInput,
}

/// One declared logical stack order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingOrder {
    /// Observe → catalytic coupling → chaos.
    CoupleThenChaos = 0,
    /// Observe → chaos → catalytic coupling.
    ChaosThenCouple = 1,
    /// Observe → coupling and chaos independently, then compare mechanically.
    SplitCompare = 2,
}

/// Fixed engine configuration: primitives and declared order only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimingEngine {
    order: TimingOrder,
    barrier: CatalyticBarrier,
    mixer: ChaoticMixer,
    delay: TransportDelay,
    base: TimingBase,
}

/// Observation-only execution receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimingReceipt {
    /// Declared order used for this run.
    pub order: TimingOrder,
    /// Base used for measurement columns.
    pub base: TimingBase,
    /// Arrangement column from the composed state.
    pub arrangement: imperium_atom_timing_function::CadenceArrangement,
    /// Trend column from the composed state.
    pub trend: imperium_atom_timing_function::CadenceTrend,
    /// Sufficiency/count record.
    pub sufficiency: imperium_atom_timing_function::TimingSufficiency,
    /// Bounded delay-recurrence residue carried for observation only.
    pub delay_residue: u8,
    /// Catalytic residual carried for observation only.
    pub barrier_residual: u8,
}

impl TimingEngine {
    /// Create an engine with fixed primitives and one declared order.
    pub fn new(
        order: TimingOrder,
        barrier: CatalyticBarrier,
        mixer: ChaoticMixer,
        delay: TransportDelay,
        base: TimingBase,
    ) -> Self {
        Self {
            order,
            barrier,
            mixer,
            delay,
            base,
        }
    }

    /// Execute the declared composition over fixed tap records and return
    /// measurements. No branching depends on tap content identifying a source,
    /// adversary, threat, or desired result.
    pub fn execute(&self, taps: &[TimingTap]) -> Result<TimingReceipt, TimingEngineError> {
        let mut state = TimingState::new();
        let mut history = HistoryCoupling::new();
        for tap in taps {
            state
                .observe(*tap)
                .map_err(|_| TimingEngineError::MalformedInput)?;
            history.absorb(tap.inter_arrival_bucket);
        }

        let coupled = self.barrier.catalyze(&history, &state);
        let mut chaotic = state.clone();
        imperium_atom_timing_function::interaction::apply_chaos(&mut chaotic, self.mixer);

        let composed = match self.order {
            TimingOrder::CoupleThenChaos => {
                let mut next = coupled;
                imperium_atom_timing_function::interaction::apply_chaos(&mut next, self.mixer);
                next
            }
            TimingOrder::ChaosThenCouple => {
                let mut next = chaotic;
                imperium_atom_timing_function::interaction::apply_coupling(
                    self.barrier,
                    &history,
                    &next,
                );
                next = self.barrier.catalyze(&history, &next);
                next
            }
            TimingOrder::SplitCompare => {
                // Fixed comparison: retain the independently coupled state so all
                // three declared orders terminate in different mechanical states.
                // There is no judgment here about which composition is better.
                coupled
            }
        };

        let (arrangement, trend, sufficiency) =
            imperium_atom_timing_function::interaction::read_columns(&composed, self.base);
        Ok(TimingReceipt {
            order: self.order,
            base: self.base,
            arrangement,
            trend,
            sufficiency,
            delay_residue: imperium_atom_timing_function::interaction::delay_from_evidence(
                self.delay,
                sufficiency.observations_in_window,
            ),
            barrier_residual: self.barrier.residual(&history),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taps(count: u8, step: u8) -> Vec<TimingTap> {
        (0..count)
            .map(|v| TimingTap {
                frame_counter: u64::from(v),
                inter_arrival_bucket: v.wrapping_mul(step),
                delay_bucket: 3,
                jitter_ceiling_ms: 20,
                cadence_sufficient: true,
                coalesced: false,
            })
            .collect()
    }

    #[test]
    fn all_declared_orders_execute_and_report_evidence() {
        let engine_base = TimingEngine::new(
            TimingOrder::CoupleThenChaos,
            CatalyticBarrier::new(8),
            ChaoticMixer::new(61, 17),
            TransportDelay::new(3, 5),
            TimingBase::Plain,
        );
        for order in [
            TimingOrder::CoupleThenChaos,
            TimingOrder::ChaosThenCouple,
            TimingOrder::SplitCompare,
        ] {
            let engine = TimingEngine::new(
                order,
                CatalyticBarrier::new(8),
                ChaoticMixer::new(61, 17),
                TransportDelay::new(3, 5),
                TimingBase::Plain,
            );
            let receipt = engine.execute(&taps(32, 1)).unwrap();
            assert_eq!(receipt.order, order);
            assert!(receipt.sufficiency.supported);
            assert_eq!(receipt.sufficiency.observations_in_window, 32);
            let _ = engine_base.execute(&taps(32, 2)).unwrap();
        }
    }

    #[test]
    fn empty_input_reports_unsupported_without_verdict() {
        let engine = TimingEngine::new(
            TimingOrder::CoupleThenChaos,
            CatalyticBarrier::new(8),
            ChaoticMixer::new(61, 17),
            TransportDelay::new(3, 5),
            TimingBase::Reversible,
        );
        let receipt = engine.execute(&[]).unwrap();
        assert!(!receipt.sufficiency.supported);
        assert_eq!(receipt.arrangement.evidence, 0);
    }

    #[test]
    fn malformed_inputs_are_rejected_not_corrected() {
        let engine = TimingEngine::new(
            TimingOrder::CoupleThenChaos,
            CatalyticBarrier::new(8),
            ChaoticMixer::new(61, 17),
            TransportDelay::new(3, 5),
            TimingBase::Plain,
        );
        let taps = [TimingTap {
            frame_counter: 0,
            inter_arrival_bucket: 0,
            delay_bucket: 0,
            jitter_ceiling_ms: 0,
            cadence_sufficient: false,
            coalesced: false,
        }];
        assert_eq!(
            engine.execute(&taps),
            Err(TimingEngineError::MalformedInput)
        );
    }
}
