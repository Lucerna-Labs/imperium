//! Fixed-order execution, observation, and return for route stacks.
//!
//! This orchestrator contains no desired output, verdict, corrective logic,
//! content-dependent routing, policy, or postprocessing toward an answer. It
//! arranges primitives in a stated logical order, executes intrinsic
//! mechanics, observes measurements, and returns them.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use thiserror::Error;

use imperium_atom_route_function::{
    AttractorMap, BifurcationThreshold, ChaoticBifurcation, CollisionConsensus, RouteBase,
    RouteState, RouteTap,
};

/// Errors in fixed orchestration execution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteEngineError {
    /// Caller supplied a malformed fixed-shape observation.
    #[error("malformed route input")]
    MalformedInput,
}

/// One declared logical stack order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteOrder {
    /// Observe → attractor → consensus.
    AttractThenAgree = 0,
    /// Observe → consensus → attractor.
    AgreeThenAttract = 1,
    /// Observe → attractor and bifurcation independently, then compare.
    SplitCompare = 2,
}

/// Fixed engine configuration: primitives and declared order only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteEngine {
    order: RouteOrder,
    attractor: AttractorMap,
    consensus: CollisionConsensus,
    threshold: BifurcationThreshold,
    bifurcation: ChaoticBifurcation,
    base: RouteBase,
}

/// Observation-only execution receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteReceipt {
    /// Declared order used for this run.
    pub order: RouteOrder,
    /// Base used for measurement columns.
    pub base: RouteBase,
    /// Selectivity column from the composed state.
    pub selectivity: imperium_atom_route_function::PathSelectivity,
    /// Rebind-shape column from the composed state.
    pub rebind_shape: imperium_atom_route_function::RebindShape,
    /// Sufficiency/count record.
    pub sufficiency: imperium_atom_route_function::RouteSufficiency,
    /// Consensus residue carried for observation only.
    pub consensus_residue: u8,
    /// Bifurcation residue carried for observation only.
    pub bifurcation_residue: u8,
}

impl RouteEngine {
    /// Create an engine with fixed primitives and one declared order.
    pub fn new(
        order: RouteOrder,
        attractor: AttractorMap,
        consensus: CollisionConsensus,
        threshold: BifurcationThreshold,
        bifurcation: ChaoticBifurcation,
        base: RouteBase,
    ) -> Self {
        Self {
            order,
            attractor,
            consensus,
            threshold,
            bifurcation,
            base,
        }
    }

    /// Execute the declared composition over fixed tap records and return
    /// measurements. No branching depends on tap content identifying a source,
    /// route, peer, adversary, threat, or desired result.
    pub fn execute(&self, taps: &[RouteTap]) -> Result<RouteReceipt, RouteEngineError> {
        let mut state = RouteState::new();
        for tap in taps {
            state
                .observe(*tap)
                .map_err(|_| RouteEngineError::MalformedInput)?;
        }
        let twin = state.clone();

        let mut attracted = state.clone();
        imperium_atom_route_function::interaction::apply_attractor(&mut attracted, self.attractor);
        let mut agreed = state.clone();
        let residue = imperium_atom_route_function::interaction::apply_consensus(
            &agreed,
            &twin,
            self.consensus,
        );
        let threshold = self.threshold;
        agreed.transform_observations(move |value| threshold.regime(value));

        let composed = match self.order {
            RouteOrder::AttractThenAgree => attracted,
            RouteOrder::AgreeThenAttract => agreed,
            RouteOrder::SplitCompare => state.clone(),
        };

        let (selectivity, rebind_shape, sufficiency) =
            imperium_atom_route_function::interaction::read_columns(&composed, self.base);
        Ok(RouteReceipt {
            order: self.order,
            base: self.base,
            selectivity,
            rebind_shape,
            sufficiency,
            consensus_residue: residue,
            bifurcation_residue:
                imperium_atom_route_function::interaction::bifurcation_from_evidence(
                    self.bifurcation,
                    sufficiency.observations_in_window,
                ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taps(count: u8, step: u8) -> Vec<RouteTap> {
        (0..count)
            .map(|v| RouteTap {
                destination_class: v % 5,
                prefix_length: 24,
                candidate_count: 3,
                best_prefix_length: 24,
                rebind_count: v.wrapping_mul(step) % 3,
                path_stable: true,
            })
            .collect()
    }

    #[test]
    fn all_declared_orders_execute_and_report_evidence() {
        for order in [
            RouteOrder::AttractThenAgree,
            RouteOrder::AgreeThenAttract,
            RouteOrder::SplitCompare,
        ] {
            let engine = RouteEngine::new(
                order,
                AttractorMap::new(5, 13),
                CollisionConsensus::new(97, 5),
                BifurcationThreshold::new(128),
                ChaoticBifurcation::new(7, 64),
                RouteBase::Plain,
            );
            let receipt = engine.execute(&taps(24, 1)).unwrap();
            assert_eq!(receipt.order, order);
            assert!(receipt.sufficiency.supported);
            assert_eq!(receipt.sufficiency.observations_in_window, 24);
        }
    }

    #[test]
    fn empty_input_reports_unsupported_without_verdict() {
        let engine = RouteEngine::new(
            RouteOrder::AttractThenAgree,
            AttractorMap::new(5, 13),
            CollisionConsensus::new(97, 5),
            BifurcationThreshold::new(128),
            ChaoticBifurcation::new(7, 64),
            RouteBase::Reversible,
        );
        let receipt = engine.execute(&[]).unwrap();
        assert!(!receipt.sufficiency.supported);
        assert_eq!(receipt.selectivity.evidence, 0);
    }

    #[test]
    fn malformed_inputs_are_rejected_not_corrected() {
        let engine = RouteEngine::new(
            RouteOrder::AttractThenAgree,
            AttractorMap::new(5, 13),
            CollisionConsensus::new(97, 5),
            BifurcationThreshold::new(128),
            ChaoticBifurcation::new(7, 64),
            RouteBase::Plain,
        );
        let taps = [RouteTap {
            destination_class: 1,
            prefix_length: 24,
            candidate_count: 0,
            best_prefix_length: 24,
            rebind_count: 0,
            path_stable: true,
        }];
        assert_eq!(engine.execute(&taps), Err(RouteEngineError::MalformedInput));
    }
}
