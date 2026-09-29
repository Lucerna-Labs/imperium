//! Walks of linear maps and degree records.
//!
//! This orchestrator records composite maps and the degree of candidate
//! readouts. It never filters, scores, labels, or asks whether a walk is a
//! copy.

use nocopy_linear_map_core::{
    coordinate_product_degree, CouplingFamily, LinearMap, ReadoutDegree, State,
};

/// One recorded walk: composites and readout degrees only.
#[derive(Clone, Debug, PartialEq)]
pub struct WalkRecord {
    /// Composite map after each step, in walk order.
    pub composites: Vec<LinearMap>,
    /// States reached from the initial state, in walk order.
    pub states: Vec<State>,
    /// Degree records requested during the walk.
    pub degrees: Vec<ReadoutDegree>,
}

/// Run a fixed walk of generators from `initial`, recording everything.
#[must_use]
pub fn walk(initial: State, maps: &[LinearMap]) -> WalkRecord {
    let mut composites = Vec::with_capacity(maps.len());
    let mut states = Vec::with_capacity(maps.len());
    let mut current_state = initial;
    let mut current_map = LinearMap::identity();
    for map in maps {
        current_map = map.compose(current_map);
        current_state = map.apply(current_state);
        composites.push(current_map);
        states.push(current_state);
    }
    // The only readout the algebra is asked about: the product readout needed
    // for a clone. The algebra answers "nonlinear" by structure.
    let degrees = vec![coordinate_product_degree()];
    WalkRecord {
        composites,
        states,
        degrees,
    }
}

/// One recorded chaos walk: the same record shape, driven by iteration of a
/// single [`CouplingFamily`] member instead of a hand-picked generator list.
///
/// The composite after step `n` is the `n`-fold composite of the member map;
/// states are its iterates from `initial`. The degree record is the same
/// product-readout question as [`walk`], so base and chaos runs carry
/// identical no-copy evidence.
#[must_use]
pub fn chaos_walk(initial: State, member: CouplingFamily, steps: usize) -> WalkRecord {
    let map = member.map();
    let mut composites = Vec::with_capacity(steps);
    let mut states = Vec::with_capacity(steps);
    let mut current_state = initial;
    let mut current_map = LinearMap::identity();
    for _ in 0..steps {
        current_map = map.compose(current_map);
        current_state = map.apply(current_state);
        composites.push(current_map);
        states.push(current_state);
    }
    let degrees = vec![coordinate_product_degree()];
    WalkRecord {
        composites,
        states,
        degrees,
    }
}

/// Sweep the coupling across `couplings`, recording one [`chaos_walk`] per
/// value. Every walk is recorded; no value is skipped, thinned, or selected.
#[must_use]
pub fn sweep(initial: State, couplings: &[f64], steps: usize) -> Vec<WalkRecord> {
    couplings
        .iter()
        .map(|coupling| chaos_walk(initial, CouplingFamily::new(*coupling), steps))
        .collect()
}

/// Report the chaos/no-chaos difference for one matched walk pair.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WalkDelta {
    /// Steps recorded in the base walk.
    pub base_steps: usize,
    /// Steps recorded in the chaos walk.
    pub chaos_steps: usize,
    /// Signed difference `chaos_steps - base_steps`.
    pub step_delta: i64,
    /// Degree records in the base walk.
    pub base_degrees: usize,
    /// Degree records in the chaos walk.
    pub chaos_degrees: usize,
    /// Final-state separation between the two walks (L1 distance).
    pub final_separation: f64,
}

/// Summarize a matched base/chaos walk pair with identical evidence.
#[must_use]
pub fn walk_delta(base: &WalkRecord, chaos: &WalkRecord) -> WalkDelta {
    let final_separation = match (base.states.last(), chaos.states.last()) {
        (Some(left), Some(right)) => {
            let mut total = 0.0;
            for index in 0..left.0.len() {
                total += (left.0[index] - right.0[index]).abs();
            }
            total
        }
        _ => 0.0,
    };
    WalkDelta {
        base_steps: base.composites.len(),
        chaos_steps: chaos.composites.len(),
        step_delta: chaos.composites.len() as i64 - base.composites.len() as i64,
        base_degrees: base.degrees.len(),
        chaos_degrees: chaos.degrees.len(),
        final_separation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_records_every_step_without_filtering() {
        let record = walk(
            State([1.0, 0.0, 0.0]),
            &[
                LinearMap::cyclic_shift(),
                LinearMap::swap_first_two(),
                LinearMap::cyclic_shift(),
            ],
        );
        assert_eq!(record.composites.len(), 3);
        assert_eq!(record.states.len(), 3);
        assert_eq!(record.degrees, vec![ReadoutDegree::Nonlinear]);
    }

    #[test]
    fn empty_walk_records_nothing_but_asks_the_degree_question() {
        let record = walk(State([0.0, 1.0, 0.0]), &[]);
        assert!(record.composites.is_empty());
        assert!(record.states.is_empty());
        assert_eq!(record.degrees, vec![ReadoutDegree::Nonlinear]);
    }

    #[test]
    fn chaos_walk_is_deterministic_and_records_every_step() {
        let member = CouplingFamily::new(1.25);
        let first = chaos_walk(State([4.0, 0.0, 0.0]), member, 5);
        let second = chaos_walk(State([4.0, 0.0, 0.0]), member, 5);
        assert_eq!(first, second);
        assert_eq!(first.composites.len(), 5);
        assert_eq!(first.states.len(), 5);
        assert_eq!(first.degrees, vec![ReadoutDegree::Nonlinear]);
    }

    #[test]
    fn chaos_walk_members_stay_linear_with_quadratic_clone_excluded() {
        for coupling in [0.25, 1.0, 1.75] {
            let record = chaos_walk(State([1.0, -2.0, 3.0]), CouplingFamily::new(coupling), 4);
            assert_eq!(record.degrees, vec![ReadoutDegree::Nonlinear]);
            // Composite linearity spot-check on the final recorded map.
            let composite = *record.composites.last().unwrap();
            let state = State([1.0, -2.0, 3.0]);
            let scaled = State([2.0, -4.0, 6.0]);
            let mapped = composite.apply(state);
            let mapped_scaled = composite.apply(scaled);
            for index in 0..mapped.0.len() {
                assert!((mapped_scaled.0[index] - 2.0 * mapped.0[index]).abs() < 1e-9);
            }
        }
    }

    #[test]
    fn sweep_records_identical_no_copy_evidence() {
        let base = walk(
            State([4.0, 0.0, 0.0]),
            &[
                LinearMap::cyclic_shift(),
                LinearMap::swap_first_two(),
                LinearMap::cyclic_shift(),
                LinearMap::swap_first_two(),
            ],
        );
        let records = sweep(State([4.0, 0.0, 0.0]), &[0.25, 1.75], 4);
        assert_eq!(records.len(), 2);
        for chaos in &records {
            let delta = walk_delta(&base, chaos);
            assert_eq!(delta.base_steps, base.composites.len());
            assert_eq!(delta.chaos_steps, chaos.composites.len());
            assert_eq!(delta.base_degrees, base.degrees.len());
            assert_eq!(delta.chaos_degrees, chaos.degrees.len());
            assert_eq!(chaos.degrees, vec![ReadoutDegree::Nonlinear]);
        }
    }

    #[test]
    fn chaos_walk_is_not_a_filter_or_random_fallback() {
        // Falsifier: if chaos mode dropped steps/regimes (filter collapse)
        // or produced nondeterministic walks (random fallback), this fails.
        // The sweep records every requested coupling deterministically, and
        // matched reruns agree exactly.
        let couplings = [0.25, 1.0, 1.75];
        let first = sweep(State([4.0, 0.0, 0.0]), &couplings, 4);
        let second = sweep(State([4.0, 0.0, 0.0]), &couplings, 4);
        assert_eq!(first.len(), couplings.len());
        assert_eq!(first, second);
        for (record, coupling) in first.iter().zip(couplings) {
            assert_eq!(record.composites.len(), 4);
            assert_eq!(record.states.len(), 4);
            assert_eq!(record.composites[0], CouplingFamily::new(coupling).map());
        }
    }
}
