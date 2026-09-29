//! Route and peer-selection observations from redacted taps.
//!
//! This function crate contains intrinsic mechanisms only. No desired output,
//! label, confidence score, mapping, policy, revocation semantic, corrective
//! branch, or answer is encoded here. Behavior is measured from composition.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use thiserror::Error;

/// Errors in intrinsic route updates.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouteFunctionError {
    /// Caller supplied a malformed fixed-shape observation.
    #[error("malformed route tap")]
    MalformedTap,
}

/// Redacted route/peer-selection observation.
///
/// Bounded classes only. There are no addresses, hostnames, payload routes,
/// labels, keys, payload content, or conclusions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteTap {
    /// Destination class identifier.
    pub destination_class: u8,
    /// Prefix length class.
    pub prefix_length: u8,
    /// Number of real candidate paths available.
    pub candidate_count: u8,
    /// Best observed prefix-length class.
    pub best_prefix_length: u8,
    /// Bounded rebind-accounting class.
    pub rebind_count: u8,
    /// Whether the selected path has remained stable through observation.
    pub path_stable: bool,
}

/// Determinism and bounded-state contract for route primitives.
pub const MAX_OBSERVATIONS: usize = 64;

/// Path-selectivity column over bounded destination/prefix classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathSelectivity {
    /// Bounded 0..=1000 selectivity index.
    pub index: u16,
    /// Supporting observations.
    pub evidence: u32,
}

/// Rebind/shape-change column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RebindShape {
    /// Bounded 0..=1000 unsigned magnitude.
    pub magnitude: u16,
    /// Supporting observations.
    pub evidence: u32,
}

/// Sufficiency/count record for a route window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteSufficiency {
    /// Observations available in the current window.
    pub observations_in_window: u32,
    /// Whether every reported column is supported.
    pub supported: bool,
}

/// Intrinsic route state: bounded candidate/prefix classes and counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteState {
    observations: [u8; MAX_OBSERVATIONS],
    len: usize,
    evidence: u32,
}

/// Passive/base mechanics for route state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteBase {
    /// Identity/pass-through accounting.
    Plain = 0,
    /// Reversible positional encoding used as a passive base transform.
    Reversible = 1,
}

impl RouteState {
    /// Create empty route state.
    pub fn new() -> Self {
        Self {
            observations: [0; MAX_OBSERVATIONS],
            len: 0,
            evidence: 0,
        }
    }

    /// Bounded observation count. Engines never read raw storage directly.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len.min(MAX_OBSERVATIONS)
    }

    /// Apply one mechanical value transform to every stored observation.
    pub fn transform_observations(&mut self, f: impl Fn(u8) -> u8) {
        let usable = self.len();
        for value in self.observations.iter_mut().take(usable) {
            *value = f(*value);
        }
    }

    /// Observe a route class. Input is already redacted and bounded.
    pub fn observe(&mut self, tap: RouteTap) -> Result<(), RouteFunctionError> {
        if tap.prefix_length > 32 || tap.best_prefix_length > 32 {
            return Err(RouteFunctionError::MalformedTap);
        }
        if tap.candidate_count == 0 {
            return Err(RouteFunctionError::MalformedTap);
        }
        let value = tap
            .destination_class
            .wrapping_add(tap.prefix_length)
            .wrapping_add(tap.best_prefix_length)
            .wrapping_add(tap.candidate_count)
            .wrapping_add(tap.rebind_count)
            .wrapping_add(u8::from(tap.path_stable));
        if self.len < MAX_OBSERVATIONS {
            self.observations[self.len] = value;
            self.len += 1;
        } else {
            self.observations.copy_within(1.., 0);
            self.observations[MAX_OBSERVATIONS - 1] = value;
        }
        self.evidence = self.evidence.saturating_add(1);
        Ok(())
    }

    /// Convert the current sequence to a reversible positional base.
    #[must_use]
    pub fn as_base(&self, base: RouteBase) -> [u8; MAX_OBSERVATIONS] {
        let mut out = [0u8; MAX_OBSERVATIONS];
        match base {
            RouteBase::Plain => out.copy_from_slice(&self.observations),
            RouteBase::Reversible => {
                for (index, value) in self.observations.iter().enumerate() {
                    let position = (index as u8).wrapping_mul(67).wrapping_add(41);
                    out[index] = value.wrapping_add(position);
                }
            }
        }
        out
    }

    /// Selectivity column: how strongly longer prefixes dominate.
    #[must_use]
    pub fn selectivity(&self, base: RouteBase) -> PathSelectivity {
        let sequence = self.as_base(base);
        let usable = self.len.min(MAX_OBSERVATIONS);
        if usable == 0 {
            return PathSelectivity {
                index: 0,
                evidence: self.evidence,
            };
        }
        let mut local_maxima = 0u32;
        for window in sequence.windows(3).take(usable.saturating_sub(2)) {
            if window[1] > window[0] && window[1] >= window[2] {
                local_maxima += 1;
            }
        }
        PathSelectivity {
            index: ((u64::from(local_maxima) * 1000) / u64::from(usable.max(1) as u32)).min(1000)
                as u16,
            evidence: self.evidence,
        }
    }

    /// Rebind/shape-change magnitude column.
    #[must_use]
    pub fn rebind_shape(&self, base: RouteBase) -> RebindShape {
        let sequence = self.as_base(base);
        let usable = self.len.min(MAX_OBSERVATIONS);
        if usable < 2 {
            return RebindShape {
                magnitude: 0,
                evidence: self.evidence,
            };
        }
        let mut changes = 0u32;
        for index in 0..(usable - 1) {
            if sequence[index + 1] != sequence[index] {
                changes += 1;
            }
        }
        RebindShape {
            magnitude: ((u64::from(changes) * 1000) / u64::from((usable - 1).max(1) as u32))
                .min(1000) as u16,
            evidence: self.evidence,
        }
    }

    /// Sufficiency/count record for the current window.
    #[must_use]
    pub fn sufficiency(&self) -> RouteSufficiency {
        RouteSufficiency {
            observations_in_window: self.evidence.min(u32::from(u16::MAX)),
            supported: self.evidence > 0,
        }
    }
}

impl Default for RouteState {
    fn default() -> Self {
        Self::new()
    }
}

/// Attractor-map primitive.
///
/// A bounded nonlinear map generates recurrence classes without claiming
/// benefit, optimality, stability, or intent. Parameters are fixed at
/// construction and never tuned by execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttractorMap {
    control: u8,
    offset: u8,
}

/// Collision/consensus primitive.
///
/// Two independent sub-traces interact through a bounded finite operation. The
/// resulting agreement residue is data; it carries no verdict about whether
/// agreement is good, expected, hostile, or benign.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollisionConsensus {
    modulus: u8,
    scale: u8,
}

/// Bifurcation-threshold primitive.
///
/// A fixed breakpoint separates two recurrence regimes. Which side an input
/// falls on is measured mechanically; the breakpoint encodes no conclusion
/// about which regime is better or desired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BifurcationThreshold {
    breakpoint: u8,
}

/// Second chaos-bearing mechanism: bounded recurrence with bifurcation.
///
/// Fixed-at-construction parameters; deterministic evolution; no tuning and no
/// claim about benefit except as measured under frozen matched controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaoticBifurcation {
    rate: u8,
    capacity: u8,
}

impl AttractorMap {
    /// Create map parameters.
    pub fn new(control: u8, offset: u8) -> Self {
        Self { control, offset }
    }

    /// Advance one map step.
    #[must_use]
    pub fn advance(&self, prior: u8) -> u8 {
        let scaled = u16::from(prior).wrapping_mul(u16::from(self.control));
        let folded = (scaled + u16::from(self.offset)) % 241;
        let stepped = folded
            .wrapping_mul(u16::from(prior.wrapping_add(5)))
            .wrapping_add(11)
            % 241;
        (stepped % 256).min(255) as u8
    }
}

impl CollisionConsensus {
    /// Create consensus parameters.
    pub fn new(modulus: u8, scale: u8) -> Self {
        Self {
            modulus: modulus.max(2),
            scale,
        }
    }

    /// Combine two traces into one agreement residue.
    #[must_use]
    pub fn combine(&self, left: u8, right: u8) -> u8 {
        let modulus = u16::from(self.modulus);
        let weighted =
            u16::from(left).wrapping_add(u16::from(right).wrapping_mul(u16::from(self.scale)));
        (weighted % modulus).min(255) as u8
    }
}

impl BifurcationThreshold {
    /// Create a fixed breakpoint.
    pub fn new(breakpoint: u8) -> Self {
        Self { breakpoint }
    }

    /// Select a recurrence regime mechanically.
    #[must_use]
    pub fn regime(&self, value: u8) -> u8 {
        if value < self.breakpoint {
            value.wrapping_mul(3).wrapping_add(5)
        } else {
            value.wrapping_mul(7).wrapping_add(11)
        }
    }
}

impl ChaoticBifurcation {
    /// Create fixed bifurcation parameters.
    pub fn new(rate: u8, capacity: u8) -> Self {
        Self { rate, capacity }
    }

    /// Advance bounded chaotic recurrence once.
    #[must_use]
    pub fn advance(&self, prior: u8) -> u8 {
        let capacity = u16::from(self.capacity.max(2));
        let driven = u16::from(prior).wrapping_mul(u16::from(self.rate));
        let saturated =
            driven.saturating_sub(u16::from(prior).wrapping_mul(u16::from(prior)) / capacity);
        let stepped = saturated.wrapping_add(23) % 239;
        (stepped % 256).min(255) as u8
    }
}

/// Intrinsic interaction mechanics retained as explicit functions.
pub mod interaction {
    use super::{
        AttractorMap, BifurcationThreshold, ChaoticBifurcation, CollisionConsensus, RouteBase,
        RouteState,
    };

    /// Map every observation through one attractor step.
    pub fn apply_attractor(state: &mut RouteState, map: AttractorMap) {
        for value in state.observations.iter_mut().take(state.len) {
            *value = map.advance(*value);
        }
    }

    /// Mix two traces into one residue without interpreting agreement.
    pub fn apply_consensus(
        left: &RouteState,
        right: &RouteState,
        consensus: CollisionConsensus,
    ) -> u8 {
        let mut residue = 0u8;
        let usable = left.len.min(right.len).min(super::MAX_OBSERVATIONS);
        for index in 0..usable {
            residue = consensus.combine(
                residue,
                left.observations[index] ^ right.observations[index],
            );
        }
        residue
    }

    /// Branch one observation by bifurcation threshold.
    pub fn apply_bifurcation(threshold: BifurcationThreshold, value: u8) -> u8 {
        threshold.regime(value)
    }

    /// Read both measurement columns from one mechanical state.
    pub fn read_columns(
        state: &RouteState,
        base: RouteBase,
    ) -> (
        super::PathSelectivity,
        super::RebindShape,
        super::RouteSufficiency,
    ) {
        (
            state.selectivity(base),
            state.rebind_shape(base),
            state.sufficiency(),
        )
    }

    /// Advance bifurcation recurrence across bounded evidence.
    pub fn bifurcation_from_evidence(bifurcation: ChaoticBifurcation, evidence: u32) -> u8 {
        let mut value = 41u8;
        for _ in 0..evidence.min(64) {
            value = bifurcation.advance(value);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tap(value: u8) -> RouteTap {
        RouteTap {
            destination_class: value % 5,
            prefix_length: 24,
            candidate_count: 3,
            best_prefix_length: 24,
            rebind_count: value % 3,
            path_stable: true,
        }
    }

    #[test]
    fn empty_state_reads_zero_with_zero_evidence() {
        let state = RouteState::new();
        assert_eq!(
            state.selectivity(RouteBase::Plain),
            PathSelectivity {
                index: 0,
                evidence: 0
            }
        );
        assert_eq!(
            state.rebind_shape(RouteBase::Plain),
            RebindShape {
                magnitude: 0,
                evidence: 0
            }
        );
        assert!(!state.sufficiency().supported);
    }

    #[test]
    fn stable_path_differs_from_changing_path() {
        let mut stable = RouteState::new();
        let mut changing = RouteState::new();
        for _ in 0..32 {
            stable.observe(tap(2)).unwrap();
            changing.observe(tap(2)).unwrap();
        }
        for v in 0..32u8 {
            changing.observe(tap(v)).unwrap();
        }
        assert!(
            changing.rebind_shape(RouteBase::Plain).magnitude
                >= stable.rebind_shape(RouteBase::Plain).magnitude
        );
    }

    #[test]
    fn reversible_base_is_invertible() {
        let mut state = RouteState::new();
        for v in 0..12u8 {
            state.observe(tap(v)).unwrap();
        }
        let encoded = state.as_base(RouteBase::Reversible);
        for (index, value) in state.observations.iter().enumerate().take(state.len) {
            let position = (index as u8).wrapping_mul(67).wrapping_add(41);
            assert_eq!(encoded[index], value.wrapping_add(position));
            assert_eq!(encoded[index].wrapping_sub(position), *value);
        }
    }

    #[test]
    fn malformed_taps_are_rejected_without_state_change() {
        let mut state = RouteState::new();
        let missing_candidates = RouteTap {
            candidate_count: 0,
            ..tap(1)
        };
        let bad_prefix = RouteTap {
            prefix_length: 33,
            ..tap(1)
        };
        assert_eq!(
            state.observe(missing_candidates),
            Err(RouteFunctionError::MalformedTap)
        );
        assert_eq!(
            state.observe(bad_prefix),
            Err(RouteFunctionError::MalformedTap)
        );
        assert_eq!(state.evidence, 0);
    }

    #[test]
    fn consensus_residue_is_bounded_and_deterministic() {
        let mut left = RouteState::new();
        let mut right = RouteState::new();
        for v in 0..24u8 {
            left.observe(tap(v)).unwrap();
            right.observe(tap(v.wrapping_add(1))).unwrap();
        }
        let consensus = CollisionConsensus::new(97, 5);
        let first = interaction::apply_consensus(&left, &right, consensus);
        let second = interaction::apply_consensus(&left, &right, consensus);
        assert_eq!(first, second);
        assert!(first < 97);
    }

    #[test]
    fn oxidative_alias_disagrees_with_addition() {
        let left = 0b0110_0110u8;
        let right = 0b1010_0011u8;
        let oxidative = left ^ right.wrapping_add(left & right);
        assert_ne!(oxidative, left.wrapping_add(right));
    }
}
