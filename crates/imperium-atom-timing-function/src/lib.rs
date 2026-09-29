//! Timing/pacing observations from redacted tap classes.
//!
//! This function crate contains intrinsic mechanisms only. It does not encode a
//! desired composite output, adversary label, confidence score, threshold
//! conclusion, mapping, policy, revocation semantic, corrective branch, or
//! prewritten answer. Composition behavior is measured, not prescribed.
//!
//! The outputs are separate measurement columns and sufficiency records. They
//! must not be folded into one scalar.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use thiserror::Error;

/// Errors in intrinsic mechanical updates.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TimingFunctionError {
    /// Caller supplied a malformed fixed-shape observation.
    #[error("malformed timing tap")]
    MalformedTap,
}

/// Redacted timing/pacing observation.
///
/// These fields mirror `VPN-CRYPTO-FREEZE.md` tap classes: bounded buckets and
/// fixed enums only. There are no addresses, sessions, payloads, labels,
/// nonces, or free-form values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimingTap {
    /// Bounded packet sequence class.
    pub frame_counter: u64,
    /// Bounded inter-arrival bucket.
    pub inter_arrival_bucket: u8,
    /// Bounded transmit-delay bucket.
    pub delay_bucket: u8,
    /// Configured jitter ceiling in milliseconds.
    pub jitter_ceiling_ms: u16,
    /// Whether the observed cadence supplied enough evidence.
    pub cadence_sufficient: bool,
    /// Whether coalescing was active for this observation.
    pub coalesced: bool,
}

/// Determinism and bounded-state contract for timing primitives.
pub const MAX_WINDOW: usize = 64;

/// Arrangement reading over bounded cadence classes.
///
/// This is one column, not a verdict. Callers must read `evidence` first:
/// `evidence == 0` means unmeasured rather than flat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CadenceArrangement {
    /// Bounded 0..=1000 arrangement index.
    pub index: u16,
    /// Number of observations supporting the reading.
    pub evidence: u32,
}

/// Trend-magnitude reading.
///
/// `magnitude` is unsigned and therefore intentionally does not distinguish
/// acceleration from deceleration. Direction, if later needed, belongs in a
/// separate column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CadenceTrend {
    /// Bounded 0..=1000 unsigned trend magnitude.
    pub magnitude: u16,
    /// Number of observations supporting the reading.
    pub evidence: u32,
}

/// Sufficiency/count record for a timing window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimingSufficiency {
    /// Observations available in the current window.
    pub observations_in_window: u32,
    /// Whether every reported column is supported.
    pub supported: bool,
}

/// Intrinsic timing state: bounded cadence classes and deterministic counters.
///
/// All update behavior is mechanical. No method interprets the state as benign,
/// hostile, preferred, or actionable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimingState {
    window: [u8; MAX_WINDOW],
    len: usize,
    observations: u32,
}

/// Passive/base mechanics of the timing state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingBase {
    /// Identity/pass-through accounting.
    Plain = 0,
    /// Reversible positional encoding used as a passive base transform.
    Reversible = 1,
}

impl TimingState {
    /// Create empty timing state.
    pub fn new() -> Self {
        Self {
            window: [0; MAX_WINDOW],
            len: 0,
            observations: 0,
        }
    }

    /// Observe a timing class. The input is already redacted and bounded.
    pub fn observe(&mut self, tap: TimingTap) -> Result<(), TimingFunctionError> {
        if tap.jitter_ceiling_ms == 0 && !tap.cadence_sufficient {
            return Err(TimingFunctionError::MalformedTap);
        }

        let value = tap
            .inter_arrival_bucket
            .wrapping_add(tap.delay_bucket)
            .wrapping_add(u8::from(tap.coalesced));
        if self.len < MAX_WINDOW {
            self.window[self.len] = value;
            self.len += 1;
        } else {
            self.window.copy_within(1.., 0);
            self.window[MAX_WINDOW - 1] = value;
        }
        self.observations = self.observations.saturating_add(1);
        Ok(())
    }

    /// Convert the current sequence to a reversible positional base.
    ///
    /// This is an invertible transform, not an interpretation: downstream
    /// measurements consume either `Plain` or `Reversible`, and base ablations
    /// compare both.
    #[must_use]
    pub fn as_base(&self, base: TimingBase) -> [u8; MAX_WINDOW] {
        let mut out = [0u8; MAX_WINDOW];
        match base {
            TimingBase::Plain => out.copy_from_slice(&self.window),
            TimingBase::Reversible => {
                for (index, value) in self.window.iter().enumerate() {
                    let position = (index as u8).wrapping_mul(37).wrapping_add(11);
                    out[index] = value.wrapping_add(position);
                }
            }
        }
        out
    }

    /// Arrangement column: bounded count of adjacent inversions over
    /// consecutive classes. This measures whether the sequence keeps changing
    /// direction, not whether that sequence is good, bad, hostile, or benign.
    /// A monotone ramp and a flat metronome both read near zero; an
    /// alternation reads high.
    #[must_use]
    pub fn arrangement(&self, base: TimingBase) -> CadenceArrangement {
        let sequence = self.as_base(base);
        let usable = self.len.min(MAX_WINDOW);
        if usable < 3 {
            return CadenceArrangement {
                index: 0,
                evidence: self.observations,
            };
        }
        let mut alternations = 0u32;
        let mut comparable = 0u32;
        for index in 0..(usable - 2) {
            let first = sequence[index];
            let second = sequence[index + 1];
            let third = sequence[index + 2];
            if first == second || second == third {
                continue;
            }
            comparable += 1;
            let rose_then_fell = first < second && second > third;
            let fell_then_rose = first > second && second < third;
            if rose_then_fell || fell_then_rose {
                alternations += 1;
            }
        }
        let index = if comparable == 0 {
            0
        } else {
            ((u64::from(alternations) * 1000) / u64::from(comparable)).min(1000) as u16
        };
        CadenceArrangement {
            index,
            evidence: self.observations,
        }
    }

    /// Unsigned trend-magnitude column over the observed window.
    #[must_use]
    pub fn trend(&self, base: TimingBase) -> CadenceTrend {
        let sequence = self.as_base(base);
        let usable = self.len.min(MAX_WINDOW);
        if usable < 2 {
            return CadenceTrend {
                magnitude: 0,
                evidence: self.observations,
            };
        }
        let first = u64::from(sequence[0]);
        let last = u64::from(sequence[usable - 1]);
        let span = u64::from(usable.saturating_sub(1).max(1) as u32);
        let change = first.abs_diff(last).saturating_mul(1000);
        let mean = (first + last + 1) / 2;
        let magnitude = (change / (span * mean.max(1))).min(1000) as u16;
        CadenceTrend {
            magnitude,
            evidence: self.observations,
        }
    }

    /// Sufficiency/count record for the current window.
    #[must_use]
    pub fn sufficiency(&self) -> TimingSufficiency {
        TimingSufficiency {
            observations_in_window: self.observations.min(u32::from(u16::MAX)),
            supported: self.observations > 0,
        }
    }
}

impl Default for TimingState {
    fn default() -> Self {
        Self::new()
    }
}

/// Catalytic coupling primitive: bounded history coupling without instruction.
///
/// The candidate state absorbs a bounded trace of the reference state. This
/// changes subsequent mechanical readings; it does not encode what those
/// readings mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCoupling {
    trace: [u8; 16],
    len: usize,
}

/// Chemistry-adjacent catalytic-barrier primitive.
///
/// The barrier is a bounded threshold over available history. It gates whether
/// catalytic coupling applies to a state. It is not an allow/deny judgment:
/// it emits a numerical residual that downstream mechanisms can consume without
/// interpreting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalyticBarrier {
    threshold: u8,
}

/// Configurable chaotic mixing primitive.
///
/// This is one required chaos-bearing mechanism. Its parameters are fixed when
/// constructed and never tuned by execution. The constructor selects
/// coefficients; `mix` applies them deterministically. Promotion requires frozen
/// benefit under matched controls, not the mere presence of irregular values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaoticMixer {
    first: u8,
    second: u8,
}

/// Position-variable transport-delay primitive.
///
/// This emulates a different stack position without moving code: the same
/// numeric delay recurrence can be placed logically before, between, or after
/// other primitives. Its recurrence is chaotic by construction, but it
/// contains no conclusion about placement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportDelay {
    slope: u8,
    intercept: u8,
}

impl HistoryCoupling {
    /// Start with empty bounded history.
    pub fn new() -> Self {
        Self {
            trace: [0; 16],
            len: 0,
        }
    }

    /// Absorb a bounded sample from a reference state.
    pub fn absorb(&mut self, sample: u8) {
        if self.len < self.trace.len() {
            self.trace[self.len] = sample;
            self.len += 1;
        } else {
            self.trace.copy_within(1.., 0);
            self.trace[self.trace.len() - 1] = sample;
        }
    }

    /// Apply the absorbed history as a bounded offset to a timing state.
    pub fn couple(&self, state: &mut TimingState) {
        let mut offset = 0u8;
        for index in 0..self.len {
            offset = offset.wrapping_add(self.trace[index]);
        }
        for value in state.window.iter_mut().take(state.len) {
            *value = value.wrapping_add(offset);
        }
    }
}

impl Default for HistoryCoupling {
    fn default() -> Self {
        Self::new()
    }
}

impl CatalyticBarrier {
    /// Create a barrier from an intrinsic chemistry-adjacent threshold.
    pub fn new(threshold: u8) -> Self {
        Self { threshold }
    }

    /// Measure available reactant/history and return the residual.
    ///
    /// Values at or above the threshold read as zero residual; lower values
    /// read as their distance from saturation. The residual is data for later
    /// mechanisms, not a pass/fail label.
    #[must_use]
    pub fn residual(&self, history: &HistoryCoupling) -> u8 {
        let available = history.len.min(255) as u8;
        self.threshold.saturating_sub(available)
    }

    /// Catalyze one candidate state from a reference state when history is
    /// available. This helper may be used in composition runs; it contains no
    /// rule that says coupling *should* happen.
    pub fn catalyze(&self, history: &HistoryCoupling, candidate: &TimingState) -> TimingState {
        let mut next = candidate.clone();
        if self.residual(history) < self.threshold {
            history.couple(&mut next);
        }
        next
    }
}

impl ChaoticMixer {
    /// Create deterministic mixer coefficients.
    pub fn new(first: u8, second: u8) -> Self {
        Self { first, second }
    }

    /// Apply bounded nonlinear recurrence to one byte.
    #[must_use]
    pub fn mix(&self, value: u8) -> u8 {
        let scaled = u16::from(value).wrapping_mul(u16::from(self.first));
        let folded = (scaled + u16::from(self.second)) % 251;
        let stepped = folded.wrapping_mul(u16::from(value.wrapping_add(7))) % 251;
        (stepped % 256).min(255) as u8
    }

    /// Mix an entire timing window in place.
    pub fn mix_window(&self, state: &mut TimingState) {
        for value in state.window.iter_mut().take(state.len) {
            *value = self.mix(*value);
        }
    }
}

impl TransportDelay {
    /// Create a deterministic recurrent delay primitive.
    pub fn new(slope: u8, intercept: u8) -> Self {
        Self { slope, intercept }
    }

    /// Advance delay recurrence once.
    #[must_use]
    pub fn advance(&self, prior: u8) -> u8 {
        prior
            .wrapping_mul(self.slope)
            .wrapping_add(self.intercept)
            .wrapping_add(13)
            % 251
    }
}

/// Intrinsic interaction mechanics retained as explicit functions.
pub mod interaction {
    use super::{
        CatalyticBarrier, ChaoticMixer, HistoryCoupling, TimingBase, TimingState, TransportDelay,
    };

    /// Apply chaos to a timing window without encoding position or benefit.
    pub fn apply_chaos(state: &mut TimingState, mixer: ChaoticMixer) {
        mixer.mix_window(state);
    }

    /// Apply catalytic coupling without encoding intent.
    pub fn apply_coupling(
        barrier: CatalyticBarrier,
        history: &HistoryCoupling,
        candidate: &TimingState,
    ) -> TimingState {
        barrier.catalyze(history, candidate)
    }

    /// Read both measurement columns from one mechanical state.
    pub fn read_columns(
        state: &TimingState,
        base: TimingBase,
    ) -> (
        super::CadenceArrangement,
        super::CadenceTrend,
        super::TimingSufficiency,
    ) {
        (
            state.arrangement(base),
            state.trend(base),
            state.sufficiency(),
        )
    }

    /// Advance a transport-delay recurrence through the observed evidence count.
    pub fn delay_from_evidence(delay: TransportDelay, evidence: u32) -> u8 {
        let mut value = 17u8;
        for _ in 0..evidence.min(64) {
            value = delay.advance(value);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tap(value: u8) -> TimingTap {
        TimingTap {
            frame_counter: u64::from(value),
            inter_arrival_bucket: value,
            delay_bucket: 3,
            jitter_ceiling_ms: 20,
            cadence_sufficient: true,
            coalesced: false,
        }
    }

    #[test]
    fn empty_state_reads_zero_with_zero_evidence() {
        let state = TimingState::new();
        assert_eq!(
            state.arrangement(TimingBase::Plain),
            CadenceArrangement {
                index: 0,
                evidence: 0
            }
        );
        assert_eq!(
            state.trend(TimingBase::Plain),
            CadenceTrend {
                magnitude: 0,
                evidence: 0
            }
        );
        assert!(!state.sufficiency().supported);
    }

    #[test]
    fn monotone_sequence_separates_from_metronome_only_with_trend() {
        let mut ramp = TimingState::new();
        let mut flat = TimingState::new();
        for v in 0..32u8 {
            ramp.observe(tap(v)).unwrap();
            flat.observe(tap(7)).unwrap();
        }
        let ramp_arrangement = ramp.arrangement(TimingBase::Plain);
        let flat_arrangement = flat.arrangement(TimingBase::Plain);
        let ramp_trend = ramp.trend(TimingBase::Plain);
        let flat_trend = flat.trend(TimingBase::Plain);
        assert_eq!(ramp_arrangement.index, flat_arrangement.index);
        assert!(ramp_trend.magnitude > flat_trend.magnitude);
    }

    #[test]
    fn reversible_base_is_invertible() {
        let mut state = TimingState::new();
        for v in 0..16u8 {
            state.observe(tap(v.wrapping_mul(5))).unwrap();
        }
        let encoded = state.as_base(TimingBase::Reversible);
        for (index, value) in state.window.iter().enumerate().take(state.len) {
            let position = (index as u8).wrapping_mul(37).wrapping_add(11);
            assert_eq!(encoded[index], value.wrapping_add(position));
            assert_eq!(encoded[index].wrapping_sub(position), *value);
        }
    }

    #[test]
    fn barrier_reports_residual_not_verdict() {
        let barrier = CatalyticBarrier::new(8);
        let empty = HistoryCoupling::new();
        let mut history = HistoryCoupling::new();
        for v in 0..10u8 {
            history.absorb(v);
        }
        assert!(barrier.residual(&empty) > barrier.residual(&history));
    }

    #[test]
    fn chaos_changes_readings_without_claiming_benefit() {
        let mut plain = TimingState::new();
        let mut mixed = TimingState::new();
        for v in 0..32u8 {
            plain.observe(tap(v)).unwrap();
            mixed.observe(tap(v)).unwrap();
        }
        ChaoticMixer::new(61, 17).mix_window(&mut mixed);
        assert_ne!(
            plain.arrangement(TimingBase::Plain),
            mixed.arrangement(TimingBase::Plain)
        );
    }

    #[test]
    fn oxidative_alias_disagrees_with_addition() {
        // Guard the chemistry-adjacent reading: an XOR-style oxidative spread
        // must not collapse to a conventional wrapping sum. The mechanism is
        // retained for its disagreement, not because it is obviously better.
        let left = 0b1010_1010u8;
        let right = 0b0101_1111u8;
        let oxidative = left ^ right.wrapping_add(left & right);
        assert_ne!(oxidative, left.wrapping_add(right));
    }
}
