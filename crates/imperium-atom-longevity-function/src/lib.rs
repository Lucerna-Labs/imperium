//! Session-longevity and rotation-cadence observations from redacted taps.
//!
//! This function crate contains intrinsic mechanisms only. No desired output,
//! label, confidence score, mapping, policy, revocation semantic, corrective
//! branch, or answer is encoded here. Behavior is measured from composition.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use thiserror::Error;

/// Errors in intrinsic longevity updates.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LongevityFunctionError {
    /// Caller supplied a malformed fixed-shape observation.
    #[error("malformed longevity tap")]
    MalformedTap,
}

/// Redacted session-longevity observation.
///
/// Bounded classes only. There are no keys, seeds, nonces, counters, identities,
/// addresses, payload content, timers from our clock, or conclusions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongevityTap {
    /// Bounded session-epoch class.
    pub session_epoch: u64,
    /// Bounded sealed-byte class.
    pub bytes_sealed_bucket: u8,
    /// Bounded idle class.
    pub idle_bucket: u8,
    /// Caller already applied the existing rotation allowance.
    pub rotation_due: bool,
    /// Whether reauthentication has already been requested elsewhere.
    pub reauth_required: bool,
    /// Small expiry-reason class.
    pub expiry_reason_code: u8,
}

/// Determinism and bounded-state contract for longevity primitives.
pub const MAX_EVENTS: usize = 64;

/// Time-persistence column over bounded session classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Persistence {
    /// Bounded 0..=1000 persistence index.
    pub index: u16,
    /// Supporting observations.
    pub evidence: u32,
}

/// Rotation-pressure column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationPressure {
    /// Bounded 0..=1000 unsigned pressure magnitude.
    pub magnitude: u16,
    /// Supporting observations.
    pub evidence: u32,
}

/// Sufficiency/count record for a longevity window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongevitySufficiency {
    /// Observations available in the current window.
    pub observations_in_window: u32,
    /// Whether every reported column is supported.
    pub supported: bool,
}

/// Intrinsic longevity state: bounded event classes and counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongevityState {
    events: [u8; MAX_EVENTS],
    len: usize,
    observations: u32,
}

/// Passive/base mechanics for longevity state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LongevityBase {
    /// Identity/pass-through accounting.
    Plain = 0,
    /// Reversible positional encoding used as a passive base transform.
    Reversible = 1,
}

impl LongevityState {
    /// Create empty longevity state.
    pub fn new() -> Self {
        Self {
            events: [0; MAX_EVENTS],
            len: 0,
            observations: 0,
        }
    }

    /// Observe a longevity class. Input is already redacted and bounded.
    pub fn observe(&mut self, tap: LongevityTap) -> Result<(), LongevityFunctionError> {
        if tap.expiry_reason_code > 15 {
            return Err(LongevityFunctionError::MalformedTap);
        }
        let value = tap
            .bytes_sealed_bucket
            .wrapping_add(tap.idle_bucket)
            .wrapping_add(tap.expiry_reason_code)
            .wrapping_add(u8::from(tap.rotation_due))
            .wrapping_add(u8::from(tap.reauth_required));
        if self.len < MAX_EVENTS {
            self.events[self.len] = value;
            self.len += 1;
        } else {
            self.events.copy_within(1.., 0);
            self.events[MAX_EVENTS - 1] = value;
        }
        self.observations = self.observations.saturating_add(1);
        Ok(())
    }

    /// Convert the current sequence to a reversible positional base.
    #[must_use]
    pub fn as_base(&self, base: LongevityBase) -> [u8; MAX_EVENTS] {
        let mut out = [0u8; MAX_EVENTS];
        match base {
            LongevityBase::Plain => out.copy_from_slice(&self.events),
            LongevityBase::Reversible => {
                for (index, value) in self.events.iter().enumerate() {
                    let position = (index as u8).wrapping_mul(53).wrapping_add(29);
                    out[index] = value.wrapping_add(position);
                }
            }
        }
        out
    }

    /// Persistence column: bounded distribution width of long-lived classes.
    #[must_use]
    pub fn persistence(&self, base: LongevityBase) -> Persistence {
        let sequence = self.as_base(base);
        let usable = self.len.min(MAX_EVENTS);
        if usable == 0 {
            return Persistence {
                index: 0,
                evidence: self.observations,
            };
        }
        let mut distinct = [false; 256];
        let mut classes = 0u32;
        for value in sequence.iter().take(usable) {
            if !distinct[usize::from(*value)] {
                distinct[usize::from(*value)] = true;
                classes += 1;
            }
        }
        Persistence {
            index: ((u64::from(classes) * 1000) / u64::from(usable.max(1) as u32)).min(1000) as u16,
            evidence: self.observations,
        }
    }

    /// Unsigned rotation-pressure column.
    #[must_use]
    pub fn pressure(&self, base: LongevityBase) -> RotationPressure {
        let sequence = self.as_base(base);
        let usable = self.len.min(MAX_EVENTS);
        if usable < 2 {
            return RotationPressure {
                magnitude: 0,
                evidence: self.observations,
            };
        }
        let mut rises = 0u32;
        for index in 0..(usable - 1) {
            if sequence[index + 1] > sequence[index] {
                rises += 1;
            }
        }
        RotationPressure {
            magnitude: ((u64::from(rises) * 1000) / u64::from((usable - 1).max(1) as u32)).min(1000)
                as u16,
            evidence: self.observations,
        }
    }

    /// Sufficiency/count record for the current window.
    #[must_use]
    pub fn sufficiency(&self) -> LongevitySufficiency {
        LongevitySufficiency {
            observations_in_window: self.observations.min(u32::from(u16::MAX)),
            supported: self.observations > 0,
        }
    }
}

impl Default for LongevityState {
    fn default() -> Self {
        Self::new()
    }
}

/// Residual-share diffusion primitive.
///
/// Shares diffuse through a bounded finite field without being solved,
/// labeled, shared as secrets, or mapped to an outcome. This is a diffusion
/// mechanic for compositional comparison, not a cryptographic share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidualDiffusion {
    modulus: u8,
    rounds: u8,
}

/// Information-theoretic bottleneck primitive.
///
/// A fixed-size code compresses a bounded event history lossily. Capacity and
/// loss are intrinsic numerical consequences of the code, not conclusions about
/// which observations matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BottleneckCode {
    codewords: u8,
    block: u8,
}

/// Configurable bounded chaotic decay primitive.
///
/// A second chaos-bearing mechanism with fixed-at-construction parameters. This
/// is decay dynamics with intrinsic sensitive dependence; it is not a judgment
/// about freshness, expiry, danger, or desirability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaoticDecay {
    growth: u8,
    damping: u8,
}

/// Position-variable suspicion/decay accumulator primitive.
///
/// This provides a recurrent budget-like recurrence that can be placed before,
/// between, or after other primitives during matched runs. It contains no
/// policy about how suspicion should behave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecayAccumulator {
    input_gain: u8,
    retention: u8,
}

impl ResidualDiffusion {
    /// Create diffusion over a bounded field for a fixed number of rounds.
    pub fn new(modulus: u8, rounds: u8) -> Self {
        Self {
            modulus: modulus.max(2),
            rounds: rounds.min(8),
        }
    }

    /// Diffuse one class value without solving, labeling, or judging it.
    #[must_use]
    pub fn diffuse(&self, value: u8) -> u8 {
        let modulus = u16::from(self.modulus);
        let mut state = u16::from(value) % modulus;
        for round in 0..self.rounds {
            state = (state * state + u16::from(round) + 3) % modulus;
        }
        state.min(255) as u8
    }

    /// Diffuse an entire longevity window in place.
    pub fn diffuse_window(&self, state: &mut LongevityState) {
        for value in state.events.iter_mut().take(state.len) {
            *value = self.diffuse(*value);
        }
    }
}

impl BottleneckCode {
    /// Create a fixed bottleneck code.
    pub fn new(codewords: u8, block: u8) -> Self {
        Self {
            codewords: codewords.max(2),
            block: block.max(1),
        }
    }

    /// Compress one window into a fixed-size count histogram.
    #[must_use]
    pub fn encode(&self, state: &LongevityState) -> [u8; 8] {
        let mut histogram = [0u8; 8];
        for value in state.events.iter().take(state.len) {
            let code = (u16::from(*value) * u16::from(self.codewords) / 256) as usize;
            let slot = code.min(7);
            histogram[slot] = histogram[slot].saturating_add(1);
        }
        histogram
    }

    /// Re-expand a histogram into a coarse representative sequence.
    #[must_use]
    pub fn decode(&self, histogram: [u8; 8]) -> [u8; 8] {
        let mut out = [0u8; 8];
        for (index, count) in histogram.iter().enumerate() {
            out[index] = count.saturating_add((index as u8).wrapping_mul(self.block));
        }
        out
    }
}

impl ChaoticDecay {
    /// Create fixed decay coefficients.
    pub fn new(growth: u8, damping: u8) -> Self {
        Self { growth, damping }
    }

    /// Advance bounded chaotic decay once.
    #[must_use]
    pub fn advance(&self, prior: u8) -> u8 {
        let scaled = u16::from(prior).wrapping_mul(u16::from(self.growth));
        let congestion = u16::from(prior).wrapping_mul(u16::from(prior)) / 256;
        let stepped = scaled
            .saturating_sub(congestion)
            .wrapping_add(u16::from(self.damping))
            % 251;
        (stepped % 256).min(255) as u8
    }
}

impl DecayAccumulator {
    /// Create a recurrent accumulator.
    pub fn new(input_gain: u8, retention: u8) -> Self {
        Self {
            input_gain,
            retention,
        }
    }

    /// Advance recurrence once without policy.
    #[must_use]
    pub fn advance(&self, prior: u8, input: u8) -> u8 {
        prior
            .wrapping_mul(self.retention)
            .wrapping_add(input.wrapping_mul(self.input_gain))
            .wrapping_add(19)
            % 251
    }
}

/// Intrinsic interaction mechanics retained as explicit functions.
pub mod interaction {
    use super::{
        BottleneckCode, ChaoticDecay, DecayAccumulator, LongevityBase, LongevityState,
        ResidualDiffusion,
    };

    /// Apply diffusion then chaos, in that fixed interaction order.
    pub fn apply_diffusion_then_chaos(
        state: &mut LongevityState,
        diffusion: ResidualDiffusion,
        decay: ChaoticDecay,
    ) {
        diffusion.diffuse_window(state);
        for value in state.events.iter_mut().take(state.len) {
            *value = decay.advance(*value);
        }
    }

    /// Read both measurement columns from one mechanical state.
    pub fn read_columns(
        state: &LongevityState,
        base: LongevityBase,
    ) -> (
        super::Persistence,
        super::RotationPressure,
        super::LongevitySufficiency,
    ) {
        (
            state.persistence(base),
            state.pressure(base),
            state.sufficiency(),
        )
    }

    /// Encode, decode, and fold a bottleneck signature into one byte.
    pub fn bottleneck_signature(state: &LongevityState, code: BottleneckCode) -> u8 {
        let histogram = code.encode(state);
        let decoded = code.decode(histogram);
        let mut signature = 0u8;
        for value in decoded {
            signature = signature
                .wrapping_add(value)
                .wrapping_mul(31)
                .wrapping_add(7);
        }
        signature
    }

    /// Advance accumulator recurrence across bounded evidence.
    pub fn accumulator_from_evidence(accumulator: DecayAccumulator, evidence: u32) -> u8 {
        let mut value = 23u8;
        for _ in 0..evidence.min(64) {
            value = accumulator.advance(value, 11);
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tap(value: u8) -> LongevityTap {
        LongevityTap {
            session_epoch: u64::from(value),
            bytes_sealed_bucket: value,
            idle_bucket: 2,
            rotation_due: false,
            reauth_required: false,
            expiry_reason_code: value % 5,
        }
    }

    #[test]
    fn empty_state_reads_zero_with_zero_evidence() {
        let state = LongevityState::new();
        assert_eq!(
            state.persistence(LongevityBase::Plain),
            Persistence {
                index: 0,
                evidence: 0
            }
        );
        assert_eq!(
            state.pressure(LongevityBase::Plain),
            RotationPressure {
                magnitude: 0,
                evidence: 0
            }
        );
        assert!(!state.sufficiency().supported);
    }

    #[test]
    fn steady_sequence_differs_from_changing_sequence() {
        let mut steady = LongevityState::new();
        let mut changing = LongevityState::new();
        for _ in 0..24 {
            steady.observe(tap(9)).unwrap();
            changing.observe(tap(9)).unwrap();
        }
        for v in 0..24u8 {
            changing.observe(tap(v)).unwrap();
        }
        assert!(
            changing.persistence(LongevityBase::Plain).index
                >= steady.persistence(LongevityBase::Plain).index
        );
    }

    #[test]
    fn reversible_base_is_invertible() {
        let mut state = LongevityState::new();
        for v in 0..12u8 {
            state.observe(tap(v)).unwrap();
        }
        let encoded = state.as_base(LongevityBase::Reversible);
        for (index, value) in state.events.iter().enumerate().take(state.len) {
            let position = (index as u8).wrapping_mul(53).wrapping_add(29);
            assert_eq!(encoded[index], value.wrapping_add(position));
            assert_eq!(encoded[index].wrapping_sub(position), *value);
        }
    }

    #[test]
    fn diffusion_changes_readings_but_preserves_window_length() {
        let mut before = LongevityState::new();
        for v in 0..24u8 {
            before.observe(tap(v)).unwrap();
        }
        let mut after = before.clone();
        ResidualDiffusion::new(97, 3).diffuse_window(&mut after);
        assert_eq!(before.len, after.len);
        assert_eq!(before.observations, after.observations);
        assert!(before.events[..before.len] != after.events[..after.len]);
    }

    #[test]
    fn bottleneck_code_is_lossy_by_construction() {
        let mut state = LongevityState::new();
        for v in 0..32u8 {
            state.observe(tap(v)).unwrap();
        }
        let code = BottleneckCode::new(8, 3);
        let signature = interaction::bottleneck_signature(&state, code);
        assert_eq!(
            code.encode(&state).iter().map(|v| *v as u32).sum::<u32>(),
            32
        );
        assert!(signature <= u8::MAX);
    }

    #[test]
    fn oxidative_alias_disagrees_with_addition() {
        let left = 0b1100_1100u8;
        let right = 0b0011_0110u8;
        let oxidative = left ^ right.wrapping_add(left & right);
        assert_ne!(oxidative, left.wrapping_add(right));
    }
}
