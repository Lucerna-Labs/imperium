//! First-principles function crate: quantum-derived passive base plus classical
//! shape mechanics.
//!
//! The linkage is structural, not instructed. A quantum-derived load-bearing
//! base supplies a passive substrate (normalized real amplitudes, a unitary
//! transform, Born-weighted evidence). A classical shape mechanism consumes
//! only the base's emitted evidence. No desired composite output, target map,
//! label, policy, corrective branch, or prewritten answer is present.
//!
//! Classical physics on a classical CPU. Nothing here is a qubit,
//! superposition, entanglement, collapse, no-cloning, quantum randomness,
//! advantage, QPU execution, or quantum security.

/// Fixed base dimension. Small by design: this is a side experiment.
pub const DIM: usize = 4;
/// Fixed evidence depth for one engine step.
pub const EVIDENCE: usize = 8;

/// Errors in intrinsic mechanical updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FunctionError {
    /// Caller supplied a malformed fixed-shape input.
    MalformedInput,
}

impl core::fmt::Display for FunctionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FunctionError::MalformedInput => write!(f, "malformed function input"),
        }
    }
}

/// Quantum-derived amplification base: selective amplitude concentration.
///
/// Intrinsic mechanics: a fixed unitary rotation moves population toward one
/// marked slot, then a fixed nonlinear gain sharpens the dominant amplitude
/// while renormalizing. This is amplitude amplification in structure — the
/// marked component grows relative to the rest — implemented as classical
/// mathematics on real amplitudes. It is not a qubit, oracle, Grover circuit,
/// measurement collapse, or quantum hardware.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct QuantumBase {
    amplitudes: [f64; DIM],
    /// Marked slot the rotation concentrates population toward.
    marked: usize,
    /// Fixed nonlinear gain applied to the marked amplitude each step.
    gain: f64,
}

/// Temperature schedule: a fixed, open-loop sequence of gain values.
///
/// Temperature here means one thing only: the per-step nonlinear gain applied
/// to the marked amplitude. It is a schedule, not a sensor — fixed before
/// execution, never read from state, never adapted to results. The analogy to
/// classical chaos knobs is structural: both vary how hard the dynamics push
/// per step. Whether temperature moves held-out discrimination monotonically,
/// non-monotonically, or not at all is measured, not assumed.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TemperatureSchedule {
    gains: [f64; 8],
    len: usize,
}

impl TemperatureSchedule {
    /// Fixed isothermal schedule: the same gain every step.
    #[must_use]
    pub fn isothermal(gain: f64) -> Self {
        TemperatureSchedule {
            gains: [gain.clamp(1.0, 2.0); 8],
            len: 8,
        }
    }

    /// Fixed anneal schedule: gains decrease across steps.
    #[must_use]
    pub fn anneal(hot: f64, cold: f64) -> Self {
        let mut gains = [cold.clamp(1.0, 2.0); 8];
        for (index, gain) in gains.iter_mut().enumerate() {
            let fraction = index as f64 / 7.0;
            *gain = (hot * (1.0 - fraction) + cold * fraction).clamp(1.0, 2.0);
        }
        TemperatureSchedule { gains, len: 8 }
    }

    /// Fixed quench schedule: gains increase across steps.
    #[must_use]
    pub fn quench(cold: f64, hot: f64) -> Self {
        let mut gains = [hot.clamp(1.0, 2.0); 8];
        for (index, gain) in gains.iter_mut().enumerate() {
            let fraction = index as f64 / 7.0;
            *gain = (cold * (1.0 - fraction) + hot * fraction).clamp(1.0, 2.0);
        }
        TemperatureSchedule { gains, len: 8 }
    }

    /// Gain for a step index, cycling deterministically.
    #[must_use]
    pub fn gain_at(&self, step: usize) -> f64 {
        self.gains[step % self.len.max(1)]
    }
}

impl QuantumBase {
    /// Build from raw weights, normalize, and fix the marked slot and gain.
    /// Pure intrinsic mechanics; the marked slot and gain are structural
    /// parameters of this base, not instructions about any input.
    #[must_use]
    pub fn new(weights: [f64; DIM]) -> Self {
        Self::with_marked(weights, 0, 1.35)
    }

    /// Build with an explicit marked slot and gain. Both are fixed at
    /// construction and never tuned by execution.
    #[must_use]
    pub fn with_marked(weights: [f64; DIM], marked: usize, gain: f64) -> Self {
        let mut norm_sq = 0.0;
        for value in weights {
            norm_sq += value * value;
        }
        let norm = norm_sq.sqrt().max(1e-12);
        let mut amplitudes = [0.0; DIM];
        for (index, value) in weights.iter().enumerate() {
            amplitudes[index] = *value / norm;
        }
        QuantumBase {
            amplitudes,
            marked: marked % DIM,
            gain: gain.clamp(1.0, 2.0),
        }
    }

    /// Marked slot this base concentrates toward.
    #[must_use]
    pub fn marked(&self) -> usize {
        self.marked
    }

    /// Fixed nonlinear gain.
    #[must_use]
    pub fn gain(&self) -> f64 {
        self.gain
    }

    /// Squared norm. Always 1 within floating tolerance by construction.
    #[must_use]
    pub fn norm_sq(&self) -> f64 {
        let mut total = 0.0;
        for value in self.amplitudes {
            total += value * value;
        }
        total
    }

    /// One amplification step at this base's fixed gain.
    #[must_use]
    pub fn amplify(&self) -> Self {
        self.amplify_at(self.gain)
    }

    /// One amplification step at a scheduled gain. Same mechanics as
    /// [`QuantumBase::amplify`]; the gain comes from a fixed open-loop
    /// schedule rather than the base's own fixed value. Never adapted.
    #[must_use]
    pub fn amplify_at(&self, gain: f64) -> Self {
        // Fixed nonlinear gain on the marked amplitude first: raise its
        // magnitude to the scheduled power while preserving sign, bounded and
        // deterministic.
        let marked_value = self.amplitudes[self.marked];
        let sign = if marked_value < 0.0 { -1.0 } else { 1.0 };
        let scheduled = gain.clamp(1.0, 2.0);
        let mut rotated = self.amplitudes;
        rotated[self.marked] = sign * marked_value.abs().powf(scheduled).min(16.0);
        // Fixed rotation: move one eighth of each unmarked amplitude in.
        for index in 0..DIM {
            if index != self.marked {
                let moved = rotated[index] * 0.125;
                rotated[index] -= moved;
                rotated[self.marked] += moved;
            }
        }
        // Renormalize: concentration, not creation.
        let mut norm_sq = 0.0;
        for value in rotated {
            norm_sq += value * value;
        }
        let norm = norm_sq.sqrt().max(1e-12);
        let mut amplitudes = [0.0; DIM];
        for (index, value) in rotated.iter().enumerate() {
            amplitudes[index] = *value / norm;
        }
        QuantumBase {
            amplitudes,
            marked: self.marked,
            gain: self.gain,
        }
    }

    /// Fixed Walsh-style unitary mixing transform (kept for the base-only
    /// control and for ablation against the amplification step).
    #[must_use]
    pub fn unitary_mix(&self) -> Self {
        // 4x4 Hadamard-pattern unitary over reals, scaled by 1/2.
        let signs = [
            [1.0, 1.0, 1.0, 1.0],
            [1.0, -1.0, 1.0, -1.0],
            [1.0, 1.0, -1.0, -1.0],
            [1.0, -1.0, -1.0, 1.0],
        ];
        let mut out = [0.0; DIM];
        for row in 0..DIM {
            let mut total = 0.0;
            for column in 0..DIM {
                total += signs[row][column] * self.amplitudes[column];
            }
            out[row] = total * 0.5;
        }
        QuantumBase {
            amplitudes: out,
            marked: self.marked,
            gain: self.gain,
        }
    }

    /// Born-weighted evidence: squared amplitudes scaled to evidence depth.
    /// This is the only channel the classical layer may read.
    #[must_use]
    pub fn born_evidence(&self) -> [u8; EVIDENCE] {
        let mut evidence = [0u8; EVIDENCE];
        for index in 0..EVIDENCE {
            let slot = index % DIM;
            let weight = self.amplitudes[slot] * self.amplitudes[slot];
            evidence[index] = (weight * 255.0).clamp(0.0, 255.0) as u8;
        }
        evidence
    }

    /// Marked-slot probability: the quantity amplification concentrates.
    #[must_use]
    pub fn marked_probability(&self) -> f64 {
        self.amplitudes[self.marked] * self.amplitudes[self.marked]
    }
}

/// Classical intrinsic state: bounded shape register fed only by base evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShapeState {
    cells: [u8; EVIDENCE],
    len: usize,
    observations: u32,
}

impl ShapeState {
    /// Empty shape register.
    pub fn new() -> Self {
        ShapeState {
            cells: [0; EVIDENCE],
            len: 0,
            observations: 0,
        }
    }

    /// Absorb base evidence mechanically. No interpretation of what it means.
    pub fn absorb(&mut self, evidence: [u8; EVIDENCE]) {
        for value in evidence {
            if self.len < self.cells.len() {
                self.cells[self.len] = value;
                self.len += 1;
            } else {
                self.cells.copy_within(1.., 0);
                let last = self.cells.len() - 1;
                self.cells[last] = value;
            }
            self.observations = self.observations.saturating_add(1);
        }
    }

    /// Arrangement column: bounded count of direction changes over triples.
    #[must_use]
    pub fn arrangement(&self) -> u16 {
        if self.len < 3 {
            return 0;
        }
        let mut alternations = 0u32;
        let mut comparable = 0u32;
        for index in 0..(self.len - 2) {
            let (a, b, c) = (
                self.cells[index],
                self.cells[index + 1],
                self.cells[index + 2],
            );
            if a == b || b == c {
                continue;
            }
            comparable += 1;
            if (a < b && b > c) || (a > b && b < c) {
                alternations += 1;
            }
        }
        if comparable == 0 {
            0
        } else {
            ((u64::from(alternations) * 1000) / u64::from(comparable)).min(1000) as u16
        }
    }

    /// Magnitude column: bounded spread of the register.
    #[must_use]
    pub fn spread(&self) -> u16 {
        if self.len < 2 {
            return 0;
        }
        let mut low = u8::MAX;
        let mut high = u8::MIN;
        for value in self.cells.iter().take(self.len) {
            if *value < low {
                low = *value;
            }
            if *value > high {
                high = *value;
            }
        }
        u16::from(high.saturating_sub(low)).min(1000)
    }

    /// Observations absorbed so far.
    #[must_use]
    pub fn evidence(&self) -> u32 {
        self.observations
    }
}

impl Default for ShapeState {
    fn default() -> Self {
        Self::new()
    }
}

/// Composed intrinsic state: base below, classical shape above.
/// The classical layer reads ONLY the base's emitted Born evidence.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinkedState {
    base: QuantumBase,
    shape: ShapeState,
}

impl LinkedState {
    /// Seed from raw weights. Intrinsic construction only.
    #[must_use]
    pub fn seed(weights: [f64; DIM]) -> Self {
        LinkedState {
            base: QuantumBase::new(weights),
            shape: ShapeState::new(),
        }
    }

    /// One intrinsic step: amplify the base, emit evidence, absorb into shape.
    pub fn step(&mut self) {
        let amplified = self.base.amplify();
        self.base = amplified;
        let evidence = amplified.born_evidence();
        self.shape.absorb(evidence);
    }

    /// Read the classical measurement columns.
    #[must_use]
    pub fn read(&self) -> (u16, u16, u32) {
        (
            self.shape.arrangement(),
            self.shape.spread(),
            self.shape.evidence(),
        )
    }

    /// Base norm invariant probe.
    #[must_use]
    pub fn base_norm_sq(&self) -> f64 {
        self.base.norm_sq()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_normalizes_by_construction() {
        let base = QuantumBase::new([3.0, 4.0, 0.0, 0.0]);
        assert!((base.norm_sq() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn unitary_mix_preserves_norm() {
        let base = QuantumBase::new([1.0, 2.0, 3.0, 4.0]);
        let mixed = base.unitary_mix();
        assert!((mixed.norm_sq() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn amplification_concentrates_marked_probability() {
        // Intrinsic benefit probe: repeated amplify steps must concentrate
        // the marked slot monotonically from the seed, with norm preserved.
        // The comparison is the seed baseline — not a one-shot Walsh mix,
        // which dumps 83% into slot 0 on this seed by construction and then
        // oscillates back (0.033 → 0.833 → 0.033). Amplification climbs
        // steadily instead: 0.033 → 0.112 → 0.210 → 0.321 → 0.438 → 0.553.
        let seed = [1.0, 2.0, 3.0, 4.0];
        let base = QuantumBase::new(seed);
        let seed_marked = base.marked_probability();
        let mut amplified = base;
        let mut previous = seed_marked;
        for _ in 0..5 {
            amplified = amplified.amplify();
            let current = amplified.marked_probability();
            assert!(
                current > previous,
                "amplification must concentrate monotonically: {previous} -> {current}"
            );
            previous = current;
        }
        assert!((amplified.norm_sq() - 1.0).abs() < 1e-9);
        assert!(
            amplified.marked_probability() > seed_marked,
            "amplified={} seed={}",
            amplified.marked_probability(),
            seed_marked
        );
    }

    #[test]
    fn amplification_is_deterministic_and_bounded() {
        let first = QuantumBase::new([0.5, 1.5, 2.5, 3.5]);
        let second = QuantumBase::new([0.5, 1.5, 2.5, 3.5]);
        assert_eq!(first.amplify(), second.amplify());
        let walked = first.amplify().amplify().amplify();
        for index in 0..DIM {
            assert!(walked.born_evidence()[index] <= u8::MAX);
        }
    }

    #[test]
    fn evidence_is_deterministic() {
        let base = QuantumBase::new([1.0, 1.0, 1.0, 1.0]);
        assert_eq!(base.born_evidence(), base.born_evidence());
    }

    #[test]
    fn empty_shape_reads_zero() {
        let state = LinkedState::seed([1.0, 0.0, 0.0, 0.0]);
        let (arrangement, spread, evidence) = state.read();
        assert_eq!((arrangement, spread, evidence), (0, 0, 0));
    }

    #[test]
    fn steps_accumulate_evidence() {
        let mut state = LinkedState::seed([1.0, 2.0, 3.0, 4.0]);
        state.step();
        state.step();
        let (_, _, evidence) = state.read();
        assert_eq!(evidence, 2 * EVIDENCE as u32);
    }
}
