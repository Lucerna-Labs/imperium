//! Fixed execution, observation, and return for the linked stack.
//!
//! No desired output, verdict, corrective logic, content-dependent routing,
//! policy, or postprocessing toward an answer. The engine arranges the single
//! declared order, executes intrinsic mechanics, observes measurements, and
//! returns them. Behavior belongs to the whole composition, per Rule 4.

use qclink_function::{FunctionError, LinkedState, DIM};

/// Errors in fixed orchestration execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineError {
    /// Caller supplied a malformed fixed-shape input.
    MalformedInput,
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EngineError::MalformedInput => write!(f, "malformed engine input"),
        }
    }
}

/// Fixed engine configuration: step count only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QclinkEngine {
    steps: u32,
}

/// Observation-only execution receipt: measurements, never conclusions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QclinkReceipt {
    /// Steps executed.
    pub steps: u32,
    /// Arrangement column from the shape register.
    pub arrangement: u16,
    /// Spread column from the shape register.
    pub spread: u16,
    /// Evidence absorbed.
    pub evidence: u32,
    /// Base norm invariant probe, scaled by 1e9 and rounded.
    pub norm_probe: u64,
}

impl QclinkEngine {
    /// Fixed configuration: how many intrinsic steps to execute.
    pub fn new(steps: u32) -> Self {
        QclinkEngine { steps }
    }

    /// Execute base-then-shape steps over fixed seeds and return measurements.
    /// Rejects oversized input rather than correcting it.
    pub fn execute(&self, seeds: &[[f64; DIM]]) -> Result<QclinkReceipt, EngineError> {
        if seeds.len() > 64 {
            return Err(EngineError::MalformedInput);
        }
        let mut arrangement = 0u16;
        let mut spread = 0u16;
        let mut evidence = 0u32;
        let mut norm_probe = 0u64;
        let mut ran = false;
        for seed in seeds {
            for value in *seed {
                if !value.is_finite() {
                    return Err(EngineError::MalformedInput);
                }
            }
            let mut state = LinkedState::seed(*seed);
            for _ in 0..self.steps.min(64) {
                state.step();
            }
            let (a, s, e) = state.read();
            arrangement = arrangement.max(a);
            spread = spread.max(s);
            evidence = evidence.saturating_add(e);
            norm_probe = (state.base_norm_sq() * 1e9).round() as u64;
            ran = true;
        }
        if !ran {
            return Ok(QclinkReceipt {
                steps: self.steps,
                arrangement: 0,
                spread: 0,
                evidence: 0,
                norm_probe: 0,
            });
        }
        Ok(QclinkReceipt {
            steps: self.steps,
            arrangement,
            spread,
            evidence,
            norm_probe,
        })
    }

    /// Decode a validated error from the function crate (kept for API parity).
    #[allow(dead_code)]
    fn _from_function(_error: FunctionError) -> EngineError {
        EngineError::MalformedInput
    }
}

/// Re-exported so tests name one EngineError only.
pub use qclink_function::FunctionError as _FunctionErrorAlias;

#[cfg(test)]
mod tests {
    use super::*;
    use qclink_function::EVIDENCE;

    #[test]
    fn executes_declared_steps_and_reports() {
        let engine = QclinkEngine::new(4);
        let receipt = engine.execute(&[[1.0, 2.0, 3.0, 4.0]]).expect("valid seed");
        assert_eq!(receipt.steps, 4);
        assert_eq!(receipt.evidence, 4 * EVIDENCE as u32);
        // Norm invariant: scaled 1.0 by 1e9.
        assert!((receipt.norm_probe as i64 - 1_000_000_000).abs() < 1000);
    }

    #[test]
    fn empty_input_reports_unsupported_without_verdict() {
        let engine = QclinkEngine::new(4);
        let receipt = engine.execute(&[]).expect("empty is valid");
        assert_eq!(
            (receipt.arrangement, receipt.spread, receipt.evidence),
            (0, 0, 0)
        );
    }

    #[test]
    fn malformed_inputs_are_rejected_not_corrected() {
        let engine = QclinkEngine::new(2);
        assert_eq!(
            engine.execute(&[[f64::NAN, 0.0, 0.0, 0.0]]),
            Err(EngineError::MalformedInput)
        );
        let many = vec![[1.0, 0.0, 0.0, 0.0]; 65];
        assert_eq!(engine.execute(&many), Err(EngineError::MalformedInput));
    }
}
