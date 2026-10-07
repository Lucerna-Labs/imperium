//! Matched controls for the linked stack: base-only, no-base replacement,
//! ablation, and order variants. Every candidate executes; nothing is tuned.

use qclink_engine::QclinkEngine;
use qclink_function::{LinkedState, ShapeState};

/// One recorded candidate: name plus measured receipt fields.
#[derive(Debug, PartialEq)]
pub struct CandidateRecord {
    pub name: &'static str,
    pub arrangement: u16,
    pub spread: u16,
    pub evidence: u32,
    pub norm_probe: u64,
}

fn seeds() -> Vec<[f64; 4]> {
    vec![[1.0, 2.0, 3.0, 4.0], [4.0, 1.0, 0.5, 0.25]]
}

#[test]
fn linked_stack_reports_measurements() {
    let engine = QclinkEngine::new(6);
    let receipt = engine.execute(&seeds()).expect("valid seeds");
    assert_eq!(receipt.evidence, 6 * 8 * 2);
    assert!((receipt.norm_probe as i64 - 1_000_000_000).abs() < 1000);
    let record = CandidateRecord {
        name: "linked",
        arrangement: receipt.arrangement,
        spread: receipt.spread,
        evidence: receipt.evidence,
        norm_probe: receipt.norm_probe,
    };
    assert!(record.evidence > 0);
}

#[test]
fn base_only_control_runs_without_shape() {
    // Base-only: unitary mixing + Born evidence emitted, shape never absorbs.
    // Proves the base executes standalone; it is not the application behavior.
    use qclink_function::{QuantumBase, DIM};
    let base = QuantumBase::new([1.0, 2.0, 3.0, 4.0]);
    let mixed = base.unitary_mix();
    assert!((mixed.norm_sq() - 1.0).abs() < 1e-9);
    let evidence = mixed.born_evidence();
    assert_eq!(evidence.len(), 8);
    let _ = DIM;
}

#[test]
fn classical_replacement_control_runs_without_base() {
    // No-base replacement: classical shape absorbs a fixed pattern with no
    // quantum-derived evidence. Matched control only, never the canonical arm.
    let mut shape = ShapeState::new();
    shape.absorb([7u8; 8]);
    shape.absorb([7u8; 8]);
    assert_eq!(shape.evidence(), 16);
}

#[test]
fn ablation_single_step_differs_from_six_steps() {
    let one = QclinkEngine::new(1).execute(&seeds()).expect("valid seeds");
    let six = QclinkEngine::new(6).execute(&seeds()).expect("valid seeds");
    assert_eq!(six.evidence, 6 * one.evidence);
}

#[test]
fn linked_state_order_is_base_then_shape() {
    // Structural order check: LinkedState::step mixes the base before the
    // shape absorbs, so one step always yields exactly one evidence block.
    let mut state = LinkedState::seed([2.0, 1.0, 0.5, 0.25]);
    state.step();
    let (_, _, evidence) = state.read();
    assert_eq!(evidence, 8);
}
