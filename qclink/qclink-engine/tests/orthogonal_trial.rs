//! Orthogonal-primitive trial: catalytic barrier plus conserved ledger.
//!
//! The frozen benefit is HELD-OUT SEED DISCRIMINATION: arrangement/spread
//! measured on two seeds never used to build or tune anything. A primitive
//! earns its place only by moving that metric beyond every control that lacks
//! it. Invariants: malformed rejected, empty unsupported, bases invertible,
//! outputs bounded, norm preserved. Falsifier: candidate metric <= best
//! no-primitive control, or any invariant violation.

use qclink_engine::QclinkEngine;
use qclink_function::{LinkedState, QuantumBase, ShapeState, DIM, EVIDENCE};

/// Held-out seeds. Never used for construction or tuning — evaluation only.
const HELD_A: [f64; DIM] = [0.3, 1.7, 2.9, 0.6];
const HELD_B: [f64; DIM] = [3.1, 0.4, 1.2, 2.2];

/// Catalytic barrier: bounded threshold state with its own history.
/// Orthogonal by construction: the base has no thresholds, the shape has no
/// gating memory. The barrier neither labels nor judges — it emits a residual.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalyticBarrier {
    threshold: u8,
    history: [u8; 16],
    len: usize,
}

impl CatalyticBarrier {
    pub fn new(threshold: u8) -> Self {
        CatalyticBarrier {
            threshold,
            history: [0; 16],
            len: 0,
        }
    }

    /// Absorb one evidence byte into barrier history. Mechanical only.
    pub fn absorb(&mut self, value: u8) {
        if self.len < self.history.len() {
            self.history[self.len] = value;
            self.len += 1;
        } else {
            self.history.copy_within(1.., 0);
            let last = self.history.len() - 1;
            self.history[last] = value;
        }
    }

    /// Residual: distance from saturation. Data for later mechanics, never a
    /// pass/fail label.
    #[must_use]
    pub fn residual(&self) -> u8 {
        let available = self.len.min(255) as u8;
        self.threshold.saturating_sub(available)
    }
}

/// Conserved ledger: integer-conserved quantity the shape must pay into.
/// The base conserves norm; this conserves COUNT. Neither implies the other,
/// so this is a new invariant, not a redescription.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConservedLedger {
    balance: i64,
    cap: i64,
}

impl ConservedLedger {
    pub fn new(cap: i64) -> Self {
        ConservedLedger { balance: 0, cap }
    }

    /// Deposit evidence count. Bounded, saturating, reversible by construction.
    pub fn deposit(&mut self, amount: u32) {
        self.balance = self
            .balance
            .saturating_add(amount as i64)
            .min(self.cap)
            .max(-self.cap);
    }

    /// Withdraw evidence count. Returns what was actually released.
    pub fn withdraw(&mut self, amount: u32) -> u32 {
        let released = (amount as i64).min(self.balance).max(0) as u32;
        self.balance -= released as i64;
        released
    }

    /// Current balance probe.
    #[must_use]
    pub fn balance(&self) -> i64 {
        self.balance
    }
}

fn discrimination(arrange_a: u16, spread_a: u16, arrange_b: u16, spread_b: u16) -> u64 {
    u64::from(arrange_a.abs_diff(arrange_b)) * 1000 + u64::from(spread_a.abs_diff(spread_b))
}

fn run_linked(seed: [f64; DIM], steps: u32) -> (u16, u16, u32, u64) {
    let receipt = QclinkEngine::new(steps)
        .execute(&[seed])
        .expect("valid seed");
    (
        receipt.arrangement,
        receipt.spread,
        receipt.evidence,
        receipt.norm_probe,
    )
}

fn run_with_barrier(seed: [f64; DIM], steps: u32, threshold: u8) -> (u16, u16, u32, u64, u8) {
    // Same linked mechanics, plus a barrier that absorbs the SAME evidence the
    // shape absorbs. The barrier emits only a residual; it never routes,
    // gates, labels, or judges. Question: does its presence change the
    // reachable measurement set?
    let mut state = LinkedState::seed(seed);
    let mut barrier = CatalyticBarrier::new(threshold);
    for _ in 0..steps.min(64) {
        state.step();
        // Feed the barrier the latest shape evidence indirectly: re-derive one
        // byte from the current arrangement (public measurement, not state).
        let (a, s, _) = state.read();
        barrier.absorb((a ^ s) as u8);
    }
    let (a, s, e) = state.read();
    (
        a,
        s,
        e,
        state.base_norm_sq().round() as u64,
        barrier.residual(),
    )
}

fn run_with_ledger(seed: [f64; DIM], steps: u32, cap: i64) -> (u16, u16, u32, i64) {
    // Same linked mechanics, plus a conserved ledger the shape pays into per
    // absorbed evidence block. New invariant (integer conservation), new
    // coupling topology (shape<->ledger), no new labels.
    let mut state = LinkedState::seed(seed);
    let mut ledger = ConservedLedger::new(cap);
    for _ in 0..steps.min(64) {
        state.step();
        ledger.deposit(EVIDENCE as u32);
    }
    let (a, s, e) = state.read();
    (a, s, e, ledger.balance())
}

fn run_base_only(seed: [f64; DIM], steps: u32) -> (u64, u64) {
    // Base-only control: unitary mixing + Born evidence, shape never absorbs.
    let mut base = QuantumBase::new(seed);
    let mut evidence_total = 0u64;
    for _ in 0..steps.min(64) {
        base = base.unitary_mix();
        evidence_total += base.born_evidence().len() as u64;
    }
    (evidence_total, (base.norm_sq() * 1e9).round() as u64)
}

fn run_no_base_classical(steps: u32) -> (u16, u16, u32) {
    // No-base replacement: classical shape absorbs a fixed pattern.
    let mut shape = ShapeState::new();
    for _ in 0..steps.min(64) {
        shape.absorb([7u8; EVIDENCE]);
    }
    (shape.arrangement(), shape.spread(), shape.evidence())
}

#[test]
fn orthogonal_trial_reports_all_arms() {
    let steps = 6u32;

    // Canonical linked arm.
    let (aa, sa, _ea, _) = run_linked(HELD_A, steps);
    let (ab, sb, _eb, _) = run_linked(HELD_B, steps);
    let linked_gap = discrimination(aa, sa, ab, sb);

    // Barrier arm.
    let (ba, bsa, _, _, ra) = run_with_barrier(HELD_A, steps, 8);
    let (bb, bsb, _, _, rb) = run_with_barrier(HELD_B, steps, 8);
    let barrier_gap = discrimination(ba, bsa, bb, bsb);

    // Ledger arm.
    let (la, lsa, _, bal_a) = run_with_ledger(HELD_A, steps, 10_000);
    let (lb, lsb, _, bal_b) = run_with_ledger(HELD_B, steps, 10_000);
    let ledger_gap = discrimination(la, lsa, lb, lsb);

    // Controls.
    let (base_ev, base_norm) = run_base_only(HELD_A, steps);
    let (ca, cs, ce) = run_no_base_classical(steps);
    assert!(base_ev > 0);
    assert!((base_norm as i64 - 1_000_000_000).abs() < 1000);
    assert_eq!(ce, steps * EVIDENCE as u32);

    // Invariants: norm preserved in every arm that has a base.
    for seed in [HELD_A, HELD_B] {
        let mut state = LinkedState::seed(seed);
        for _ in 0..steps {
            state.step();
        }
        assert!((state.base_norm_sq() - 1.0).abs() < 1e-9);
    }
    // Ledger conservation: deposits bounded by cap on both seeds.
    assert!(bal_a >= 0 && bal_a <= 10_000);
    assert!(bal_b >= 0 && bal_b <= 10_000);
    // Barrier residuals are data, never verdicts.
    assert!(ra <= 8 && rb <= 8);

    // The verdict this trial can return: which arm moved held-out
    // discrimination beyond the canonical linked arm, if any.
    println!("linked_gap={linked_gap} barrier_gap={barrier_gap} ledger_gap={ledger_gap}");
    println!("classical_only=({ca},{cs}) barrier_residuals=({ra},{rb}) ledger_balances=({bal_a},{bal_b})");

    // Structural assertions only — no benefit claim without a frozen gate:
    // every arm must run and report; gaps are numbers, not winners.
    assert!(linked_gap + barrier_gap + ledger_gap > 0);
}
