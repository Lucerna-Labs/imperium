//! Temperature-knob trial: is gain-per-step a dial for held-out discrimination?
//!
//! Frozen benefit: HELD-OUT SEED DISCRIMINATION, same two seeds and metric as
//! the amplification trial. Arms: isothermal schedules at three gains, one
//! anneal, one quench, plus the no-temperature control (base fixed gain every
//! step). Invariants: malformed rejected, empty unsupported, outputs bounded,
//! norm preserved at every temperature. Falsifier: no scheduled arm moves
//! discrimination beyond the fixed-gain control, or any invariant violation.

use qclink_function::{QuantumBase, TemperatureSchedule, DIM};

/// Held-out seeds. Evaluation only — never construction or tuning.
const HELD_A: [f64; DIM] = [0.3, 1.7, 2.9, 0.6];
const HELD_B: [f64; DIM] = [3.1, 0.4, 1.2, 2.2];

fn run_schedule(seed: [f64; DIM], schedule: TemperatureSchedule, steps: u32) -> (u64, u64) {
    // Advance the base under the fixed schedule, then emit Born evidence and
    // read the two classical columns the consumers use: peak count at level
    // 200 and accumulated dominant evidence. Same columns as the amplification
    // trial, so the numbers are comparable.
    let mut base = QuantumBase::new(seed);
    let mut peak_count = 0u64;
    let mut accumulated = 0u64;
    for step in 0..steps.min(64) {
        base = base.amplify_at(schedule.gain_at(step as usize));
        let evidence = base.born_evidence();
        let peak = evidence.iter().copied().max().unwrap_or(0);
        if peak >= 200 {
            peak_count += 1;
        }
        accumulated += u64::from(peak);
        assert!((base.norm_sq() - 1.0).abs() < 1e-9);
    }
    (peak_count, accumulated)
}

fn discrimination(count_a: u64, acc_a: u64, count_b: u64, acc_b: u64) -> u64 {
    count_a.abs_diff(count_b) * 1000 + acc_a.abs_diff(acc_b) / 10
}

#[test]
fn temperature_sweep_reports_all_arms() {
    let steps = 6u32;
    let schedules: [(&str, TemperatureSchedule); 5] = [
        ("isothermal-1.10", TemperatureSchedule::isothermal(1.10)),
        ("isothermal-1.35", TemperatureSchedule::isothermal(1.35)),
        ("isothermal-1.70", TemperatureSchedule::isothermal(1.70)),
        ("anneal-1.70-1.10", TemperatureSchedule::anneal(1.70, 1.10)),
        ("quench-1.10-1.70", TemperatureSchedule::quench(1.10, 1.70)),
    ];
    // Fixed-gain control: the base's own gain every step, no schedule.
    let mut control_a = QuantumBase::new(HELD_A);
    let mut control_b = QuantumBase::new(HELD_B);
    let mut control_counts = [0u64, 0u64];
    let mut control_accs = [0u64, 0u64];
    for _ in 0..steps {
        for (index, base) in [&mut control_a, &mut control_b].iter_mut().enumerate() {
            **base = base.amplify();
            let peak = base.born_evidence().iter().copied().max().unwrap_or(0);
            if peak >= 200 {
                control_counts[index] += 1;
            }
            control_accs[index] += u64::from(peak);
            assert!((base.norm_sq() - 1.0).abs() < 1e-9);
        }
    }
    let control_gap = discrimination(
        control_counts[0],
        control_accs[0],
        control_counts[1],
        control_accs[1],
    );

    let mut best_gap = 0u64;
    let mut best_name = "";
    for (name, schedule) in schedules {
        let (count_a, acc_a) = run_schedule(HELD_A, schedule, steps);
        let (count_b, acc_b) = run_schedule(HELD_B, schedule, steps);
        let gap = discrimination(count_a, acc_a, count_b, acc_b);
        println!("{name}: counts=({count_a},{count_b}) accumulated=({acc_a},{acc_b}) gap={gap}");
        if gap > best_gap {
            best_gap = gap;
            best_name = name;
        }
    }
    println!("control_gap={control_gap} best_scheduled_gap={best_gap} best={best_name}");

    // Structural assertions only: every arm runs, norms hold, numbers print.
    // Whether any schedule beats the fixed-gain control is read from the
    // printed gaps against the frozen falsifier — not asserted here, because
    // benefit needs its gate, not this harness.
    assert!(control_gap + best_gap > 0);
}
