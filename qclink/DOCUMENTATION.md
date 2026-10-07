# qclink: quantum amplification base, temperature knob, classical consumers

Side experiment proving that a quantum-derived amplification base and its
temperature schedule each earn their place independently, measured on held-out
seeds against matched controls. Classical physics on a classical CPU throughout:
no qubits, superposition, entanglement, collapse, no-cloning, quantum
randomness, advantage, QPU execution, or quantum security is claimed anywhere.

## Layout

```
qclink/
  Cargo.toml                    workspace (qclink-function, qclink-engine)
  qclink-function/src/lib.rs    first principles: base + shape + linkage
  qclink-engine/src/lib.rs      fixed execution, observation, return
  qclink-engine/tests/
    linked_controls.rs          base-only / no-base / ablation / order
    orthogonal_trial.rs         barrier + ledger negative result
    amplification_trial.rs      amplification vs old base + consumers
    temperature_trial.rs        isothermal / anneal / quench sweep
```

Two crates, one-way dependency `function <- engine`. Zero external
dependencies. `cargo test --workspace`: **18 passed, 0 failed**.

## The theory correction this build tests

First theory: classical functions work because of quantum, so a quantum
variant of the same classical function behaves almost identically — the
quantum layer is redundant, a redescription of the same fixed point.

Corrected theory: the redundancy claim holds only when the new primitive
brings nothing the function lacks. A primitive earns its place by bringing at
least one of: a new invariant, a new timescale or memory, a broken symmetry,
or a new coupling topology. Otherwise it is decoration under any name.

## The base: amplification, not mixing

`QuantumBase` (`qclink-function/src/lib.rs:43`): normalized real amplitudes
(`new`, `norm_sq`), a marked slot, and a fixed gain.

- `amplify()` (`:157`): fixed nonlinear gain on the marked amplitude
  (magnitude to a fixed power, sign preserved, bounded), then a fixed
  rotation moving one eighth of each unmarked amplitude inward, then
  renormalize. Concentration, not creation; total probability conserved.
- `amplify_at(gain)` (`:165`): identical mechanics with the gain supplied by
  a fixed open-loop schedule. Never adapted to state or results.
- `unitary_mix()` (`:202`): the old Walsh-style base, kept for the base-only
  control and for ablation against amplification.
- `born_evidence()` (`:228`): squared amplitudes scaled to 8 bytes. The only
  channel the classical layer may read.
- `marked_probability()` (`:240`): the quantity amplification concentrates.

Measured trajectory on `[1.0, 2.0, 3.0, 4.0]`, pinned by
`amplification_concentrates_marked_probability`:

```
seed 0.033 → 0.112 → 0.210 → 0.321 → 0.438 → 0.553
```

Monotone concentration, norm 1.0 throughout. The test also records the design
error it caught: rotate-then-gain stalled at 0.657 because rotation dilutes
the marked slot before gain sharpens it; gain-first climbs steadily.

Honest comparison note, also pinned in the test: a one-shot Walsh mix dumps
83% into slot 0 on this seed by construction, then oscillates back
(0.033 → 0.833 → 0.033). The claim is steady monotone concentration from the
seed baseline, not beating a cherry-picked single mix.

## Temperature: gain-per-step as a dial

`TemperatureSchedule` (`qclink-function/src/lib.rs:60`): `isothermal(gain)`,
`anneal(hot, cold)`, `quench(cold, hot)`, `gain_at(step)`. Temperature means
exactly one thing: the per-step nonlinear gain. Fixed before execution, never
read from state, never adapted. The analogy to classical chaos knobs is
structural — both vary how hard dynamics push per step — and it is tested as
such, not asserted.

Sweep on held-out seeds `[0.3, 1.7, 2.9, 0.6]` and `[3.1, 0.4, 1.2, 2.2]`
(`temperature_trial.rs`):

```
isothermal-1.10:  gap=5038
isothermal-1.35:  gap=4043
isothermal-1.70:  gap=3024
anneal-1.70-1.10: gap=3034
quench-1.10-1.70: gap=5047
control (fixed gain): gap=4043
```

Lower gain → larger gap, monotonically across isothermals. Anneal matches its
cold end (3034 ≈ 3024); quench matches its cold start (5047 ≈ 5038). Time
spent cold predicts the outcome. Quench and the cold isothermal both beat the
fixed-gain default — which explains why the amplification trial's number was
what it was: one point on this dial.

## Classical consumers that benefit from amplification

`PeakCounter` and `ThresholdSwitch` (`amplification_trial.rs`): read ONLY
emitted Born evidence, never base state; no routing, gating, labeling, or
judgment. Held-out result:

```
linked_gap=500105  old_gap=31
counts=(0,6)
```

Four orders of magnitude better discrimination than the old base, and a 0-vs-6
peak-count separation the old base never produced. Latches did not trip at the
tested budget (accumulated 816 vs 1428) — the threshold needs the old base's
scale recalibrated, recorded as an open item rather than a failure.

## The negative result that scopes everything

`orthogonal_trial.rs`: a catalytic barrier (threshold state, own history) and
a conserved ledger (integer conservation, shape pays in) — both genuinely new
machinery. Result: `linked_gap=31 barrier_gap=31 ledger_gap=31`, with
identical residuals and balances across seeds. New invariants, new memory, new
coupling — and the measurements didn't move.

Conclusion, stated as the rule it implies: **orthogonality on paper is not
orthogonality in the dynamics.** A primitive earns its place only by moving a
frozen metric beyond every control that lacks it. Redundant here means
redundant *on this discrimination task at this scale* (two seeds, six steps),
not universally inert.

## Controls and invariants

- Base-only: unitary mixing + Born evidence, shape never absorbs.
- Classical-replacement: fixed pattern, no base.
- Single-step vs six-step ablation; base-then-shape structural order check.
- Malformed inputs rejected (NaN, oversize); empty input reports unsupported
  without a verdict.
- Norm preserved at 1.0 through every amplify step on every seed.
- No labels, policies, tuning, verdicts, RNG, clocks, or adaptive branches
  anywhere in either crate.

## Open items

- Threshold-switch budget recalibration against the amplified scale.
- Wider sweep: more seeds, more steps, finer temperature grid — monotonicity
  could break outside the tested range, and that would be a finding, not a
  failure.
- The fixed Walsh base remains a valid matched control; do not delete it.
