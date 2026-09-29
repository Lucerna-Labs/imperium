//! Adversarial ledger tests for the lightcone (`src/lightcone.rs`).
//!
//! Framing: the LEDGER. `unconstructible_claims` only evaluates observations
//! that DECLARE a cause, and every coordinate it checks is caller-supplied.
//! Each test asserts CURRENT observed behavior (green either way) and carries
//! a classification comment: DEFENDED / HOLE / BOUNDARY.

use std::panic::{catch_unwind, AssertUnwindSafe};

use imperium_net_mesh::{fit_law, ring_distance, CausalObservation, Lightcone, PropagationLaw};

fn law() -> PropagationLaw {
    PropagationLaw {
        v_max: 2,
        ring_size: 64,
    }
}

fn obs(tick: u64, position: u64, cause: Option<(u64, u64)>) -> CausalObservation {
    CausalObservation {
        tick,
        position,
        claims_cause: cause,
    }
}

// ---------------------------------------------------------------------------
// 1. Undeclared ancestry
// ---------------------------------------------------------------------------

/// BOUNDARY: forgeries that declare no cause are invisible to the geometry.
/// `unconstructible_claims` (lightcone.rs:226-253) `continue`s past every
/// observation with `claims_cause == None`. 99 silent forgeries + 1 declared
/// impossibility -> exactly 1 fact: 99% of the hostile ledger sails through
/// by simply not declaring. This is inherent to passive geometry (there is no
/// assertion to check when nothing is asserted; cf. the `CausalObservation`
/// docs, lightcone.rs:173-176), so it is a trust/coverage boundary, not a bug.
#[test]
fn undeclared_ancestry_is_invisible_to_the_geometry() {
    let mut cone = Lightcone::new(law());
    for i in 0..99u64 {
        // 99 forged messages that assert nothing.
        cone.record(obs(500 + i, 12, None));
    }
    // One forgery that DOES declare an impossible cause: 20 hops in 2 ticks.
    cone.record(obs(900, 12, Some((898, 32))));

    let facts = cone.unconstructible_claims();
    assert_eq!(facts.len(), 1, "only the declaring forgery is visible");
    assert_eq!(facts[0].distance, 20);

    // The all-silent ledger is completely quiet.
    let mut silent = Lightcone::new(law());
    for i in 0..100u64 {
        silent.record(obs(i, 40, None));
    }
    assert!(silent.unconstructible_claims().is_empty());
}

// ---------------------------------------------------------------------------
// 2. Coordinate authority: the attacker picks cozy coordinates
// ---------------------------------------------------------------------------

/// BOUNDARY: callers supply tick and position freely (`record` does pure
/// bookkeeping, lightcone.rs:206-211; nothing assigns or authenticates a
/// sender's ring position). An attacker citing the victim's event at (90, 50)
/// self-assigns (91, 51): distance 1 <= 2*1, so the forgery tests as
/// constructible. Worse, the universal forge — claim position == cause
/// position one tick later — is constructible under EVERY law (distance 0).
/// The geometry is correct given its inputs; the unstated trust assumption is
/// that inputs are bound to real senders by something else (nothing in this
/// module does it — by design it "depends on nothing but its trained world").
#[test]
fn attacker_chosen_coordinates_make_any_cause_constructible() {
    let mut cone = Lightcone::new(law());
    // Victim event allegedly at tick 90, ring 50. Attacker sits "next door".
    cone.record(obs(91, 51, Some((90, 50))));
    assert!(
        cone.unconstructible_claims().is_empty(),
        "cozy-coordinate forgery passed as constructible"
    );

    // Universal forge: same ring slot, one tick later — distance 0.
    let mut cone2 = Lightcone::new(law());
    cone2.record(obs(10_001, 7, Some((10_000, 7))));
    assert!(
        cone2.unconstructible_claims().is_empty(),
        "zero-distance forge is constructible under any law"
    );
    // Direct query agrees: distance-0 past causes always fit.
    assert!(law().cone_contains(10_001, 7, 10_000, 7));
}

/// BOUNDARY: positions are never range-checked against the ring, so an
/// off-ring position silently aliases. On ring 64, position 64 == position 0
/// (`ring_distance(64, 0, 64) == min(64, 0) == 0`). A claim filed from
/// out-of-range coordinate 64 citing a cause at 0 is distance-0
/// "constructible". Same trust assumption as above: no input validation.
#[test]
fn off_ring_position_silently_aliases_to_zero() {
    assert_eq!(ring_distance(64, 0, 64), 0);
    let mut cone = Lightcone::new(law());
    cone.record(obs(100, 64, Some((99, 0))));
    assert!(
        cone.unconstructible_claims().is_empty(),
        "off-ring position 64 aliased to 0 and passed"
    );
}

// ---------------------------------------------------------------------------
// 3. The cause is never required to exist in the ledger
// ---------------------------------------------------------------------------

/// BOUNDARY: `unconstructible_claims` checks reachability, never membership.
/// A claim citing a cause that was never observed — ledger otherwise empty —
/// passes whenever the cone fits. Quote a ghost at (499, 11), one hop away:
/// no fact. Geometry answers "could a path exist", not "did it happen".
#[test]
fn cited_cause_need_never_have_been_observed() {
    let mut cone = Lightcone::new(law());
    cone.record(obs(500, 12, Some((499, 11)))); // ghost cause, 1 hop, 1 tick
    assert!(
        cone.unconstructible_claims().is_empty(),
        "unobserved cause within the cone passes silently"
    );
}

// ---------------------------------------------------------------------------
// 4. Future / same-tick causes ARE rejected (control)
// ---------------------------------------------------------------------------

/// DEFENDED: `cone_contains` (lightcone.rs:89-92) rejects any ancestor that
/// is not strictly in the past, and the ledger surfaces both as facts. A
/// claim citing next tick's event, or its own tick, is unconstructible.
#[test]
fn future_and_same_tick_causes_are_flagged() {
    let mut cone = Lightcone::new(law());
    cone.record(obs(500, 12, Some((600, 0)))); // cause from the future
    cone.record(obs(500, 12, Some((500, 12)))); // same-tick self-cause
    let facts = cone.unconstructible_claims();
    assert_eq!(facts.len(), 2, "future and same-tick causes must be facts");
}

// ---------------------------------------------------------------------------
// 5. Replay, contradiction, and eviction: the ledger links nothing
// ---------------------------------------------------------------------------

/// BOUNDARY: the ledger is append-only bookkeeping with no dedup, nonce, or
/// site identity. Re-recording the same impossible claim 3x yields 3
/// identical facts — any consumer counting facts over-counts replays 3:1.
#[test]
fn replayed_claim_multiplies_facts() {
    let mut cone = Lightcone::new(law());
    for _ in 0..3 {
        cone.record(obs(500, 12, Some((498, 32))));
    }
    let facts = cone.unconstructible_claims();
    assert_eq!(facts.len(), 3, "one claim replayed 3x reads as 3 facts");
}

/// BOUNDARY: two observations from the SAME (tick, position) making
/// incompatible causal claims coexist unlinked — the ledger has no notion of
/// "site 5 at tick 100 can only say one thing". One cites (99, 5) (legal),
/// the other cites (99, 40) (29 hops away, needs 15 ticks, has 1). Exactly
/// one fact; the contradiction itself is never reported as such.
#[test]
fn same_spacetime_contradictory_claims_coexist_unlinked() {
    let mut cone = Lightcone::new(law());
    cone.record(obs(100, 5, Some((99, 5))));
    cone.record(obs(100, 5, Some((99, 40))));
    let facts = cone.unconstructible_claims();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].cause_position, 40);
}

/// BOUNDARY: the ledger is a bounded FIFO (`LEDGER_CAPACITY = 4096`,
/// lightcone.rs:184; `record` evicts the front, lightcone.rs:206-211). After
/// the forgery is recorded, 4096 filler observations push it out and the fact
/// disappears from `unconstructible_claims`. The cap is explicit design, but
/// anyone who can record can erase anyone's impossibility evidence by flood.
/// No retention, no auth, no tombstone.
#[test]
fn flood_eviction_erases_impossibility_evidence() {
    let mut cone = Lightcone::new(law());
    // Impossible claim: 20 hops in 2 ticks.
    cone.record(obs(500, 12, Some((498, 32))));
    assert_eq!(cone.unconstructible_claims().len(), 1);
    // Flood with 4096 filler records; the forgery falls off the front.
    for i in 0..4096u64 {
        cone.record(obs(1000 + i, 1, None));
    }
    assert!(
        cone.unconstructible_claims().is_empty(),
        "flood evicted the impossibility fact"
    );
}

// ---------------------------------------------------------------------------
// 6. Geometry math: panics (denial of the fact service)
// ---------------------------------------------------------------------------

/// HOLE: `PropagationLaw`'s fields are `pub` with no validated constructor —
/// only `from_bytes` rejects `ring_size == 0` (lightcone.rs:126-128). A
/// directly constructed zero-ring law breaks every fact query: `ring_distance`
/// opens with `debug_assert!(ring_size > 0)` (lightcone.rs:60), so in debug
/// builds ANY `cone_contains`/`unconstructible_claims` call panics — even the
/// vacuous same-slot case. The type's core invariant ("ring size must be
/// positive") is asserted but never enforced at construction.
#[test]
fn zero_ring_law_is_constructible_and_panics() {
    let degenerate = PropagationLaw {
        v_max: 2,
        ring_size: 0,
    };
    // Constructing the degenerate law itself succeeds — no validation.
    // In debug builds, every cone query through it panics at lightcone.rs:60.
    assert!(catch_unwind(|| degenerate.cone_contains(100, 10, 99, 10)).is_err());
    assert!(catch_unwind(|| degenerate.cone_contains(100, 10, 99, 11)).is_err());
    let mut cone = Lightcone::new(degenerate);
    cone.record(obs(100, 10, Some((99, 10))));
    let r = catch_unwind(AssertUnwindSafe(|| cone.unconstructible_claims()));
    assert!(r.is_err(), "zero-ring law DoSes ledger fact queries");
    // (Release builds compile the debug_assert out; behavior there was not
    // probed by this test.)
}

/// HOLE: positions are never validated against `ring_size`, and
/// `ring_distance` computes `ring_size - |a-b|` in plain u64 arithmetic
/// (lightcone.rs:61-62). Any observation with |a-b| > ring_size underflows
/// and panics in debug builds. `record` itself never evaluates, so ONE
/// poisoned entry permanently DoSes every later `unconstructible_claims`
/// query over the whole ledger — a single-entry denial of the fact service.
#[test]
fn out_of_range_position_panics_and_doses_fact_queries() {
    // Direct: |1000 - 16| = 984 > ring 64 -> `64 - 984` underflows.
    assert!(catch_unwind(|| ring_distance(1000, 16, 64)).is_err());
    assert!(catch_unwind(|| law().cone_contains(500, 1000, 499, 16)).is_err());

    // Via the ledger: recording succeeds (no evaluation at record time)...
    let mut cone = Lightcone::new(law());
    cone.record(obs(500, 1000, Some((499, 16))));
    cone.record(obs(501, 12, Some((500, 12)))); // innocent bystander claim
                                                // ...but every fact query over the ledger now panics.
    let r = catch_unwind(AssertUnwindSafe(|| cone.unconstructible_claims()));
    assert!(r.is_err(), "one poisoned entry DoSes all fact queries");
}

/// HOLE: `min_ticks_for` computes `(distance + v_max - 1) / v_max`
/// (lightcone.rs:109) in wrapping-unchecked u64 arithmetic. Adversarial-scale
/// inputs overflow and panic in debug builds: `u64::MAX` distance, or even
/// distance 1 under a `v_max = u64::MAX` law (`1 + MAX` overflows).
#[test]
fn min_ticks_for_overflows_on_adversarial_inputs() {
    assert!(catch_unwind(|| law().min_ticks_for(u64::MAX)).is_err());
    let huge_v = PropagationLaw {
        v_max: u64::MAX,
        ring_size: 64,
    };
    assert!(catch_unwind(|| huge_v.min_ticks_for(1)).is_err());
}

// ---------------------------------------------------------------------------
// 7. Geometry math that holds (controls)
// ---------------------------------------------------------------------------

/// DEFENDED: the propagation budget uses `saturating_mul` (lightcone.rs:95,
/// 101), so extreme ticks/velocities degrade to "everything fits" instead of
/// overflowing. `cone_radius` still caps at half the ring.
#[test]
fn saturating_budget_never_overflows() {
    let huge_v = PropagationLaw {
        v_max: u64::MAX,
        ring_size: 64,
    };
    assert!(huge_v.cone_contains(u64::MAX, 7, 0, 7)); // dt=MAX, saturates
    assert_eq!(huge_v.cone_radius(u64::MAX), 32); // capped at 64/2, no panic
    assert_eq!(law().cone_radius(u64::MAX), 32);
}

/// DEFENDED: `fit_law` rejects out-of-range samples (lightcone.rs:272-277),
/// so its output is bounded by the input gate: worst-case legal samples
/// (32 hops in 1 tick on ring 64) yield exactly v_max = ceil(32 * 1.5) = 48.
/// Calibration cannot emit an arbitrarily huge law from valid inputs.
#[test]
fn fit_law_output_is_bounded_by_input_validation() {
    let worst: Vec<(u64, u64)> = vec![(32, 1); 32];
    let fitted = fit_law(&worst, 64).expect("worst-case valid samples fit");
    assert_eq!(fitted.v_max, 48);
}

// ---------------------------------------------------------------------------
// 8. Calibration warping with a MINORITY of poison (near-cut attack)
// ---------------------------------------------------------------------------

/// HOLE: the MAD trim cut (`median + 8*MAD`, lightcone.rs:286) is generous
/// when the honest corpus has natural spread, and `v_max` is set by the
/// MAXIMUM kept velocity (lightcone.rs:296-297). Poison samples parked just
/// under the cut are kept yet redefine the maximum. Here 64 honest samples
/// (velocities 0.25..2.0) give v_max = 3; adding just 12 poison samples
/// (16% of the corpus) at velocity 5.0 keeps them under the cut and nearly
/// triples the law to v_max = 8 — and a hostile 14-hops-in-2-ticks claim,
/// unconstructible under the honest law, tests as constructible under the
/// warped one. No majority needed; the "majority-hostile is a curation bug"
/// fallback (lightcone.rs:289) never fires.
#[test]
fn near_cut_minority_poison_warps_the_law() {
    // Honest corpus: natural spread, velocities 0.25..=2.0 hops/tick.
    let mut honest: Vec<(u64, u64)> = Vec::new();
    for i in 0..64u64 {
        honest.push((1 + (i % 8), 4)); // hops 1..8 over 4 ticks
    }
    let honest_law = fit_law(&honest, 64).expect("honest samples fit");
    assert_eq!(honest_law.v_max, 3, "honest v_max = {}", honest_law.v_max);

    // Poison: 12/76 samples (15.8%) at velocity 5.0, under the MAD cut.
    let mut poisoned = honest.clone();
    for _ in 0..12 {
        poisoned.push((5, 1)); // 5 hops in 1 tick
    }
    let warped = fit_law(&poisoned, 64).expect("poisoned samples fit");
    assert!(
        warped.v_max > honest_law.v_max,
        "minority poison moved v_max {} -> {}",
        honest_law.v_max,
        warped.v_max
    );
    assert_eq!(warped.v_max, 8, "warped v_max = {}", warped.v_max);

    // End-to-end impact: hostile claim, 14 hops in 2 ticks (velocity 7).
    let claim = obs(100, 0, Some((98, 14)));
    let mut cone_honest = Lightcone::new(honest_law);
    cone_honest.record(claim.clone());
    assert_eq!(
        cone_honest.unconstructible_claims().len(),
        1,
        "honest law flags the hostile claim"
    );
    let mut cone_warped = Lightcone::new(warped);
    cone_warped.record(claim);
    assert!(
        cone_warped.unconstructible_claims().is_empty(),
        "warped law admits the hostile claim as constructible"
    );
}
