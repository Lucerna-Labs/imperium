//! Adversarial calibration tests for the lightcone's trained law (`fit_law`).
//!
//! Target: `crates/imperium-net-mesh/src/lightcone.rs` (`fit_law`, lines 265-300,
//! trim at lines 286-293, `cone_contains` at lines 82-96).
//!
//! Doctrine respected: the lightcone is passive causal geometry; there is no
//! scoring/judgment/policy surface here, and none of these tests asks for one.
//! Every attack below poisons the *training corpus* handed to `fit_law` and then
//! shows the payoff through the geometric check `cone_contains` — i.e. the
//! trained law itself is warped, which is attack class 2 in the brief.

use imperium_net_mesh::{fit_law, Lightcone, PropagationLaw};

const RING: u64 = 64;

/// Helper: honest-physics verdict for a (distance, dt) pair under v=1.
/// Honest traffic here moves at 1.0 hops/tick, so any law with v_max >= 2
/// (after the 1.5x tail tolerance) keeps it constructible; a forged claim
/// needing velocity > 2 is unconstructible under honest physics.
fn honest_vmax_floor() -> u64 {
    2 // ceil(1.0 * 1.5)
}

// Attack 1 — HOLE: MAD-widening. A spread honest corpus (velocities 1.0 and
// 2.0, MAD = 0.5, cut = 5.5) gives the attacker nonzero MAD headroom; 16
// colluding samples at exactly v = 5.0 sit just under the widened cut
// (median 2.0 + 8*MAD 8.0 = 10.0) and are KEPT, so the fitted v_max jumps
// 3 -> 8 and a forged (distance 15, dt 2) claim passes that honest physics
// (needs v = 7.5) calls unconstructible.
#[test]
fn boiling_frog_mad_widening_inflates_vmax() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..32 {
        corpus.push((2, 2)); // v = 1.0 honest slow wing
    }
    for _ in 0..32 {
        corpus.push((4, 2)); // v = 2.0 honest fast wing
    }
    let honest_law = fit_law(&corpus, RING).unwrap();
    assert_eq!(honest_law.v_max, 3); // ceil(2.0 * 1.5)

    for _ in 0..16 {
        corpus.push((10, 2)); // v = 5.0 colluding, under the widened cut 10.0
    }
    let poisoned = fit_law(&corpus, RING).unwrap();
    // Classification: HOLE — attacker samples survived the trim and redefined v_max.
    assert_eq!(poisoned.v_max, 8); // ceil(5.0 * 1.5)
                                   // Honest physics (v_max 3): distance 15 in dt 2 needs v = 7.5 — impossible.
    assert!(!honest_law.cone_contains(2, 15, 0, 0));
    // Poisoned law admits the same forged claim.
    assert!(poisoned.cone_contains(2, 15, 0, 0));
}

// Attack 2 — HOLE: majority takeover. 64 honest samples at v = 1.0 plus 64
// hostile samples at v = 3.0 flip the median to 2.0 and inflate MAD to 1.0,
// so the cut (10.0) keeps the entire hostile wing: the attacker-owned half of
// the corpus fully defines the physics (v_max 2 -> 5), and a forged
// (distance 9, dt 2) claim passes that honest physics rejects.
#[test]
fn majority_takeover_redefines_physics() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..64 {
        corpus.push((2, 2)); // v = 1.0 honest
    }
    let honest_law = fit_law(&corpus, RING).unwrap();
    assert_eq!(honest_law.v_max, honest_vmax_floor());

    for _ in 0..64 {
        corpus.push((6, 2)); // v = 3.0 hostile, 50% of the corpus
    }
    let taken = fit_law(&corpus, RING).unwrap();
    // Classification: HOLE — a 50%-hostile corpus sets v_max, not the honest half.
    assert_eq!(taken.v_max, 5); // ceil(3.0 * 1.5)
    assert!(!honest_law.cone_contains(2, 9, 0, 0)); // needs v = 4.5
    assert!(taken.cone_contains(2, 9, 0, 0));
}

// Attack 2b — DEFENDED: just below the majority cliff (33 honest vs 31
// hostile, 48.4% hostile), the median stays honest (1.0), MAD stays 0.0, and
// the cut (1.0) trims every hostile sample: v_max stays 2 and the forged
// (distance 9, dt 2) claim is still rejected.
#[test]
fn just_below_half_hostile_is_trimmed() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..33 {
        corpus.push((2, 2)); // v = 1.0 honest
    }
    for _ in 0..31 {
        corpus.push((30, 1)); // v = 30.0 hostile, 48.4% of the corpus
    }
    let law = fit_law(&corpus, RING).unwrap();
    // Classification: DEFENDED — minority-hostile outliers are trimmed.
    assert_eq!(law.v_max, 2);
    assert!(!law.cone_contains(2, 9, 0, 0));
}

// Attack 3 — HOLE: exactly-at-cut single sample. On the spread honest corpus
// (cut 5.5), one hostile sample at exactly v = 5.5 ((11, 2)) satisfies the
// `<= cut` filter, survives, and becomes the kept maximum: v_max jumps
// 3 -> 9 (ceil(5.5 * 1.5)), so a forged (distance 16, dt 2) claim passes.
#[test]
fn exactly_at_cut_sample_survives_and_sets_vmax() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..32 {
        corpus.push((2, 2));
    }
    for _ in 0..32 {
        corpus.push((4, 2));
    }
    corpus.push((11, 2)); // v = 5.5, exactly the honest cut 1.5 + 8*0.5
    let law = fit_law(&corpus, RING).unwrap();
    // Classification: HOLE — the boundary-inclusive filter keeps the at-cut poison.
    assert_eq!(law.v_max, 9); // ceil(5.5 * 1.5)
    assert!(law.cone_contains(2, 16, 0, 0)); // needs v = 8.0; honest law (v 3) rejects
    let honest_law = fit_law(
        &{
            let mut h = Vec::new();
            for _ in 0..32 {
                h.push((2, 2));
            }
            for _ in 0..32 {
                h.push((4, 2));
            }
            h
        },
        RING,
    )
    .unwrap();
    assert!(!honest_law.cone_contains(2, 16, 0, 0));
}

// Attack 4 — HOLE: bimodal collusion. Against 64 honest samples at v = 2.0
// (MAD 0, cut 2.0 — any lone fast wing is trimmed), the attacker adds BOTH a
// fast wing (32 x v = 6.0) and a slow wing (32 x v = 0.5). The slow wing drags
// the median down but inflates MAD to 0.75, widening the cut to 8.0 so the
// fast wing is kept: v_max jumps 3 -> 9, and a forged (distance 17, dt 2)
// claim passes that the honest law rejects.
#[test]
fn bimodal_colluding_wings_widen_cut() {
    let honest: Vec<(u64, u64)> = vec![(4, 2); 64]; // v = 2.0
    let honest_law = fit_law(&honest, RING).unwrap();
    assert_eq!(honest_law.v_max, 3);

    // Lone fast wing is trimmed — the control for this attack.
    let mut lone = honest.clone();
    for _ in 0..32 {
        lone.push((12, 2)); // v = 6.0
    }
    assert_eq!(fit_law(&lone, RING).unwrap().v_max, 3);

    // Colluding slow wing widens the cut and admits the fast wing.
    let mut corpus = honest.clone();
    for _ in 0..32 {
        corpus.push((12, 2)); // v = 6.0 fast wing
    }
    for _ in 0..32 {
        corpus.push((1, 2)); // v = 0.5 slow wing
    }
    let law = fit_law(&corpus, RING).unwrap();
    // Classification: HOLE — the slow wing exists only to inflate MAD for the fast wing.
    assert_eq!(law.v_max, 9); // ceil(6.0 * 1.5)
    assert!(!honest_law.cone_contains(2, 17, 0, 0)); // needs v = 8.5
    assert!(law.cone_contains(2, 17, 0, 0));
}

// Attack 5 — HOLE (false impossibility, the other direction): an honest
// bimodal corpus — 60 samples at v = 1.0 plus 6 legitimate fast samples at
// v = 3.0 (e.g. a genuinely faster relay path) — is trimmed by its own
// calibration: median 1.0, MAD 0.0, cut 1.0 removes the honest fast wing, so
// the fitted law (v_max 2) declares legitimate traffic
// (distance 6, dt 2, needs v = 3.0) UNCONSTRUCTIBLE.
#[test]
fn honest_fast_wing_trimmed_into_false_impossibility() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..60 {
        corpus.push((2, 2)); // v = 1.0 bulk honest traffic
    }
    for _ in 0..6 {
        corpus.push((6, 2)); // v = 3.0 legitimate fast path
    }
    let law = fit_law(&corpus, RING).unwrap();
    assert_eq!(law.v_max, 2);
    // Classification: HOLE — the law cannot keep its own honest fast samples constructible.
    assert!(!law.cone_contains(2, 6, 0, 0)); // needs v = 3.0 > fitted 2
}

// Attack 6 — HOLE: minimum-size corpus hijack. With only 16 samples required,
// an 8 x v=1.0 + 8 x v=2.0 honest base (cut 5.5, v_max 3) is hijacked by ONE
// hostile sample placed exactly at the cut (v = 5.5), which the
// boundary-inclusive filter keeps: v_max jumps 3 -> 9.
#[test]
fn minimum_corpus_at_cut_hijack() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..8 {
        corpus.push((2, 2)); // v = 1.0
    }
    for _ in 0..8 {
        corpus.push((4, 2)); // v = 2.0; honest cut = 5.5, v_max = 3
    }
    assert_eq!(fit_law(&corpus, RING).unwrap().v_max, 3);
    corpus.push((11, 2)); // v = 5.5, exactly at the honest cut
    let law = fit_law(&corpus, RING).unwrap();
    // Classification: HOLE — one crafted sample suffices at minimum corpus scale.
    assert_eq!(law.v_max, 9);
    assert!(law.cone_contains(2, 16, 0, 0));
}

// Attack 7 — HOLE: supermajority hostile corpus. 16 honest samples at v = 1.0
// plus 48 hostile samples at v = 9.0: the median itself (9.0) is attacker
// territory and MAD collapses to 0.0, so the cut (9.0) keeps everything and
// v_max lands at 14 (ceil(9.0 * 1.5)) — the honest sixteenth of the corpus
// has no measurable influence on the physics.
#[test]
fn supermajority_hostile_corpus_owns_median() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..16 {
        corpus.push((2, 2)); // v = 1.0 honest minority
    }
    for _ in 0..48 {
        corpus.push((18, 2)); // v = 9.0 hostile supermajority
    }
    let law = fit_law(&corpus, RING).unwrap();
    // Classification: HOLE — past 50%, hostile samples set median, MAD, and max.
    assert_eq!(law.v_max, 14); // ceil(9.0 * 1.5)
    assert!(law.cone_contains(2, 27, 0, 0)); // needs v = 13.5; honest law rejects
    let honest_law = fit_law(&vec![(2, 2); 16], RING).unwrap();
    assert!(!honest_law.cone_contains(2, 27, 0, 0));
}

// Attack 8 — BOUNDARY: pure-hostile corpus. fit_law cannot distinguish curation
// from physics — 32 samples at v = 30.0 fit v_max 45 with no error, because
// "normal traffic" is a trust assumption on the caller, not something geometry
// can check. This is inherent to the passive-geometry doctrine (the lightcone
// depends on its trained world; who supplies that world is an architecture
// decision), but it is recorded here because it is the limiting case of every
// HOLE above: past the majority cliff there is no residual honest anchor.
#[test]
fn pure_hostile_corpus_is_accepted_as_physics() {
    let corpus: Vec<(u64, u64)> = vec![(30, 1); 32]; // v = 30.0 throughout
    let law = fit_law(&corpus, RING).unwrap();
    // Classification: BOUNDARY — no trim, no error; curation trust is load-bearing.
    assert_eq!(law.v_max, 45); // ceil(30.0 * 1.5)
    assert!(law.cone_contains(1, 30, 0, 0));
}

// Attack 9 — payoff through the Lightcone API (HOLE end-to-end): the poisoned
// law from Attack 1 is installed in a real Lightcone, and a recorded claim
// whose cause is 2 ticks back and 15 hops away — geometrically impossible
// under honest physics — produces NO CausalImpossibility fact.
#[test]
fn poisoned_law_silences_unconstructible_claims_end_to_end() {
    let honest_law = PropagationLaw {
        v_max: 3,
        ring_size: RING,
    };
    let poisoned_law = PropagationLaw {
        v_max: 8,
        ring_size: RING,
    };

    let mut honest_cone = Lightcone::new(honest_law);
    honest_cone.record(imperium_net_mesh::CausalObservation {
        tick: 500,
        position: 12,
        claims_cause: Some((498, 27)), // ring distance 15, dt 2
    });
    let honest_facts = honest_cone.unconstructible_claims();
    assert_eq!(honest_facts.len(), 1);
    assert_eq!(honest_facts[0].distance, 15);

    let mut poisoned_cone = Lightcone::new(poisoned_law);
    poisoned_cone.record(imperium_net_mesh::CausalObservation {
        tick: 500,
        position: 12,
        claims_cause: Some((498, 27)),
    });
    // Classification: HOLE — the same forged claim evaporates as a fact under the warped law.
    assert_eq!(poisoned_cone.unconstructible_claims().len(), 0);
}

// Attack 10 — DEFENDED (control): gradual creep BELOW the cut fails. Adding 16
// samples at v = 1.5 to 64 honest samples at v = 1.0 leaves median 1.0 and MAD
// 0.0, so the cut (1.0) trims the creep wing entirely: v_max stays 2. The trim
// does defeat sub-cut creep against a zero-spread baseline — the attacker must
// first widen MAD (Attacks 1/4) or capture the median (Attacks 2/7).
#[test]
fn sub_cut_creep_against_zero_spread_baseline_fails() {
    let mut corpus: Vec<(u64, u64)> = Vec::new();
    for _ in 0..64 {
        corpus.push((2, 2)); // v = 1.0
    }
    for _ in 0..16 {
        corpus.push((3, 2)); // v = 1.5 creep wing
    }
    let law = fit_law(&corpus, RING).unwrap();
    // Classification: DEFENDED — sub-cut creep is trimmed when the baseline has no spread.
    assert_eq!(law.v_max, 2);
}
