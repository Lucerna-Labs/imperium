//! Adversarial geometry tests for the lightcone (passive causal geometry).
//!
//! Every test asserts CURRENT observed behavior under the debug test profile,
//! so the suite compiles and runs green regardless of outcome:
//!   cargo test --manifest-path /home/jesse/Desktop/Projects/imperium-main/imperium-main/Cargo.toml -p imperium-net-mesh --test lightcone_adversary_geometry
//! Each test carries a classification comment: DEFENDED / HOLE / BOUNDARY.

use imperium_net_mesh::{fit_law, ring_distance, CausalObservation, Lightcone, PropagationLaw};
use std::panic::AssertUnwindSafe;

fn std_law() -> PropagationLaw {
    PropagationLaw {
        v_max: 2,
        ring_size: 64,
    }
}

/// HOLE (math broken: denial of the fact service under the test/debug
/// profile, silent metric corruption in release). Nothing validates positions
/// against ring_size. |10 - 200| = 190 > ring 64, so `ring_size - forward`
/// (lightcone.rs:62) underflows. Observed: panics here; in release (overflow
/// checks off) the same line wraps and returns min(190, 2^64-126) = 190, a
/// distance larger than the ring's half (32) — the ring metric is broken.
#[test]
fn out_of_range_position_panics_ring_distance() {
    let r = std::panic::catch_unwind(|| ring_distance(10, 200, 64));
    assert!(
        r.is_err(),
        "expected underflow panic for |a-b| > ring_size, got {r:?}"
    );
}

/// BOUNDARY (inherent to unnormalized u64 coordinates; requires an
/// architecture decision on who canonicalizes positions). 74 = 10 + 64, so it
/// aliases site 10 without underflow (forward = 64, backward = 64 - 64 = 0),
/// and a cause 64 raw hops away with only 1 tick elapsed tests as
/// constructible. The geometry is defined on the ring but coordinates are
/// never reduced mod ring_size, so the trust assumption is: whoever assigns
/// positions binds each site to one canonical representative in
/// [0, ring_size). Observed: distance 0, contained with dt = 1.
#[test]
fn ring_alias_without_normalization_admits_far_raw_cause() {
    assert_eq!(ring_distance(10, 74, 64), 0);
    assert!(std_law().cone_contains(11, 10, 10, 74));
}

/// HOLE (denial): record() validates nothing (lightcone.rs:206-211), and
/// unconstructible_claims() feeds ledger coordinates straight into
/// cone_contains -> ring_distance, so ONE recorded observation whose cause
/// position is out of range panics the entire fact query. Observed: panics.
#[test]
fn ledger_query_panics_on_out_of_range_cause() {
    let mut cone = Lightcone::new(std_law());
    cone.record(CausalObservation {
        tick: 100,
        position: 10,
        claims_cause: Some((0, 200)), // |10 - 200| = 190 > ring 64
    });
    let r = std::panic::catch_unwind(AssertUnwindSafe(|| cone.unconstructible_claims()));
    assert!(r.is_err(), "expected fact-service panic, got {r:?}");
}

/// DEFENDED: saturating_mul at huge dt does NOT admit forgeries. With dt =
/// u64::MAX the reach saturates to u64::MAX, but the true product v*dt also
/// exceeds every valid distance, so saturation coincides with the law's own
/// ordering — and cone_radius still caps at half the ring. Observed:
/// contained (correct: after ~1.8e19 ticks, 32 hops is reachable), radius 32.
#[test]
fn saturating_reach_at_max_dt_stays_consistent() {
    let law = std_law();
    // distance(5, 37) = 32; reach saturates to u64::MAX; min_ticks_for(32) = 16.
    assert!(law.cone_contains(u64::MAX, 5, 0, 37));
    assert_eq!(law.min_ticks_for(32), 16);
    assert_eq!(law.cone_radius(u64::MAX), 32);
}

/// DEFENDED: a zero-velocity law is degenerate but consistent — only the
/// same site in the past is contained, any move is rejected. Note (reporting
/// wart, degenerate law only): min_ticks_for(0) returns u64::MAX under v = 0
/// via the early return, even though cone_contains admits the same-site past
/// claim. Observed: true / false / u64::MAX as asserted.
#[test]
fn zero_velocity_law_freezes_causality_consistently() {
    let law = PropagationLaw {
        v_max: 0,
        ring_size: 64,
    };
    assert!(law.cone_contains(10, 5, 5, 5)); // same site, past: contained
    assert!(!law.cone_contains(10, 5, 5, 6)); // one hop with v = 0: rejected
    assert_eq!(law.min_ticks_for(5), u64::MAX);
    assert_eq!(law.min_ticks_for(0), u64::MAX);
}

/// DEFENDED: odd and degenerate ring sizes keep a consistent metric for
/// in-range positions. Ring 65: distance(0, 32) = min(32, 33) = 32, needs 16
/// ticks at v = 2 — dt = 16 admitted, dt = 15 rejected, radius caps at
/// 65/2 = 32. Ring 1 has a single site (distance 0); ring 2 caps radius at 1;
/// ring 0 is refused by debug_assert. Observed: all as asserted.
#[test]
fn odd_and_degenerate_ring_sizes_stay_consistent() {
    let law = PropagationLaw {
        v_max: 2,
        ring_size: 65,
    };
    assert_eq!(ring_distance(0, 32, 65), 32);
    assert!(law.cone_contains(16, 0, 0, 32));
    assert!(!law.cone_contains(15, 0, 0, 32));
    assert_eq!(law.cone_radius(1_000), 32);

    assert_eq!(ring_distance(0, 0, 1), 0);
    let one = PropagationLaw {
        v_max: 2,
        ring_size: 1,
    };
    assert!(one.cone_contains(10, 0, 5, 0));
    assert_eq!(one.cone_radius(5), 0); // capped at 1/2 = 0
    assert_eq!(ring_distance(0, 1, 2), 1);

    let r = std::panic::catch_unwind(|| ring_distance(5, 5, 0));
    assert!(r.is_err(), "ring_size 0 must be refused, got {r:?}");
}

/// HOLE (math broken: panic): min_ticks_for computes (distance + v_max - 1)
/// (lightcone.rs:109) with plain wrapping-prone arithmetic, so the maximum
/// distance overflows in debug. Observed: min_ticks_for(u64::MAX) with
/// v = 2 panics on `u64::MAX + 2`. (In release it wraps to required ticks 0
/// for the maximum distance — a false fact, though only the report field, not
/// the containment decision, uses it.)
#[test]
fn min_ticks_for_overflows_on_max_distance() {
    let law = std_law();
    let r = std::panic::catch_unwind(AssertUnwindSafe(|| law.min_ticks_for(u64::MAX)));
    assert!(r.is_err(), "expected overflow panic, got {r:?}");
}

/// BOUNDARY (inherent: bytes carry encoding integrity, not provenance —
/// requires an architecture decision on who may define the world).
/// from_bytes validates only length and ring != 0 (lightcone.rs:120-130), so
/// attacker-supplied law bytes with v_max = u64::MAX decode to Some and
/// silently redefine constructibility: reach saturates to u64::MAX for any
/// dt >= 1, so a claim needing 10 ticks (distance 20, dt 2) tests as
/// constructible. The component cannot distinguish its calibrated law from a
/// forged one — only the holder of the expected digest can. Observed: decodes
/// to Some, forged claim admitted, digest differs from the honest law.
/// Proposed fix: pin the fit_law digest and refuse any law bytes whose digest
/// does not match; never accept law bytes across a trust boundary unchecked.
#[test]
fn law_codec_accepts_world_redefining_vmax() {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[8..].copy_from_slice(&64u64.to_le_bytes());
    let forged = PropagationLaw::from_bytes(&bytes).expect("codec must decode per current code");
    assert_eq!(forged.v_max, u64::MAX);

    // Impossible under the honest law (20 > 2*2), admitted under the forgery.
    assert!(!std_law().cone_contains(10, 0, 8, 20));
    assert!(forged.cone_contains(10, 0, 8, 20));
    assert_ne!(forged.digest(), std_law().digest());
}

/// HOLE (law warped): the documented robustness ("MAD trimming keeps hostile
/// samples from inflating the physics", lightcone.rs:35-37, 285) fails for
/// ONE in-band poisoned sample. 31 honest samples (velocities 1/2 and 1/3)
/// fit v_max = 1; adding a single valid sample (4 hops, 4 ticks — velocity
/// 1.0, inside the median + 8*MAD band) doubles the fitted v_max to 2, and a
/// concrete forgery (4 hops in 2 ticks) flips from rejected to admitted.
/// Observed: honest v_max 1, poisoned v_max 2, claim flips false -> true.
/// Proposed fix: fit v_max from a high quantile of kept velocities (not the
/// max), or bound single-sample influence on the declared law.
#[test]
fn single_in_band_poison_sample_doubles_vmax() {
    let mut honest = Vec::new();
    for _ in 0..16 {
        honest.push((1u64, 2u64));
    }
    for _ in 0..15 {
        honest.push((1u64, 3u64));
    }
    let honest_law = fit_law(&honest, 64).expect("honest corpus must fit");
    assert_eq!(honest_law.v_max, 1);

    let mut poisoned = honest.clone();
    poisoned.push((4u64, 4u64)); // velocity 1.0: valid sample, inside trim band
    let warped = fit_law(&poisoned, 64).expect("poisoned corpus must fit");
    assert_eq!(warped.v_max, 2);

    // Forgery: 4 hops in 2 ticks. Rejected under the honest law, admitted
    // under the warped one.
    assert!(!honest_law.cone_contains(10, 0, 8, 4));
    assert!(warped.cone_contains(10, 0, 8, 4));
}

/// BOUNDARY (inherent: curation trust — the code documents it as "a
/// majority-hostile corpus is a curation bug", lightcone.rs:288-293).
/// fit_law requires samples "from traffic known to be normal"; when 9 of 16
/// samples are poisoned near-instant replies (20 hops, 1 tick), the fallback
/// keeps the poison and declares v_max = 30, under which the poison's own
/// forgery shape (20 hops in 1 tick) tests constructible. The trust
/// assumption is precise: the calibrator must curate a majority-honest
/// corpus — the component cannot create honesty from samples. Observed:
/// v_max 30, hostile shape admitted.
#[test]
fn majority_hostile_corpus_falls_back_to_warped_law() {
    let mut samples = Vec::new();
    for _ in 0..7 {
        samples.push((1u64, 2u64)); // honest: velocity 0.5
    }
    for _ in 0..9 {
        samples.push((20u64, 1u64)); // hostile: velocity 20, valid per checks
    }
    let law = fit_law(&samples, 64).expect("16 samples must fit");
    assert_eq!(law.v_max, 30);
    assert!(law.cone_contains(1, 20, 0, 0)); // the hostile shape now fits
}
