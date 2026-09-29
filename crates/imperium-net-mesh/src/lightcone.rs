//! The lightcone: causal geometry over network spacetime.
//!
//! Faithful to the measured physics (LIGHTCONE-PHYSICS.md, experiment E5)
//! and its operational form (the E8 cone containment validator; the D60
//! correction: "the ORIGINAL lightcone is GEOMETRIC — a causal cone").
//! Every observation lives at a `(tick, position)` in spacetime; a
//! propagation law declares how far information can travel per tick
//! (`v_max` — the network's speed of light, calibrated on normal traffic,
//! the discrete-law version of the measured group velocity 2J). The cone
//! answers one question as a fact of structure:
//!
//! ```text
//! ring_distance(record_pos, ancestor_pos) <= v_max * (record_tick - ancestor_tick)
//! ```
//!
//! The measured design rules, carried here:
//!
//! 1. Cone containment is a property of the LAW, not the medium. A
//!    discrete local law (bounded hops per tick) is cone-bearing by
//!    construction; this module only accepts such laws.
//! 2. Every law declares its v, and the declaration carries tail
//!    tolerance: real propagation keeps exponentially small mass beyond
//!    v·t (measured: 1.5·v·t at < 1e-4), so `fit_law` bakes the 1.5
//!    safety factor into the declared v rather than demanding compact
//!    support at the check.
//! 3. Validity = unconstructibility, checked against the LAW's reachable
//!    set — never against policy. The lightcone depends on nothing but
//!    its trained world: no policy, profile, or orchestrator input
//!    exists in this module, and none can reach in. That seal is the
//!    point — hence lightcone.
//! 4. Reading is measurement; the interior stays unobserved. The ledger
//!    is the unmeasured layer where cones stay sharp; the query methods
//!    are the classical tap interface where structure resolves to facts.
//! 5. The propagation budget is physical: `fit_law` measures it from
//!    normal activity (robust MAD trimming keeps hostile samples from
//!    inflating the physics — an on-path attacker answering
//!    near-instantly must not widen the cone).
//!
//! The law is immutable after construction: a different law is a
//! different world, and you construct a new lightcone for it. The fitted
//! law serializes bit-exactly and carries a SHA-256 digest.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};

/// A site in network space: the sender's position on the overlay ring.
pub type Position = u64;
/// A moment on the node's monotonic observation clock.
pub type Tick = u64;

/// Measured tail tolerance (E5): exponentially small mass persists beyond
/// v·t, so the declared law scales its velocity by 1.5 rather than
/// demanding compact support at the containment check.
const TAIL_TOLERANCE: f64 = 1.5;

/// Ring distance: the minimum of clockwise and counterclockwise paths.
pub fn ring_distance(a: Position, b: Position, ring_size: u64) -> u64 {
    debug_assert!(ring_size > 0, "ring size must be positive");
    let forward = a.abs_diff(b);
    let backward = ring_size - forward;
    forward.min(backward)
}

/// The declared propagation law: how far information can travel per tick.
/// This is the network's "speed of light" — the geometry's one constant,
/// calibrated from normal traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PropagationLaw {
    /// Maximum ring hops per tick (the causal velocity).
    pub v_max: u64,
    /// The overlay ring's circumference.
    pub ring_size: u64,
}

impl PropagationLaw {
    /// Whether an ancestor at `(ancestor_tick, ancestor_position)` lies
    /// within the causal cone of a record at `(record_tick,
    /// record_position)`. The ancestor must be strictly in the past and
    /// within reach; anything else is unconstructible.
    pub fn cone_contains(
        &self,
        record_tick: Tick,
        record_position: Position,
        ancestor_tick: Tick,
        ancestor_position: Position,
    ) -> bool {
        if ancestor_tick >= record_tick {
            // Same tick or future: not a valid ancestor at all.
            return false;
        }
        let dt = record_tick - ancestor_tick;
        let distance = ring_distance(record_position, ancestor_position, self.ring_size);
        distance <= self.v_max.saturating_mul(dt)
    }

    /// The cone radius at a given Δtick (the maximum reachable distance),
    /// capped at half the ring.
    pub fn cone_radius(&self, dt: Tick) -> u64 {
        self.v_max.saturating_mul(dt).min(self.ring_size / 2)
    }

    /// The minimum Δtick for causality to bridge a ring distance.
    pub fn min_ticks_for(&self, distance: u64) -> Tick {
        if self.v_max == 0 {
            return Tick::MAX;
        }
        (distance + self.v_max - 1) / self.v_max
    }

    /// Bit-exact canonical encoding of the law.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.v_max.to_le_bytes());
        out[8..].copy_from_slice(&self.ring_size.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 16 {
            return None;
        }
        let v_max = u64::from_le_bytes(bytes[..8].try_into().ok()?);
        let ring_size = u64::from_le_bytes(bytes[8..].try_into().ok()?);
        if ring_size == 0 {
            return None;
        }
        Some(Self { v_max, ring_size })
    }

    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"imperium/lightcone/law/v1");
        hasher.update(self.to_bytes());
        let out = hasher.finalize();
        out.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A passive causal fact: a claim whose stated cause lies outside the
/// claimant's causal cone. No severity, no confidence — geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalImpossibility {
    /// The claim's position in spacetime.
    pub claim_tick: Tick,
    pub claim_position: Position,
    /// Where the claim said its cause was.
    pub cause_tick: Tick,
    pub cause_position: Position,
    /// Ring distance vs. the reach the law allows.
    pub distance: u64,
    pub required_min_ticks: Tick,
}

impl CausalImpossibility {
    /// The fact, stated plainly.
    pub fn statement(&self) -> String {
        format!(
            "claim at (tick {}, ring {}) cites a cause at (tick {}, ring {}): \
             ring distance {} requires at least {} ticks under the law, only {} elapsed",
            self.claim_tick,
            self.claim_position,
            self.cause_tick,
            self.cause_position,
            self.distance,
            self.required_min_ticks,
            self.claim_tick.saturating_sub(self.cause_tick),
        )
    }
}

/// One recorded observation in network spacetime. `claims_cause` is the
/// causal assertion the message itself made (a response citing its
/// request, gossip citing the event it reports) — the lightcone checks
/// the assertion against geometry, nothing more.
#[derive(Clone, Debug)]
pub struct CausalObservation {
    pub tick: Tick,
    pub position: Position,
    pub claims_cause: Option<(Tick, Position)>,
}

const LEDGER_CAPACITY: usize = 4_096;

/// The lightcone: a ledger of observations plus the propagation law.
/// Queryable, passive, judgment-free.
pub struct Lightcone {
    law: PropagationLaw,
    observations: VecDeque<CausalObservation>,
}

impl Lightcone {
    pub fn new(law: PropagationLaw) -> Self {
        Self {
            law,
            observations: VecDeque::with_capacity(LEDGER_CAPACITY),
        }
    }

    pub fn law(&self) -> &PropagationLaw {
        &self.law
    }

    /// Record an observation. Pure bookkeeping — no evaluation happens here.
    pub fn record(&mut self, observation: CausalObservation) {
        if self.observations.len() == LEDGER_CAPACITY {
            self.observations.pop_front();
        }
        self.observations.push_back(observation);
    }

    /// The passive containment query, exposed directly.
    pub fn cone_contains(&self, record: (Tick, Position), ancestor: (Tick, Position)) -> bool {
        self.law
            .cone_contains(record.0, record.1, ancestor.0, ancestor.1)
    }

    /// Every recorded claim whose stated cause lies outside its cone.
    /// These are geometric facts about the ledger; what to do with them
    /// is not this component's business.
    pub fn unconstructible_claims(&self) -> Vec<CausalImpossibility> {
        let mut facts = Vec::new();
        for observation in &self.observations {
            let Some((cause_tick, cause_position)) = observation.claims_cause else {
                continue;
            };
            if self.law.cone_contains(
                observation.tick,
                observation.position,
                cause_tick,
                cause_position,
            ) {
                continue;
            }
            let distance = ring_distance(observation.position, cause_position, self.law.ring_size);
            facts.push(CausalImpossibility {
                claim_tick: observation.tick,
                claim_position: observation.position,
                cause_tick,
                cause_position,
                distance,
                required_min_ticks: self.law.min_ticks_for(distance),
            });
        }
        facts
    }
}

/// Calibration: fit the propagation law's `v_max` from normal-activity
/// samples. Each sample is one observed causal hop — `(distance in ring
/// hops, elapsed ticks)` — from traffic known to be normal. Robust
/// MAD trimming excludes hostile outliers (near-instant on-path replies
/// would otherwise inflate the physics and widen the cone for attackers).
///
/// `v_max` is the smallest velocity that keeps the trimmed normal corpus
/// constructible, at a 1-tick safety margin: the law must never declare
/// the system's own honest traffic impossible.
pub fn fit_law(samples: &[(u64, Tick)], ring_size: u64) -> Result<PropagationLaw, String> {
    if ring_size == 0 {
        return Err("ring size must be positive".to_string());
    }
    if samples.len() < 16 {
        return Err(format!("needs at least 16 samples, got {}", samples.len()));
    }
    if samples
        .iter()
        .any(|(d, t)| *d == 0 || *t == 0 || *d > ring_size / 2)
    {
        return Err("samples must be positive hops within half the ring".to_string());
    }

    // Per-sample velocity: ceil(distance / ticks), in ticks^-1 hops.
    let velocities: Vec<f64> = samples.iter().map(|(d, t)| *d as f64 / *t as f64).collect();

    // Robust trim (median + 8*MAD) against poisoned fast outliers.
    let cut = median(&mut velocities.clone()) + 8.0 * mad(&velocities);
    let trimmed: Vec<f64> = velocities.iter().copied().filter(|v| *v <= cut).collect();
    // Never trim below half — a majority-hostile corpus is a curation bug.
    let kept: &[f64] = if trimmed.len() < samples.len() / 2 {
        &velocities
    } else {
        &trimmed
    };

    // v_max = ceil(max kept velocity x 1.5 tail tolerance), at least 1.
    let fastest = kept.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let v_max = (fastest * TAIL_TOLERANCE).ceil().max(1.0) as u64;

    Ok(PropagationLaw { v_max, ring_size })
}

fn median(sorted: &mut [f64]) -> f64 {
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

fn mad(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    let med = median(&mut sorted);
    let mut deviations: Vec<f64> = values.iter().map(|v| (v - med).abs()).collect();
    median(&mut deviations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn law() -> PropagationLaw {
        PropagationLaw {
            v_max: 2,
            ring_size: 64,
        }
    }

    #[test]
    fn cone_containment_truth_table() {
        let law = law();
        // dt = 4, reach = 8: distance 8 is on the boundary, 9 is outside.
        assert!(law.cone_contains(100, 10, 96, 2)); // distance 8 == 2*4
        assert!(!law.cone_contains(100, 10, 96, 1)); // distance 9 > 8
                                                     // Ring wraparound: positions 10 and 58 are 16 apart the short way.
        assert!(law.cone_contains(100, 10, 90, 58)); // 16 <= 2*10
                                                     // Same tick or future: never a valid ancestor.
        assert!(!law.cone_contains(100, 10, 100, 10));
        assert!(!law.cone_contains(100, 10, 101, 10));
    }

    #[test]
    fn cone_radius_caps_at_half_ring() {
        let law = law();
        assert_eq!(law.cone_radius(4), 8);
        assert_eq!(law.cone_radius(1_000), 32); // 64/2
        assert_eq!(law.min_ticks_for(5), 3); // ceil(5/2)
        assert_eq!(law.min_ticks_for(0), 0);
    }

    #[test]
    fn unconstructible_claims_are_facts_not_judgments() {
        let mut cone = Lightcone::new(law());

        // A legal response: cause 5 ticks ago, 4 hops away (needs 2 ticks).
        cone.record(CausalObservation {
            tick: 500,
            position: 12,
            claims_cause: Some((495, 16)),
        });
        // An impossible claim: cause 2 ticks ago, 20 hops away (needs 10).
        cone.record(CausalObservation {
            tick: 500,
            position: 12,
            claims_cause: Some((498, 32)),
        });

        let facts = cone.unconstructible_claims();
        assert_eq!(facts.len(), 1);
        let fact = &facts[0];
        assert_eq!(fact.distance, 20);
        assert_eq!(fact.required_min_ticks, 10);
        // The statement states geometry; it contains no severity language.
        let text = fact.statement();
        assert!(text.contains("requires at least 10 ticks"));
        assert!(!text.to_lowercase().contains("confidence"));
        assert!(!text.to_lowercase().contains("threat"));
    }

    #[test]
    fn ledger_is_bounded_bookkeeping() {
        let mut cone = Lightcone::new(law());
        for i in 0..(LEDGER_CAPACITY + 50) as u64 {
            cone.record(CausalObservation {
                tick: i,
                position: 1,
                claims_cause: None,
            });
        }
        assert_eq!(cone.unconstructible_claims().len(), 0);
    }

    #[test]
    fn law_serializes_bit_exactly_with_digest() {
        let law = law();
        let round = PropagationLaw::from_bytes(&law.to_bytes()).unwrap();
        assert_eq!(round, law);
        assert_eq!(round.digest(), law.digest());
        assert!(PropagationLaw::from_bytes(&[0u8; 15]).is_none());
        // Zero ring is not a world.
        assert!(PropagationLaw::from_bytes(&{
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&2u64.to_le_bytes());
            b
        })
        .is_none());
    }

    #[test]
    fn fit_law_keeps_normal_traffic_constructible_and_trims_poison() {
        // Normal corpus: consistent slow-ish propagation, 1 hop per 2-3 ticks.
        let mut samples = Vec::new();
        for i in 0..64u64 {
            let hops = 1 + i % 6;
            let ticks = hops * (2 + i % 2);
            samples.push((hops, ticks));
        }
        // Poisoned fast outliers: near-instant long hops.
        for _ in 0..6 {
            samples.push((20, 1));
        }

        let law = fit_law(&samples, 64).unwrap();
        // Trimmed poison must not define the physics: normal velocities top
        // out near 0.5 hops/tick, so with the 1.5 tail tolerance the law
        // lands at 1; the poison (20 hops in 1 tick = velocity 20) is far
        // outside and must not move it.
        assert!(
            law.v_max <= 2,
            "poisoned samples inflated v_max to {}",
            law.v_max
        );
        assert!(law.v_max >= 1);

        // Every honest sample stays constructible under the fitted law.
        for (hops, ticks) in &samples[..64] {
            assert!(
                law.cone_contains(*ticks, *hops, 0, 0),
                "honest sample ({hops}, {ticks}) fell outside the fitted cone"
            );
        }
    }

    #[test]
    fn fit_law_is_deterministic_and_validates_input() {
        let samples: Vec<(u64, Tick)> = (0..32u64).map(|i| (1 + i % 4, 2 + i % 3)).collect();
        let a = fit_law(&samples, 64).unwrap();
        let b = fit_law(&samples, 64).unwrap();
        assert_eq!(a.digest(), b.digest());

        assert!(fit_law(&samples, 0).is_err());
        assert!(fit_law(&[], 64).is_err());
        assert!(fit_law(&[(0, 1); 32], 64).is_err());
        assert!(fit_law(&[(40, 1); 32], 64).is_err()); // beyond half ring
    }
}
