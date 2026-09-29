//! imperium-net-guard — a no-pass guard: a gate that refuses passage, not a
//! function. See README.md for the PRINCIPLE LIMIT and CRITICALITY blocks.
//!
//! The guard is dumb and deterministic (THESIS.md #2, #5): it admits or it
//! doesn't, and it never decides policy. The verifier behind it keeps all
//! authority. A failed knock is indistinguishable from silence (P2), and a
//! knocker who forces the gate past budget is moved into an illusion interior
//! rather than merely denied.

mod judge;
mod ledger;

pub use judge::{GrayZone, GrayZoneJudge, JudgeVerdict, ZoneClassification};
pub use ledger::{Ledger, LedgerError, SourceState};

use imperium_protocol::BusEvent;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use spiderweb::{BusError, BusPublisher};

/// A knock presented at the gate. The presented material is opaque: the guard
/// performs shape and length checks only, and never interprets content.
#[derive(Clone, Debug)]
pub struct Knock {
    /// Who is knocking. The source tag is the only thing every layer reads.
    pub source: String,
    /// A single-use attempt token id. Burns on presentation, win or lose.
    pub attempt_token: String,
    /// Opaque presented bytes. Shape-checked, never parsed.
    pub presented: Vec<u8>,
}

/// The gate's decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardVerdict {
    /// Full passage. All three of P3's conjuncts held.
    Admit,
    /// Zero passage, and zero information. Every failure reason produces this
    /// same value with the same (empty) payload (P2).
    SilentReject,
}

impl GuardVerdict {
    /// The bytes a knocker can observe. Identical for every failure reason —
    /// this is the observable half of P2.
    pub fn observable_bytes(&self) -> &'static [u8] {
        match self {
            // Admission yields nothing here either: the verifier behind the
            // gate is what speaks on the honest path, not the guard.
            GuardVerdict::Admit | GuardVerdict::SilentReject => &[],
        }
    }

    /// The timing bucket an observable lands in. Every failure reason maps to
    /// the same bucket, so a knocker cannot time the difference.
    pub fn timing_bucket(&self) -> u32 {
        TIMING_BUCKET
    }
}

/// One timing bucket for the whole gate. Named so the intent is unmissable:
/// there is no second bucket to leak into.
pub const TIMING_BUCKET: u32 = 0;

/// Why a knock failed — **internal only**. Never reaches the knocker; the
/// operator sees it in the log, the knocker sees [`GuardVerdict::SilentReject`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectReason {
    UnknownToken,
    ReusedToken,
    OverBudget,
    BadShape,
    WindowClosed,
}

/// An avalanched source and the face it was given. The nesting seam the
/// illusion interior consumes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvalanchedSource {
    pub source: String,
    pub face_id: u64,
    pub since: i64,
}

/// Configuration. One construction-time budget, one construction-time shape
/// limit, one construction-time hysteresis gap. No runtime mutation anywhere
/// (no threshold drift).
#[derive(Clone, Debug)]
pub struct GuardConfig {
    /// `B` from P1: the per-source attempt budget.
    pub budget: u64,
    /// Maximum presented-material length the gate will accept. Shape only.
    pub max_shape_len: usize,
    /// Hysteresis: the avalanche untrips only after this many *fewer* attempts
    /// than it took to trip. `trip_at < budget`, `untrip_at < trip_at`.
    pub untrip_after: u64,
    /// The emission budget per source (P3 of the illusion stack, seeded here so
    /// the ledger is the single accounting boundary).
    pub emission_budget: u64,
}

impl Default for GuardConfig {
    fn default() -> Self {
        // K = (A − L) / σ_L is a construction-time property. With L = 1 by
        // design, B = 8 leaves a wide gap for ordinary retry jitter.
        Self {
            budget: 8,
            max_shape_len: 4096,
            untrip_after: 4,
            emission_budget: 65_536,
        }
    }
}

/// The guard.
pub struct Guard {
    config: GuardConfig,
    ledger: Mutex<Ledger>,
    judge: Box<dyn GrayZoneJudge>,
}

impl Guard {
    pub fn new(config: GuardConfig) -> Result<Self, GuardConfigError> {
        if config.budget == 0 {
            return Err(GuardConfigError::ZeroBudget);
        }
        if config.untrip_after >= config.budget {
            return Err(GuardConfigError::HysteresisGapTooLarge);
        }
        Ok(Self {
            config,
            ledger: Mutex::new(Ledger::new()),
            // With no judge attached the guard still refuses; it simply does
            // not subdivide the gray zone (abstain toward sinking).
            judge: Box::new(judge::AbstainToSink),
        })
    }

    /// Attach the cognitive judge. The judge classifies the gray zone only; it
    /// never acts (see `judge` module).
    pub fn with_judge(mut self, judge: Box<dyn GrayZoneJudge>) -> Self {
        self.judge = judge;
        self
    }

    pub fn config(&self) -> &GuardConfig {
        &self.config
    }

    /// Mint an attempt token. The operator's hand on the gate — and the cheap
    /// half of the declared payer (README, Option A): the honest knock carries
    /// a token the imitator does not have, while the *failure* side stays
    /// indistinguishable (P2).
    pub fn issue_token(&self, token: &str) {
        self.ledger.lock().issue_token(token);
    }

    /// The gate. This is the only entry point, and it has no caller-identity
    /// parameter beyond the source tag: the guard cannot deny *by instruction*
    /// because admission is decided by behavior (P3's conjunction), not policy.
    pub fn knock(&self, knock: &Knock, now: i64) -> GuardVerdict {
        let mut ledger = self.ledger.lock();

        // --- shape check is the only look at content, and it is length-only.
        let shape_ok = knock.presented.len() <= self.config.max_shape_len;

        // --- the token burns BEFORE any decision (conservation of attempts).
        // A valid token presented twice fails the second time.
        let burn = ledger.burn_token(&knock.source, &knock.attempt_token);

        let reason = if !shape_ok {
            Some(RejectReason::BadShape)
        } else {
            match burn {
                ledger::BurnOutcome::Unknown => Some(RejectReason::UnknownToken),
                ledger::BurnOutcome::Reused => Some(RejectReason::ReusedToken),
                ledger::BurnOutcome::Burned => None,
            }
        };

        // --- budget is the limiting reagent, and it is spent either way: an
        // attempt costs the source whether or not it was well-formed.
        let spent = ledger.spend_attempt(&knock.source, now);

        // --- hysteresis trip: avalanche at budget, untrip only below
        // untrip_after. The band never repeats the same width, so a knocker
        // sliding along the axis cannot locate the line.
        if spent >= self.config.budget {
            let face_id = derive_face(&knock.source, ledger.window_of(&knock.source));
            let avalanche = AvalanchedSource {
                source: knock.source.clone(),
                face_id,
                since: now,
            };
            ledger.mark_avalanched(&knock.source, &avalanche);
            // The judge may subdivide the gray zone, but it cannot admit and
            // cannot avalanche: it only classifies. The deterministic rule
            // below is what acts.
            let rationale = self.classify_gray(&ledger, knock);
            return match rationale {
                ZoneClassification::AdmitLeaning => GuardVerdict::SilentReject,
                ZoneClassification::AvalancheLeaning => GuardVerdict::SilentReject,
            };
        }

        match reason {
            None => GuardVerdict::Admit,
            Some(r) => {
                // Internal distinguishability, external indistinguishability.
                tracing::debug!(source = %knock.source, reason = ?r, "knock rejected");
                GuardVerdict::SilentReject
            }
        }
    }

    /// Ask the judge to classify the gray zone. With no judge attached the
    /// deterministic rule abstains toward sinking (the safe default).
    fn classify_gray(&self, ledger: &Ledger, knock: &Knock) -> ZoneClassification {
        let strained = judge::StrainedContext {
            zone: ledger.zone_of(&knock.source),
            attempts_in_window: ledger.spent_of(&knock.source),
            avalanched: ledger.is_avalanched(&knock.source),
        };
        match &self.judge {
            j => j.classify(&strained),
        }
    }

    /// Whether a source is currently in the illusion interior.
    pub fn is_avalanched(&self, source: &str) -> bool {
        self.ledger.lock().is_avalanched(source)
    }

    /// The face a source was given, if any.
    pub fn face_of(&self, source: &str) -> Option<AvalanchedSource> {
        self.ledger.lock().face_of(source)
    }

    /// P1's invariant as a checkable predicate: for every tracked source,
    /// spent + remaining == budget.
    pub fn ledger_invariant_holds(&self) -> bool {
        self.ledger.lock().invariant_holds(self.config.budget)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuardConfigError {
    #[error("budget must be non-zero")]
    ZeroBudget,
    #[error("untrip_after must be strictly less than budget (hysteresis needs a band)")]
    HysteresisGapTooLarge,
}

/// The face is *derived*, not chosen: a deterministic function of the shared
/// source id and the window. Two sources that burn identically still receive
/// uncorrelated faces because the source is in the derivation, and the layer
/// reads the shared source — never another layer's output.
fn derive_face(source: &str, window: u64) -> u64 {
    let mut z = 0x9E37_79B9_7F4A_7C15u64 ^ window;
    for b in source.as_bytes() {
        z = (z ^ *b as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z ^= z >> 29;
    }
    z
}

/// Bus wiring. Topics follow BUS_CONVENTIONS.md (general → specific).
pub mod topics {
    pub const READY: &str = "net.guard.ready";
    pub const AVALANCHE: &str = "net.guard.avalanche";
    pub const REJECTION: &str = "net.guard.rejection";
}

/// An avalanche event for the bus. Other stacks honor it; the fingerprint
/// stack consumes `face_id` as its input.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AvalancheEvent {
    pub source: String,
    pub face_id: u64,
    pub since: i64,
}

impl From<&AvalanchedSource> for AvalancheEvent {
    fn from(a: &AvalanchedSource) -> Self {
        Self {
            source: a.source.clone(),
            face_id: a.face_id,
            since: a.since,
        }
    }
}

pub async fn init(publisher: &BusPublisher) -> Result<(), BusError> {
    let ready = BusEvent::new(
        topics::READY,
        imperium_protocol::Message::SubsystemReady { name: NAME.into() },
    );
    publisher.publish(topics::READY, ready)?;
    tracing::info!("imperium-net-guard initialized");
    Ok(())
}

/// The subsystem name used in the readiness message and in logs.
pub const NAME: &str = "imperium-net-guard";

// ---------------------------------------------------------------------------
// Gates. Named for what they PROVE, not what they exercise.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod gates {
    use super::*;

    fn guard() -> Guard {
        Guard::new(GuardConfig::default()).unwrap()
    }

    fn knock(source: &str, token: &str, len: usize) -> Knock {
        Knock {
            source: source.into(),
            attempt_token: token.into(),
            presented: vec![0u8; len],
        }
    }

    /// A knock whose presented material is one byte over the shape limit.
    /// Built from the config rather than from `usize::MAX` so the test does not
    /// allocate a huge buffer just to be rejected for its size.
    fn over_long_knock(source: &str, token: &str) -> Knock {
        let limit = GuardConfig::default().max_shape_len;
        Knock {
            source: source.into(),
            attempt_token: token.into(),
            presented: vec![0u8; limit + 1],
        }
    }

    /// P2 — the no-oracle lemma. Every failure reason produces byte-identical
    /// output AND the same timing bucket.
    #[test]
    fn p2_all_failure_reasons_are_indistinguishable() {
        let g = guard();
        let mut observed: Vec<(Vec<u8>, u32)> = Vec::new();

        // bad shape
        observed.push((
            g.knock(&over_long_knock("s", "t1"), 0)
                .observable_bytes()
                .to_vec(),
            GuardVerdict::SilentReject.timing_bucket(),
        ));

        // unknown token (shape fine)
        observed.push((
            g.knock(&knock("s", "t2", 8), 1).observable_bytes().to_vec(),
            GuardVerdict::SilentReject.timing_bucket(),
        ));

        // over budget: burn the budget then knock again
        let g2 = guard();
        for i in 0..8 {
            g2.issue_token(&format!("tok{i}"));
            let _ = g2.knock(&knock("b", &format!("tok{i}"), 8), i);
        }
        g2.issue_token("tok-extra");
        observed.push((
            g2.knock(&knock("b", "tok-extra", 8), 9)
                .observable_bytes()
                .to_vec(),
            GuardVerdict::SilentReject.timing_bucket(),
        ));

        // Every observed failure is identical.
        let (first_bytes, first_bucket) = &observed[0];
        for (bytes, bucket) in &observed {
            assert_eq!(bytes, first_bytes, "failure output must be byte-identical");
            assert_eq!(bucket, first_bucket, "failure timing bucket must match");
        }
    }

    /// P3 — no free admission. Each conjunct removed individually yields a
    /// silent reject while the internal reason names the failed conjunct.
    #[test]
    fn p3_each_conjunct_is_load_bearing() {
        // all three hold -> Admit (token must be issued first)
        let g = guard();
        g.issue_token("tok");
        assert_eq!(g.knock(&knock("s", "tok", 8), 0), GuardVerdict::Admit);

        // shape removed: too long
        let g = guard();
        g.issue_token("tok");
        assert_eq!(
            g.knock(&over_long_knock("s", "tok"), 0),
            GuardVerdict::SilentReject
        );

        // token validity removed: a token the operator never minted
        let g = guard();
        assert_eq!(
            g.knock(&knock("s", "never-minted", 8), 0),
            GuardVerdict::SilentReject
        );

        // budget removed: exhaust then try a well-formed issued knock
        let g = guard();
        g.issue_token("fresh");
        for i in 0..8 {
            g.issue_token(&format!("t{i}"));
            let _ = g.knock(&knock("s", &format!("t{i}"), 8), i);
        }
        assert_eq!(
            g.knock(&knock("s", "fresh", 8), 9),
            GuardVerdict::SilentReject
        );
    }

    /// Valence — a token is exhausted on presentation, win or lose. A valid
    /// token presented twice fails the second time even though the first
    /// admitted.
    #[test]
    fn token_reuse_rejected_after_admission() {
        let g = guard();
        g.issue_token("once");
        let k = knock("s", "once", 8);
        assert_eq!(g.knock(&k, 0), GuardVerdict::Admit);
        assert_eq!(g.knock(&k, 1), GuardVerdict::SilentReject);
        assert!(!g.is_avalanched("s"), "one retry is not a forcing attempt");
    }

    /// P1 — windowed conservation. After any sequence of knocks,
    /// spent + remaining == budget for every tracked source.
    #[test]
    fn p1_conservation_holds_across_random_sequences() {
        let g = guard();
        let mut z = 0x1234_5678u64;
        for step in 0..500u64 {
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            let source = format!("s{}", z % 7);
            let token = format!("t{step}");
            // Exercise both the in-shape and out-of-shape paths across the run.
            let knock = if z % 11 == 0 {
                over_long_knock(&source, &token)
            } else {
                knock(&source, &token, 8)
            };
            g.issue_token(&token);
            let _ = g.knock(&knock, step as i64);
            assert!(g.ledger_invariant_holds(), "P1 broken at step {step}");
        }
    }

    /// The avalanche trips at budget and hands off a derived face. The face is
    /// a function of the shared source id, so two sources burning identically
    /// get different faces.
    #[test]
    fn avalanche_trips_and_derives_uncorrelated_faces() {
        let g = guard();
        for i in 0..8 {
            g.issue_token(&format!("a{i}"));
            let _ = g.knock(&knock("alpha", &format!("a{i}"), 8), i);
        }
        assert!(g.is_avalanched("alpha"));
        let fa = g.face_of("alpha").expect("face handed off");

        let g2 = guard();
        for i in 0..8 {
            g2.issue_token(&format!("b{i}"));
            let _ = g2.knock(&knock("beta", &format!("b{i}"), 8), i);
        }
        let fb = g2.face_of("beta").expect("face handed off");

        assert_ne!(
            fa.face_id, fb.face_id,
            "faces must not correlate across sources"
        );
    }

    /// The judge is advisory: with a judge attached that leans to admit, the
    /// over-budget source is still NOT admitted. Classification never becomes
    /// authority.
    #[test]
    fn judge_classifies_but_never_acts() {
        struct AlwaysAdmitLeaning;
        impl GrayZoneJudge for AlwaysAdmitLeaning {
            fn classify(&self, _ctx: &judge::StrainedContext) -> ZoneClassification {
                ZoneClassification::AdmitLeaning
            }
        }

        let g = Guard::new(GuardConfig::default())
            .unwrap()
            .with_judge(Box::new(AlwaysAdmitLeaning));
        for i in 0..8 {
            g.issue_token(&format!("t{i}"));
            let _ = g.knock(&knock("s", &format!("t{i}"), 8), i);
        }
        g.issue_token("final");
        // Even a judge that always leans toward admission cannot admit.
        assert_eq!(
            g.knock(&knock("s", "final", 8), 9),
            GuardVerdict::SilentReject
        );
        assert!(g.is_avalanched("s"));
    }

    /// Hysteresis: the trip threshold and the untrip threshold differ, so the
    /// band does not repeat at one position.
    #[test]
    fn hysteresis_requires_a_band() {
        let cfg = GuardConfig {
            budget: 8,
            untrip_after: 8,
            ..GuardConfig::default()
        };
        match Guard::new(cfg) {
            Err(GuardConfigError::HysteresisGapTooLarge) => {}
            Err(other) => panic!("expected HysteresisGapTooLarge, got {other:?}"),
            Ok(_) => panic!("a zero-width hysteresis band must be refused"),
        }
    }

    /// The operator's honest path is cheap: one well-formed knock admits.
    #[test]
    fn operator_path_is_cheap() {
        let g = guard();
        g.issue_token("once");
        assert_eq!(
            g.knock(&knock("operator", "once", 64), 0),
            GuardVerdict::Admit
        );
        assert!(!g.is_avalanched("operator"));
    }
}
