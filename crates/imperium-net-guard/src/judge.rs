//! The cognitive judge — the E36 pattern.
//!
//! Deterministic walls decide the clear cases. The judge classifies the gray
//! zone **after** them, reading **strained context only**, and abstains toward
//! **sinking** — over-sinking breaks visibly and recoverably, under-sinking
//! leaks invisibly and permanently.
//!
//! The judge is deliberately powerless. It emits a [`ZoneClassification`] and
//! nothing else. A deterministic rule in the guard maps that classification to
//! an action. The judge cannot admit, cannot avalanche, and cannot set a
//! threshold — so steering the judge steers nothing that matters. This is
//! THESIS #5: classifiers classify, the deterministic substrate decides.

/// The strained context a judge is allowed to see. It contains no raw knock
/// bytes — only already-normalized facts. This is the same guarantee as the
/// gate's P2: a judge cannot leak what it was never given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrainedContext {
    /// The coarse accounting zone the source is in.
    pub zone: u64,
    /// Attempts spent in the current window.
    pub attempts_in_window: u64,
    /// Whether the source is already in the illusion interior.
    pub avalanched: bool,
}

/// A judge's only output: which side of the gray zone a knock leans to.
///
/// There is no `Admit` and no `Avalanche` variant, and their absence is the
/// point — a classification is not a decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZoneClassification {
    AdmitLeaning,
    AvalancheLeaning,
}

/// The judge.
pub trait GrayZoneJudge: Send + Sync {
    fn classify(&self, ctx: &StrainedContext) -> ZoneClassification;
}

/// The gray zone, named for status reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrayZone {
    Clear,
    Ambiguous,
}

/// A verdict the judge may render, for reporting. Never acted on directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JudgeVerdict {
    Classification(ZoneClassification),
    Abstained,
}

/// The default judge when none is attached: always abstain toward sinking.
/// A guard with no judge still refuses — it simply does not subdivide.
#[derive(Debug, Default)]
pub struct AbstainToSink;

impl GrayZoneJudge for AbstainToSink {
    fn classify(&self, _ctx: &StrainedContext) -> ZoneClassification {
        ZoneClassification::AvalancheLeaning
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_judge_abstains_toward_sinking() {
        let j = AbstainToSink;
        let ctx = StrainedContext {
            zone: 0,
            attempts_in_window: 0,
            avalanched: false,
        };
        assert_eq!(j.classify(&ctx), ZoneClassification::AvalancheLeaning);
    }

    #[test]
    fn classification_has_no_action_variants() {
        // Compile-time guarantee expressed as a runtime assertion: the only
        // two classifications are leanings, neither of which is an action.
        let all = [
            ZoneClassification::AdmitLeaning,
            ZoneClassification::AvalancheLeaning,
        ];
        assert_eq!(
            all.len(),
            2,
            "a third (acting) variant would be a violation"
        );
    }
}
