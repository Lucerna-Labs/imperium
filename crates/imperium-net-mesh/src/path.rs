use chrono::Utc;
use imperium_protocol::{PathMetrics, PathSelection};

#[derive(Clone, Debug)]
pub struct PathScoreWeights {
    pub rtt: f64,
    pub jitter: f64,
    pub loss: f64,
    pub burn: f64,
    pub handshake_failure: f64,
    pub relay_penalty: f64,
}

impl Default for PathScoreWeights {
    fn default() -> Self {
        Self {
            rtt: 1.0,
            jitter: 1.5,
            loss: 2.0,
            burn: 100.0,
            handshake_failure: 0.02,
            relay_penalty: 50.0,
        }
    }
}

pub struct PathManager {
    weights: PathScoreWeights,
}

impl PathManager {
    pub fn new(weights: PathScoreWeights) -> Self {
        Self { weights }
    }

    pub fn select_best(&self, candidates: &[PathMetrics]) -> Option<PathSelection> {
        candidates
            .iter()
            .map(|metrics| (self.score(metrics), metrics))
            .min_by(|(left, _), (right, _)| left.total_cmp(right))
            .map(|(score, metrics)| PathSelection {
                selected_path_id: metrics.path_id.clone(),
                score,
                reason: format!(
                    "rtt={}ms jitter={}ms loss={}ppm burn={:.2}",
                    metrics.rtt_ms, metrics.jitter_ms, metrics.loss_ppm, metrics.burn_score
                ),
                selected_at: Utc::now(),
            })
    }

    pub fn score(&self, metrics: &PathMetrics) -> f64 {
        let handshake_failure_ppm = 1_000_000u32.saturating_sub(metrics.handshake_success_ppm);
        let relay_penalty = if metrics.relay_required {
            self.weights.relay_penalty
        } else {
            0.0
        };

        metrics.rtt_ms as f64 * self.weights.rtt
            + metrics.jitter_ms as f64 * self.weights.jitter
            + metrics.loss_ppm as f64 * self.weights.loss / 1_000.0
            + metrics.burn_score * self.weights.burn
            + handshake_failure_ppm as f64 * self.weights.handshake_failure / 1_000.0
            + relay_penalty
    }
}

impl Default for PathManager {
    fn default() -> Self {
        Self::new(PathScoreWeights::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(path_id: &str, rtt_ms: u64, loss_ppm: u32, burn_score: f64) -> PathMetrics {
        PathMetrics {
            path_id: path_id.to_string(),
            rtt_ms,
            jitter_ms: 3,
            loss_ppm,
            burn_score,
            handshake_success_ppm: 990_000,
            relay_required: false,
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn selects_lowest_deterministic_score() {
        let manager = PathManager::default();
        let selected = manager
            .select_best(&[
                metrics("fast_burned", 10, 0, 0.9),
                metrics("stable", 30, 50, 0.0),
            ])
            .unwrap();

        assert_eq!(selected.selected_path_id, "stable");
    }
}
