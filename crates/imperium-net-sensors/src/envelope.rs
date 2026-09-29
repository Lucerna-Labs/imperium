//! Normality envelope: a one-class anomaly sensor trained exclusively on NORMAL
//! network activity.
//!
//! The envelope is the shape of benign behavior learned from a clean
//! corpus — steady mesh chatter, bucket-quantized frame sizes, a handful of
//! endpoints, rare session failures. Probes, snooping, sniffing, and other
//! malicious activity are excluded at THREE layers:
//!
//! 1. **Corpus curation** — the trainer is fed normal-only windows.
//! 2. **Robust trimming** — the fit itself drops windows that score as
//!    statistical outliers against the emerging envelope (pass 1 → trim →
//!    refit), so poisoned records that snuck into the corpus are excluded
//!    anyway.
//! 3. **Cone boundary with margin** — the flag threshold sits 25% beyond the
//!    worst trimmed-training score, so borderline-normal variance never
//!    alerts and genuinely hostile patterns land far outside.
//!
//! The model is static once trained: serialized, SHA-256 digested, swappable
//! (`EnvelopeModel::digest`). It publishes the same `ThreatAssessment`
//! events as the classifier and signature engine, and pulling it out leaves
//! the deterministic floor untouched (THESIS principles 3 and 5).
//!
//! The synthetic corpus builder is a deterministic stand-in for real
//! captures; production models train on operator-supplied captures of known
//! clean traffic with the same feature contract.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use imperium_protocol::BusEvent;
use imperium_protocol::{Message, SuggestedAction, ThreatAssessment, ThreatSource};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spiderweb::BusPublisher;

pub const ENVELOPE_VERSION: u32 = 1;
/// Aggregation window shared by training corpora and the live sensor so the
/// feature semantics match exactly.
pub const WINDOW_SECS: f64 = 10.0;
/// Boundary margin beyond the worst trimmed-training score.
const BOUNDARY_MARGIN: f64 = 1.25;
const FEATURE_BINS: usize = 24;
/// Laplace smoothing so unseen-but-plausible bins never produce -inf.
const LAPLACE: f64 = 1.0;

/// Fixed feature contract. Order is the model's vector layout.
pub const FEATURE_NAMES: [&str; 8] = [
    "events_per_sec",
    "distinct_endpoints",
    "mean_wire_size",
    "wire_size_variance",
    "off_bucket_ratio",
    "session_establishments",
    "failed_session_ratio",
    "mean_interarrival_jitter_ms",
];

pub type FeatureVector = [f64; FEATURE_NAMES.len()];

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("training corpus needs at least {0} windows, got {1}")]
    TooFewWindows(usize, usize),
    #[error("degenerate corpus: feature '{0}' has no spread")]
    DegenerateFeature(String),
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// Fitted per-feature histogram (log-probabilities over fixed bins).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct FeatureHistogram {
    /// Bin edges, len = FEATURE_BINS + 1.
    edges: Vec<f64>,
    log_probs: Vec<f64>,
    /// Smallest smoothed bin mass: the penalty baseline for out-of-range
    /// values, which must score worse than anything the corpus contains.
    floor_logp: f64,
}

/// How far below the smoothed floor an out-of-range value lands.
const OUT_OF_RANGE_PENALTY: f64 = 1.2;

impl FeatureHistogram {
    fn log_prob(&self, value: f64) -> f64 {
        if value < self.edges[0] || value > self.edges[FEATURE_BINS] {
            return self.floor_logp - OUT_OF_RANGE_PENALTY;
        }
        let idx = self.bin_index(value);
        self.log_probs[idx]
    }

    fn bin_index(&self, value: f64) -> usize {
        bin_index(&self.edges, value)
    }
}

fn bin_index(edges: &[f64], value: f64) -> usize {
    // Below the training range clamps to bin 0, above to the last bin:
    // both carry only smoothing mass, so extremes score as far away.
    if value <= edges[0] {
        return 0;
    }
    if value >= edges[FEATURE_BINS] {
        return FEATURE_BINS - 1;
    }
    let mut lo = 0usize;
    let mut hi = FEATURE_BINS;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if value < edges[mid + 1] {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo.min(FEATURE_BINS - 1)
}

/// The trained light cone: per-feature normal-behavior histograms plus the
/// cone boundary. Static, serializable, digestible, swappable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopeModel {
    pub version: u32,
    /// Frame-size buckets considered normal (from the corpus's shape table).
    pub bucket_sizes: Vec<u16>,
    /// Aggregate cone boundary (mean negative log-probability).
    pub boundary: f64,
    /// Per-feature floors: the worst log-probability any trimmed-training
    /// window achieved. A live window below a floor by more than
    /// FLOOR_MARGIN on ANY feature is outside the cone, even when the
    /// aggregate stays low — single-feature attacks cannot hide in the mean.
    floors: Vec<f64>,
    pub trained_windows: usize,
    pub trimmed_windows: usize,
    histograms: Vec<FeatureHistogram>,
}

const FLOOR_MARGIN: f64 = 1.0;

impl EnvelopeModel {
    /// Mean per-feature negative log-probability: the cone distance. Normal
    /// windows sit low; hostile patterns sit far above `boundary`.
    pub fn score(&self, window: &FeatureVector) -> f64 {
        let total: f64 = self
            .histograms
            .iter()
            .zip(window.iter())
            .map(|(h, v)| -h.log_prob(*v))
            .sum();
        total / self.histograms.len() as f64
    }

    /// Per-feature contribution, worst first — the "why" behind a flag.
    pub fn feature_distances(&self, window: &FeatureVector) -> Vec<(String, f64)> {
        let mut out: Vec<(String, f64)> = FEATURE_NAMES
            .iter()
            .zip(self.histograms.iter().zip(window.iter()))
            .map(|(name, (h, v))| (name.to_string(), -h.log_prob(*v)))
            .collect();
        out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        out
    }

    pub fn outside_cone(&self, window: &FeatureVector) -> bool {
        if self.score(window) > self.boundary {
            return true;
        }
        self.histograms
            .iter()
            .zip(window.iter())
            .enumerate()
            .any(|(i, (h, v))| h.log_prob(*v) < self.floors[i] - FLOOR_MARGIN)
    }

    /// Human-readable inspection form. Informational only — JSON float
    /// parsing is not guaranteed bit-exact, so identity and interchange use
    /// the binary codec below.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("envelope model serializes")
    }

    /// Bit-exact canonical encoding (all floats as little-endian bytes).
    /// This — not the JSON form — is the interchange and digest basis.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.bucket_sizes.len() as u64).to_le_bytes());
        for b in &self.bucket_sizes {
            out.extend_from_slice(&b.to_le_bytes());
        }
        out.extend_from_slice(&self.boundary.to_le_bytes());
        out.extend_from_slice(&(self.trained_windows as u64).to_le_bytes());
        out.extend_from_slice(&(self.trimmed_windows as u64).to_le_bytes());
        for f in &self.floors {
            out.extend_from_slice(&f.to_le_bytes());
        }
        for h in &self.histograms {
            out.extend_from_slice(&h.floor_logp.to_le_bytes());
            for e in &h.edges {
                out.extend_from_slice(&e.to_le_bytes());
            }
            for p in &h.log_probs {
                out.extend_from_slice(&p.to_le_bytes());
            }
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let mut cursor = 0usize;
        let take_f64 = |bytes: &[u8], cursor: &mut usize| -> Result<f64, EnvelopeError> {
            if *cursor + 8 > bytes.len() {
                return Err(EnvelopeError::DegenerateFeature(
                    "truncated model".to_string(),
                ));
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[*cursor..*cursor + 8]);
            *cursor += 8;
            Ok(f64::from_le_bytes(buf))
        };
        let corrupt = || EnvelopeError::DegenerateFeature("corrupt model".to_string());

        if bytes.len() < 4 + 8 {
            return Err(corrupt());
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        cursor += 4;
        let bucket_count =
            u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        if bytes.len() < cursor + bucket_count * 2 + 8 * 4 {
            return Err(corrupt());
        }
        let mut bucket_sizes = Vec::with_capacity(bucket_count);
        for _ in 0..bucket_count {
            bucket_sizes.push(u16::from_le_bytes(
                bytes[cursor..cursor + 2].try_into().unwrap(),
            ));
            cursor += 2;
        }
        let boundary = take_f64(bytes, &mut cursor)?;
        let trained_windows =
            u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        let trimmed_windows =
            u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        let mut floors = Vec::with_capacity(FEATURE_NAMES.len());
        for _ in 0..FEATURE_NAMES.len() {
            floors.push(take_f64(bytes, &mut cursor)?);
        }
        let mut histograms = Vec::with_capacity(FEATURE_NAMES.len());
        for _ in 0..FEATURE_NAMES.len() {
            let floor_logp = take_f64(bytes, &mut cursor)?;
            let mut edges = Vec::with_capacity(FEATURE_BINS + 1);
            for _ in 0..=FEATURE_BINS {
                edges.push(take_f64(bytes, &mut cursor)?);
            }
            let mut log_probs = Vec::with_capacity(FEATURE_BINS);
            for _ in 0..FEATURE_BINS {
                log_probs.push(take_f64(bytes, &mut cursor)?);
            }
            histograms.push(FeatureHistogram {
                edges,
                floor_logp,
                log_probs,
            });
        }
        if cursor != bytes.len() {
            return Err(corrupt());
        }
        Ok(EnvelopeModel {
            version,
            bucket_sizes,
            boundary,
            floors,
            trained_windows,
            trimmed_windows,
            histograms,
        })
    }

    /// SHA-256 over the canonical binary encoding — the model's identity
    /// for verification and swap audits.
    pub fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        let out = hasher.finalize();
        out.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Trainer
// ---------------------------------------------------------------------------

pub struct EnvelopeTrainer;

impl EnvelopeTrainer {
    /// Fit a light cone on a normal-only corpus. Two passes: an initial fit,
    /// robust MAD-based trimming of outlier windows (the anti-poisoning
    /// backstop), and a refit on the trimmed set.
    pub fn fit(
        corpus: &[FeatureVector],
        bucket_sizes: Vec<u16>,
    ) -> Result<EnvelopeModel, EnvelopeError> {
        let min_windows = 32;
        if corpus.len() < min_windows {
            return Err(EnvelopeError::TooFewWindows(min_windows, corpus.len()));
        }

        let first = fit_histograms(corpus)?;
        let scores: Vec<f64> = corpus.iter().map(|w| mean_distance(&first, w)).collect();

        // Robust trim via median + k*MAD: unlike a quantile cut, this fences
        // off an arbitrarily large poisoned minority, because median and MAD
        // barely move when less than half the corpus is hostile.
        let cut = robust_cut(&scores);
        let trimmed: Vec<FeatureVector> = corpus
            .iter()
            .zip(scores.iter())
            .filter(|(_, s)| **s <= cut)
            .map(|(w, _)| *w)
            .collect();
        let mut trimmed_count = corpus.len() - trimmed.len();

        // Never trim below half the corpus — a corpus that is majority
        // hostile is a curation bug, not something to fit around.
        let kept: Vec<FeatureVector> = if trimmed.len() < corpus.len() / 2 {
            trimmed_count = 0;
            corpus.to_vec()
        } else {
            trimmed
        };

        let histograms = fit_histograms(&kept)?;
        let floors: Vec<f64> = (0..FEATURE_NAMES.len())
            .map(|i| {
                kept.iter()
                    .map(|w| histograms[i].log_prob(w[i]))
                    .fold(f64::INFINITY, f64::min)
            })
            .collect();
        let worst: f64 = kept
            .iter()
            .map(|w| mean_distance(&histograms, w))
            .fold(0.0f64, f64::max);
        let boundary = (worst * BOUNDARY_MARGIN).max(0.25);

        Ok(EnvelopeModel {
            version: ENVELOPE_VERSION,
            bucket_sizes,
            boundary,
            floors,
            trained_windows: corpus.len(),
            trimmed_windows: trimmed_count,
            histograms,
        })
    }
}

fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// median + 8 * MAD, floored so a tight-but-honest corpus never trims itself.
fn robust_cut(scores: &[f64]) -> f64 {
    let mut sorted = scores.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let med = median(&sorted);
    let mut deviations: Vec<f64> = scores.iter().map(|s| (s - med).abs()).collect();
    deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = median(&deviations);
    if mad < 1e-9 {
        return f64::INFINITY;
    }
    med + 8.0 * mad
}

fn fit_histograms(corpus: &[FeatureVector]) -> Result<Vec<FeatureHistogram>, EnvelopeError> {
    let mut histograms = Vec::with_capacity(FEATURE_NAMES.len());
    for (feature_idx, name) in FEATURE_NAMES.iter().enumerate() {
        let values: Vec<f64> = corpus.iter().map(|w| w[feature_idx]).collect();
        if values.iter().any(|v| v.is_nan()) {
            return Err(EnvelopeError::DegenerateFeature(name.to_string()));
        }
        let min = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        // A constant feature ("normal is ALWAYS on-bucket") is meaningful,
        // not degenerate: widen it into a sharp peak so any deviation lands
        // in smoothed-tail bins and scores far outside the cone.
        let (lo, hi) = if (max - min).abs() < f64::EPSILON {
            let scale = max.abs().max(1.0);
            (min - scale, max + scale)
        } else {
            // Pad the range slightly so min/max land inside, not on the edge.
            let span = (max - min) * 0.01;
            (min - span, max + span)
        };

        let mut edges = Vec::with_capacity(FEATURE_BINS + 1);
        for b in 0..=FEATURE_BINS {
            edges.push(lo + (hi - lo) * b as f64 / FEATURE_BINS as f64);
        }

        let mut counts = vec![0u64; FEATURE_BINS];
        for v in values {
            counts[bin_index(&edges, v)] += 1;
        }

        let total: f64 = counts.iter().sum::<u64>() as f64 + LAPLACE * FEATURE_BINS as f64;
        let log_probs: Vec<f64> = counts
            .iter()
            .map(|c| ((LAPLACE + *c as f64) / total).ln())
            .collect();

        histograms.push(FeatureHistogram {
            edges,
            floor_logp: log_probs.iter().cloned().fold(f64::INFINITY, f64::min),
            log_probs,
        });
    }
    Ok(histograms)
}

fn mean_distance(histograms: &[FeatureHistogram], window: &FeatureVector) -> f64 {
    let total: f64 = histograms
        .iter()
        .zip(window.iter())
        .map(|(h, v)| -h.log_prob(*v))
        .sum();
    total / histograms.len() as f64
}

// ---------------------------------------------------------------------------
// Live sensor
// ---------------------------------------------------------------------------

/// Aggregates raw observations into a window's feature vector. The same
/// aggregation semantics produce the training corpus, so live features and
/// corpus features mean the same thing.
#[derive(Default)]
struct WindowAggregator {
    started_at: Option<Instant>,
    events: u64,
    endpoints: HashSet<String>,
    wire_sizes: Vec<f64>,
    sessions_established: u64,
    sessions_failed: u64,
    jitter_ms: Vec<f64>,
}

impl WindowAggregator {
    fn feature_vector(&self, window: Duration, buckets: &BucketTable) -> FeatureVector {
        let secs = window.as_secs_f64().max(WINDOW_SECS);
        let (mean_size, var_size) = mean_variance(&self.wire_sizes);
        let off_bucket = if self.wire_sizes.is_empty() {
            0.0
        } else {
            self.wire_sizes
                .iter()
                .filter(|s| !buckets.contains(**s as u16))
                .count() as f64
                / self.wire_sizes.len() as f64
        };
        let failed_ratio = if self.sessions_established + self.sessions_failed == 0 {
            0.0
        } else {
            self.sessions_failed as f64 / (self.sessions_established + self.sessions_failed) as f64
        };
        let (mean_jitter, _) = mean_variance(&self.jitter_ms);

        [
            self.events as f64 / secs,
            self.endpoints.len() as f64,
            mean_size,
            var_size,
            off_bucket,
            self.sessions_established as f64,
            failed_ratio,
            mean_jitter,
        ]
    }

    fn reset(&mut self) {
        *self = WindowAggregator::default();
    }
}

/// The model's notion of normal frame shapes; off-table sizes are a probe
/// tell.
struct BucketTable(Vec<u16>);

impl BucketTable {
    fn contains(&self, size: u16) -> bool {
        self.0.contains(&size)
    }
}

pub struct EnvelopeSensor {
    model: Arc<EnvelopeModel>,
    buckets: BucketTable,
    bus: Arc<BusPublisher>,
    window: RwLock<WindowAggregator>,
}

impl EnvelopeSensor {
    pub fn new(model: EnvelopeModel, bus: Arc<BusPublisher>) -> Self {
        let buckets = BucketTable(model.bucket_sizes.clone());
        Self {
            model: Arc::new(model),
            buckets,
            bus,
            window: RwLock::new(WindowAggregator::default()),
        }
    }

    pub fn model_digest(&self) -> String {
        self.model.digest()
    }

    pub fn observe_mesh_event(&self, endpoint: impl Into<String>) {
        let mut w = self.window.write();
        if w.started_at.is_none() {
            w.started_at = Some(Instant::now());
        }
        w.events += 1;
        w.endpoints.insert(endpoint.into());
    }

    pub fn observe_wire_frame(&self, size: u16) {
        let mut w = self.window.write();
        w.events += 1;
        w.wire_sizes.push(f64::from(size));
    }

    pub fn observe_session_established(&self) {
        let mut w = self.window.write();
        w.events += 1;
        w.sessions_established += 1;
    }

    pub fn observe_session_failed(&self) {
        let mut w = self.window.write();
        w.events += 1;
        w.sessions_failed += 1;
    }

    pub fn observe_jitter(&self, ms: f64) {
        self.window.write().jitter_ms.push(ms);
    }

    /// Close the current window: compute its feature vector, score it against
    /// the cone, publish a ThreatAssessment when it lands outside, and start
    /// a fresh window. Returns the assessment when one was published.
    pub fn evaluate_window(&self) -> Result<Option<ThreatAssessment>, EnvelopeError> {
        let vector = {
            let mut w = self.window.write();
            let vector = w.feature_vector(
                w.started_at.map(|t| t.elapsed()).unwrap_or_default(),
                &self.buckets,
            );
            w.reset();
            vector
        };

        if vector[0] == 0.0 && vector[5] == 0.0 {
            // Nothing observed; nothing to say.
            return Ok(None);
        }

        if !self.model.outside_cone(&vector) {
            return Ok(None);
        }

        let score = self.model.score(&vector);
        let severity = ((score - self.model.boundary) / self.model.boundary).clamp(0.0, 1.0);
        let confidence = 0.5 + 0.5 * severity;

        let worst: Vec<String> = self
            .model
            .feature_distances(&vector)
            .into_iter()
            .take(3)
            .map(|(name, distance)| format!("{name} ({distance:.2})"))
            .collect();

        let suggested_action = if confidence > 0.8 {
            SuggestedAction::ActivateStrainer {
                strainer_name: "probe_response".into(),
            }
        } else {
            SuggestedAction::IncreaseMonitoring
        };

        let assessment = ThreatAssessment {
            source: ThreatSource::Heuristic {
                name: format!("envelope-v{}", self.model.version),
            },
            confidence,
            description: format!(
                "activity outside the normality envelope: {}",
                worst.join(", ")
            ),
            remote_addr: None,
            timestamp: Utc::now(),
            suggested_action,
        };

        BusEvent::publish(
            &self.bus,
            "net.sensors.threat",
            Message::ThreatAssessment(assessment.clone()),
        )?;

        Ok(Some(assessment))
    }
}

fn mean_variance(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / values.len() as f64;
    (mean, var)
}

// ---------------------------------------------------------------------------
// Deterministic synthetic corpora (stand-ins for real captures)
// ---------------------------------------------------------------------------

const NORMAL_BUCKETS: [u16; 4] = [64, 256, 768, 1200];

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1);
    *state
}

fn uniform(state: &mut u64, lo: f64, hi: f64) -> f64 {
    let v = (lcg(state) >> 11) as f64 / (1u64 << 53) as f64;
    lo + v * (hi - lo)
}

/// A deterministic corpus of NORMAL windows: steady mesh chatter, bucketed
/// frame sizes, few endpoints, rare session failures, mild jitter. Hostile
/// patterns are never generated here.
pub fn synthetic_normal_windows(seed: u64, count: usize) -> Vec<FeatureVector> {
    let mut state = seed;
    (0..count)
        .map(|_| {
            let sizes: Vec<f64> = (0..(8 + lcg(&mut state) % 24))
                .map(|_| {
                    let pick = lcg(&mut state) % 100;
                    let bucket = if pick < 45 {
                        NORMAL_BUCKETS[0]
                    } else if pick < 75 {
                        NORMAL_BUCKETS[1]
                    } else if pick < 92 {
                        NORMAL_BUCKETS[2]
                    } else {
                        NORMAL_BUCKETS[3]
                    };
                    f64::from(bucket)
                })
                .collect();
            let (mean_size, var_size) = mean_variance(&sizes);
            // Rare benign off-bucket frames (retransmits, oversized control).
            let off_bucket = if lcg(&mut state) % 40 == 0 {
                uniform(&mut state, 0.005, 0.03)
            } else {
                0.0
            };
            let established = lcg(&mut state) % 3;
            let failed = if lcg(&mut state) % 12 == 0 { 1 } else { 0 };
            [
                uniform(&mut state, 8.0, 26.0),
                (2 + lcg(&mut state) % 6) as f64,
                mean_size,
                var_size,
                off_bucket,
                established as f64,
                if established + failed == 0 {
                    0.0
                } else {
                    failed as f64 / (established + failed) as f64
                },
                uniform(&mut state, 1.0, 16.0),
            ]
        })
        .collect()
}

/// Hostile pattern: probe burst — high rate, raw unbucketed sizes, wild
/// variance, many endpoints.
pub fn adversarial_probe_burst(seed: u64) -> FeatureVector {
    let mut state = seed;
    [
        uniform(&mut state, 120.0, 300.0),
        (20 + lcg(&mut state) % 30) as f64,
        uniform(&mut state, 40.0, 1400.0),
        uniform(&mut state, 90_000.0, 260_000.0),
        uniform(&mut state, 0.35, 0.8),
        uniform(&mut state, 0.0, 1.0),
        uniform(&mut state, 0.1, 0.4),
        uniform(&mut state, 0.1, 4.0),
    ]
}

/// Hostile pattern: fan-out scan / snooping sweep — endpoint explosion.
pub fn adversarial_scan_fanout(seed: u64) -> FeatureVector {
    let mut state = seed;
    let base = synthetic_normal_windows(seed, 1).remove(0);
    let mut out = base;
    out[1] = (40 + lcg(&mut state) % 80) as f64;
    out[0] = uniform(&mut state, 40.0, 90.0);
    out
}

/// Hostile pattern: volume anomaly — bulk transfer masquerading as mesh
/// chatter.
pub fn adversarial_volume_anomaly(seed: u64) -> FeatureVector {
    let mut state = seed;
    let base = synthetic_normal_windows(seed, 1).remove(0);
    let mut out = base;
    out[2] = uniform(&mut state, 1_380.0, 1_490.0);
    out[3] = uniform(&mut state, 20_000.0, 60_000.0);
    out[4] = uniform(&mut state, 0.5, 0.9);
    out
}

/// Hostile pattern: session probing — repeated failed handshakes.
pub fn adversarial_session_probe(seed: u64) -> FeatureVector {
    let mut state = seed;
    let base = synthetic_normal_windows(seed, 1).remove(0);
    let mut out = base;
    out[5] = uniform(&mut state, 30.0, 90.0);
    out[6] = uniform(&mut state, 0.55, 0.95);
    out[0] = uniform(&mut state, 60.0, 140.0);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trained() -> EnvelopeModel {
        EnvelopeTrainer::fit(
            &synthetic_normal_windows(0xC0FFEE, 400),
            NORMAL_BUCKETS.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn model_is_deterministic_and_serializable() {
        let a = EnvelopeTrainer::fit(&synthetic_normal_windows(7, 64), NORMAL_BUCKETS.to_vec())
            .unwrap();
        let b = EnvelopeTrainer::fit(&synthetic_normal_windows(7, 64), NORMAL_BUCKETS.to_vec())
            .unwrap();
        assert_eq!(a.digest(), b.digest(), "same corpus must give same digest");

        // Binary codec is bit-exact: round-trip preserves identity.
        let round = EnvelopeModel::from_bytes(&a.to_bytes()).unwrap();
        assert_eq!(round.digest(), a.digest());
        assert_eq!(round.boundary, a.boundary);
        assert_eq!(round.to_bytes(), a.to_bytes());

        // Truncated/corrupt models fail closed.
        let bytes = a.to_bytes();
        assert!(EnvelopeModel::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(EnvelopeModel::from_bytes(&[]).is_err());
    }

    #[test]
    fn held_out_normal_windows_stay_inside_the_cone() {
        let model = trained();
        let held_out = synthetic_normal_windows(0x5EED, 200);
        let outside = held_out.iter().filter(|w| model.outside_cone(w)).count();
        // Robustness requirement: the normal pass rate is high. A couple of
        // borderline windows out of 200 is acceptable noise; more is not.
        assert!(
            outside <= held_out.len() / 20,
            "{outside} of {} held-out normal windows flagged",
            held_out.len()
        );
    }

    #[test]
    fn adversarial_patterns_land_outside_the_cone() {
        let model = trained();
        for seed in [1u64, 42, 999] {
            for (name, window) in [
                ("probe_burst", adversarial_probe_burst(seed)),
                ("scan_fanout", adversarial_scan_fanout(seed)),
                ("volume_anomaly", adversarial_volume_anomaly(seed)),
                ("session_probe", adversarial_session_probe(seed)),
            ] {
                assert!(
                    model.outside_cone(&window),
                    "{name} (seed {seed}) slipped inside the cone"
                );
            }
        }
    }

    #[test]
    fn poisoned_training_data_is_trimmed_and_still_flagged() {
        // A clean corpus with 10% probe-burst records snuck in.
        let mut corpus = synthetic_normal_windows(0xBEEF, 360);
        for i in 0..36 {
            corpus[i] = adversarial_probe_burst(i as u64 + 1);
        }
        let model = EnvelopeTrainer::fit(&corpus, NORMAL_BUCKETS.to_vec()).unwrap();

        assert!(
            model.trimmed_windows >= 16,
            "expected the poisoned windows to be trimmed ({} trimmed)",
            model.trimmed_windows
        );
        assert!(model.outside_cone(&adversarial_probe_burst(77)));
    }

    #[test]
    fn sensor_publishes_threat_for_probe_traffic_only() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mut sub = crate::test_supervision::subscribe_queue(&bus, "net.sensors.threat", 64);
        let sensor = EnvelopeSensor::new(trained(), Arc::clone(&bus));
        let _ = sensor.model_digest();

        // A normal window: quiet evaluation, no publication.
        for i in 0..120 {
            sensor.observe_mesh_event(format!("10.0.0.{}", i % 5));
        }
        for i in 0..18 {
            sensor.observe_wire_frame(NORMAL_BUCKETS[i % 3]);
        }
        sensor.observe_session_established();
        for ms in [2.0, 5.0, 9.0, 3.0] {
            sensor.observe_jitter(ms);
        }
        assert!(sensor.evaluate_window().unwrap().is_none());

        // A probe burst: many events, raw sizes far off the bucket table.
        for i in 0..2400 {
            sensor.observe_mesh_event(format!("198.51.100.{}", i % 40));
        }
        for i in 0..600 {
            sensor.observe_wire_frame((40 + (i * 37) % 1400) as u16);
        }
        for _ in 0..40 {
            sensor.observe_session_failed();
        }
        let assessment = sensor
            .evaluate_window()
            .unwrap()
            .expect("probe burst flagged");
        assert!(assessment.confidence > 0.5);
        assert!(assessment
            .description
            .contains("outside the normality envelope"));

        let event = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { tokio::time::timeout(Duration::from_millis(100), sub.recv()).await })
            .unwrap()
            .unwrap();
        assert!(matches!(event.message, Message::ThreatAssessment { .. }));
    }

    #[test]
    fn constant_features_become_point_masses() {
        // "Normal is always on-bucket" must fit, not error — and any real
        // off-bucket value must then score far outside the cone.
        let mut corpus = synthetic_normal_windows(3, 40);
        for w in &mut corpus {
            w[4] = 0.0;
        }
        let model = EnvelopeTrainer::fit(&corpus, NORMAL_BUCKETS.to_vec()).unwrap();
        let mut probe = corpus[0];
        probe[4] = 0.5;
        assert!(model.outside_cone(&probe));
    }

    #[test]
    fn trainer_rejects_nan_and_tiny_corpora() {
        let mut corpus = synthetic_normal_windows(5, 40);
        corpus[0][2] = f64::NAN;
        assert!(EnvelopeTrainer::fit(&corpus, NORMAL_BUCKETS.to_vec()).is_err());
        assert!(EnvelopeTrainer::fit(&[], NORMAL_BUCKETS.to_vec()).is_err());
    }
}
