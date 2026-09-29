//! The probe-behaviour sensor: *what a prober is doing*, per source, as a set of
//! separate readings.
//!
//! A stack that reacts to a probe must first be *affected by the behaviour of
//! the probe*. This is that first component. It watches probe traffic — who,
//! when, and which shape — and characterises the shape of the probing itself.
//! Its output feeds a later responder stack, which changes its behaviour
//! according to *what the probe is doing*.
//!
//! # It is a sensor, not a judge
//!
//! This module never scores, ranks, decides, blocks, or emits a verdict. It
//! produces observations, and the observations are deliberately plural:
//!
//! | Dimension | Moves when |
//! |---|---|
//! | [`ProbeProfile::rhythm_pe`] | the *arrangement* of the cadence changes (metronome ↔ organic) |
//! | [`ProbeProfile::drift`] | the *trend* of the cadence changes (steady ↔ smoothly accelerating) |
//! | [`ProbeProfile::repeat_ratio`] | the prober re-uses shapes it has already sent |
//! | [`ProbeProfile::exploration`] | the prober widens or narrows its coverage |
//! | [`ProbeProfile::convergence`] | the shape distribution settles or keeps changing |
//! | [`ProbeProfile::rate_per_sec`] | the prober's budget burn rate changes |
//!
//! There is no scalar that combines the six, and there must not be one. The
//! anti-collapse law of this project — *"statistical envelope SCORES ... are
//! separate epistemic classes and are never fused into one number"*
//! (`crates/imperium-net-sensors/src/fusion.rs:31-35`), restated for the
//! spider's gate as *"deliberately no scalar 'score' variant — that would
//! violate the anti-collapse law"*
//! (`crates/imperium-net-toolkit/CLAMAV-SENSOR.md:192-195`) — applies to
//! readings exactly as it applies to verdicts. A fused score would also be
//! *useless* to the responder: a stack that reacts to probing has to react to
//! **which** dimension moved (a beacon that is metronomic needs a different
//! response from a sweeper that is burning its budget, even if both "score"
//! 0.8). `no_single_weighting_holds_all_readings` in the tests is the gate that
//! proves the columns are load-bearing rather than decorative: for every
//! non-negative weighting of the six dimensions, at least one of the readings
//! the responder needs is lost.
//!
//! # `drift` exists because `rhythm_pe` cannot see a trend
//!
//! [`ProbeProfile::rhythm_pe`] and [`ProbeProfile::drift`] are deliberately
//! separate readings of the *same* gap series, and a consumer must consult
//! **both**:
//!
//! * `rhythm_pe` reads **arrangement** — how the gaps are ordered relative to
//!   each other. It is a permutation entropy over triples of consecutive gaps,
//!   so a prober whose gaps rise smoothly (2000, 2016, 2032, …) presents the
//!   same ordinal pattern on every triple and reads **exactly** as a perfect
//!   metronome (`0.0000`), despite 64 distinct gap values. That blind spot is
//!   pinned by `rhythm_is_blind_to_a_smoothly_drifting_cadence`.
//! * `drift` reads **trend** — how the gaps move in magnitude across the
//!   window. The same ramp reads ≈`0.40`; a metronome with the same mean gap
//!   reads exactly `0.0`.
//!
//! Neither substitutes for the other, and the two are never fused into one
//! number: "smoothly accelerating prober" is `rhythm_pe ≈ 0` **and** `drift`
//! high, and a consumer that reads only one of the columns gets it wrong. The
//! separation is exact rather than approximate, in both directions: a zigzag and
//! a ramp carrying the same zigzag tick read the *same* `rhythm_pe` (0.3869 in
//! both) while their `drift` differs by more than 5×; and a monotone ramp and
//! that same ramp with the tick added read the *same* `drift` (0.4026 vs
//! 0.4010) while their `rhythm_pe` differs completely (0.0000 vs 0.3869).
//! Arrangement and trend are orthogonal on these sequences, so trend was added
//! as a sixth dimension rather than folded into `rhythm_pe` — fusing them would
//! be exactly the anti-collapse violation this module forbids everywhere else.
//!
//! # Bounded per source
//!
//! The prober's traffic must never grow our memory. Each source gets one
//! fixed-size [`SourceRecord`] — no `Vec`, no `HashMap`, no `String` inside —
//! and the source map is capped at [`ProbeSensorConfig::max_sources`], so the
//! recorded state is at most `max_sources × size_of::<SourceRecord>()` (with the
//! map's own per-entry bookkeeping, itself bounded by the same cap) no matter
//! how much traffic arrives (`flood_does_not_grow_the_footprint` asserts it).
//! This is the catalysis lesson applied: a guard's ledger has to be fixed-size,
//! because the attacker writes to it.
//!
//! Eviction is **TTL, not LRU**. A source that has stopped probing is the
//! right thing to forget; a source that is *still* probing should keep its
//! history even if it probes rarely. LRU would evict exactly the wrong way
//! round: a burst flooder would push out a low-and-slow prober whose whole
//! signal *is* its slowness. TTL also keeps the eviction decision a pure
//! function of the event timestamps (no wall clock, no counter of our own), so
//! determinism survives. When the map is full and nothing has expired, the
//! stalest record (oldest `last_seen`, ties broken by address so the choice is
//! total-ordered) is dropped to make room.
//!
//! # Passive
//!
//! [`ProbeSensor::observe`] records and returns nothing. It cannot fail, it
//! cannot publish, and it never touches the probe path. One source's events
//! cannot change another source's reading
//! (`interleaving_sources_does_not_change_their_profiles` asserts that): there
//! is no shared accumulator, no global normalisation, no cross-source coupling.
//!
//! # Deterministic
//!
//! Given the same event sequence, the sensor produces bit-for-bit identical
//! profiles. It never reads a clock (the caller supplies the timestamps), never
//! uses a random number generator, never iterates a hash map in a way that
//! reaches its output, and never divides by a quantity whose order depends on
//! it. `same_events_give_bit_identical_profiles` asserts this.
//!
//! # The rhythm dimensions are E30's chaos organ, ported, plus its trend twin
//!
//! `permutation_entropy` below is a faithful port of the instrument from Jesse's
//! E30 experiment — `quantum-network/experiments/e30_chaos.rs`, the commit
//! "E30: the chaos organ — rhythm as a second sensor dimension" — where it was
//! calibrated as: periodic `0.000`, organic `0.967`, jittered beacon (±20%)
//! `0.329`, zigzag (alternating gaps) `0.387`, burst-pause scan `0.325`. Those
//! five anchors are the sensor's gate (`e30_anchors_reproduce_through_the_sensor`),
//! and they are reproduced by using E30's own synthetic sequences and its own
//! arithmetic (same operations, same order, on the same `u64` gaps), not by
//! tuning a different estimator until the numbers look similar.
//!
//! `gap_drift` is not a port: it is the dimension E30's organ was found to be
//! missing. It is plain least squares over the same gap series, kept separate
//! from the entropy *because* the two read different properties of it.
//!
//! # What this sensor does not do
//!
//! * It does not read payloads. A probe's "shape" is an opaque `u64` the caller
//!   supplies ([`probe_shape_fingerprint`] is a convenience for making one); the
//!   sensor only tests equality on it, so it can characterise *repetition*
//!   without ever parsing content.
//! * It does not normalise source identity: `10.0.0.5:41022` and
//!   `10.0.0.5:41023` are two sources. The calling stack chooses the granularity
//!   it wants to characterise.
//! * It does not claim certainty. Every dimension that can be reported before it
//!   is measurable is reported as `0.0` and flagged through
//!   [`ProbeProfile::sufficiency`]: `rhythm_pe` needs
//!   [`MIN_GAPS_FOR_PE`] gaps, `convergence` needs two completed
//!   [`EPOCH_PROBES`]-probe epochs. A consumer **must** read the sufficiency
//!   block before reading a `0.0` as "measured flat" — the honest failure mode
//!   is under-claiming, never over-claiming.
//!
//! Known limits, stated rather than hidden:
//!
//! * A prober that spoofs source addresses can churn the source map, evicting
//!   quiet sources. The map stays bounded (which is the point), but a responder
//!   must not read "no profile" as "not a prober".
//! * `repeat_ratio`'s memory is bounded to the last
//!   [`SHAPE_MEMORY`] first-seen shapes, so a probe shape that a source used
//!   more than that many *distinct* shapes ago is treated as new. The horizon is
//!   the price of the fixed-size record.
//! * `rhythm_pe` is computed over at most [`PROBE_WINDOW`] gaps. Below
//!   [`MIN_GAPS_FOR_PE`] it is not reported as a measurement at all, so a `0.0`
//!   there means "no reading yet", not "metronome". `drift` has a different
//!   floor — two gaps — and its own thin-window caveat, recorded below.
//! * `drift` is a **magnitude, not a direction**. A prober smoothly
//!   accelerating and one smoothly decelerating over the same relative span
//!   read the same value (`drift` is deliberately unsigned, so the two
//!   directions cannot be told apart). This is a *known remaining gap*, not an
//!   oversight: direction would be the next **separate** dimension — a signed
//!   trend reading — because smuggling a sign into this column would fuse "how
//!   much" with "which way", the same collapse the anti-collapse law forbids
//!   everywhere else. `drift_is_a_magnitude_and_does_not_capture_direction`
//!   pins the current behaviour so that a later signed dimension is added
//!   *beside* this one rather than in place of it.
//! * `drift` is defined from two gaps upward (the least-squares slope of two
//!   points always exists), unlike `rhythm_pe`, which needs
//!   [`MIN_GAPS_FOR_PE`]. A thin window's `drift` is a real reading of very
//!   little evidence — a gap that triples across a two-gap window reads `1.0`
//!   — so a consumer must read [`ProbeSufficiency::gaps_in_window`] before
//!   acting on it. The `0.0`-means-unmeasurable contract is preserved by
//!   saying this rather than by suppressing the reading.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use imperium_protocol::BusEvent;
use imperium_protocol::{Message, ProbeProfile, ProbeSufficiency};
use parking_lot::RwLock;
use spiderweb::BusPublisher;
use thiserror::Error;

/// Bus topic this sensor publishes [`Message::ProbeProfile`] on.
///
/// `net.sensors.*` is the established sensor namespace and the dynamic segment
/// (the kind of profile) comes last, so the existing `net.sensors.` prefix
/// subscriptions — the transport orchestrator among them — receive it while the
/// `net.sensors.threat` lane stays what it was (`BUS_CONVENTIONS.md`,
/// rules 1 and 5).
pub const PROBE_PROFILE_TOPIC: &str = "net.sensors.probe_profile";

/// Probes retained per source in the sliding windows (gaps and shapes).
///
/// 64 gaps is the depth the E30 anchors were computed at, so a source that has
/// sent 65 probes is measured over exactly the sequence E30 measured.
pub const PROBE_WINDOW: usize = 64;

/// Probes per convergence epoch. Two completed epochs are compared, so
/// `convergence` becomes measurable at `2 × EPOCH_PROBES` probes.
pub const EPOCH_PROBES: usize = 32;

/// Bounded shape memory per source: the most recent *distinct* shapes this
/// source has sent. A probe whose shape is still in that memory is a repeat.
///
/// This is what makes `repeat_ratio` a different reading from `exploration`
/// rather than its mirror image: the memory outlives the window (a source that
/// cycles back to a shape it used 100 distinct shapes ago is repeating, even
/// though every shape in the current window is distinct).
pub const SHAPE_MEMORY: usize = 64;

/// Minimum gaps before permutation entropy is reported as a measurement.
///
/// E30's `current_pe` refuses to answer below 16 gaps; the same floor is used
/// here so the anchors stay comparable, and so a `rhythm_pe` of `0.0` is never
/// claimed on a handful of samples.
pub const MIN_GAPS_FOR_PE: usize = 16;

/// Default cap on tracked sources. 128 records of ~2.4 KiB is a fixed ceiling of
/// roughly 300 KiB for the whole sensor, whatever the attacker sends.
pub const DEFAULT_MAX_SOURCES: usize = 128;

/// Default idle time after which a source may be forgotten (5 minutes, in the
/// caller's microsecond clock).
pub const DEFAULT_SOURCE_TTL_MICROS: u64 = 300_000_000;

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

/// One observed probe: the three facts a passive observer can honestly supply.
///
/// The sensor never sees payloads, so "shape" is an identity the caller derived.
/// Use [`probe_shape_fingerprint`] if you need a stable one from bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeEvent {
    /// Who probed. Granularity is the caller's choice (see
    /// [`ProbeProfile::source`]).
    pub source: SocketAddr,
    /// When, on the caller's monotonic microsecond clock. The sensor never reads
    /// a clock of its own, so this — and only this — is what orders events.
    ///
    /// Timestamps must be non-decreasing per source; a probe that arrives with
    /// an earlier timestamp than its predecessor yields a gap of `0`
    /// (saturating subtraction), which is deterministic but not meaningful, so
    /// callers should feed a monotonic clock.
    pub at_micros: u64,
    /// Which shape. Opaque: the sensor tests equality and remembers the value,
    /// nothing else.
    pub shape: u64,
}

/// Sensor configuration. Both limits are hard bounds, not hints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeSensorConfig {
    /// Maximum sources tracked at once. `0` disables tracking entirely (events
    /// are ignored) rather than growing the map.
    pub max_sources: usize,
    /// Idle time (in the event clock's microseconds) after which a source's
    /// record may be evicted by [`ProbeSensor::prune_expired`] or by the
    /// capacity pressure path.
    pub source_ttl_micros: u64,
}

impl Default for ProbeSensorConfig {
    fn default() -> Self {
        Self {
            max_sources: DEFAULT_MAX_SOURCES,
            source_ttl_micros: DEFAULT_SOURCE_TTL_MICROS,
        }
    }
}

/// Failure modes of the publishing half of the sensor. Observation itself
/// cannot fail.
#[derive(Debug, Error)]
pub enum ProbeSensorError {
    #[error("bus error: {0}")]
    Bus(#[from] spiderweb::BusError),
}

// ---------------------------------------------------------------------------
// The E30 estimator, ported
// ---------------------------------------------------------------------------

/// Position-stable ordinal pattern of three consecutive gaps.
///
/// Ported verbatim from E30 (`quantum-network/experiments/e30_chaos.rs`):
/// ties are broken by position, per the atom-writer tie rule, so identical
/// values cannot manufacture false diversity. This is why a metronome reads
/// `0.0` exactly rather than "almost flat": every window collapses onto one
/// pattern.
fn ordinal_pattern(a: u64, b: u64, c: u64) -> usize {
    let mut sorted = [(a, 0usize), (b, 1), (c, 2)];
    sorted.sort_unstable_by_key(|&(value, position)| (value, position));
    let mut ranks = [0usize; 3];
    for (rank, &(_, position)) in sorted.iter().enumerate() {
        ranks[position] = rank;
    }
    ranks[0] * 2 + usize::from(ranks[1] > ranks[2])
}

/// Bandt-Pompe permutation entropy, order 3, normalised to `[0, 1]`.
///
/// Ported verbatim from E30 (see the module docs). `0.0` = every gap triple has
/// the same ordinal pattern (a metronome, or a fixed burst cadence), `1.0` =
/// the six patterns are uniformly represented.
fn permutation_entropy(series: &[u64]) -> f64 {
    if series.len() < 3 {
        return 0.0;
    }
    let mut counts = [0usize; 6];
    for window in series.windows(3) {
        counts[ordinal_pattern(window[0], window[1], window[2])] += 1;
    }
    let total = (series.len() - 2) as f64;
    let mut bits = 0.0;
    for count in counts {
        if count > 0 {
            let p = count as f64 / total;
            bits -= p * p.log2();
        }
    }
    bits / 6.0f64.log2()
}

/// Magnitude of the smooth change in cadence across the window: the **trend**
/// reading of the gap series.
///
/// Defined as the total relative change in gap over the window,
/// `|slope × (n − 1)| / mean_gap`, where `slope` is the least-squares linear
/// slope of the gaps against their index and `slope × (n − 1)` is the change the
/// fit describes from the first probe to the last.
///
/// The reading is directly interpretable: **`0.0` = the cadence is steady across
/// the window; the reading saturates at `1.0` once the cadence has travelled the
/// whole mean gap.** For a smooth ramp that is a gap which has *tripled* (or
/// fallen to a third) — `g → 2g` reads `2/3`, `g → 3g` reads exactly `1.0`, and
/// a steeper ramp clamps to `1.0` as well, so `1.0` is "at least this much, not
/// more". A metronome reads exactly `0.0`.
///
/// Deliberately separate from [`permutation_entropy`], which reads the
/// *arrangement* of the same series and cannot see a monotone ramp at all (see
/// the module docs). Plain `f64` least squares on the indices — no smoothing,
/// no windowing, no randomness — so the same gaps always give the same value.
///
/// `0.0` when fewer than two gaps are in the window (no slope exists) or when
/// the mean gap is zero (no *relative* change is definable). The result is
/// clamped to `[0, 1]`, so the declared range holds for any floating-point
/// input.
fn gap_drift(series: &[u64]) -> f64 {
    let count = series.len();
    if count < 2 {
        return 0.0;
    }
    let n = count as f64;
    let mean_gap = series.iter().map(|gap| *gap as f64).sum::<f64>() / n;
    if mean_gap == 0.0 {
        return 0.0;
    }
    // Least squares in centred form. The design matrix (the indices `0..n`) is
    // symmetric about its own mean, so centring both axes evaluates the same
    // slope as `(n·Σig − Σi·Σg) / (n·Σi² − (Σi)²)` without the cancellation
    // that form suffers when the indices are large and the trend is small.
    let mean_index = (n - 1.0) / 2.0;
    let mut covariance = 0.0;
    let mut variance = 0.0;
    for (index, gap) in series.iter().enumerate() {
        let offset = index as f64 - mean_index;
        covariance += offset * (*gap as f64 - mean_gap);
        variance += offset * offset;
    }
    if variance == 0.0 {
        return 0.0;
    }
    let slope = covariance / variance;
    ((slope * (n - 1.0)).abs() / mean_gap).clamp(0.0, 1.0)
}

/// Chronological index of the `k`-th oldest entry of a ring buffer.
///
/// `len` is the number of valid entries, `head` the next write position. A ring
/// that has not wrapped stores its entries from index `0`; once full, the oldest
/// entry is exactly at `head`.
fn ring_index(len: usize, head: usize, k: usize, capacity: usize) -> usize {
    let start = if len == capacity { head } else { 0 };
    (start + k) % capacity
}

// ---------------------------------------------------------------------------
// Convergence: tumbling shape histograms
// ---------------------------------------------------------------------------

/// One epoch's shape histogram.
///
/// At most one entry per probe in the epoch, so `EPOCH_PROBES` slots can never
/// overflow (distinct shapes ≤ probes) and no allocation is needed. Entries keep
/// first-sighting order, and every computation walks them in that order, so the
/// result does not depend on hashing.
#[derive(Clone, Copy)]
struct EpochHistogram {
    hashes: [u64; EPOCH_PROBES],
    counts: [u32; EPOCH_PROBES],
    distinct: usize,
    probes: u32,
}

impl EpochHistogram {
    fn new() -> Self {
        Self {
            hashes: [0; EPOCH_PROBES],
            counts: [0; EPOCH_PROBES],
            distinct: 0,
            probes: 0,
        }
    }

    fn push(&mut self, shape: u64) {
        match self.hashes[..self.distinct]
            .iter()
            .position(|h| *h == shape)
        {
            Some(i) => self.counts[i] = self.counts[i].saturating_add(1),
            None => {
                self.hashes[self.distinct] = shape;
                self.counts[self.distinct] = 1;
                self.distinct += 1;
            }
        }
        self.probes = self.probes.saturating_add(1);
    }

    fn is_complete(&self) -> bool {
        self.probes as usize == EPOCH_PROBES
    }

    fn has_data(&self) -> bool {
        self.probes > 0
    }

    fn overwrite_with(&mut self, other: &Self) {
        self.hashes = other.hashes;
        self.counts = other.counts;
        self.distinct = other.distinct;
        self.probes = other.probes;
    }

    /// Total-variation distance between this histogram and `other`, in `[0, 1]`:
    /// `0.0` = the same distribution, `1.0` = no shared mass at all.
    fn total_variation(&self, other: &Self) -> f64 {
        let mine = self.probes as f64;
        let theirs = other.probes as f64;
        if mine == 0.0 || theirs == 0.0 {
            return 1.0;
        }
        let mut acc = 0.0;
        for (hash, count) in self.hashes[..self.distinct]
            .iter()
            .zip(self.counts[..self.distinct].iter())
        {
            let p = f64::from(*count) / mine;
            let q = other.hashes[..other.distinct]
                .iter()
                .position(|h| h == hash)
                .map_or(0.0, |i| f64::from(other.counts[i]) / theirs);
            acc += (p - q).abs();
        }
        // Mass that exists only in `other` still counts toward the distance.
        for (hash, count) in other.hashes[..other.distinct]
            .iter()
            .zip(other.counts[..other.distinct].iter())
        {
            if !self.hashes[..self.distinct].contains(hash) {
                acc += f64::from(*count) / theirs;
            }
        }
        0.5 * acc
    }
}

// ---------------------------------------------------------------------------
// Per-source record — fixed size, no heap
// ---------------------------------------------------------------------------

/// Everything the sensor remembers about one source. Fixed size by construction:
/// the arrays are the memory, and there is no growable container inside.
struct SourceRecord {
    last_at_micros: u64,
    probes_seen: u64,

    /// Inter-arrival gaps, sliding window (one gap per probe after the first).
    gaps: [u64; PROBE_WINDOW],
    gaps_len: usize,
    gaps_head: usize,

    /// Probe shapes and, per probe, whether that shape had already been sent by
    /// this source at the moment it arrived. The flag is decided at observation
    /// time because the memory it consults changes over time.
    shapes: [u64; PROBE_WINDOW],
    repeated: [bool; PROBE_WINDOW],
    window_len: usize,
    window_head: usize,

    /// Bounded first-sighting memory: the last `SHAPE_MEMORY` distinct shapes.
    memory: [u64; SHAPE_MEMORY],
    memory_len: usize,
    memory_head: usize,

    /// Convergence state: the last two completed epochs.
    current_epoch: EpochHistogram,
    previous_epoch: EpochHistogram,
    convergence: f64,
    epochs_compared: u32,
}

impl SourceRecord {
    fn new(at_micros: u64) -> Self {
        Self {
            last_at_micros: at_micros,
            probes_seen: 0,
            gaps: [0; PROBE_WINDOW],
            gaps_len: 0,
            gaps_head: 0,
            shapes: [0; PROBE_WINDOW],
            repeated: [false; PROBE_WINDOW],
            window_len: 0,
            window_head: 0,
            memory: [0; SHAPE_MEMORY],
            memory_len: 0,
            memory_head: 0,
            current_epoch: EpochHistogram::new(),
            previous_epoch: EpochHistogram::new(),
            convergence: 0.0,
            epochs_compared: 0,
        }
    }

    fn memory_contains(&self, shape: u64) -> bool {
        self.memory[..self.memory_len].contains(&shape)
    }

    fn memory_remember(&mut self, shape: u64) {
        self.memory[self.memory_head] = shape;
        self.memory_head = (self.memory_head + 1) % SHAPE_MEMORY;
        if self.memory_len < SHAPE_MEMORY {
            self.memory_len += 1;
        }
    }

    fn observe(&mut self, at_micros: u64, shape: u64) {
        if self.probes_seen > 0 {
            let gap = at_micros.saturating_sub(self.last_at_micros);
            self.gaps[self.gaps_head] = gap;
            self.gaps_head = (self.gaps_head + 1) % PROBE_WINDOW;
            if self.gaps_len < PROBE_WINDOW {
                self.gaps_len += 1;
            }
        }
        self.last_at_micros = at_micros;
        self.probes_seen = self.probes_seen.saturating_add(1);

        // Decided before the memory is updated, so a shape's first sighting is
        // not its own repeat.
        let repeated = self.memory_contains(shape);
        if !repeated {
            self.memory_remember(shape);
        }
        self.shapes[self.window_head] = shape;
        self.repeated[self.window_head] = repeated;
        self.window_head = (self.window_head + 1) % PROBE_WINDOW;
        if self.window_len < PROBE_WINDOW {
            self.window_len += 1;
        }

        self.current_epoch.push(shape);
        if self.current_epoch.is_complete() {
            self.close_epoch();
        }
    }

    /// Finish an epoch: compare it with the previous one (when there is one),
    /// then make it the previous one.
    fn close_epoch(&mut self) {
        if self.previous_epoch.has_data() {
            let tv = self.current_epoch.total_variation(&self.previous_epoch);
            // 1.0 = the distribution has settled; 0.0 = every window differs.
            self.convergence = (1.0 - tv).clamp(0.0, 1.0);
            self.epochs_compared = self.epochs_compared.saturating_add(1);
        }
        self.previous_epoch.overwrite_with(&self.current_epoch);
        self.current_epoch = EpochHistogram::new();
    }

    fn profile(&self, source: SocketAddr) -> ProbeProfile {
        // Gaps: materialise the window in chronological order so the estimator
        // sees exactly the series E30 saw (a stack buffer, not an allocation).
        let mut gap_buf = [0u64; PROBE_WINDOW];
        let mut gap_sum: u128 = 0;
        for k in 0..self.gaps_len {
            let gap = self.gaps[ring_index(self.gaps_len, self.gaps_head, k, PROBE_WINDOW)];
            gap_buf[k] = gap;
            gap_sum += u128::from(gap);
        }
        let rhythm_pe = if self.gaps_len >= MIN_GAPS_FOR_PE {
            // The normalisation cannot exceed 1 mathematically; clamp so the
            // declared `[0, 1]` range holds for any floating-point input.
            permutation_entropy(&gap_buf[..self.gaps_len]).clamp(0.0, 1.0)
        } else {
            // Not measurable yet — the sufficiency block says so.
            0.0
        };

        // Cadence trend: how far the gaps travel across the window, as a
        // fraction of the mean gap. The same gaps `rhythm_pe` above measures the
        // *arrangement* of — the two are separate columns on purpose, because
        // the entropy cannot see a monotone ramp and the slope cannot see a
        // zigzag (see the module docs). Neither ever folds into the other.
        let drift = gap_drift(&gap_buf[..self.gaps_len]);

        // Budget burn: the window's mean rate. Zero elapsed time cannot be
        // turned into a rate, so it reports 0.0 rather than dividing by zero.
        let rate_per_sec = if gap_sum == 0 {
            0.0
        } else {
            self.gaps_len as f64 * 1_000_000.0 / gap_sum as f64
        };

        // Coverage: distinct shapes in the window / probes in the window.
        let mut distinct = 0usize;
        for k in 0..self.window_len {
            let shape = self.shapes[ring_index(self.window_len, self.window_head, k, PROBE_WINDOW)];
            let seen_earlier = (0..k).any(|j| {
                self.shapes[ring_index(self.window_len, self.window_head, j, PROBE_WINDOW)] == shape
            });
            if !seen_earlier {
                distinct += 1;
            }
        }
        let exploration = if self.window_len == 0 {
            0.0
        } else {
            distinct as f64 / self.window_len as f64
        };

        // Repetition: probes whose shape this source had already sent.
        let repeats = (0..self.window_len)
            .filter(|k| {
                self.repeated[ring_index(self.window_len, self.window_head, *k, PROBE_WINDOW)]
            })
            .count();
        let repeat_ratio = if self.window_len == 0 {
            0.0
        } else {
            repeats as f64 / self.window_len as f64
        };

        ProbeProfile {
            source,
            rhythm_pe,
            drift,
            repeat_ratio,
            exploration,
            convergence: self.convergence.clamp(0.0, 1.0),
            rate_per_sec,
            sufficiency: ProbeSufficiency {
                probes_in_window: self.window_len as u32,
                gaps_in_window: self.gaps_len as u32,
                probes_seen: self.probes_seen,
                epochs_compared: self.epochs_compared,
            },
            last_seen_micros: self.last_at_micros,
        }
    }
}

// ---------------------------------------------------------------------------
// The sensor
// ---------------------------------------------------------------------------

/// Windowed, per-source probe-behaviour sensor. See the module docs.
///
/// Nothing here blocks, decides, or influences the probe path: [`observe`]
/// records, [`profile`] reads, [`publish_profile`] puts the reading on the bus
/// for a later stack to consume.
///
/// [`observe`]: ProbeSensor::observe
/// [`profile`]: ProbeSensor::profile
/// [`publish_profile`]: ProbeSensor::publish_profile
pub struct ProbeSensor {
    config: ProbeSensorConfig,
    sources: RwLock<HashMap<SocketAddr, SourceRecord>>,
    bus: Arc<BusPublisher>,
}

impl ProbeSensor {
    pub fn new(bus: Arc<BusPublisher>) -> Self {
        Self::with_config(bus, ProbeSensorConfig::default())
    }

    pub fn with_config(bus: Arc<BusPublisher>, config: ProbeSensorConfig) -> Self {
        Self {
            config,
            sources: RwLock::new(HashMap::new()),
            bus,
        }
    }

    pub fn config(&self) -> ProbeSensorConfig {
        self.config
    }

    /// Record one probe. Never fails, never publishes, never touches the probe
    /// path: this is the passive half of the sensor.
    pub fn observe(&self, event: ProbeEvent) {
        if self.config.max_sources == 0 {
            return;
        }
        let mut sources = self.sources.write();
        if !sources.contains_key(&event.source) {
            if sources.len() >= self.config.max_sources {
                self.make_room(&mut sources, event.at_micros);
            }
            sources.insert(event.source, SourceRecord::new(event.at_micros));
        }
        if let Some(record) = sources.get_mut(&event.source) {
            record.observe(event.at_micros, event.shape);
        }
    }

    /// The current reading for one source, or `None` if this sensor has no
    /// observations of it. Read-only: profiling is not an event.
    pub fn profile(&self, source: SocketAddr) -> Option<ProbeProfile> {
        self.sources
            .read()
            .get(&source)
            .map(|record| record.profile(source))
    }

    /// Publish [`PROBE_PROFILE_TOPIC`] with the current reading for `source`.
    ///
    /// Publishing changes nothing about the reading (observation is the only
    /// input), so a stack may publish as often as it likes. `Ok(None)` means
    /// there is nothing to publish because the source was never observed — the
    /// sensor does not invent a profile for a source it has not seen.
    pub fn publish_profile(
        &self,
        source: SocketAddr,
    ) -> Result<Option<ProbeProfile>, ProbeSensorError> {
        let Some(profile) = self.profile(source) else {
            return Ok(None);
        };
        BusEvent::publish(
            &self.bus,
            PROBE_PROFILE_TOPIC,
            Message::ProbeProfile(profile.clone()),
        )?;
        Ok(Some(profile))
    }

    /// How many sources are currently tracked. Bounded by
    /// [`ProbeSensorConfig::max_sources`].
    pub fn tracked_sources(&self) -> usize {
        self.sources.read().len()
    }

    /// The sensor's fixed record footprint in bytes
    /// (`tracked_sources × size_of::<SourceRecord>()`, excluding the map's own
    /// bookkeeping). Constant for a given source count — this is the quantity
    /// that must not grow with the attacker's traffic.
    pub fn footprint_bytes(&self) -> usize {
        self.sources.read().len() * std::mem::size_of::<SourceRecord>()
    }

    /// Forget sources idle for at least [`ProbeSensorConfig::source_ttl_micros`]
    /// as of `now_micros`, returning how many were dropped. `now_micros` is the
    /// caller's clock reading in the same units as [`ProbeEvent::at_micros`] —
    /// the sensor still reads no clock of its own, so a composition root can
    /// call this on whatever schedule it likes.
    pub fn prune_expired(&self, now_micros: u64) -> usize {
        let mut sources = self.sources.write();
        let before = sources.len();
        let ttl = self.config.source_ttl_micros;
        sources.retain(|_, record| now_micros.saturating_sub(record.last_at_micros) < ttl);
        before - sources.len()
    }

    /// Make room for one new source: first everything that has expired, then —
    /// only if the map is still full — the stalest record.
    ///
    /// The stalest-record choice is a total order (`last_seen`, then address),
    /// so it does not depend on hash-map iteration order.
    fn make_room(&self, sources: &mut HashMap<SocketAddr, SourceRecord>, now_micros: u64) {
        let ttl = self.config.source_ttl_micros;
        sources.retain(|_, record| now_micros.saturating_sub(record.last_at_micros) < ttl);
        if sources.len() < self.config.max_sources {
            return;
        }
        let stalest = sources
            .iter()
            .min_by(|(addr_a, a), (addr_b, b)| {
                a.last_at_micros
                    .cmp(&b.last_at_micros)
                    .then_with(|| addr_a.cmp(addr_b))
            })
            .map(|(addr, _)| *addr);
        if let Some(addr) = stalest {
            sources.remove(&addr);
        }
    }
}

/// A stable fingerprint of a probe's shape, for callers that need to turn a
/// probe's bytes into the opaque `u64` the sensor compares.
///
/// FNV-1a, for the same reason the rest of this tree reaches for it: no
/// dependencies, no randomness, and the same bytes always produce the same
/// value. It is a *helper*, not a policy — the sensor never interprets the
/// value, and nothing here decides whether a shape is interesting.
pub fn probe_shape_fingerprint(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // Fixtures. The synthetic sequences are E30's, byte for byte, so the
    // anchors below are the recorded ones rather than a re-derivation.
    // -----------------------------------------------------------------------

    /// SplitMix64 — E30's `Rng`, copied so the organic anchor is measured on the
    /// exact stream the E30 run measured (`0xE30_5EED`, first 64 draws).
    /// Test-only: the sensor itself never generates random numbers.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    const E30_ORGANIC_SEED: u64 = 0xE30_5EED;

    fn gaps_periodic(count: usize, gap: u64) -> Vec<u64> {
        vec![gap; count]
    }

    /// E30's `organic`: `rng.next_u64() % 97 + 1`.
    fn gaps_organic(count: usize, seed: u64) -> Vec<u64> {
        let mut rng = SplitMix64(seed);
        (0..count).map(|_| rng.next_u64() % 97 + 1).collect()
    }

    /// E30's jittered beacon: `20 + (i * 7919 % 11)` — a ±20%-ish ramp.
    fn gaps_e30_jittered(count: usize) -> Vec<u64> {
        (0..count).map(|i| 20 + (i * 7919 % 11) as u64).collect()
    }

    /// E30's zigzag: alternating short/long (the anti-periodicity trick).
    fn gaps_e30_zigzag(count: usize) -> Vec<u64> {
        (0..count)
            .map(|i| if i % 2 == 0 { 5 } else { 40 })
            .collect()
    }

    /// E30's burst-pause scan rhythm.
    fn gaps_e30_burst(count: usize) -> Vec<u64> {
        (0..count)
            .map(|i| if i % 10 == 9 { 200 } else { 5 })
            .collect()
    }

    /// Mean 25, like `gaps_periodic(_, 25)`, so the pair isolates rhythm from
    /// every other dimension including `rate_per_sec`.
    fn gaps_alternating(count: usize) -> Vec<u64> {
        (0..count)
            .map(|i| if i % 2 == 0 { 24 } else { 26 })
            .collect()
    }

    /// A smoothly drifting cadence: gaps `2_000, 2_016, 2_032, …`, i.e.
    /// `2_000 + 16·i`. The whole point of the sixth dimension — every ordinal
    /// pattern is identical (`rhythm_pe` exactly `0.0`) while the magnitude
    /// climbs (`drift` ≈ 0.40).
    ///
    /// Mean gap: `2_000 + 16 · 63 / 2 = 2_504`, which is the metronome
    /// [`GAPS_RAMP_MEAN`] used in the drift gates, so a ramp/metronome pair
    /// differs in `drift` alone.
    fn gaps_ramp(count: usize) -> Vec<u64> {
        (0..count).map(|i| 2_000 + i as u64 * 16).collect()
    }

    /// The ramp's exact mean gap (`Σ(2000 + 16i)/64`), so the metronome paired
    /// with the ramp has the same `rate_per_sec` *and* the same mean cadence.
    const GAPS_RAMP_MEAN: u64 = 2_504;

    /// The ramp's exact `drift`: `|16 × 63| / 2_504`. Spelled out so the gates
    /// assert the definition rather than whatever the implementation returns.
    const GAPS_RAMP_DRIFT: f64 = 1_008.0 / 2_504.0; // 0.402_555_910_543_131

    /// A zigzag that is symmetric under time reversal — `5, 40, 40, 5, …` — so
    /// its gaps are arranged non-monotonically while its least-squares trend is
    /// **exactly** zero (the ramp's opposite failure mode). `rhythm_pe` is high.
    fn gaps_palindromic_zigzag(count: usize) -> Vec<u64> {
        const PATTERN: [u64; 4] = [5, 40, 40, 5];
        (0..count).map(|i| PATTERN[i % 4]).collect()
    }

    /// The E30 zigzag with a constant-16-per-probe ramp added: the same
    /// *arrangement* as the flat zigzag, a strong *trend*. Keeps the alternating
    /// tick (a `+25` on odd indices) and therefore the same `rhythm_pe` as the
    /// ramp-free alternation, while `drift` tracks the ramp almost exactly.
    fn gaps_ramp_with_zigzag_tick(count: usize) -> Vec<u64> {
        (0..count)
            .map(|i| 2_000 + i as u64 * 16 + if i % 2 == 0 { 0 } else { 25 })
            .collect()
    }

    fn shapes_constant(count: usize, shape: u64) -> Vec<u64> {
        vec![shape; count]
    }

    /// Every probe a shape never used before (a first-pass sweeper).
    fn shapes_distinct(count: usize) -> Vec<u64> {
        (0..count).map(|i| 0x1000 + i as u64).collect()
    }

    fn shapes_cycle(count: usize, cycle: &[u64]) -> Vec<u64> {
        (0..count).map(|i| cycle[i % cycle.len()]).collect()
    }

    /// Epoch 1 (32 probes): 8 each of four shapes. Epoch 2: 16, 16, 0, 0. Same
    /// vocabulary, same window coverage, different distribution — the
    /// convergence-only perturbation.
    fn shapes_drifting_cycle(count: usize) -> Vec<u64> {
        (0..count)
            .map(|i| {
                let within = i % EPOCH_PROBES;
                if (i / EPOCH_PROBES) % 2 == 0 {
                    100 + (within / 8) as u64
                } else {
                    100 + (within / 16) as u64
                }
            })
            .collect()
    }

    fn sensor() -> (Arc<BusPublisher>, ProbeSensor) {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let sensor = ProbeSensor::new(Arc::clone(&bus));
        (bus, sensor)
    }

    fn addr(n: u16) -> SocketAddr {
        format!("10.0.0.1:{n}").parse().unwrap()
    }

    /// Feed one source `gaps.len() + 1` probes: the first at the epoch, then one
    /// per gap. Gap `k` therefore becomes the inter-arrival time between probe
    /// `k` and probe `k + 1` — the same series E30 measured.
    fn feed(
        sensor: &ProbeSensor,
        source: SocketAddr,
        gaps: &[u64],
        shapes: &[u64],
    ) -> ProbeProfile {
        assert_eq!(
            gaps.len() + 1,
            shapes.len(),
            "one gap per probe after the first"
        );
        let mut at = 1_000_000u64;
        sensor.observe(ProbeEvent {
            source,
            at_micros: at,
            shape: shapes[0],
        });
        for (gap, shape) in gaps.iter().zip(&shapes[1..]) {
            at += gap;
            sensor.observe(ProbeEvent {
                source,
                at_micros: at,
                shape: *shape,
            });
        }
        sensor.profile(source).expect("source was observed")
    }

    /// 65 probes = 64 gaps = exactly the window, so the sensor measures the
    /// whole sequence and the anchors transfer without truncation.
    fn feed_window(
        sensor: &ProbeSensor,
        source: SocketAddr,
        gaps: &[u64],
        shapes: &[u64],
    ) -> ProbeProfile {
        assert_eq!(gaps.len(), PROBE_WINDOW);
        feed(sensor, source, gaps, shapes)
    }

    fn assert_all_dimensions_in_range(profile: &ProbeProfile) {
        for (name, value) in [
            ("rhythm_pe", profile.rhythm_pe),
            ("drift", profile.drift),
            ("repeat_ratio", profile.repeat_ratio),
            ("exploration", profile.exploration),
            ("convergence", profile.convergence),
        ] {
            assert!(
                value.is_finite() && (0.0..=1.0).contains(&value),
                "{name} out of [0, 1]: {value}"
            );
        }
        assert!(
            profile.rate_per_sec.is_finite() && profile.rate_per_sec >= 0.0,
            "rate_per_sec must be a finite non-negative rate: {}",
            profile.rate_per_sec
        );
    }

    // -----------------------------------------------------------------------
    // Gate 1 — the E30 anchors
    // -----------------------------------------------------------------------

    #[test]
    fn e30_anchors_reproduce_through_the_sensor() {
        let (_bus, sensor) = sensor();

        // (name, E30's synthetic sequence, the value E30 recorded)
        let anchors: [(&str, Vec<u64>, f64); 5] = [
            ("periodic", gaps_periodic(PROBE_WINDOW, 25), 0.000),
            (
                "organic",
                gaps_organic(PROBE_WINDOW, E30_ORGANIC_SEED),
                0.967,
            ),
            ("jittered_beacon", gaps_e30_jittered(PROBE_WINDOW), 0.329),
            ("zigzag", gaps_e30_zigzag(PROBE_WINDOW), 0.387),
            ("burst_pause", gaps_e30_burst(48), 0.325),
        ];

        // Tolerance: the recorded anchors are quoted to three decimals, so
        // 0.001 is the tightest tolerance the record supports. It is also far
        // tighter than any change of *method* would allow — dropping the
        // position-stable tie rule moves `periodic` from 0.000 to 1.000, and
        // changing the window order moves `organic` by ~0.05. The port does not
        // need the slack: it runs E30's operations, in E30's order, on E30's
        // integers.
        const TOLERANCE: f64 = 0.001;

        for (index, (name, gaps, expected)) in anchors.into_iter().enumerate() {
            let source = addr(9000 + index as u16);
            let profile = feed(
                &sensor,
                source,
                &gaps,
                &shapes_constant(gaps.len() + 1, 0xAA),
            );
            assert_all_dimensions_in_range(&profile);
            assert_eq!(
                profile.sufficiency.gaps_in_window as usize,
                gaps.len(),
                "{name}: the whole sequence must be inside the window"
            );
            println!(
                "E30 anchor {name}: sensor={:.4} recorded={expected:.3} (gaps={})",
                profile.rhythm_pe, profile.sufficiency.gaps_in_window
            );
            assert!(
                (profile.rhythm_pe - expected).abs() <= TOLERANCE,
                "{name}: sensor rhythm_pe {:.6} differs from E30's recorded {expected:.3} by more than {TOLERANCE}",
                profile.rhythm_pe
            );
        }

        // The sharpest anchor: with position-stable ties, a metronome collapses
        // onto ONE ordinal pattern, so this is exactly 0.0 and not merely small.
        let periodic = feed(
            &sensor,
            addr(9100),
            &gaps_periodic(PROBE_WINDOW, 25),
            &shapes_constant(PROBE_WINDOW + 1, 0xAA),
        );
        assert_eq!(
            periodic.rhythm_pe, 0.0,
            "a metronome must read exactly 0.0 (position-stable ties)"
        );
    }

    // -----------------------------------------------------------------------
    // Gate 2 — driller vs sweeper: independent dimensions
    // -----------------------------------------------------------------------

    #[test]
    fn driller_and_sweeper_share_rhythm_while_shape_dimensions_split() {
        let (_bus, sensor) = sensor();
        let gaps = gaps_organic(PROBE_WINDOW, E30_ORGANIC_SEED);
        let probes = gaps.len() + 1;

        let driller = feed_window(&sensor, addr(1), &gaps, &shapes_constant(probes, 0xD1));
        let sweeper = feed_window(&sensor, addr(2), &gaps, &shapes_distinct(probes));

        println!(
            "driller: pe={:.4} repeat={:.4} exploration={:.4} convergence={:.2} rate={:.0}",
            driller.rhythm_pe,
            driller.repeat_ratio,
            driller.exploration,
            driller.convergence,
            driller.rate_per_sec
        );
        println!(
            "sweeper: pe={:.4} repeat={:.4} exploration={:.4} convergence={:.2} rate={:.0}",
            sweeper.rhythm_pe,
            sweeper.repeat_ratio,
            sweeper.exploration,
            sweeper.convergence,
            sweeper.rate_per_sec
        );

        // The rhythm dimension does not move: same gap sequence in, same number
        // out (identical by construction, asserted rather than assumed).
        assert_eq!(
            driller.rhythm_pe, sweeper.rhythm_pe,
            "the same gap sequence must give the same rhythm reading"
        );
        assert_eq!(driller.rate_per_sec, sweeper.rate_per_sec);

        // The shape dimensions move, and they move completely.
        assert!(
            driller.repeat_ratio > 0.9 && sweeper.repeat_ratio < 0.05,
            "a driller repeats ({:.4}) and a sweeper does not ({:.4})",
            driller.repeat_ratio,
            sweeper.repeat_ratio
        );
        assert!(
            driller.exploration < 0.05 && sweeper.exploration > 0.95,
            "a driller covers one point ({:.4}) while a sweeper covers the window ({:.4})",
            driller.exploration,
            sweeper.exploration
        );
    }

    /// Deterministic ±`pct`% jitter band around a base gap: draws *within* the
    /// band, deliberately non-monotonic, so the gaps actually reorder. A
    /// monotonic sweep is not jitter — see
    /// `rhythm_is_blind_to_a_smoothly_drifting_cadence`.
    fn gaps_jitter_at(base: u64, pct: u64, count: usize) -> Vec<u64> {
        let span = base * pct / 100;
        let mut z = E30_ORGANIC_SEED;
        (0..count)
            .map(|_| {
                z = z
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                if span == 0 {
                    base
                } else {
                    base - span + (z >> 33) % (2 * span + 1)
                }
            })
            .collect()
    }

    /// EDGE-OF-CHAOS PASS on the sensor — the measurement-resolution axis.
    ///
    /// For an instrument whose output is a *reading*, the criticality question
    /// is not "where does it break" but "where does the reading stop being a
    /// reading". `rhythm_pe` is computed over ordinal patterns of three
    /// consecutive gaps, and the number of distinct patterns available is bound
    /// by how many distinct gap *values* occur. So the axis is gap magnitude:
    ///
    /// - too coarse: the jitter band is narrower than the tick, so every gap
    ///   quantises to the same integer and PE reads 0.000 for **any** prober,
    ///   however hard it is actually jittering;
    /// - too fine: scheduler noise dominates and every prober reads organic.
    ///
    /// The same ±20% beacon jitter is applied at two cadences. If the reading
    /// were cadence-independent they would match; it is not, so `rhythm_pe` has
    /// a cadence floor.
    #[test]
    fn rhythm_under_reads_at_high_cadence_because_gaps_quantise() {
        // ±20% jitter (the beacon's shape) at a slow cadence, gaps ~2500.
        let slow = gaps_jitter_at(2_500, 20, PROBE_WINDOW);
        // The identical relative jitter at a fast cadence, gaps ~5.
        let fast = gaps_jitter_at(5, 20, PROBE_WINDOW);
        // The floor: a band narrower than one tick collapses to one value.
        let degenerate = gaps_jitter_at(1, 20, PROBE_WINDOW);

        let pe_slow = permutation_entropy(&slow);
        let pe_fast = permutation_entropy(&fast);
        let pe_degenerate = permutation_entropy(&degenerate);

        let distinct = |g: &[u64]| {
            let mut v = g.to_vec();
            v.sort_unstable();
            v.dedup();
            v.len()
        };

        println!(
            "resolution axis: slow(base=2500)= {pe_slow:.4}  fast(base=5)= {pe_fast:.4}  \
             degenerate(base=1)= {pe_degenerate:.4}"
        );
        println!(
            "distinct gap values: slow= {}  fast= {}  degenerate= {}",
            distinct(&slow),
            distinct(&fast),
            distinct(&degenerate)
        );

        // Identical relative behaviour reads LOWER as the cadence rises,
        // because the ordinal-pattern space shrinks with the representable gaps.
        assert!(
            pe_fast < pe_slow,
            "a fast prober must not read the same as a slow one; \
             got fast={pe_fast:.4} slow={pe_slow:.4}"
        );
        // The floor: a sub-tick jitter band is invisible, so a jittering prober
        // reads exactly as a metronome. `ProbeSufficiency` cannot catch this —
        // the measurement succeeds, it just reads the wrong thing.
        assert!(
            pe_degenerate <= 0.0001,
            "a sub-tick jitter band must collapse to the periodic reading; \
             got {pe_degenerate:.4}"
        );
    }

    /// EDGE-OF-CHAOS PASS, second finding — and this one came from a mistake.
    ///
    /// The first draft of the test above built its "jitter" as a monotonic sweep
    /// across the band (2000, 2016, 2032, …). That draft read **0.0000 at 64
    /// distinct gap values**, which is not a quantisation effect at all: a
    /// monotonic ramp presents the *same ordinal pattern* on every triple, and
    /// permutation entropy measures arrangement, not magnitude.
    ///
    /// The consequence is a real blind spot worth pinning: a prober whose
    /// cadence drifts **smoothly** — gradually speeding up or slowing down —
    /// reads as a perfect metronome. `rhythm_pe` cannot distinguish "steady
    /// beat" from "smoothly accelerating", so a drifting prober is classified
    /// with the naive beacons. Any consumer of this dimension must not read
    /// `rhythm_pe ≈ 0` as "not adapting".
    ///
    /// EDGE-OF-CHAOS PASS on `drift` — the trend-window axis.
    ///
    /// `drift` is the magnitude of a least-squares slope across the window, so
    /// it measures **net** trend. The criticality question for a net-trend
    /// measure is what shape of cadence change it cannot see, and the candidate
    /// is the prober that changes speed and then changes back: a V-shaped
    /// cadence profile. Rises and falls cancel, so a net trend may read ~0 for
    /// the most adaptive behaviour available.
    ///
    /// That would be the same family of blind spot as `rhythm_pe`'s — a reading
    /// correct about the property it measures and silent about the adjacent one
    /// — which is exactly why this sensor has separate columns rather than one
    /// score.
    ///
    /// Setup is pinned so the comparison is fair: the V, the pure ramp and the
    /// metronome all share a mean gap of 2504, so `rate_per_sec` cannot be what
    /// separates them.
    #[test]
    fn trend_axis_v_shaped_cadence() {
        let half = PROBE_WINDOW / 2;
        let mut v_shape: Vec<u64> = (0..half as u64).map(|i| 2_000 + i * 32).collect();
        v_shape.extend((0..half as u64).map(|i| 3_008 - i * 32));
        let ramp: Vec<u64> = (0..PROBE_WINDOW as u64).map(|i| 2_000 + i * 16).collect();
        let metronome = gaps_periodic(PROBE_WINDOW, 2_504);

        let mean = |g: &[u64]| g.iter().sum::<u64>() as f64 / g.len() as f64;

        println!(
            "trend axis: v_shape mean= {:.1} drift= {:.6} pe= {:.4}",
            mean(&v_shape),
            gap_drift(&v_shape),
            permutation_entropy(&v_shape)
        );
        println!(
            "trend axis: ramp    mean= {:.1} drift= {:.6} pe= {:.4}",
            mean(&ramp),
            gap_drift(&ramp),
            permutation_entropy(&ramp)
        );
        println!(
            "trend axis: metron  mean= {:.1} drift= {:.6} pe= {:.4}",
            mean(&metronome),
            gap_drift(&metronome),
            permutation_entropy(&metronome)
        );

        // Setup validity: equal means, so rate_per_sec is not the separator.
        assert_eq!(mean(&v_shape), mean(&metronome));
        assert_eq!(mean(&ramp), mean(&metronome));
        // The metronome is the zero point of the trend reading.
        assert_eq!(gap_drift(&metronome), 0.0);
        // The pure ramp is the reading working as intended.
        assert!(gap_drift(&ramp) > 0.4);

        // THE FINDING: a net-trend measure reads a V as steady, because the
        // rise and the fall cancel. Measured 0.0094 against the pure ramp's
        // 0.4026 — about one forty-third. `drift` alone cannot tell "no change"
        // from "changed and changed back".
        let drift_v = gap_drift(&v_shape);
        assert!(
            drift_v < 0.02,
            "a V-shaped cadence must collapse toward the steady reading, or \
             `drift` is seeing more than net trend; got {drift_v:.6}"
        );

        // BUT `rhythm_pe` catches it — with the opposite instrument. A reversal
        // changes the ordinal *arrangement*, which is exactly what a monotonic
        // ramp does not do, so the reading that is blind to trend is the one
        // that sees the reversal. Measured 0.4266.
        let pe_v = permutation_entropy(&v_shape);
        assert!(
            pe_v > 0.4,
            "the reversal must appear as arrangement disorder; got {pe_v:.4}"
        );

        // THE PAYOFF — joint coverage, which is the whole argument for separate
        // columns rather than one score, demonstrated on a case neither reading
        // was designed for:
        //   `drift` alone      → the V hides with the metronome
        //   `rhythm_pe` alone  → the ramp hides with the metronome
        //   both together      → all three separate
        let drift_ramp = gap_drift(&ramp);
        let drift_metronome = gap_drift(&metronome);
        let pe_ramp = permutation_entropy(&ramp);
        let pe_metronome = permutation_entropy(&metronome);

        assert!(
            drift_v < 0.02 && drift_metronome == 0.0,
            "`drift` alone must lose this case, or the payoff below is vacuous"
        );
        assert_eq!(
            pe_ramp, pe_metronome,
            "`rhythm_pe` alone must lose the ramp case, or the payoff below is \
             vacuous"
        );
        assert!(
            pe_v != pe_ramp && pe_v != pe_metronome,
            "the V must be separable from both by arrangement"
        );
        assert!(
            drift_ramp != drift_v && drift_ramp != drift_metronome,
            "the ramp must be separable from both by trend"
        );
    }

    /// This test is the *reason* the sixth dimension ([`ProbeProfile::drift`])
    /// exists, so it also carries that dimension's reading of the same two
    /// sequences: the blind spot is closed by a separate column, never by
    /// changing `rhythm_pe`. The `rhythm_pe` assertions below are untouched.
    #[test]
    fn rhythm_is_blind_to_a_smoothly_drifting_cadence() {
        let ramp: Vec<u64> = (0..PROBE_WINDOW as u64).map(|i| 2_000 + i * 16).collect();
        let metronome = gaps_periodic(PROBE_WINDOW, 2_500);

        let pe_ramp = permutation_entropy(&ramp);
        let pe_metronome = permutation_entropy(&metronome);

        let drift_ramp = gap_drift(&ramp);
        let drift_metronome = gap_drift(&metronome);

        let distinct = {
            let mut v = ramp.clone();
            v.sort_unstable();
            v.dedup();
            v.len()
        };

        println!(
            "drift axis: ramp(gaps 2000..=3008, {distinct} distinct)= {pe_ramp:.4}  \
             metronome(gap 2500)= {pe_metronome:.4}"
        );
        println!(
            "drift axis: ramp drift= {drift_ramp:.6}  metronome drift= {drift_metronome:.6} \
             (magnitude of the trend the entropy above cannot see)"
        );

        assert!(
            distinct == PROBE_WINDOW,
            "the ramp must span many distinct gaps for this to be about \
             arrangement rather than resolution; got {distinct}"
        );
        assert_eq!(
            pe_ramp, pe_metronome,
            "a smoothly drifting cadence reads exactly as a metronome — that is \
             the blind spot this test exists to document"
        );

        // The sixth dimension: the ramp's cadence travels 1008µs across the
        // window (0.4026 of the mean gap), the metronome's travels none of it.
        assert!(
            (drift_ramp - GAPS_RAMP_DRIFT).abs() < 1e-12,
            "the ramp's drift must be its total relative change |16 × 63| / 2504 = \
             {GAPS_RAMP_DRIFT:.6}, got {drift_ramp:.6}"
        );
        assert_eq!(
            drift_metronome, 0.0,
            "a metronome has no trend at all — exactly 0.0, not merely small"
        );
        assert!(
            drift_ramp > 0.4,
            "the ramp that the entropy reads as a metronome is exactly what drift \
             must show: {drift_ramp:.6}"
        );
    }

    #[test]
    fn rhythm_moves_while_every_other_dimension_holds() {
        let (_bus, sensor) = sensor();
        let probes = PROBE_WINDOW + 1;

        // Same mean gap (25), same shape, so rate, repetition, coverage and
        // convergence are identical and only the *arrangement* of the gaps
        // differs: a metronome versus a regular alternation.
        let periodic = feed_window(
            &sensor,
            addr(1),
            &gaps_periodic(PROBE_WINDOW, 25),
            &shapes_constant(probes, 0x7),
        );
        let alternating = feed_window(
            &sensor,
            addr(2),
            &gaps_alternating(PROBE_WINDOW),
            &shapes_constant(probes, 0x7),
        );

        println!(
            "periodic: pe={:.4} rate={:.1} | alternating: pe={:.4} rate={:.1}",
            periodic.rhythm_pe,
            periodic.rate_per_sec,
            alternating.rhythm_pe,
            alternating.rate_per_sec
        );

        assert_eq!(periodic.rhythm_pe, 0.0);
        assert!(
            alternating.rhythm_pe > 0.35,
            "an alternating cadence is not a metronome: {:.4}",
            alternating.rhythm_pe
        );
        assert_eq!(periodic.rate_per_sec, alternating.rate_per_sec);
        assert_eq!(periodic.repeat_ratio, alternating.repeat_ratio);
        assert_eq!(periodic.exploration, alternating.exploration);
        assert_eq!(periodic.convergence, alternating.convergence);
        // The *sixth* column does move a hair here, and the reason is worth
        // stating rather than hiding: `gaps_alternating` is an even-length
        // alternation starting on the short gap, which is not quite
        // trend-free (the two phase classes straddle the window's midpoint
        // unequally). The move is real but three orders of magnitude smaller
        // than the arrangement move above, so it changes nothing about this
        // test's argument — it is the trend residual of a 24/26 alternation,
        // not a second rhythm reading.
        println!(
            "periodic drift={:.6} | alternating drift={:.6}",
            periodic.drift, alternating.drift
        );
        assert!(
            alternating.drift < 0.01 && periodic.drift == 0.0,
            "an even-length alternation has a near-zero trend residual \
             ({:.6}), not a trend",
            alternating.drift
        );
    }

    // -----------------------------------------------------------------------
    // Gate 2b — the sixth dimension: cadence trend
    //
    // `rhythm_pe` is blind to a smoothly drifting cadence (pinned by
    // `rhythm_is_blind_to_a_smoothly_drifting_cadence`). The three gates below
    // are the new column's own: it covers that blind spot, it moves
    // independently of `rhythm_pe`, and it is not a restatement of any other
    // column.
    // -----------------------------------------------------------------------

    /// THE HEADLINE GATE: the blind spot is closed by a *separate* column.
    ///
    /// A monotone ramp and a metronome with the **same mean gap** are the same
    /// prober as far as every pre-existing column is concerned — same budget
    /// burn rate, same repetition, same coverage, same convergence, and the same
    /// `rhythm_pe` (`0.0` for both, despite the ramp spanning 64 distinct gap
    /// values). `drift` is the only column that separates them, and it separates
    /// them completely: `0.4026` against exactly `0.0`.
    ///
    /// Nothing about `rhythm_pe` is changed by this: the ramp still reads
    /// `0.0000` there, exactly as the blind-spot test requires. The fix for a
    /// blind sensor is a new reading, never a reinterpretation of an old one.
    #[test]
    fn drift_separates_the_ramp_that_rhythm_reads_as_a_metronome() {
        let (_bus, sensor) = sensor();
        let probes = PROBE_WINDOW + 1;

        // Same mean gap (2504), same shapes — so every other column is held.
        let ramp = feed_window(
            &sensor,
            addr(1),
            &gaps_ramp(PROBE_WINDOW),
            &shapes_constant(probes, 0xD2),
        );
        let metronome = feed_window(
            &sensor,
            addr(2),
            &gaps_periodic(PROBE_WINDOW, GAPS_RAMP_MEAN),
            &shapes_constant(probes, 0xD2),
        );

        println!(
            "blind spot, ramp vs metronome (same mean gap {}):",
            GAPS_RAMP_MEAN
        );
        println!(
            "  ramp      pe={:.4} drift={:.6} rate={:.4} repeat={:.3} expl={:.3} conv={:.2}",
            ramp.rhythm_pe,
            ramp.drift,
            ramp.rate_per_sec,
            ramp.repeat_ratio,
            ramp.exploration,
            ramp.convergence
        );
        println!(
            "  metronome pe={:.4} drift={:.6} rate={:.4} repeat={:.3} expl={:.3} conv={:.2}",
            metronome.rhythm_pe,
            metronome.drift,
            metronome.rate_per_sec,
            metronome.repeat_ratio,
            metronome.exploration,
            metronome.convergence
        );

        // The old columns: identical, including the one that should have seen it.
        assert_eq!(
            ramp.rhythm_pe, metronome.rhythm_pe,
            "the entropy reads the ramp exactly as the metronome — the blind spot"
        );
        assert_eq!(ramp.rhythm_pe, 0.0);
        assert_eq!(metronome.rhythm_pe, 0.0);
        assert_eq!(ramp.rate_per_sec, metronome.rate_per_sec);
        assert_eq!(ramp.repeat_ratio, metronome.repeat_ratio);
        assert_eq!(ramp.exploration, metronome.exploration);
        assert_eq!(ramp.convergence, metronome.convergence);
        assert_eq!(
            ramp.sufficiency.gaps_in_window,
            metronome.sufficiency.gaps_in_window
        );

        // The new column: it is the whole difference between them.
        assert_eq!(
            ramp.drift, GAPS_RAMP_DRIFT,
            "the ramp's trend is its exact total relative change"
        );
        assert_eq!(
            metronome.drift, 0.0,
            "a steady cadence has no trend at all — exactly 0.0"
        );
        assert!(
            ramp.drift > 0.4,
            "the ramp must read high on drift: {:.6}",
            ramp.drift
        );
    }

    /// Gate 2 for the sixth column: it and `rhythm_pe` move independently.
    ///
    /// Four feeds of the same length, through the real sensor:
    ///
    /// | signal | `rhythm_pe` | `drift` |
    /// |---|---|---|
    /// | jittered (flat mean) | high | low |
    /// | jittered (rising mean) | high (unchanged) | high |
    /// | palindromic zigzag | high | exactly `0.0` |
    /// | monotone ramp | exactly `0.0` | high |
    ///
    /// The jittered pair is the "one moves while the other holds" case: the same
    /// arrangement, a genuinely different trend. The zigzag/ramp pair is the
    /// "opposite directions" case: the zigzag out-reads the ramp on arrangement
    /// and under-reads it on trend, so neither ordering predicts the other.
    #[test]
    fn drift_and_rhythm_move_independently() {
        let (_bus, sensor) = sensor();
        let probes = PROBE_WINDOW + 1;

        let jitter_flat = gaps_jitter_at(2_500, 20, PROBE_WINDOW);
        let jitter_ramp: Vec<u64> = jitter_flat
            .iter()
            .enumerate()
            .map(|(index, gap)| gap + 32 * index as u64)
            .collect();

        let jitter_flat = feed_window(
            &sensor,
            addr(1),
            &jitter_flat,
            &shapes_constant(probes, 0xD4),
        );
        let jitter_ramp = feed_window(
            &sensor,
            addr(2),
            &jitter_ramp,
            &shapes_constant(probes, 0xD4),
        );
        let zigzag = feed_window(
            &sensor,
            addr(3),
            &gaps_palindromic_zigzag(PROBE_WINDOW),
            &shapes_constant(probes, 0xD4),
        );
        let ramp = feed_window(
            &sensor,
            addr(4),
            &gaps_ramp(PROBE_WINDOW),
            &shapes_constant(probes, 0xD4),
        );

        println!(
            "independence: jitter_flat  pe={:.4} drift={:.6}",
            jitter_flat.rhythm_pe, jitter_flat.drift
        );
        println!(
            "independence: jitter_ramp  pe={:.4} drift={:.6}",
            jitter_ramp.rhythm_pe, jitter_ramp.drift
        );
        println!(
            "independence: zigzag       pe={:.4} drift={:.6}",
            zigzag.rhythm_pe, zigzag.drift
        );
        println!(
            "independence: ramp         pe={:.4} drift={:.6}",
            ramp.rhythm_pe, ramp.drift
        );

        // (a) One moves while the other holds. The rising mean is *not* a change
        // of arrangement: the ±20% jitter band reads as organic either way.
        assert!(
            jitter_flat.rhythm_pe > 0.9 && jitter_ramp.rhythm_pe > 0.9,
            "both jittered feeds are arrangement-rich: {:.4} / {:.4}",
            jitter_flat.rhythm_pe,
            jitter_ramp.rhythm_pe
        );
        assert!(
            (jitter_flat.rhythm_pe - jitter_ramp.rhythm_pe).abs() < 0.005,
            "adding a smooth trend must leave the arrangement reading where it \
             was: {:.4} vs {:.4}",
            jitter_flat.rhythm_pe,
            jitter_ramp.rhythm_pe
        );
        assert!(
            jitter_ramp.drift - jitter_flat.drift > 0.5,
            "…while the trend reading moves a long way: {:.6} vs {:.6}",
            jitter_flat.drift,
            jitter_ramp.drift
        );

        // (b) Arrangement-rich with *no* trend at all: a zigzag whose sequence
        // is its own reverse has a least-squares slope of exactly zero.
        assert!(
            zigzag.rhythm_pe > 0.5,
            "the palindromic zigzag is arrangement-rich: {:.4}",
            zigzag.rhythm_pe
        );
        assert_eq!(
            zigzag.drift, 0.0,
            "a reversal-symmetric zigzag has exactly zero trend, however varied \
             its arrangement"
        );

        // (c) Opposite directions: zigzag ≫ ramp on arrangement, ramp ≫ zigzag
        // on trend.
        assert!(zigzag.rhythm_pe > ramp.rhythm_pe);
        assert!(ramp.drift > zigzag.drift);
        println!(
            "independence: zigzag leads on rhythm (pe {:.4} vs {:.4}) while the \
             ramp leads on trend (drift {:.6} vs {:.6})",
            zigzag.rhythm_pe, ramp.rhythm_pe, ramp.drift, zigzag.drift
        );
    }

    /// Gate 3 for the sixth column: it is not a function of any other column.
    ///
    /// Two independent demonstrations, with the numbers printed:
    ///
    /// * **Same `rhythm_pe`, different `drift`.** The E30 zigzag and the same
    ///   zigzag tick carried on a ramp have the *same* `rhythm_pe` (0.3869 —
    ///   both alternate between two ordinal patterns) but trends of `0.0718`
    ///   and `0.4010`. `rhythm_pe` cannot tell these probers apart; `drift` can.
    /// * **Equal `rate_per_sec`, different `drift`.** A ramp and a metronome
    ///   with the same mean gap burn the same budget (identical `rate_per_sec`)
    ///   and read the same `rhythm_pe` (both `0.0`) while their `drift` is
    ///   `0.4026` against `0.0`. A zigzag around the same mean gap completes the
    ///   picture: equal rate again, a different `rhythm_pe` *and* a different
    ///   `drift`.
    ///
    /// Together: no other column is a proxy for `drift`, and `drift` is not a
    /// proxy for any of them.
    #[test]
    fn drift_is_not_a_function_of_any_existing_dimension() {
        let (_bus, sensor) = sensor();
        let probes = PROBE_WINDOW + 1;
        let zigzag_around = |amplitude: u64, count: usize| -> Vec<u64> {
            (0..count)
                .map(|i| {
                    if i % 2 == 0 {
                        GAPS_RAMP_MEAN - amplitude
                    } else {
                        GAPS_RAMP_MEAN + amplitude
                    }
                })
                .collect()
        };

        let zigzag = feed_window(
            &sensor,
            addr(1),
            &gaps_e30_zigzag(PROBE_WINDOW),
            &shapes_constant(probes, 0xD5),
        );
        let ramped_zigzag = feed_window(
            &sensor,
            addr(2),
            &gaps_ramp_with_zigzag_tick(PROBE_WINDOW),
            &shapes_constant(probes, 0xD5),
        );
        let ramp = feed_window(
            &sensor,
            addr(3),
            &gaps_ramp(PROBE_WINDOW),
            &shapes_constant(probes, 0xD5),
        );
        let metronome = feed_window(
            &sensor,
            addr(4),
            &gaps_periodic(PROBE_WINDOW, GAPS_RAMP_MEAN),
            &shapes_constant(probes, 0xD5),
        );
        let zigzag_same_rate = feed_window(
            &sensor,
            addr(5),
            &zigzag_around(800, PROBE_WINDOW),
            &shapes_constant(probes, 0xD5),
        );

        println!(
            "not-a-duplicate: zigzag          pe={:.4} drift={:.6} rate={:.4}",
            zigzag.rhythm_pe, zigzag.drift, zigzag.rate_per_sec
        );
        println!(
            "not-a-duplicate: ramped_zigzag   pe={:.4} drift={:.6} rate={:.4}",
            ramped_zigzag.rhythm_pe, ramped_zigzag.drift, ramped_zigzag.rate_per_sec
        );
        println!(
            "not-a-duplicate: ramp            pe={:.4} drift={:.6} rate={:.4}",
            ramp.rhythm_pe, ramp.drift, ramp.rate_per_sec
        );
        println!(
            "not-a-duplicate: metronome       pe={:.4} drift={:.6} rate={:.4}",
            metronome.rhythm_pe, metronome.drift, metronome.rate_per_sec
        );
        println!(
            "not-a-duplicate: zigzag_same_rate pe={:.4} drift={:.6} rate={:.4}",
            zigzag_same_rate.rhythm_pe, zigzag_same_rate.drift, zigzag_same_rate.rate_per_sec
        );

        // (i) Same rhythm_pe, different drift. The shared reading is exact: both
        // signals alternate between two ordinal patterns with 31 occurrences
        // each, so the entropy is bit-identical.
        assert!(
            (zigzag.rhythm_pe - ramped_zigzag.rhythm_pe).abs() < 1e-12,
            "the zigzag and the ramped zigzag must share a rhythm reading: \
             {:.6} vs {:.6}",
            zigzag.rhythm_pe,
            ramped_zigzag.rhythm_pe
        );
        assert!(
            ramped_zigzag.drift > 5.0 * zigzag.drift,
            "…and the trend reading must separate them anyway: {:.6} vs {:.6}",
            ramped_zigzag.drift,
            zigzag.drift
        );

        // (ii) Equal rate_per_sec, different drift. Two signals with the same
        // mean gap burn the same budget; the trend is not derivable from it.
        assert_eq!(
            ramp.rate_per_sec, zigzag_same_rate.rate_per_sec,
            "the ramp and this zigzag have the same mean gap, so the same rate"
        );
        assert_eq!(
            ramp.rate_per_sec, metronome.rate_per_sec,
            "as does the metronome at the ramp's mean gap"
        );
        assert!(
            ramp.drift > 10.0 * zigzag_same_rate.drift && ramp.drift > metronome.drift,
            "equal rates, different trends: ramp {:.6}, zigzag {:.6}, metronome {:.6}",
            ramp.drift,
            zigzag_same_rate.drift,
            metronome.drift
        );

        // (iii) All five pre-existing columns identical, only `drift` different:
        // the ramp and the metronome at its mean gap.
        assert_eq!(ramp.rhythm_pe, metronome.rhythm_pe);
        assert_eq!(ramp.repeat_ratio, metronome.repeat_ratio);
        assert_eq!(ramp.exploration, metronome.exploration);
        assert_eq!(ramp.convergence, metronome.convergence);
        assert_eq!(ramp.rate_per_sec, metronome.rate_per_sec);
        assert_ne!(
            ramp.drift, metronome.drift,
            "the sixth column is the only thing that separates these two feeds"
        );

        // (iv) …and the reverse: equal drift, different rhythm_pe. A ramp and the
        // same ramp carrying a zigzag tick trend identically while their
        // arrangements are nothing alike.
        assert!(
            (ramp.drift - ramped_zigzag.drift).abs() < 0.01,
            "the tick barely moves the trend reading: {:.6} vs {:.6}",
            ramp.drift,
            ramped_zigzag.drift
        );
        assert!(
            (ramp.rhythm_pe - ramped_zigzag.rhythm_pe).abs() > 0.3,
            "…while the arrangement reading is completely different: {:.4} vs {:.4}",
            ramp.rhythm_pe,
            ramped_zigzag.rhythm_pe
        );
    }

    /// Gate 4 for the sixth column — the limit, stated rather than papered over.
    ///
    /// `drift` is a **magnitude**: the total relative change in gap, unsigned.
    /// A prober smoothly accelerating and one smoothly decelerating over the same
    /// span therefore read the *same* value, and no combination of the six
    /// columns distinguishes them. That is a known remaining gap. It is not
    /// fixed by putting a sign on `drift` — "how much" and "which way" are
    /// separate readings, and fusing them is the anti-collapse violation this
    /// module exists to avoid. If the direction is ever wanted it belongs in a
    /// **seventh, separate, signed dimension**; this test pins the current
    /// behaviour so that dimension gets *added beside* this one.
    #[test]
    fn drift_is_a_magnitude_and_does_not_capture_direction() {
        let (_bus, sensor) = sensor();
        let probes = PROBE_WINDOW + 1;

        // The same gaps, one series reversed: same mean, same multiset, opposite
        // direction.
        let accelerating = gaps_ramp(PROBE_WINDOW);
        let decelerating: Vec<u64> = gaps_ramp(PROBE_WINDOW).into_iter().rev().collect();

        let accelerating = feed_window(
            &sensor,
            addr(1),
            &accelerating,
            &shapes_constant(probes, 0xD6),
        );
        let decelerating = feed_window(
            &sensor,
            addr(2),
            &decelerating,
            &shapes_constant(probes, 0xD6),
        );

        println!(
            "direction: accelerating (2000→3008) pe={:.4} drift={:.6}",
            accelerating.rhythm_pe, accelerating.drift
        );
        println!(
            "direction: decelerating (3008→2000) pe={:.4} drift={:.6}",
            decelerating.rhythm_pe, decelerating.drift
        );

        assert!(
            accelerating.drift > 0.4,
            "the trend must be large for this test to say anything: {:.6}",
            accelerating.drift
        );
        assert_eq!(
            accelerating.drift, decelerating.drift,
            "drift is unsigned: accelerating and decelerating probers read the same"
        );
        assert_eq!(accelerating.rhythm_pe, decelerating.rhythm_pe);
        assert_eq!(accelerating.rate_per_sec, decelerating.rate_per_sec);
        // Not just the same drift — the same profile on every column. Fed to two
        // sensors at the *same* address so the profiles are directly comparable
        // (the `source` field is an identity, not a reading).
        let forward_sensor = ProbeSensor::new(Arc::new(spiderweb::Bus::open().publisher()));
        let backward_sensor = ProbeSensor::new(Arc::new(spiderweb::Bus::open().publisher()));
        let forward = feed_window(
            &forward_sensor,
            addr(7),
            &gaps_ramp(PROBE_WINDOW),
            &shapes_constant(probes, 0xD6),
        );
        let backward = feed_window(
            &backward_sensor,
            addr(7),
            &gaps_ramp(PROBE_WINDOW)
                .into_iter()
                .rev()
                .collect::<Vec<u64>>(),
            &shapes_constant(probes, 0xD6),
        );
        assert_eq!(
            forward, backward,
            "no column of this profile carries the direction of the trend"
        );
        // The reading is bounded below by construction, so a consumer cannot even
        // recover a sign by looking for negatives.
        assert_all_dimensions_in_range(&forward);
    }

    // -----------------------------------------------------------------------
    // Gate 3 — converging vs wandering
    // -----------------------------------------------------------------------

    #[test]
    fn convergence_distinguishes_settled_drifting_and_wandering() {
        let (_bus, sensor) = sensor();
        let gaps = gaps_periodic(PROBE_WINDOW, 25);
        let probes = PROBE_WINDOW + 1;

        let settled = feed_window(
            &sensor,
            addr(1),
            &gaps,
            &shapes_cycle(probes, &[100, 101, 102, 103]),
        );
        let drifting = feed_window(&sensor, addr(2), &gaps, &shapes_drifting_cycle(probes));
        let wandering = feed_window(&sensor, addr(3), &gaps, &shapes_distinct(probes));

        println!(
            "convergence: settled={:.4} drifting={:.4} wandering={:.4}",
            settled.convergence, drifting.convergence, wandering.convergence
        );

        assert!(
            settled.convergence > 0.9,
            "a prober repeating one distribution is settled: {:.4}",
            settled.convergence
        );
        assert!(
            wandering.convergence < 0.1,
            "a prober inventing a new shape every probe has changed nothing: {:.4}",
            wandering.convergence
        );
        // The pair that differs ONLY in convergence: same vocabulary, same
        // coverage, same repetition, same rhythm — different distribution over
        // successive windows.
        assert_eq!(settled.repeat_ratio, drifting.repeat_ratio);
        assert_eq!(settled.exploration, drifting.exploration);
        assert_eq!(settled.rhythm_pe, drifting.rhythm_pe);
        assert_eq!(settled.rate_per_sec, drifting.rate_per_sec);
        assert!(
            (drifting.convergence - 0.5).abs() < 1e-9,
            "a half-changed distribution reads 0.5 here: {:.4}",
            drifting.convergence
        );
        assert!(settled.sufficiency.epochs_compared >= 1);
    }

    #[test]
    fn convergence_rises_as_a_prober_settles() {
        let (_bus, sensor) = sensor();
        let source = addr(1);
        let mut at = 1_000_000u64;
        let mut send = |shape: u64| {
            sensor.observe(ProbeEvent {
                source,
                at_micros: at,
                shape,
            });
            at += 25;
        };

        // Probe 1..32: a new shape every time (still looking).
        for i in 0..EPOCH_PROBES {
            send(0x2000 + i as u64);
        }
        let before = sensor.profile(source).unwrap();
        assert_eq!(
            before.sufficiency.epochs_compared, 0,
            "one epoch cannot be compared with anything"
        );
        assert_eq!(before.convergence, 0.0);

        // Probe 33..64: it has settled on a fixed cycle.
        for i in 0..EPOCH_PROBES {
            send(300 + (i % 4) as u64);
        }
        let transition = sensor.profile(source).unwrap();
        assert_eq!(transition.sufficiency.epochs_compared, 1);
        assert!(
            transition.convergence < 0.1,
            "the window that changed reads as unsettled: {:.4}",
            transition.convergence
        );

        // Probe 65..96: another identical window. Now the distribution has
        // flattened, and the reading says so.
        for i in 0..EPOCH_PROBES {
            send(300 + (i % 4) as u64);
        }
        let settled = sensor.profile(source).unwrap();
        assert_eq!(settled.sufficiency.epochs_compared, 2);
        assert!(
            settled.convergence > 0.9,
            "two identical windows read as settled: {:.4}",
            settled.convergence
        );
    }

    // -----------------------------------------------------------------------
    // Gate 4 — the anti-collapse gate
    // -----------------------------------------------------------------------

    #[test]
    fn no_single_weighting_holds_all_readings() {
        let (_bus, sensor) = sensor();
        let gaps = gaps_periodic(PROBE_WINDOW, 25);
        let organic = gaps_organic(PROBE_WINDOW, E30_ORGANIC_SEED);
        let probes = PROBE_WINDOW + 1;

        // Fourteen cases, every one of them built by driving the real sensor.
        // `drifting_ramp`/`steady_metronome` are a deliberate minimal pair: the
        // same mean gap (2_504) and the same shapes, so they differ in exactly
        // one column — `drift` — and are identical on the other five.
        let cases: Vec<(&str, ProbeProfile)> = vec![
            (
                "periodic_beacon",
                feed_window(&sensor, addr(1), &gaps, &shapes_constant(probes, 0xA1)),
            ),
            (
                "alternating_cadence",
                feed_window(
                    &sensor,
                    addr(2),
                    &gaps_alternating(PROBE_WINDOW),
                    &shapes_constant(probes, 0xA1),
                ),
            ),
            (
                "driller",
                feed_window(&sensor, addr(3), &organic, &shapes_constant(probes, 0xA2)),
            ),
            (
                "sweeper",
                feed_window(&sensor, addr(4), &organic, &shapes_distinct(probes)),
            ),
            (
                "jittered_beacon",
                feed_window(
                    &sensor,
                    addr(5),
                    &gaps_e30_jittered(PROBE_WINDOW),
                    &shapes_constant(probes, 0xA3),
                ),
            ),
            (
                "burst_scanner",
                feed_window(
                    &sensor,
                    addr(6),
                    &gaps_e30_burst(PROBE_WINDOW),
                    &shapes_distinct(probes),
                ),
            ),
            (
                "zigzag_prober",
                feed_window(
                    &sensor,
                    addr(7),
                    &gaps_e30_zigzag(PROBE_WINDOW),
                    &shapes_constant(probes, 0xA4),
                ),
            ),
            (
                "organic_child",
                feed_window(
                    &sensor,
                    addr(8),
                    &gaps_organic(PROBE_WINDOW, 0x5EED),
                    &shapes_distinct(probes),
                ),
            ),
            (
                "converged_cycle",
                feed_window(
                    &sensor,
                    addr(9),
                    &gaps,
                    &shapes_cycle(probes, &[100, 101, 102, 103]),
                ),
            ),
            (
                "drifting_cycle",
                feed_window(&sensor, addr(10), &gaps, &shapes_drifting_cycle(probes)),
            ),
            (
                "low_rate_sweeper",
                feed_window(
                    &sensor,
                    addr(11),
                    &gaps_periodic(PROBE_WINDOW, 100_000),
                    &shapes_distinct(probes),
                ),
            ),
            (
                "high_rate_beacon",
                feed_window(
                    &sensor,
                    addr(12),
                    &gaps_periodic(PROBE_WINDOW, 5),
                    &shapes_constant(probes, 0xA5),
                ),
            ),
            (
                "drifting_ramp",
                feed_window(
                    &sensor,
                    addr(13),
                    &gaps_ramp(PROBE_WINDOW),
                    &shapes_constant(probes, 0xA6),
                ),
            ),
            (
                "steady_metronome",
                feed_window(
                    &sensor,
                    addr(14),
                    &gaps_periodic(PROBE_WINDOW, GAPS_RAMP_MEAN),
                    &shapes_constant(probes, 0xA6),
                ),
            ),
        ];

        for (name, profile) in &cases {
            assert_all_dimensions_in_range(profile);
            println!(
                "{name:<20} pe={:.3} drift={:.3} repeat={:.3} expl={:.3} conv={:.2} rate={:.0}",
                profile.rhythm_pe,
                profile.drift,
                profile.repeat_ratio,
                profile.exploration,
                profile.convergence,
                profile.rate_per_sec
            );
        }

        // A reading the responder needs. These are *dimension readings*, never
        // produced by the sensor: the sensor ranks nothing. Each delta is the
        // measured difference between two cases, in the order "A must outrank B"
        // on that reading.
        let by_name = |name: &str| {
            cases
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, p)| p.clone())
                .expect("case exists")
        };
        let delta = |a: &ProbeProfile, b: &ProbeProfile| {
            [
                a.rhythm_pe - b.rhythm_pe,
                a.drift - b.drift,
                a.repeat_ratio - b.repeat_ratio,
                a.exploration - b.exploration,
                a.convergence - b.convergence,
                a.rate_per_sec - b.rate_per_sec,
            ]
        };

        let periodic_beacon = by_name("periodic_beacon");
        let alternating_cadence = by_name("alternating_cadence");
        let driller = by_name("driller");
        let sweeper = by_name("sweeper");
        let converged_cycle = by_name("converged_cycle");
        let drifting_cycle = by_name("drifting_cycle");
        let low_rate_sweeper = by_name("low_rate_sweeper");
        let high_rate_beacon = by_name("high_rate_beacon");
        let drifting_ramp = by_name("drifting_ramp");
        let steady_metronome = by_name("steady_metronome");

        let requirements: [(&str, [f64; 6]); 7] = [
            (
                "varied rhythm (alternating cadence > metronome)",
                delta(&alternating_cadence, &periodic_beacon),
            ),
            (
                "settled (converged cycle > drifting cycle)",
                delta(&converged_cycle, &drifting_cycle),
            ),
            ("repetition (driller > sweeper)", delta(&driller, &sweeper)),
            ("coverage (sweeper > driller)", delta(&sweeper, &driller)),
            (
                "budget burn (high-rate beacon > low-rate sweeper)",
                delta(&high_rate_beacon, &low_rate_sweeper),
            ),
            (
                "coverage (low-rate sweeper > high-rate beacon)",
                delta(&low_rate_sweeper, &high_rate_beacon),
            ),
            (
                "cadence trend (drifting ramp > steady metronome)",
                delta(&drifting_ramp, &steady_metronome),
            ),
        ];

        // Two settings for the search, so the result cannot be blamed on
        // magnitudes: the raw dimensions (where an unbounded rate can dominate),
        // and min-max normalised dimensions (each scaled to [0, 1] across the
        // cases — the most generous thing a fusion designer could do).
        let raw: Vec<[f64; 6]> = cases
            .iter()
            .map(|(_, p)| {
                [
                    p.rhythm_pe,
                    p.drift,
                    p.repeat_ratio,
                    p.exploration,
                    p.convergence,
                    p.rate_per_sec,
                ]
            })
            .collect();
        let mut normalised = raw.clone();
        for dimension in 0..6 {
            let min = raw
                .iter()
                .map(|d| d[dimension])
                .fold(f64::INFINITY, f64::min);
            let max = raw
                .iter()
                .map(|d| d[dimension])
                .fold(f64::NEG_INFINITY, f64::max);
            if max > min {
                for dims in &mut normalised {
                    dims[dimension] = (dims[dimension] - min) / (max - min);
                }
            }
        }

        for (label, vectors) in [("raw", &raw), ("normalised", &normalised)] {
            let survey = survey_weightings(vectors, &requirements);
            println!(
                "{label}: {} weightings tried; satisfied all seven: {}; invents a total order: {}",
                survey.total,
                survey.satisfied_all,
                survey.separating.is_some()
            );
            for (index, (requirement, _)) in requirements.iter().enumerate() {
                println!(
                    "  [{label}] satisfied by {:>5} / {} — {requirement}",
                    survey.satisfied[index], survey.total
                );
            }
            if let Some(w) = survey.best {
                println!(
                    "  [{label}] best weighting {w:?} holds {} of 7 readings",
                    survey.best_score
                );
            }

            assert_eq!(
                survey.total, 531_440,
                "the search must cover the whole 1/8-granularity six-dimension grid \
                 (9^6 − 1)"
            );
            assert_eq!(
                survey.repetition_and_coverage, 0,
                "[{label}] no weighting can hold both the repetition and the coverage reading"
            );
            assert_eq!(
                survey.burn_and_coverage, 0,
                "[{label}] no weighting can hold both the budget-burn and the coverage reading"
            );
            assert_eq!(
                survey.satisfied_all, 0,
                "[{label}] a single weighted sum must not be able to answer every documented reading"
            );
            assert!(
                survey.best_score < requirements.len(),
                "[{label}] some weighting holds every reading — that would be the collapse finding"
            );
            // The new reading is answerable *only* by a weighting that carries
            // the new column: a weighted sum that ignores `drift` cannot answer
            // it at all, exactly as one that ignores `rhythm_pe` cannot answer
            // the rhythm reading. That is what "load-bearing" means here, and it
            // is the count of weightings with a non-zero drift weight
            // (`8 × 9^5 = 472_392`).
            assert_eq!(
                survey.satisfied[6], 472_392,
                "[{label}] the cadence-trend reading must be answerable exactly when \
                 the weighting gives the drift column a non-zero weight"
            );
            // The rhythm and convergence readings are NOT a rigged pair: a
            // weighting can hold both at once (and the best one above does).
            // The collapse only becomes impossible once the readings that
            // describe *shape behaviour* have to be answered too.
            assert!(
                survey.varied_and_settled > 0,
                "[{label}] weightings can hold the rhythm and convergence readings together"
            );

            // The honest finding, reported rather than hidden: making the
            // fourteen cases pairwise distinct is cheap for a weighted sum in six
            // dimensions, and such weightings do exist. Distinctness is
            // therefore NOT the thing that matters — the point is that even a
            // weighting that separates every case cannot answer the readings the
            // responder acts on, and the order it invents is an artefact of the
            // weights, not a property of the traffic.
            if let Some(w) = survey.separating {
                let wf = w.map(f64::from);
                let mut ranked: Vec<(&str, f64)> = cases
                    .iter()
                    .map(|(name, profile)| (*name, weighted(&driller_dims(profile), wf)))
                    .collect();
                ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
                let order: Vec<&str> = ranked.iter().map(|(name, _)| *name).collect();
                let lost: Vec<&str> = requirements
                    .iter()
                    .filter(|(_, delta)| weighted(delta, wf) <= 0.0)
                    .map(|(name, _)| *name)
                    .collect();
                println!(
                    "  [{label}] FINDING: weighting {w:?} gives all fourteen cases distinct \
                     sums (order: {order:?}), yet it still cannot answer {} of the 7 \
                     readings: {lost:?}",
                    lost.len()
                );
                assert!(
                    lost.len() >= 2,
                    "[{label}] a separating weighting that answers every reading would be the collapse finding"
                );
            } else {
                println!("  [{label}] no weighting even makes all fourteen sums distinct");
            }
        }

        // The task's litmus test, made concrete: two reasonable weightings, two
        // cases, opposite orders. Whichever the responder picks, it loses a
        // reading it needs.
        let repetition_only = [0.0, 0.0, 1.0, 0.0, 0.0, 0.0];
        let coverage_only = [0.0, 0.0, 0.0, 1.0, 0.0, 0.0];
        let burn_only = [0.0, 0.0, 0.0, 0.0, 0.0, 1.0];
        // The sixth column's own litmus, on the pair the five old columns tie on.
        let rhythm_only = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let drift_only = [0.0, 1.0, 0.0, 0.0, 0.0, 0.0];

        let driller_repetition = weighted(&driller_dims(&driller), repetition_only);
        let sweeper_repetition = weighted(&driller_dims(&sweeper), repetition_only);
        let driller_coverage = weighted(&driller_dims(&driller), coverage_only);
        let sweeper_coverage = weighted(&driller_dims(&sweeper), coverage_only);
        println!(
            "driller/sweeper under w=repeat: {driller_repetition:.4} vs {sweeper_repetition:.4}; \
             under w=exploration: {driller_coverage:.4} vs {sweeper_coverage:.4}"
        );
        assert!(driller_repetition > sweeper_repetition);
        assert!(sweeper_coverage > driller_coverage);

        let beacon_burn = weighted(&driller_dims(&high_rate_beacon), burn_only);
        let sweeper_burn = weighted(&driller_dims(&low_rate_sweeper), burn_only);
        println!(
            "high-rate beacon/low-rate sweeper under w=rate: {beacon_burn:.1} vs {sweeper_burn:.1}"
        );
        assert!(beacon_burn > sweeper_burn);
        assert!(sweeper_coverage > driller_coverage);

        // The sixth column's own litmus, on the one pair the other five columns
        // cannot separate at all: identical position under the arrangement
        // reading, fully separated under the trend reading.
        let ramp_rhythm = weighted(&driller_dims(&drifting_ramp), rhythm_only);
        let metronome_rhythm = weighted(&driller_dims(&steady_metronome), rhythm_only);
        let ramp_drift = weighted(&driller_dims(&drifting_ramp), drift_only);
        let metronome_drift = weighted(&driller_dims(&steady_metronome), drift_only);
        println!(
            "drifting ramp/steady metronome under w=rhythm: {ramp_rhythm:.4} vs {metronome_rhythm:.4} \
             (a tie — the blind spot); under w=drift: {ramp_drift:.4} vs {metronome_drift:.4}"
        );
        assert_eq!(
            ramp_rhythm, metronome_rhythm,
            "the old rhythm column ranks a drifting ramp exactly as a metronome"
        );
        assert!(ramp_drift > metronome_drift);
    }

    /// The six dimensions of a profile, in the order the weightings assume.
    fn driller_dims(profile: &ProbeProfile) -> [f64; 6] {
        [
            profile.rhythm_pe,
            profile.drift,
            profile.repeat_ratio,
            profile.exploration,
            profile.convergence,
            profile.rate_per_sec,
        ]
    }

    fn weighted(dims: &[f64; 6], weights: [f64; 6]) -> f64 {
        dims.iter().zip(weights).map(|(d, w)| d * w).sum()
    }

    struct Survey {
        total: usize,
        satisfied: [usize; 7],
        satisfied_all: usize,
        /// Requirements 3 and 4 are the *same* measured difference with
        /// opposite required signs, so this counter is zero by construction —
        /// stated openly, because it is the core of the argument rather than a
        /// trick: one number has to choose which of two documented readings it
        /// answers, and that choice is policy imposed on the reading.
        repetition_and_coverage: usize,
        burn_and_coverage: usize,
        /// Requirements 1 and 2 *can* be held together; the impossibility is not
        /// a trivial contradiction between every pair.
        varied_and_settled: usize,
        separating: Option<[i32; 6]>,
        best: Option<[i32; 6]>,
        best_score: usize,
    }

    /// Try every non-negative weighting at 1/8 granularity (0..=8 per dimension,
    /// 9^6 − 1 = 531,440 candidates) against the required readings.
    fn survey_weightings(vectors: &[[f64; 6]], requirements: &[(&str, [f64; 6]); 7]) -> Survey {
        let mut survey = Survey {
            total: 0,
            satisfied: [0; 7],
            satisfied_all: 0,
            repetition_and_coverage: 0,
            burn_and_coverage: 0,
            varied_and_settled: 0,
            separating: None,
            best: None,
            best_score: 0,
        };
        for a in 0..=8 {
            for b in 0..=8 {
                for c in 0..=8 {
                    for d in 0..=8 {
                        for e in 0..=8 {
                            for f in 0..=8 {
                                let weights = [a, b, c, d, e, f];
                                if weights.iter().all(|w| *w == 0) {
                                    continue;
                                }
                                survey.total += 1;
                                let w = weights.map(f64::from);
                                let mut score = 0usize;
                                let mut met = [false; 7];
                                for (index, (_, delta)) in requirements.iter().enumerate() {
                                    if weighted(delta, w) > 0.0 {
                                        met[index] = true;
                                        survey.satisfied[index] += 1;
                                        score += 1;
                                    }
                                }
                                if met[2] && met[3] {
                                    survey.repetition_and_coverage += 1;
                                }
                                if met[4] && met[5] {
                                    survey.burn_and_coverage += 1;
                                }
                                if met[0] && met[1] {
                                    survey.varied_and_settled += 1;
                                }
                                if met.iter().all(|m| *m) {
                                    survey.satisfied_all += 1;
                                }
                                if survey.separating.is_none() {
                                    let sums: Vec<f64> =
                                        vectors.iter().map(|dims| weighted(dims, w)).collect();
                                    let mut distinct = true;
                                    'outer: for i in 0..sums.len() {
                                        for j in (i + 1)..sums.len() {
                                            if sums[i] == sums[j] {
                                                distinct = false;
                                                break 'outer;
                                            }
                                        }
                                    }
                                    if distinct {
                                        survey.separating = Some(weights);
                                    }
                                }
                                if score > survey.best_score {
                                    survey.best_score = score;
                                    survey.best = Some(weights);
                                }
                            }
                        }
                    }
                }
            }
        }
        survey
    }

    #[test]
    fn profile_carries_the_dimensions_separately_and_no_fused_score() {
        let (_bus, sensor) = sensor();
        let profile = feed_window(
            &sensor,
            addr(1),
            &gaps_periodic(PROBE_WINDOW, 25),
            &shapes_constant(PROBE_WINDOW + 1, 0x1),
        );
        let value = serde_json::to_value(&profile).expect("profile serialises");
        let object = value.as_object().expect("profile is an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "convergence",
                "drift",
                "exploration",
                "last_seen_micros",
                "rate_per_sec",
                "repeat_ratio",
                "rhythm_pe",
                "source",
                "sufficiency",
            ],
            "the published reading must expose the six columns, and nothing that \
             combines them"
        );

        // Both cadence readings of the *same* gap series reach the wire, as two
        // separate numbers. A metronome is 0.0 on each — which is exactly why
        // neither may be read alone.
        assert_eq!(profile.rhythm_pe, 0.0);
        assert_eq!(profile.drift, 0.0);
    }

    // -----------------------------------------------------------------------
    // Gate 5 — bounded
    // -----------------------------------------------------------------------

    #[test]
    fn flood_does_not_grow_the_footprint() {
        let (_bus, sensor) = sensor();
        let source = addr(1);

        let one_record = sensor_footprint_after_probe(&sensor, source);
        for i in 0..200_000u64 {
            sensor.observe(ProbeEvent {
                source,
                at_micros: 1_000_000 + i * 3,
                shape: i % 7,
            });
        }

        assert_eq!(sensor.tracked_sources(), 1, "one source, one record");
        assert_eq!(
            sensor.footprint_bytes(),
            one_record,
            "the footprint must not move when the attacker sends more traffic"
        );
        println!(
            "footprint: one SourceRecord = {} bytes; max_sources = {} → fixed ceiling {} bytes",
            std::mem::size_of::<SourceRecord>(),
            sensor.config().max_sources,
            sensor.config().max_sources * std::mem::size_of::<SourceRecord>()
        );
        assert!(
            std::mem::size_of::<SourceRecord>() < 4096,
            "a source record must be a small fixed struct: {} bytes",
            std::mem::size_of::<SourceRecord>()
        );

        let profile = sensor.profile(source).expect("source is tracked");
        assert_all_dimensions_in_range(&profile);
        assert_eq!(
            profile.sufficiency.probes_in_window as usize, PROBE_WINDOW,
            "the window saturates at its bound and stops there"
        );
        assert_eq!(profile.sufficiency.gaps_in_window as usize, PROBE_WINDOW);
        assert_eq!(profile.sufficiency.probes_seen, 200_001);
    }

    fn sensor_footprint_after_probe(sensor: &ProbeSensor, source: SocketAddr) -> usize {
        sensor.observe(ProbeEvent {
            source,
            at_micros: 0,
            shape: 0,
        });
        sensor.footprint_bytes()
    }

    #[test]
    fn source_map_is_capped_and_evicts_the_stalest() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let sensor = ProbeSensor::with_config(
            bus,
            ProbeSensorConfig {
                max_sources: 4,
                source_ttl_micros: 1_000_000,
            },
        );

        // Five distinct sources, oldest first. The cap is 4, so the first one
        // is displaced.
        for i in 0..5u64 {
            sensor.observe(ProbeEvent {
                source: addr(100 + i as u16),
                at_micros: 1_000 + i * 10,
                shape: i,
            });
        }
        assert_eq!(sensor.tracked_sources(), 4);
        assert!(
            sensor.profile(addr(100)).is_none(),
            "the stalest source is the one evicted"
        );
        assert!(sensor.profile(addr(104)).is_some());

        // A flood of one source cannot displace anything at all.
        for i in 0..50_000u64 {
            sensor.observe(ProbeEvent {
                source: addr(104),
                at_micros: 2_000 + i,
                shape: 1,
            });
        }
        assert_eq!(sensor.tracked_sources(), 4);

        // TTL: 100 ms of quiet past the 1 s limit forgets an idle source.
        let dropped = sensor.prune_expired(2_000 + 50_000 + 1_000_000);
        assert_eq!(dropped, 4, "everything idle past the TTL is forgotten");
        assert_eq!(sensor.tracked_sources(), 0);
        assert!(sensor.footprint_bytes() == 0);
    }

    // -----------------------------------------------------------------------
    // Gate 6 — determinism and passivity
    // -----------------------------------------------------------------------

    #[test]
    fn same_events_give_bit_identical_profiles() {
        let sequence: Vec<(SocketAddr, u64, u64)> = (0..600u64)
            .map(|i| {
                let source = addr(1 + (i % 7) as u16);
                let at = 1_000_000 + i * 37 + (i % 3) * 11;
                let shape = if i % 5 == 0 { 0xAAAA } else { i % 13 };
                (source, at, shape)
            })
            .collect();

        let build = || {
            let (_bus, sensor) = sensor();
            for (source, at, shape) in &sequence {
                sensor.observe(ProbeEvent {
                    source: *source,
                    at_micros: *at,
                    shape: *shape,
                });
            }
            sensor
        };

        let first = build();
        let second = build();

        assert_eq!(first.tracked_sources(), second.tracked_sources());
        for i in 1..=7u16 {
            let a = first.profile(addr(i));
            let b = second.profile(addr(i));
            assert_eq!(a, b, "profile for source {i} must be identical bit for bit");
            assert!(a.is_some());
        }

        // The sixth dimension is covered by that contract, and not vacuously:
        // the ramp's `drift` is non-zero, two independently-built sensors agree
        // on it bit for bit, and the whole profile — not just the number — is
        // identical.
        let ramp = gaps_ramp(PROBE_WINDOW);
        let build_ramp = || {
            let (_bus, sensor) = sensor();
            feed_window(
                &sensor,
                addr(42),
                &ramp,
                &shapes_constant(PROBE_WINDOW + 1, 0x9),
            )
        };
        let first_ramp = build_ramp();
        let second_ramp = build_ramp();
        println!("determinism: ramp drift = {:.12} (twice)", first_ramp.drift);
        assert_eq!(first_ramp.drift, second_ramp.drift);
        assert_eq!(
            first_ramp, second_ramp,
            "the whole profile, drift included, must be identical"
        );
        assert!(
            first_ramp.drift > 0.4,
            "determinism must be asserted on a real trend, not on 0.0: {:.6}",
            first_ramp.drift
        );
    }

    #[test]
    fn interleaving_sources_does_not_change_their_profiles() {
        let (_bus, sensor_a) = sensor();
        let (_bus_b, sensor_b) = sensor();
        let gaps = gaps_organic(PROBE_WINDOW, E30_ORGANIC_SEED);

        // Source 1: organic gaps, one shape. Source 2: periodic gaps, sweeping.
        let plan: Vec<(SocketAddr, u64, u64)> = {
            let mut events = Vec::new();
            let mut at_one = 1_000_000u64;
            let mut at_two = 2_000_000u64;
            events.push((addr(1), at_one, 0x1));
            events.push((addr(2), at_two, 0x2000));
            for (index, gap) in gaps.iter().enumerate() {
                at_one += gap;
                at_two += 25;
                events.push((addr(1), at_one, 0x1));
                events.push((addr(2), at_two, 0x2000 + index as u64 + 1));
            }
            events
        };

        for (source, at, shape) in &plan {
            sensor_a.observe(ProbeEvent {
                source: *source,
                at_micros: *at,
                shape: *shape,
            });
        }
        // The same two streams, each delivered in one block instead of
        // alternating: a passive sensor cannot tell the difference.
        for (source, at, shape) in plan.iter().filter(|(s, _, _)| *s == addr(1)) {
            sensor_b.observe(ProbeEvent {
                source: *source,
                at_micros: *at,
                shape: *shape,
            });
        }
        for (source, at, shape) in plan.iter().filter(|(s, _, _)| *s == addr(2)) {
            sensor_b.observe(ProbeEvent {
                source: *source,
                at_micros: *at,
                shape: *shape,
            });
        }

        for i in 1..=2u16 {
            assert_eq!(
                sensor_a.profile(addr(i)),
                sensor_b.profile(addr(i)),
                "source {i}'s reading must not depend on the other source's traffic"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Honesty: an unmeasurable 0.0 is not a measurement
    // -----------------------------------------------------------------------

    #[test]
    fn insufficient_observations_cannot_be_read_as_measurements() {
        let (_bus, sensor) = sensor();
        let source = addr(1);

        for i in 0..3u64 {
            sensor.observe(ProbeEvent {
                source,
                at_micros: 1_000 + i * 25,
                shape: 0x1,
            });
        }
        let thin = sensor.profile(source).unwrap();
        assert_eq!(thin.rhythm_pe, 0.0);
        assert!(thin.sufficiency.gaps_in_window < MIN_GAPS_FOR_PE as u32);
        assert_eq!(thin.sufficiency.epochs_compared, 0);
        assert_eq!(thin.convergence, 0.0);

        // `drift` has a *different* floor, and the same `0.0` means something
        // else here: two gaps are enough for a slope, so this `0.0` is a
        // measurement of a steady pair rather than a placeholder. The sufficiency
        // block is what tells the two apart.
        assert_eq!(thin.sufficiency.gaps_in_window, 2);
        assert_eq!(thin.drift, 0.0);

        // …and on that same two-gap window, `drift` says what it means even when
        // it is loud — a reading `rhythm_pe` is not yet entitled to make at all.
        let pair = addr(3);
        for (at, shape) in [
            (1_000_000u64, 0x1u64),
            (1_001_000, 0x1),
            // Gaps 1000 then 500: the cadence halves.
            (1_001_500, 0x1),
        ] {
            sensor.observe(ProbeEvent {
                source: pair,
                at_micros: at,
                shape,
            });
        }
        let halving = sensor.profile(pair).unwrap();
        println!(
            "thin window: gaps={} pe={:.4} (below the {MIN_GAPS_FOR_PE}-gap floor) \
             drift={:.4} (measured)",
            halving.sufficiency.gaps_in_window, halving.rhythm_pe, halving.drift
        );
        assert_eq!(halving.sufficiency.gaps_in_window, 2);
        assert_eq!(
            halving.rhythm_pe, 0.0,
            "below the floor the entropy is not a measurement"
        );
        assert!(
            halving.drift > 0.6,
            "a cadence that halves across the window is a measured trend: {:.4}",
            halving.drift
        );

        // The saturated end of the same scale, pinned: a gap that *triples*
        // across the window reads exactly 1.0 — that is the documented boundary,
        // and it is reachable on a two-gap window.
        let tripling = addr(4);
        for (at, shape) in [(1_000_000u64, 0x1u64), (1_001_000, 0x1), (1_004_000, 0x1)] {
            sensor.observe(ProbeEvent {
                source: tripling,
                at_micros: at,
                shape,
            });
        }
        let tripled = sensor.profile(tripling).unwrap();
        assert_eq!(tripled.sufficiency.gaps_in_window, 2);
        assert_eq!(
            tripled.drift, 1.0,
            "a gap that triples across the window is the exact saturation point"
        );

        // The same 0.0 with enough data *is* a measurement.
        let metronome = feed_window(
            &sensor,
            addr(2),
            &gaps_periodic(PROBE_WINDOW, 25),
            &shapes_constant(PROBE_WINDOW + 1, 0x1),
        );
        assert_eq!(metronome.rhythm_pe, 0.0);
        assert_eq!(metronome.sufficiency.gaps_in_window as usize, PROBE_WINDOW);
        assert!(metronome.sufficiency.gaps_in_window >= MIN_GAPS_FOR_PE as u32);
    }

    // -----------------------------------------------------------------------
    // The bus seam
    // -----------------------------------------------------------------------

    #[test]
    fn publishes_probe_profiles_on_the_sensor_topic() {
        let bus = Arc::new(spiderweb::Bus::open().publisher());
        let mut sub = crate::test_supervision::subscribe_queue(&bus, "net.sensors.", 64);
        let sensor = ProbeSensor::new(Arc::clone(&bus));
        let source = addr(1);
        feed_window(
            &sensor,
            source,
            &gaps_organic(PROBE_WINDOW, E30_ORGANIC_SEED),
            &shapes_distinct(PROBE_WINDOW + 1),
        );

        let before = sensor.profile(source).unwrap();
        let published = sensor.publish_profile(source).unwrap().unwrap();
        assert_eq!(
            before, published,
            "publishing is not an observation: the reading cannot move"
        );
        assert!(sensor.publish_profile(addr(2)).unwrap().is_none());

        let event = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { tokio::time::timeout(Duration::from_millis(250), sub.recv()).await })
            .unwrap()
            .unwrap();
        assert!(event.topic.starts_with("net.sensors."));
        match event.message {
            Message::ProbeProfile(profile) => {
                assert_eq!(profile, before);
                assert_all_dimensions_in_range(&profile);
            }
            other => panic!("expected a probe profile, got {other:?}"),
        }
    }

    #[test]
    fn shape_fingerprint_is_deterministic_and_opaque() {
        let probe = [0x16u8, 0x03, 0x01, 0x00, 0x40];
        assert_eq!(
            probe_shape_fingerprint(&probe),
            probe_shape_fingerprint(&probe)
        );
        assert_ne!(
            probe_shape_fingerprint(&probe),
            probe_shape_fingerprint(&[0x16, 0x03, 0x01, 0x00, 0x41])
        );

        // A driller whose probes share bytes reads as repeating; a sweeper whose
        // probes differ reads as exploring. The fingerprint is only the bridge
        // between bytes and the sensor's opaque identity.
        let (_bus, sensor) = sensor();
        let shapes: Vec<u64> = (0..PROBE_WINDOW + 1)
            .map(|i| probe_shape_fingerprint(&[0x16, 0x03, i as u8]))
            .collect();
        let sweeper = feed_window(&sensor, addr(1), &gaps_periodic(PROBE_WINDOW, 25), &shapes);
        assert_eq!(sweeper.repeat_ratio, 0.0);
        assert_eq!(sweeper.exploration, 1.0);

        let constant = vec![probe_shape_fingerprint(&probe); PROBE_WINDOW + 1];
        let driller = feed_window(
            &sensor,
            addr(2),
            &gaps_periodic(PROBE_WINDOW, 25),
            &constant,
        );
        assert_eq!(driller.repeat_ratio, 1.0);
        assert_eq!(driller.exploration, 1.0 / PROBE_WINDOW as f64);
    }

    // -----------------------------------------------------------------------
    // EXPERIMENT — perception by contrast: can distinctions form with no
    // instructions at all?
    //
    // The open fork (recorded 2026-09-24): is a "perception" layer a
    // **classifier** — categories declared from outside, i.e. instructions —
    // or is it structurally different, forming distinctions with no declared
    // vocabulary? If distinctions can form with nothing declared, it belongs to
    // the same family as E27/E26/E30 (behaviour emerging from mechanism). This
    // test tries the weakest instruction-free candidate: **contrast**.
    //
    // The method is [`nearest_neighbours`] + [`purity`]. Neither takes a kind,
    // a `k`, a threshold or a vocabulary: the only structure extracted is
    // "whose six-dimensional reading is closest to whose". Ground-truth kinds
    // exist ONLY to generate the sources and to score the output afterwards.
    //
    // THE VERDICT IS THE PRINTED COMPARISON — purity (the fraction of sources
    // whose nearest neighbour shares their kind) against the shuffled-label
    // baseline distribution. Nothing here asserts an outcome, because the
    // outcome is the unknown this experiment exists to read; tuning it upward
    // would destroy the experiment. What *is* asserted is the setup: every
    // source is a complete measurement, no two sources read identically, and
    // instances within a kind genuinely vary — without that last one, "the
    // nearest neighbour is the same kind" would prove nothing and the test must
    // fail rather than pass vacuously.
    //
    // Run it with:
    //   cargo test -p imperium-net-sensors contrast_forms_distinctions -- --nocapture
    // -----------------------------------------------------------------------

    /// The seven behaviour kinds. This vocabulary lives only in this test, and
    /// is used only to *generate* the sources and to *score* the result — it is
    /// never an input to the contrast method.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Kind {
        Periodic,
        Beacon,
        Zigzag,
        Ramp,
        VShape,
        Organic,
        Burst,
    }

    const KINDS: [Kind; 7] = [
        Kind::Periodic,
        Kind::Beacon,
        Kind::Zigzag,
        Kind::Ramp,
        Kind::VShape,
        Kind::Organic,
        Kind::Burst,
    ];

    const KINDS_COUNT: usize = 7;

    /// Instances per kind, each with different parameters. Within-kind variation
    /// is the whole point: the question is "does a source's nearest neighbour
    /// tend to be the same kind?", which is only a question if same-kind
    /// instances are themselves different from each other.
    const INSTANCES_PER_KIND: usize = 8;

    /// `K × N` sources.
    const CORPUS_SIZE: usize = KINDS_COUNT * INSTANCES_PER_KIND;

    /// One shape for the entire corpus, so the three shape columns
    /// (`repeat_ratio`, `exploration`, `convergence`) are held constant and the
    /// experiment is about the cadence readings the kinds are made of. That
    /// those columns are constant is *printed* as the live-dimension count
    /// rather than hidden — it is a stated limit of this corpus.
    const CONTRAST_SHAPE: u64 = 0xC0_57_7A_57;

    /// The six readings, in the order [`READING_NAMES`] names them. This is the
    /// same column order the anti-collapse gate's `delta` uses.
    fn readings(profile: &ProbeProfile) -> [f64; 6] {
        [
            profile.rhythm_pe,
            profile.drift,
            profile.repeat_ratio,
            profile.exploration,
            profile.convergence,
            profile.rate_per_sec,
        ]
    }

    const READING_NAMES: [&str; 6] = [
        "rhythm_pe",
        "drift",
        "repeat_ratio",
        "exploration",
        "convergence",
        "rate_per_sec",
    ];

    /// The two distance regimes the experiment is scored under.
    const REGIME_NAMES: [&str; 2] = ["raw", "normalised (min-max)"];

    impl Kind {
        fn name(self) -> &'static str {
            match self {
                Kind::Periodic => "periodic",
                Kind::Beacon => "beacon",
                Kind::Zigzag => "zigzag",
                Kind::Ramp => "ramp",
                Kind::VShape => "v_shape",
                Kind::Organic => "organic",
                Kind::Burst => "burst",
            }
        }
    }

    fn kind_index(kind: Kind) -> usize {
        KINDS
            .iter()
            .position(|candidate| *candidate == kind)
            .expect("every kind is in KINDS")
    }

    /// One deterministic SplitMix64 stream per (generation seed, source),
    /// so each instance's parameters are drawn independently of every other's.
    fn generation_stream(generation_seed: u64, serial: usize) -> SplitMix64 {
        SplitMix64(
            generation_seed
                .wrapping_mul(0xD1B5_4A32_D192_ED03)
                .wrapping_add((serial as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)),
        )
    }

    fn draw_in(rng: &mut SplitMix64, lo: u64, hi: u64) -> u64 {
        debug_assert!(lo <= hi);
        lo + rng.next_u64() % (hi - lo + 1)
    }

    /// The gaps of one instance of one kind, drawn from `rng`. Every draw is a
    /// *within-kind* parameter (different base cadence, jitter seed, amplitude,
    /// duty cycle), never a different kind: same-kind instances must vary
    /// without becoming other kinds.
    fn gaps_for_kind(kind: Kind, rng: &mut SplitMix64) -> Vec<u64> {
        match kind {
            // Metronome, base cadence drawn across nearly three decades.
            Kind::Periodic => {
                let base = draw_in(rng, 100, 8_000);
                vec![base; PROBE_WINDOW]
            }
            // Beacon: jitter of a drawn band around a drawn base cadence, from a
            // drawn stream. Non-monotonic by construction (a monotonic "jitter"
            // would be a ramp, not a beacon).
            Kind::Beacon => {
                let base = draw_in(rng, 40, 3_000);
                let percent = draw_in(rng, 12, 28);
                let span = (base * percent / 100).max(2);
                let mut jitter = SplitMix64(rng.next_u64());
                (0..PROBE_WINDOW)
                    .map(|_| base - span + jitter.next_u64() % (2 * span + 1))
                    .collect()
            }
            // Zigzag: strict alternating cadence, drawn short gap and ratio.
            Kind::Zigzag => {
                let short = draw_in(rng, 3, 120);
                let long = short * draw_in(rng, 3, 8);
                (0..PROBE_WINDOW)
                    .map(|index| if index % 2 == 0 { short } else { long })
                    .collect()
            }
            // Ramp: a monotone cadence change across the window, drawn
            // direction, start and total ratio. Every step is at least two
            // ticks, so the progression is a real one rather than a quantised
            // flat line.
            Kind::Ramp => {
                let start = draw_in(rng, 500, 4_000);
                let end = start * draw_in(rng, 150, 300) / 100;
                let upward = rng.next_u64() % 2 == 0;
                let (lo, hi) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };
                let delta = hi - lo;
                let last = PROBE_WINDOW as u64 - 1;
                (0..=last)
                    .map(|index| {
                        if upward {
                            lo + delta * index / last
                        } else {
                            hi - delta * index / last
                        }
                    })
                    .collect()
            }
            // V-shape: the cadence runs one way and reverts, drawn base,
            // direction and amplitude.
            Kind::VShape => {
                let base = draw_in(rng, 300, 4_000);
                let amplitude = base * draw_in(rng, 30, 120) / 100;
                let v_shaped = rng.next_u64() % 2 == 0;
                let half = (PROBE_WINDOW / 2) as u64;
                (0..PROBE_WINDOW)
                    .map(|index| {
                        let index = index as u64;
                        let phase = if index < half {
                            index
                        } else {
                            PROBE_WINDOW as u64 - 1 - index
                        };
                        let offset = amplitude * phase / (half - 1);
                        if v_shaped {
                            base + offset
                        } else {
                            base + amplitude - offset
                        }
                    })
                    .collect()
            }
            // Organic: high-disorder uniform jitter, drawn ceiling and stream.
            Kind::Organic => {
                let ceiling = draw_in(rng, 50, 3_000);
                let mut stream = SplitMix64(rng.next_u64());
                (0..PROBE_WINDOW)
                    .map(|_| stream.next_u64() % ceiling + 1)
                    .collect()
            }
            // Burst-pause: one drawn fast gap repeated for a drawn duty, then a
            // drawn pause. Duty is at least four, so this is never a two-value
            // zigzag in disguise.
            Kind::Burst => {
                let fast = draw_in(rng, 2, 20);
                let pause = fast * draw_in(rng, 10, 60);
                let duty = draw_in(rng, 4, 20) as usize;
                (0..PROBE_WINDOW)
                    .map(|index| {
                        if index % (duty + 1) == duty {
                            pause
                        } else {
                            fast
                        }
                    })
                    .collect()
            }
        }
    }

    /// The corpus: `K × N` sources, each fed through the real sensor path
    /// (`ProbeSensor::observe` → `ProbeProfile`) as 64 gaps / 65 probes, which
    /// is exactly [`PROBE_WINDOW`] — the same route the other probes tests use.
    fn contrast_corpus(generation_seed: u64) -> Vec<(Kind, ProbeProfile)> {
        let (_bus, sensor) = sensor();
        let mut corpus = Vec::with_capacity(CORPUS_SIZE);
        for (kind_position, kind) in KINDS.iter().enumerate() {
            for instance in 0..INSTANCES_PER_KIND {
                let serial = kind_position * INSTANCES_PER_KIND + instance;
                let mut rng = generation_stream(generation_seed, serial);
                let gaps = gaps_for_kind(*kind, &mut rng);
                assert_eq!(gaps.len(), PROBE_WINDOW);
                assert!(
                    gaps.iter().all(|gap| *gap >= 1),
                    "{} instance {instance}: a zero gap is not a cadence",
                    kind.name()
                );
                let source = addr(1 + serial as u16);
                let profile = feed_window(
                    &sensor,
                    source,
                    &gaps,
                    &shapes_constant(PROBE_WINDOW + 1, CONTRAST_SHAPE),
                );
                corpus.push((*kind, profile));
            }
        }
        corpus
    }

    /// The instruction-free method, part 1 of 2: each source's nearest
    /// neighbour in the reading space (itself excluded). No kind, no `k`, no
    /// threshold appears anywhere in this function. Ties (exactly equal
    /// distances, which [`tie_count`] counts) go to the lowest index, so the
    /// edge set is a total function of the readings.
    fn nearest_neighbours(vectors: &[[f64; 6]]) -> Vec<usize> {
        (0..vectors.len())
            .map(|source| {
                let (mut best, mut best_distance) = (usize::MAX, f64::INFINITY);
                for (other, vector) in vectors.iter().enumerate() {
                    if other == source {
                        continue;
                    }
                    let distance: f64 = (0..6)
                        .map(|dimension| (vectors[source][dimension] - vector[dimension]).powi(2))
                        .sum();
                    if distance < best_distance {
                        best_distance = distance;
                        best = other;
                    }
                }
                best
            })
            .collect()
    }

    /// Part 2 of 2: purity — the fraction of sources whose nearest neighbour
    /// carries the same ground-truth kind. The labels are read *only* here, for
    /// scoring; they were never used to choose the neighbour.
    fn purity(neighbours: &[usize], labels: &[usize]) -> f64 {
        let agreeing = neighbours
            .iter()
            .enumerate()
            .filter(|(source, neighbour)| labels[*source] == labels[**neighbour])
            .count();
        agreeing as f64 / neighbours.len() as f64
    }

    /// How many sources have a *second* neighbour at exactly the same distance
    /// as the nearest one — i.e. how many edges the tie-break, rather than the
    /// geometry, decided. Printed so a purity number cannot be an artefact of
    /// edge ordering without saying so.
    fn tie_count(vectors: &[[f64; 6]], neighbours: &[usize]) -> usize {
        let squared_distance = |first: usize, second: usize| -> f64 {
            (0..6)
                .map(|dimension| (vectors[first][dimension] - vectors[second][dimension]).powi(2))
                .sum()
        };
        (0..vectors.len())
            .filter(|source| {
                let nearest = squared_distance(*source, neighbours[*source]);
                (0..vectors.len()).any(|other| {
                    other != *source
                        && other != neighbours[*source]
                        && squared_distance(*source, other) == nearest
                })
            })
            .count()
    }

    /// Min-max each dimension across the corpus into `[0, 1]`. A dimension with
    /// no spread is set to `0.0` for every source — it carries no contrast and
    /// therefore contributes nothing to any distance. The returned flags say
    /// which dimensions were live, so a corpus that silently lost columns to
    /// degeneracy says so out loud.
    fn min_max_normalise(vectors: &mut [[f64; 6]]) -> [bool; 6] {
        let mut live = [false; 6];
        for dimension in 0..6 {
            let min = vectors
                .iter()
                .map(|vector| vector[dimension])
                .fold(f64::INFINITY, f64::min);
            let max = vectors
                .iter()
                .map(|vector| vector[dimension])
                .fold(f64::NEG_INFINITY, f64::max);
            if max > min {
                live[dimension] = true;
                for vector in vectors.iter_mut() {
                    vector[dimension] = (vector[dimension] - min) / (max - min);
                }
            } else {
                for vector in vectors.iter_mut() {
                    vector[dimension] = 0.0;
                }
            }
        }
        live
    }

    /// The null: the kind labels are permuted across the sources and purity is
    /// recomputed. The neighbour graph is not touched — only the scoring labels
    /// move — which is what makes the shuffled distribution the chance baseline
    /// for *this* neighbour structure.
    struct NullDistribution {
        mean: f64,
        sd: f64,
        min: f64,
        max: f64,
        at_least_observed: usize,
        shuffles: usize,
    }

    fn shuffle_null(
        neighbours: &[usize],
        labels: &[usize],
        shuffles: usize,
        tag: u64,
    ) -> NullDistribution {
        let observed = purity(neighbours, labels);
        let mut rng = SplitMix64(0x5EED_5EED_5EED_5EED ^ tag.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let mut permuted = labels.to_vec();
        let mut sum = 0.0;
        let mut sum_of_squares = 0.0;
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        let mut at_least_observed = 0usize;
        for _ in 0..shuffles {
            // Fisher-Yates, deterministic stream: the same seed reproduces the
            // same baseline exactly.
            permuted.clear();
            permuted.extend_from_slice(labels);
            for index in (1..permuted.len()).rev() {
                let swap_with = (rng.next_u64() % (index as u64 + 1)) as usize;
                permuted.swap(index, swap_with);
            }
            let sample = purity(neighbours, &permuted);
            sum += sample;
            sum_of_squares += sample * sample;
            min = min.min(sample);
            max = max.max(sample);
            if sample >= observed {
                at_least_observed += 1;
            }
        }
        let mean = sum / shuffles as f64;
        // Population sd; the variance cannot go negative, the clamp is only
        // there so a floating-point round-off cannot produce a NaN.
        let variance = (sum_of_squares / shuffles as f64 - mean * mean).max(0.0);
        NullDistribution {
            mean,
            sd: variance.sqrt(),
            min,
            max,
            at_least_observed,
            shuffles,
        }
    }

    fn confusion_matrix(
        labels: &[usize],
        neighbours: &[usize],
    ) -> [[usize; KINDS_COUNT]; KINDS_COUNT] {
        let mut matrix = [[0usize; KINDS_COUNT]; KINDS_COUNT];
        for (source, neighbour) in neighbours.iter().enumerate() {
            matrix[labels[source]][labels[*neighbour]] += 1;
        }
        matrix
    }

    fn print_confusion(matrix: &[[usize; KINDS_COUNT]; KINDS_COUNT], regime: &str) {
        println!("  confusion ({regime}) — row = true kind, column = its instances' nearest neighbour's kind:");
        print!("    {:>10}", "true \\ nn");
        for kind in KINDS {
            print!(" {:>8}", kind.name());
        }
        println!();
        for (row, kind) in KINDS.iter().enumerate() {
            print!("    {:>10}", kind.name());
            for column in 0..KINDS_COUNT {
                print!(" {:>8}", matrix[row][column]);
            }
            println!();
        }
    }

    /// The ordered off-diagonal cells, largest first.
    fn ranked_confusions(
        matrix: &[[usize; KINDS_COUNT]; KINDS_COUNT],
    ) -> Vec<((usize, usize), usize)> {
        let mut pairs: Vec<((usize, usize), usize)> = Vec::new();
        for row in 0..KINDS_COUNT {
            for column in 0..KINDS_COUNT {
                if row != column && matrix[row][column] > 0 {
                    pairs.push(((row, column), matrix[row][column]));
                }
            }
        }
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs
    }

    /// The same, but counting each unordered kind pair once (both directions
    /// summed), which is the right unit for "these two kinds get mistaken for
    /// each other".
    fn ranked_symmetric_confusions(
        matrix: &[[usize; KINDS_COUNT]; KINDS_COUNT],
    ) -> Vec<((usize, usize), usize)> {
        let mut pairs: Vec<((usize, usize), usize)> = Vec::new();
        for first in 0..KINDS_COUNT {
            for second in first + 1..KINDS_COUNT {
                let count = matrix[first][second] + matrix[second][first];
                if count > 0 {
                    pairs.push(((first, second), count));
                }
            }
        }
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        pairs
    }

    fn euclidean(a: &[f64; 6], b: &[f64; 6]) -> f64 {
        (0..6)
            .map(|dimension| (a[dimension] - b[dimension]).powi(2))
            .sum::<f64>()
            .sqrt()
    }

    /// What each dimension contributes to the corpus's total squared distance —
    /// the read-out that says whether a regime is actually a six-dimensional
    /// comparison or a one-dimensional one wearing six columns.
    fn distance_shares(vectors: &[[f64; 6]]) -> [f64; 6] {
        let mut shares = [0.0; 6];
        for first in 0..vectors.len() {
            for second in first + 1..vectors.len() {
                for dimension in 0..6 {
                    shares[dimension] +=
                        (vectors[first][dimension] - vectors[second][dimension]).powi(2);
                }
            }
        }
        let total: f64 = shares.iter().sum();
        if total > 0.0 {
            for share in shares.iter_mut() {
                *share /= total;
            }
        }
        shares
    }

    fn print_distance_shares(vectors: &[[f64; 6]], regime: &str) {
        let shares = distance_shares(vectors);
        let rendered: Vec<String> = (0..6)
            .map(|dimension| {
                format!(
                    "{} {:.2}%",
                    READING_NAMES[dimension],
                    shares[dimension] * 100.0
                )
            })
            .collect();
        println!(
            "  distance share by dimension ({regime}): {}",
            rendered.join(", ")
        );
    }

    /// The mean absolute per-dimension gap between two kinds' instances — used
    /// to say *what* separated a pair that rhythm alone was expected to confuse.
    fn mean_dimension_deltas(
        labels: &[usize],
        vectors: &[[f64; 6]],
        first_kind: usize,
        second_kind: usize,
    ) -> ([f64; 6], usize) {
        let mut sums = [0.0; 6];
        let mut pairs = 0usize;
        for (first, first_label) in labels.iter().enumerate() {
            for (second, second_label) in labels.iter().enumerate() {
                if *first_label == first_kind && *second_label == second_kind {
                    for dimension in 0..6 {
                        sums[dimension] +=
                            (vectors[first][dimension] - vectors[second][dimension]).abs();
                    }
                    pairs += 1;
                }
            }
        }
        if pairs > 0 {
            for sum in sums.iter_mut() {
                *sum /= pairs as f64;
            }
        }
        (sums, pairs)
    }

    fn print_pair_dimensions(
        labels: &[usize],
        vectors: &[[f64; 6]],
        first_kind: usize,
        second_kind: usize,
        regime: &str,
    ) {
        let (deltas, pairs) = mean_dimension_deltas(labels, vectors, first_kind, second_kind);
        let rendered: Vec<String> = (0..6)
            .map(|dimension| format!("{} {:.4}", READING_NAMES[dimension], deltas[dimension]))
            .collect();
        println!(
            "    {} vs {} ({pairs} pairs, {regime}) mean |Δ| per dimension: {}",
            KINDS[first_kind].name(),
            KINDS[second_kind].name(),
            rendered.join(", ")
        );
    }

    /// Setup validity + the evidence it rests on. If instances within a kind
    /// were identical, or if any source's reading were a placeholder rather than
    /// a measurement, the experiment would be vacuous — so this fails loudly
    /// instead of letting a purity number be read out of a degenerate corpus.
    fn assert_setup_is_not_vacuous(corpus: &[(Kind, ProbeProfile)]) {
        assert_eq!(corpus.len(), CORPUS_SIZE, "K × N sources must be generated");
        // (a) Every source is a complete measurement, not a thin-window 0.0.
        for (kind, profile) in corpus {
            assert_eq!(
                profile.sufficiency.gaps_in_window as usize,
                PROBE_WINDOW,
                "{}: the whole gap window must be measured",
                kind.name()
            );
            assert!(
                profile.sufficiency.epochs_compared >= 1,
                "{}: convergence must have been compared at least once",
                kind.name()
            );
            assert_all_dimensions_in_range(profile);
        }
        // (b) No two sources in the corpus read identically.
        for first in 0..corpus.len() {
            for second in first + 1..corpus.len() {
                assert_ne!(
                    readings(&corpus[first].1),
                    readings(&corpus[second].1),
                    "{} instance and {} instance read identically — the corpus is degenerate",
                    corpus[first].0.name(),
                    corpus[second].0.name()
                );
            }
        }
        // (c) Instances within each kind genuinely vary, and vary from each other.
        for kind in KINDS {
            let members: Vec<[f64; 6]> = corpus
                .iter()
                .filter(|(member_kind, _)| *member_kind == kind)
                .map(|(_, profile)| readings(profile))
                .collect();
            assert_eq!(members.len(), INSTANCES_PER_KIND);
            let varies = (0..6).any(|dimension| {
                let min = members
                    .iter()
                    .map(|member| member[dimension])
                    .fold(f64::INFINITY, f64::min);
                let max = members
                    .iter()
                    .map(|member| member[dimension])
                    .fold(f64::NEG_INFINITY, f64::max);
                max > min
            });
            assert!(
                varies,
                "{}: all {INSTANCES_PER_KIND} instances read identically on every \
                 dimension — within-kind variation is zero and the experiment is vacuous",
                kind.name()
            );
            for first in 0..members.len() {
                for second in first + 1..members.len() {
                    assert_ne!(
                        members[first],
                        members[second],
                        "{}: instances {first} and {second} read identically — within-kind \
                         variation is missing for that pair",
                        kind.name()
                    );
                }
            }
        }
    }

    fn print_reading_ranges(vectors: &[[f64; 6]], live: &[bool; 6], regime: &str) {
        println!("  reading ranges across the {CORPUS_SIZE} sources ({regime}; a constant dimension carries no contrast):");
        for dimension in 0..6 {
            let min = vectors
                .iter()
                .map(|vector| vector[dimension])
                .fold(f64::INFINITY, f64::min);
            let max = vectors
                .iter()
                .map(|vector| vector[dimension])
                .fold(f64::NEG_INFINITY, f64::max);
            println!(
                "    {:>12}: [{min:.4}, {max:.4}] {}",
                READING_NAMES[dimension],
                if live[dimension] { "live" } else { "constant" }
            );
        }
    }

    /// Per kind, the raw range of every reading that varies across its own
    /// instances: the within-kind variance that makes "the nearest neighbour is
    /// the same kind" a question rather than a tautology.
    fn print_kind_ranges(labels: &[usize], vectors: &[[f64; 6]], regime: &str) {
        println!("  within-kind ranges of the readings ({regime}):");
        for (row, kind) in KINDS.iter().enumerate() {
            let members: Vec<&[f64; 6]> = (0..labels.len())
                .filter(|index| labels[*index] == row)
                .map(|index| &vectors[index])
                .collect();
            let bounds = |dimension: usize| {
                let min = members
                    .iter()
                    .map(|member| member[dimension])
                    .fold(f64::INFINITY, f64::min);
                let max = members
                    .iter()
                    .map(|member| member[dimension])
                    .fold(f64::NEG_INFINITY, f64::max);
                (min, max)
            };
            let rendered: Vec<String> = (0..6)
                .filter(|dimension| bounds(*dimension).1 > bounds(*dimension).0)
                .map(|dimension| {
                    let (min, max) = bounds(dimension);
                    format!("{} {min:.4}..{max:.4}", READING_NAMES[dimension])
                })
                .collect();
            println!("    {:>9}: {}", kind.name(), rendered.join(", "));
        }
    }

    /// Per kind: the closest pair of its own instances, the mean such distance,
    /// and the closest source of any *other* kind. A kind whose instances sit on
    /// top of each other, or which is already swallowed by another kind, is
    /// visible here before any purity number is read.
    fn print_within_kind_spread(labels: &[usize], vectors: &[[f64; 6]], regime: &str) {
        println!("  within-kind spread and closest foreign source ({regime}):");
        for (row, kind) in KINDS.iter().enumerate() {
            let members: Vec<usize> = (0..labels.len())
                .filter(|index| labels[*index] == row)
                .collect();
            let mut within = Vec::new();
            for (position, first) in members.iter().enumerate() {
                for second in &members[position + 1..] {
                    within.push(euclidean(&vectors[*first], &vectors[*second]));
                }
            }
            let min_within = within.iter().cloned().fold(f64::INFINITY, f64::min);
            let mean_within = within.iter().sum::<f64>() / within.len() as f64;
            let closest_foreign = members
                .iter()
                .map(|first| {
                    (0..labels.len())
                        .filter(|second| labels[*second] != row)
                        .map(|second| euclidean(&vectors[*first], &vectors[second]))
                        .fold(f64::INFINITY, f64::min)
                })
                .fold(f64::INFINITY, f64::min);
            println!(
                "    {:>9}: min pair {min_within:.4} mean pair {mean_within:.4} | closest foreign source {closest_foreign:.4}",
                kind.name()
            );
        }
    }

    struct SeedResult {
        generation_seed: u64,
        /// `[raw, normalised]`.
        observed: [f64; 2],
        null_mean: [f64; 2],
        null_sd: [f64; 2],
        null_max: [f64; 2],
        at_least_observed: [usize; 2],
    }

    #[test]
    fn contrast_forms_distinctions_without_instructions() {
        const GENERATION_SEEDS: [u64; 5] = [
            0xC0FF_EE01,
            0xC0FF_EE02,
            0xC0FF_EE03,
            0xC0FF_EE04,
            0xC0FF_EE05,
        ];
        const SHUFFLES: usize = 2_000;

        println!(
            "=== perception by contrast: K={KINDS_COUNT} kinds × N={INSTANCES_PER_KIND} instances = {CORPUS_SIZE} sources"
        );
        println!("=== method: nearest neighbour in the six-dimensional reading space; purity = fraction whose nearest neighbour is the same kind");
        println!("=== the method never sees a kind, a k, or a threshold; the kinds are used only to generate sources and score the result");
        // For a fixed neighbour graph with randomly permuted labels, a source's
        // neighbour agrees on (N-1)/(K·N-1) of the edges by symmetry, so the
        // shuffled mean should land there — a check on the shuffle itself.
        let analytic_baseline = (INSTANCES_PER_KIND - 1) as f64 / (CORPUS_SIZE - 1) as f64;
        println!(
            "=== shuffled-label baseline expectation for a fixed neighbour graph: (N-1)/(K·N-1) = {analytic_baseline:.4}"
        );
        println!("=== THE VERDICT IS THE PRINTED purity-vs-baseline COMPARISON BELOW; no assertion is made about the outcome");

        // --- Setup validity, before any scoring -----------------------------
        let first = contrast_corpus(GENERATION_SEEDS[0]);
        assert_setup_is_not_vacuous(&first);
        let rebuilt = contrast_corpus(GENERATION_SEEDS[0]);
        assert!(
            first
                .iter()
                .zip(&rebuilt)
                .all(|((_, a), (_, b))| readings(a) == readings(b)),
            "the same generation seed must reproduce the same sources bit for bit"
        );
        let second_seed = contrast_corpus(GENERATION_SEEDS[1]);
        assert!(
            first
                .iter()
                .zip(&second_seed)
                .any(|((_, a), (_, b))| readings(a) != readings(b)),
            "a different generation seed must produce a different corpus, or the \
             per-seed stability check below is vacuous"
        );
        println!(
            "=== setup asserted: {} sources, all complete measurements, no two readings identical, within-kind variation non-zero for all {KINDS_COUNT} kinds, same seed reproduces bit for bit",
            first.len()
        );

        let mut results: Vec<SeedResult> = Vec::new();
        let mut aggregate = [[[0usize; KINDS_COUNT]; KINDS_COUNT]; 2];

        for generation_seed in GENERATION_SEEDS {
            let corpus = if generation_seed == GENERATION_SEEDS[0] {
                first.clone()
            } else {
                contrast_corpus(generation_seed)
            };
            let labels: Vec<usize> = corpus.iter().map(|(kind, _)| kind_index(*kind)).collect();
            let raw: Vec<[f64; 6]> = corpus
                .iter()
                .map(|(_, profile)| readings(profile))
                .collect();
            let mut normalised = raw.clone();
            let live = min_max_normalise(&mut normalised);

            println!("\n--- generation seed {generation_seed:#010X} ---");
            let live_names: Vec<&str> = (0..6)
                .filter(|dimension| live[*dimension])
                .map(|dimension| READING_NAMES[dimension])
                .collect();
            println!(
                "  live dimensions ({} of 6): {}",
                live_names.len(),
                live_names.join(", ")
            );
            print_reading_ranges(&raw, &live, "raw");
            print_kind_ranges(&labels, &raw, "raw");
            print_distance_shares(&raw, "raw");
            print_distance_shares(&normalised, "normalised (min-max)");
            print_within_kind_spread(&labels, &raw, "raw");
            print_within_kind_spread(&labels, &normalised, "normalised (min-max)");

            let mut observed = [0.0f64; 2];
            let mut null_mean = [0.0f64; 2];
            let mut null_sd = [0.0f64; 2];
            let mut null_max = [0.0f64; 2];
            let mut at_least_observed = [0usize; 2];

            for (index, regime) in REGIME_NAMES.iter().enumerate() {
                let vectors = if index == 0 { &raw } else { &normalised };
                let neighbours = nearest_neighbours(vectors);
                let null = shuffle_null(
                    &neighbours,
                    &labels,
                    SHUFFLES,
                    generation_seed ^ (index as u64) << 32,
                );
                let matrix = confusion_matrix(&labels, &neighbours);
                for row in 0..KINDS_COUNT {
                    for column in 0..KINDS_COUNT {
                        aggregate[index][row][column] += matrix[row][column];
                    }
                }
                observed[index] = purity(&neighbours, &labels);
                null_mean[index] = null.mean;
                null_sd[index] = null.sd;
                null_max[index] = null.max;
                at_least_observed[index] = null.at_least_observed;
                println!(
                    "  {regime:>20}: purity {:.4} | shuffled ({} draws) mean {:.4} sd {:.4} min {:.4} max {:.4} | draws >= observed: {}/{} ({:.4}) | exact-distance ties: {}",
                    observed[index],
                    null.shuffles,
                    null.mean,
                    null.sd,
                    null.min,
                    null.max,
                    null.at_least_observed,
                    null.shuffles,
                    null.at_least_observed as f64 / null.shuffles as f64,
                    tie_count(vectors, &neighbours)
                );
                print_confusion(&matrix, regime);
                let symmetric = ranked_symmetric_confusions(&matrix);
                println!("  per-dimension gaps of this seed's most-confused pair and of the predicted pair ({regime}):");
                if let Some((pair, count)) = symmetric.first() {
                    println!("    most-confused symmetric pair ({count} confused edges between the two kinds):");
                    print_pair_dimensions(&labels, vectors, pair.0, pair.1, regime);
                }
                println!(
                    "    predicted pair burst/beacon: {} confused edges",
                    matrix[kind_index(Kind::Burst)][kind_index(Kind::Beacon)]
                        + matrix[kind_index(Kind::Beacon)][kind_index(Kind::Burst)]
                );
                print_pair_dimensions(
                    &labels,
                    vectors,
                    kind_index(Kind::Burst),
                    kind_index(Kind::Beacon),
                    regime,
                );
            }
            println!(
                "  regime verdict: raw purity {:.4} = {:.1}x the shuffled mean {:.4} ({} of {SHUFFLES} draws >= it) | normalised purity {:.4} = {:.1}x the shuffled mean {:.4} ({} of {SHUFFLES} draws >= it)",
                observed[0],
                observed[0] / null_mean[0],
                null_mean[0],
                at_least_observed[0],
                observed[1],
                observed[1] / null_mean[1],
                null_mean[1],
                at_least_observed[1]
            );

            results.push(SeedResult {
                generation_seed,
                observed,
                null_mean,
                null_sd,
                null_max,
                at_least_observed,
            });
        }

        // --- Stability across generation seeds ------------------------------
        println!(
            "\n=== stability across {} generation seeds ===",
            GENERATION_SEEDS.len()
        );
        for result in &results {
            println!(
                "  seed {:#010X}: raw purity {:.4} (shuffled mean {:.4}, max {:.4}, draws >= observed {}/{SHUFFLES}) | normalised purity {:.4} (shuffled mean {:.4}, max {:.4}, draws >= observed {}/{SHUFFLES})",
                result.generation_seed,
                result.observed[0],
                result.null_mean[0],
                result.null_max[0],
                result.at_least_observed[0],
                result.observed[1],
                result.null_mean[1],
                result.null_max[1],
                result.at_least_observed[1]
            );
        }
        let mean_over_seeds = |index: usize| {
            results
                .iter()
                .map(|result| result.observed[index])
                .sum::<f64>()
                / results.len() as f64
        };
        let min_over_seeds = |index: usize| {
            results
                .iter()
                .map(|result| result.observed[index])
                .fold(f64::INFINITY, f64::min)
        };
        let max_over_seeds = |index: usize| {
            results
                .iter()
                .map(|result| result.observed[index])
                .fold(f64::NEG_INFINITY, f64::max)
        };
        for (index, regime) in REGIME_NAMES.iter().enumerate() {
            let above = results
                .iter()
                .filter(|result| result.observed[index] > result.null_max[index])
                .count();
            println!(
                "  {regime:>20}: mean {:.4} min {:.4} max {:.4} | above every shuffle in {above}/{} seeds | shuffled mean across seeds {:.4} (~{:.4}), sd {:.4}, shuffled max {:.4}",
                mean_over_seeds(index),
                min_over_seeds(index),
                max_over_seeds(index),
                results.len(),
                results
                    .iter()
                    .map(|result| result.null_mean[index])
                    .sum::<f64>()
                    / results.len() as f64,
                analytic_baseline,
                results
                    .iter()
                    .map(|result| result.null_sd[index])
                    .sum::<f64>()
                    / results.len() as f64,
                results
                    .iter()
                    .map(|result| result.null_max[index])
                    .fold(f64::NEG_INFINITY, f64::max)
            );
        }

        // --- The confusion table, and the burst/beacon prediction -----------
        for (index, regime) in REGIME_NAMES.iter().enumerate() {
            println!(
                "\n=== confusion summed over {} seeds ({regime}) ===",
                results.len()
            );
            print_confusion(&aggregate[index], regime);
            let ranked = ranked_confusions(&aggregate[index]);
            println!("  most-confused ordered kind pairs (true -> nearest neighbour):");
            for (rank, (pair, count)) in ranked.iter().take(6).enumerate() {
                println!(
                    "    {}. {} -> {} : {count} of {} edges",
                    rank + 1,
                    KINDS[pair.0].name(),
                    KINDS[pair.1].name(),
                    CORPUS_SIZE * results.len()
                );
            }
            let burst_to_beacon =
                aggregate[index][kind_index(Kind::Burst)][kind_index(Kind::Beacon)];
            let beacon_to_burst =
                aggregate[index][kind_index(Kind::Beacon)][kind_index(Kind::Burst)];
            let pair_total = burst_to_beacon + beacon_to_burst;
            let pair_rank = ranked
                .iter()
                .position(|(pair, _)| {
                    (*pair == (kind_index(Kind::Beacon), kind_index(Kind::Burst)))
                        || (*pair == (kind_index(Kind::Burst), kind_index(Kind::Beacon)))
                })
                .map(|position| position + 1);
            println!(
                "  prediction check (burst and beacon have the closest rhythm anchors, 0.325 vs 0.329): \
                 burst -> beacon {burst_to_beacon} + beacon -> burst {beacon_to_burst} = {pair_total} of {} burst/beacon edges; \
                 rank among the {} non-empty cross-kind cells: {}",
                2 * INSTANCES_PER_KIND * results.len(),
                ranked.len(),
                pair_rank.map_or("not a confusion pair at all".to_string(), |rank| format!("#{rank}"))
            );
        }

        // --- The verdict, printed rather than asserted ----------------------
        println!("\n=== VERDICT (printed, not asserted — this comparison is the answer) ===");
        for (index, regime) in REGIME_NAMES.iter().enumerate() {
            let above = results
                .iter()
                .filter(|result| result.observed[index] > result.null_max[index])
                .count();
            let mean = mean_over_seeds(index);
            println!(
                "  {regime:>20}: purity mean over seeds {mean:.4} (min {:.4}, max {:.4}), {:.1}x the shuffled baseline {:.4} (sd ~{:.4}); above every one of the {SHUFFLES} shuffles in {above}/{} seeds -> {}",
                min_over_seeds(index),
                max_over_seeds(index),
                mean / analytic_baseline,
                analytic_baseline,
                results
                    .iter()
                    .map(|result| result.null_sd[index])
                    .sum::<f64>()
                    / results.len() as f64,
                results.len(),
                if above == results.len() {
                    "clearly above the chance baseline"
                } else if above * 2 >= results.len() {
                    "above the chance baseline, but not beyond every shuffle in all seeds"
                } else if above > 0 {
                    "mostly inside the chance baseline"
                } else {
                    "indistinguishable from chance — the kinds were not recovered"
                }
            );
        }
    }
}
