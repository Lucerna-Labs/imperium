//! Read-only behavioral measurement tap for the live mesh.
//!
//! This crate feeds redacted frame-shape classes into the no-copy stacks and
//! records separation measurements. It is observe-only:
//!
//! - it never alters a payload, route, session, key, or counter;
//! - it never emits verdicts, scores, labels, policies, or actuation;
//! - it publishes nothing and holds no bus handle.
//!
//! The only question asked of a measurement is asked by the caller after the
//! numbers are recorded — the same boundary the no-copy demo enforces.

use nocopy_closure_orchestrator::{closure, count_second_copy_worlds, ClosureRecord};
use nocopy_generator_core::{Carrier, World};
use nocopy_linear_map_core::State;
use nocopy_linear_map_orchestrator::{sweep, WalkDelta};
use thiserror::Error;

/// Errors in tap observation. Malformed input is rejected, never corrected.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ObserverError {
    /// Frame length class outside the bounded table.
    #[error("frame length outside bounded classes")]
    OutOfRange,
}

/// A redacted frame observation: length class only.
///
/// No payload bytes, addresses, identities, keys, nonces, counters, or routes
/// are recorded. Length is quantized to 8 classes so a measurement consumer
/// cannot reconstruct size precisely, only relatively.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameClass(pub u8);

impl FrameClass {
    /// Quantize a wire length into 8 classes. Pure function of length.
    #[must_use]
    pub fn quantize(wire_len: usize) -> Self {
        let class = match wire_len {
            0..=64 => 0,
            65..=128 => 1,
            129..=256 => 2,
            257..=512 => 3,
            513..=1024 => 4,
            1025..=1200 => 5,
            1201..=1472 => 6,
            _ => 7,
        };
        FrameClass(class)
    }
}

/// Bounded per-daemon observation state: 64 most recent frame classes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnObserver {
    classes: [u8; 64],
    len: usize,
    frames: u64,
}

impl VpnObserver {
    /// Empty observer.
    pub fn new() -> Self {
        Self {
            classes: [0; 64],
            len: 0,
            frames: 0,
        }
    }

    /// Record one outbound or inbound frame's wire length. Never fails on
    /// valid input; the class table covers every length.
    pub fn observe_frame(&mut self, wire_len: usize) {
        let FrameClass(class) = FrameClass::quantize(wire_len);
        if self.len < self.classes.len() {
            self.classes[self.len] = class;
            self.len += 1;
        } else {
            self.classes.copy_within(1.., 0);
            self.classes[self.classes.len() - 1] = class;
        }
        self.frames = self.frames.saturating_add(1);
    }

    /// Frames observed so far (saturating).
    #[must_use]
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// Build the generator-stack initial world from observed classes.
    ///
    /// Each observed class becomes one neutral carrier of that charge at a
    /// position derived from its index. This is a mechanical projection, not
    /// an interpretation: the closure decides nothing about the VPN.
    #[must_use]
    pub fn generator_world(&self) -> World {
        let carriers: Vec<Carrier> = self.classes[..self.len]
            .iter()
            .enumerate()
            .map(|(index, class)| Carrier {
                charge: i32::from(*class).max(2),
                winding: 0,
                position: (index % 3) as u32,
            })
            .collect();
        World::new(carriers)
    }

    /// Run the generator closure on the observed classes. Records only.
    #[must_use]
    pub fn generator_snapshot(&self, depth: usize) -> ClosureRecord {
        closure(&self.generator_world(), &[(0, 1), (1, 2)], depth)
    }

    /// Count second-copy worlds in the snapshot. Asked here, after the
    /// closure is computed — never inside the generators.
    #[must_use]
    pub fn second_copy_count(&self, record: &ClosureRecord, charge: i32) -> usize {
        count_second_copy_worlds(record, charge)
    }

    /// Run the linear-map sweep from a state derived from observed classes.
    ///
    /// Fixed three-point sweep of the coupling, four steps each, matching
    /// the standalone evidence run.
    #[must_use]
    pub fn linear_sweep(&self) -> Vec<WalkDelta> {
        let seed =
            self.classes[..self.len.min(3)]
                .iter()
                .fold([4.0f64, 0.0, 0.0], |mut acc, class| {
                    acc[0] += f64::from(*class);
                    acc
                });
        let base = nocopy_linear_map_orchestrator::walk(
            State(seed),
            &[nocopy_linear_map_core::LinearMap::cyclic_shift(); 4],
        );
        sweep(State(seed), &[0.25, 1.0, 1.75], 4)
            .into_iter()
            .map(|chaos| nocopy_linear_map_orchestrator::walk_delta(&base, &chaos))
            .collect()
    }
}

impl Default for VpnObserver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocopy_linear_map_core::{LinearMap, ReadoutDegree};

    #[test]
    fn quantization_covers_every_length() {
        for len in [
            0usize, 1, 64, 65, 128, 256, 512, 1024, 1200, 1472, 1473, 65535,
        ] {
            let FrameClass(class) = FrameClass::quantize(len);
            assert!(class <= 7, "len {len} gave class {class}");
        }
    }

    #[test]
    fn observation_is_bounded() {
        let mut observer = VpnObserver::new();
        for index in 0..200usize {
            observer.observe_frame(100 + (index % 1400));
        }
        assert_eq!(observer.frames(), 200);
    }

    #[test]
    fn closure_records_without_filtering() {
        let mut observer = VpnObserver::new();
        for len in [100usize, 300, 900, 1400] {
            observer.observe_frame(len);
        }
        let record = observer.generator_snapshot(4);
        assert!(!record.visited.is_empty());
    }

    #[test]
    fn sweep_runs_from_observed_seed() {
        let mut observer = VpnObserver::new();
        observer.observe_frame(500);
        observer.observe_frame(900);
        let deltas = observer.linear_sweep();
        assert_eq!(deltas.len(), 3);
        for delta in deltas {
            assert_eq!(delta.chaos_steps, 4);
        }
    }

    #[test]
    fn readout_degree_stays_nonlinear_on_live_seed() {
        let mut observer = VpnObserver::new();
        for len in [64usize, 200, 700, 1300] {
            observer.observe_frame(len);
        }
        let record = nocopy_linear_map_orchestrator::walk(
            State([6.0, 0.0, 0.0]),
            &[LinearMap::cyclic_shift(); 2],
        );
        assert_eq!(record.degrees, vec![ReadoutDegree::Nonlinear]);
    }
}
