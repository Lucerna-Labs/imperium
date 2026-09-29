//! Outer conventional operator envelope for atom VPN behavior.
//!
//! This crate is explicitly **not** an Atom function or engine crate. It is
//! ordinary Rust composition that maps already-emitted atom partitions onto
//! already-implemented VPN actuator choices. It may arbitrate measured outputs
//! within an enumerated finite envelope. It must not manufacture missing
//! behavior, alter atom state except through invocation, encode desired VPN
//! outcomes as emergent output, fuse columns into verdicts, or touch crypto,
//! identity, admission, revocation, cover, payload, or private material.
//!
//! Every effect is ceiling-bounded and fail-closed. Unknown, unconfigured, or
//! out-of-envelope inputs leave the current actuator state unchanged.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

use thiserror::Error;

/// Errors in conventional envelope arbitration.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Caller supplied an incomplete or malformed envelope input.
    #[error("malformed policy input")]
    MalformedInput,
    /// Caller asked for an effect outside the enumerated envelope.
    #[error("effect outside operator envelope")]
    OutsideEnvelope,
}

/// Bounded transmission-delay choice supported by existing jitter fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelayChoice {
    /// Selected delay in milliseconds, already within a configured ceiling.
    pub delay_ms: u16,
}

/// Bounded session-longevity choice within live byte/time allowances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongevityChoice {
    /// Whether the next eligible rotation window should be preferred.
    pub prefer_early_rotation: bool,
}

/// Bounded route-selection choice among real candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteChoice {
    /// Ordered candidate index supplied by existing longest-prefix selection.
    /// The envelope only chooses among indices that already exist.
    pub candidate_index: u8,
    /// Number of candidates supplied by existing selection.
    pub candidate_count: u8,
}

/// Finite outer action selected from atom partitions.
///
/// `NoChange` is the safe default. Every other variant selects an already
/// available VPN behavior within a caller-supplied ceiling. No variant creates
/// a destination, key, session, identity, verdict, score, or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedAction {
    /// Leave actuator state unchanged.
    NoChange,
    /// Use a bounded transmission delay.
    UseDelay(DelayChoice),
    /// Prefer the next eligible rotation window.
    PreferEarlyRotation(LongevityChoice),
    /// Select an already-available route candidate.
    UseRouteCandidate(RouteChoice),
}

/// Envelope ceilings configured by the operator.
///
/// These are upper bounds on selectable behavior, not targets. Selection logic
/// must remain fail-closed when partitions are unsupported, unknown, or tied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorEnvelope {
    /// Maximum selectable transmission delay in milliseconds.
    pub max_delay_ms: u16,
    /// Whether early rotation may be preferred within allowances.
    pub allow_early_rotation: bool,
    /// Maximum selectable route-candidate index.
    pub max_route_candidate: u8,
}

/// Read-only atom partitions supplied to the envelope.
///
/// Columns mirror the six pilot measurement families without labels, verdicts,
/// scores, or conclusions. Unsupported columns must be rejected upstream by
/// sufficiency records, not reinterpreted here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnvelopePartitions {
    /// Timing arrangement index, 0..=1000.
    pub arrangement: u16,
    /// Timing trend magnitude, 0..=1000.
    pub trend: u16,
    /// Longevity persistence index, 0..=1000.
    pub persistence: u16,
    /// Longevity pressure magnitude, 0..=1000.
    pub pressure: u16,
    /// Route selectivity index, 0..=1000.
    pub selectivity: u16,
    /// Route rebind-shape magnitude, 0..=1000.
    pub rebind_shape: u16,
    /// Whether every source column is supported.
    pub supported: bool,
}

impl OperatorEnvelope {
    /// Select one bounded action from measured partitions.
    ///
    /// Deterministic arbitration only: the largest supported column chooses a
    /// corresponding already-available effect; ties and unsupported inputs
    /// return [`BoundedAction::NoChange`]. This function never inspects why a
    /// column moved and never invents a VPN behavior.
    pub fn select(
        &self,
        partitions: &EnvelopePartitions,
        candidate_count: u8,
    ) -> Result<BoundedAction, PolicyError> {
        if candidate_count == 0 {
            return Err(PolicyError::MalformedInput);
        }
        if !partitions.supported {
            return Ok(BoundedAction::NoChange);
        }
        for value in [
            partitions.arrangement,
            partitions.trend,
            partitions.persistence,
            partitions.pressure,
            partitions.selectivity,
            partitions.rebind_shape,
        ] {
            if value > 1000 {
                return Err(PolicyError::OutsideEnvelope);
            }
        }
        if candidate_count > self.max_route_candidate.saturating_add(1) {
            return Err(PolicyError::OutsideEnvelope);
        }

        let mut best_kind = 0u8;
        let mut best_value = 0u16;
        let mut tied = false;
        let columns = [
            (0u8, partitions.arrangement),
            (1u8, partitions.trend),
            (2u8, partitions.persistence),
            (3u8, partitions.pressure),
            (4u8, partitions.selectivity),
            (5u8, partitions.rebind_shape),
        ];
        for (kind, value) in columns {
            if value > best_value {
                best_kind = kind;
                best_value = value;
                tied = false;
            } else if value == best_value && value > 0 {
                tied = true;
            }
        }
        if best_value == 0 || tied {
            return Ok(BoundedAction::NoChange);
        }

        match best_kind {
            0 | 1 => {
                // Timing columns map only to an already-configured delay ceiling.
                let delay = best_value.min(self.max_delay_ms.saturating_mul(10) / 10);
                Ok(BoundedAction::UseDelay(DelayChoice {
                    delay_ms: delay.min(self.max_delay_ms),
                }))
            }
            2 | 3 => {
                if self.allow_early_rotation {
                    Ok(BoundedAction::PreferEarlyRotation(LongevityChoice {
                        prefer_early_rotation: true,
                    }))
                } else {
                    Ok(BoundedAction::NoChange)
                }
            }
            _ => {
                // Route columns map only to an already-available candidate index.
                // The envelope never invents destinations or overrides
                // longest-prefix selection.
                let index = (best_value % u16::from(candidate_count.max(1))) as u8;
                if index > self.max_route_candidate || index >= candidate_count {
                    Ok(BoundedAction::NoChange)
                } else {
                    Ok(BoundedAction::UseRouteCandidate(RouteChoice {
                        candidate_index: index,
                        candidate_count,
                    }))
                }
            }
        }
    }
}

/// Bounded local snapshot used only to derive already-redacted tap inputs.
///
/// This snapshot carries counters and classes that the operator assembly
/// already publishes. It never carries identities, keys, payloads, addresses,
/// routes, secrets, or private material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalSnapshot {
    /// Observed inter-arrival class, 0..=255.
    pub inter_arrival_bucket: u8,
    /// Observed delay class, 0..=255.
    pub delay_bucket: u8,
    /// Whether coalescing was reported active.
    pub coalesced: bool,
    /// Session-epoch class.
    pub session_epoch: u64,
    /// Sealed-byte class.
    pub bytes_sealed_bucket: u8,
    /// Idle class.
    pub idle_bucket: u8,
    /// Rotation already due under live allowances.
    pub rotation_due: bool,
    /// Reauthentication already requested elsewhere.
    pub reauth_required: bool,
    /// Small expiry-reason class, 0..=15.
    pub expiry_reason_code: u8,
    /// Destination class identifier.
    pub destination_class: u8,
    /// Prefix-length class, 0..=32.
    pub prefix_length: u8,
    /// Number of real candidates supplied by existing selection.
    pub candidate_count: u8,
    /// Best observed prefix-length class, 0..=32.
    pub best_prefix_length: u8,
    /// Bounded rebind-accounting class.
    pub rebind_count: u8,
    /// Whether the selected path remained stable through observation.
    pub path_stable: bool,
}

/// Read-only tap triple derived from one local snapshot.
///
/// The mapping is total on the snapshot shape and rejects malformed classes.
/// It performs no I/O, spawns nothing, reads no clock, publishes nothing, and
/// alters no state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTaps {
    /// Timing tap classes.
    pub timing: TimingTapInput,
    /// Longevity tap classes.
    pub longevity: LongevityTapInput,
    /// Route tap classes.
    pub route: RouteTapInput,
}

/// Timing observation classes accepted by the atom timing function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimingTapInput {
    /// Bounded inter-arrival bucket.
    pub inter_arrival_bucket: u8,
    /// Bounded delay bucket.
    pub delay_bucket: u8,
    /// Configured jitter ceiling already in force.
    pub jitter_ceiling_ms: u16,
    /// Whether cadence evidence is sufficient.
    pub cadence_sufficient: bool,
    /// Whether coalescing was active.
    pub coalesced: bool,
}

/// Longevity observation classes accepted by the atom longevity function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongevityTapInput {
    /// Bounded session-epoch class.
    pub session_epoch: u64,
    /// Bounded sealed-byte class.
    pub bytes_sealed_bucket: u8,
    /// Bounded idle class.
    pub idle_bucket: u8,
    /// Rotation already due under live allowances.
    pub rotation_due: bool,
    /// Reauthentication already requested elsewhere.
    pub reauth_required: bool,
    /// Small expiry-reason class, 0..=15.
    pub expiry_reason_code: u8,
}

/// Route observation classes accepted by the atom route function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteTapInput {
    /// Destination class identifier.
    pub destination_class: u8,
    /// Prefix-length class, 0..=32.
    pub prefix_length: u8,
    /// Real candidate count supplied by existing selection.
    pub candidate_count: u8,
    /// Best observed prefix-length class, 0..=32.
    pub best_prefix_length: u8,
    /// Bounded rebind-accounting class.
    pub rebind_count: u8,
    /// Whether the selected path remained stable.
    pub path_stable: bool,
}

impl LocalSnapshot {
    /// Validate one snapshot and project it onto the three tap shapes. The
    /// projection is fixed and total on valid input; malformed classes are
    /// rejected, never corrected.
    pub fn taps(&self) -> Result<PolicyTaps, PolicyError> {
        if self.expiry_reason_code > 15
            || self.prefix_length > 32
            || self.best_prefix_length > 32
            || self.candidate_count == 0
        {
            return Err(PolicyError::MalformedInput);
        }
        Ok(PolicyTaps {
            timing: TimingTapInput {
                inter_arrival_bucket: self.inter_arrival_bucket,
                delay_bucket: self.delay_bucket,
                jitter_ceiling_ms: 20,
                cadence_sufficient: true,
                coalesced: self.coalesced,
            },
            longevity: LongevityTapInput {
                session_epoch: self.session_epoch,
                bytes_sealed_bucket: self.bytes_sealed_bucket,
                idle_bucket: self.idle_bucket,
                rotation_due: self.rotation_due,
                reauth_required: self.reauth_required,
                expiry_reason_code: self.expiry_reason_code,
            },
            route: RouteTapInput {
                destination_class: self.destination_class,
                prefix_length: self.prefix_length,
                candidate_count: self.candidate_count,
                best_prefix_length: self.best_prefix_length,
                rebind_count: self.rebind_count,
                path_stable: self.path_stable,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn supported(
        arrangement: u16,
        trend: u16,
        persistence: u16,
        pressure: u16,
        selectivity: u16,
        rebind_shape: u16,
    ) -> EnvelopePartitions {
        EnvelopePartitions {
            arrangement,
            trend,
            persistence,
            pressure,
            selectivity,
            rebind_shape,
            supported: true,
        }
    }

    fn envelope() -> OperatorEnvelope {
        OperatorEnvelope {
            max_delay_ms: 80,
            allow_early_rotation: true,
            max_route_candidate: 7,
        }
    }

    #[test]
    fn unsupported_partitions_leave_state_unchanged() {
        let mut partitions = supported(900, 10, 10, 10, 10, 10);
        partitions.supported = false;
        assert_eq!(
            envelope().select(&partitions, 3),
            Ok(BoundedAction::NoChange)
        );
    }

    #[test]
    fn ties_leave_state_unchanged() {
        let partitions = supported(400, 400, 100, 100, 100, 100);
        assert_eq!(
            envelope().select(&partitions, 3),
            Ok(BoundedAction::NoChange)
        );
    }

    #[test]
    fn timing_columns_select_bounded_delay() {
        let partitions = supported(900, 10, 10, 10, 10, 10);
        assert_eq!(
            envelope().select(&partitions, 3),
            Ok(BoundedAction::UseDelay(DelayChoice { delay_ms: 80 }))
        );
    }

    #[test]
    fn longevity_columns_respect_rotation_permission() {
        let partitions = supported(10, 10, 900, 10, 10, 10);
        assert_eq!(
            envelope().select(&partitions, 3),
            Ok(BoundedAction::PreferEarlyRotation(LongevityChoice {
                prefer_early_rotation: true
            }))
        );
        let mut closed = envelope();
        closed.allow_early_rotation = false;
        assert_eq!(closed.select(&partitions, 3), Ok(BoundedAction::NoChange));
    }

    #[test]
    fn route_columns_select_only_existing_candidates() {
        let partitions = supported(10, 10, 10, 10, 900, 10);
        let action = envelope().select(&partitions, 3).unwrap();
        match action {
            BoundedAction::UseRouteCandidate(choice) => {
                assert!(choice.candidate_index < 3);
                assert_eq!(choice.candidate_count, 3);
            }
            other => panic!("expected route candidate, got {other:?}"),
        }
    }

    #[test]
    fn malformed_and_outside_envelope_inputs_are_rejected() {
        let partitions = supported(10, 10, 10, 10, 10, 10);
        assert_eq!(
            envelope().select(&partitions, 0),
            Err(PolicyError::MalformedInput)
        );
        assert_eq!(
            envelope().select(
                &EnvelopePartitions {
                    arrangement: 1001,
                    ..partitions
                },
                3
            ),
            Err(PolicyError::OutsideEnvelope)
        );
    }

    #[test]
    fn snapshot_projects_fixed_taps_and_rejects_malformed_classes() {
        let snapshot = LocalSnapshot {
            inter_arrival_bucket: 7,
            delay_bucket: 3,
            coalesced: false,
            session_epoch: 4,
            bytes_sealed_bucket: 9,
            idle_bucket: 2,
            rotation_due: false,
            reauth_required: false,
            expiry_reason_code: 1,
            destination_class: 2,
            prefix_length: 24,
            candidate_count: 3,
            best_prefix_length: 24,
            rebind_count: 0,
            path_stable: true,
        };
        let taps = snapshot.taps().expect("valid snapshot projects");
        assert_eq!(taps.timing.inter_arrival_bucket, 7);
        assert_eq!(taps.timing.delay_bucket, 3);
        assert_eq!(taps.timing.jitter_ceiling_ms, 20);
        assert!(taps.timing.cadence_sufficient);
        assert!(!taps.timing.coalesced);
        assert_eq!(taps.longevity.session_epoch, 4);
        assert_eq!(taps.longevity.bytes_sealed_bucket, 9);
        assert_eq!(taps.route.destination_class, 2);
        assert_eq!(taps.route.prefix_length, 24);
        assert_eq!(taps.route.candidate_count, 3);

        let mut bad_expiry = snapshot;
        bad_expiry.expiry_reason_code = 16;
        assert_eq!(bad_expiry.taps(), Err(PolicyError::MalformedInput));

        let mut bad_prefix = snapshot;
        bad_prefix.prefix_length = 33;
        assert_eq!(bad_prefix.taps(), Err(PolicyError::MalformedInput));

        let mut no_candidates = snapshot;
        no_candidates.candidate_count = 0;
        assert_eq!(no_candidates.taps(), Err(PolicyError::MalformedInput));
    }
}
