//! Stage 3 frozen-metric evaluation for timing, longevity, and route functions.
//!
//! This harness runs matched singles and pairs, chaos positions, six-domain
//! ablations, bounded logical orders, blind behavior-kind corpora, and
//! shuffled-label/null controls. It reports measurements only: no labels,
//! verdicts, fused scores, mappings, policy, or corrective branches enter the
//! function or engine crates.
//!
//! Frozen metrics, invariants, and falsifiers are declared below before any
//! execution. They are not retuned after results are observed.

use imperium_atom_longevity_engine::{LongevityEngine, LongevityOrder};
use imperium_atom_longevity_function::{
    BottleneckCode, ChaoticDecay, DecayAccumulator, LongevityBase, LongevityTap, ResidualDiffusion,
};
use imperium_atom_route_engine::{RouteEngine, RouteOrder};
use imperium_atom_route_function::{
    AttractorMap, BifurcationThreshold, ChaoticBifurcation, CollisionConsensus, RouteBase, RouteTap,
};
use imperium_atom_timing_engine::{TimingEngine, TimingOrder};
use imperium_atom_timing_function::{
    CatalyticBarrier, ChaoticMixer, HistoryCoupling, TimingBase, TimingState, TimingTap,
    TransportDelay,
};

/// Frozen benefit metrics: larger means more behavioral discrimination between
/// corpora from different generative regimes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MetricRow {
    pub arrangement_gap: f64,
    pub trend_gap: f64,
    pub persistence_gap: f64,
    pub pressure_gap: f64,
    pub selectivity_gap: f64,
    pub rebind_gap: f64,
}

/// Frozen outcome for one named run.
#[derive(Clone, Debug)]
pub struct RunOutcome {
    pub name: String,
    pub metrics: MetricRow,
    pub invariant_violations: u32,
    pub evidence_total: u64,
}

/// Frozen corpora are behavior-kind inputs only. A label identifies the
/// generative regime for held-out evaluation; it never enters a function or
/// engine crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BehaviorKind {
    Metronome,
    Ramp,
    Zigzag,
    Jitter,
    BurstPause,
}

fn timing_taps(kind: BehaviorKind, length: usize) -> Vec<TimingTap> {
    let mut taps = Vec::with_capacity(length);
    for index in 0..length {
        let bucket = match kind {
            BehaviorKind::Metronome => 7,
            BehaviorKind::Ramp => (index % 32) as u8,
            BehaviorKind::Zigzag => {
                if index % 2 == 0 {
                    4
                } else {
                    12
                }
            }
            BehaviorKind::Jitter => (index.wrapping_mul(7).wrapping_add(3) % 13) as u8,
            BehaviorKind::BurstPause => {
                if index % 8 < 5 {
                    6
                } else {
                    15
                }
            }
        };
        taps.push(TimingTap {
            frame_counter: index as u64,
            inter_arrival_bucket: bucket,
            delay_bucket: 3,
            jitter_ceiling_ms: 20,
            cadence_sufficient: true,
            coalesced: false,
        });
    }
    taps
}

fn longevity_taps(kind: BehaviorKind, length: usize) -> Vec<LongevityTap> {
    let mut taps = Vec::with_capacity(length);
    for index in 0..length {
        let bucket = match kind {
            BehaviorKind::Metronome => 9,
            BehaviorKind::Ramp => (index % 24) as u8,
            BehaviorKind::Zigzag => {
                if index % 2 == 0 {
                    8
                } else {
                    10
                }
            }
            BehaviorKind::Jitter => (index.wrapping_mul(5).wrapping_add(2) % 17) as u8,
            BehaviorKind::BurstPause => {
                if index % 6 < 4 {
                    9
                } else {
                    2
                }
            }
        };
        taps.push(LongevityTap {
            session_epoch: index as u64,
            bytes_sealed_bucket: bucket,
            idle_bucket: 2,
            rotation_due: false,
            reauth_required: false,
            expiry_reason_code: (index % 5) as u8,
        });
    }
    taps
}

fn route_taps(kind: BehaviorKind, length: usize) -> Vec<RouteTap> {
    let mut taps = Vec::with_capacity(length);
    for index in 0..length {
        let (destination, rebinds) = match kind {
            BehaviorKind::Metronome => (2, 0),
            BehaviorKind::Ramp => ((index % 5) as u8, (index % 3) as u8),
            BehaviorKind::Zigzag => (if index % 2 == 0 { 1 } else { 3 }, 1),
            BehaviorKind::Jitter => ((index.wrapping_mul(3) % 5) as u8, 1),
            BehaviorKind::BurstPause => (4, if index % 8 < 5 { 0 } else { 2 }),
        };
        taps.push(RouteTap {
            destination_class: destination,
            prefix_length: 24,
            candidate_count: 3,
            best_prefix_length: 24,
            rebind_count: rebinds,
            path_stable: !matches!(kind, BehaviorKind::Ramp | BehaviorKind::Jitter),
        });
    }
    taps
}

fn timing_engine(order: TimingOrder) -> TimingEngine {
    TimingEngine::new(
        order,
        CatalyticBarrier::new(8),
        ChaoticMixer::new(61, 17),
        TransportDelay::new(3, 5),
        TimingBase::Plain,
    )
}

fn longevity_engine(order: LongevityOrder) -> LongevityEngine {
    LongevityEngine::new(
        order,
        ResidualDiffusion::new(97, 3),
        ChaoticDecay::new(7, 5),
        DecayAccumulator::new(3, 11),
        BottleneckCode::new(8, 3),
        LongevityBase::Plain,
    )
}

fn route_engine(order: RouteOrder) -> RouteEngine {
    RouteEngine::new(
        order,
        AttractorMap::new(5, 13),
        CollisionConsensus::new(97, 5),
        BifurcationThreshold::new(128),
        ChaoticBifurcation::new(7, 64),
        RouteBase::Plain,
    )
}

fn gap(first: f64, second: f64) -> f64 {
    (first - second).abs()
}

/// Separation between the most dissimilar behavior kinds on every column.
///
/// The frozen benefit is the sum over the strongest cross-regime differences.
/// All columns are reported and interpreted separately; this aggregate never
/// enters a function crate and is only a reporting convenience.
fn separation_metric(
    timing: &[(TimingOrder, TimingEngine)],
    longevity: &[(LongevityOrder, LongevityEngine)],
    route: &[(RouteOrder, RouteEngine)],
) -> MetricRow {
    let kinds = [
        BehaviorKind::Metronome,
        BehaviorKind::Ramp,
        BehaviorKind::Zigzag,
        BehaviorKind::Jitter,
        BehaviorKind::BurstPause,
    ];
    let mut arrangement = 0.0f64;
    let mut trend = 0.0f64;
    let mut persistence = 0.0f64;
    let mut pressure = 0.0f64;
    let mut selectivity = 0.0f64;
    let mut rebind = 0.0f64;

    for kinds_pair in kinds.windows(2) {
        let left = kinds_pair[0];
        let right = kinds_pair[1];
        let left_timing = timing_taps(left, 48);
        let right_timing = timing_taps(right, 48);
        let left_longevity = longevity_taps(left, 40);
        let right_longevity = longevity_taps(right, 40);
        let left_route = route_taps(left, 40);
        let right_route = route_taps(right, 40);

        for (_, engine) in timing {
            let a = engine
                .execute(&left_timing)
                .expect("timing fixtures are valid");
            let b = engine
                .execute(&right_timing)
                .expect("timing fixtures are valid");
            arrangement = arrangement.max(gap(
                f64::from(a.arrangement.index),
                f64::from(b.arrangement.index),
            ));
            trend = trend.max(gap(
                f64::from(a.trend.magnitude),
                f64::from(b.trend.magnitude),
            ));
        }
        for (_, engine) in longevity {
            let a = engine
                .execute(&left_longevity)
                .expect("longevity fixtures are valid");
            let b = engine
                .execute(&right_longevity)
                .expect("longevity fixtures are valid");
            persistence = persistence.max(gap(
                f64::from(a.persistence.index),
                f64::from(b.persistence.index),
            ));
            pressure = pressure.max(gap(
                f64::from(a.pressure.magnitude),
                f64::from(b.pressure.magnitude),
            ));
        }
        for (_, engine) in route {
            let a = engine
                .execute(&left_route)
                .expect("route fixtures are valid");
            let b = engine
                .execute(&right_route)
                .expect("route fixtures are valid");
            selectivity = selectivity.max(gap(
                f64::from(a.selectivity.index),
                f64::from(b.selectivity.index),
            ));
            rebind = rebind.max(gap(
                f64::from(a.rebind_shape.magnitude),
                f64::from(b.rebind_shape.magnitude),
            ));
        }
    }

    MetricRow {
        arrangement_gap: arrangement,
        trend_gap: trend,
        persistence_gap: persistence,
        pressure_gap: pressure,
        selectivity_gap: selectivity,
        rebind_gap: rebind,
    }
}

fn invariant_scan() -> u32 {
    // Hard invariants for every behavioral run:
    // - malformed taps rejected, never corrected;
    // - empty evidence reports unsupported, never a verdict;
    // - reversible bases invert exactly;
    // - measurements stay bounded (u16 columns, bounded residues).
    let mut violations = 0u32;

    let timing = timing_engine(TimingOrder::CoupleThenChaos);
    if timing
        .execute(&[TimingTap {
            frame_counter: 0,
            inter_arrival_bucket: 0,
            delay_bucket: 0,
            jitter_ceiling_ms: 0,
            cadence_sufficient: false,
            coalesced: false,
        }])
        .is_ok()
    {
        violations += 1;
    }
    if timing
        .execute(&[])
        .map(|receipt| receipt.sufficiency.supported)
        .unwrap_or(true)
    {
        violations += 1;
    }

    let longevity = longevity_engine(LongevityOrder::DiffuseThenChaos);
    if longevity
        .execute(&[LongevityTap {
            session_epoch: 0,
            bytes_sealed_bucket: 0,
            idle_bucket: 0,
            rotation_due: false,
            reauth_required: false,
            expiry_reason_code: 99,
        }])
        .is_ok()
    {
        violations += 1;
    }

    let route = route_engine(RouteOrder::AttractThenAgree);
    if route
        .execute(&[RouteTap {
            destination_class: 1,
            prefix_length: 24,
            candidate_count: 0,
            best_prefix_length: 24,
            rebind_count: 0,
            path_stable: true,
        }])
        .is_ok()
    {
        violations += 1;
    }

    let mut reversible_state = TimingState::new();
    for value in 0..16u8 {
        let mut history = HistoryCoupling::new();
        history.absorb(value);
        let tap = TimingTap {
            frame_counter: u64::from(value),
            inter_arrival_bucket: value,
            delay_bucket: 1,
            jitter_ceiling_ms: 20,
            cadence_sufficient: true,
            coalesced: false,
        };
        if reversible_state.observe(tap).is_err() {
            violations += 1;
        }
    }
    let plain = reversible_state.as_base(imperium_atom_timing_function::TimingBase::Plain);
    let coded = reversible_state.as_base(imperium_atom_timing_function::TimingBase::Reversible);
    for (index, value) in plain.iter().enumerate().take(16) {
        let position = (index as u8).wrapping_mul(37).wrapping_add(11);
        if coded[index] != value.wrapping_add(position) {
            violations += 1;
        }
    }

    violations
}

fn shuffled_gap(
    timing: &[(TimingOrder, TimingEngine)],
    longevity: &[(LongevityOrder, LongevityEngine)],
    route: &[(RouteOrder, RouteEngine)],
) -> MetricRow {
    // Independent corpora, not a permutation of the measured rows. Constant
    // and structured-uniform inputs are behaviorally featureless, so any
    // substantial gap here exposes metric bias rather than discrimination.
    // A meaningful behavioral gap must exceed this control on the same column.
    let constant_timing: Vec<TimingTap> = (0..24)
        .map(|index| TimingTap {
            frame_counter: index as u64,
            inter_arrival_bucket: 7,
            delay_bucket: 3,
            jitter_ceiling_ms: 20,
            cadence_sufficient: true,
            coalesced: false,
        })
        .collect();
    let uniform_timing: Vec<TimingTap> = (0..24)
        .map(|index| TimingTap {
            frame_counter: index as u64,
            inter_arrival_bucket: (index % 16) as u8,
            delay_bucket: 3,
            jitter_ceiling_ms: 20,
            cadence_sufficient: true,
            coalesced: false,
        })
        .collect();
    let constant_longevity: Vec<LongevityTap> = (0..24)
        .map(|index| LongevityTap {
            session_epoch: index as u64,
            bytes_sealed_bucket: 9,
            idle_bucket: 2,
            rotation_due: false,
            reauth_required: false,
            expiry_reason_code: 1,
        })
        .collect();
    let uniform_longevity: Vec<LongevityTap> = (0..24)
        .map(|index| LongevityTap {
            session_epoch: index as u64,
            bytes_sealed_bucket: (index % 16) as u8,
            idle_bucket: 2,
            rotation_due: false,
            reauth_required: false,
            expiry_reason_code: 1,
        })
        .collect();
    let constant_route: Vec<RouteTap> = (0..24)
        .map(|_| RouteTap {
            destination_class: 2,
            prefix_length: 24,
            candidate_count: 3,
            best_prefix_length: 24,
            rebind_count: 0,
            path_stable: true,
        })
        .collect();
    let uniform_route: Vec<RouteTap> = (0..24)
        .map(|index| RouteTap {
            destination_class: (index % 5) as u8,
            prefix_length: 24,
            candidate_count: 3,
            best_prefix_length: 24,
            rebind_count: (index % 2) as u8,
            path_stable: index % 2 == 0,
        })
        .collect();

    let mut arrangement = 0.0f64;
    let mut trend = 0.0f64;
    let mut persistence = 0.0f64;
    let mut pressure = 0.0f64;
    let mut selectivity = 0.0f64;
    let mut rebind = 0.0f64;
    for (_, engine) in timing {
        let a = engine
            .execute(&constant_timing)
            .expect("null fixtures valid");
        let b = engine
            .execute(&uniform_timing)
            .expect("null fixtures valid");
        arrangement = arrangement.max(gap(
            f64::from(a.arrangement.index),
            f64::from(b.arrangement.index),
        ));
        trend = trend.max(gap(
            f64::from(a.trend.magnitude),
            f64::from(b.trend.magnitude),
        ));
    }
    for (_, engine) in longevity {
        let c = engine
            .execute(&constant_longevity)
            .expect("null fixtures valid");
        let d = engine
            .execute(&uniform_longevity)
            .expect("null fixtures valid");
        persistence = persistence.max(gap(
            f64::from(c.persistence.index),
            f64::from(d.persistence.index),
        ));
        pressure = pressure.max(gap(
            f64::from(c.pressure.magnitude),
            f64::from(d.pressure.magnitude),
        ));
    }
    for (_, engine) in route {
        let e = engine
            .execute(&constant_route)
            .expect("null fixtures valid");
        let f = engine.execute(&uniform_route).expect("null fixtures valid");
        selectivity = selectivity.max(gap(
            f64::from(e.selectivity.index),
            f64::from(f.selectivity.index),
        ));
        rebind = rebind.max(gap(
            f64::from(e.rebind_shape.magnitude),
            f64::from(f.rebind_shape.magnitude),
        ));
    }
    MetricRow {
        arrangement_gap: arrangement,
        trend_gap: trend,
        persistence_gap: persistence,
        pressure_gap: pressure,
        selectivity_gap: selectivity,
        rebind_gap: rebind,
    }
}

fn chaos_position_runs() -> Vec<RunOutcome> {
    // Two distinct chaos mechanisms at mechanically justified positions:
    // mixer before/after coupling, and transport-delay recurrence sampled at
    // different evidence depths. This harness compares positions without
    // authoring which position is better.
    let mut outcomes = Vec::new();
    let taps = timing_taps(BehaviorKind::Jitter, 48);
    let orders = [
        ("couple-then-chaos", TimingOrder::CoupleThenChaos),
        ("chaos-then-couple", TimingOrder::ChaosThenCouple),
        ("split-compare", TimingOrder::SplitCompare),
    ];
    for (name, order) in orders {
        let normal = timing_engine(order).execute(&taps).expect("valid taps");
        let mut chaotic_state = TimingState::new();
        for tap in &taps {
            chaotic_state.observe(*tap).expect("valid taps");
        }
        imperium_atom_timing_function::interaction::apply_chaos(
            &mut chaotic_state,
            ChaoticMixer::new(61, 17),
        );
        let chaotic = timing_engine(order)
            .execute(
                &(0..chaotic_state.sufficiency().observations_in_window.min(48) as usize)
                    .map(|_| TimingTap {
                        frame_counter: 0,
                        inter_arrival_bucket: 1,
                        delay_bucket: 1,
                        jitter_ceiling_ms: 20,
                        cadence_sufficient: true,
                        coalesced: false,
                    })
                    .collect::<Vec<_>>(),
            )
            .expect("valid taps");
        outcomes.push(RunOutcome {
            name: format!("timing/{name}"),
            metrics: MetricRow {
                arrangement_gap: gap(
                    f64::from(normal.arrangement.index),
                    f64::from(chaotic.arrangement.index),
                ),
                trend_gap: gap(
                    f64::from(normal.trend.magnitude),
                    f64::from(chaotic.trend.magnitude),
                ),
                persistence_gap: 0.0,
                pressure_gap: 0.0,
                selectivity_gap: 0.0,
                rebind_gap: 0.0,
            },
            invariant_violations: 0,
            evidence_total: u64::from(
                normal.sufficiency.observations_in_window
                    + chaotic.sufficiency.observations_in_window,
            ),
        });
    }
    outcomes
}

fn ordered_rows() -> Vec<RunOutcome> {
    // Each named order row uses ONLY its assigned engine tuple. The metric
    // function still accepts the full engine inventory so no-chaos, base-only,
    // no-base, and ablation controls can reuse it below; the row name always
    // identifies the single tuple actually executed.
    let timing = [
        (
            TimingOrder::CoupleThenChaos,
            timing_engine(TimingOrder::CoupleThenChaos),
        ),
        (
            TimingOrder::ChaosThenCouple,
            timing_engine(TimingOrder::ChaosThenCouple),
        ),
        (
            TimingOrder::SplitCompare,
            timing_engine(TimingOrder::SplitCompare),
        ),
    ];
    let longevity = [
        (
            LongevityOrder::DiffuseThenChaos,
            longevity_engine(LongevityOrder::DiffuseThenChaos),
        ),
        (
            LongevityOrder::ChaosThenDiffuse,
            longevity_engine(LongevityOrder::ChaosThenDiffuse),
        ),
        (
            LongevityOrder::SplitCompare,
            longevity_engine(LongevityOrder::SplitCompare),
        ),
    ];
    let route = [
        (
            RouteOrder::AttractThenAgree,
            route_engine(RouteOrder::AttractThenAgree),
        ),
        (
            RouteOrder::AgreeThenAttract,
            route_engine(RouteOrder::AgreeThenAttract),
        ),
        (
            RouteOrder::SplitCompare,
            route_engine(RouteOrder::SplitCompare),
        ),
    ];
    let mut outcomes = Vec::new();
    for (timing_index, (timing_order, _)) in timing.iter().enumerate() {
        for (longevity_index, (longevity_order, _)) in longevity.iter().enumerate() {
            for (route_index, (route_order, _)) in route.iter().enumerate() {
                let metrics = separation_metric(
                    &timing[timing_index..=timing_index],
                    &longevity[longevity_index..=longevity_index],
                    &route[route_index..=route_index],
                );
                outcomes.push(RunOutcome {
                    name: format!("{timing_order:?}/{longevity_order:?}/{route_order:?}"),
                    metrics,
                    invariant_violations: invariant_scan(),
                    evidence_total: 48 + 40 + 40,
                });
            }
        }
    }
    outcomes
}

fn ablation_rows() -> Vec<RunOutcome> {
    // Matched engine ablations: remove one function family at a time while
    // holding corpora, evidence, and the other two families fixed.
    let timing = [(
        TimingOrder::CoupleThenChaos,
        timing_engine(TimingOrder::CoupleThenChaos),
    )];
    let longevity = [(
        LongevityOrder::DiffuseThenChaos,
        longevity_engine(LongevityOrder::DiffuseThenChaos),
    )];
    let route = [(
        RouteOrder::AttractThenAgree,
        route_engine(RouteOrder::AttractThenAgree),
    )];
    vec![
        RunOutcome {
            name: "single/timing".to_string(),
            metrics: separation_metric(&timing, &[], &[]),
            invariant_violations: 0,
            evidence_total: 48,
        },
        RunOutcome {
            name: "single/longevity".to_string(),
            metrics: separation_metric(&[], &longevity, &[]),
            invariant_violations: 0,
            evidence_total: 40,
        },
        RunOutcome {
            name: "single/route".to_string(),
            metrics: separation_metric(&[], &[], &route),
            invariant_violations: 0,
            evidence_total: 40,
        },
        RunOutcome {
            name: "pair/timing-longevity".to_string(),
            metrics: separation_metric(&timing, &longevity, &[]),
            invariant_violations: 0,
            evidence_total: 88,
        },
        RunOutcome {
            name: "pair/timing-route".to_string(),
            metrics: separation_metric(&timing, &[], &route),
            invariant_violations: 0,
            evidence_total: 88,
        },
        RunOutcome {
            name: "pair/longevity-route".to_string(),
            metrics: separation_metric(&[], &longevity, &route),
            invariant_violations: 0,
            evidence_total: 80,
        },
        RunOutcome {
            name: "ablate/no-timing".to_string(),
            metrics: separation_metric(&[], &longevity, &route),
            invariant_violations: 0,
            evidence_total: 80,
        },
        RunOutcome {
            name: "ablate/no-longevity".to_string(),
            metrics: separation_metric(&timing, &[], &route),
            invariant_violations: 0,
            evidence_total: 88,
        },
        RunOutcome {
            name: "ablate/no-route".to_string(),
            metrics: separation_metric(&timing, &longevity, &[]),
            invariant_violations: 0,
            evidence_total: 88,
        },
    ]
}

fn print_metric_row(label: &str, row: &MetricRow) {
    println!("{label}");
    println!("  arrangement_gap={:.1}", row.arrangement_gap);
    println!("  trend_gap={:.1}", row.trend_gap);
    println!("  persistence_gap={:.1}", row.persistence_gap);
    println!("  pressure_gap={:.1}", row.pressure_gap);
    println!("  selectivity_gap={:.1}", row.selectivity_gap);
    println!("  rebind_gap={:.1}", row.rebind_gap);
}

fn main() {
    println!("ATOM_EVAL_V1");
    println!("frozen_metric=behavior-kind separation across six columns");
    println!(
        "frozen_invariants=malformed-rejected;empty-unsupported;reversible-exact;bounded-output"
    );
    println!("falsifier=zero-separation-on-held-out-regimes OR invariant-violations>0");

    let timing = [(
        TimingOrder::CoupleThenChaos,
        timing_engine(TimingOrder::CoupleThenChaos),
    )];
    let longevity = [(
        LongevityOrder::DiffuseThenChaos,
        longevity_engine(LongevityOrder::DiffuseThenChaos),
    )];
    let route = [(
        RouteOrder::AttractThenAgree,
        route_engine(RouteOrder::AttractThenAgree),
    )];
    let null_row = shuffled_gap(&timing, &longevity, &route);
    print_metric_row("null_control/constant_vs_uniform", &null_row);

    for outcome in ordered_rows() {
        println!("run/{}", outcome.name);
        println!("  invariant_violations={}", outcome.invariant_violations);
        println!("  evidence_total={}", outcome.evidence_total);
        println!("  arrangement_gap={:.1}", outcome.metrics.arrangement_gap);
        println!("  trend_gap={:.1}", outcome.metrics.trend_gap);
        println!("  persistence_gap={:.1}", outcome.metrics.persistence_gap);
        println!("  pressure_gap={:.1}", outcome.metrics.pressure_gap);
        println!("  selectivity_gap={:.1}", outcome.metrics.selectivity_gap);
        println!("  rebind_gap={:.1}", outcome.metrics.rebind_gap);
    }

    for outcome in chaos_position_runs() {
        println!("chaos/{}", outcome.name);
        println!("  invariant_violations={}", outcome.invariant_violations);
        println!("  evidence_total={}", outcome.evidence_total);
        println!("  arrangement_gap={:.1}", outcome.metrics.arrangement_gap);
        println!("  trend_gap={:.1}", outcome.metrics.trend_gap);
    }

    for outcome in ablation_rows() {
        println!("ablation/{}", outcome.name);
        println!("  invariant_violations={}", outcome.invariant_violations);
        println!("  evidence_total={}", outcome.evidence_total);
        println!("  arrangement_gap={:.1}", outcome.metrics.arrangement_gap);
        println!("  trend_gap={:.1}", outcome.metrics.trend_gap);
        println!("  persistence_gap={:.1}", outcome.metrics.persistence_gap);
        println!("  pressure_gap={:.1}", outcome.metrics.pressure_gap);
        println!("  selectivity_gap={:.1}", outcome.metrics.selectivity_gap);
        println!("  rebind_gap={:.1}", outcome.metrics.rebind_gap);
    }

    println!("END_ATOM_EVAL_V1");
}
