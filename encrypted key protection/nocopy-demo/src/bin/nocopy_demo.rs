//! Evidence harness for the generator and linear-map no-copy shapes.
//!
//! The copy/copy-count question is asked here, after both closures are
//! computed. Neither core nor orchestrator knows that question.
//!
//! Four runs are reported: Stack A base, Stack A chaos, Stack B base, and
//! Stack B chaos, plus the per-stack chaos/no-chaos differences.

use nocopy_closure_orchestrator::{chaos_delta, closure, closure_with_chaos};
use nocopy_generator_core::{Carrier, World};
use nocopy_linear_map_core::{CouplingFamily, LinearMap, State};
use nocopy_linear_map_orchestrator::{chaos_walk, sweep, walk, walk_delta};

fn main() {
    // ---- Stack A: generator closure, base vs. chaos ----
    let identity = Carrier {
        charge: 4,
        winding: 0,
        position: 0,
    };
    let initial = World::new(vec![identity]);
    let edges = [(0u32, 1u32), (1u32, 2u32), (2u32, 0u32)];
    let base_closure = closure(&initial, &edges, 12);
    let chaos_closure = closure_with_chaos(&initial, &edges, 12);
    let delta = chaos_delta(&base_closure, &chaos_closure, 4);

    println!(
        "stack A base: reachable worlds: {}",
        base_closure.visited.len()
    );
    println!(
        "stack A base: worlds containing a second copy of the identity: {}",
        delta.base_copies
    );
    println!(
        "stack A chaos: reachable worlds: {}",
        chaos_closure.visited.len()
    );
    println!(
        "stack A chaos: worlds containing a second copy of the identity: {}",
        delta.chaos_copies
    );
    println!(
        "stack A delta: worlds {:+}, second-copy worlds {:+}",
        delta.world_delta, delta.copy_delta
    );
    // Composite initial: the stir rearranges split pairs apart, so the chaos
    // closure reaches arrangement-dynamics worlds the base closure cannot.
    let composite = World::new(vec![
        Carrier {
            charge: 4,
            winding: 0,
            position: 0,
        },
        Carrier {
            charge: 3,
            winding: 1,
            position: 0,
        },
        Carrier {
            charge: 2,
            winding: -1,
            position: 1,
        },
    ]);
    let base_wide = closure(&composite, &edges, 8);
    let chaos_wide = closure_with_chaos(&composite, &edges, 8);
    let wide = chaos_delta(&base_wide, &chaos_wide, 4);
    println!(
        "stack A wide (composite initial): base worlds {}, chaos worlds {}, delta {:+}; second-copy base {}, chaos {}, delta {:+}",
        wide.base_worlds,
        wide.chaos_worlds,
        wide.world_delta,
        wide.base_copies,
        wide.chaos_copies,
        wide.copy_delta
    );
    let mut sample: Vec<_> = chaos_closure.visited.iter().collect();
    sample.sort_by_key(|world| world.carriers.len());
    for world in sample.iter().take(8) {
        println!("  {:?}", world.carriers);
    }

    // ---- Stack B: linear walks, base vs. chaos ----
    let maps = [
        LinearMap::cyclic_shift(),
        LinearMap::swap_first_two(),
        LinearMap::cyclic_shift(),
        LinearMap::swap_first_two(),
    ];
    let base_walk = walk(State([4.0, 0.0, 0.0]), &maps);
    let calm = CouplingFamily::new(0.25);
    let wild = CouplingFamily::new(1.75);
    let chaos_calm = chaos_walk(State([4.0, 0.0, 0.0]), calm, maps.len());
    let chaos_wild = chaos_walk(State([4.0, 0.0, 0.0]), wild, maps.len());
    let calm_delta = walk_delta(&base_walk, &chaos_calm);
    let wild_delta = walk_delta(&base_walk, &chaos_wild);

    println!(
        "stack B base: linear walk steps: {}",
        base_walk.composites.len()
    );
    println!(
        "stack B base: linear readout degrees: {:?}",
        base_walk.degrees
    );
    println!(
        "stack B chaos (coupling {}): steps: {}, degrees: {:?}",
        calm.coupling,
        chaos_calm.composites.len(),
        chaos_calm.degrees
    );
    println!(
        "stack B chaos (coupling {}): steps: {}, degrees: {:?}",
        wild.coupling,
        chaos_wild.composites.len(),
        chaos_wild.degrees
    );
    println!(
        "stack B delta (base vs coupling {}): steps {:+}, final separation {:.6}",
        calm.coupling, calm_delta.step_delta, calm_delta.final_separation
    );
    println!(
        "stack B delta (base vs coupling {}): steps {:+}, final separation {:.6}",
        wild.coupling, wild_delta.step_delta, wild_delta.final_separation
    );
    let swept = sweep(State([4.0, 0.0, 0.0]), &[0.25, 1.0, 1.75], maps.len());
    for (coupling, record) in [0.25, 1.0, 1.75].iter().zip(swept.iter()) {
        let last = record.states.last().unwrap();
        println!(
            "  sweep coupling {coupling}: final state {:?}, degrees {:?}",
            last.0, record.degrees
        );
    }
    println!("clone map is quadratic, therefore outside the linear monoid");
}
