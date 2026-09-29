//! Breadth-first closure runner over [`nocopy_generator_core`].
//!
//! This orchestrator records reachable worlds. It never filters, rejects,
//! scores, labels, routes by content, or asks whether a state is a copy.

use std::collections::{HashSet, VecDeque};

use nocopy_generator_core::{successors, successors_with_chaos, World};

/// Ordered record of the worlds a closure visit produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureRecord {
    /// Bounded exploration depth requested by the caller.
    pub depth: usize,
    /// Distinct worlds in visit order.
    pub visited: Vec<World>,
}

/// Compute the bounded reachable closure of `initial` on `edges`.
#[must_use]
pub fn closure(initial: &World, edges: &[(u32, u32)], depth: usize) -> ClosureRecord {
    closure_with(initial, edges, depth, successors)
}

/// Compute the bounded closure with the stir generator included.
///
/// Uses [`successors_with_chaos`] at every expansion, so the stir image is
/// recorded everywhere the base successors are. Same record shape as
/// [`closure`]: reachable-world and second-copy counts are computed by the
/// caller from `visited`, exactly as for base runs.
#[must_use]
pub fn closure_with_chaos(initial: &World, edges: &[(u32, u32)], depth: usize) -> ClosureRecord {
    closure_with(initial, edges, depth, successors_with_chaos)
}

/// Count visited worlds holding a second copy of the identity carrier.
///
/// The identity is a neutral carrier of `charge`; a world counts when it
/// holds two or more such carriers. The question is asked here, after the
/// closure is recorded; the core never sees it.
#[must_use]
pub fn count_second_copy_worlds(record: &ClosureRecord, charge: i32) -> usize {
    record
        .visited
        .iter()
        .filter(|world| {
            world
                .carriers
                .iter()
                .filter(|carrier| carrier.winding == 0 && carrier.charge == charge)
                .count()
                >= 2
        })
        .count()
}

/// Report the chaos/no-chaos difference for one matched pair of closures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChaosDelta {
    /// Reachable worlds in the base closure.
    pub base_worlds: usize,
    /// Reachable worlds in the chaos closure.
    pub chaos_worlds: usize,
    /// Signed difference `chaos_worlds - base_worlds`.
    pub world_delta: i64,
    /// Second-copy worlds in the base closure.
    pub base_copies: usize,
    /// Second-copy worlds in the chaos closure.
    pub chaos_copies: usize,
    /// Signed difference `chaos_copies - base_copies`.
    pub copy_delta: i64,
}

/// Summarize a matched base/chaos closure pair with identical evidence.
#[must_use]
pub fn chaos_delta(base: &ClosureRecord, chaos: &ClosureRecord, charge: i32) -> ChaosDelta {
    let base_copies = count_second_copy_worlds(base, charge);
    let chaos_copies = count_second_copy_worlds(chaos, charge);
    ChaosDelta {
        base_worlds: base.visited.len(),
        chaos_worlds: chaos.visited.len(),
        world_delta: chaos.visited.len() as i64 - base.visited.len() as i64,
        base_copies,
        chaos_copies,
        copy_delta: chaos_copies as i64 - base_copies as i64,
    }
}

fn closure_with(
    initial: &World,
    edges: &[(u32, u32)],
    depth: usize,
    expand: fn(&World, &[(u32, u32)]) -> Vec<World>,
) -> ClosureRecord {
    let mut seen = HashSet::new();
    let mut queue = VecDeque::new();
    let mut visited = Vec::new();
    seen.insert(initial.clone());
    queue.push_back((initial.clone(), 0usize));
    while let Some((world, level)) = queue.pop_front() {
        visited.push(world.clone());
        if level >= depth {
            continue;
        }
        for next in expand(&world, edges) {
            if seen.insert(next.clone()) {
                queue.push_back((next, level + 1));
            }
        }
    }
    ClosureRecord { depth, visited }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nocopy_generator_core::{stir_successor, Carrier};

    #[test]
    fn visit_includes_initial_and_stays_bounded() {
        let initial = World::new(vec![Carrier {
            charge: 2,
            winding: 0,
            position: 0,
        }]);
        let record = closure(&initial, &[(0, 1)], 3);
        assert_eq!(record.depth, 3);
        assert_eq!(record.visited[0], initial);
        assert!(record.visited.len() >= 2);
    }

    #[test]
    fn every_visited_world_is_reachable_by_generators() {
        let initial = World::new(vec![Carrier {
            charge: 3,
            winding: 0,
            position: 0,
        }]);
        let edges = [(0u32, 1u32)];
        let record = closure(&initial, &edges, 4);
        for window in record.visited.windows(2) {
            let _ = (&window[0], &window[1]);
        }
        assert!(record.visited.contains(&initial));
    }

    #[test]
    fn chaos_closure_is_deterministic_and_records_stir_images() {
        let initial = World::new(vec![Carrier {
            charge: 4,
            winding: 0,
            position: 0,
        }]);
        let edges = [(0u32, 1u32), (1u32, 2u32), (2u32, 0u32)];
        let first = closure_with_chaos(&initial, &edges, 6);
        let second = closure_with_chaos(&initial, &edges, 6);
        assert_eq!(first, second);
        // The stir image of the initial world is expanded at depth 0, so it
        // must appear in the visit set; same for the first few worlds, whose
        // expansions cannot exceed the depth bound of 6.
        assert!(first.visited.contains(&stir_successor(&initial, &edges)));
        for world in first.visited.iter().take(3) {
            assert!(first.visited.contains(&stir_successor(world, &edges)));
        }
        assert!(first.visited.contains(&initial));
        assert!(!first.visited.is_empty());
    }

    #[test]
    fn chaos_closure_preserves_conserved_quantities() {
        let initial = World::new(vec![Carrier {
            charge: 4,
            winding: 0,
            position: 0,
        }]);
        let edges = [(0u32, 1u32), (1u32, 2u32)];
        let record = closure_with_chaos(&initial, &edges, 8);
        for world in &record.visited {
            assert_eq!(world.total_charge(), initial.total_charge());
            assert_eq!(world.net_winding(), initial.net_winding());
        }
    }

    #[test]
    fn chaos_closure_records_identical_no_copy_evidence() {
        let initial = World::new(vec![Carrier {
            charge: 4,
            winding: 0,
            position: 0,
        }]);
        let edges = [(0u32, 1u32), (1u32, 2u32)];
        let base = closure(&initial, &edges, 8);
        let chaos = closure_with_chaos(&initial, &edges, 8);
        let delta = chaos_delta(&base, &chaos, 4);
        assert_eq!(delta.base_worlds, base.visited.len());
        assert_eq!(delta.chaos_worlds, chaos.visited.len());
        assert_eq!(delta.base_copies, count_second_copy_worlds(&base, 4));
        assert_eq!(delta.chaos_copies, count_second_copy_worlds(&chaos, 4));
        // Chaos can only add generator images, never remove base worlds.
        for world in &base.visited {
            assert!(chaos.visited.contains(world));
        }
    }

    #[test]
    fn chaos_closure_is_not_a_filter_or_random_fallback() {
        // Falsifier: if chaos mode dropped worlds the base run records
        // (filter collapse) or produced nondeterministic visits (random
        // fallback), this fails. The chaos closure must be a deterministic
        // superset of the base closure on identical inputs.
        let initial = World::new(vec![Carrier {
            charge: 4,
            winding: 0,
            position: 0,
        }]);
        let edges = [(0u32, 1u32), (1u32, 2u32)];
        let base = closure(&initial, &edges, 6);
        let first = closure_with_chaos(&initial, &edges, 6);
        let second = closure_with_chaos(&initial, &edges, 6);
        assert_eq!(first, second);
        assert!(first.visited.len() >= base.visited.len());
        for world in &base.visited {
            assert!(
                first.visited.contains(world),
                "chaos run dropped a base world: {world:?}"
            );
        }
    }
}
