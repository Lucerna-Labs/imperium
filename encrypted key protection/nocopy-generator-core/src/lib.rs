//! Move/Split/Merge carrier generators only.
//!
//! There is no validity check, predicate, filter, or copy test here.
//! Every reachable state is a composition of the three generators below.

/// A carrier: an integer charge, a winding class, and a graph position.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Carrier {
    /// Conserved additive quantity carried by this carrier.
    pub charge: i32,
    /// Winding class: -1, 0, or +1.
    pub winding: i32,
    /// Position on the causal graph.
    pub position: u32,
}

/// A multiset of carriers in canonical order.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct World {
    /// Carriers, kept sorted by `(position, winding, charge)`.
    pub carriers: Vec<Carrier>,
}

impl World {
    /// Build a world and normalize carrier order.
    pub fn new(carriers: Vec<Carrier>) -> Self {
        let mut world = World { carriers };
        world.sort();
        world
    }

    fn sort(&mut self) {
        self.carriers
            .sort_by_key(|carrier| (carrier.position, carrier.winding, carrier.charge));
    }

    /// Normalized copy of this world.
    #[must_use]
    pub fn canonical(mut self) -> Self {
        self.sort();
        self
    }

    /// Total charge. Each generator below preserves it by construction.
    #[must_use]
    pub fn total_charge(&self) -> i32 {
        self.carriers.iter().map(|carrier| carrier.charge).sum()
    }

    /// Net winding. Each generator below preserves it by construction.
    #[must_use]
    pub fn net_winding(&self) -> i32 {
        self.carriers.iter().map(|carrier| carrier.winding).sum()
    }
}

/// One application of Move: relocate a carrier along a causal edge.
#[must_use]
pub fn move_successors(world: &World, edges: &[(u32, u32)]) -> Vec<World> {
    let mut out = Vec::new();
    for (index, carrier) in world.carriers.iter().enumerate() {
        for &(from, to) in edges {
            if carrier.position == from {
                let mut next = world.clone();
                next.carriers[index].position = to;
                out.push(next.canonical());
            }
        }
    }
    out
}

/// One application of Split: a neutral carrier of charge >= 2 becomes a
/// complementary (+1, -1) pair whose charges sum to the original.
#[must_use]
pub fn split_successors(world: &World) -> Vec<World> {
    let mut out = Vec::new();
    for (index, carrier) in world.carriers.iter().enumerate() {
        if carrier.winding == 0 && carrier.charge >= 2 {
            for share in 1..carrier.charge {
                let mut next = world.clone();
                next.carriers.swap_remove(index);
                next.carriers.push(Carrier {
                    charge: share,
                    winding: 1,
                    position: carrier.position,
                });
                next.carriers.push(Carrier {
                    charge: carrier.charge - share,
                    winding: -1,
                    position: carrier.position,
                });
                out.push(next.canonical());
            }
        }
    }
    out
}

/// One application of Merge: a complementary pair at one position becomes a
/// single neutral carrier whose charge is the sum of the pair.
#[must_use]
pub fn merge_successors(world: &World) -> Vec<World> {
    let mut out = Vec::new();
    for first in 0..world.carriers.len() {
        for second in (first + 1)..world.carriers.len() {
            let a = world.carriers[first];
            let b = world.carriers[second];
            if a.winding == -b.winding && a.winding != 0 && a.position == b.position {
                let mut next = world.clone();
                let removed_b = next.carriers.swap_remove(second);
                let removed_a = next.carriers.swap_remove(first);
                next.carriers.push(Carrier {
                    charge: removed_a.charge + removed_b.charge,
                    winding: 0,
                    position: removed_a.position,
                });
                out.push(next.canonical());
            }
        }
    }
    out
}

/// Every one-step successor under Move, Split, and Merge.
#[must_use]
pub fn successors(world: &World, edges: &[(u32, u32)]) -> Vec<World> {
    let mut out = move_successors(world, edges);
    out.extend(split_successors(world));
    out.extend(merge_successors(world));
    out
}

/// Intrinsic chaotic stir of the arrangement (Stack A mechanism only).
///
/// A bounded nonlinear recurrence over carrier charge classes. Charge values
/// and winding classes select recurrence coefficients; iteration relocates
/// each carrier along `edges` by a deterministically computed hop count.
/// No predicate, filter, label, score, policy, or copy check is involved:
/// the single stir image is always produced, even when it coincides with the
/// input world.
///
/// Conserved quantities are untouched by construction: the stir copies every
/// carrier's `charge` and `winding` verbatim and only rewrites `position`.
/// Chaos acts on arrangement/position dynamics, never on conserved charge.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StirState {
    /// Bounded nonlinear recurrence state.
    pub value: u64,
}

/// Seed the stir recurrence from a world's charge classes.
///
/// The seed folds each carrier's charge magnitude with a small odd
/// multiplier so distinct charge multisets deterministically select distinct
/// trajectories. Winding and position do not enter the seed; they are what
/// the recurrence later rearranges.
#[must_use]
pub fn stir_seed(world: &World) -> StirState {
    let mut value: u64 = 0x9E37_79B9_7F4A_7C15;
    for carrier in &world.carriers {
        let magnitude = carrier.charge.unsigned_abs() as u64;
        value = value
            .wrapping_mul(31)
            .wrapping_add(magnitude.wrapping_mul(7).wrapping_add(1));
    }
    StirState { value }
}

/// Advance the bounded nonlinear recurrence one step.
///
/// `x <- (a * x^2 + b * x + c) mod m` with odd `a`, nonzero `b`, and a
/// fixed odd modulus. All arithmetic is wrapping/deterministic; there is no
/// RNG, clock, or environment read. Different seeds follow different bounded
/// orbits, which is the only source of irregularity.
#[must_use]
pub fn stir_step(state: StirState) -> StirState {
    const A: u64 = 1_103_515_245;
    const B: u64 = 12_345;
    const C: u64 = 7;
    const M: u64 = 1 << 31;
    let x = state.value % M;
    StirState {
        value: (A.wrapping_mul(x).wrapping_mul(x))
            .wrapping_add(B.wrapping_mul(x))
            .wrapping_add(C)
            % M,
    }
}

/// Advance the recurrence `rounds` steps from the seed. Pure iteration.
#[must_use]
pub fn stir_advance(seed: StirState, rounds: usize) -> StirState {
    let mut state = seed;
    for _ in 0..rounds {
        state = stir_step(state);
    }
    state
}

/// The single stir image of `world`: same carriers, rearranged positions.
///
/// For carrier `i` (in canonical order) the hop count is
/// `stir_advance(seed, i + 1).value % edges.len()`. Carrier `i` walks that
/// many edges forward from its current position, wrapping around `edges`.
/// With no edges, or an empty world, the image is the input world.
/// Charge and winding are copied verbatim, so total charge and net winding
/// are preserved exactly.
#[must_use]
pub fn stir_successor(world: &World, edges: &[(u32, u32)]) -> World {
    if world.carriers.is_empty() || edges.is_empty() {
        return world.clone();
    }
    let seed = stir_seed(world);
    // Position lookup: from-node -> index of first outgoing edge.
    let mut carriers = world.carriers.clone();
    for (i, carrier) in carriers.iter_mut().enumerate() {
        let hops = stir_advance(seed, i + 1).value % (edges.len() as u64);
        let mut position = carrier.position;
        for _ in 0..hops {
            let mut next_position = position;
            for &(from, to) in edges {
                if from == position {
                    next_position = to;
                    break;
                }
            }
            position = next_position;
        }
        carrier.position = position;
    }
    World::new(carriers)
}

/// Every one-step successor under Move, Split, Merge, plus the stir image.
///
/// The stir image is appended unconditionally: it is a fourth generator, not
/// a rule about the other three.
#[must_use]
pub fn successors_with_chaos(world: &World, edges: &[(u32, u32)]) -> Vec<World> {
    let mut out = successors(world, edges);
    out.push(stir_successor(world, edges));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_preserve_charge_and_winding() {
        let world = World::new(vec![
            Carrier {
                charge: 4,
                winding: 0,
                position: 0,
            },
            Carrier {
                charge: 3,
                winding: 1,
                position: 1,
            },
            Carrier {
                charge: 2,
                winding: -1,
                position: 1,
            },
        ]);
        let edges = [(0u32, 1u32), (1u32, 0u32)];
        for next in successors(&world, &edges) {
            assert_eq!(next.total_charge(), world.total_charge());
            assert_eq!(next.net_winding(), world.net_winding());
        }
    }

    #[test]
    fn split_needs_two_units_of_neutral_charge() {
        let flat = World::new(vec![Carrier {
            charge: 1,
            winding: 0,
            position: 0,
        }]);
        assert!(split_successors(&flat).is_empty());
        let wound = World::new(vec![Carrier {
            charge: 4,
            winding: 1,
            position: 0,
        }]);
        assert!(split_successors(&wound).is_empty());
    }

    #[test]
    fn merge_needs_a_colocated_complementary_pair() {
        let apart = World::new(vec![
            Carrier {
                charge: 2,
                winding: 1,
                position: 0,
            },
            Carrier {
                charge: 2,
                winding: -1,
                position: 1,
            },
        ]);
        assert!(merge_successors(&apart).is_empty());
        let together = World::new(vec![
            Carrier {
                charge: 2,
                winding: 1,
                position: 0,
            },
            Carrier {
                charge: 2,
                winding: -1,
                position: 0,
            },
        ]);
        assert_eq!(merge_successors(&together).len(), 1);
    }

    #[test]
    fn stir_is_deterministic() {
        let world = World::new(vec![
            Carrier {
                charge: 4,
                winding: 0,
                position: 0,
            },
            Carrier {
                charge: 3,
                winding: 1,
                position: 1,
            },
            Carrier {
                charge: 2,
                winding: -1,
                position: 2,
            },
        ]);
        let edges = [(0u32, 1u32), (1u32, 2u32), (2u32, 0u32)];
        assert_eq!(
            stir_successor(&world, &edges),
            stir_successor(&world, &edges)
        );
        assert_eq!(stir_seed(&world), stir_seed(&world));
        assert_eq!(
            stir_advance(stir_seed(&world), 5),
            stir_advance(stir_seed(&world), 5)
        );
    }

    #[test]
    fn stir_preserves_charge_and_winding() {
        let world = World::new(vec![
            Carrier {
                charge: 4,
                winding: 0,
                position: 0,
            },
            Carrier {
                charge: 3,
                winding: 1,
                position: 1,
            },
            Carrier {
                charge: 2,
                winding: -1,
                position: 1,
            },
        ]);
        let edges = [(0u32, 1u32), (1u32, 0u32)];
        let stirred = stir_successor(&world, &edges);
        assert_eq!(stirred.total_charge(), world.total_charge());
        assert_eq!(stirred.net_winding(), world.net_winding());
        // Only positions may change: same multiset of (charge, winding).
        let mut before: Vec<(i32, i32)> = world
            .carriers
            .iter()
            .map(|carrier| (carrier.charge, carrier.winding))
            .collect();
        let mut after: Vec<(i32, i32)> = stirred
            .carriers
            .iter()
            .map(|carrier| (carrier.charge, carrier.winding))
            .collect();
        before.sort();
        after.sort();
        assert_eq!(before, after);
    }

    #[test]
    fn chaos_successors_record_the_stir_image_without_filtering() {
        let world = World::new(vec![Carrier {
            charge: 4,
            winding: 0,
            position: 0,
        }]);
        let edges = [(0u32, 1u32), (1u32, 0u32)];
        let base = successors(&world, &edges);
        let chaotic = successors_with_chaos(&world, &edges);
        assert_eq!(chaotic.len(), base.len() + 1);
        assert_eq!(*chaotic.last().unwrap(), stir_successor(&world, &edges));
        for next in &chaotic {
            assert_eq!(next.total_charge(), world.total_charge());
            assert_eq!(next.net_winding(), world.net_winding());
        }
    }

    #[test]
    fn stir_is_not_a_filter_or_random_fallback() {
        // Falsifier: if the stir ever refused to emit (filter collapse) or
        // produced nondeterministic output (random fallback), this fails.
        // A world whose stir image coincides with the input must still be
        // recorded exactly once, and repeats must agree bit-for-bit.
        let world = World::new(vec![Carrier {
            charge: 2,
            winding: 0,
            position: 0,
        }]);
        let single = [(0u32, 0u32)];
        let first = stir_successor(&world, &single);
        let second = stir_successor(&world, &single);
        assert_eq!(first, second);
        let chaotic = successors_with_chaos(&world, &single);
        assert_eq!(chaotic.len(), successors(&world, &single).len() + 1);
        assert!(chaotic.contains(&first));
    }
}
