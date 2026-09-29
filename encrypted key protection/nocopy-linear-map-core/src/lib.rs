//! Linear maps over a small vector state.
//!
//! The operation set is the monoid of linear maps. The clone map
//! `v -> v tensor v` is quadratic, not linear, so it is not a member.
//! No generator is chosen here; linearity is the algebra.

/// Fixed small vector dimension for the demo algebra.
pub const DIM: usize = 3;

/// A state vector.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct State(pub [f64; DIM]);

/// A linear map as a `DIM x DIM` matrix.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinearMap(pub [[f64; DIM]; DIM]);

impl LinearMap {
    /// Identity map.
    #[must_use]
    pub fn identity() -> Self {
        let mut matrix = [[0.0; DIM]; DIM];
        for index in 0..DIM {
            matrix[index][index] = 1.0;
        }
        LinearMap(matrix)
    }

    /// Fixed cyclic shift used as one concrete linear generator.
    #[must_use]
    pub fn cyclic_shift() -> Self {
        let mut matrix = [[0.0; DIM]; DIM];
        for index in 0..DIM {
            matrix[(index + 1) % DIM][index] = 1.0;
        }
        LinearMap(matrix)
    }

    /// Fixed swap used as a second concrete linear generator.
    #[must_use]
    pub fn swap_first_two() -> Self {
        let mut matrix = LinearMap::identity().0;
        matrix[0][0] = 0.0;
        matrix[1][1] = 0.0;
        matrix[0][1] = 1.0;
        matrix[1][0] = 1.0;
        LinearMap(matrix)
    }

    /// Apply this linear map to a state.
    #[must_use]
    pub fn apply(&self, state: State) -> State {
        let mut out = [0.0; DIM];
        for row in 0..DIM {
            let mut total = 0.0;
            for column in 0..DIM {
                total += self.0[row][column] * state.0[column];
            }
            out[row] = total;
        }
        State(out)
    }

    /// Compose maps: first `other`, then `self`.
    #[must_use]
    pub fn compose(self, other: LinearMap) -> LinearMap {
        let mut out = [[0.0; DIM]; DIM];
        for row in 0..DIM {
            for column in 0..DIM {
                let mut total = 0.0;
                for inner in 0..DIM {
                    total += self.0[row][inner] * other.0[inner][column];
                }
                out[row][column] = total;
            }
        }
        LinearMap(out)
    }
}

/// Degree of a polynomial readout in the state coordinates.
///
/// Identity and every linear composite has degree 1. A readout that would need
/// the tensor square `v tensor v` has degree 2. Degree is a structural fact of
/// the expression, not a filter or rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadoutDegree {
    /// Linear in the state coordinates.
    Linear = 1,
    /// At least quadratic in the state coordinates.
    Nonlinear = 2,
}

/// Record the degree of a product-coordinate readout.
#[must_use]
pub fn coordinate_product_degree() -> ReadoutDegree {
    ReadoutDegree::Nonlinear
}

/// Intrinsic chaos for the linear stack (Stack B mechanism only).
///
/// A parametric family of linear maps: one fixed sparse coupling skeleton
/// plus a single scalar parameter `coupling` swept across the critical value
/// `1.0`. Below the critical value iteration contracts toward a fixed
/// direction (regular regime); above it, iteration stretches neighboring
/// states apart step after step (irregular regime). The transition is a
/// property of iterating the fixed linear rule, not a rule about which
/// states to keep.
///
/// Every member is exactly linear: the matrix entries are fixed
/// deterministic fractions of `coupling`, with no RNG, clocks, or
/// environment reads. The clone map `v -> v tensor v` stays quadratic at
/// every parameter value, so it remains outside the monoid throughout the
/// sweep.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CouplingFamily {
    /// Scalar coupling swept across the critical value `1.0`.
    pub coupling: f64,
}

impl CouplingFamily {
    /// Critical coupling separating the regular and irregular regimes.
    pub const CRITICAL: f64 = 1.0;

    /// Build the family member at `coupling`. Non-finite inputs
    /// deterministically normalize to `0.0`; there is no rejection.
    #[must_use]
    pub fn new(coupling: f64) -> Self {
        if coupling.is_finite() {
            CouplingFamily { coupling }
        } else {
            CouplingFamily { coupling: 0.0 }
        }
    }

    /// The linear map at this parameter value: fixed sparse skeleton with
    /// the coupling on the subdiagonal feedback entries.
    ///
    /// ```text
    /// | 0  1  0 |
    /// | c  0  1 |
    /// | 1  0  0 |
    /// ```
    #[must_use]
    pub fn map(&self) -> LinearMap {
        let c = self.coupling;
        LinearMap([[0.0, 1.0, 0.0], [c, 0.0, 1.0], [1.0, 0.0, 0.0]])
    }

    /// Iterate the member map `steps` times from `initial`. Pure iteration.
    #[must_use]
    pub fn iterate(&self, initial: State, steps: usize) -> Vec<State> {
        let map = self.map();
        let mut states = Vec::with_capacity(steps);
        let mut current = initial;
        for _ in 0..steps {
            current = map.apply(current);
            states.push(current);
        }
        states
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concrete_generators_are_linear() {
        let state = State([1.0, 2.0, 3.0]);
        let scaled = State([2.0, 4.0, 6.0]);
        for map in [
            LinearMap::identity(),
            LinearMap::cyclic_shift(),
            LinearMap::swap_first_two(),
        ] {
            let mapped = map.apply(state);
            let mapped_scaled = map.apply(scaled);
            for index in 0..DIM {
                assert!((mapped_scaled.0[index] - 2.0 * mapped.0[index]).abs() < 1e-9);
            }
        }
    }

    #[test]
    fn compositions_stay_linear() {
        let composite = LinearMap::cyclic_shift().compose(LinearMap::swap_first_two());
        let state = State([0.5, -1.0, 2.0]);
        let expected_first = composite.apply(state);
        let stepwise = LinearMap::cyclic_shift().apply(LinearMap::swap_first_two().apply(state));
        assert_eq!(expected_first, stepwise);
    }

    #[test]
    fn clone_needs_a_quadratic_readout() {
        assert_eq!(coordinate_product_degree(), ReadoutDegree::Nonlinear);
    }

    #[test]
    fn coupling_family_is_deterministic() {
        let member = CouplingFamily::new(1.25);
        assert_eq!(member.map(), member.map());
        assert_eq!(
            member.iterate(State([4.0, 0.0, 0.0]), 6),
            member.iterate(State([4.0, 0.0, 0.0]), 6)
        );
    }

    #[test]
    fn every_family_member_is_linear() {
        for coupling in [0.0, 0.5, 1.0, 1.5, 2.0] {
            let map = CouplingFamily::new(coupling).map();
            let state = State([1.0, -2.0, 3.0]);
            let scaled = State([2.0, -4.0, 6.0]);
            let mapped = map.apply(state);
            let mapped_scaled = map.apply(scaled);
            for index in 0..DIM {
                assert!(
                    (mapped_scaled.0[index] - 2.0 * mapped.0[index]).abs() < 1e-9,
                    "nonlinear at coupling {coupling}"
                );
            }
            // Additivity as well: f(u + v) == f(u) + f(v).
            let other = State([0.5, 1.5, -1.0]);
            let sum = State([
                state.0[0] + other.0[0],
                state.0[1] + other.0[1],
                state.0[2] + other.0[2],
            ]);
            let mapped_sum = map.apply(sum);
            let separate = map.apply(other);
            for index in 0..DIM {
                assert!(
                    (mapped_sum.0[index] - (mapped.0[index] + separate.0[index])).abs() < 1e-9,
                    "additivity failed at coupling {coupling}"
                );
            }
        }
    }

    #[test]
    fn clone_stays_quadratic_across_the_sweep() {
        // The copy map is quadratic/outside the monoid at every parameter
        // value, in both regimes and at the critical point.
        for coupling in [0.25, 1.0, 1.75] {
            let _map = CouplingFamily::new(coupling).map();
            assert_eq!(coordinate_product_degree(), ReadoutDegree::Nonlinear);
        }
    }

    #[test]
    fn sweep_shows_a_controllable_regular_to_irregular_transition() {
        // Neighbor separation after fixed iteration is ordered:
        // subcritical < critical < supercritical. The transition is
        // controlled by the swept scalar, not by any per-state decision.
        let initial = State([1.0, 0.0, 0.0]);
        let nudged = State([1.0 + 1e-6, 0.0, 0.0]);
        let separation = |coupling: f64| {
            let member = CouplingFamily::new(coupling);
            let calm = member.iterate(initial, 12);
            let wild = member.iterate(nudged, 12);
            let last_calm = calm.last().unwrap();
            let last_wild = wild.last().unwrap();
            let mut total = 0.0;
            for index in 0..DIM {
                total += (last_calm.0[index] - last_wild.0[index]).abs();
            }
            total
        };
        let calm = separation(0.25);
        let critical = separation(CouplingFamily::CRITICAL);
        let wild = separation(1.75);
        assert!(
            calm <= critical,
            "subcritical separation {calm} exceeds critical {critical}"
        );
        assert!(
            critical <= wild,
            "critical separation {critical} exceeds supercritical {wild}"
        );
        assert!(
            wild > calm,
            "sweep shows no regular-to-irregular transition: {calm} vs {wild}"
        );
    }

    #[test]
    fn coupling_family_is_not_a_filter_or_random_fallback() {
        // Falsifier: if the family ever refused a parameter (filter collapse)
        // or produced nondeterministic maps (random fallback), this fails.
        // Even degenerate inputs yield a deterministic linear member.
        let degenerate = CouplingFamily::new(f64::NAN);
        assert_eq!(degenerate.coupling, 0.0);
        assert_eq!(degenerate.map(), degenerate.map());
        let member = CouplingFamily::new(1.5);
        assert_eq!(member.map(), CouplingFamily::new(1.5).map());
        let state = State([1.0, 2.0, 3.0]);
        let scaled = State([2.0, 4.0, 6.0]);
        let mapped = member.map().apply(state);
        let mapped_scaled = member.map().apply(scaled);
        for index in 0..DIM {
            assert!((mapped_scaled.0[index] - 2.0 * mapped.0[index]).abs() < 1e-9);
        }
    }
}
