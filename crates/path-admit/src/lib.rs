//! PATHCONE (path-lightcone/PATHCONE-1-PRECOMMIT.md): the gate law. A packet passes if and only if
//! its path follows the allow world and does not follow the deny world (Jesse's "reverse version").
//! No path (an unparsable frame) never passes: fail-closed. Mechanism only; which worlds are loaded
//! is the orchestrator's.

use path_sense::Path;
use path_world::World;

pub fn admit(allow: &World, deny: &World, path: Option<&Path>) -> bool {
    match path {
        None => false,
        Some(p) => allow.matches(p) && !deny.matches(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use path_sense::Sym;

    #[test]
    fn deny_overrides_allow_and_no_path_never_passes() {
        let a: Path = vec![Sym { field: 0, value: 1 }];
        let allow = World::train(&[a.clone()]);
        assert!(admit(&allow, &World::default(), Some(&a)));
        assert!(!admit(&allow, &World::train(&[a.clone()]), Some(&a)));
        assert!(!admit(&allow, &World::default(), None));
    }
}
