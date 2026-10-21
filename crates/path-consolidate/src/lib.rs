//! CONSOLIDATE-1, door two → door one: **consolidation** (borrowed from neuroscience: the
//! hippocampus hands what it learned to the slow cortex). The candidate training set is the old
//! pack's paths plus the self-caused evidence. It is **add-only** (every old path kept), takes
//! **evidence, never rules** (observed paths only), refuses any path the deny world matches, and
//! de-duplicates. Door one then relearns from it with its own law; this crate never folds.

use path_sense::Path;
use path_world::World;
use std::collections::HashSet;

pub struct Candidate {
    pub paths: Vec<Path>,
    pub added: usize,
    pub refused_by_deny: usize,
}

pub fn consolidate(old: &[Path], evidence: &[Path], deny: &World) -> Candidate {
    let mut seen: HashSet<Path> = old.iter().cloned().collect();
    let mut paths = old.to_vec();
    let (mut added, mut refused_by_deny) = (0, 0);
    for p in evidence {
        if deny.matches(p) {
            refused_by_deny += 1;
        } else if seen.insert(p.clone()) {
            paths.push(p.clone());
            added += 1;
        }
    }
    Candidate { paths, added, refused_by_deny }
}

#[cfg(test)]
mod tests {
    use super::*;
    use path_sense::Sym;

    #[test]
    fn add_only_deduplicated_and_deny_checked() {
        let p = |v: u128| vec![Sym { field: 6, value: v }];
        let old = vec![p(1), p(2)];
        let deny = World::train(&[p(9)]);
        let c = consolidate(&old, &[p(3), p(3), p(9), p(1)], &deny);
        assert_eq!(c.paths, vec![p(1), p(2), p(3)]);
        assert_eq!((c.added, c.refused_by_deny), (1, 1));
    }
}
