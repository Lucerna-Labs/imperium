//! PATHCONE (path-lightcone/PATHCONE-1-PRECOMMIT.md): the world. A trie of the paths seen in
//! training — "only paths trained can pass" (Jesse). A position may become a wildcard only by
//! **context folding** (run 6, the law that held): a value is *ephemeral* when it follows fewer than
//! min(min_distinct, the number of contexts its field occurs in) distinct raw training prefixes —
//! the continuation count of linguistics (Kneser–Ney) — and a node folds when at least
//! `min_distinct` of its exact children are present and at least `ephemeral_fraction` of them are
//! ephemeral, shallowest first. No value is ever written by hand; the settings are the
//! orchestrator's. Matching walks exact children first, then the wildcard, with backtracking; a
//! path matches only at a trained terminal.
//!
//! The laws that failed (volatility, time recurrence, top-down recurrence, nibble prefixes, context
//! == 1, context < 3) were removed in the cleanup of 2026-10-21; their code and results are at
//! commit 2641345 and in the precommit doc.

use path_sense::{Path, Sym};
use std::collections::{HashMap, HashSet};

/// The wildcard value a folded position takes.
pub const WILD: u128 = u128::MAX;

#[derive(Default, Clone, Debug)]
struct Node {
    children: HashMap<Sym, usize>,
    terminal: bool,
    visits: u64,
}

#[derive(Clone, Debug, Default)]
pub struct World {
    nodes: Vec<Node>,
    /// Every (field, value) trained, for callers choosing untrained values.
    pub seen: HashSet<Sym>,
    pub folds: usize,
}

fn build(paths: &[Path]) -> (Vec<Node>, Vec<Vec<usize>>) {
    let mut nodes = vec![Node::default()];
    let mut trail = Vec::with_capacity(paths.len());
    for p in paths {
        let mut n = 0;
        let mut t = Vec::with_capacity(p.len());
        for s in p {
            t.push(n);
            nodes[n].visits += 1;
            let next = match nodes[n].children.get(s) {
                Some(&c) => c,
                None => {
                    nodes.push(Node::default());
                    let c = nodes.len() - 1;
                    nodes[n].children.insert(*s, c);
                    c
                }
            };
            n = next;
        }
        nodes[n].visits += 1;
        nodes[n].terminal = true;
        trail.push(t);
    }
    (nodes, trail)
}

impl World {
    /// The strict world: exactly the trained paths, no folding (the deny world, and the control).
    pub fn train(paths: &[Path]) -> World {
        let (nodes, _) = build(paths);
        World { nodes, seen: paths.iter().flatten().copied().collect(), folds: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.len() <= 1
    }

    fn walk(&self, n: usize, p: &[Sym]) -> bool {
        let Some((s, rest)) = p.split_first() else {
            return self.nodes[n].terminal;
        };
        let node = &self.nodes[n];
        if let Some(&c) = node.children.get(s) {
            if self.walk(c, rest) {
                return true;
            }
        }
        if let Some(&c) = node.children.get(&Sym { field: s.field, value: WILD }) {
            return self.walk(c, rest);
        }
        false
    }

    /// Does this path follow a trained path (exact or through folded positions)?
    pub fn matches(&self, p: &Path) -> bool {
        !self.nodes.is_empty() && self.walk(0, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_world_matches_only_trained_paths() {
        let p = |v: &[(u8, u128)]| -> Path { v.iter().map(|&(f, x)| Sym { field: f, value: x }).collect() };
        let train: Vec<Path> = (0..5).map(|k| p(&[(0, 1), (5, 40000 + k), (6, 53)])).collect();
        let strict = World::train(&train);
        assert!(strict.matches(&train[2]) && !strict.matches(&p(&[(0, 1), (5, 41234), (6, 53)])));
        assert!(!World::train(&[]).matches(&train[0]));
    }
}

impl World {
    /// Diagnostic: how many wildcard children each field holds.
    pub fn folded_fields(&self) -> std::collections::BTreeMap<u8, usize> {
        let mut m = std::collections::BTreeMap::new();
        for n in &self.nodes {
            for s in n.children.keys() {
                if s.value == WILD {
                    *m.entry(s.field).or_insert(0) += 1;
                }
            }
        }
        m
    }
}

impl World {
    fn walk_trace(&self, n: usize, p: &[Sym], trace: &mut Vec<bool>) -> bool {
        let Some((s, rest)) = p.split_first() else {
            return self.nodes[n].terminal;
        };
        let node = &self.nodes[n];
        if let Some(&c) = node.children.get(s) {
            trace.push(true);
            if self.walk_trace(c, rest, trace) {
                return true;
            }
            trace.pop();
        }
        if let Some(&c) = node.children.get(&Sym { field: s.field, value: WILD }) {
            trace.push(false);
            if self.walk_trace(c, rest, trace) {
                return true;
            }
            trace.pop();
        }
        false
    }

    /// For a matching path: per position, whether it matched exactly (true) or by wildcard (false).
    pub fn match_trace(&self, p: &Path) -> Option<Vec<bool>> {
        let mut t = Vec::with_capacity(p.len());
        (!self.nodes.is_empty() && self.walk_trace(0, p, &mut t)).then_some(t)
    }
}

impl World {
    /// Diagnostic: the trained prefix leading to every wildcard of `field`, with how many exact
    /// siblings sit beside the wildcard.
    pub fn wild_contexts(&self, field: u8) -> Vec<(Path, usize)> {
        let mut out = Vec::new();
        let mut stack: Vec<(usize, Path)> = vec![(0, Vec::new())];
        while let Some((n, pre)) = stack.pop() {
            let node = &self.nodes[n];
            if node.children.keys().any(|s| s.field == field && s.value == WILD) {
                out.push((pre.clone(), node.children.keys().filter(|s| s.value != WILD).count()));
            }
            for (s, &c) in &node.children {
                let mut p = pre.clone();
                p.push(*s);
                stack.push((c, p));
            }
        }
        out
    }
}

/// Context folding (run 6). See the crate doc.
#[derive(Clone, Copy, Debug)]
pub struct CtxFold {
    pub min_distinct: usize,
    pub ephemeral_fraction: f64,
}

impl World {
    /// Train with context folding, top-down. Context counts come from the raw paths once (the
    /// distinct raw-trie parents of each symbol), so they stay stable as folding merges branches.
    pub fn train_context(paths: &[Path], fold: CtxFold) -> World {
        let seen: HashSet<Sym> = paths.iter().flatten().copied().collect();
        let (_, raw_trail) = build(paths);
        let mut parents: HashMap<Sym, HashSet<usize>> = HashMap::new();
        for (i, p) in paths.iter().enumerate() {
            for (d, s) in p.iter().enumerate() {
                parents.entry(*s).or_default().insert(raw_trail[i][d]);
            }
        }
        let mut field_parents: HashMap<u8, HashSet<usize>> = HashMap::new();
        for (s, h) in &parents {
            field_parents.entry(s.field).or_default().extend(h.iter().copied());
        }
        let below = |s: &Sym| fold.min_distinct.min(field_parents[&s.field].len());
        let ctx: HashMap<Sym, usize> = parents.into_iter().map(|(s, h)| (s, h.len())).collect();
        let mut ps: Vec<Path> = paths.to_vec();
        let mut folds = 0;
        loop {
            let (nodes, trail) = build(&ps);
            let mut depth: HashMap<usize, usize> = HashMap::new();
            for t in &trail {
                for (d, &n) in t.iter().enumerate() {
                    depth.insert(n, d);
                }
            }
            let mut eligible: Vec<(usize, usize)> = Vec::new();
            for (id, n) in nodes.iter().enumerate() {
                let kids: Vec<&Sym> = n.children.keys().filter(|s| s.value != WILD).collect();
                if kids.len() >= fold.min_distinct {
                    let eph = kids.iter().filter(|s| ctx[**s] < below(s)).count();
                    if eph as f64 >= fold.ephemeral_fraction * kids.len() as f64 {
                        eligible.push((id, depth[&id]));
                    }
                }
            }
            let Some(shallowest) = eligible.iter().map(|e| e.1).min() else {
                return World { nodes, seen, folds };
            };
            let fold_at: HashSet<usize> = eligible.iter().filter(|e| e.1 == shallowest).map(|e| e.0).collect();
            folds += fold_at.len();
            for (i, p) in ps.iter_mut().enumerate() {
                for (d, s) in p.iter_mut().enumerate() {
                    if fold_at.contains(&trail[i][d]) {
                        s.value = WILD;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod context_tests {
    use super::*;

    #[test]
    fn ephemeral_ports_fold_flags_and_services_stay() {
        // Ten flows from three hosts (3), all within one millisecond (no time signal): ephemeral
        // port (5), service (6), flags (7).
        let p = |h: u128, sp: u128, svc: u128, f: u128| vec![Sym { field: 3, value: h }, Sym { field: 5, value: sp }, Sym { field: 6, value: svc }, Sym { field: 7, value: f }];
        let mut train = Vec::new();
        for k in 0..10u128 {
            for f in [2u128, 18, 16] {
                train.push(p(k % 3, 40000 + k, 46000 + k % 2, f));
            }
        }
        let w = World::train_context(&train, CtxFold { min_distinct: 3, ephemeral_fraction: 0.8 });
        let ff = w.folded_fields();
        assert!(ff.contains_key(&5) && !ff.contains_key(&3) && !ff.contains_key(&6) && !ff.contains_key(&7), "{ff:?}");
        assert!(w.matches(&p(1, 49999, 46001, 18)));
        assert!(!w.matches(&p(1, 49999, 46002, 18)) && !w.matches(&p(1, 49999, 46000, 1)) && !w.matches(&p(7, 49999, 46000, 18)));
    }

}

#[cfg(test)]
mod relative_tests {
    use super::*;

    #[test]
    fn a_closed_field_under_a_two_valued_parent_does_not_fold() {
        // Direction (0) has two values; three link types (1) follow both: universal, not ephemeral.
        let p = |d: u128, l: u128, port: u128| vec![Sym { field: 0, value: d }, Sym { field: 1, value: l }, Sym { field: 5, value: port }];
        let mut train = Vec::new();
        for d in 0..2 {
            for l in [0x0800u128, 0x86dd, 0x0806] {
                for k in 0..4 {
                    train.push(p(d, l, 40000 + 10 * l + k + 100 * d));
                }
            }
        }
        let rel = World::train_context(&train, CtxFold { min_distinct: 3, ephemeral_fraction: 0.8 });
        assert!(!rel.folded_fields().contains_key(&1) && rel.folded_fields().contains_key(&5));
    }
}

impl World {
    fn walk_except(&self, n: usize, p: &[Sym], depth: usize, free: &[usize]) -> bool {
        let Some((s, rest)) = p.split_first() else {
            return self.nodes[n].terminal;
        };
        let node = &self.nodes[n];
        if free.contains(&depth) {
            // Any trained value of this field may stand here.
            return node.children.iter().filter(|(k, _)| k.field == s.field).any(|(_, &c)| self.walk_except(c, rest, depth + 1, free));
        }
        if let Some(&c) = node.children.get(s) {
            if self.walk_except(c, rest, depth + 1, free) {
                return true;
            }
        }
        if let Some(&c) = node.children.get(&Sym { field: s.field, value: WILD }) {
            return self.walk_except(c, rest, depth + 1, free);
        }
        false
    }

    /// CONSOLIDATE-1: does this path follow a trained path everywhere except at the `free`
    /// positions (where any trained value of the same field may stand)? Read-only; the world's
    /// law is unchanged.
    pub fn matches_except(&self, p: &Path, free: &[usize]) -> bool {
        !self.nodes.is_empty() && self.walk_except(0, p, 0, free)
    }
}

#[cfg(test)]
mod except_tests {
    use super::*;

    #[test]
    fn free_position_accepts_any_trained_value_of_its_field_only() {
        let p = |a: u128, b: u128| vec![Sym { field: 3, value: a }, Sym { field: 6, value: b }];
        let w = World::train(&[p(1, 53), p(2, 80)]);
        assert!(w.matches_except(&p(9, 53), &[0]), "novel source, trained rest");
        assert!(!w.matches_except(&p(9, 54), &[0]), "novelty elsewhere is not explained");
        assert!(!w.matches_except(&p(1, 54), &[0]));
        assert!(w.matches_except(&p(1, 53), &[]));
    }
}
