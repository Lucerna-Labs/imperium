//! Door two (DOOR-TWO-BRAIN-PRECOMMIT-2026-10-21.md): the brain behind the lightcone.
//!
//! It **reads** door one's receipts and never changes door one. On each receipt that door one did
//! **not** admit, it asks `path-self` whether the machine itself explains the novelty — the source
//! is this host's (outbound) or an authenticated peer's (inbound), and the path otherwise matches a
//! trained path. Self-caused drops are kept as **evidence**. The evidence consolidates (add-only,
//! deny-checked, `path-consolidate`) into a **candidate** training pack for door one to relearn
//! with its own law. The brain emits the candidate and the review; it never seals or swaps — that
//! ceremony is external (Jesse's TPU seal, at door one's single loader).
//!
//! Learning is **self versus non-self** (immunology) and **consolidation** (hippocampus → cortex).
//! Integrity is immutability by relearning, not hashes.

mod strand;
pub use strand::{init_with_service, topics, BrainStrand, NAME};

use std::collections::HashSet;

use imperium_net_pathworld::PathWorld;
use imperium_protocol::{LightconeReceipt, LightconeSymbol};
use parking_lot::Mutex;
use path_self::{cause_by_identity, Cause};
use path_sense::{Path, Sym};
use path_world::World;

/// Bound on retained evidence paths (setting). Oldest-dropped when full.
pub const EVIDENCE_CAP: usize = 4096;

fn to_path(symbols: &[LightconeSymbol]) -> Path {
    symbols.iter().map(|s| Sym { field: s.field, value: s.value }).collect()
}

/// The gated reseal precondition. The ceremony proceeds only when all flags are good.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateReview {
    pub old_paths: usize,
    pub candidate_paths: usize,
    pub added: usize,
    pub refused_by_deny: usize,
    /// Every old path is still present.
    pub add_only: bool,
    /// No evidence path was a denied shape (if false, the ceremony must stop).
    pub deny_clean: bool,
    /// The candidate world admits every self-caused evidence path.
    pub admits_all_evidence: bool,
}

struct Inner {
    own_addresses: HashSet<u128>,
    authenticated_sources: HashSet<u128>,
    evidence: Vec<Path>,
    evidence_seen: HashSet<Path>,
    observed: u64,
    self_caused: u64,
    unexplained: u64,
}

/// Door two's service. Thread-safe; `observe` is called from the receipt strand.
pub struct BrainService {
    role: String,
    old_paths: Vec<Path>,
    allow: World,
    deny: World,
    inner: Mutex<Inner>,
}

impl BrainService {
    /// Build from door one's world for a role (the same trained paths door one holds).
    pub fn from_world(world: &PathWorld, old_paths: Vec<Path>) -> BrainService {
        let allow = World::train_context(&old_paths, imperium_net_pathworld::FOLD);
        let deny = rebuild_deny(&old_paths, &allow);
        let _ = world;
        BrainService {
            role: world.role().to_string(),
            old_paths,
            allow,
            deny,
            inner: Mutex::new(Inner {
                own_addresses: HashSet::new(),
                authenticated_sources: HashSet::new(),
                evidence: Vec::new(),
                evidence_seen: HashSet::new(),
                observed: 0,
                self_caused: 0,
                unexplained: 0,
            }),
        }
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    /// The host's own addresses (path-value form), replaced wholesale.
    pub fn set_own_addresses(&self, addrs: HashSet<u128>) {
        self.inner.lock().own_addresses = addrs;
    }

    /// The addresses of peers the mesh has authenticated, replaced wholesale.
    pub fn set_authenticated_sources(&self, addrs: HashSet<u128>) {
        self.inner.lock().authenticated_sources = addrs;
    }

    /// Read one door-one receipt. A drop whose novelty the machine explains becomes evidence.
    /// Returns the cause. Never changes door one.
    pub fn observe(&self, receipt: &LightconeReceipt) -> Cause {
        let mut inner = self.inner.lock();
        inner.observed += 1;
        if receipt.admitted || receipt.path.is_empty() {
            return Cause::Unexplained;
        }
        let path = to_path(&receipt.path);
        let outbound = receipt.direction == 1;
        let cause = cause_by_identity(&path, outbound, &inner.own_addresses, &inner.authenticated_sources, &self.allow);
        match cause {
            Cause::Unexplained => inner.unexplained += 1,
            _ => {
                inner.self_caused += 1;
                if inner.evidence_seen.insert(path.clone()) {
                    if inner.evidence.len() >= EVIDENCE_CAP {
                        let old = inner.evidence.remove(0);
                        inner.evidence_seen.remove(&old);
                    }
                    inner.evidence.push(path);
                }
            }
        }
        cause
    }

    /// The add-only, deny-checked candidate paths for door one to relearn.
    pub fn candidate(&self) -> Vec<Path> {
        let inner = self.inner.lock();
        path_consolidate::consolidate(&self.old_paths, &inner.evidence, &self.deny).paths
    }

    /// The reseal precondition check. The ceremony proceeds only when `add_only && deny_clean`.
    pub fn review(&self) -> CandidateReview {
        let inner = self.inner.lock();
        let c = path_consolidate::consolidate(&self.old_paths, &inner.evidence, &self.deny);
        let cand_allow = World::train_context(&c.paths, imperium_net_pathworld::FOLD);
        let cand_deny = rebuild_deny(&c.paths, &cand_allow);
        let admits_all_evidence = inner.evidence.iter().all(|p| path_admit::admit(&cand_allow, &cand_deny, Some(p)));
        CandidateReview {
            old_paths: self.old_paths.len(),
            candidate_paths: c.paths.len(),
            added: c.added,
            refused_by_deny: c.refused_by_deny,
            add_only: self.old_paths.iter().all(|p| c.paths.contains(p)),
            deny_clean: c.refused_by_deny == 0,
            admits_all_evidence,
        }
    }

    /// Counters for the operator surface: (observed, self_caused, unexplained, evidence).
    pub fn counters(&self) -> (u64, u64, u64, usize) {
        let inner = self.inner.lock();
        (inner.observed, inner.self_caused, inner.unexplained, inner.evidence.len())
    }
}

/// The deny world: each trained path with its exactly-matched service port changed to an untrained
/// one (PATHCONE-1 class a) — the same construction as `imperium-net-pathworld`.
fn rebuild_deny(paths: &[Path], allow: &World) -> World {
    use path_sense::{F_DPORT, F_SPORT};
    let seen: HashSet<Sym> = paths.iter().flatten().copied().collect();
    let port = (40000u128..).find(|v| !seen.contains(&Sym { field: F_DPORT, value: *v }) && !seen.contains(&Sym { field: F_SPORT, value: *v })).unwrap();
    let deny_train: Vec<Path> = paths
        .iter()
        .filter_map(|p| {
            let t = allow.match_trace(p)?;
            let at = |f: u8| p.iter().position(|s| s.field == f).filter(|&i| t[i]);
            let i = at(F_DPORT).or_else(|| at(F_SPORT))?;
            let mut q = p.clone();
            q[i].value = port;
            Some(q)
        })
        .collect();
    World::train(&deny_train)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(field: u8, value: u128) -> LightconeSymbol {
        LightconeSymbol { field, value }
    }

    fn receipt(dir: u8, admitted: bool, src: u128, dport: u128) -> LightconeReceipt {
        LightconeReceipt {
            sequence: 0,
            direction: dir,
            frame_format: imperium_protocol::LightconeFrameFormat::RawIp,
            observation_kind: 0,
            world: "receiver".into(),
            query_sha256: String::new(),
            path: vec![sym(0, dir as u128), sym(1, 0x0800), sym(2, 17), sym(3, src), sym(4, 0xc633_6402), sym(5, 51000), sym(6, dport)],
            admitted,
            denied: false,
            learned_positions: Vec::new(),
            passive: true,
            holds_verdict: false,
            timestamp: chrono::Utc::now(),
        }
    }

    fn train(dir: u8, src: u128, dport: u128) -> Path {
        [(0u8, dir as u128), (1, 0x0800), (2, 17), (3, src), (4, 0xc633_6402), (5, 51000), (6, dport)].iter().map(|&(f, v)| Sym { field: f, value: v }).collect()
    }

    #[test]
    fn learns_self_caused_refuses_spoof_and_novelty_and_gates_the_reseal() {
        let own = 0xc000_0202u128;
        let peer = 0xc000_0201u128;
        let old = vec![train(0, peer, 45998), train(1, own, 45998)];
        let world = PathWorld::untrained();
        let brain = BrainService::from_world(&world, old.clone());
        let fresh = 0xc000_02aau128; // a new address this host owns this episode
        brain.set_own_addresses([own, fresh].into_iter().collect());
        brain.set_authenticated_sources([peer].into_iter().collect());

        // Door one admitted this one: ignored.
        assert_eq!(brain.observe(&receipt(0, true, peer, 45998)), Cause::Unexplained);
        // A dropped OUTBOUND from a FRESH address this host owns, novelty only in the source: self.
        assert_eq!(brain.observe(&receipt(1, false, fresh, 45998)), Cause::OwnAddress);
        // A spoof of our own address arriving INBOUND is not an authenticated source: unexplained.
        assert_eq!(brain.observe(&receipt(0, false, own, 45998)), Cause::Unexplained);
        // Novelty beyond the source (untrained port): unexplained.
        assert_eq!(brain.observe(&receipt(1, false, own, 45996)), Cause::Unexplained);
        // An inbound novel-source drop cannot be identity-confirmed on the bus (its source is new,
        // not a known peer): unexplained here, pending interface telemetry (see precommit).
        assert_eq!(brain.observe(&receipt(0, false, 0xc000_02ff, 45998)), Cause::Unexplained);

        let (observed, self_caused, unexplained, evidence) = brain.counters();
        assert_eq!((observed, self_caused, unexplained, evidence), (5, 1, 3, 1));

        let review = brain.review();
        assert!(review.add_only && review.deny_clean && review.admits_all_evidence);
        assert_eq!(review.added, 1);
        assert_eq!(review.refused_by_deny, 0);
        // Add-only: the candidate keeps both old paths and adds the one self-caused one.
        let cand = brain.candidate();
        assert!(old.iter().all(|p| cand.contains(p)) && cand.len() == old.len() + 1);
    }
}
