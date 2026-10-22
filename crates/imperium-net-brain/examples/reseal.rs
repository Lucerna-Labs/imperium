//! RESEAL-1 ceremony tool (DOOR-TWO-BRAIN-PRECOMMIT-2026-10-21.md).
//! Usage: reseal ROLE EVIDENCE_PACK OUT_PACK APPROVED(yes|no)
//!
//! 1. Writes the candidate through the brain's reseal gate (review must pass, approval required).
//! 2. Structural "loosened nothing" check: the candidate world may gain learned positions only at
//!    the source address (field 3); a new wildcard at any other field refuses the swap.

use imperium_net_brain::BrainService;
use imperium_net_pathworld::{role_pack_paths, PathWorld, FOLD};
use path_world::World;
use std::collections::BTreeMap;

/// Fields where door one may learn new wildcard positions in a reseal (setting): the source address.
const ALLOWED_NEW_WILDCARD_FIELDS: [u8; 1] = [3];

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (role, evidence, out, approved) = (&a[1], &a[2], &a[3], a[4] == "yes");
    let old = role_pack_paths(role).expect("embedded role pack");
    let world = PathWorld::embedded(role).expect("role world");
    let brain = BrainService::from_world(&world, old.clone()).with_state(evidence.into());
    let review = match brain.reseal_to(std::path::Path::new(out), approved) {
        Ok(r) => r,
        Err(e) => {
            println!("[{role}] RESEAL REFUSED: {e}");
            std::process::exit(2);
        }
    };
    println!("[{role}] gate: old {} -> candidate {} (+{}), add_only {}, deny_clean {}, admits_all_evidence {}",
        review.old_paths, review.candidate_paths, review.added, review.add_only, review.deny_clean, review.admits_all_evidence);
    let cand = path_pack::decode(&std::fs::read_to_string(out).unwrap()).expect("written pack decodes").paths;
    let before: BTreeMap<u8, usize> = World::train_context(&old, FOLD).folded_fields();
    let after: BTreeMap<u8, usize> = World::train_context(&cand, FOLD).folded_fields();
    let mut loosened = Vec::new();
    for (field, n) in &after {
        let was = before.get(field).copied().unwrap_or(0);
        if *n > was && !ALLOWED_NEW_WILDCARD_FIELDS.contains(field) {
            loosened.push((*field, was, *n));
        }
    }
    println!("[{role}] wildcards per field: old {before:?} -> candidate {after:?}");
    if loosened.is_empty() {
        println!("[{role}] STRUCTURE OK: new learned positions only at the source address");
    } else {
        println!("[{role}] LOOSENED (swap refused): {loosened:?}");
        let _ = std::fs::remove_file(out);
        std::process::exit(3);
    }
}
