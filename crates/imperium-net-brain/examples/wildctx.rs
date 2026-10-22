//! Diagnostic: list where field-3 (source address) wildcards sit in a pack's world.
use imperium_net_pathworld::FOLD;
use path_world::{World, WILD};
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let pack = path_pack::decode(&std::fs::read_to_string(&a[1]).unwrap()).unwrap();
    let w = World::train_context(&pack.paths, FOLD);
    for (pre, sib) in w.wild_contexts(3) {
        println!("{} ({sib} exact siblings)", pre.iter().map(|s| if s.value == WILD { format!("{}:*", s.field) } else { format!("{}:{:x}", s.field, s.value) }).collect::<Vec<_>>().join(" "));
    }
}
