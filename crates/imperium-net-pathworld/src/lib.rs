//! Door one: Imperium's network lightcone world (PATH-LIGHTCONE-DOOR-PRECOMMIT-2026-10-21.md).
//!
//! Jesse's design: a restrained **allow world** in which only trained paths can pass, plus a
//! reverse **deny world** of trained paths that must never pass. A path is admitted when the allow
//! world matches it and the deny world does not. The positions that may vary are learned from the
//! training traffic by context folding (network-lightcone PATHCONE-1 run 6); nothing is
//! hand-written. The crates doing the work are vendored unchanged from network-lightcone
//! (`crates/path-*`, see PROVENANCE.md); this crate is their orchestrator and holds every setting.
//!
//! A world is built only from a training pack, through [`PathWorld::from_pack`], and has no
//! mutating API afterwards. The embedded packs are the three roles of the 2026-10-01 VM lab. With
//! no role chosen the world is **untrained**: it admits nothing. The world is diagnostic and
//! unsealed; sealing comes later, by Jesse's TPU path, at this same single loading point.

use path_admit::admit;
use path_sense::{Path, Sym, F_DPORT, F_SPORT};
use path_world::{CtxFold, World};
use std::collections::HashSet;

/// Run-6 context folding (setting; measured in network-lightcone PATHCONE-1).
pub const FOLD: CtxFold = CtxFold { min_distinct: 3, ephemeral_fraction: 0.8 };
/// The environment variable choosing the embedded role (setting).
pub const ROLE_ENV: &str = "IMPERIUM_LIGHTCONE_ROLE";
pub const UNTRAINED: &str = "untrained";

const PACKS: [(&str, &str); 3] = [
    ("hub", include_str!("../packs/hub.pathpack")),
    ("source", include_str!("../packs/source.pathpack")),
    ("receiver", include_str!("../packs/receiver.pathpack")),
];

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A pack that does not decode (fail-closed: no partial world).
    MalformedPack,
    /// A role name with no embedded pack (fail-closed: no silent fallback to untrained).
    UnknownRole(String),
}

/// What the world admitted for one path. A reading, not an authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// The allow world matched and the deny world did not.
    pub admitted: bool,
    /// The deny world matched.
    pub denied: bool,
    /// Positions matched through a learned (folded) wildcard rather than an exact trained value.
    pub learned_positions: Vec<u8>,
}

pub struct PathWorld {
    role: String,
    allow: World,
    deny: World,
    trained_paths: usize,
    deny_paths: usize,
}

fn untrained_port(seen: &HashSet<Sym>) -> u128 {
    (40000u128..).find(|v| !seen.contains(&Sym { field: F_DPORT, value: *v }) && !seen.contains(&Sym { field: F_SPORT, value: *v })).unwrap()
}

/// The deny world's training: each training path with its exactly-matched service port changed to
/// an untrained one (PATHCONE-1's mutation class a).
fn deny_paths(paths: &[Path], allow: &World, port: u128) -> Vec<Path> {
    paths
        .iter()
        .filter_map(|p| {
            let trace = allow.match_trace(p)?;
            let at = |f: u8| p.iter().position(|s| s.field == f).filter(|&i| trace[i]);
            let i = at(F_DPORT).or_else(|| at(F_SPORT))?;
            let mut q = p.clone();
            q[i].value = port;
            Some(q)
        })
        .collect()
}

impl PathWorld {
    /// No trained paths: admits nothing.
    pub fn untrained() -> PathWorld {
        PathWorld { role: UNTRAINED.into(), allow: World::default(), deny: World::default(), trained_paths: 0, deny_paths: 0 }
    }

    /// The only way a trained world is built.
    pub fn from_pack(text: &str) -> Result<PathWorld, Error> {
        let pack = path_pack::decode(text).ok_or(Error::MalformedPack)?;
        let allow = World::train_context(&pack.paths, FOLD);
        let deny_train = deny_paths(&pack.paths, &allow, untrained_port(&allow.seen));
        Ok(PathWorld { role: pack.role, deny: World::train(&deny_train), allow, trained_paths: pack.paths.len(), deny_paths: deny_train.len() })
    }

    /// An embedded lab role's world.
    pub fn embedded(role: &str) -> Result<PathWorld, Error> {
        let (_, text) = PACKS.iter().find(|(r, _)| *r == role).ok_or_else(|| Error::UnknownRole(role.into()))?;
        PathWorld::from_pack(text)
    }

    /// The role named by `IMPERIUM_LIGHTCONE_ROLE`, or untrained when it is unset or empty.
    pub fn from_env() -> Result<PathWorld, Error> {
        match std::env::var(ROLE_ENV) {
            Ok(role) if !role.is_empty() && role != UNTRAINED => PathWorld::embedded(&role),
            _ => Ok(PathWorld::untrained()),
        }
    }

    /// Judge one path (`None`: the frame had no path, so it is not admitted).
    pub fn admit(&self, path: Option<&Path>) -> Admission {
        let Some(p) = path else {
            return Admission { admitted: false, denied: false, learned_positions: Vec::new() };
        };
        let trace = self.allow.match_trace(p);
        Admission {
            admitted: admit(&self.allow, &self.deny, Some(p)),
            denied: self.deny.matches(p),
            learned_positions: trace.map(|t| t.iter().enumerate().filter(|(_, &exact)| !exact).map(|(i, _)| i as u8).collect()).unwrap_or_default(),
        }
    }

    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn trained_paths(&self) -> usize {
        self.trained_paths
    }
    pub fn deny_paths(&self) -> usize {
        self.deny_paths
    }
    pub fn folds(&self) -> usize {
        self.allow.folds
    }
    pub fn is_trained(&self) -> bool {
        self.trained_paths > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use path_sense::{F_DIR, F_DST, F_L4, F_LINK, F_SRC};

    fn udp(dir: u128, src: u128, dst: u128, sp: u128, dp: u128) -> Path {
        [(F_DIR, dir), (F_LINK, 0x0800), (F_L4, 17), (F_SRC, src), (F_DST, dst), (F_SPORT, sp), (F_DPORT, dp)].iter().map(|&(field, value)| Sym { field, value }).collect()
    }

    #[test]
    fn embedded_receiver_admits_trained_service_and_refuses_untrained() {
        let w = PathWorld::embedded("receiver").unwrap();
        assert_eq!(w.trained_paths(), 472);
        // Inbound direct UDP4 from the source to the trained service 45998, any client port.
        let ok = w.admit(Some(&udp(0, 0xc000_0202, 0xc633_6402, 51234, 45998)));
        assert!(ok.admitted && !ok.denied && ok.learned_positions == vec![5], "{ok:?}");
        assert!(!w.admit(Some(&udp(0, 0xc000_0202, 0xc633_6402, 51234, 45996))).admitted, "untrained port");
        assert!(!w.admit(Some(&udp(0, 0xc000_024d, 0xc633_6402, 51234, 45998))).admitted, "untrained address");
        assert!(!w.admit(None).admitted, "no path, no pass");
    }

    #[test]
    fn untrained_admits_nothing_and_unknown_roles_fail_closed() {
        let u = PathWorld::untrained();
        assert!(!u.is_trained() && !u.admit(Some(&udp(0, 1, 2, 3, 4))).admitted);
        assert_eq!(PathWorld::embedded("nobody").err(), Some(Error::UnknownRole("nobody".into())));
        assert_eq!(PathWorld::from_pack("PATHPACK 1\nrole x\npaths 1\n").err(), Some(Error::MalformedPack));
        for r in ["hub", "source"] {
            assert!(PathWorld::embedded(r).unwrap().is_trained());
        }
    }
}
