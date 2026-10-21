//! PATHCONE: the training pack — the one form a world's trained paths travel in, so a world is
//! always built through one loader (and a later sealed pack can replace a lab pack at that point).
//! Text, line per path, `field:hexvalue` symbols separated by spaces:
//!
//! ```text
//! PATHPACK 1
//! role receiver
//! paths 2
//! 0:0 1:800 2:11 3:c0000202 4:c6336402 5:b436 6:b3ae
//! 0:1 1:806 9:1 3:c6336401 4:c6336402
//! ```
//!
//! Decoding is fail-closed: a wrong header, a wrong count, or any malformed symbol yields `None`,
//! never a partial pack.

use path_sense::{Path, Sym};

pub struct Pack {
    pub role: String,
    pub paths: Vec<Path>,
}

pub fn encode(role: &str, paths: &[Path]) -> String {
    let mut s = format!("PATHPACK 1\nrole {role}\npaths {}\n", paths.len());
    for p in paths {
        let line: Vec<String> = p.iter().map(|y| format!("{}:{:x}", y.field, y.value)).collect();
        s.push_str(&line.join(" "));
        s.push('\n');
    }
    s
}

pub fn decode(text: &str) -> Option<Pack> {
    let mut lines = text.lines();
    if lines.next()? != "PATHPACK 1" {
        return None;
    }
    let role = lines.next()?.strip_prefix("role ")?.to_string();
    if role.is_empty() || role.contains(' ') {
        return None;
    }
    let n: usize = lines.next()?.strip_prefix("paths ")?.parse().ok()?;
    let mut paths = Vec::with_capacity(n);
    for line in lines {
        let mut p = Vec::new();
        for tok in line.split(' ') {
            let (f, v) = tok.split_once(':')?;
            p.push(Sym { field: f.parse().ok()?, value: u128::from_str_radix(v, 16).ok()? });
        }
        if p.is_empty() {
            return None;
        }
        paths.push(p);
    }
    (paths.len() == n).then_some(Pack { role, paths })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_fail_closed() {
        let paths = vec![vec![Sym { field: 0, value: 0 }, Sym { field: 3, value: 0xfe80_0000_0000_0000_0000_0000_0000_0001 }], vec![Sym { field: 6, value: 45999 }]];
        let text = encode("hub", &paths);
        let back = decode(&text).unwrap();
        assert_eq!(back.role, "hub");
        assert_eq!(back.paths, paths);
        assert!(decode(&text.replace("paths 2", "paths 3")).is_none());
        assert!(decode(&text.replace("PATHPACK 1", "PATHPACK 2")).is_none());
        assert!(decode(&text.replace("6:afaf", "6:zz")).is_none() || decode(&text.replace("6:", "6;")).is_none());
        assert!(decode(&format!("{text}\n")).is_none(), "an empty line is malformed");
        assert!(decode("").is_none());
    }
}
