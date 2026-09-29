//! Passive causal-world admission. No traffic judgment, authorization or learning.
#![cfg_attr(not(any(test, feature = "std")), no_std)]
use sha2::{Digest, Sha256};
pub mod embedded;
pub const MAX_NODES: usize = 256;
pub const MAX_EDGES: usize = 512;
pub const NODE_WORDS: usize = MAX_NODES / 64;
pub const EDGE_WORDS: usize = MAX_EDGES / 64;
pub const DIMS: usize = 48;
const HEADER: usize = 1044;
const NODE: usize = 216;
const EDGE: usize = 16;
pub fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Hash,
    Format,
    Reference,
    Policy,
    Index,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Past = 0,
    Future = 1,
    Both = 2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub direction: Direction,
    pub hops: u8,
    pub max_nodes: u16,
    pub relations: u8,
    pub polarity: i8,
}
impl Policy {
    pub const NETWORK: Self = Self {
        direction: Direction::Both,
        hops: 3,
        max_nodes: 32,
        relations: 31,
        polarity: 0,
    };
}
#[derive(Clone, Copy)]
pub struct World<'a> {
    data: &'a [u8],
    pub id: u16,
    n: usize,
    e: usize,
    strings: usize,
    pub digest: [u8; 32],
}
fn u16at(b: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([b[i], b[i + 1]])
}
fn u32at(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub source: u16,
    pub target: u16,
    pub relation: u8,
    pub polarity: i8,
    pub split: u8,
}
impl<'a> World<'a> {
    pub fn load(data: &'a [u8], expected: [u8; 32]) -> Result<Self, Error> {
        if hash(data) != expected {
            return Err(Error::Hash);
        }
        if data.len() < HEADER || &data[..8] != b"ATLCNET2" {
            return Err(Error::Format);
        }
        let n = u16at(data, 8) as usize;
        let e = u16at(data, 10) as usize;
        if n == 0 || n > MAX_NODES || e > MAX_EDGES || u16at(data, 12) != 48 || u16at(data, 14) == 0
        {
            return Err(Error::Format);
        }
        let strings = HEADER + n * NODE + e * EDGE;
        if strings + u32at(data, 16) as usize != data.len() {
            return Err(Error::Format);
        }
        let world = Self {
            data,
            id: u16at(data, 14),
            n,
            e,
            strings,
            digest: expected,
        };
        if data[20..52].iter().all(|&b| b == 0) || data[52..84].iter().all(|&b| b == 0) {
            return Err(Error::Format);
        }
        for i in 0..n {
            world.node_json(i)?;
            for d in 0..52 {
                if world.coordinate(i, d)?.unsigned_abs() > 1_000_000_000 {
                    return Err(Error::Format);
                }
            }
        }
        // Recompute observer projection and its non-expansion certificate from
        // the train-fitted quantized basis. It never participates in admission.
        for axis in 0..4 {
            for other in 0..4 {
                let mut dot = 0i64;
                for d in 0..48 {
                    let a = world.basis(d, axis);
                    let b = world.basis(d, other);
                    if a.unsigned_abs() > 1_000_000 || b.unsigned_abs() > 1_000_000 {
                        return Err(Error::Format);
                    }
                    dot += (a as i64) * (b as i64);
                }
                let expected = if axis == other {
                    1_000_000_000_000i64
                } else {
                    0
                };
                if (dot - expected).abs() > 10_000_000 {
                    return Err(Error::Format);
                }
            }
        }
        for i in 0..n {
            for axis in 0..4 {
                let mut projected = 0i64;
                for d in 0..48 {
                    let center = u32at(data, 84 + d * 4) as i32;
                    if center.unsigned_abs() > 1_000_000_000 {
                        return Err(Error::Format);
                    }
                    projected += (world.coordinate(i, d)? as i64 - center as i64)
                        * world.basis(d, axis) as i64;
                }
                if (projected / 1_000_000 - world.coordinate(i, 48 + axis)? as i64).abs() > 256 {
                    return Err(Error::Format);
                }
            }
        }
        for i in 0..e {
            let edge = world.edge(i)?;
            if edge.source as usize >= n
                || edge.target as usize >= n
                || edge.relation >= 5
                || ![-1, 1].contains(&edge.polarity)
                || edge.split > 4
            {
                return Err(Error::Reference);
            }
            world.edge_json(i)?;
        }
        Ok(world)
    }
    fn basis(&self, dim: usize, axis: usize) -> i32 {
        u32at(self.data, 84 + 48 * 4 + (dim * 4 + axis) * 4) as i32
    }
    pub fn node_count(&self) -> usize {
        self.n
    }
    pub fn edge_count(&self) -> usize {
        self.e
    }
    pub fn source_digest(&self) -> &[u8] {
        &self.data[20..52]
    }
    pub fn training_digest(&self) -> &[u8] {
        &self.data[52..84]
    }
    fn metadata(&self, o: usize) -> Result<&'a str, Error> {
        let start = self
            .strings
            .checked_add(u32at(self.data, o) as usize)
            .ok_or(Error::Format)?;
        let end = start
            .checked_add(u32at(self.data, o + 4) as usize)
            .ok_or(Error::Format)?;
        let b = self.data.get(start..end).ok_or(Error::Format)?;
        if b.is_empty() {
            return Err(Error::Format);
        }
        core::str::from_utf8(b).map_err(|_| Error::Format)
    }
    pub fn node_json(&self, i: usize) -> Result<&'a str, Error> {
        if i >= self.n {
            return Err(Error::Index);
        }
        self.metadata(HEADER + i * NODE)
    }
    pub fn edge_json(&self, i: usize) -> Result<&'a str, Error> {
        if i >= self.e {
            return Err(Error::Index);
        }
        self.metadata(HEADER + self.n * NODE + i * EDGE + 8)
    }
    /// Coordinates quantized to millionths; dimensions 48..52 are observer-only.
    pub fn coordinate(&self, i: usize, d: usize) -> Result<i32, Error> {
        if i >= self.n || d >= 52 {
            return Err(Error::Index);
        }
        Ok(u32at(self.data, HEADER + i * NODE + 8 + d * 4) as i32)
    }
    pub fn edge(&self, i: usize) -> Result<Edge, Error> {
        if i >= self.e {
            return Err(Error::Index);
        }
        let o = HEADER + self.n * NODE + i * EDGE;
        Ok(Edge {
            source: u16at(self.data, o),
            target: u16at(self.data, o + 2),
            relation: self.data[o + 4],
            polarity: self.data[o + 5] as i8,
            split: self.data[o + 6],
        })
    }
    pub fn admit(
        &self,
        seeds: [u64; NODE_WORDS],
        policy: Policy,
        query: [u8; 32],
    ) -> Result<Receipt, Error> {
        if policy.hops > 64
            || policy.max_nodes == 0
            || policy.max_nodes as usize > MAX_NODES
            || policy.relations & !31 != 0
            || ![-1, 0, 1].contains(&policy.polarity)
        {
            return Err(Error::Policy);
        }
        for i in self.n..MAX_NODES {
            if bit(&seeds, i) {
                return Err(Error::Index);
            }
        }
        let mut r = Receipt {
            world: self.digest,
            query,
            policy,
            seeds,
            nodes: [0; NODE_WORDS],
            edges: [0; EDGE_WORDS],
            excluded: [0; NODE_WORDS],
            hop_frontier: [0; NODE_WORDS],
            digest: [0; 32],
        };
        let mut queue = [0u16; MAX_NODES];
        let mut depths = [0u8; MAX_NODES];
        let mut head = 0;
        let mut tail = 0;
        for i in 0..self.n {
            if bit(&seeds, i) {
                if tail < policy.max_nodes as usize {
                    set(&mut r.nodes, i);
                    queue[tail] = i as u16;
                    tail += 1;
                } else {
                    set(&mut r.excluded, i)
                }
            }
        }
        while head < tail {
            let node = queue[head];
            let hop = depths[head];
            head += 1;
            for i in 0..self.e {
                let edge = self.edge(i)?;
                if !eligible(edge, policy) {
                    continue;
                }
                let neighbor = if edge.source == node && policy.direction != Direction::Past {
                    Some(edge.target)
                } else if edge.target == node && policy.direction != Direction::Future {
                    Some(edge.source)
                } else {
                    None
                };
                if let Some(n) = neighbor {
                    let n = n as usize;
                    if bit(&r.nodes, n) {
                        continue;
                    }
                    if hop >= policy.hops {
                        set(&mut r.hop_frontier, n);
                        continue;
                    }
                    if tail >= policy.max_nodes as usize {
                        set(&mut r.excluded, n);
                        continue;
                    }
                    set(&mut r.nodes, n);
                    queue[tail] = n as u16;
                    depths[tail] = hop + 1;
                    tail += 1;
                }
            }
        }
        // All eligible exact edges within the neighborhood are preserved, including
        // cycles and parallel typed/negative edges, not only a spanning tree.
        for i in 0..self.e {
            let edge = self.edge(i)?;
            if eligible(edge, policy)
                && bit(&r.nodes, edge.source as usize)
                && bit(&r.nodes, edge.target as usize)
            {
                set(&mut r.edges, i)
            }
        }
        for j in 0..NODE_WORDS {
            r.excluded[j] &= !r.nodes[j];
            r.hop_frontier[j] &= !r.nodes[j];
        }
        r.digest = r.compute_digest();
        Ok(r)
    }
}
fn eligible(e: Edge, p: Policy) -> bool {
    p.relations & (1 << e.relation) != 0 && (p.polarity == 0 || e.polarity == p.polarity)
}
pub fn bit<const N: usize>(a: &[u64; N], i: usize) -> bool {
    i < N * 64 && a[i / 64] & (1u64 << (i % 64)) != 0
}
pub fn set<const N: usize>(a: &mut [u64; N], i: usize) {
    if i < N * 64 {
        a[i / 64] |= 1u64 << (i % 64)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receipt {
    pub world: [u8; 32],
    pub query: [u8; 32],
    pub policy: Policy,
    pub seeds: [u64; NODE_WORDS],
    pub nodes: [u64; NODE_WORDS],
    pub edges: [u64; EDGE_WORDS],
    pub excluded: [u64; NODE_WORDS],
    pub hop_frontier: [u64; NODE_WORDS],
    pub digest: [u8; 32],
}
impl Receipt {
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"ATOM-NETWORK-ADMISSION-2");
        h.update(self.world);
        h.update(self.query);
        h.update([
            self.policy.direction as u8,
            self.policy.hops,
            self.policy.relations,
            self.policy.polarity as u8,
        ]);
        h.update(self.policy.max_nodes.to_le_bytes());
        for a in [
            &self.seeds[..],
            &self.nodes[..],
            &self.edges[..],
            &self.excluded[..],
            &self.hop_frontier[..],
        ] {
            for v in a {
                h.update(v.to_le_bytes());
            }
        }
        h.finalize().into()
    }
    pub fn count(&self) -> u32 {
        self.nodes.iter().map(|n| n.count_ones()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, VecDeque};
    fn world() -> World<'static> {
        World::load(embedded::PACK, embedded::HASH).unwrap()
    }
    #[test]
    fn integrity_and_untrusted_pack_bounds() {
        assert_eq!(
            hash(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        let raw = embedded::PACK;
        for n in [0, 8, 83, raw.len() - 1] {
            assert!(World::load(&raw[..n], hash(&raw[..n])).is_err())
        }
        for offset in [0, 8, 12, 16, 20, 84, 92, raw.len() - 1] {
            let mut b = raw.to_vec();
            b[offset] ^= 128;
            assert!(matches!(World::load(&b, embedded::HASH), Err(Error::Hash)))
        }
        let mut b = raw.to_vec();
        b[12] = 47;
        assert!(World::load(&b, hash(&b)).is_err());
        let o = HEADER + world().n * NODE;
        b = raw.to_vec();
        b[o..o + 2].copy_from_slice(&999u16.to_le_bytes());
        assert!(World::load(&b, hash(&b)).is_err());
        b = raw.to_vec();
        b[HEADER..HEADER + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(World::load(&b, hash(&b)).is_err());
    }
    // A separately expressed set/queue oracle checks every node, direction, hop,
    // relation family and polarity against exact source edges, not coordinates.
    #[test]
    fn exact_graph_oracle_all_seeds_directions_relations() {
        let w = world();
        for seed in 0..w.n {
            for dir in [Direction::Past, Direction::Future, Direction::Both] {
                for hops in 0..5 {
                    for rels in [1, 2, 4, 8, 16, 31] {
                        for pol in [-1, 0, 1] {
                            let p = Policy {
                                direction: dir,
                                hops,
                                max_nodes: MAX_NODES as u16,
                                relations: rels,
                                polarity: pol,
                            };
                            let mut seeds = [0; NODE_WORDS];
                            set(&mut seeds, seed);
                            let got = w.admit(seeds, p, hash(b"oracle")).unwrap();
                            let mut expected = BTreeSet::from([seed]);
                            let mut q = VecDeque::from([(seed, 0)]);
                            while let Some((node, h)) = q.pop_front() {
                                if h >= hops {
                                    continue;
                                }
                                for i in 0..w.e {
                                    let e = w.edge(i).unwrap();
                                    if rels & (1 << e.relation) == 0
                                        || (pol != 0 && pol != e.polarity)
                                    {
                                        continue;
                                    }
                                    let mut add = |a: usize, b: usize| {
                                        if a == node && expected.insert(b) {
                                            q.push_back((b, h + 1));
                                        }
                                    };
                                    if dir != Direction::Past {
                                        add(e.source as usize, e.target as usize)
                                    }
                                    if dir != Direction::Future {
                                        add(e.target as usize, e.source as usize)
                                    }
                                }
                            }
                            for i in 0..w.n {
                                assert_eq!(bit(&got.nodes, i), expected.contains(&i))
                            }
                            for i in 0..w.e {
                                let e = w.edge(i).unwrap();
                                assert_eq!(
                                    bit(&got.edges, i),
                                    expected.contains(&(e.source as usize))
                                        && expected.contains(&(e.target as usize))
                                        && rels & (1 << e.relation) != 0
                                        && (pol == 0 || pol == e.polarity)
                                )
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn unknown_caps_direction_and_immutable_replay() {
        let w = world();
        let p = Policy::NETWORK;
        let empty = w.admit([0; NODE_WORDS], p, hash(b"unknown")).unwrap();
        assert_eq!(empty.count(), 0);
        let mut seed = [0; NODE_WORDS];
        set(&mut seed, embedded::UDP);
        let a = w.admit(seed, p, hash(b"udp")).unwrap();
        assert_eq!(a, w.admit(seed, p, hash(b"udp")).unwrap());
        assert_eq!(a.digest, a.compute_digest());
        let capped = w
            .admit(seed, Policy { max_nodes: 1, ..p }, hash(b"udp"))
            .unwrap();
        assert_eq!(capped.count(), 1);
        assert_ne!(capped.excluded, [0; NODE_WORDS]);
        let zero = w
            .admit(seed, Policy { hops: 0, ..p }, hash(b"udp"))
            .unwrap();
        assert_eq!(zero.count(), 1);
        assert_ne!(zero.hop_frontier, [0; NODE_WORDS]);
        let past = w
            .admit(
                seed,
                Policy {
                    direction: Direction::Past,
                    ..p
                },
                hash(b"udp"),
            )
            .unwrap();
        let future = w
            .admit(
                seed,
                Policy {
                    direction: Direction::Future,
                    ..p
                },
                hash(b"udp"),
            )
            .unwrap();
        assert_ne!(past.nodes, future.nodes);
        let removed = w
            .admit(seed, Policy { relations: 0, ..p }, hash(b"udp"))
            .unwrap();
        assert_eq!(removed.count(), 1);
        assert_ne!(removed.nodes, a.nodes);
        assert_eq!(hash(embedded::PACK), embedded::HASH);
        assert!(w
            .admit(seed, Policy { max_nodes: 0, ..p }, [0; 32])
            .is_err());
        assert!(w.node_json(w.n).is_err());
        assert!(w.coordinate(0, 52).is_err());
    }
    #[test]
    fn observer_coordinates_do_not_change_admission() {
        let w = world();
        let mut b = embedded::PACK.to_vec();
        for d in 0..48 {
            let off = 84 + 48 * 4 + d * 16;
            for k in 0..4 {
                b.swap(off + k, off + 4 + k);
            }
        }
        for i in 0..w.n {
            let off = HEADER + i * NODE + 8 + 48 * 4;
            for k in 0..4 {
                b.swap(off + k, off + 4 + k);
            }
        }
        let changed = World::load(&b, hash(&b)).unwrap();
        let mut seed = [0; NODE_WORDS];
        set(&mut seed, embedded::UDP);
        let a = w.admit(seed, Policy::NETWORK, [0; 32]).unwrap();
        let c = changed.admit(seed, Policy::NETWORK, [0; 32]).unwrap();
        assert_eq!(a.nodes, c.nodes);
        assert_eq!(a.edges, c.edges);
        assert_ne!(a.world, c.world);
    }
}
