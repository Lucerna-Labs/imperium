//! Passive conditional causal neighborhoods. No network operation or verdict.
//!
//! Conditions are immutable world records. Unknown facts make a relation
//! unavailable; neither coordinates nor a nonempty receipt create an edge.

use imperium_net_world::{
    bit, hash, set, Direction, Policy, Receipt, World, EDGE_WORDS, NODE_WORDS,
};
use std::net::IpAddr;

const FIELDS: usize = 9;
const MAGIC: &[u8; 8] = b"LCPASS6\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactValue {
    Bool(bool),
    Number(u16),
    Address(IpAddr),
}

#[derive(Clone, Debug)]
pub struct PacketFacts {
    values: [Option<FactValue>; FIELDS],
}

impl Default for PacketFacts {
    fn default() -> Self {
        Self {
            values: [None; FIELDS],
        }
    }
}

impl PacketFacts {
    /// Field IDs belong to the immutable predicate catalog, not payload text.
    pub fn put(&mut self, field: u8, value: FactValue) -> Result<(), PassageError> {
        let slot = self
            .values
            .get_mut(usize::from(field))
            .ok_or(PassageError::Conditions)?;
        let valid_type = matches!(
            (field, value),
            (0 | 7, FactValue::Bool(_))
                | (1..=4 | 8, FactValue::Number(_))
                | (5 | 6, FactValue::Address(_))
        );
        if !valid_type || slot.is_some() {
            return Err(PassageError::Conditions);
        }
        *slot = Some(value);
        Ok(())
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = b"LIGHTCONE-PACKET-FACTS-6".to_vec();
        for value in self.values {
            match value {
                None => bytes.push(0),
                Some(FactValue::Bool(value)) => bytes.extend_from_slice(&[1, u8::from(value)]),
                Some(FactValue::Number(value)) => {
                    bytes.push(2);
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
                Some(FactValue::Address(IpAddr::V4(value))) => {
                    bytes.push(4);
                    bytes.extend_from_slice(&value.octets());
                }
                Some(FactValue::Address(IpAddr::V6(value))) => {
                    bytes.push(6);
                    bytes.extend_from_slice(&value.octets());
                }
            }
        }
        hash(&bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassageError {
    World(imperium_net_world::Error),
    Conditions,
    Binding,
    Limit,
}

#[derive(Clone)]
struct Term {
    field: u8,
    operation: u8,
    value: Vec<u8>,
}

impl Term {
    fn validate(&self) -> Result<(), PassageError> {
        let valid = match (self.field, self.operation) {
            (0 | 7, 0) => self.value.len() == 1 && self.value[0] <= 1,
            (1..=4 | 8, 0) => self.value.len() == 2,
            (1..=4 | 8, 1) => self.value.len() == 4 && self.number(0)? <= self.number(2)?,
            (1..=4 | 8, 3) => !self.value.is_empty() && self.value.len() % 2 == 0,
            (5 | 6, 2) => {
                if !matches!(
                    (self.value.len(), self.value.first()),
                    (6, Some(4)) | (18, Some(6))
                ) {
                    false
                } else {
                    let width = if self.value[0] == 4 { 32 } else { 128 };
                    let prefix = usize::from(self.value[1]);
                    prefix <= width
                        && (prefix..width).all(|i| self.value[2 + i / 8] & (0x80 >> (i % 8)) == 0)
                }
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(PassageError::Conditions)
        }
    }
    fn number(&self, offset: usize) -> Result<u16, PassageError> {
        let bytes = self
            .value
            .get(offset..offset + 2)
            .ok_or(PassageError::Conditions)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn applies(&self, facts: &PacketFacts) -> bool {
        let Some(value) = facts.values[usize::from(self.field)] else {
            return false;
        };
        match (value, self.operation) {
            (FactValue::Bool(value), 0) => self.value == [u8::from(value)],
            (FactValue::Number(value), 0) => self.number(0) == Ok(value),
            (FactValue::Number(value), 1) => {
                self.number(0).is_ok_and(|low| value >= low)
                    && self.number(2).is_ok_and(|high| value <= high)
            }
            (FactValue::Number(value), 3) => self
                .value
                .chunks_exact(2)
                .any(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) == value),
            (FactValue::Address(address), 2) => {
                let bytes = match address {
                    IpAddr::V4(v) => v.octets().to_vec(),
                    IpAddr::V6(v) => v.octets().to_vec(),
                };
                let version = if address.is_ipv4() { 4 } else { 6 };
                version == self.value[0]
                    && (0..usize::from(self.value[1])).all(|i| {
                        bytes[i / 8] & (0x80 >> (i % 8))
                            == self.value[2 + i / 8] & (0x80 >> (i % 8))
                    })
            }
            _ => false,
        }
    }
}

/// A complete represented causal path, bound to one packet and factual context.
/// This is structural evidence; it performs no socket, TUN or kernel operation.
#[derive(Clone, Debug)]
pub struct CausalPacketRelation {
    receipt: Receipt,
    context: [u8; 32],
    relation_digest: [u8; 32],
}
impl CausalPacketRelation {
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    pub fn context_digest(&self) -> [u8; 32] {
        self.context
    }
    pub fn digest(&self) -> [u8; 32] {
        self.relation_digest
    }
    pub fn describes(&self, packet: &[u8]) -> bool {
        self.receipt.query == hash(packet)
    }
}

pub struct ConditionalNeighborhood {
    pub receipt: Receipt,
    pub active_negative_edges: [u64; EDGE_WORDS],
    pub context_digest: [u8; 32],
    pub relation: Option<CausalPacketRelation>,
}

/// Immutable, verified graph/full geometry and source-bound conditional edges.
pub struct CausalGeometry {
    pack: Box<[u8]>,
    expected: [u8; 32],
    root: usize,
    terminal: usize,
    conditions: Vec<Vec<Term>>,
}

fn take<'a>(bytes: &mut &'a [u8], count: usize) -> Result<&'a [u8], PassageError> {
    let value = bytes.get(..count).ok_or(PassageError::Conditions)?;
    *bytes = &bytes[count..];
    Ok(value)
}
fn number(bytes: &mut &[u8]) -> Result<u16, PassageError> {
    let value = take(bytes, 2)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

impl CausalGeometry {
    pub fn load(
        pack: Vec<u8>,
        expected: [u8; 32],
        mut conditions: &[u8],
    ) -> Result<Self, PassageError> {
        if pack.len() > 4 * 1024 * 1024 || conditions.len() > 1024 * 1024 {
            return Err(PassageError::Limit);
        }
        let world = World::load(&pack, expected).map_err(PassageError::World)?;
        if world.id != 6 || take(&mut conditions, 8)? != MAGIC || number(&mut conditions)? != 6 {
            return Err(PassageError::Binding);
        }
        let root = usize::from(number(&mut conditions)?);
        let terminal = usize::from(number(&mut conditions)?);
        if usize::from(number(&mut conditions)?) != world.edge_count()
            || take(&mut conditions, 32)? != world.source_digest()
            || root == terminal
            || root >= world.node_count()
            || terminal >= world.node_count()
            || !world
                .node_json(root)
                .map_err(PassageError::World)?
                .contains("\"passage_role\":\"input\"")
            || !world
                .node_json(terminal)
                .map_err(PassageError::World)?
                .contains("\"passage_role\":\"complete\"")
        {
            return Err(PassageError::Binding);
        }
        let mut parsed = Vec::new();
        for edge in 0..world.edge_count() {
            let count = usize::from(number(&mut conditions)?);
            if count > 64 {
                return Err(PassageError::Limit);
            }
            let record_start = conditions;
            let mut terms = Vec::new();
            for _ in 0..count {
                let header = take(&mut conditions, 3)?;
                let value = take(&mut conditions, usize::from(header[2]))?.to_vec();
                let term = Term {
                    field: header[0],
                    operation: header[1],
                    value,
                };
                term.validate()?;
                terms.push(term);
            }
            let consumed = record_start.len() - conditions.len();
            let binding = format!(
                "\"condition_sha256\":\"{}\"",
                crate::hex(&hash(&record_start[..consumed]))
            );
            if !world
                .edge_json(edge)
                .map_err(PassageError::World)?
                .contains(&binding)
            {
                return Err(PassageError::Binding);
            }
            parsed.push(terms);
        }
        if !conditions.is_empty() {
            return Err(PassageError::Conditions);
        }
        Ok(Self {
            pack: pack.into_boxed_slice(),
            expected,
            root,
            terminal,
            conditions: parsed,
        })
    }

    pub fn world(&self) -> Result<World<'_>, PassageError> {
        World::load(&self.pack, self.expected).map_err(PassageError::World)
    }

    pub fn neighborhood(
        &self,
        packet_hash: [u8; 32],
        facts: &PacketFacts,
    ) -> Result<ConditionalNeighborhood, PassageError> {
        let world = self.world()?;
        let mut active = [0u64; EDGE_WORDS];
        let mut negative = [0u64; EDGE_WORDS];
        for (index, terms) in self.conditions.iter().enumerate() {
            let edge = world.edge(index).map_err(PassageError::World)?;
            if terms.iter().all(|term| term.applies(facts)) {
                if edge.polarity < 0 {
                    set(&mut negative, index);
                } else if edge.split == 0 {
                    set(&mut active, index);
                }
            }
        }
        let mut receipt = Receipt {
            world: self.expected,
            query: packet_hash,
            policy: Policy {
                direction: Direction::Future,
                hops: 8,
                max_nodes: 256,
                relations: 31,
                polarity: 1,
            },
            seeds: [0; NODE_WORDS],
            nodes: [0; NODE_WORDS],
            edges: [0; EDGE_WORDS],
            excluded: [0; NODE_WORDS],
            hop_frontier: [0; NODE_WORDS],
            digest: [0; 32],
        };
        set(&mut receipt.seeds, self.root);
        set(&mut receipt.nodes, self.root);
        let mut queue = std::collections::VecDeque::from([(self.root, 0u8)]);
        while let Some((source, depth)) = queue.pop_front() {
            for index in 0..world.edge_count() {
                let edge = world.edge(index).map_err(PassageError::World)?;
                if !bit(&active, index) || usize::from(edge.source) != source {
                    continue;
                }
                let target = usize::from(edge.target);
                if bit(&receipt.nodes, target) {
                    continue;
                }
                if depth == receipt.policy.hops {
                    set(&mut receipt.hop_frontier, target);
                    continue;
                }
                set(&mut receipt.nodes, target);
                queue.push_back((target, depth + 1));
            }
        }
        for index in 0..world.edge_count() {
            let edge = world.edge(index).map_err(PassageError::World)?;
            if bit(&active, index)
                && bit(&receipt.nodes, usize::from(edge.source))
                && bit(&receipt.nodes, usize::from(edge.target))
            {
                set(&mut receipt.edges, index);
            }
        }
        receipt.digest = receipt.compute_digest();
        let context = facts.digest();
        let contradicted = (0..world.edge_count()).any(|index| {
            world.edge(index).is_ok_and(|edge| {
                bit(&negative, index)
                    && usize::from(edge.target) == self.terminal
                    && bit(&receipt.nodes, usize::from(edge.source))
            })
        });
        let relation = if !contradicted
            && bit(&receipt.nodes, self.terminal)
            && receipt.hop_frontier.iter().all(|v| *v == 0)
        {
            let mut bytes = b"LIGHTCONE-CAUSAL-PACKET-6".to_vec();
            bytes.extend_from_slice(&receipt.digest);
            bytes.extend_from_slice(&context);
            Some(CausalPacketRelation {
                receipt,
                context,
                relation_digest: hash(&bytes),
            })
        } else {
            None
        };
        Ok(ConditionalNeighborhood {
            receipt,
            active_negative_edges: negative,
            context_digest: context,
            relation,
        })
    }
}
