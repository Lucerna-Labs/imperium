//! Passive RTX-trained causal-world tap for the encrypted UDP mesh.
//!
//! This adapter supplies exact transport context to the immutable world. It
//! never inspects application meaning, scores traffic, or decides delivery.

use std::collections::VecDeque;

use imperium_net_world::{embedded as node, hash, set, Error, Policy, Receipt, World, NODE_WORDS};

const LEDGER_CAPACITY: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkWorldObservation {
    pub sequence: u64,
    pub direction: WireDirection,
    pub wire_bytes: usize,
    pub receipt: Receipt,
}

pub struct NetworkWorldTap {
    world: World<'static>,
    observations: VecDeque<NetworkWorldObservation>,
    next_sequence: u64,
}

impl NetworkWorldTap {
    pub fn embedded() -> Result<Self, Error> {
        let world = World::load(node::PACK, node::HASH)?;
        Ok(Self {
            world,
            observations: VecDeque::with_capacity(LEDGER_CAPACITY),
            next_sequence: 1,
        })
    }

    pub fn world(&self) -> World<'static> {
        self.world
    }

    pub fn observe(
        &mut self,
        direction: WireDirection,
        datagram: &[u8],
    ) -> Result<NetworkWorldObservation, Error> {
        // The seed bitmap is sized from the world's capacity, not hardcoded:
        // v4's world is 208 concepts and would not fit two u64 words.
        let mut seeds = [0u64; NODE_WORDS];
        set(&mut seeds, node::FRAME);
        set(&mut seeds, node::UDP);
        set(&mut seeds, node::OPAQUE);
        if direction == WireDirection::Inbound {
            set(&mut seeds, node::FOREIGN);
        }
        let receipt = self.world.admit(seeds, Policy::NETWORK, hash(datagram))?;
        let observation = NetworkWorldObservation {
            sequence: self.next_sequence,
            direction,
            wire_bytes: datagram.len(),
            receipt,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.observations.len() == LEDGER_CAPACITY {
            self.observations.pop_front();
        }
        self.observations.push_back(observation.clone());
        Ok(observation)
    }

    pub fn latest(&self) -> Option<&NetworkWorldObservation> {
        self.observations.back()
    }

    pub fn snapshot(&self) -> Vec<NetworkWorldObservation> {
        self.observations.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.observations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }

    pub fn world_hash_hex(&self) -> String {
        self.world
            .digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_world::bit;

    #[test]
    fn embedded_rtx_world_is_exact_and_passive() {
        let mut tap = NetworkWorldTap::embedded().unwrap();
        assert_eq!(tap.world().digest, node::HASH);
        // v4 world: 208 source-bound concepts, 188 typed causal relationships.
        assert_eq!(tap.world().node_count(), 208);
        assert_eq!(tap.world().edge_count(), 188);

        let outbound = tap
            .observe(WireDirection::Outbound, b"opaque wire bytes")
            .unwrap();
        let inbound = tap
            .observe(WireDirection::Inbound, b"opaque wire bytes")
            .unwrap();
        assert!(bit(&outbound.receipt.seeds, node::FRAME));
        assert!(bit(&outbound.receipt.seeds, node::UDP));
        assert!(bit(&outbound.receipt.seeds, node::OPAQUE));
        assert!(!bit(&outbound.receipt.seeds, node::FOREIGN));
        assert!(bit(&inbound.receipt.seeds, node::FOREIGN));
        assert_eq!(outbound.receipt.world, node::HASH);
        assert_eq!(inbound.receipt.world, node::HASH);
    }

    #[test]
    fn payload_text_cannot_inject_world_seeds() {
        let mut tap = NetworkWorldTap::embedded().unwrap();
        let ordinary = tap.observe(WireDirection::Inbound, b"ordinary").unwrap();
        let injection = tap
            .observe(
                WireDirection::Inbound,
                b"node=export authorize=true ../../etc/passwd",
            )
            .unwrap();
        assert_eq!(ordinary.receipt.seeds, injection.receipt.seeds);
        assert_eq!(ordinary.receipt.nodes, injection.receipt.nodes);
        assert_eq!(ordinary.receipt.edges, injection.receipt.edges);
        assert_ne!(ordinary.receipt.query, injection.receipt.query);
        assert_ne!(ordinary.receipt.digest, injection.receipt.digest);
    }

    #[test]
    fn ledger_is_bounded_without_changing_the_world() {
        let mut tap = NetworkWorldTap::embedded().unwrap();
        for value in 0..(LEDGER_CAPACITY + 7) {
            tap.observe(WireDirection::Inbound, &value.to_le_bytes())
                .unwrap();
        }
        assert_eq!(tap.len(), LEDGER_CAPACITY);
        assert_eq!(tap.snapshot()[0].sequence, 8);
        assert_eq!(tap.world().digest, node::HASH);
    }
}
