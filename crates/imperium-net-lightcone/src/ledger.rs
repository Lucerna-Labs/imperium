//! The bounded sequenced receipt ledger.
//!
//! A ring of [`SLOTS`] entries with a monotonic sequence number. The ring is
//! the point: an evicted sequence number becomes a permanent gap, and a lookup
//! by that sequence returns `None` rather than a neighbouring record. An
//! eviction therefore reads as an explicit absence, never as a wrong answer.

use imperium_net_world::Receipt;
use imperium_protocol::LightconeFrameFormat;

use crate::WireDirection;

/// How many receipts the ring retains. Older entries are evicted and their
/// sequence numbers become explicit gaps.
pub const SLOTS: usize = 32;

/// One recorded admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LightconeReceiptRecord {
    pub sequence: u64,
    pub format: LightconeFrameFormat,
    pub direction: WireDirection,
    pub kind: imperium_net_observer::ObservationKind,
    pub receipt: Receipt,
}

/// World identity and counters, for the operator's read surface.
#[derive(Clone, Debug)]
pub struct LightconeInfo {
    pub world_version: u16,
    pub nodes: usize,
    pub edges: usize,
    pub dimensions: usize,
    pub rx: u64,
    pub tx: u64,
    pub raw_ip_rx: u64,
    pub raw_ip_tx: u64,
    pub mesh_rx: u64,
    pub mesh_tx: u64,
    pub failures: u64,
    pub latest: u64,
    pub oldest: u64,
    pub pack_sha256: String,
    pub source_sha256: String,
    pub training_sha256: String,
    pub training_platform: &'static str,
    pub sealed: bool,
    pub passive: bool,
    pub holds_verdict: bool,
}

#[derive(Debug)]
pub struct Ledger {
    slots: [Option<LightconeReceiptRecord>; SLOTS],
    next: u64,
    pub rx: u64,
    pub tx: u64,
    pub raw_ip_rx: u64,
    pub raw_ip_tx: u64,
    pub mesh_rx: u64,
    pub mesh_tx: u64,
    pub failures: u64,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            next: 1,
            rx: 0,
            tx: 0,
            raw_ip_rx: 0,
            raw_ip_tx: 0,
            mesh_rx: 0,
            mesh_tx: 0,
            failures: 0,
        }
    }

    /// Record an admission and return the sequenced entry.
    pub fn record(
        &mut self,
        format: LightconeFrameFormat,
        direction: WireDirection,
        kind: imperium_net_observer::ObservationKind,
        receipt: Receipt,
    ) -> LightconeReceiptRecord {
        match direction {
            WireDirection::Inbound => self.rx = self.rx.saturating_add(1),
            WireDirection::Outbound => self.tx = self.tx.saturating_add(1),
        }
        if format == LightconeFrameFormat::RawIp {
            match direction {
                WireDirection::Inbound => self.raw_ip_rx = self.raw_ip_rx.saturating_add(1),
                WireDirection::Outbound => self.raw_ip_tx = self.raw_ip_tx.saturating_add(1),
            }
        }
        if format == LightconeFrameFormat::MeshDatagram {
            match direction {
                WireDirection::Inbound => self.mesh_rx = self.mesh_rx.saturating_add(1),
                WireDirection::Outbound => self.mesh_tx = self.mesh_tx.saturating_add(1),
            }
        }
        let sequence = self.next;
        self.next = self.next.saturating_add(1);
        let record = LightconeReceiptRecord {
            sequence,
            format,
            direction,
            kind,
            receipt,
        };
        self.slots[((sequence - 1) % SLOTS as u64) as usize] = Some(record.clone());
        record
    }

    pub fn note_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    /// A receipt by sequence; `0` means the latest.
    ///
    /// The `filter` on the stored sequence is what makes eviction explicit: a
    /// slot that has been overwritten holds a *different* sequence number, so
    /// the lookup fails rather than returning the wrong record.
    pub fn get(&self, sequence: u64) -> Option<LightconeReceiptRecord> {
        let id = if sequence == 0 {
            self.next.checked_sub(1)?
        } else {
            sequence
        };
        if id == 0 {
            return None;
        }
        self.slots[((id - 1) % SLOTS as u64) as usize]
            .clone()
            .filter(|r| r.sequence == id)
    }

    pub fn latest_sequence(&self) -> u64 {
        self.next.saturating_sub(1)
    }

    pub fn oldest_sequence(&self) -> u64 {
        self.next.saturating_sub(SLOTS as u64).max(1)
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_observer::ObservationKind;

    /// A minimal valid receipt for ledger-only tests.
    fn receipt() -> Receipt {
        let world = imperium_net_world::World::load(
            imperium_net_world::embedded::PACK,
            imperium_net_world::embedded::HASH,
        )
        .unwrap();
        world
            .admit(
                [0u64; imperium_net_world::NODE_WORDS],
                imperium_net_world::Policy::NETWORK,
                [0; 32],
            )
            .unwrap()
    }

    #[test]
    fn evicted_sequence_is_absent_not_substituted() {
        let mut l = Ledger::new();
        let r = receipt();
        let first = l
            .record(
                LightconeFrameFormat::Ethernet,
                WireDirection::Inbound,
                ObservationKind::Decoded,
                r,
            )
            .sequence;
        assert_eq!(first, 1);
        for _ in 0..SLOTS {
            l.record(
                LightconeFrameFormat::Ethernet,
                WireDirection::Outbound,
                ObservationKind::Decoded,
                receipt(),
            );
        }
        // Sequence 1 has been overwritten; it must read as absent.
        assert!(l.get(first).is_none());
        // ...but the slot it occupied now answers for its own sequence.
        assert!(l.get(first + SLOTS as u64).is_some());
    }

    #[test]
    fn zero_means_latest_and_empty_ledger_has_none() {
        let mut l = Ledger::new();
        assert!(l.get(0).is_none());
        l.record(
            LightconeFrameFormat::Ethernet,
            WireDirection::Inbound,
            ObservationKind::Unknown,
            receipt(),
        );
        assert_eq!(l.get(0).unwrap().sequence, 1);
    }
}
