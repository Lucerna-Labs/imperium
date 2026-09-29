//! Operator-signed membership, bootstrap tokens, and configuration gossip.
//!
//! A node's cluster state is held by two managers —
//! [`MembershipManager`] and [`ConfigManager`] — and the two loops that update
//! that state from the bus are supervised Spiderweb **strands**
//! ([`MembershipGrantStrand`], [`ConfigResponseStrand`]): the composition root
//! queues their specs with [`register_strands`] before
//! the kernel's run loop, and the
//! spider restarts them on a crash. The old `tokio::spawn`ed recv loops are
//! gone — see [`strand`] and the pilot (`imperium-net-lightcone`).
//!
//! Because both loops apply **signature-verified state changes**, their strand
//! form dedupes replayed events on [`BusEvent::id`](imperium_protocol::BusEvent)
//! with a record shared across restarts: a replayed grant or fetch response must
//! never be re-applied. The managers themselves are unchanged and remain
//! directly usable (and testable) without a bus.

mod access;
mod config;
mod membership;
mod strand;

#[cfg(test)]
mod test_supervision;
mod token;

pub use access::AccessPolicy;
pub use config::{ClusterConfig, ConfigManager};
pub use membership::{MembershipManager, MembershipState};
pub use strand::{
    attach_config, attach_membership, links_for, register_strands, register_strands_with,
    ClusterLinks, ConfigResponseStrand, FaultPolicy, MembershipGrantStrand, SeenIds, CONFIG_STRAND,
    CRASH_AFTER_MESSAGES_ENV, MEMBERSHIP_STRAND, NAME,
};
pub use token::TokenManager;

/// Bus topics of this subsystem. General → specific, per `BUS_CONVENTIONS.md`.
///
/// Named here, once, because three different things must agree on them: the
/// publishers (the managers), the strands' declared input sockets, and every
/// consumer that subscribes by prefix.
pub mod topics {
    /// `init`'s readiness announcement; its `name` field is [`crate::NAME`].
    pub const READY: &str = "net.cluster.ready";
    /// Operator-signed grant, published by
    /// [`MembershipManager::approve_membership`](crate::MembershipManager::approve_membership)
    /// and consumed by the supervised membership strand.
    pub const MEMBERSHIP_GRANTED: &str = "net.cluster.membership.granted";
    /// Fetched configuration, published by
    /// [`ConfigManager::handle_fetch_request`](crate::ConfigManager::handle_fetch_request)
    /// and consumed by the supervised config strand.
    pub const CONFIG_FETCH_RESPONSE: &str = "net.cluster.config.fetch_response";
}

use imperium_protocol::{BusEvent, Message};
use spiderweb::BusPublisher;

/// Announce readiness. Publishes only; the supervised membership and config
/// loops are queued separately by [`register_strands`].
pub async fn init(publisher: &BusPublisher) -> Result<(), spiderweb::BusError> {
    let ready = BusEvent::new(topics::READY, Message::SubsystemReady { name: NAME.into() });
    publisher.publish(topics::READY, ready)?;
    tracing::info!("imperium-net-cluster initialized");
    Ok(())
}
