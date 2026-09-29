mod crypto;
mod daemon;
mod destination;
pub mod flow_behavior;
pub mod flow_policy;
mod gate;
mod handshake;
mod hardening;
mod lightcone;
mod path;
mod peer;
mod session;
mod stun;
mod transport;
mod traversal;
pub mod wire;
mod world_lightcone;

pub use crypto::{CryptoError, DirectionKeys, ReplayWindow};
pub use daemon::{DaemonError, DaemonStats, MeshDaemon, MeshInbound, MeshNodeConfig, PeerConfig};
pub use destination::{Destination, DestinationError};
pub use gate::{HandshakeGate, COOKIE_LEN, GATE_MAC_LEN};
pub use handshake::{
    decode_identity_vk, encode_identity_vk, fresh_session_id, hello_signed_payload,
    hello_transcript_hash, initiator_encapsulate, response_signed_payload, verify_hello,
    verify_hello_response, HandshakeError, IdentityBinding,
};
pub use hardening::{
    HardenedPayload, HardenerStats, MeshHardener, RecoveredFrame, MAX_SAFE_TUN_MTU,
};
pub use lightcone::{
    fit_law, ring_distance, CausalImpossibility, CausalObservation, Lightcone, Position,
    PropagationLaw, Tick,
};
pub use path::{PathManager, PathScoreWeights};
pub use peer::{PeerManager, PeerState};
pub use session::{PeerSession, SessionManager};
pub use stun::StunClient;
pub use transport::MeshTransport;
pub use traversal::{
    BoundProbeSocket, NatProbePolicyError, NatProbeSetupError, NatTraversalPlanner,
    MAX_PROBES_PER_SOCKET, MAX_PROBE_CANDIDATES, MAX_PROBE_SOCKETS, MAX_PROBE_WINDOW_MS,
};
pub use wire::{
    decode_hello, decode_hello_response, encode_hello, encode_hello_response, fragment,
    handshake_datagram_len, handshake_response_datagram_len, split_fragment, DatagramKind,
    HandshakeKind, Reassembler, WireError, FRAGMENT_CHUNK,
};
/// This subsystem's bus topics, general → specific per `BUS_CONVENTIONS.md`.
pub mod topics {
    /// Readiness announcement, published once by [`init`].
    pub const READY: &str = "net.mesh.ready";
}

pub use world_lightcone::{NetworkWorldObservation, NetworkWorldTap, WireDirection};

use imperium_protocol::{BusEvent, Message};
use spiderweb::BusPublisher;

/// Verify the embedded RTX world and announce readiness on the shared
/// publisher. NAT traversal policies remain planner inputs; the live mesh
/// daemon does not run those probe plans, so startup must not announce one as
/// an applied runtime policy.
pub async fn init(publisher: &BusPublisher) -> Result<(), spiderweb::BusError> {
    let network_world =
        NetworkWorldTap::embedded().expect("embedded RTX network world must verify at startup");
    tracing::info!(
        world_sha256 = %network_world.world_hash_hex(),
        training_platform = imperium_net_world::embedded::TRAINING_PLATFORM,
        sealed = false,
        "RTX network causal world verified"
    );
    BusEvent::publish(
        publisher,
        topics::READY,
        Message::SubsystemReady {
            name: "imperium-net-mesh".into(),
        },
    )?;

    tracing::info!("imperium-net-mesh initialized");
    Ok(())
}

#[cfg(test)]
mod startup_tests {
    use super::*;

    #[tokio::test]
    async fn startup_announces_readiness_without_claiming_nat_policy_is_applied() {
        let publisher = spiderweb::Bus::open().publisher();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<BusEvent>(4);
        publisher.subscribe_prefix(
            "net.mesh.",
            Box::new(move |_socket, payload| {
                if let Ok(event) = payload.downcast::<BusEvent>() {
                    let _ = tx.try_send(*event);
                }
            }),
        );

        init(&publisher).await.expect("mesh init");
        let ready = rx.try_recv().expect("readiness event");
        assert_eq!(&*ready.topic, topics::READY);
        assert!(matches!(
            ready.message,
            Message::SubsystemReady { ref name } if name == "imperium-net-mesh"
        ));
        assert!(rx.try_recv().is_err(), "no unimplemented NAT policy claim");
    }
}
