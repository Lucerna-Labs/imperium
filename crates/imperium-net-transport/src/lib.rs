mod controller;
mod hardening;
mod leak_guard;
mod live;
mod masque;
mod orchestrator;

pub mod strand;
#[cfg(test)]
mod test_supervision;

pub use controller::{ProtocolController, ProtocolControllerConfig, ProtocolKind};
pub use hardening::{HardeningController, HardeningError, ProbeDeceptionEngine};
pub use leak_guard::LeakGuard;
pub use live::{
    LiveHealthProbe, LivePathCommand, LiveProtocolProfile, LiveTransportError,
    LiveTransportRuntime, LiveTransportStatus, ProfileStatus, TransitionAction, TransitionReceipt,
    ACTIVE_REQUEST_TOPIC, CONTROL_STATUS_TOPIC, PROFILE_ROTATION_TOPIC,
};
pub use masque::MasqueController;
pub use orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorPolicy};
pub use strand::{
    queue_hardening, queue_lanes, register_strands, register_strands_with, FaultPolicy,
    HardeningFaultPolicy, HardeningStrand, Lane, OrchestratorStrand, SeenIds,
    CRASH_AFTER_MESSAGES_ENV, DECISION_TOPIC, HARDENING_APPLY_TOPIC,
    HARDENING_CRASH_AFTER_PROFILES_ENV, HARDENING_STATUS_TOPIC, HARDENING_STRAND,
    PROTOCOL_EVENTS_STRAND, PROTOCOL_EVENT_TOPIC, SENSOR_TOPIC_PREFIX, THREAT_ASSESSMENTS_STRAND,
    TOOLKIT_REQUEST_TOPIC,
};

use std::sync::Arc;

use imperium_protocol::BusEvent;
use imperium_protocol::Message;
use spiderweb::BusPublisher;

/// Announce readiness and the node's starting transport profile on the shared
/// publisher. The supervised orchestrator and hardening lanes are queued
/// separately by [`register_strands`].
pub async fn init(publisher: &Arc<BusPublisher>) -> Result<(), spiderweb::BusError> {
    BusEvent::publish(
        publisher,
        "net.transport.ready",
        Message::SubsystemReady {
            name: "imperium-net-transport".into(),
        },
    )?;

    let hardening_profile = HardeningController::balanced_profile(None);
    BusEvent::publish(
        publisher,
        "net.transport.hardening.apply",
        Message::ProtocolHardeningProfile(hardening_profile.clone()),
    )?;
    if let Err(e) = HardeningController::new(Arc::clone(publisher)).apply(hardening_profile) {
        tracing::warn!(error = %e, "default hardening profile rejected");
    }

    tracing::info!("imperium-net-transport initialized");
    Ok(())
}
