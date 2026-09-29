mod classifier;
mod envelope;
mod fusion;
mod probe;
mod signature_engine;
mod strand;

#[cfg(test)]
mod test_supervision;

pub use classifier::{ClassifierConfig, ClassifierSensor};
pub use envelope::{
    adversarial_probe_burst, adversarial_scan_fanout, adversarial_session_probe,
    adversarial_volume_anomaly, synthetic_normal_windows, EnvelopeError, EnvelopeModel,
    EnvelopeSensor, EnvelopeTrainer, FeatureVector, FEATURE_NAMES, WINDOW_SECS,
};
pub use fusion::{FusionPolicy, SensorFusion};
// The probe-behaviour sensor: what a prober is *doing*, per source, as five
// separate readings that are never fused into one number. See `probe.rs` for
// the doctrine and the E30 lineage.
pub use probe::{
    probe_shape_fingerprint, ProbeEvent, ProbeSensor, ProbeSensorConfig, ProbeSensorError,
    DEFAULT_MAX_SOURCES, DEFAULT_SOURCE_TTL_MICROS, EPOCH_PROBES, MIN_GAPS_FOR_PE,
    PROBE_PROFILE_TOPIC, PROBE_WINDOW, SHAPE_MEMORY,
};
pub use signature_engine::SignatureEngineSensor;
// The signature-engine approval loop is a supervised Spiderweb **strand** (see
// the pilot (`imperium-net-lightcone`) and the pilot in
// `imperium-net-lightcone`): the composition root queues
// `SignatureEngineSensor::register_strand(&bus)` as a spec *before*
// `Bus::engage_supervision()`, and the spider restarts it on a crash.
pub use strand::{topics, FaultPolicy, SignatureEngineStrand, CRASH_AFTER_APPROVALS_ENV, NAME};

/// The crate-level registration entry point for the composition root.
///
/// Queue the signature engine's supervised strand on `bus` — before
/// [`Bus::engage_supervision`] — exactly like
/// `imperium_net_signatures::register_strands`. The engine is passed in (rather
/// than built here) because the node that owns it configures it: the operator
/// verify key, the store and the auditable database are the composition root's
/// choices, and the strand must share *that* engine, not a fresh one.
///
/// The fault policy comes from [`FaultPolicy::from_env`] (see
/// [`CRASH_AFTER_APPROVALS_ENV`]); it is [`FaultPolicy::None`] unless an
/// operator armed a drill, and an armed drill is logged loudly.
pub fn register_strands(bus: &mut Bus, engine: &Arc<SignatureEngineSensor>) {
    engine.register_strand(bus);
}

use std::sync::Arc;

use imperium_protocol::{BusEvent, Message};
use spiderweb::{Bus, BusPublisher};

/// Announce readiness. Publishes only; the supervised signature-engine loop is
/// queued separately by [`register_strands`].
pub async fn init(publisher: &BusPublisher) -> Result<(), spiderweb::BusError> {
    BusEvent::publish(
        publisher,
        "net.sensors.ready",
        Message::SubsystemReady {
            name: "imperium-net-sensors".into(),
        },
    )?;
    tracing::info!("imperium-net-sensors initialized");
    Ok(())
}
