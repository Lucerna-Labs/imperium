mod database;
mod extractor;
mod staging;
mod strand;

#[cfg(test)]
mod test_supervision;

pub use database::{SignatureDatabase, SignatureEntry, SignatureProvenance};
pub use extractor::{ExtractionLoop, SignatureExtractor};
pub use staging::{ApprovalFlow, CandidateStatus, StagedCandidateSnapshot, StagingArea};
pub use strand::{ExtractionStrand, FaultPolicy, SeenRequests, CRASH_AFTER_REQUESTS_ENV, NAME};

use std::sync::Arc;

use imperium_protocol::BusEvent;
use imperium_protocol::Message;
use spiderweb::{Bus, BusPublisher};

/// Bus topics of this subsystem. General → specific, per `BUS_CONVENTIONS.md`.
///
/// Named here, once, because three different things must agree on them: the
/// publishers (`ExtractionLoop`), the strand's declared input/output sockets,
/// and the operator surface (`imperium-cli`'s control pipe).
pub mod topics {
    pub const READY: &str = "net.signatures.ready";
    /// The request the extraction strand consumes.
    pub const REQUEST: &str = "net.signatures.extraction_request";
    /// Staged candidate, published by `StagingArea::submit`.
    pub const CANDIDATE: &str = "net.signatures.candidate";
    /// Extraction succeeded: the candidate is persisted and awaiting review.
    pub const CANDIDATE_PENDING: &str = "net.signatures.candidate_pending";
    /// Extraction could not produce a candidate.
    pub const EXTRACTION_FAILED: &str = "net.signatures.extraction_failed";
}

/// Announce readiness. Publishes only; the supervised extraction loop is queued
/// separately by [`register_strands`].
pub async fn init(publisher: &BusPublisher) -> Result<(), spiderweb::BusError> {
    BusEvent::publish(
        publisher,
        topics::READY,
        Message::SubsystemReady { name: NAME.into() },
    )?;
    tracing::info!("imperium-net-signatures initialized");
    Ok(())
}

/// Queue this subsystem's supervised strands on `bus`.
///
/// # Call this *before* `bus.engage_supervision()`
///
/// Strand specs are installed by the kernel's run loop, which only happens
/// inside `engage_supervision`. Registering later is refused with
/// [`StrandRegistrationError::Engaged`] rather than silently leaving the
/// extraction loop unsupervised — and an unsupervised loop is a subsystem that
/// does not run at all, since the old `tokio::spawn` is gone.
///
/// # Why this takes the loop, not just the bus
///
/// The extraction loop reads durable state the node owns and shares elsewhere
/// — `Arc<Store>` (also handed to the signature engine), `Arc<MemoryLog>` (also
/// fed by the memory-log subscriptions) and `Arc<StagingArea>` (also held by
/// the operator console and the control surface). Building that state here
/// would give the strand a *different* store, log and staging area than the
/// rest of the node, so the caller passes the one it already wired. The strand
/// shares it through its factory, which is what makes a restart resume the same
/// subsystem instead of a parallel one.
///
/// The fault policy comes from [`FaultPolicy::from_env`] (see
/// [`CRASH_AFTER_REQUESTS_ENV`]); it is [`FaultPolicy::None`] unless an operator
/// armed a drill, and an armed drill is logged loudly.
pub fn register_strands(bus: &mut Bus, extraction: &Arc<ExtractionLoop>) {
    let faults = FaultPolicy::from_env();
    if faults.is_injected() {
        // A deliberately armed fault must never look like a real one in the
        // logs, and must be impossible to leave on by accident without a trace.
        tracing::warn!(
            policy = ?faults,
            env = CRASH_AFTER_REQUESTS_ENV,
            "signatures fault injection ARMED — the strand will crash on purpose"
        );
    }
    bus.register_spec(ExtractionStrand::spec(Arc::clone(extraction), faults));
}
