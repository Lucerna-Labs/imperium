//! The signature-engine approval loop as a supervised Spiderweb **strand**.
//!
//! This loop used to be a `tokio::spawn`ed task holding a
//! [`BusSubscription`](spiderweb::BusPublisher) for
//! [`topics::APPROVED`]: every `net.signatures.approved` message ran
//! `SignatureEngineSensor::activate_candidate` (verify-before-activate, then
//! compile and load the rule). It is now a
//! [`Strand`](spiderweb::Strand) registered through
//! [`Bus::register_spec`](spiderweb::Bus::register_spec), so the spider
//! owns it: a crash becomes a `LifecycleEvent::Crashed`, the spider restarts it
//! three times, and the fourth crash quarantines it. See
//! the pilot (`imperium-net-lightcone`) for the general recipe and
//! `crates/imperium-net-lightcone/src/strand.rs` for the pilot.
//!
//! # What is (and is not) preserved
//!
//! The strand is a thin adapter over [`SignatureEngineSensor`]: the same method
//! runs, in the same order, with the same topics in and out, and the same
//! `Message::SignatureActivated` / `Message::SignatureActivationFailed`
//! payloads — minted by the service itself with the shim's
//! `BusPublisher::publish`, exactly as before, so
//! `BusEvent::new(topic, message)` semantics are byte-identical.
//!
//! Three mechanics change, all deliberately:
//!
//! * **Filtering moves into the strand.** Spiderweb routes strand deliveries by
//!   `TypeId`, not by socket name: a strand declaring a [`BusEvent`] input
//!   receives *every* `BusEvent` on the bus, so the old kernel-side prefix
//!   filter (`bus.subscribe(topics::APPROVED)`) becomes the
//!   `event.topic.starts_with(topics::APPROVED)` test in [`run`](Strand::run).
//!   Identical comparison, other side of the bus.
//! * **The pending-buffer replay is deduped.** The kernel keeps a bounded tail
//!   (32 messages per `TypeId`) and flushes it to a late subscriber — and a
//!   restarted strand is a late subscriber. Re-activation is **not**
//!   idempotent (it would load a second copy of the rule and publish a second
//!   `SignatureActivated` with a fresh `signature_id`), so this strand dedupes
//!   on `BusEvent::id`, exactly as the recipe requires. The remembered-id set
//!   is durable (shared by every generation through the spec factory), because
//!   a *fresh* set per generation could not recognise the replayed tail.
//!   Without a crash the set changes nothing: each published event has a fresh
//!   id, so every real approval still activates exactly once.
//! * **Ownership.** The durable state (the two rule vectors, the store, the
//!   operator verify key, the auditable database) is reached through one
//!   `Arc<SignatureEngineSensor>` captured by the spec factory — the pilot's
//!   shape — so every generation shares it and nothing is restructured
//!   ([`activate_candidate`](SignatureEngineSensor::activate_candidate) writes
//!   through the existing `Arc<RwLock<…>>`s). The per-generation counters stay
//!   plain fields on the strand.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use imperium_protocol::{BusEvent, Message};
use parking_lot::Mutex;
use spiderweb::Bus;
use spiderweb::{BusHandle, Socket, Strand, StrandError, StrandSpec};
use uuid::Uuid;

use crate::signature_engine::SignatureEngineSensor;

/// Strand name. Fixed, `&'static str` (Spiderweb requires it), and equal to the
/// subsystem name in the `net.sensors.ready` message, so one identifier works in
/// the topic table, the kernel log, and the spider log.
pub const NAME: &str = "imperium-net-sensors";

/// Environment variable that arms a deliberate fault, for supervision drills:
/// `IMPERIUM_SENSORS_CRASH_AFTER_APPROVALS=<n>` makes every strand instance
/// return [`StrandError::Crashed`] once it has observed `n` approval messages.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. It exists so the restart/quarantine path can be exercised
/// end-to-end against the real strand instead of a stand-in, and so an operator
/// can drill the supervisor on a live node.
pub const CRASH_AFTER_APPROVALS_ENV: &str = "IMPERIUM_SENSORS_CRASH_AFTER_APPROVALS";

/// The bus topics of this loop, unchanged from the `tokio::spawn` version.
pub mod topics {
    /// Consumed by the strand (prefix match, as the old `bus.subscribe` was).
    pub const APPROVED: &str = "net.signatures.approved";
    /// Published by the service on a successful activation.
    pub const ACTIVATED: &str = "net.signatures.activated";
    /// Published by the service when activation is refused.
    pub const ACTIVATION_FAILED: &str = "net.signatures.activation_failed";
}

/// How many recently processed `BusEvent::id`s the dedupe set remembers.
///
/// The kernel's replay tail is 32 messages per `TypeId` (`PENDING_BUFFER_CAP`,
/// see the recipe §5.4), so 64 covers a full replay with headroom and keeps the
/// set's memory bounded for the life of the node.
const DEDUPE_WINDOW: usize = 64;

/// How a signature-engine strand instance should fault, for drills and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Serve approvals normally. The production default.
    #[default]
    None,
    /// Deliberately crash after observing `n` approval messages. The count is
    /// per strand *instance*, so a restarted instance crashes again after its
    /// own `n`th approval — which is what lets a drill drive the full
    /// crash → restart ×3 → quarantine sequence.
    CrashAfterApprovals(u32),
}

impl FaultPolicy {
    /// Read the policy from [`CRASH_AFTER_APPROVALS_ENV`]. Absent/zero/invalid
    /// values all mean [`FaultPolicy::None`]: a typo must never crash a node.
    pub fn from_env() -> Self {
        Self::parse(std::env::var(CRASH_AFTER_APPROVALS_ENV).ok().as_deref())
    }

    /// The parsing half of [`FaultPolicy::from_env`], without process-env
    /// access so it can be tested without racing other tests.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim).and_then(|v| v.parse::<u32>().ok()) {
            Some(n) if n > 0 => FaultPolicy::CrashAfterApprovals(n),
            _ => FaultPolicy::None,
        }
    }

    /// Whether this policy injects a fault (used to warn loudly at boot).
    pub fn is_injected(&self) -> bool {
        !matches!(self, FaultPolicy::None)
    }

    /// The crash reason for an instance that has just observed `seen`
    /// approvals, or `None` while this instance should keep running.
    fn tripped(&self, seen: u32) -> Option<String> {
        match self {
            FaultPolicy::None => None,
            FaultPolicy::CrashAfterApprovals(n) if seen >= *n => Some(format!(
                "injected fault: crashed after {seen} approval(s) \
                 ({CRASH_AFTER_APPROVALS_ENV} = {n})"
            )),
            FaultPolicy::CrashAfterApprovals(_) => None,
        }
    }
}

/// Bounded, order-insensitive set of `BusEvent` ids already acted on.
///
/// `EventId` wraps a `Uuid`, so ids are neither ordered nor monotonic — a
/// "highest id seen" watermark would drop legitimate events. A bounded set of
/// the most recent ids is exact for the replay it has to defeat (the kernel
/// replays a tail of 32) and cannot grow without bound.
#[derive(Debug, Default)]
struct ProcessedEvents {
    /// Insertion order, oldest first, so the window can be evicted FIFO.
    order: VecDeque<Uuid>,
    ids: HashSet<Uuid>,
}

impl ProcessedEvents {
    fn new() -> Self {
        Self::default()
    }

    /// Record `id` and report whether it is the first time it was seen.
    fn mark_new(&mut self, id: Uuid) -> bool {
        if !self.ids.insert(id) {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > DEDUPE_WINDOW {
            if let Some(evicted) = self.order.pop_front() {
                self.ids.remove(&evicted);
            }
        }
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.ids.len()
    }

    #[cfg(test)]
    fn remembers(&self, id: Uuid) -> bool {
        self.ids.contains(&id)
    }
}

/// The signature-engine approval loop as a strand.
///
/// Owns its state: the engine is shared with whatever built it (`Arc`), the
/// fault policy is `Copy`, the dedupe set is shared across generations, and the
/// approval counter is per instance. Nothing is borrowed from outside, which is
/// what makes the strand restartable — the kernel's factory call produces a
/// fresh, independent instance.
pub struct SignatureEngineStrand {
    engine: Arc<SignatureEngineSensor>,
    /// Durable across restarts, like the engine itself: it exists precisely to
    /// recognise the tail the kernel replays to a restarted generation.
    processed: Arc<Mutex<ProcessedEvents>>,
    faults: FaultPolicy,
    /// Approvals this *instance* has observed. Per-instance by construction, so
    /// a restart resets it.
    approvals_seen: u32,
}

impl SignatureEngineStrand {
    /// The restartable spec for this loop, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec). This is the
    /// only constructor: a strand must arrive as a spec to be restartable (a
    /// live strand registered without a factory is crash-*reportable* but the
    /// spider's restart is refused for it).
    ///
    /// The factory captures an `Arc<SignatureEngineSensor>` clone, so every
    /// restarted instance verifies and loads against the same rule vectors, the
    /// same store, the same operator key and the same auditable database:
    /// restart resumes activation state instead of reloading a different one. It
    /// also captures one [`ProcessedEvents`] set, so the replayed pending tail
    /// is skipped rather than re-activated.
    pub fn spec(engine: Arc<SignatureEngineSensor>, faults: FaultPolicy) -> StrandSpec {
        let processed = Arc::new(Mutex::new(ProcessedEvents::new()));
        StrandSpec::new(NAME, move || -> Box<dyn Strand> {
            Box::new(SignatureEngineStrand::new(
                Arc::clone(&engine),
                Arc::clone(&processed),
                faults,
            ))
        })
    }

    /// A strand over `engine`, deduping through the shared `processed` set.
    /// Private by design: callers go through [`SignatureEngineStrand::spec`],
    /// which creates the durable dedupe set the restart path depends on.
    fn new(
        engine: Arc<SignatureEngineSensor>,
        processed: Arc<Mutex<ProcessedEvents>>,
        faults: FaultPolicy,
    ) -> Self {
        Self {
            engine,
            processed,
            faults,
            approvals_seen: 0,
        }
    }
}

impl Strand for SignatureEngineStrand {
    fn name(&self) -> &str {
        NAME
    }

    fn inputs(&self) -> &[Socket] {
        // The socket name documents the topic in the lifecycle event and the web
        // graph; routing is by `BusEvent`'s `TypeId` (see the module docs).
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::APPROVED)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 2] = [
            Socket::new::<BusEvent>(topics::ACTIVATED),
            Socket::new::<BusEvent>(topics::ACTIVATION_FAILED),
        ];
        &SOCKS
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick and
        // let the worker join (draining instead would delay shutdown).
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on. Draining by socket name (`recv::<BusEvent>(name)`) would
        // leave every non-matching carrier in the inbox forever — the inbox is a
        // mailbox, not a filter.
        //
        // `?` is infallible in practice: the inbox only ever holds payloads
        // whose `TypeId` matched this strand's declared input, so `TypeMismatch`
        // cannot fire. A genuine kernel fault still surfaces as `Crashed` and is
        // supervised.
        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            // The prefix filter the kernel used to apply for the old
            // `bus.subscribe(topics::APPROVED)` subscription.
            if !event.topic.starts_with(topics::APPROVED) {
                continue;
            }
            // The old loop ignored every other message kind on that prefix.
            if !matches!(event.message, Message::SignatureApproved(_)) {
                continue;
            }

            // Dedupe on the event id before the effect (recipe §5.4): a
            // restarted generation is replayed the kernel's pending tail, and
            // activation is not idempotent. The set is durable, so a replay
            // after a restart is recognised; without a crash this never fires,
            // because every publish mints a fresh id.
            if self.processed.lock().mark_new(event.id.0) {
                if let Message::SignatureApproved(approved) = &event.message {
                    // The service method is unchanged: same verify-before-
                    // activate semantics, same topics out, same payloads, and it
                    // publishes through the shim exactly as the old loop did.
                    self.engine.activate_candidate(approved);
                }
            } else {
                tracing::debug!(
                    event_id = ?event.id,
                    "skipping a replayed signature approval already acted on"
                );
            }

            // Per-generation fault drill; see `FaultPolicy`.
            self.approvals_seen = self.approvals_seen.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.approvals_seen) {
                // Diagnostic-only path: the tick's publishes (already made by
                // `activate_candidate`) are still delivered by the kernel.
                return Err(StrandError::Crashed(reason));
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick
        // (the worker paces them at 10 ms), which is this strand's idle loop.
        Ok(())
    }
}

impl SignatureEngineSensor {
    /// The restartable strand spec for this engine's approval loop.
    ///
    /// Same shape as the pilot's `LightconeStrand::spec`: the caller (the
    /// composition root) registers it with
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec) **before**
    /// the kernel's run loop — a
    /// spec queued after engage can never be installed, and
    /// `register_strand` says so instead of dropping it.
    pub fn strand_spec(self: &Arc<Self>, faults: FaultPolicy) -> StrandSpec {
        SignatureEngineStrand::spec(Arc::clone(self), faults)
    }

    /// Read the fault policy from the environment and queue this engine's strand
    /// on `bus`, logging loudly when a drill is armed.
    ///
    /// This is the one call the composition root needs (see the crate report):
    /// it replaces the old `tasks.push(engine.subscribe_signature_approvals(&bus))`
    /// — the approval loop is a supervised strand now, not a spawned task, so it
    /// produces no `JoinHandle`.
    pub fn register_strand(self: &Arc<Self>, bus: &mut Bus) {
        let faults = FaultPolicy::from_env();
        if faults.is_injected() {
            // A deliberately armed fault must never look like a real one in the
            // logs, and must be impossible to leave on by accident without a
            // trace.
            tracing::warn!(
                policy = ?faults,
                env = CRASH_AFTER_APPROVALS_ENV,
                "signature engine fault injection ARMED — the strand will crash on purpose"
            );
        }
        bus.register_spec(self.strand_spec(faults));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------------
    // Layer (a): service-level units that need no bus and no kernel.
    // ---------------------------------------------------------------------

    #[test]
    fn fault_policy_absent_zero_or_invalid_means_none() {
        assert_eq!(FaultPolicy::parse(None), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("   ")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("0")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("many")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("-3")), FaultPolicy::None);
        assert!(!FaultPolicy::parse(Some("0")).is_injected());
    }

    #[test]
    fn fault_policy_parses_a_positive_count_and_trips_from_there() {
        let policy = FaultPolicy::parse(Some(" 2 "));
        assert_eq!(policy, FaultPolicy::CrashAfterApprovals(2));
        assert!(policy.is_injected());
        assert!(policy.tripped(1).is_none(), "not yet at the threshold");
        let reason = policy.tripped(2).expect("threshold reached");
        assert!(
            reason.contains("injected fault") && reason.contains(CRASH_AFTER_APPROVALS_ENV),
            "the reason must name the drill that caused it: {reason}"
        );
    }

    #[test]
    fn dedupe_recognises_a_replay_and_stays_bounded() {
        let mut processed = ProcessedEvents::new();
        let first = Uuid::new_v4();

        assert!(processed.mark_new(first), "first sighting is new");
        assert!(
            !processed.mark_new(first),
            "a replay of the same id must be recognised (this is the restart case)"
        );

        // Push past the window: the oldest ids are forgotten, the newest are
        // kept, and the set never exceeds the window.
        let mut newest = first;
        for _ in 0..(DEDUPE_WINDOW * 2) {
            newest = Uuid::new_v4();
            assert!(processed.mark_new(newest));
        }
        assert_eq!(processed.len(), DEDUPE_WINDOW);
        assert!(processed.remembers(newest), "recent ids are remembered");
        assert!(
            !processed.remembers(first),
            "ids older than the window are evicted, so memory is bounded"
        );
    }
}
