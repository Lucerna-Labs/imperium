//! The signature-extraction request loop as a supervised Spiderweb **strand**.
//!
//! Before this module the loop was a `tokio::spawn`ed task holding a
//! [`BusSubscription`](spiderweb::BusPublisher) for
//! [`topics::REQUEST`](crate::topics::REQUEST). It is now a
//! [`Strand`](spiderweb::Strand) registered through
//! [`Bus::register_spec`](spiderweb::Bus::register_spec), so the spider
//! owns it: a crash becomes a `LifecycleEvent::Crashed`, is restarted three
//! times, and is quarantined on the fourth. See
//! the pilot (`imperium-net-lightcone`) for the recipe, and the pilot
//! (`crates/imperium-net-lightcone/src/strand.rs`) for the worked example this
//! module follows.
//!
//! # What is preserved, and what changes
//!
//! The strand is a thin adapter over [`ExtractionLoop`]: the same handler runs
//! on the same input topic, against the same shared state, and mints the same
//! messages on the same output topics. Three mechanics change, deliberately:
//!
//! * **Filtering moves into the strand.** Spiderweb routes strand deliveries by
//!   `TypeId`, not by socket name: a strand declaring a [`BusEvent`] input
//!   receives *every* `BusEvent` published anywhere on the bus, so the old
//!   kernel-side prefix filter (`bus.subscribe(topics::REQUEST)`) becomes the
//!   `event.topic.starts_with(topics::REQUEST)` test below. Semantics are
//!   identical; only the location of the comparison moved.
//! * **Requests are deduplicated on [`BusEvent::id`].** The kernel keeps a
//!   bounded tail (32 messages per `TypeId`) so a *late* subscriber can be
//!   caught up, and a restarted generation is exactly that: it is replayed the
//!   most recent messages, including the request it was already working on.
//!   Extraction is **not** idempotent — it mints a candidate, persists it and
//!   stages it — so a replay must not run the handler again. [`SeenRequests`]
//!   is that guard, and it lives in the factory-shared state so it survives a
//!   restart (a per-generation set would be empty exactly when it is needed).
//! * **The inbox cannot lag.** The old loop could drop messages under
//!   backpressure (`BusError::Lagged`); a strand's inbox is an unbounded
//!   mailbox that is drained every tick, so that arm has no analogue here.
//!
//! # Shared state: the `Arc`s, not a redesign
//!
//! The handler reads `Arc<Store>`, `Arc<MemoryLog>` and `Arc<StagingArea>`
//! (and publishes through `Arc<Bus>`), all owned by [`ExtractionLoop`]. The
//! strand holds **one** `Arc<ExtractionLoop>` and the spec's factory clones it
//! into every generation, so a restart resumes the same store, the same memory
//! log and the same staging area instead of starting over with empty ones. The
//! ownership model is untouched; only the way the loop is *driven* changed.
//!
//! # The output path
//!
//! The handler keeps publishing through the shim's
//! `BusPublisher::publish` — the same four publish sites,
//! the same topics, the same [`BusEvent::new`] payloads, in the same order.
//! That is deliberate: routing the three failure topics and the
//! `candidate_pending` notification back out through
//! [`BusHandle::publish`](spiderweb::BusHandle::publish) would mean
//! changing the handler's contract from "publish as you go" to "return an
//! outcome", and the fourth publisher (`net.signatures.candidate`, emitted by
//! `StagingArea::submit`, which is also called by the GUI and the control
//! surface) would stay on the old path regardless. Both paths reach the same
//! kernel `deliver`, which fans out to (a) every strand declaring that `TypeId`
//! and (b) every named/prefix subscriber registered through `Bus::subscribe`
//! — proven by
//! `tests/strand_supervision.rs::extraction_strand_serves_requests_and_publishes_to_shim_subscribers`.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use imperium_protocol::{BusEvent, EventId, Message};
use parking_lot::Mutex;
use spiderweb::{BusHandle, Socket, Strand, StrandError, StrandSpec};
use uuid::Uuid;

use crate::extractor::ExtractionLoop;
use crate::topics;

/// Strand name. Fixed, `&'static str` (Spiderweb requires it), and equal to the
/// subsystem name `init` announces in its `net.signatures.ready` message, so one
/// identifier works in the topic table, the kernel log, and the spider log.
pub const NAME: &str = "imperium-net-signatures";

/// Environment variable that arms a deliberate fault, for supervision drills:
/// `IMPERIUM_SIGNATURES_CRASH_AFTER_REQUESTS=<n>` makes every strand instance
/// return `StrandError::Crashed` once it has **handled** `n` extraction
/// requests.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. It exists so the restart/quarantine path can be exercised
/// end-to-end against the real strand instead of a stand-in, and so an operator
/// can drill the supervisor on a live node.
pub const CRASH_AFTER_REQUESTS_ENV: &str = "IMPERIUM_SIGNATURES_CRASH_AFTER_REQUESTS";

/// How an extraction strand instance should fault, for drills and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Handle requests normally. The production default.
    #[default]
    None,
    /// Deliberately crash after handling `n` requests. The count is per strand
    /// *instance*, so a restarted instance crashes again after its own `n`th
    /// request — which is what lets a drill drive the full
    /// crash → restart ×3 → quarantine sequence.
    ///
    /// Only requests that pass the [`SeenRequests`] guard are counted: a
    /// deduplicated replay is not work, so it neither advances the drill nor
    /// re-runs the handler.
    CrashAfterRequests(u32),
}

impl FaultPolicy {
    /// Read the policy from [`CRASH_AFTER_REQUESTS_ENV`]. Absent/zero/invalid
    /// values all mean [`FaultPolicy::None`]: a typo must never crash a node.
    pub fn from_env() -> Self {
        Self::parse(std::env::var(CRASH_AFTER_REQUESTS_ENV).ok().as_deref())
    }

    /// The parsing half of [`FaultPolicy::from_env`], without process-env
    /// access so it can be tested without racing other tests.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim).and_then(|v| v.parse::<u32>().ok()) {
            Some(n) if n > 0 => FaultPolicy::CrashAfterRequests(n),
            _ => FaultPolicy::None,
        }
    }

    /// Whether this policy injects a fault (used to warn loudly at boot).
    pub fn is_injected(&self) -> bool {
        !matches!(self, FaultPolicy::None)
    }

    /// The crash reason for an instance that has just handled `requests_seen`
    /// requests, or `None` while this instance should keep running.
    fn tripped(&self, requests_seen: u32) -> Option<String> {
        match self {
            FaultPolicy::None => None,
            FaultPolicy::CrashAfterRequests(n) if requests_seen >= *n => Some(format!(
                "injected fault: crashed after {requests_seen} request(s) \
                 ({CRASH_AFTER_REQUESTS_ENV} = {n})"
            )),
            FaultPolicy::CrashAfterRequests(_) => None,
        }
    }
}

/// The bounded record of extraction-request ids this subsystem has already
/// handled, shared by every generation through the strand factory.
///
/// Bounded on purpose: a node runs for months and an unbounded `HashSet` would
/// be a leak. The kernel replays at most 32 messages per `TypeId` to a late
/// subscriber, so a ring of [`SeenRequests::DEFAULT_CAPACITY`] ids is far more
/// history than a replay can ever reach.
pub struct SeenRequests {
    seen: Mutex<Seen>,
    capacity: usize,
}

struct Seen {
    /// Insertion order, so the oldest id can be evicted with the set.
    order: VecDeque<Uuid>,
    /// Membership, so the guard is O(1) rather than O(ring length).
    members: HashSet<Uuid>,
}

impl Default for SeenRequests {
    fn default() -> Self {
        Self::new()
    }
}

impl SeenRequests {
    /// How many handled ids are remembered. Comfortably above the kernel's
    /// 32-message-per-`TypeId` replay tail.
    pub const DEFAULT_CAPACITY: usize = 1024;

    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(Seen {
                order: VecDeque::new(),
                members: HashSet::new(),
            }),
            capacity: capacity.max(1),
        }
    }

    /// Record `id` as handled, returning `true` if it had **already** been
    /// handled. Marking and testing in one call is what makes the guard
    /// race-free and impossible to forget: a caller cannot check without
    /// recording, and a replay therefore can never run the handler twice.
    pub fn seen_or_record(&self, id: &EventId) -> bool {
        let mut seen = self.seen.lock();
        if seen.members.contains(&id.0) {
            return true;
        }
        if seen.order.len() >= self.capacity {
            if let Some(oldest) = seen.order.pop_front() {
                seen.members.remove(&oldest);
            }
        }
        seen.order.push_back(id.0);
        seen.members.insert(id.0);
        false
    }

    /// How many ids are currently remembered (never more than the capacity).
    pub fn len(&self) -> usize {
        self.seen.lock().order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The extraction request loop as a strand.
///
/// Owns its state: the loop and the dedupe record are shared (`Arc`) so every
/// restarted generation resumes the same durable state, the fault policy is
/// `Copy`, and the request counter is per instance. Nothing is borrowed from
/// outside, which is what makes a strand restartable — the kernel's factory
/// call produces a fresh, independent instance.
pub struct ExtractionStrand {
    extraction: Arc<ExtractionLoop>,
    /// Durable: shared with every generation, so a replayed request is still
    /// recognised after a restart.
    seen: Arc<SeenRequests>,
    faults: FaultPolicy,
    /// Requests this *instance* has handled. Per-instance by construction, so a
    /// restart resets it.
    requests_seen: u32,
}

impl ExtractionStrand {
    pub fn new(
        extraction: Arc<ExtractionLoop>,
        seen: Arc<SeenRequests>,
        faults: FaultPolicy,
    ) -> Self {
        Self {
            extraction,
            seen,
            faults,
            requests_seen: 0,
        }
    }

    /// The restartable spec for this strand, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec).
    ///
    /// The factory captures an `Arc<ExtractionLoop>` clone and an
    /// `Arc<SeenRequests>` clone, so every restarted instance extracts against
    /// the same store, memory log, staging area and dedupe record — restart
    /// resumes the subsystem rather than reloading a parallel one.
    pub fn spec(extraction: Arc<ExtractionLoop>, faults: FaultPolicy) -> StrandSpec {
        Self::spec_with_dedupe(extraction, Arc::new(SeenRequests::new()), faults)
    }

    /// [`ExtractionStrand::spec`] with an explicit dedupe record, for a caller
    /// (or test) that wants to hold — and inspect — the same one the strand
    /// uses.
    pub fn spec_with_dedupe(
        extraction: Arc<ExtractionLoop>,
        seen: Arc<SeenRequests>,
        faults: FaultPolicy,
    ) -> StrandSpec {
        StrandSpec::new(NAME, move || -> Box<dyn Strand> {
            Box::new(ExtractionStrand::new(
                Arc::clone(&extraction),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for ExtractionStrand {
    fn name(&self) -> &str {
        NAME
    }

    fn inputs(&self) -> &[Socket] {
        // The socket name is documentation for the lifecycle event and the web
        // graph; routing is by `BusEvent`'s `TypeId` (see the module docs), so
        // the prefix test in `run` is what actually selects this loop's input.
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::REQUEST)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        // The two topics this strand's handler publishes directly. It also
        // causes `net.signatures.candidate`, but that one is published by
        // `StagingArea::submit` (see the module docs).
        const SOCKS: [Socket; 2] = [
            Socket::new::<BusEvent>(topics::CANDIDATE_PENDING),
            Socket::new::<BusEvent>(topics::EXTRACTION_FAILED),
        ];
        &SOCKS
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick
        // and let the worker join (draining instead would delay shutdown —
        // and this strand has no unbounded blocking section to bound).
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on. Draining by socket name instead (`recv::<BusEvent>(name)`)
        // would keep every non-matching carrier in the inbox forever, growing it
        // one event per bus publish — the inbox is a mailbox, not a filter.
        //
        // `?` is infallible here in practice: the inbox only ever contains
        // payloads whose `TypeId` matched this strand's declared input, so the
        // only error variant (`TypeMismatch`) cannot fire. A genuine kernel
        // fault still surfaces as `Crashed` and is supervised.
        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            // The prefix filter the kernel used to apply for the old
            // `bus.subscribe(topics::REQUEST)` subscription.
            if !event.topic.starts_with(topics::REQUEST) {
                continue;
            }
            let Message::ExtractionRequest(ref request) = event.message else {
                // A different payload on the request topic is not ours to
                // guess at; ignore it without polluting the dedupe record.
                continue;
            };

            // Replay guard. A restarted generation is a late subscriber, so the
            // kernel hands it the pending tail (up to 32 messages per type) —
            // including requests this subsystem already handled. Staging a
            // candidate is not idempotent, so a replay is dropped here.
            if self.seen.seen_or_record(&event.id) {
                tracing::debug!(
                    event_id = %event.id.0,
                    "replayed extraction request ignored (already handled)"
                );
                continue;
            }

            // The old `tokio` loop body, verbatim: same handler, same shared
            // state, same publishes (see the module docs on the output path).
            self.extraction.handle_extraction_request(
                &request.triggering_event_ids,
                &request.reason,
                &request.requested_by,
            );

            self.requests_seen = self.requests_seen.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.requests_seen) {
                // Diagnostic-only path; see `FaultPolicy`. Returning `Crashed`
                // (rather than panicking) keeps this tick's output: the kernel
                // flushes the outbox of a tick that returned.
                return Err(StrandError::Crashed(reason));
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick
        // (the worker paces them at 10ms), which is this strand's idle loop.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_policy_is_none_unless_a_drill_is_armed() {
        assert_eq!(FaultPolicy::parse(None), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("0")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("not a number")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("-3")), FaultPolicy::None);
        assert_eq!(
            FaultPolicy::parse(Some(" 2 ")),
            FaultPolicy::CrashAfterRequests(2)
        );
        assert!(!FaultPolicy::None.is_injected());
        assert!(FaultPolicy::CrashAfterRequests(1).is_injected());
    }

    #[test]
    fn fault_trips_on_the_nth_handled_request_only() {
        let policy = FaultPolicy::CrashAfterRequests(2);
        assert!(policy.tripped(0).is_none());
        assert!(policy.tripped(1).is_none());
        let reason = policy.tripped(2).expect("the second request trips it");
        assert!(reason.contains("injected fault"));
        assert!(reason.contains("2 request(s)"));
        assert!(FaultPolicy::None.tripped(1_000).is_none());
    }

    #[test]
    fn dedupe_recognises_a_replay_and_is_bounded() {
        let seen = SeenRequests::with_capacity(2);
        let first = EventId::new();
        let second = EventId::new();
        let third = EventId::new();

        assert!(!seen.seen_or_record(&first), "first sight");
        assert!(!seen.seen_or_record(&second), "second sight");
        assert!(!seen.seen_or_record(&third), "third sight evicts the first");
        assert_eq!(seen.len(), 2, "the record is bounded by its capacity");
        assert!(!seen.is_empty());

        // A replay of a handled request is refused...
        assert!(seen.seen_or_record(&third), "a replay must be refused");
        assert!(seen.seen_or_record(&second), "a replay must be refused");
        // ...while an evicted id reads as unseen: the ring is history, not a
        // proof, and the kernel's 32-message replay tail is far below it.
        assert!(!seen.seen_or_record(&first), "evicted = unseen");
    }
}
