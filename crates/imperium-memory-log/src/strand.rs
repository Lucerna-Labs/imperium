//! The memory log's two recv loops as supervised Spiderweb **strands**.
//!
//! Before this module, `MemoryLog` held two `tokio::spawn`ed tasks: one on
//! `net.strainer.rejection` appending [`Message::StrainerRejection`], and one on
//! the `net.transport.` prefix appending [`Message::ProtocolEvt`]. Neither was
//! visible to the spider: a panic killed the task silently and the log simply
//! stopped recording. They are now [`MemoryLogStrand`]s, queued as **specs** by
//! [`register_strands`](crate::register_strands) and installed by the kernel's
//! run loop, so a crash becomes a
//! [`LifecycleEvent::Crashed`](spiderweb::LifecycleEvent::Crashed), is restarted
//! up to three times, and the fourth crash is a quarantine. The pilot for this
//! conversion is `imperium-net-lightcone`, and this module follows it.
//!
//! # Two lanes, two strands — and why not one
//!
//! The file had two standing consumer loops, so it gets two strands
//! ([`Lane::StrainerRejections`], [`Lane::ProtocolEvents`]). A single strand
//! draining both topics was rejected for three reasons:
//!
//! 1. **Behaviour preservation — the log's ordering semantics.** The two loops
//!    were *independent* consumers: each had its own subscription, its own
//!    task, and there was **no defined relative order** between the two streams
//!    (two tasks racing for the runtime). Both appended to the same
//!    [`MemoryLog`], so the interleaving of their sequence numbers was already
//!    unspecified — and it stays unspecified here, because two strands drain
//!    two independent inboxes on two independent worker threads, exactly like
//!    the two tasks. One strand would have serialised them by arrival order in
//!    a *single* inbox (up to 32 deep, the kernel's replay tail), **introducing**
//!    a cross-stream ordering relation the system never had. What *is* pinned,
//!    then and now: within one stream, arrival order is preserved (the old
//!    `mpsc` subscription was FIFO; a strand inbox is FIFO and
//!    [`run`](Strand::run) drains it in order and appends each event before
//!    looking at the next), and every accepted event is appended exactly once.
//! 2. **Failure-domain isolation.** `net.transport.` carries the failover /
//!    emergency-shutdown record — the stream an operator reads to learn what
//!    the node did — while `net.strainer.rejection` is the noisy detector
//!    stream. Supervision exists to bound blast radius: a crash, a restart or a
//!    replayed tail must be confined to one lane. With two strands one lane can
//!    be quarantined while the other keeps recording, which
//!    `quarantined_rejection_lane_does_not_stop_the_transport_lane` proves end
//!    to end.
//! 3. **Restart accounting.** A restarted strand is replayed up to 32 pending
//!    messages *per `TypeId`*; two strands replay into their own (durable)
//!    seen-sets and their own crash counters, so restart accounting stays
//!    per-loop, exactly like the per-task accounting it replaces. One strand
//!    would need one record conflating both lanes' ids.
//!
//! # What changed deliberately (and nothing else)
//!
//! * **The prefix filter moved into the strand** (recipe §5.2). Spiderweb routes
//!   strand deliveries by `TypeId`, not by socket name, so every `BusEvent` on
//!   the bus reaches a strand that declares a `BusEvent` input. The old
//!   `bus.subscribe("net.strainer.rejection")` /
//!   `bus.subscribe("net.transport.")` prefix test is now
//!   [`Lane::matches_topic`] — the same comparison on the other side of the bus.
//!   The old loop's `if let Message::StrainerRejection(..)` /
//!   `if let Message::ProtocolEvt(..)` gate is preserved verbatim as
//!   [`Lane::accepts`].
//! * **A replay guard on `BusEvent.id`** (recipe §5.4). A restarted generation
//!   is a late subscriber and *is* replayed the kernel's pending tail — of
//!   messages the *previous* generation already appended. Appending them again
//!   would corrupt the log: a duplicate [`LogEntry`](crate::LogEntry) with a
//!   fresh, higher sequence number claims a second occurrence of an event that
//!   happened once, which is exactly what a forensic record must never do, and
//!   every consumer of the log (`MemoryLog::entries_since`,
//!   `get_by_event_id`, the extraction loop and the projection) would see the
//!   double. So each lane keeps a [`SeenIds`] history, **durable** — shared by
//!   every generation of a lane through the spec's factory — because the replay
//!   it must defeat is aimed at the new generation, whose own record would
//!   otherwise be empty. Without a crash the record changes nothing: every
//!   publish mints a fresh `EventId`, so each real event is still appended
//!   exactly once.
//! * **The `BusError::Lagged` arm is gone.** The old loops handled a lagging
//!   bounded subscription channel (`DEFAULT_CAPACITY` 1024) by logging a warning
//!   and continuing. A strand receives on the kernel's mailbox, which is
//!   **unbounded** — the only send failure is a disconnected receiver, which is
//!   the crash/restart case and is handled by supervision, not by the loop. So
//!   there is no lag to warn about and no arm to keep. This is a strengthening
//!   (a busy bus can no longer drop log records for lag) bought with the
//!   supervision trade: while a strand is down its events are not appended at
//!   all (the kernel's 32-deep tail is what a restart recovers).
//!
//! Nothing else moves: the log, its sequence counter, its capacity and its
//! eviction policy are untouched (`Arc` moved into the factory, not
//! restructured), and the strand publishes nothing, so there is no output topic
//! and no `outputs()` socket to declare.
//!
//! # Registration order (recipe §5.1, §5.9)
//!
//! Specs are **queued, not started**: they are installed by
//! `Bus::engage_supervision()`. Queue them first, then engage — exactly what
//! [`register_strands`](crate::register_strands) documents:
//!
//! ```text
//! imperium_memory_log::register_strands(&bus, &memory_log)?;
//! let supervision = bus.engage_supervision();
//! // … on the way out:
//! supervision.shutdown();
//! ```

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use imperium_protocol::{BusEvent, Message};
use parking_lot::Mutex;
use spiderweb::{BusHandle, Socket, Strand, StrandError, StrandSpec};

use crate::{topics, MemoryLog};

/// Strand name of the rejection lane (`net.strainer.rejection`).
///
/// Fixed and `&'static str` (Spiderweb requires it), and one name works in the
/// topic table, the kernel's log and the spider's log — the pilot's convention.
/// The two lane names must differ: the kernel **panics** on a strand-name
/// collision (recipe §5.8).
pub const REJECTIONS_STRAND: &str = "imperium-memory-log-rejections";

/// Strand name of the protocol-event lane (`net.transport.`).
pub const PROTOCOL_EVENTS_STRAND: &str = "imperium-memory-log-protocol-events";

/// Environment variable that arms a deliberate fault, for supervision drills:
/// `IMPERIUM_MEMORY_LOG_CRASH_AFTER_EVENTS=<n>` makes every strand instance
/// return [`StrandError::Crashed`] once it has *appended* `n` events.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. It exists so the restart/quarantine path can be exercised
/// end-to-end against the real strands instead of a stand-in, and so an
/// operator can drill the supervisor on a live node. The policy is read once by
/// [`register_strands`](crate::register_strands) and applied to **both** lanes,
/// so an armed drill crashes both (arm one lane at a time with
/// [`MemoryLogStrand::spec`] where that matters, as the tests do).
pub const CRASH_AFTER_EVENTS_ENV: &str = "IMPERIUM_MEMORY_LOG_CRASH_AFTER_EVENTS";

/// Which of the memory log's two recv loops a strand is.
///
/// The lane is what turns one strand type into two independent strands: it
/// carries the strand name, the topic filter (the old `bus.subscribe(..)`), the
/// message-variant gate (the old `if let Message::X`), and the declared input
/// socket. Everything lane-independent lives in [`MemoryLogStrand`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// `net.strainer.rejection` → [`Message::StrainerRejection`].
    StrainerRejections,
    /// `net.transport.` → [`Message::ProtocolEvt`].
    ProtocolEvents,
}

impl Lane {
    /// Both lanes, in registration order.
    pub const ALL: [Lane; 2] = [Lane::StrainerRejections, Lane::ProtocolEvents];

    /// The strand name this lane registers under.
    pub const fn strand_name(self) -> &'static str {
        match self {
            Lane::StrainerRejections => REJECTIONS_STRAND,
            Lane::ProtocolEvents => PROTOCOL_EVENTS_STRAND,
        }
    }

    /// The topic prefix this lane consumes — the old named-subscription prefix,
    /// verbatim (matching is `starts_with`, as it always was).
    pub const fn topic_prefix(self) -> &'static str {
        match self {
            Lane::StrainerRejections => topics::STRAINER_REJECTION,
            Lane::ProtocolEvents => topics::TRANSPORT_PREFIX,
        }
    }

    /// The declared input socket. Routing is by `BusEvent`'s `TypeId`; the name
    /// is what the lifecycle event and the web graph show, so it repeats the old
    /// subscription string exactly.
    pub fn input_sockets(self) -> &'static [Socket] {
        match self {
            Lane::StrainerRejections => {
                const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::STRAINER_REJECTION)];
                &SOCKS
            }
            Lane::ProtocolEvents => {
                const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::TRANSPORT_PREFIX)];
                &SOCKS
            }
        }
    }

    /// The old kernel-side `bus.subscribe(prefix)` test, moved into the
    /// consumer (recipe §5.2). `starts_with`, exactly as the shim compared it.
    pub fn matches_topic(self, topic: &str) -> bool {
        topic.starts_with(self.topic_prefix())
    }

    /// The old loop's message-variant gate: a `net.strainer.ready`, a
    /// `net.transport.decision` or any other payload on a matching topic was
    /// ignored then too.
    pub fn accepts(self, message: &Message) -> bool {
        match self {
            Lane::StrainerRejections => matches!(message, Message::StrainerRejection(_)),
            Lane::ProtocolEvents => matches!(message, Message::ProtocolEvt(_)),
        }
    }

    /// Human-readable lane name, for log lines.
    pub const fn description(self) -> &'static str {
        match self {
            Lane::StrainerRejections => "strainer rejection",
            Lane::ProtocolEvents => "protocol event",
        }
    }
}

/// How a memory-log strand instance should fault, for drills and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Append normally. The production default.
    #[default]
    None,
    /// Deliberately crash after appending `n` events. The count is per strand
    /// *instance*, so a restarted instance crashes again after its own `n`th
    /// event — which is what lets a drill drive the full
    /// crash → restart ×3 → quarantine sequence.
    CrashAfterEvents(u32),
}

impl FaultPolicy {
    /// Read the policy from [`CRASH_AFTER_EVENTS_ENV`]. Absent/zero/invalid
    /// values all mean [`FaultPolicy::None`]: a typo must never crash a node.
    pub fn from_env() -> Self {
        Self::parse(std::env::var(CRASH_AFTER_EVENTS_ENV).ok().as_deref())
    }

    /// The parsing half of [`FaultPolicy::from_env`], without process-env
    /// access so it can be tested without racing other tests.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim).and_then(|v| v.parse::<u32>().ok()) {
            Some(n) if n > 0 => FaultPolicy::CrashAfterEvents(n),
            _ => FaultPolicy::None,
        }
    }

    /// Whether this policy injects a fault (used to warn loudly at boot).
    pub fn is_injected(&self) -> bool {
        !matches!(self, FaultPolicy::None)
    }

    /// The crash reason for an instance that has just appended `appended`
    /// events, or `None` while this instance should keep running.
    fn tripped(&self, appended: u32) -> Option<String> {
        match self {
            FaultPolicy::None => None,
            FaultPolicy::CrashAfterEvents(n) if appended >= *n => Some(format!(
                "injected fault: crashed after {appended} appended event(s) \
                 ({CRASH_AFTER_EVENTS_ENV} = {n})"
            )),
            FaultPolicy::CrashAfterEvents(_) => None,
        }
    }
}

/// How many recent `BusEvent.id`s one lane remembers.
///
/// The kernel's replay tail is 32 messages per `TypeId` (recipe §5.4) — and all
/// `BusEvent`s share one `TypeId`, so a lane's own messages are separated in
/// that tail by events of any other topic. 256 is eight times the tail: a
/// restart cannot out-run the guard even if a burst of unrelated `BusEvent`s
/// sits between the lane's messages.
const SEEN_CAPACITY: usize = 256;

/// Durable replay guard: the ids one lane has already appended.
///
/// Deliberately **not** per generation. A restarted strand is a late subscriber
/// and the kernel replays it the recent tail — of messages the *previous*
/// generation already appended. A per-generation record would be empty at
/// exactly the moment it is needed, and appending a replayed event would
/// corrupt the log (see the module docs), so the record is shared by every
/// generation of a lane through the spec's factory: durable state, shared
/// through the `Arc`, exactly like the log itself (recipe §3.2).
///
/// Bounded and FIFO-evicted: memory stays flat however long a node runs, and
/// only ids older than `SEEN_CAPACITY` further events are forgotten — far
/// outside the replay window a restart can present.
pub struct SeenIds {
    inner: Mutex<SeenInner>,
}

#[derive(Default)]
struct SeenInner {
    /// Insertion order, for FIFO eviction once the bound is reached.
    order: VecDeque<u128>,
    set: HashSet<u128>,
}

impl SeenIds {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SeenInner::default()),
        }
    }

    /// `true` the first time this event id is offered, `false` for a replay of
    /// one already appended by this lane.
    pub fn first_sight(&self, id: u128) -> bool {
        let mut inner = self.inner.lock();
        if inner.set.contains(&id) {
            return false;
        }
        if inner.order.len() >= SEEN_CAPACITY {
            if let Some(oldest) = inner.order.pop_front() {
                inner.set.remove(&oldest);
            }
        }
        inner.set.insert(id);
        inner.order.push_back(id);
        true
    }

    /// How many ids are currently remembered.
    pub fn len(&self) -> usize {
        self.inner.lock().order.len()
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SeenIds {
    fn default() -> Self {
        Self::new()
    }
}

/// One memory-log lane as a supervised strand.
///
/// Owns its state: the [`MemoryLog`] is shared with whatever built it (`Arc`, so
/// the appended entries — and the sequence numbers — are visible to every other
/// consumer of the log, exactly as before), the seen-set is shared per *lane*
/// (so a restart still recognises the replay), and the fault policy and the
/// appended counter are per instance (so a restart resets the drill). Nothing is
/// borrowed from outside, which is what makes the strand restartable: the
/// kernel's factory call produces a fresh, independent instance.
pub struct MemoryLogStrand {
    lane: Lane,
    log: Arc<MemoryLog>,
    seen: Arc<SeenIds>,
    faults: FaultPolicy,
    /// Events this *instance* has appended. Per-instance by construction, so a
    /// restart resets it.
    appended: u32,
}

impl MemoryLogStrand {
    pub fn new(lane: Lane, log: Arc<MemoryLog>, seen: Arc<SeenIds>, faults: FaultPolicy) -> Self {
        Self {
            lane,
            log,
            seen,
            faults,
            appended: 0,
        }
    }

    /// The restartable spec for one lane, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec).
    ///
    /// The factory captures `Arc`s of the log *and* of the lane's [`SeenIds`],
    /// so every restarted instance appends to the same log (the one the
    /// composition root built and every other consumer reads) and still
    /// recognises the kernel's replay — restart resumes the lane rather than
    /// starting a fresh, amnesiac one.
    pub fn spec(lane: Lane, log: Arc<MemoryLog>, faults: FaultPolicy) -> StrandSpec {
        let seen = Arc::new(SeenIds::new());
        StrandSpec::new(lane.strand_name(), move || -> Box<dyn Strand> {
            Box::new(MemoryLogStrand::new(
                lane,
                Arc::clone(&log),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for MemoryLogStrand {
    fn name(&self) -> &str {
        self.lane.strand_name()
    }

    fn inputs(&self) -> &[Socket] {
        // The socket name is documentation for the lifecycle event and the web
        // graph; routing is by `BusEvent`'s `TypeId` (see the module docs), so
        // this strand feels every `BusEvent` published anywhere and filters
        // below.
        self.lane.input_sockets()
    }

    fn outputs(&self) -> &[Socket] {
        // The log publishes nothing: its effect is the appended entry, which
        // every other consumer already reaches through the shared `Arc`.
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick
        // and let the worker join (recipe §2). Nothing in this `run` blocks —
        // `MemoryLog::append` takes two short-held `parking_lot` locks and
        // returns — so there is no bounded-blocking section to shorten.
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on. Draining by socket name instead (`recv::<BusEvent>(name)`)
        // would leave every non-matching carrier in the inbox forever, growing
        // it one event per unrelated publish — the inbox is a mailbox, not a
        // filter (recipe §5.3). `?` is infallible in practice: the inbox only
        // ever holds payloads whose `TypeId` matched this strand's declared
        // input, and a genuine kernel fault still surfaces as `Crashed`.
        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            // The prefix filter the kernel used to apply for the old
            // `bus.subscribe(..)` (recipe §5.2).
            if !self.lane.matches_topic(&event.topic) {
                continue;
            }
            // The old loop's message-variant gate.
            if !self.lane.accepts(&event.message) {
                continue;
            }
            // Replay guard (recipe §5.4): a restarted generation is replayed
            // the recent tail, which the previous generation already appended.
            // Appending it again would put a second, higher-sequence entry in
            // the log for one occurrence (see `SeenIds`).
            if !self.seen.first_sight(event.id.0.as_u128()) {
                tracing::debug!(
                    event_id = ?event.id,
                    lane = self.lane.description(),
                    "skipping a replayed event already in the memory log"
                );
                continue;
            }

            // The old loop body, verbatim: append, and nothing else. The return
            // value (the assigned sequence number) was ignored then and is
            // ignored now; the entry is what other consumers read.
            self.log.append(event);

            self.appended = self.appended.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.appended) {
                // Diagnostic-only path; see `FaultPolicy`. The append above has
                // already happened and is visible to every consumer of the log,
                // which is the whole point of the shape of this drill: a crash
                // must not cost a record that was already written.
                return Err(StrandError::Crashed(reason));
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick
        // (the worker paces them at 10 ms), which is this strand's idle loop.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use imperium_protocol::{ProtocolEvent, ProtocolEventKind, ProtocolRole, ProtocolStatus};

    fn protocol_event() -> Message {
        Message::ProtocolEvt(ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Running,
            event: ProtocolEventKind::Started,
            timestamp: Utc::now(),
        })
    }

    /// A fault must never be armable by a typo — absent/zero/unparsable all mean
    /// `None`. `parse` is the testable half of `from_env` (recipe §6c).
    #[test]
    fn fault_policy_parser_never_arms_on_a_bad_value() {
        assert_eq!(FaultPolicy::parse(None), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("   ")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("0")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("events")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("-1")), FaultPolicy::None);
        assert_eq!(
            FaultPolicy::parse(Some(" 3 ")),
            FaultPolicy::CrashAfterEvents(3)
        );
        assert!(FaultPolicy::parse(Some("3")).is_injected());
        assert!(!FaultPolicy::None.is_injected());
    }

    #[test]
    fn fault_policy_trips_exactly_at_its_threshold() {
        let policy = FaultPolicy::CrashAfterEvents(2);
        assert_eq!(policy.tripped(0), None);
        assert_eq!(policy.tripped(1), None);
        let reason = policy.tripped(2).expect("trips at the threshold");
        assert!(
            reason.contains("injected fault") && reason.contains(CRASH_AFTER_EVENTS_ENV),
            "the reason must name the drill that caused it: {reason}"
        );
        assert_eq!(FaultPolicy::None.tripped(99), None);
    }

    /// The replay guard: the first sighting is accepted, every repeat is not —
    /// and the memory stays bounded however long the lane runs.
    #[test]
    fn seen_ids_accept_once_then_treat_repeats_as_replays() {
        let seen = SeenIds::new();
        assert!(seen.is_empty());
        assert!(seen.first_sight(7));
        assert!(!seen.first_sight(7), "a replayed id must be refused");
        assert!(seen.first_sight(8));
        assert_eq!(seen.len(), 2);

        for id in 0..(SEEN_CAPACITY as u128 * 2) {
            seen.first_sight(id);
        }
        assert_eq!(seen.len(), SEEN_CAPACITY, "the history must stay bounded");
        assert!(
            seen.first_sight(1_000_000),
            "an id never seen before is still accepted"
        );
        // The capacity must stay clear of the kernel's 32-deep replay tail
        // (recipe §5.4): a restart cannot out-run the guard.
        assert!(SEEN_CAPACITY > 32);
    }

    /// The lane filter is the old `bus.subscribe(prefix)` plus the old
    /// `if let Message::X` gate, and nothing else.
    #[test]
    fn lanes_filter_topics_and_variants_like_the_old_subscriptions() {
        assert!(Lane::StrainerRejections.matches_topic("net.strainer.rejection"));
        assert!(!Lane::StrainerRejections.matches_topic("net.transport.event"));
        assert!(Lane::ProtocolEvents.matches_topic("net.transport.event"));
        assert!(Lane::ProtocolEvents.matches_topic("net.transport.decision"));
        assert!(!Lane::ProtocolEvents.matches_topic("net.strainer.rejection"));

        assert!(
            Lane::StrainerRejections.accepts(&Message::StrainerRejection(
                imperium_protocol::StrainerRejection {
                    strainer_id: "timing".into(),
                    stack_id: "auth_stack".into(),
                    shape_failed: "too slow".into(),
                    source_identifier: None,
                    timestamp: Utc::now(),
                }
            ))
        );
        // A protocol event on the rejection prefix was ignored then too.
        assert!(!Lane::StrainerRejections.accepts(&protocol_event()));
        assert!(Lane::ProtocolEvents.accepts(&protocol_event()));
        // `net.transport.ready` matched the old prefix and was ignored for the
        // same reason: it is not a protocol event.
        assert!(!Lane::ProtocolEvents.accepts(&Message::SubsystemReady {
            name: "imperium-net-transport".into(),
        }));

        assert_eq!(Lane::ALL.len(), 2);
        assert_eq!(Lane::ALL[0].strand_name(), REJECTIONS_STRAND);
        assert_eq!(Lane::ALL[1].strand_name(), PROTOCOL_EVENTS_STRAND);
        assert_ne!(
            REJECTIONS_STRAND, PROTOCOL_EVENTS_STRAND,
            "the kernel panics on a duplicate strand name"
        );
        assert_eq!(
            Lane::StrainerRejections.topic_prefix(),
            topics::STRAINER_REJECTION
        );
        assert_eq!(
            Lane::ProtocolEvents.topic_prefix(),
            topics::TRANSPORT_PREFIX
        );
        assert_eq!(Lane::ALL[0].input_sockets().len(), 1);
        assert_eq!(Lane::ALL[1].input_sockets().len(), 1);
    }
}
