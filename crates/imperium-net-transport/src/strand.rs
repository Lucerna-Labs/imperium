//! The transport orchestrator's two recv loops as supervised Spiderweb
//! **strands**.
//!
//! Before this module, `orchestrator.rs` held two `tokio::spawn`ed tasks:
//! `subscribe_threat_assessments` (a subscription on `net.sensors.`) and
//! `subscribe_protocol_events` (a subscription on `net.transport.event`), each
//! driving one half of the failover/emergency-shutdown brain. Neither was
//! visible to the spider: a panic killed the task silently. They are now
//! [`OrchestratorStrand`]s, registered as **specs** through
//! [`Orchestrator::queue_strands`](crate::Orchestrator::queue_strands) (or the
//! crate-level [`register_strands`]) and installed by
//! `Bus::engage_supervision()`, so a crash becomes a
//! [`LifecycleEvent::Crashed`](spiderweb::LifecycleEvent::Crashed),
//! is restarted up to three times, and the fourth crash is a quarantine. See
//! the pilot (`imperium-net-lightcone`) for the general recipe; this
//! module follows it, and §6 of that document is the shape of the tests in
//! `tests/orchestrator_supervision.rs`.
//!
//! # Two lanes, two strands — and why not one
//!
//! The file had two standing consumer loops, so it gets two strands
//! ([`Lane::ProtocolEvents`], [`Lane::ThreatAssessments`]). A single strand
//! draining both topics was rejected for three reasons:
//!
//! 1. **Behaviour preservation.** The two loops were *independent* consumers:
//!    each had its own subscription, its own task, and no relative ordering
//!    between the two streams (two tasks racing for the runtime). One strand
//!    would serialise them — a burst of sensor assessments would sit in front
//!    of a protocol event in the same inbox, up to 32 deep — *introducing* an
//!    ordering relationship the system never had. The recipe's rule is that
//!    only the prefix filter moves and only the pending-tail replay is added;
//!    a new cross-stream ordering is neither.
//! 2. **Failure-domain isolation.** `net.transport.event` is the failover /
//!    emergency-shutdown path; `net.sensors.` is the noisiest input on the
//!    bus (three sensor families publishing on independent schedules) and the
//!    most complex handler (windowed fusion, toolkit requests, strainer
//!    routing). Supervision exists to bound blast radius: a crash, a restart,
//!    or a replayed tail must be confined to one lane. With two strands, the
//!    threat lane can be quarantined while the failover lane keeps serving —
//!    which `crashed_threat_lane_is_quarantined_while_the_failover_lane_serves`
//!    proves end to end.
//! 3. **Restart accounting.** A restarted strand is replayed up to 32 pending
//!    messages *per TypeId*; two strands replay into their own (durable) seen
//!    sets and their own crash counters, so restart accounting stays per-lane
//!    exactly like the per-task accounting it replaces.
//!
//! # What changed deliberately (and nothing else)
//!
//! * **The prefix filter moved into the strand** (recipe §5.2). Spiderweb
//!    routes strand deliveries by `TypeId`, not by socket name, so every
//!    `BusEvent` on the bus reaches a strand that declares a `BusEvent` input.
//!    The old `crate::test_supervision::subscribe_queue(&publisher, "net.sensors.", 64)` / `crate::test_supervision::subscribe_queue(&publisher, "net.transport.event", 64)`
//!    prefix test is now [`Lane::matches_topic`] — the same comparison on the
//!    other side of the bus. The old `if let Message::ThreatAssessment(..)` /
//!    `if let Message::ProtocolEvt(..)` gate is preserved verbatim as
//!    [`Lane::accepts`].
//! * **A replay guard on `BusEvent.id`** (recipe §5.4). The orchestrator's
//!    state machine is emphatically *not* idempotent: re-feeding a `Crashed`
//!    event that was already processed can move `Healing` → `Emergency` (a
//!    second "active crashed during healing" transition), and re-feeding a
//!    high-confidence threat can fail over twice. A restarted generation is a
//!    late subscriber and *is* replayed the recent tail, so each lane keeps a
//!    [`SeenIds`] history. The history is **durable** — shared by every
//!    generation of one lane through the spec's factory — because the replay
//!    it must defeat is aimed at the new generation, whose own history would
//!    otherwise be empty.
//!
//! Nothing else moves: the orchestrator's state, thresholds, windowed fusion
//! and construction-time constants are untouched (`Arc` moved into the
//! factory, not restructured), the effects are published through the
//! orchestrator's own `Arc<Bus>` exactly as before, and so they reach the same
//! topics and the same `Bus::subscribe` subscribers as the old task's
//! publishes.
//!
//! # Ordering: the property the integration tests pin
//!
//! `crates/imperium-runtime/tests/integration.rs` asserts that one crash
//! produces `PromoteStandby`, `QuarantineActive`, `BeginHealing` **in that
//! order**. Those three publishes happen inside one
//! [`handle_protocol_event`](crate::Orchestrator::handle_protocol_event) call,
//! on one thread, in source order — the delivery path (the shim's `publish`,
//! which is inline) has not changed, and the strand does not reorder anything
//! inside a tick: it drains its inbox in arrival order and handles each event
//! to completion before the next. So the three decisions still arrive in order.
//! The only latency change is the worker's 10 ms tick before a drained event
//! is handled.
//!
//! # Registration order (recipe §5.1, §5.9)
//!
//! Specs are **queued, not started**: they are installed by
//! `Bus::engage_supervision()`. Queue them first, then engage — exactly what
//! [`register_strands`] documents:
//!
//! ```ignore
//! let _orchestrator = imperium_net_transport::register_strands(&bus)?;
//! let supervision = bus.engage_supervision();
//! // … on the way out:
//! supervision.shutdown();
//! ```
//!
//! # The hardening lane
//!
//! The orchestrator's two lanes were not the crate's only standing recv loop.
//! `hardening.rs` held a third one — `HardeningController::subscribe_hardening_profiles`,
//! the `net.transport.hardening.apply` → `HardeningController::apply` loop — and
//! it is converted here too, as the third strand of this module
//! ([`HardeningStrand`], name [`HARDENING_STRAND`]). It is a *separate* strand
//! rather than a third lane of [`OrchestratorStrand`] for the reasons §"Two
//! lanes, two strands" gives: it was an independent consumer with its own
//! subscription and no ordering relationship to either orchestrator lane, its
//! state is a different object, and its failure domain must be its own (a
//! quarantined hardening lane must not stop failover).
//!
//! It differs from the orchestrator's lanes in one respect worth naming:
//! [`HardeningController::apply`](crate::HardeningController::apply) is reached
//! through `Arc<HardeningController>`, which the composition root usually owns —
//! so the lane is queued by [`register_strands`] (which builds a controller if
//! the caller did not) *and* by the legacy shim, idempotently, first
//! registration winning. See [`queue_hardening`].

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, OnceLock, Weak};

use imperium_protocol::{BusEvent, Message, OrchestratorDecision};
use parking_lot::Mutex;
use spiderweb::{Bus, BusPublisher};
use spiderweb::{BusHandle, Socket, Strand, StrandError, StrandSpec};

use crate::hardening::HardeningController;
use crate::orchestrator::{Orchestrator, OrchestratorConfig, OrchestratorError};

/// Topic the protocol-event lane consumes. Also its `inputs()` socket name, so
/// the lifecycle event and the web graph name the same string the old
/// `crate::test_supervision::subscribe_queue(&publisher, "net.transport.event", 64)` matched.
pub const PROTOCOL_EVENT_TOPIC: &str = "net.transport.event";

/// Topic prefix the threat lane consumes — the old `crate::test_supervision::subscribe_queue(&publisher, "net.sensors.", 64)`.
pub const SENSOR_TOPIC_PREFIX: &str = "net.sensors.";

/// Where both lanes' decisions land (`emit_decision`). Declared by
/// `outputs()` for the lifecycle event and the web graph.
pub const DECISION_TOPIC: &str = "net.transport.decision";

/// Where the threat lane's toolkit requests land (`emit_tool_request`).
/// Declared by `outputs()`; the same reason as [`DECISION_TOPIC`].
pub const TOOLKIT_REQUEST_TOPIC: &str = "net.toolkit.request";

/// Topic the hardening lane consumes — the old
/// `crate::test_supervision::subscribe_queue(&publisher, "net.transport.hardening.apply", 64)`. Also its `inputs()` socket
/// name, so the lifecycle event and the web graph name the same string the old
/// subscription matched.
pub const HARDENING_APPLY_TOPIC: &str = "net.transport.hardening.apply";

/// Where the hardening lane's accept/reject outcomes land
/// (`HardeningController::emit_status`). Declared by `outputs()`.
pub const HARDENING_STATUS_TOPIC: &str = "net.transport.hardening.status";

/// Strand name of the hardening lane.
///
/// Fixed, `&'static str`, built from the crate's identifier plus the lane — the
/// same shape as [`PROTOCOL_EVENTS_STRAND`], and unique in the kernel (names are
/// a kernel-global resource and a collision is a panic, recipe §5.8).
pub const HARDENING_STRAND: &str = "imperium-net-transport-hardening";

/// Strand name of the failover lane (`net.transport.event`).
///
/// Fixed, `&'static str` (Spiderweb requires it), and built from the crate's
/// existing identifier (`imperium-net-transport`, the name the crate publishes
/// on `net.transport.ready`) plus the lane, so one name works in the kernel
/// log, the lifecycle events and the spider log (recipe §5.8).
pub const PROTOCOL_EVENTS_STRAND: &str = "imperium-net-transport-orchestrator";

/// Strand name of the threat lane (`net.sensors.`).
pub const THREAT_ASSESSMENTS_STRAND: &str = "imperium-net-transport-threats";

/// Environment variable that arms a deliberate fault for supervision drills:
/// `IMPERIUM_TRANSPORT_ORCHESTRATOR_CRASH_AFTER_MESSAGES=<n>` makes every
/// strand instance of both lanes return
/// [`StrandError::Crashed`] once it has handled `n` messages.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. Like the pilot's equivalent, it exists so the
/// restart/quarantine path can be drilled end-to-end against the real strands
/// instead of a stand-in.
pub const CRASH_AFTER_MESSAGES_ENV: &str = "IMPERIUM_TRANSPORT_ORCHESTRATOR_CRASH_AFTER_MESSAGES";

/// Which of the orchestrator's two recv loops a strand instance is.
///
/// The lane is what turns one strand type into two independent strands: it
/// names the strand, declares its input socket, filters the shared `BusEvent`
/// stream, and selects the orchestrator entry point. See the module docs for
/// why these are two strands and not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// `net.transport.event` → [`Orchestrator::handle_protocol_event`].
    ProtocolEvents,
    /// `net.sensors.` → [`Orchestrator::handle_threat_assessment`].
    ThreatAssessments,
}

impl Lane {
    /// Both lanes, in registration order.
    pub const ALL: [Lane; 2] = [Lane::ProtocolEvents, Lane::ThreatAssessments];

    /// The strand name this lane registers under.
    pub const fn strand_name(self) -> &'static str {
        match self {
            Lane::ProtocolEvents => PROTOCOL_EVENTS_STRAND,
            Lane::ThreatAssessments => THREAT_ASSESSMENTS_STRAND,
        }
    }

    /// The topic prefix this lane consumes (the old `crate::test_supervision::subscribe_queue(&publisher, prefix, 64)`).
    pub const fn topic_prefix(self) -> &'static str {
        match self {
            Lane::ProtocolEvents => PROTOCOL_EVENT_TOPIC,
            Lane::ThreatAssessments => SENSOR_TOPIC_PREFIX,
        }
    }

    /// The input socket name (documentation; routing is by `BusEvent`'s
    /// `TypeId` — the socket name is what the lifecycle event and the web graph
    /// display).
    const fn input_sockets(self) -> &'static [Socket] {
        const PROTOCOL_EVENTS: [Socket; 1] = [Socket::new::<BusEvent>(PROTOCOL_EVENT_TOPIC)];
        const THREAT_ASSESSMENTS: [Socket; 1] = [Socket::new::<BusEvent>(SENSOR_TOPIC_PREFIX)];
        match self {
            Lane::ProtocolEvents => &PROTOCOL_EVENTS,
            Lane::ThreatAssessments => &THREAT_ASSESSMENTS,
        }
    }

    /// Where this lane's effects land (documentation only, see [`DECISION_TOPIC`]).
    const fn output_sockets(self) -> &'static [Socket] {
        const DECISIONS: [Socket; 1] = [Socket::new::<BusEvent>(DECISION_TOPIC)];
        const TOOLKIT: [Socket; 1] = [Socket::new::<BusEvent>(TOOLKIT_REQUEST_TOPIC)];
        match self {
            Lane::ProtocolEvents => &DECISIONS,
            Lane::ThreatAssessments => &TOOLKIT,
        }
    }

    /// The old kernel-side prefix filter, moved into the consumer (recipe §5.2).
    fn matches_topic(self, topic: &str) -> bool {
        topic.starts_with(self.topic_prefix())
    }

    /// The old loop's `if let Message::X(..) = event.message` gate.
    fn accepts(self, message: &Message) -> bool {
        match self {
            Lane::ProtocolEvents => matches!(message, Message::ProtocolEvt(_)),
            Lane::ThreatAssessments => matches!(message, Message::ThreatAssessment(_)),
        }
    }

    /// The old loop's `if let Message::X(ref payload) = … { orch.handle_x(payload) }`
    /// body. Any other message variant on a matching topic is ignored, exactly
    /// as the old loop ignored it (`_ => {}`).
    fn handle(
        self,
        orchestrator: &Orchestrator,
        message: &Message,
    ) -> Result<Option<OrchestratorDecision>, OrchestratorError> {
        match (self, message) {
            (Lane::ProtocolEvents, Message::ProtocolEvt(event)) => {
                orchestrator.handle_protocol_event(event)
            }
            (Lane::ThreatAssessments, Message::ThreatAssessment(assessment)) => {
                orchestrator.handle_threat_assessment(assessment)
            }
            _ => Ok(None),
        }
    }

    /// Human-readable name used in log lines — kept identical to the old loop's
    /// `"failed to handle threat assessment"` / `"failed to handle protocol event"`.
    const fn description(self) -> &'static str {
        match self {
            Lane::ProtocolEvents => "protocol event",
            Lane::ThreatAssessments => "threat assessment",
        }
    }
}

/// How a strand instance should fault, for drills and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Consume normally. The production default.
    #[default]
    None,
    /// Deliberately crash after handling `n` messages. The count is per strand
    /// *instance*, so a restarted instance crashes again after its own `n`th
    /// message — which is what lets a drill drive the full
    /// crash → restart ×3 → quarantine sequence.
    CrashAfterMessages(u32),
}

impl FaultPolicy {
    /// Read the policy from [`CRASH_AFTER_MESSAGES_ENV`]. Absent/zero/invalid
    /// values all mean [`FaultPolicy::None`]: a typo must never crash a node.
    pub fn from_env() -> Self {
        Self::parse(std::env::var(CRASH_AFTER_MESSAGES_ENV).ok().as_deref())
    }

    /// The parsing half of [`FaultPolicy::from_env`], without process-env
    /// access so it can be tested without racing other tests.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw
            .map(str::trim)
            .and_then(|value| value.parse::<u32>().ok())
        {
            Some(n) if n > 0 => FaultPolicy::CrashAfterMessages(n),
            _ => FaultPolicy::None,
        }
    }

    /// Whether this policy injects a fault (used to warn loudly when armed).
    pub fn is_injected(&self) -> bool {
        !matches!(self, FaultPolicy::None)
    }

    /// The crash reason for an instance that has just handled `handled`
    /// messages, or `None` while this instance should keep running.
    fn tripped(&self, handled: u32) -> Option<String> {
        match self {
            FaultPolicy::None => None,
            FaultPolicy::CrashAfterMessages(n) if handled >= *n => Some(format!(
                "injected fault: crashed after {handled} message(s) ({CRASH_AFTER_MESSAGES_ENV} = {n})"
            )),
            FaultPolicy::CrashAfterMessages(_) => None,
        }
    }
}

/// How many recent `BusEvent.id`s one lane remembers.
///
/// The kernel's replay tail is 32 messages per `TypeId` (recipe §5.4); 256 is
/// eight times that, so a restart cannot out-run the guard even if a burst of
/// `BusEvent`s of other kinds separates the lane's own messages in the tail.
const SEEN_CAPACITY: usize = 256;

/// Durable replay guard: the ids one lane has already handled.
///
/// Deliberately **not** per generation. A restarted strand is a late
/// subscriber and the kernel replays it the recent tail — of messages the
/// *previous* generation already handled. A per-generation history would be
/// empty at exactly the moment it is needed, and the orchestrator's transitions
/// are not idempotent (`Healing` + a replayed crash = emergency shutdown), so
/// the history is shared by every generation of a lane through the spec's
/// factory: durable state, shared through the `Arc`, exactly like the
/// orchestrator itself (recipe §3.2).
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
    /// one already handled by this lane.
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

    /// Whether nothing has been handled yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SeenIds {
    fn default() -> Self {
        Self::new()
    }
}

/// One orchestrator lane as a supervised strand.
///
/// Owns its state: the orchestrator is shared with whatever built it (`Arc`,
/// so a restart resumes the same state machine and the same fusion window), the
/// seen-set is shared per *lane* (so a restart still recognises the replay), and
/// the fault policy and handled counter are per instance (so a restart resets
/// the drill). Nothing is borrowed from outside, which is what makes the strand
/// restartable: the kernel's factory call produces a fresh, independent
/// instance.
pub struct OrchestratorStrand {
    lane: Lane,
    orchestrator: Arc<Orchestrator>,
    seen: Arc<SeenIds>,
    faults: FaultPolicy,
    /// Messages this *instance* has handled. Per-instance by construction, so a
    /// restart resets it.
    handled: u32,
}

impl OrchestratorStrand {
    pub fn new(
        lane: Lane,
        orchestrator: Arc<Orchestrator>,
        seen: Arc<SeenIds>,
        faults: FaultPolicy,
    ) -> Self {
        Self {
            lane,
            orchestrator,
            seen,
            faults,
            handled: 0,
        }
    }

    /// The restartable spec for one lane, ready for
    /// [`Bus::register_strand`] (prefer [`queue_lane`], which is idempotent).
    ///
    /// The factory captures `Arc`s of the orchestrator *and* of the lane's
    /// [`SeenIds`], so every restarted instance runs against the same state
    /// machine, the same windowed fusion and the same replay history — restart
    /// resumes the lane rather than reloading a fresh one.
    pub fn spec(lane: Lane, orchestrator: Arc<Orchestrator>, faults: FaultPolicy) -> StrandSpec {
        let seen = Arc::new(SeenIds::new());
        StrandSpec::new(lane.strand_name(), move || -> Box<dyn Strand> {
            Box::new(OrchestratorStrand::new(
                lane,
                Arc::clone(&orchestrator),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for OrchestratorStrand {
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
        self.lane.output_sockets()
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick
        // and let the worker join (recipe §2). Nothing in this `run` blocks —
        // every call below is a synchronous state transition or an inline
        // publish — so there is no bounded-blocking section to shorten here.
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
            // The old loop's message-variant gate: a `net.sensors.ready`, or
            // any other payload on a matching topic, was ignored then too.
            if !self.lane.accepts(&event.message) {
                continue;
            }
            // Replay guard (recipe §5.4): a restarted generation is replayed
            // the recent tail, which the previous generation already handled.
            // Handing it to the orchestrator again would re-run a
            // non-idempotent transition (see `SeenIds`).
            if !self.seen.first_sight(event.id.0.as_u128()) {
                continue;
            }

            // The old loop body, verbatim: handle, and log-and-continue on
            // error (the errors this can produce are publish failures; a
            // delivery detail must not turn a tick into a crash).
            if let Err(error) = self.lane.handle(&self.orchestrator, &event.message) {
                tracing::error!(
                    error = %error,
                    "failed to handle {}",
                    self.lane.description()
                );
            }

            self.handled = self.handled.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.handled) {
                // Diagnostic-only path; see `FaultPolicy`. Everything this tick
                // published is already delivered: the orchestrator's effects go
                // through the shim's inline `Bus::publish`, not the strand
                // outbox, so a `Crashed` tick loses no work (recipe §5.5).
                return Err(StrandError::Crashed(reason));
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick
        // (the worker paces them at 10 ms), which is this strand's idle loop.
        Ok(())
    }
}

/// Environment variable that arms a deliberate fault on the **hardening** lane,
/// for supervision drills:
/// `IMPERIUM_TRANSPORT_HARDENING_CRASH_AFTER_PROFILES=<n>` makes every
/// `HardeningStrand` instance return [`StrandError::Crashed`] once it has
/// applied `n` profiles.
///
/// A separate variable from the orchestrator lanes'
/// [`CRASH_AFTER_MESSAGES_ENV`] on purpose: a drill must be armable per lane, so
/// that quarantining one lane while the others serve can be exercised (and so a
/// crash reason always names the variable that caused it). Unset (or `0`, or
/// unparsable) means no injection.
pub const HARDENING_CRASH_AFTER_PROFILES_ENV: &str =
    "IMPERIUM_TRANSPORT_HARDENING_CRASH_AFTER_PROFILES";

/// How the **hardening** lane should fault, for drills and tests.
///
/// Deliberately a type of its own rather than a reuse of [`FaultPolicy`]: the
/// two lanes count different things (messages vs profiles) and are armed by
/// different variables, and `.reason` below must name the variable that actually
/// caused the crash.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HardeningFaultPolicy {
    /// Apply profiles normally. The production default.
    #[default]
    None,
    /// Deliberately crash after applying `n` profiles. The count is per strand
    /// *instance*, so a restarted instance crashes again after its own `n`th
    /// profile — which is what lets a drill drive the full
    /// crash → restart ×3 → quarantine sequence.
    CrashAfterProfiles(u32),
}

impl HardeningFaultPolicy {
    /// Read the policy from [`HARDENING_CRASH_AFTER_PROFILES_ENV`].
    /// Absent/zero/invalid values all mean [`HardeningFaultPolicy::None`]: a
    /// typo must never crash a node.
    pub fn from_env() -> Self {
        Self::parse(
            std::env::var(HARDENING_CRASH_AFTER_PROFILES_ENV)
                .ok()
                .as_deref(),
        )
    }

    /// The parsing half of [`HardeningFaultPolicy::from_env`], without process-env
    /// access so it can be tested without racing other tests.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw
            .map(str::trim)
            .and_then(|value| value.parse::<u32>().ok())
        {
            Some(n) if n > 0 => HardeningFaultPolicy::CrashAfterProfiles(n),
            _ => HardeningFaultPolicy::None,
        }
    }

    /// Whether this policy injects a fault (used to warn loudly when armed).
    pub fn is_injected(&self) -> bool {
        !matches!(self, HardeningFaultPolicy::None)
    }

    /// The crash reason for an instance that has just applied `applied`
    /// profiles, or `None` while this instance should keep running.
    fn tripped(&self, applied: u32) -> Option<String> {
        match self {
            HardeningFaultPolicy::None => None,
            HardeningFaultPolicy::CrashAfterProfiles(n) if applied >= *n => Some(format!(
                "injected fault: crashed after {applied} profile(s) \
                 ({HARDENING_CRASH_AFTER_PROFILES_ENV} = {n})"
            )),
            HardeningFaultPolicy::CrashAfterProfiles(_) => None,
        }
    }
}

/// The `net.transport.hardening.apply` loop as a supervised strand.
///
/// Owns its state: the controller is shared with whatever built it (`Arc`, so a
/// restart keeps applying profiles to the *same* controller the composition root
/// can read back), the seen-set is shared by every generation (so a restart still
/// recognises the replay), and the fault policy and applied counter are per
/// instance (so a restart resets the drill).
pub struct HardeningStrand {
    controller: Arc<HardeningController>,
    /// Durable across restarts, like the controller itself: it exists precisely
    /// to recognise the tail the kernel replays to a restarted generation.
    seen: Arc<SeenIds>,
    faults: HardeningFaultPolicy,
    /// Profiles this *instance* has applied. Per-instance by construction, so a
    /// restart resets it.
    applied: u32,
}

impl HardeningStrand {
    fn new(
        controller: Arc<HardeningController>,
        seen: Arc<SeenIds>,
        faults: HardeningFaultPolicy,
    ) -> Self {
        Self {
            controller,
            seen,
            faults,
            applied: 0,
        }
    }

    /// The restartable spec for the hardening lane, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec). Prefer
    /// [`queue_hardening`], which is idempotent.
    ///
    /// The factory captures an `Arc<HardeningController>` clone, so every
    /// restarted instance applies profiles to the same controller — a restart
    /// never splits the hardening state in two — and one [`SeenIds`] record, so
    /// the replayed pending tail is skipped rather than applied twice.
    pub fn spec(controller: Arc<HardeningController>, faults: HardeningFaultPolicy) -> StrandSpec {
        let seen = Arc::new(SeenIds::new());
        StrandSpec::new(HARDENING_STRAND, move || -> Box<dyn Strand> {
            Box::new(HardeningStrand::new(
                Arc::clone(&controller),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for HardeningStrand {
    fn name(&self) -> &str {
        HARDENING_STRAND
    }

    fn inputs(&self) -> &[Socket] {
        // The socket name is documentation for the lifecycle event and the web
        // graph; routing is by `BusEvent`'s `TypeId`.
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(HARDENING_APPLY_TOPIC)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(HARDENING_STATUS_TOPIC)];
        &SOCKS
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick and
        // let the worker join (recipe §2). Nothing here blocks — `apply` is a
        // validate + write + inline publish — so there is no bounded-blocking
        // section to shorten.
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on (recipe §5.3). `?` is infallible in practice: the inbox only
        // holds payloads whose `TypeId` matched this strand's declared input.
        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            // The prefix filter the kernel used to apply for the old
            // `crate::test_supervision::subscribe_queue(&publisher, HARDENING_APPLY_TOPIC, 64)` (recipe §5.2).
            if !event.topic.starts_with(HARDENING_APPLY_TOPIC) {
                continue;
            }
            // The old loop ignored every other message kind on that prefix.
            let Message::ProtocolHardeningProfile(profile) = event.message else {
                continue;
            };
            // Replay guard (recipe §5.4): a restarted generation is replayed the
            // recent tail, which the previous generation already applied.
            // Applying a profile is not idempotent in what it publishes (a second
            // apply emits a second `net.transport.hardening.status` with a fresh
            // `active_at`), so the replay is refused by the durable record.
            if !self.seen.first_sight(event.id.0.as_u128()) {
                tracing::debug!(
                    event_id = ?event.id,
                    "skipping a replayed hardening profile already applied"
                );
                continue;
            }

            // The old loop body, verbatim: apply, and log-and-continue on error
            // (the errors this can produce are validation refusals and publish
            // failures; neither must turn a tick into a crash).
            if let Err(error) = self.controller.apply(profile) {
                tracing::warn!(
                    error = %error,
                    "hardening profile rejected"
                );
            }

            self.applied = self.applied.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.applied) {
                // Diagnostic-only path; see `HardeningFaultPolicy`. The status
                // this tick published went through the controller's inline
                // `Bus::publish`, not the strand outbox, so a `Crashed` tick
                // loses no work (recipe §5.5).
                return Err(StrandError::Crashed(reason));
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick
        // (the worker paces them at 10 ms), which is this strand's idle loop.
        Ok(())
    }
}

/// `(strand name, bus)` pairs already queued in this process.
///
/// Two registration paths exist while this conversion lands: the canonical
/// [`register_strands`] / [`queue_hardening`], and the legacy
/// [`subscribe_hardening_profiles`](crate::HardeningController::subscribe_hardening_profiles)
/// shim the composition root already calls. A strand name is a kernel-global
/// resource and re-registering one **panics** inside the kernel's
/// `register_spec` — a boot failure, not a recoverable error — so the queue path
/// is made idempotent here rather than relying on the composition root to use
/// exactly one of the two.
///
/// Keyed by `Weak<Bus>`: a dropped bus is pruned, and because a live `Weak`
/// keeps its allocation alive, an address cannot be recycled behind a stale
/// entry — a fresh `Bus` in the same test process is never mistaken for an
/// already-registered one.
static QUEUED_HARDENING: OnceLock<
    Mutex<Vec<(&'static str, Weak<BusPublisher>, HardeningFaultPolicy)>>,
> = OnceLock::new();

fn hardening_registry(
) -> &'static Mutex<Vec<(&'static str, Weak<BusPublisher>, HardeningFaultPolicy)>> {
    QUEUED_HARDENING.get_or_init(|| Mutex::new(Vec::new()))
}

/// The fault policy the hardening lane was queued with on `bus`, if it already
/// was.
fn queued_hardening_policy(publisher: &Arc<BusPublisher>) -> Option<HardeningFaultPolicy> {
    let mut entries = hardening_registry().lock();
    entries.retain(|(_, queued_publisher, _)| queued_publisher.strong_count() > 0);
    let publisher = Arc::downgrade(publisher);
    entries
        .iter()
        .find(|(name, queued_publisher, _)| {
            *name == HARDENING_STRAND && queued_publisher.ptr_eq(&publisher)
        })
        .map(|(_, _, policy)| *policy)
}

fn mark_hardening_queued(publisher: &Arc<BusPublisher>, faults: HardeningFaultPolicy) {
    hardening_registry()
        .lock()
        .push((HARDENING_STRAND, Arc::downgrade(publisher), faults));
}

/// Queue the hardening lane's strand spec on `bus`, at most once per bus.
///
/// Idempotent: a second call — from [`register_strands`] after the composition
/// root's own shim, or the other way round — is a no-op, because the first
/// registration wins. That ordering is what lets the composition root keep
/// owning its `Arc<HardeningController>` (and read `active_profile()` back from
/// it) while [`register_strands`] remains a single call that also wires this
/// lane. A differing fault policy is warned about rather than silently ignored:
/// a drill that never armed would otherwise look like a supervisor that did not
/// restart.
///
/// Returns `()`: `register_spec` cannot fail. The ordering the old
/// `StrandRegistrationError::Engaged` enforced is now enforced by ownership —
/// `Bus::run_until` consumes the bus, so a spec queued after the loop started
/// is a borrow-check error, not a value.
pub fn queue_hardening(
    bus: &mut Bus,
    publisher: &Arc<BusPublisher>,
    controller: &Arc<HardeningController>,
    faults: HardeningFaultPolicy,
) {
    if let Some(queued) = queued_hardening_policy(publisher) {
        if queued != faults {
            tracing::warn!(
                strand = HARDENING_STRAND,
                queued = ?queued,
                requested = ?faults,
                "the hardening lane was already queued with a different fault policy; \
                 the first registration wins"
            );
        }
        return;
    }
    bus.register_spec(HardeningStrand::spec(Arc::clone(controller), faults));
    mark_hardening_queued(publisher, faults);
}

/// `(strand name, bus)` pairs already queued in this process.
///
/// Two registration paths exist while this conversion lands: the canonical
/// [`register_strands`] / [`Orchestrator::queue_strands`], and the legacy
/// `subscribe_*` shims on the orchestrator. A strand name is a kernel-global
/// resource and re-registering one **panics** inside the kernel's
/// `register_spec` — a boot failure, not a recoverable error — so the queue
/// path is made idempotent here rather than relying on the composition root to
/// use exactly one of the two.
///
/// Keyed by `Weak<Bus>`: a dropped bus is pruned, and because a live `Weak`
/// keeps its allocation alive, an address cannot be recycled behind a stale
/// entry — a fresh `Bus` in the same test process is never mistaken for an
/// already-registered one.
static QUEUED: OnceLock<Mutex<Vec<(&'static str, Weak<BusPublisher>, FaultPolicy)>>> =
    OnceLock::new();

fn queued_registry() -> &'static Mutex<Vec<(&'static str, Weak<BusPublisher>, FaultPolicy)>> {
    QUEUED.get_or_init(|| Mutex::new(Vec::new()))
}

/// The fault policy `name` was queued with on `bus`, if it already was.
fn queued_policy(publisher: &Arc<BusPublisher>, name: &'static str) -> Option<FaultPolicy> {
    let mut entries = queued_registry().lock();
    entries.retain(|(_, queued_publisher, _)| queued_publisher.strong_count() > 0);
    let publisher = Arc::downgrade(publisher);
    entries
        .iter()
        .find(|(queued_name, queued_publisher, _)| {
            *queued_name == name && queued_publisher.ptr_eq(&publisher)
        })
        .map(|(_, _, policy)| *policy)
}

fn mark_queued(publisher: &Arc<BusPublisher>, name: &'static str, faults: FaultPolicy) {
    queued_registry()
        .lock()
        .push((name, Arc::downgrade(publisher), faults));
}

/// Queue one lane's strand spec on `bus`, at most once per bus.
///
/// Idempotent: a second call for the same `(bus, lane)` is a no-op — the first
/// registration wins, and a differing fault policy is warned about rather than
/// silently ignored (a drill that was never armed would otherwise look like a
/// supervisor that did not restart). So the legacy shims and
/// [`register_strands`] can both run without the kernel's collision panic.
/// Returns `()`: the old `StrandRegistrationError::Engaged` is gone, because
/// the ordering it enforced is now a borrow-check error (see [`register_strands`]).
pub fn queue_lane(
    bus: &mut Bus,
    publisher: &Arc<BusPublisher>,
    lane: Lane,
    orchestrator: &Arc<Orchestrator>,
    faults: FaultPolicy,
) {
    let name = lane.strand_name();
    if let Some(queued) = queued_policy(publisher, name) {
        if queued != faults {
            tracing::warn!(
                lane = name,
                queued = ?queued,
                requested = ?faults,
                "this lane was already queued with a different fault policy; \
                 the first registration wins"
            );
        }
        return;
    }
    bus.register_spec(OrchestratorStrand::spec(
        lane,
        Arc::clone(orchestrator),
        faults,
    ));
    mark_queued(publisher, name, faults);
}

/// Queue both lanes with the same fault policy.
///
/// A lane that is already queued on this bus is left exactly as it was (the
/// first registration wins — see [`queue_lane`]).
pub fn queue_lanes(
    bus: &mut Bus,
    publisher: &Arc<BusPublisher>,
    orchestrator: &Arc<Orchestrator>,
    faults: FaultPolicy,
) {
    if faults.is_injected() {
        tracing::warn!(
            policy = ?faults,
            env = CRASH_AFTER_MESSAGES_ENV,
            "transport orchestrator strand fault drill ARMED — the orchestrator \
             lanes will crash on purpose"
        );
    }
    for lane in Lane::ALL {
        queue_lane(bus, publisher, lane, orchestrator, faults);
    }
}

/// Register the transport orchestrator's strands on `bus`, with the node's
/// deployment configuration.
///
/// This is the composition root's entry point (recipe §3.6): call it while the
/// bus is still idle, before `Bus::engage_supervision()`, and keep the
/// returned handle if the caller wants to observe the orchestrator's state.
/// Returns the shared [`Orchestrator`] whose state machine both strands drive.
///
/// The fault policy comes from [`CRASH_AFTER_MESSAGES_ENV`]; unset (the
/// production default) means no injection.
pub fn register_strands(bus: &mut Bus, publisher: &Arc<BusPublisher>) -> Arc<Orchestrator> {
    register_strands_with(bus, publisher, OrchestratorConfig::default())
}

/// [`register_strands`], with an explicit [`OrchestratorConfig`] (the CLI wires
/// a policy, tests wire others).
///
/// Queues every strand this crate owns: the orchestrator's two lanes **and** the
/// hardening lane. The hardening controller is built here only if the caller did
/// not queue the lane first through the legacy
/// [`subscribe_hardening_profiles`](crate::HardeningController::subscribe_hardening_profiles)
/// shim or [`queue_hardening`]; the first registration wins, so a composition root
/// that owns a controller keeps owning it (see [`queue_hardening`]).
pub fn register_strands_with(
    bus: &mut Bus,
    publisher: &Arc<BusPublisher>,
    config: OrchestratorConfig,
) -> Arc<Orchestrator> {
    let orchestrator = Arc::new(Orchestrator::new(config, Arc::clone(publisher)));
    queue_lanes(bus, publisher, &orchestrator, FaultPolicy::from_env());

    let hardening_faults = HardeningFaultPolicy::from_env();
    if hardening_faults.is_injected() {
        tracing::warn!(
            policy = ?hardening_faults,
            env = HARDENING_CRASH_AFTER_PROFILES_ENV,
            "transport hardening strand fault drill ARMED — the hardening lane \
             will crash on purpose"
        );
    }
    // A controller this function built is dropped if the lane was already queued
    // with the composition root's own instance (the first registration wins, and
    // the strand's factory holds an `Arc` of whichever one won).
    let hardening = Arc::new(HardeningController::new(Arc::clone(publisher)));
    queue_hardening(bus, publisher, &hardening, hardening_faults);

    orchestrator
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::{
        ProtocolEvent, ProtocolEventKind, ProtocolRole, ProtocolStatus, SuggestedAction,
        ThreatAssessment,
    };

    /// A fault must never be armable by a typo — absent/zero/unparsable all mean
    /// `None`. `parse` is the testable half of `from_env` (recipe §6c).
    #[test]
    fn fault_policy_parser_never_arms_on_a_bad_value() {
        assert_eq!(FaultPolicy::parse(None), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("0")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("frames")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("-1")), FaultPolicy::None);
        assert_eq!(
            FaultPolicy::parse(Some(" 3 ")),
            FaultPolicy::CrashAfterMessages(3)
        );
        assert!(FaultPolicy::parse(Some("3")).is_injected());
        assert!(!FaultPolicy::None.is_injected());
    }

    #[test]
    fn fault_policy_trips_exactly_at_its_threshold() {
        let policy = FaultPolicy::CrashAfterMessages(2);
        assert_eq!(policy.tripped(0), None);
        assert_eq!(policy.tripped(1), None);
        let reason = policy.tripped(2).expect("trips at the threshold");
        assert!(reason.contains("injected fault") && reason.contains("2 message"));
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
    }

    /// The hardening lane's drill must be as un-armable by a typo as the
    /// orchestrator's (recipe §6c), and it is a *separate* policy so a crash
    /// reason always names the variable that caused it.
    #[test]
    fn hardening_fault_policy_never_arms_on_a_bad_value() {
        assert_eq!(
            HardeningFaultPolicy::parse(None),
            HardeningFaultPolicy::None
        );
        assert_eq!(
            HardeningFaultPolicy::parse(Some("")),
            HardeningFaultPolicy::None
        );
        assert_eq!(
            HardeningFaultPolicy::parse(Some("0")),
            HardeningFaultPolicy::None
        );
        assert_eq!(
            HardeningFaultPolicy::parse(Some("profiles")),
            HardeningFaultPolicy::None
        );
        assert_eq!(
            HardeningFaultPolicy::parse(Some("-3")),
            HardeningFaultPolicy::None
        );
        assert_eq!(
            HardeningFaultPolicy::parse(Some(" 2 ")),
            HardeningFaultPolicy::CrashAfterProfiles(2)
        );
        assert!(HardeningFaultPolicy::parse(Some("2")).is_injected());
        assert!(!HardeningFaultPolicy::None.is_injected());
    }

    #[test]
    fn hardening_fault_policy_trips_exactly_at_its_threshold() {
        let policy = HardeningFaultPolicy::CrashAfterProfiles(2);
        assert_eq!(policy.tripped(0), None);
        assert_eq!(policy.tripped(1), None);
        let reason = policy.tripped(2).expect("trips at the threshold");
        assert!(
            reason.contains("injected fault")
                && reason.contains("2 profile")
                && reason.contains(HARDENING_CRASH_AFTER_PROFILES_ENV),
            "the reason must name the drill that caused it: {reason}"
        );
        assert_eq!(HardeningFaultPolicy::None.tripped(99), None);
    }

    /// The three strands of this crate share one kernel, and the kernel panics on
    /// a duplicate name — so the hardening lane's name must be its own, and the
    /// topic it consumes must be the one the old subscription matched.
    #[test]
    fn hardening_lane_names_and_topics_are_their_own() {
        assert_ne!(HARDENING_STRAND, PROTOCOL_EVENTS_STRAND);
        assert_ne!(HARDENING_STRAND, THREAT_ASSESSMENTS_STRAND);
        for lane in Lane::ALL {
            assert_ne!(HARDENING_STRAND, lane.strand_name());
        }
        assert_eq!(HARDENING_APPLY_TOPIC, "net.transport.hardening.apply");
        assert_eq!(HARDENING_STATUS_TOPIC, "net.transport.hardening.status");
        // The lane's input socket name IS its topic prefix filter, so the
        // lifecycle event and the web graph display what the loop consumes.
        assert!(HARDENING_APPLY_TOPIC.starts_with("net.transport."));
    }

    /// Size contract (recipe §5.4): the kernel replays its last 32 messages per
    /// `TypeId` to a restarted generation, so the durable record the
    /// orchestrator's lanes *and* the hardening lane share must remember strictly
    /// more than those 32 — a tail-sized record would let the oldest replayed
    /// message through, and applying a profile twice publishes a second
    /// acceptance status.
    #[test]
    fn replay_record_out_sizes_the_kernels_replay_tail() {
        const KERNEL_REPLAY_TAIL: usize = 32;
        assert!(
            SEEN_CAPACITY > KERNEL_REPLAY_TAIL,
            "the record must cover the whole replay tail, not part of it"
        );

        let seen = SeenIds::new();
        let tail: Vec<u128> = (0..KERNEL_REPLAY_TAIL as u128).collect();
        for (index, id) in tail.iter().enumerate() {
            assert!(seen.first_sight(*id), "id {index} is new");
        }
        for id in &tail {
            assert!(
                !seen.first_sight(*id),
                "a full replay tail must be refused in its entirety"
            );
        }
        assert_eq!(seen.len(), KERNEL_REPLAY_TAIL);
    }

    /// The lane filter is the old `crate::test_supervision::subscribe_queue(&publisher, prefix, 64)` plus the old
    /// `if let Message::X` gate, and nothing else.
    #[test]
    fn lanes_filter_topics_and_variants_like_the_old_subscriptions() {
        assert!(Lane::ProtocolEvents.matches_topic("net.transport.event"));
        assert!(Lane::ProtocolEvents.matches_topic("net.transport.event.xray"));
        assert!(!Lane::ProtocolEvents.matches_topic("net.transport.decision"));
        assert!(Lane::ThreatAssessments.matches_topic("net.sensors.threat"));
        assert!(!Lane::ThreatAssessments.matches_topic("net.transport.event"));

        let protocol_event = Message::ProtocolEvt(ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: "test".into(),
            },
            timestamp: chrono::Utc::now(),
        });
        let threat = Message::ThreatAssessment(ThreatAssessment {
            source: imperium_protocol::ThreatSource::Heuristic {
                name: "timing".into(),
            },
            confidence: 0.5,
            description: "test".into(),
            remote_addr: None,
            timestamp: chrono::Utc::now(),
            suggested_action: SuggestedAction::None,
        });
        let ready = Message::SubsystemReady {
            name: "imperium-net-sensors".into(),
        };

        assert!(Lane::ProtocolEvents.accepts(&protocol_event));
        assert!(!Lane::ProtocolEvents.accepts(&threat));
        assert!(Lane::ThreatAssessments.accepts(&threat));
        assert!(!Lane::ThreatAssessments.accepts(&protocol_event));
        // `net.sensors.ready` matched the old prefix too, and was ignored for
        // the same reason: it is not an assessment.
        assert!(!Lane::ThreatAssessments.accepts(&ready));

        assert_eq!(Lane::ALL.len(), 2);
        assert_eq!(Lane::ALL[0].strand_name(), PROTOCOL_EVENTS_STRAND);
        assert_eq!(Lane::ALL[1].strand_name(), THREAT_ASSESSMENTS_STRAND);
        assert_ne!(
            PROTOCOL_EVENTS_STRAND, THREAT_ASSESSMENTS_STRAND,
            "the kernel panics on a duplicate strand name"
        );
        assert_eq!(Lane::ProtocolEvents.topic_prefix(), PROTOCOL_EVENT_TOPIC);
        assert_eq!(Lane::ThreatAssessments.topic_prefix(), SENSOR_TOPIC_PREFIX);
    }

    /// The deployment default exists so the composition root can register with
    /// one call — and must stay the pair the CLI wires.
    #[test]
    fn default_config_is_the_deployment_pair() {
        let config = OrchestratorConfig::default();
        assert_eq!(config.active_protocol, "xray");
        assert_eq!(config.standby_protocol, "amneziawg");
    }
}
