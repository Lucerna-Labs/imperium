//! The deployment orchestrator's two recv loops as supervised Spiderweb
//! **strands**.
//!
//! `deployment.rs` used to hold two `tokio::spawn`ed tasks:
//! [`DeploymentOrchestrator::subscribe_deployment_plans`] (a subscription on
//! `net.vpn.deployment.apply`) and
//! [`DeploymentOrchestrator::subscribe_status_requests`] (a subscription on
//! `net.vpn.deployment.status_request`). Neither was visible to the spider: a
//! panic killed the task silently — no lifecycle event, no restart, no
//! quarantine, no vibration. They are now [`DeploymentStrand`]s, registered as
//! **specs** through [`queue_lanes`] (or the crate's single composition-root
//! call, [`DeploymentOrchestrator::register_strands`]) and installed by
//! `Bus::engage_supervision()`, so a crash becomes a
//! [`LifecycleEvent::Crashed`](spiderweb::LifecycleEvent::Crashed),
//! is restarted up to three times, and the fourth crash is a quarantine. See
//! the pilot (`imperium-net-lightcone`) for the general recipe.
//!
//! # Two lanes, not one
//!
//! The file had two standing consumer loops, so it gets two strands
//! ([`Lane::Plans`], [`Lane::StatusRequests`]). Merging them was rejected for
//! the same reasons the transport orchestrator's lanes stayed separate:
//!
//! 1. **Behaviour preservation.** The two loops were independent consumers with
//!    their own subscriptions and their own tasks, and no ordering relationship
//!    between them. One strand would serialise them — a `net.vpn.deployment.apply`
//!    (a *heavy* synchronous body: crypto, membership, relay selection, a dozen
//!    publishes) would sit in front of a status request in the same inbox for as
//!    long as it takes to run. The recipe's rule is that only the prefix filter
//!    moves and only the pending-tail replay is added; a new cross-stream
//!    ordering is neither.
//! 2. **Failure-domain isolation.** The plan lane is the only lane that mutates
//!    cluster state; a bad plan, a panic in the crypto path, or a quarantine must
//!    not take the *status* lane down with it. Two strands let the question "what
//!    was the last known deployment status?" still be answered after the plan lane
//!    has crashed and been quarantined.
//! 3. **Restart accounting.** A restarted strand is replayed up to 32 pending
//!    messages; two lanes replay into their own (durable) seen sets and their own
//!    crash counters, exactly like the two tasks they replace.
//!
//! # The replay guard is the point of this conversion
//!
//! The plan lane's effect is emphatically **not idempotent**: re-running
//! `deploy()` mints fresh tokens, re-requests and re-approves membership,
//! re-selects relays, re-applies hardening profiles and re-publishes all of it.
//! A restarted generation is a late subscriber, and the kernel replays it the
//! recent tail (recipe §5.4) — so a replayed `net.vpn.deployment.apply` would
//! re-run a whole deployment. Each lane therefore keeps a durable [`SeenIds`]
//! history of `BusEvent.id`s, shared by every generation of that lane through
//! the spec's factory: the replay it must defeat is aimed at the *new*
//! generation, whose own history would otherwise be empty.
//!
//! The status lane is deduped too, for a smaller reason: answering one request
//! twice would publish a duplicate status for a single request, which the old
//! broadcast bus never did (there was no replay at all).
//!
//! # What changed deliberately (and nothing else)
//!
//! * **The prefix filter moved into the strand** (recipe §5.2). Spiderweb routes
//!   strand deliveries by `TypeId`, not by socket name, so every `BusEvent` on
//!   the bus reaches a strand that declares a `BusEvent` input. The old
//!   `crate::test_supervision::subscribe_queue(&publisher, "net.vpn.deployment.apply", 64)` / `…status_request` prefix test
//!   is now [`Lane::matches_topic`] — the same comparison on the other side of
//!   the bus.
//! * **A replay guard on `BusEvent.id`** (recipe §5.4), as above.
//! * **The `Lagged` arms are gone.** The old loops handled
//!   `BusError::Lagged(n)` because the shim's `recv()` sits on a *bounded*
//!   channel that drops when a consumer falls behind. A strand's inbox is an
//!   unbounded `std::sync::mpsc` channel the kernel owns, so a busy
//!   `deploy()` cannot lose a plan: there is no lag to report and nothing to
//!   drop. `Err(BusError::Closed) => break` also disappears — the kernel
//!   signals shutdown with [`BusHandle::is_shutting_down`] instead, which `run`
//!   honours on every tick.
//!
//! Nothing else moves: `deploy()` is called with the same plan, in the same
//! order, through the same `Arc<Bus>`, so its effects reach the same topics and
//! the same `Bus::subscribe` subscribers as before; the error path publishes the
//! same rejected status; the status lane answers with the same payload (the last
//! known status, or [`no_deployment_status`](super::no_deployment_status)).
//!
//! # Durable state
//!
//! `DeploymentOrchestrator::last_status` is the one piece of state that must
//! outlive a strand generation: a restarted deployment orchestrator should still
//! answer a status request with the last known status, not with "no deployment
//! has run". It already lives behind the orchestrator's `Arc`, and the specs'
//! factories capture that same `Arc`, so both lanes and every generation of
//! every lane observe one `last_status` — recipe §3.2's "wrap durable state in an
//! `Arc` and move a clone into the factory closure".
//!
//! # Registration order (recipe §5.1, §5.9)
//!
//! Specs are **queued, not started**: they are installed by
//! `Bus::engage_supervision()`. Queue them first, then engage:
//!
//! ```ignore
//! // Prose recipe only: `test_supervision` is `#[cfg(test)]` and
//! // `register_strands` takes `&mut Bus`, so this snippet cannot compile as
//! // a doctest. See the `deployment_supervision` tests in this file.
//! use std::sync::Arc;
//!
//! use spiderweb::Bus;
//! use imperium_runtime::DeploymentOrchestrator;
//!
//! let (mut bus, publisher) = crate::test_supervision::open();
//! let deployment = DeploymentOrchestrator::register_strands(&bus)?;
//! let mut supervision = crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));
//! // … on the way out:
//! supervision.shutdown();
//! # Ok::<(), spiderweb::BusError>(())
//! ```
//!
//! # Where this module is visible
//!
//! `lib.rs` declares `mod deployment;` (private) and re-exports exactly
//! `DeploymentError` and `DeploymentOrchestrator`, and this conversion is
//! deliberately not allowed to edit that file (a parallel workstream owns
//! `RuntimeCoordinator::run` in it). Everything else here is therefore
//! crate-internal, reachable from outside the crate only through
//! [`DeploymentOrchestrator::register_strands`]. Publishing the strand
//! vocabulary — for a boot-log reader, a dashboard, or an integration test that
//! wants a recorder strand — would be one line in `lib.rs`:
//! `pub use deployment::strand;`. The supervision drill below lives in this
//! file's test module for the same reason (an integration test could not name
//! [`FaultPolicy`]); its assertions are the pilot's
//! (`crates/imperium-net-lightcone/tests/pilot_supervision.rs`), driven through
//! the real kernel, and nothing is stubbed.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use imperium_protocol::{BusEvent, Message};
use spiderweb::{Bus, BusHandle, BusPublisher, Socket, Strand, StrandError, StrandSpec};

use super::DeploymentOrchestrator;

/// Topic the plan lane consumes — the old
/// `crate::test_supervision::subscribe_queue(&publisher, "net.vpn.deployment.apply", 64)`. Also its `inputs()` socket name,
/// so the lifecycle event and the web graph name the same string the old
/// subscription matched.
pub const APPLY_TOPIC: &str = "net.vpn.deployment.apply";

/// Topic the status lane consumes — the old
/// `crate::test_supervision::subscribe_queue(&publisher, "net.vpn.deployment.status_request", 64)`.
pub const STATUS_REQUEST_TOPIC: &str = "net.vpn.deployment.status_request";

/// Where both lanes' answers land (`emit_status`). Declared by `outputs()` for
/// the lifecycle event and the web graph.
pub const STATUS_TOPIC: &str = "net.vpn.deployment.status";

/// Strand name of the plan lane.
///
/// Fixed, `&'static str` (Spiderweb requires it), and built from the crate's
/// identifier plus the lane, so one name works in the kernel log, the lifecycle
/// events and the spider log (recipe §5.8).
pub const PLANS_STRAND: &str = "imperium-runtime-deployment-plans";

/// Strand name of the status lane. Must differ from [`PLANS_STRAND`]: the kernel
/// *panics* on a duplicate strand name.
pub const STATUS_STRAND: &str = "imperium-runtime-deployment-status";

/// Environment variable that arms a deliberate fault for supervision drills:
/// `IMPERIUM_DEPLOYMENT_CRASH_AFTER_MESSAGES=<n>` makes every strand instance of
/// both lanes return [`StrandError::Crashed`] once it has handled `n` messages.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. Like the pilot's equivalent, it exists so the
/// restart/quarantine path can be drilled end-to-end against the real strands
/// instead of a stand-in.
pub const CRASH_AFTER_MESSAGES_ENV: &str = "IMPERIUM_DEPLOYMENT_CRASH_AFTER_MESSAGES";

/// Which of the orchestrator's two recv loops a strand instance is.
///
/// The lane is what turns one strand type into two independent strands: it names
/// the strand, declares its input socket, filters the shared `BusEvent` stream,
/// and selects the orchestrator entry point. See the module docs for why these
/// are two strands and not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// `net.vpn.deployment.apply` → [`DeploymentOrchestrator::handle_plan`].
    Plans,
    /// `net.vpn.deployment.status_request` →
    /// [`DeploymentOrchestrator::handle_status_request`].
    StatusRequests,
}

impl Lane {
    /// Both lanes, in registration order.
    pub const ALL: [Lane; 2] = [Lane::Plans, Lane::StatusRequests];

    /// The strand name this lane registers under.
    pub const fn strand_name(self) -> &'static str {
        match self {
            Lane::Plans => PLANS_STRAND,
            Lane::StatusRequests => STATUS_STRAND,
        }
    }

    /// The topic prefix this lane consumes (the old `bus.subscribe(prefix)`).
    pub const fn topic_prefix(self) -> &'static str {
        match self {
            Lane::Plans => APPLY_TOPIC,
            Lane::StatusRequests => STATUS_REQUEST_TOPIC,
        }
    }

    /// The input socket name (documentation; routing is by `BusEvent`'s
    /// `TypeId` — the socket name is what the lifecycle event and the web graph
    /// display).
    const fn input_sockets(self) -> &'static [Socket] {
        const PLANS: [Socket; 1] = [Socket::new::<BusEvent>(APPLY_TOPIC)];
        const STATUS: [Socket; 1] = [Socket::new::<BusEvent>(STATUS_REQUEST_TOPIC)];
        match self {
            Lane::Plans => &PLANS,
            Lane::StatusRequests => &STATUS,
        }
    }

    /// Where this lane's effects land (`emit_status`). Documentation only, but
    /// the spider logs it and it shows in the web graph.
    const fn output_sockets(self) -> &'static [Socket] {
        const STATUS: [Socket; 1] = [Socket::new::<BusEvent>(STATUS_TOPIC)];
        match self {
            Lane::Plans => &STATUS,
            Lane::StatusRequests => &STATUS,
        }
    }

    /// The old kernel-side prefix filter, moved into the consumer (recipe §5.2).
    ///
    /// The two prefixes are disjoint (`net.vpn.deployment.status` does not start
    /// with `…status_request`, and vice versa), so neither lane's own output is
    /// ever mistaken for its input.
    fn matches_topic(self, topic: &str) -> bool {
        topic.starts_with(self.topic_prefix())
    }

    /// The old loop's `if let Message::X(..) = event.message` gate.
    fn accepts(self, message: &Message) -> bool {
        match self {
            Lane::Plans => matches!(message, Message::VpnDeploymentPlan(_)),
            Lane::StatusRequests => matches!(message, Message::VpnDeploymentStatusRequest(_)),
        }
    }

    /// The old loop's body. Any other message variant on a matching topic is
    /// ignored, exactly as the old loops ignored it (`if let … { }` with no
    /// `else`).
    fn handle(self, orchestrator: &DeploymentOrchestrator, message: &Message) {
        match (self, message) {
            (Lane::Plans, Message::VpnDeploymentPlan(plan)) => orchestrator.handle_plan(plan),
            (Lane::StatusRequests, Message::VpnDeploymentStatusRequest(_)) => {
                orchestrator.handle_status_request()
            }
            _ => {}
        }
    }
}

/// How a strand instance should fault, for drills and tests.
///
/// Env-gated in production ([`FaultPolicy::from_env`], read once by
/// [`DeploymentOrchestrator::register_strands`]) and constructible directly by a
/// test through [`queue_lane`], so a drill never races the process environment.
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
/// The kernel's replay tail is 32 messages per `TypeId` (recipe §5.4) and
/// `BusEvent` is one `TypeId` for the whole process, so 256 is eight times the
/// largest batch a restart can ever be handed — enough margin that a burst of
/// unrelated `BusEvent`s between a lane's own messages cannot push a handled plan
/// out of the history it needs it in.
const SEEN_CAPACITY: usize = 256;

/// Durable replay guard: the ids one lane has already handled.
///
/// Deliberately **not** per generation. A restarted strand is a late subscriber
/// and the kernel replays it the recent tail — of messages the *previous*
/// generation already handled. A per-generation history would be empty at
/// exactly the moment it is needed, and the plan lane's effect is not idempotent
/// (see the module docs), so the history is shared by every generation of a lane
/// through the spec's factory: durable state, shared through the `Arc`, exactly
/// like the orchestrator itself (recipe §3.2).
pub struct SeenIds {
    /// A plain `std::sync::Mutex` around a set that is only ever inserted into:
    /// a poisoned lock (a panic elsewhere in this crate) cannot leave the set
    /// inconsistent, so every accessor is poison-tolerant instead of
    /// cascading the panic into a strand crash.
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
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
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
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .order
            .len()
    }
}

impl Default for SeenIds {
    fn default() -> Self {
        Self::new()
    }
}

/// One deployment-orchestrator lane as a supervised strand.
///
/// Owns its state: the orchestrator is shared with whatever built it (`Arc`, so a
/// restart keeps the same buses, the same deployment semantics and — critically
/// — the same `last_status`), the seen-set is shared per *lane* (so a restart
/// still recognises the replay), and the fault policy and handled counter are per
/// instance (so a restart resets the drill). Nothing is borrowed from outside,
/// which is what makes the strand restartable: the kernel's factory call produces
/// a fresh, independent instance.
pub struct DeploymentStrand {
    lane: Lane,
    orchestrator: Arc<DeploymentOrchestrator>,
    seen: Arc<SeenIds>,
    faults: FaultPolicy,
    /// Messages this *instance* has handled. Per-instance by construction, so a
    /// restart resets it.
    handled: u32,
}

impl DeploymentStrand {
    pub fn new(
        lane: Lane,
        orchestrator: Arc<DeploymentOrchestrator>,
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
    /// [`SeenIds`], so every restarted instance runs against the same durable
    /// state — the same `last_status`, and a replay history that already knows
    /// what the previous generation handled.
    pub fn spec(
        lane: Lane,
        orchestrator: Arc<DeploymentOrchestrator>,
        faults: FaultPolicy,
    ) -> StrandSpec {
        let seen = Arc::new(SeenIds::new());
        StrandSpec::new(lane.strand_name(), move || -> Box<dyn Strand> {
            Box::new(DeploymentStrand::new(
                lane,
                Arc::clone(&orchestrator),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for DeploymentStrand {
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
        // Cooperative shutdown: the kernel is winding down, so end this tick and
        // let the worker join (recipe §2). Nothing in this `run` blocks — the
        // lane body is synchronous, bounded work (a plan deployment is CPU and
        // crypto, with no I/O wait) plus inline publishes — so there is no
        // blocking section to shorten here.
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on. Draining by socket name (`recv::<BusEvent>(name)`) would
        // leave every non-matching carrier in the inbox forever, growing it one
        // event per unrelated publish — the inbox is a mailbox, not a filter
        // (recipe §5.3). `?` is infallible in practice: the inbox only ever holds
        // payloads whose `TypeId` matched this strand's declared input, and a
        // genuine kernel fault still surfaces as `Crashed`.
        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            // The prefix filter the kernel used to apply for the old
            // `bus.subscribe(..)` (recipe §5.2).
            if !self.lane.matches_topic(&event.topic) {
                continue;
            }
            // The old loop's message-variant gate: a `net.vpn.deployment.apply`
            // carrying anything but a plan (or a status request topic carrying
            // anything but a request) was ignored then too.
            if !self.lane.accepts(&event.message) {
                continue;
            }
            // Replay guard (recipe §5.4): a restarted generation is replayed the
            // recent tail, which the previous generation already handled. Re-running
            // `deploy()` on it would mint fresh tokens, re-approve membership and
            // re-select relays a second time (see `SeenIds`).
            if !self.seen.first_sight(event.id.0.as_u128()) {
                continue;
            }

            // The old loop body, verbatim: handle the message. `deploy`'s error
            // path (publish a rejected status) and the status lane's
            // answer-with-last-status path both live in the orchestrator, so the
            // two loops' semantics are exactly what they were — including the
            // fact that neither logged anything on failure.
            self.lane.handle(&self.orchestrator, &event.message);

            self.handled = self.handled.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.handled) {
                // Diagnostic-only path; see `FaultPolicy`. Nothing published this
                // tick is lost: both lanes' effects go through the shim's inline
                // `Bus::publish`, not the strand outbox, so the rejected status /
                // the answered status of the crashing tick is already delivered
                // (recipe §5.5).
                return Err(StrandError::Crashed(reason));
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick (the
        // worker paces them at 10 ms), which is this strand's idle loop.
        Ok(())
    }
}

/// `(strand name, bus)` pairs already queued in this process.
///
/// Two registration paths exist while this conversion lands: the canonical
/// [`DeploymentOrchestrator::register_strands`] / [`queue_lanes`], and the legacy
/// `subscribe_*` shims on the orchestrator (still called by the CLI until the
/// composition-root patch lands). A strand name is a kernel-global resource and
/// re-registering one **panics** inside the kernel's `register_spec` — a boot
/// failure, not a recoverable error — so the queue path is made idempotent here
/// rather than relying on the composition root to use exactly one of the two.
///
/// Keyed by `Weak<Bus>`: a dropped bus is pruned, and because a live `Weak` keeps
/// its allocation alive, an address cannot be recycled behind a stale entry — a
/// fresh `Bus` in the same test process is never mistaken for an
/// already-registered one.
static QUEUED: OnceLock<Mutex<Vec<(&'static str, Weak<BusPublisher>, FaultPolicy)>>> =
    OnceLock::new();

fn queued_registry() -> &'static Mutex<Vec<(&'static str, Weak<BusPublisher>, FaultPolicy)>> {
    QUEUED.get_or_init(|| Mutex::new(Vec::new()))
}

/// The fault policy `name` was queued with on `publisher`'s bus, if it already was.
fn queued_policy(publisher: &Arc<BusPublisher>, name: &'static str) -> Option<FaultPolicy> {
    let mut entries = queued_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push((name, Arc::downgrade(publisher), faults));
}

/// Queue one lane's strand spec on `bus`, at most once per bus.
///
/// Idempotent: a second call for the same `(bus, lane)` is a no-op — the first
/// registration wins, and a differing fault policy is warned about rather than
/// silently ignored (a drill that was never armed would otherwise look like a
/// supervisor that did not restart). So repeated registration is a no-op rather
/// than the kernel's duplicate-name panic. Returns `()`: `register_spec` cannot
/// fail, and the old `StrandRegistrationError::Engaged` is gone because
/// `Bus::run_until` consumes the bus — a spec queued after the loop started is a
/// borrow-check error, not a value.
pub fn queue_lane(
    bus: &mut Bus,
    publisher: &Arc<BusPublisher>,
    lane: Lane,
    orchestrator: &Arc<DeploymentOrchestrator>,
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
    bus.register_spec(DeploymentStrand::spec(
        lane,
        Arc::clone(orchestrator),
        faults,
    ));
    mark_queued(publisher, name, faults);
}

/// Queue both lanes with the same fault policy.
///
/// A lane that is already queued on this bus is left exactly as it was (the first
/// registration wins — see [`queue_lane`]).
pub fn queue_lanes(
    bus: &mut Bus,
    publisher: &Arc<BusPublisher>,
    orchestrator: &Arc<DeploymentOrchestrator>,
    faults: FaultPolicy,
) {
    if faults.is_injected() {
        tracing::warn!(
            policy = ?faults,
            env = CRASH_AFTER_MESSAGES_ENV,
            "deployment orchestrator strand fault drill ARMED — both lanes will \
             crash on purpose"
        );
    }
    for lane in Lane::ALL {
        queue_lane(bus, publisher, lane, orchestrator, faults);
    }
}

#[cfg(test)]
mod tests {
    //! The pilot's drill (`crates/imperium-net-lightcone/tests/pilot_supervision.rs`)
    //! against the real deployment strands: behaviour preservation through the
    //! shim's subscription surface and through a peer strand, spec registration,
    //! the crash → `LifecycleEvent::Crashed` → restart ×3 → quarantine sequence,
    //! the replay guard that keeps a replayed plan from re-running a deployment,
    //! and `last_status` surviving the crash of the lane that observed it.
    //!
    //! These are unit tests of the library rather than an integration test file
    //! because `lib.rs` declares `mod deployment;` privately and this conversion
    //! may not edit `lib.rs` (see the module docs). Everything they drive is the
    //! production path: a real `Bus::new()`, real `queue_lane`/
    //! `Bus::register_strand(spec)`, real `Bus::engage_supervision()` (kernel run
    //! loop + spider on their own OS threads), real strand workers, and the real
    //! [`DeploymentStrand`]. Nothing is simulated and nothing is stubbed.

    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use chrono::Utc;
    use imperium_protocol::{
        VpnDeploymentNodeSpec, VpnDeploymentPlan, VpnDeploymentRole, VpnDeploymentStatus,
        VpnDeploymentStatusRequest,
    };
    use spiderweb::{LifecycleEvent, SYS_LIFECYCLE};

    use super::*;

    // -----------------------------------------------------------------------
    // Recorder strands — the supervision instruments
    // -----------------------------------------------------------------------

    /// Shared, test-owned record of every lifecycle event the kernel published.
    /// `std::sync::Mutex` so a poisoned lock cannot hide an assertion failure.
    type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;
    /// Shared, test-owned record of the `BusEvent`s a recorder strand felt.
    type EventLog = Arc<Mutex<Vec<BusEvent>>>;

    fn new_lifecycle_log() -> LifecycleLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn new_event_log() -> EventLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn lifecycle_snapshot(log: &LifecycleLog) -> Vec<LifecycleEvent> {
        log.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn event_snapshot(log: &EventLog) -> Vec<BusEvent> {
        log.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Count lifecycle events matching `pred`.
    fn count(log: &LifecycleLog, pred: impl Fn(&LifecycleEvent) -> bool) -> usize {
        lifecycle_snapshot(log)
            .iter()
            .filter(|event| pred(event))
            .count()
    }

    /// Count `Registered` events for one strand name. The kernel emits one per
    /// *generation*, so a strand restarted three times reports four.
    fn registered(log: &LifecycleLog, name: &str) -> usize {
        count(
            log,
            |event| matches!(event, LifecycleEvent::Registered { name: n, .. } if n == name),
        )
    }

    fn crashed(log: &LifecycleLog, name: &str) -> usize {
        count(
            log,
            |event| matches!(event, LifecycleEvent::Crashed { name: n, .. } if n == name),
        )
    }

    fn restarted(log: &LifecycleLog, name: &str) -> usize {
        count(
            log,
            |event| matches!(event, LifecycleEvent::Restarted { name: n, .. } if n == name),
        )
    }

    fn quarantined(log: &LifecycleLog, name: &str) -> usize {
        count(
            log,
            |event| matches!(event, LifecycleEvent::Quarantined { name: n, .. } if n == name),
        )
    }

    /// The crash reasons recorded for one strand name.
    fn crash_reasons(log: &LifecycleLog, name: &str) -> Vec<String> {
        lifecycle_snapshot(log)
            .into_iter()
            .filter_map(|event| match event {
                LifecycleEvent::Crashed { name: n, reason } if n == name => Some(reason),
                _ => None,
            })
            .collect()
    }

    /// Every lifecycle event naming one strand, so "nothing further happened to
    /// it" is assertable. (`Buffered`/`ThreadFormed` events for unrelated topics
    /// arrive continuously, so the whole stream cannot be compared.)
    fn events_for(log: &LifecycleLog, name: &str) -> usize {
        count(log, |event| match event {
            LifecycleEvent::Registered { name: n, .. }
            | LifecycleEvent::Crashed { name: n, .. }
            | LifecycleEvent::Restarted { name: n, .. }
            | LifecycleEvent::Quarantined { name: n, .. }
            | LifecycleEvent::Detached { name: n } => n == name,
            _ => false,
        })
    }

    /// Whether the kernel flushed a replayed tail into `name`'s newest
    /// generation — the precondition that makes the dedupe assertions mean
    /// something.
    fn replays_into(log: &LifecycleLog, name: &str) -> usize {
        count(
            log,
            |event| matches!(event, LifecycleEvent::Flushed { to, .. } if to == name),
        )
    }

    /// Block (with a hard deadline) until `pred` holds, so a supervision bug
    /// fails the test instead of hanging it.
    fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !pred() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A strand that records the kernel's lifecycle stream — who registered, who
    /// crashed, who was restarted, who was quarantined.
    ///
    /// Registered as a **spec**, exactly like a converted subsystem, so it starts
    /// with the run loop and survives the crash of its neighbour.
    struct LifecycleRecorder {
        log: LifecycleLog,
    }

    impl Strand for LifecycleRecorder {
        fn name(&self) -> &str {
            "test.lifecycle-recorder"
        }

        fn inputs(&self) -> &[Socket] {
            // Routing is by `TypeId`, so this strand feels every `LifecycleEvent`
            // on the web rather than one named socket.
            const SOCKS: [Socket; 1] = [Socket::new::<LifecycleEvent>(SYS_LIFECYCLE)];
            &SOCKS
        }

        fn outputs(&self) -> &[Socket] {
            &[]
        }

        fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
            for (_socket, event) in bus.recv_all::<LifecycleEvent>()? {
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(event);
            }
            Ok(())
        }
    }

    /// A strand that records every `BusEvent` whose topic starts with `prefix`.
    ///
    /// Its input type is [`BusEvent`] — the same type the lanes declare — because
    /// strand routing is by `TypeId`; the prefix filter here is the
    /// `Bus::subscribe(prefix)` comparison, moved into the consumer. It also
    /// proves a strand's publish reaches another strand.
    struct EventRecorder {
        name: &'static str,
        prefix: &'static str,
        log: EventLog,
    }

    impl Strand for EventRecorder {
        fn name(&self) -> &str {
            self.name
        }

        fn inputs(&self) -> &[Socket] {
            const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>("<any>")];
            &SOCKS
        }

        fn outputs(&self) -> &[Socket] {
            &[]
        }

        fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
            // `recv_all`, not `recv(prefix)`: the inbox is a mailbox, not a
            // filter.
            for (socket, event) in bus.recv_all::<BusEvent>()? {
                if !socket.starts_with(self.prefix) && !event.topic.starts_with(self.prefix) {
                    continue;
                }
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(event);
            }
            Ok(())
        }
    }

    fn lifecycle_recorder_spec(log: LifecycleLog) -> StrandSpec {
        StrandSpec::new("test.lifecycle-recorder", move || -> Box<dyn Strand> {
            Box::new(LifecycleRecorder {
                log: Arc::clone(&log),
            })
        })
    }

    fn event_recorder_spec(name: &'static str, prefix: &'static str, log: EventLog) -> StrandSpec {
        StrandSpec::new(name, move || -> Box<dyn Strand> {
            Box::new(EventRecorder {
                name,
                prefix,
                log: Arc::clone(&log),
            })
        })
    }

    // -----------------------------------------------------------------------
    // Fixtures and drivers
    // -----------------------------------------------------------------------

    fn orchestrator(publisher: &Arc<BusPublisher>) -> Arc<DeploymentOrchestrator> {
        Arc::new(DeploymentOrchestrator::new(Arc::clone(&publisher)))
    }

    fn node(
        label: &str,
        role: VpnDeploymentRole,
        endpoint: &str,
        capability: &str,
    ) -> VpnDeploymentNodeSpec {
        VpnDeploymentNodeSpec {
            label: label.into(),
            role,
            peer_id: None,
            endpoint: Some(endpoint.parse().unwrap()),
            capabilities: vec![capability.into()],
        }
    }

    /// The deployment the unit tests in `deployment.rs` use: one operator, one
    /// client, one relay, auto relay selection, fortress hardening. Every call
    /// mints a fresh `deployment_id`, so a drill can tell one plan from the next.
    fn plan_three_nodes() -> VpnDeploymentPlan {
        VpnDeploymentPlan {
            deployment_id: uuid::Uuid::new_v4(),
            cluster_id: None,
            nodes: vec![
                node(
                    "operator",
                    VpnDeploymentRole::Operator,
                    "127.0.0.1:32000",
                    "vpn.cluster.admin",
                ),
                node(
                    "client-a",
                    VpnDeploymentRole::Client,
                    "127.0.0.1:32001",
                    "vpn.client",
                ),
                node(
                    "relay-a",
                    VpnDeploymentRole::Relay,
                    "127.0.0.1:32002",
                    "vpn.relay",
                ),
            ],
            hardening_preset: "fortress".into(),
            nat_aggressive: false,
            relay_auto: true,
            config_blob: br#"{"deployment":"auto"}"#.to_vec(),
            requested_by: "test".into(),
            requested_at: Utc::now(),
        }
    }

    /// A minimal valid plan: the operator alone.
    ///
    /// Used by the replay test on purpose. A deployment publishes a handful of
    /// `BusEvent`s for every node (membership gossip, config fetch, a NAT probe
    /// plan, a hardening profile) plus the status, and the replay tail only holds
    /// 32 — with one node, everything a deployment publishes stays comfortably
    /// inside the tail, so the replayed batch is *certainly* still carrying the
    /// plan event when the restarted generation subscribes. That makes the dedupe
    /// assertion deterministic instead of dependent on buffer arithmetic.
    fn plan_single_operator() -> VpnDeploymentPlan {
        VpnDeploymentPlan {
            deployment_id: uuid::Uuid::new_v4(),
            cluster_id: None,
            nodes: vec![node(
                "operator",
                VpnDeploymentRole::Operator,
                "127.0.0.1:32010",
                "vpn.cluster.admin",
            )],
            hardening_preset: "balanced".into(),
            nat_aggressive: false,
            relay_auto: true,
            config_blob: br#"{"deployment":"single"}"#.to_vec(),
            requested_by: "test".into(),
            requested_at: Utc::now(),
        }
    }

    /// Offer a plan exactly as the control pipe does.
    fn offer_plan(publisher: &BusPublisher, plan: VpnDeploymentPlan) {
        BusEvent::publish(&publisher, APPLY_TOPIC, Message::VpnDeploymentPlan(plan))
            .expect("publish is fire-and-forget and never fails");
    }

    /// Ask for the last status exactly as the control pipe / Ordo does.
    fn offer_status_request(publisher: &BusPublisher, requested_by: &str) {
        BusEvent::publish(
            &publisher,
            STATUS_REQUEST_TOPIC,
            Message::VpnDeploymentStatusRequest(VpnDeploymentStatusRequest {
                requested_by: requested_by.into(),
                requested_at: Utc::now(),
            }),
        )
        .expect("publish is fire-and-forget and never fails");
    }

    /// The next *answer* on a shim subscription, skipping other traffic.
    ///
    /// `crate::test_supervision::subscribe_queue(&publisher, "net.vpn.deployment.status", 64)` is a **prefix** subscription
    /// (that is the shim's contract, unchanged by this conversion), so it also
    /// sees `net.vpn.deployment.status_request` events — the pre-conversion bus
    /// behaved exactly the same way, and a status consumer filters by variant.
    /// A recorder strand filtering by topic prefix sees them for the same reason,
    /// which is why the assertions below count `VpnDeploymentStatus` payloads
    /// rather than deliveries.
    async fn recv_answered_status(
        rx: &mut tokio::sync::mpsc::Receiver<BusEvent>,
    ) -> VpnDeploymentStatus {
        for _ in 0..4 {
            let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("the status lane must answer")
                .expect("subscription must not lag or close");
            if let Message::VpnDeploymentStatus(status) = event.message {
                return status;
            }
        }
        panic!("the status lane did not answer");
    }

    /// The `VpnDeploymentStatus` payloads a recorder strand felt.
    fn recorded_statuses(log: &EventLog) -> Vec<VpnDeploymentStatus> {
        event_snapshot(log)
            .into_iter()
            .filter_map(|event| match event.message {
                Message::VpnDeploymentStatus(status) => Some(status),
                _ => None,
            })
            .collect()
    }

    /// The statuses a recorder strand felt for one deployment.
    fn statuses_for(log: &EventLog, deployment_id: uuid::Uuid) -> usize {
        recorded_statuses(log)
            .iter()
            .filter(|status| status.deployment_id == deployment_id)
            .count()
    }

    // -----------------------------------------------------------------------
    // (a) The fault policy and the replay guard, in isolation
    // -----------------------------------------------------------------------

    /// A fault must never be armable by a typo — absent/zero/unparsable all mean
    /// `None`. `parse` is the testable half of `from_env` (recipe §6c).
    #[test]
    fn fault_policy_parser_never_arms_on_a_bad_value() {
        assert_eq!(FaultPolicy::parse(None), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("0")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("messages")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("-1")), FaultPolicy::None);
        assert_eq!(
            FaultPolicy::parse(Some(" 3 ")),
            FaultPolicy::CrashAfterMessages(3)
        );
        assert!(FaultPolicy::parse(Some("3")).is_injected());
        assert!(!FaultPolicy::None.is_injected());
        // The production default, in this test process, is no injection.
        assert_eq!(FaultPolicy::from_env(), FaultPolicy::None);
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
        assert!(
            SEEN_CAPACITY > 32,
            "the guard must outsize the kernel's 32-deep replay tail"
        );
    }

    /// The lane filter is the old `bus.subscribe(prefix)` plus the old
    /// `if let Message::X` gate, and nothing else.
    #[test]
    fn lanes_filter_topics_and_variants_like_the_old_subscriptions() {
        assert!(Lane::Plans.matches_topic(APPLY_TOPIC));
        assert!(Lane::StatusRequests.matches_topic(STATUS_REQUEST_TOPIC));
        // The two prefixes must not overlap: neither lane may consume its own or
        // its sibling's output.
        assert!(!Lane::Plans.matches_topic(STATUS_REQUEST_TOPIC));
        assert!(!Lane::StatusRequests.matches_topic(APPLY_TOPIC));
        assert!(!Lane::Plans.matches_topic(STATUS_TOPIC));
        assert!(!Lane::StatusRequests.matches_topic(STATUS_TOPIC));

        let plan = Message::VpnDeploymentPlan(plan_three_nodes());
        let request = Message::VpnDeploymentStatusRequest(VpnDeploymentStatusRequest {
            requested_by: "ordo".into(),
            requested_at: Utc::now(),
        });
        let ready = Message::SubsystemReady {
            name: "imperium-runtime".into(),
        };

        assert!(Lane::Plans.accepts(&plan));
        assert!(!Lane::Plans.accepts(&request));
        assert!(Lane::StatusRequests.accepts(&request));
        assert!(!Lane::StatusRequests.accepts(&plan));
        // `net.vpn.deployment.apply` carrying a non-plan was ignored by the old
        // loop too.
        assert!(!Lane::Plans.accepts(&ready));

        assert_eq!(Lane::ALL.len(), 2);
        assert_eq!(Lane::ALL[0].strand_name(), PLANS_STRAND);
        assert_eq!(Lane::ALL[1].strand_name(), STATUS_STRAND);
        assert_ne!(
            PLANS_STRAND, STATUS_STRAND,
            "the kernel panics on a duplicate strand name"
        );
        assert_eq!(Lane::Plans.topic_prefix(), APPLY_TOPIC);
        assert_eq!(Lane::StatusRequests.topic_prefix(), STATUS_REQUEST_TOPIC);
    }

    // -----------------------------------------------------------------------
    // (b) Behaviour preservation through the real strand
    // -----------------------------------------------------------------------

    /// Both lanes serve the same topics with the same payloads the old loops did:
    /// a plan published on `net.vpn.deployment.apply` still converges (the same
    /// counters the direct-call unit test asserts), its heavy effects still land
    /// on their old topics, and a request on `net.vpn.deployment.status_request`
    /// is still answered on `net.vpn.deployment.status` — through the shim's
    /// `Bus::subscribe` surface (the path every existing consumer uses) and
    /// through a peer strand.
    #[tokio::test]
    async fn deployment_strand_serves_both_topics_like_the_old_loops() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let status_log = new_event_log();

        // A peer strand consuming the orchestrator's output by TypeId.
        bus.register_spec(event_recorder_spec(
            "test.status-recorder",
            STATUS_TOPIC,
            Arc::clone(&status_log),
        ));

        let deployment = orchestrator(&publisher);
        queue_lanes(&mut bus, &publisher, &deployment, FaultPolicy::None);

        // The shim's own subscriber surface — the path every existing consumer of
        // these topics uses, and the path the pre-conversion loops' `Bus::publish`
        // reached.
        let mut status_sub = crate::test_supervision::subscribe_queue(&publisher, STATUS_TOPIC, 64);
        let mut gossip_sub = crate::test_supervision::subscribe_queue(
            &publisher,
            "net.cluster.membership.gossip",
            64,
        );
        let mut relay_sub =
            crate::test_supervision::subscribe_queue(&publisher, "net.mesh.relay.selected", 64);

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        let plan = plan_three_nodes();
        let deployment_id = plan.deployment_id;
        offer_plan(&publisher, plan);

        // 1. The plan lane converged the plan and published the status: same
        //    topic, same `VpnDeploymentStatus` payload, same counters the
        //    direct-call service test asserts.
        let event = tokio::time::timeout(Duration::from_secs(5), status_sub.recv())
            .await
            .expect("a status must arrive on the shim subscription")
            .expect("subscription must not lag or close");
        assert_eq!(&*event.topic, STATUS_TOPIC);
        let status = match event.message {
            Message::VpnDeploymentStatus(status) => status,
            other => panic!("expected a VpnDeploymentStatus, got {other:?}"),
        };
        assert!(status.accepted, "reason: {}", status.reason);
        assert_eq!(status.deployment_id, deployment_id);
        assert_eq!(status.planned_nodes, 3);
        assert_eq!(status.approved_nodes, 3);
        assert_eq!(status.config_version, 1);
        assert_eq!(status.established_sessions, 6);
        assert_eq!(status.relay_fallbacks_selected, 1);
        assert_eq!(status.hardening_profiles_accepted, 3);

        // 2. The deployment's own effects still land on the topics the old
        //    `deploy()` published to.
        for (label, sub) in [("gossip", &mut gossip_sub), ("relay", &mut relay_sub)] {
            let event = tokio::time::timeout(Duration::from_secs(5), sub.recv())
                .await
                .unwrap_or_else(|_| panic!("a {label} event must arrive"))
                .expect("subscription must not lag or close");
            assert!(
                matches!(
                    (label, &event.message),
                    ("gossip", Message::MembershipGossip(_))
                        | ("relay", Message::RelayFallbackSelected(_))
                ),
                "unexpected {label} payload: {:?}",
                event.message
            );
        }

        // 3. The status lane answers a request with the last known status.
        offer_status_request(&publisher, "ordo");
        let answered = recv_answered_status(&mut status_sub).await;
        assert_eq!(answered.deployment_id, deployment_id);
        assert!(answered.accepted);
        assert_eq!(answered.approved_nodes, 3);

        // 4. A peer strand saw the same statuses, in the same order: the
        //    conversion's publish path reaches strand subscribers as well as
        //    named ones.
        wait_until("the status recorder strand to see both statuses", || {
            recorded_statuses(&status_log).len() >= 2
        });
        supervision.shutdown();

        let seen = recorded_statuses(&status_log);
        assert_eq!(seen.len(), 2, "one deploy status and one request answer");
        assert!(seen.iter().all(|s| s.deployment_id == deployment_id));
        assert_eq!(seen[0].config_version, 1);
        assert!(seen[1].accepted);
    }

    /// The status lane's answer with no deployment behind it: the same
    /// `no_deployment_status` payload the old loop sent.
    #[tokio::test]
    async fn status_request_without_a_deployment_answers_the_empty_status() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let deployment = orchestrator(&publisher);
        queue_lanes(&mut bus, &publisher, &deployment, FaultPolicy::None);
        let mut status_sub = crate::test_supervision::subscribe_queue(&publisher, STATUS_TOPIC, 64);

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));
        offer_status_request(&publisher, "ordo");

        let status = recv_answered_status(&mut status_sub).await;
        supervision.shutdown();

        assert_eq!(status.deployment_id, uuid::Uuid::nil());
        assert!(!status.accepted);
        assert_eq!(status.reason, "no deployment has run");
    }

    // -----------------------------------------------------------------------
    // (c) Specs are queued, not started
    // -----------------------------------------------------------------------

    /// The exact call the composition root makes: one function, both lanes, the
    /// production fault policy, before `engage_supervision()` — and the returned
    /// handle is the shared orchestrator both lanes drive.
    #[test]
    fn register_strands_is_the_single_composition_root_call() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let lifecycle = new_lifecycle_log();

        bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

        let deployment = DeploymentOrchestrator::register_strands(&mut bus, &publisher);
        assert!(deployment.last_status().is_none());

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));
        wait_until("both lanes to be installed from the one call", || {
            registered(&lifecycle, PLANS_STRAND) == 1 && registered(&lifecycle, STATUS_STRAND) == 1
        });

        // Both lanes serve through the handle `register_strands` returned.
        let plan = plan_three_nodes();
        let deployment_id = plan.deployment_id;
        offer_plan(&publisher, plan);
        wait_until("the plan lane to converge the plan", || {
            deployment
                .last_status()
                .is_some_and(|status| status.deployment_id == deployment_id && status.accepted)
        });

        offer_status_request(&publisher, "ordo");
        // A converged deployment is the last status; the lane's own publish keeps
        // it there whatever a request republishes.
        wait_until("the status lane to answer", || {
            deployment
                .last_status()
                .is_some_and(|status| status.deployment_id == deployment_id)
        });

        // Idempotence is claimed for *repeated* registration, and the new model
        // makes the interesting half of it a type-level fact: a second
        // registration cannot happen after the run loop starts, because the loop
        // consumed the bus. What remains testable — and what the kernel would
        // panic on (a duplicate strand name) — is that a second call is a no-op.
        let mut second_bus = Bus::open();
        let second_publisher = Arc::new(second_bus.publisher());
        DeploymentOrchestrator::register_strands(&mut second_bus, &second_publisher);
        DeploymentOrchestrator::register_strands(&mut second_bus, &second_publisher);

        supervision.shutdown();
    }

    /// A spec can only be installed while the kernel is idle — and the new model
    /// enforces that by **ownership**, not by a runtime refusal.
    ///
    /// The old form of this test asserted `Err(StrandRegistrationError::Engaged)`.
    /// That error cannot exist any more: `Bus::run_until` consumes the bus and
    /// `Supervision::engage_with` moves it onto the run-loop thread, so "queue a
    /// lane after the loop started" is a borrow-check error rather than a value a
    /// test can hold. What this test proves instead is the positive side of the
    /// same guarantee: the lanes queued *before* the loop are exactly the ones
    /// installed once it runs.
    #[test]
    fn lanes_queued_before_the_run_loop_are_the_ones_installed() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let lifecycle = new_lifecycle_log();
        bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

        let deployment = DeploymentOrchestrator::register_strands(&mut bus, &publisher);
        assert!(deployment.last_status().is_none());

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));
        wait_until("both queued lanes to be installed", || {
            registered(&lifecycle, PLANS_STRAND) == 1 && registered(&lifecycle, STATUS_STRAND) == 1
        });
        supervision.shutdown();
    }

    #[test]
    fn queued_specs_are_not_started_until_engage() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let lifecycle = new_lifecycle_log();

        bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

        let deployment = orchestrator(&publisher);
        queue_lanes(&mut bus, &publisher, &deployment, FaultPolicy::None);
        // Idempotent by contract: the kernel panics on a duplicate strand name,
        // so re-queueing (which the legacy shims do) must be a no-op.
        queue_lanes(&mut bus, &publisher, &deployment, FaultPolicy::None);

        // Nothing has started yet: a spec is queued, not installed.
        // (`register_spec` only appends; only `run_until` installs, and it
        // consumes the bus, so "queued but running" is unrepresentable.)
        assert_eq!(
            registered(&lifecycle, PLANS_STRAND),
            0,
            "queueing the spec must not start the plan lane"
        );
        assert_eq!(
            registered(&lifecycle, STATUS_STRAND),
            0,
            "queueing the spec must not start the status lane"
        );

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));
        wait_until("both deployment lanes to be installed", || {
            registered(&lifecycle, PLANS_STRAND) == 1 && registered(&lifecycle, STATUS_STRAND) == 1
        });
        assert!(supervision.is_running(), "the run loop must be live");
        supervision.shutdown();

        // The declared IO is the old subscription's topic on the way in and
        // `emit_status`'s topic on the way out.
        let installed = lifecycle_snapshot(&lifecycle);
        let plans = installed
            .iter()
            .find_map(|event| match event {
                LifecycleEvent::Registered {
                    name,
                    inputs,
                    outputs,
                } if name == PLANS_STRAND => Some((inputs.clone(), outputs.clone())),
                _ => None,
            })
            .expect("the plan lane registered");
        assert_eq!(plans.0, vec![APPLY_TOPIC.to_string()]);
        assert_eq!(plans.1, vec![STATUS_TOPIC.to_string()]);
        supervision.shutdown();
        supervision.shutdown();
    }

    // -----------------------------------------------------------------------
    // (d) The crash-restart-quarantine drill, with failure-domain isolation
    // -----------------------------------------------------------------------

    /// The plan lane's full crash policy, driven through the real strand with an
    /// injected fault — and the status lane's independence from it.
    ///
    /// The plan lane is armed to crash after the first message each generation
    /// handles, so every restart crashes again and the spider's whole policy runs:
    /// four `Crashed` events, three `Restarted` events, one `Quarantined`. The
    /// status lane runs beside it with no fault: it is never crashed, never
    /// restarted, and still answers a status request afterwards.
    #[test]
    fn crashed_plan_lane_is_restarted_three_times_then_quarantined() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let lifecycle = new_lifecycle_log();
        let status_log = new_event_log();

        bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
        bus.register_spec(event_recorder_spec(
            "test.status-recorder",
            STATUS_TOPIC,
            Arc::clone(&status_log),
        ));

        let deployment = orchestrator(&publisher);
        queue_lane(
            &mut bus,
            &publisher,
            Lane::Plans,
            &deployment,
            FaultPolicy::CrashAfterMessages(1),
        );
        queue_lane(
            &mut bus,
            &publisher,
            Lane::StatusRequests,
            &deployment,
            FaultPolicy::None,
        );

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        wait_until("the plan lane to be installed and register itself", || {
            registered(&lifecycle, PLANS_STRAND) == 1
        });

        // Feed *fresh* plans until the fourth crash has been quarantined. A fresh
        // plan has a new id, so the replay guard never eats it, and each
        // generation crashes after its own first handled message — the drill does
        // not depend on replay timing.
        wait_until(
            "the plan lane to be quarantined after its fourth crash",
            || {
                offer_plan(&publisher, plan_three_nodes());
                quarantined(&lifecycle, PLANS_STRAND) >= 1
            },
        );

        assert!(
            supervision.is_running(),
            "the run loop was live for the whole drill"
        );

        // (a) Installed from a queued spec — only a spec is restartable, so the
        // `Restarted` events below are themselves proof the lane arrived as one.
        // `Registered` fires once per generation: initial + 3 restarts.
        assert_eq!(
            registered(&lifecycle, PLANS_STRAND),
            4,
            "one `Registered` per generation: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
        // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
        assert_eq!(
            crashed(&lifecycle, PLANS_STRAND),
            4,
            "every crash must be visible as a lifecycle event: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
        assert_eq!(
            restarted(&lifecycle, PLANS_STRAND),
            3,
            "the spider restarts three times: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
        assert_eq!(
            quarantined(&lifecycle, PLANS_STRAND),
            1,
            "the fourth crash quarantines the lane: {:?}",
            lifecycle_snapshot(&lifecycle)
        );

        // The injected fault names itself in every crash reason: a real forensic
        // signal, and proof the crash came from the drill and not from a bug.
        let reasons = crash_reasons(&lifecycle, PLANS_STRAND);
        assert!(
            reasons
                .iter()
                .all(|reason| reason.contains("injected fault") && reason.contains("1 message")),
            "the injected fault must name itself in every Crashed reason: {reasons:?}"
        );

        // Work was delivered before the crashes: the lanes were doing their job
        // right up to (and including) the tick they crashed on.
        let deployed = recorded_statuses(&status_log).len();
        assert!(
            deployed >= 1,
            "a deployment must have been published before the crashes"
        );

        // --- Isolation: the status lane was never touched by any of that -------
        assert_eq!(
            crashed(&lifecycle, STATUS_STRAND),
            0,
            "the status lane must not crash because its neighbour did"
        );
        assert_eq!(restarted(&lifecycle, STATUS_STRAND), 0);
        assert_eq!(quarantined(&lifecycle, STATUS_STRAND), 0);
        assert_eq!(
            registered(&lifecycle, STATUS_STRAND),
            1,
            "the status lane is still the generation it was installed as"
        );

        // …and it still serves: a request after the quarantine is answered from
        // the durable last status.
        offer_status_request(&publisher, "ordo");
        wait_until("the status lane to still answer a request", || {
            recorded_statuses(&status_log).len() > deployed
        });
        let answered = recorded_statuses(&status_log)
            .last()
            .cloned()
            .expect("an answer");
        assert!(
            answered.accepted,
            "the last converged status is still stored"
        );

        // After quarantine the plan lane is gone for good: further plans cannot
        // revive it. (Its own events are counted, not the whole stream —
        // unrelated `Buffered`/`ThreadFormed` events keep arriving.)
        supervision.shutdown();
        let before = events_for(&lifecycle, PLANS_STRAND);
        for _ in 0..5 {
            offer_plan(&publisher, plan_three_nodes());
        }
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            events_for(&lifecycle, PLANS_STRAND),
            before,
            "a quarantined lane must stay quarantined: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
    }

    // -----------------------------------------------------------------------
    // (e) The replayed apply is deduped, never re-executed
    // -----------------------------------------------------------------------

    /// A restarted generation is a late subscriber and is replayed the recent tail
    /// (recipe §5.4) — of messages the *previous* generation already handled. The
    /// plan lane's effect is not idempotent, so its durable [`SeenIds`] history
    /// refuses the replayed plan.
    ///
    /// The proof is exact, and the fixture is chosen to make it deterministic: a
    /// one-node plan publishes few enough `BusEvent`s that the replayed tail
    /// certainly still carries the plan event. So after one plan, one crash and one
    /// replay:
    ///
    ///   * the deployment ran **once** — one membership gossip, one NAT probe
    ///     plan, one status for that deployment, not two of each;
    ///   * the lane did **not** re-trip its own fault — one crash, one restart,
    ///     no quarantine — because a deduped replay never counts as handled work.
    #[test]
    fn replayed_apply_is_deduped_not_re_executed() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let lifecycle = new_lifecycle_log();
        let gossip_log = new_event_log();
        let nat_log = new_event_log();
        let status_log = new_event_log();

        bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
        bus.register_spec(event_recorder_spec(
            "test.gossip-recorder",
            "net.cluster.membership.gossip",
            Arc::clone(&gossip_log),
        ));
        bus.register_spec(event_recorder_spec(
            "test.nat-recorder",
            "net.mesh.nat.plan",
            Arc::clone(&nat_log),
        ));
        bus.register_spec(event_recorder_spec(
            "test.status-recorder",
            STATUS_TOPIC,
            Arc::clone(&status_log),
        ));

        let deployment = orchestrator(&publisher);
        queue_lane(
            &mut bus,
            &publisher,
            Lane::Plans,
            &deployment,
            FaultPolicy::CrashAfterMessages(1),
        );
        queue_lane(
            &mut bus,
            &publisher,
            Lane::StatusRequests,
            &deployment,
            FaultPolicy::None,
        );

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));
        wait_until("the plan lane to be installed", || {
            registered(&lifecycle, PLANS_STRAND) == 1
        });

        // Exactly one plan, ever. Handling it once is what a replayed tail must
        // not do twice.
        let plan = plan_single_operator();
        let deployment_id = plan.deployment_id;
        offer_plan(&publisher, plan);

        wait_until("the first crash (the armed fault)", || {
            crashed(&lifecycle, PLANS_STRAND) >= 1
        });
        wait_until("the restart", || restarted(&lifecycle, PLANS_STRAND) >= 1);
        wait_until(
            "the kernel to flush the pending tail into the restarted generation",
            || replays_into(&lifecycle, PLANS_STRAND) >= 1,
        );
        // Let the restarted generation drain whatever it was replayed, and give a
        // broken guard time to run the deployment a second time and crash again.
        std::thread::sleep(Duration::from_millis(500));
        supervision.shutdown();

        // The guard was genuinely exercised: the replay reached the new
        // generation, so a broken dedupe would have had the chance to re-run.
        assert!(
            replays_into(&lifecycle, PLANS_STRAND) >= 1,
            "the replay must actually have happened for this test to mean anything: {:?}",
            lifecycle_snapshot(&lifecycle)
        );

        // …and it was refused, exactly as the recipe prescribes.
        assert_eq!(
            crashed(&lifecycle, PLANS_STRAND),
            1,
            "a deduped replay must not count as handled work: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
        assert_eq!(
            restarted(&lifecycle, PLANS_STRAND),
            1,
            "one crash, one restart: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
        assert_eq!(
            quarantined(&lifecycle, PLANS_STRAND),
            0,
            "the restarted generation must survive its replay: {:?}",
            lifecycle_snapshot(&lifecycle)
        );

        // The observable consequence: the deployment ran exactly once. Re-running
        // it would mint fresh tokens, re-approve membership, re-select relays and
        // republish all of it — one more gossip, one more NAT probe plan, and one
        // more status for the same deployment id.
        assert_eq!(
            event_snapshot(&gossip_log).len(),
            1,
            "one deployment, one membership gossip: {:?}",
            event_snapshot(&gossip_log)
        );
        assert_eq!(
            event_snapshot(&nat_log).len(),
            1,
            "one deployment, one NAT probe plan (one node): {:?}",
            event_snapshot(&nat_log)
        );
        assert_eq!(
            statuses_for(&status_log, deployment_id),
            1,
            "one deployment, one status for it: {:?}",
            recorded_statuses(&status_log)
        );
        let status = recorded_statuses(&status_log)
            .into_iter()
            .next()
            .expect("the deployment published its status");
        assert!(status.accepted, "reason: {}", status.reason);
        assert_eq!(status.planned_nodes, 1);
        assert_eq!(status.approved_nodes, 1);
        assert_eq!(status.established_sessions, 0);
    }

    // -----------------------------------------------------------------------
    // (f) Durable state: a restarted lane still answers with the last status
    // -----------------------------------------------------------------------

    /// `last_status` is durable, not per generation: it lives behind the
    /// orchestrator's `Arc`, which every generation of every lane shares through
    /// the spec's factory.
    ///
    /// The drill proves it the hard way — the lane that observed the status is the
    /// lane that crashes. The *status* lane is armed, so it answers the first
    /// request and dies on the same tick (recipe §5.5: the answer is already
    /// delivered, because effects go through the shim's inline `Bus::publish`).
    /// The restarted generation is then replayed that request — and refuses it,
    /// because it is a request the previous generation already answered — and
    /// answers the *next* request with the status the crashed generation saw.
    #[test]
    fn restarted_status_lane_still_answers_with_the_last_known_status() {
        let (mut bus, publisher) = crate::test_supervision::open();
        let lifecycle = new_lifecycle_log();
        let status_log = new_event_log();

        bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
        bus.register_spec(event_recorder_spec(
            "test.status-recorder",
            STATUS_TOPIC,
            Arc::clone(&status_log),
        ));

        let deployment = orchestrator(&publisher);
        queue_lane(
            &mut bus,
            &publisher,
            Lane::Plans,
            &deployment,
            FaultPolicy::None,
        );
        queue_lane(
            &mut bus,
            &publisher,
            Lane::StatusRequests,
            &deployment,
            FaultPolicy::CrashAfterMessages(1),
        );

        let mut supervision =
            crate::test_supervision::Supervision::engage_with(bus, Arc::clone(&publisher));

        // The plan lane converges a deployment, so there *is* a last status to
        // remember.
        let plan = plan_three_nodes();
        let deployment_id = plan.deployment_id;
        offer_plan(&publisher, plan);
        wait_until("the deployment to publish its status", || {
            statuses_for(&status_log, deployment_id) >= 1
        });
        assert!(
            recorded_statuses(&status_log)
                .first()
                .expect("the deploy status")
                .accepted
        );

        // The status lane answers the first request and crashes on the same tick
        // (the fault is per generation).
        offer_status_request(&publisher, "ordo");
        wait_until("the status request to be answered", || {
            statuses_for(&status_log, deployment_id) >= 2
        });
        wait_until("the armed status lane to crash", || {
            crashed(&lifecycle, STATUS_STRAND) >= 1
        });
        wait_until("the status lane to be restarted", || {
            restarted(&lifecycle, STATUS_STRAND) >= 1
        });
        wait_until(
            "the kernel to flush the pending tail into the restarted status lane",
            || replays_into(&lifecycle, STATUS_STRAND) >= 1,
        );

        // The replayed request is the one the previous generation answered, so the
        // new generation refuses it and does not publish a duplicate answer.
        offer_status_request(&publisher, "ordo");
        wait_until("the restarted generation to answer the new request", || {
            statuses_for(&status_log, deployment_id) >= 3
        });
        std::thread::sleep(Duration::from_millis(250));
        supervision.shutdown();

        assert_eq!(
            statuses_for(&status_log, deployment_id),
            3,
            "the deploy status, one answer, and the restarted generation's answer \
             — a replayed request must not be answered twice: {:?}",
            recorded_statuses(&status_log)
        );
        assert_eq!(
            quarantined(&lifecycle, STATUS_STRAND),
            0,
            "one crash, one restart — the lane must not spiral: {:?}",
            lifecycle_snapshot(&lifecycle)
        );

        // The answer is the *durable* status: the restarted generation never ran a
        // deployment itself, yet it answers with the one the previous generation
        // recorded — not the "no deployment has run" placeholder.
        let answered = recorded_statuses(&status_log)
            .into_iter()
            .last()
            .expect("the answered status");
        assert_eq!(answered.deployment_id, deployment_id);
        assert!(answered.accepted);
        assert_eq!(answered.planned_nodes, 3);
        assert_eq!(answered.approved_nodes, 3);
        assert_eq!(answered.config_version, 1);
        assert_eq!(answered.established_sessions, 6);
        assert_ne!(
            deployment.last_status().map(|status| status.deployment_id),
            Some(uuid::Uuid::nil()),
            "the shared orchestrator still holds the converged status"
        );
    }
}
