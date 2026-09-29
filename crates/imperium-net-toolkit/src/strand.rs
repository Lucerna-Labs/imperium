//! The tool-activation loop as a supervised Spiderweb **strand**.
//!
//! This loop used to be a `tokio::spawn`ed task holding a
//! [`BusSubscription`](spiderweb::BusPublisher) for
//! [`topics::REQUEST`]: every `net.toolkit.request` message ran
//! [`ToolManager::activate`](crate::ToolManager::activate) (state gate, cooldown
//! gate, per-tool hourly budget, then the state change and the activation
//! request out). It is now a [`Strand`](spiderweb::Strand) registered
//! through [`Bus::register_spec`](spiderweb::Bus::register_spec), so the
//! spider owns it: a crash becomes a `LifecycleEvent::Crashed`, the spider
//! restarts it three times, and the fourth crash quarantines it. See
//! the pilot (`imperium-net-lightcone`) for the general recipe,
//! `crates/imperium-net-lightcone/src/strand.rs` for the pilot, and
//! `crates/imperium-net-transport/src/strand.rs` for the two-lane version of the
//! same shape.
//!
//! # What is (and is not) preserved
//!
//! The strand is a thin adapter over [`ToolManager`]: the same method runs, in
//! the same order, with the same topic in and the same topics out. The manager
//! publishes its own state changes and activation requests through the shim's
//! `BusPublisher::publish`, exactly as the old task did, so
//! `net.toolkit.state` / `net.toolkit.activation` reach the same subscribers
//! with the same payloads and the same `BusEvent::new` semantics.
//!
//! Three mechanics change, all deliberately:
//!
//! * **Filtering moves into the strand.** Spiderweb routes strand deliveries by
//!   `TypeId`, not by socket name: a strand declaring a [`BusEvent`] input
//!   receives *every* `BusEvent` on the bus, so the old kernel-side prefix
//!   filter (`bus.subscribe(topics::REQUEST)`) becomes the
//!   `event.topic.starts_with(topics::REQUEST)` test in [`run`](Strand::run) —
//!   the same comparison on the other side of the bus. The old loop's
//!   `if let Message::ToolActivationReq(..)` gate is preserved verbatim: any
//!   other payload on that prefix was ignored then, and is ignored now.
//! * **The pending-buffer replay is deduped.** The kernel keeps a bounded tail
//!   (32 messages per `TypeId`) and flushes it to a late subscriber — and a
//!   restarted strand is a late subscriber. Activation is **not** idempotent: it
//!   consumes a slot of a per-tool hourly budget, stamps `last_activity`, moves
//!   the tool to `Active`, and publishes a state change plus an activation
//!   request. A replayed request must therefore not be handled a second time, so
//!   the strand dedupes on `BusEvent::id` through a record shared by every
//!   generation (a *fresh* record per generation could not recognise the
//!   replayed tail — see [`SeenIds`]). Without a crash the record changes
//!   nothing: every publish mints a fresh id, so every real request is still
//!   handled exactly once.
//! * **Ownership.** The `Arc<ToolManager>` (and, through it, its `Arc<Bus>`) is
//!   moved into the spec factory, so every generation drives the *same* tool
//!   table the composition root registered its manifests on — restart resumes
//!   budgets and cooldowns instead of reloading a fresh table. The fault policy
//!   and the handled counter are per-generation fields, so a restart resets the
//!   drill.
//!
//! One line of the old loop has no successor: its `Err(BusError::Lagged)` arm.
//! A strand has no lagging subscription to warn about — the kernel delivers into
//! its inbox and the strand drains it with `recv_all` — so there is nothing to
//! report there. Nothing observable is lost: the lag warning was a delivery
//! detail of the old subscription, not part of the loop's contract.
//!
//! # The tick also reconciles processes
//!
//! Since tools can run real processes, a tick does one thing beyond serving
//! requests: it calls [`ToolManager::tick`](crate::ToolManager::tick), the
//! manager's reconciliation step. That is where a tool whose process has ended —
//! stopped by its idle timeout or its runtime budget, or simply exited — leaves
//! `Active` and cools down, and it is the only place tool state is written
//! outside an operator call, so the table keeps one writer.
//!
//! The processes themselves are owned by a supervisor thread on the manager, not
//! by this strand (see `src/proc.rs`): nothing in `run` awaits, blocks on, or
//! even touches a `ManagedProcess`. Two consequences worth naming: a restarted
//! generation resumes supervision of the *same* processes rather than stranding
//! or duplicating them, and a quarantined strand stops reconciling state (the
//! supervisor still enforces the deadlines and still stops the processes, but
//! the state changes they imply are not published) — supervision of the loop and
//! supervision of its subprocesses are deliberately separate concerns.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, OnceLock, Weak};

use imperium_protocol::{BusEvent, Message};
use parking_lot::Mutex;
use spiderweb::{Bus, BusPublisher};
use spiderweb::{BusHandle, Socket, Strand, StrandError, StrandSpec};

use crate::ToolManager;

/// Strand name. Fixed, `&'static str` (Spiderweb requires it), and equal to the
/// subsystem name in the `net.toolkit.ready` message, so one identifier works in
/// the topic table, the kernel log, and the spider log (recipe §5.8).
pub const NAME: &str = "imperium-net-toolkit";

/// The bus topics of this loop, unchanged from the `tokio::spawn` version.
pub mod topics {
    /// Consumed by the strand (prefix match, as the old `bus.subscribe` was).
    pub const REQUEST: &str = "net.toolkit.request";
    /// Published by the manager when a tool is activated.
    pub const ACTIVATION: &str = "net.toolkit.activation";
    /// Published by the manager on every state change.
    pub const STATE: &str = "net.toolkit.state";
}

/// Environment variable that arms a deliberate fault, for supervision drills:
/// `IMPERIUM_TOOLKIT_CRASH_AFTER_REQUESTS=<n>` makes every strand instance
/// return [`StrandError::Crashed`] once it has observed `n` activation requests.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. It exists so the restart/quarantine path can be exercised
/// end-to-end against the real strand instead of a stand-in, and so an operator
/// can drill the supervisor on a live node.
pub const CRASH_AFTER_REQUESTS_ENV: &str = "IMPERIUM_TOOLKIT_CRASH_AFTER_REQUESTS";

/// How many recently handled `BusEvent.id`s the replay guard remembers.
///
/// The kernel's replay tail is 32 messages per `TypeId` (recipe §5.4); 256 is
/// eight times that, so a restart cannot out-run the guard even if a burst of
/// `BusEvent`s of other kinds separates this loop's own messages in the tail.
/// See [`SeenIds`] for why the capacity must stay *above* the tail rather than
/// merely equal to it.
pub const SEEN_CAPACITY: usize = 256;

/// How a toolkit strand instance should fault, for drills and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Serve activation requests normally. The production default.
    #[default]
    None,
    /// Deliberately crash after observing `n` activation requests. The count is
    /// per strand *instance*, so a restarted instance crashes again after its own
    /// `n`th request — which is what lets a drill drive the full
    /// crash → restart ×3 → quarantine sequence.
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
        match raw
            .map(str::trim)
            .and_then(|value| value.parse::<u32>().ok())
        {
            Some(n) if n > 0 => FaultPolicy::CrashAfterRequests(n),
            _ => FaultPolicy::None,
        }
    }

    /// Whether this policy injects a fault (used to warn loudly at boot).
    pub fn is_injected(&self) -> bool {
        !matches!(self, FaultPolicy::None)
    }

    /// The crash reason for an instance that has just handled `handled`
    /// requests, or `None` while this instance should keep running.
    fn tripped(&self, handled: u32) -> Option<String> {
        match self {
            FaultPolicy::None => None,
            FaultPolicy::CrashAfterRequests(n) if handled >= *n => Some(format!(
                "injected fault: crashed after {handled} request(s) ({CRASH_AFTER_REQUESTS_ENV} = {n})"
            )),
            FaultPolicy::CrashAfterRequests(_) => None,
        }
    }
}

/// Durable, bounded record of the `BusEvent` ids this loop has already handled.
///
/// Deliberately **not** per generation. A restarted strand is a late subscriber
/// and the kernel replays it the recent tail — of messages the *previous*
/// generation already handled. A per-generation record would be empty at exactly
/// the moment it is needed, and handling an activation twice is not idempotent
/// (see the module docs), so the record is shared by every generation of this
/// loop through the spec's factory: durable state, shared through the `Arc`,
/// exactly like the manager itself (recipe §3.2).
///
/// `EventId` wraps a `Uuid`, so ids are neither ordered nor monotonic — a
/// "highest id seen" watermark would drop legitimate events. A bounded set of
/// the most recent ids is exact for the replay it must defeat and cannot grow
/// without bound.
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
    /// one already handled.
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

/// The tool-activation loop as a strand.
///
/// Owns its state: the manager is shared with whatever built it (`Arc`, so a
/// restart resumes the same tool table, budgets and cooldowns), the seen-set is
/// shared by every generation (so a restart still recognises the replay), and
/// the fault policy and handled counter are per instance (so a restart resets
/// the drill). Nothing is borrowed from outside, which is what makes the strand
/// restartable — the kernel's factory call produces a fresh, independent
/// instance.
pub struct ToolkitStrand {
    manager: Arc<ToolManager>,
    seen: Arc<SeenIds>,
    faults: FaultPolicy,
    /// Requests this *instance* has handled. Per-instance by construction, so a
    /// restart resets it.
    handled: u32,
}

impl ToolkitStrand {
    fn new(manager: Arc<ToolManager>, seen: Arc<SeenIds>, faults: FaultPolicy) -> Self {
        Self {
            manager,
            seen,
            faults,
            handled: 0,
        }
    }

    /// The restartable spec for this loop, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec). Prefer
    /// [`queue_strand`], which is idempotent.
    ///
    /// The factory captures an `Arc<ToolManager>` clone, so every restarted
    /// instance drives the same tool table — the manifests, budgets and cooldown
    /// clocks the composition root set up survive a crash. It also captures one
    /// [`SeenIds`] record, so the replayed pending tail is skipped rather than
    /// re-activated.
    pub fn spec(manager: Arc<ToolManager>, faults: FaultPolicy) -> StrandSpec {
        let seen = Arc::new(SeenIds::new());
        StrandSpec::new(NAME, move || -> Box<dyn Strand> {
            Box::new(ToolkitStrand::new(
                Arc::clone(&manager),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for ToolkitStrand {
    fn name(&self) -> &str {
        NAME
    }

    fn inputs(&self) -> &[Socket] {
        // The socket name is documentation for the lifecycle event and the web
        // graph; routing is by `BusEvent`'s `TypeId` (see the module docs).
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::REQUEST)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 2] = [
            Socket::new::<BusEvent>(topics::ACTIVATION),
            Socket::new::<BusEvent>(topics::STATE),
        ];
        &SOCKS
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick and
        // let the worker join (recipe §2). Nothing in this `run` blocks: the
        // manager's calls are synchronous state transitions, one bounded
        // snapshot read, and inline publishes — no subprocess is awaited here.
        // The tool processes themselves are stopped by the manager's supervisor
        // thread when the manager shuts down, not by this tick.
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on. Draining by socket name (`recv::<BusEvent>(name)`) would
        // leave every non-matching carrier in the inbox forever, growing it one
        // event per unrelated publish — the inbox is a mailbox, not a filter
        // (recipe §5.3). `?` is infallible in practice: the inbox only ever
        // holds payloads whose `TypeId` matched this strand's declared input,
        // and a genuine kernel fault still surfaces as `Crashed`.
        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            // The prefix filter the kernel used to apply for the old
            // `bus.subscribe(topics::REQUEST)` subscription (recipe §5.2).
            if !event.topic.starts_with(topics::REQUEST) {
                continue;
            }
            // The old loop ignored every other message kind on that prefix.
            if !matches!(event.message, Message::ToolActivationReq(_)) {
                continue;
            }
            // Replay guard (recipe §5.4): a restarted generation is replayed the
            // recent tail, which the previous generation already handled. The
            // record is durable, so the replay is recognised; without a crash
            // this never fires, because every publish mints a fresh id.
            if !self.seen.first_sight(event.id.0.as_u128()) {
                tracing::debug!(
                    event_id = ?event.id,
                    "skipping a replayed tool activation request already handled"
                );
                continue;
            }

            // The old loop body, verbatim: handle, and log-and-continue on error
            // (the errors this can produce are state/budget refusals and publish
            // failures; neither must turn a tick into a crash).
            if let Message::ToolActivationReq(ref request) = event.message {
                if let Err(error) = self.manager.activate(request) {
                    tracing::warn!(
                        tool_name = %request.tool_name,
                        trigger = %request.trigger,
                        error = %error,
                        "tool activation request rejected"
                    );
                }
            }

            self.handled = self.handled.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.handled) {
                // Diagnostic-only path; see `FaultPolicy`. Everything the manager
                // published (state change + activation request) goes through the
                // shim's inline `Bus::publish`, not the strand outbox, so a
                // `Crashed` tick loses no work (recipe §5.5).
                return Err(StrandError::Crashed(reason));
            }
        }

        // Reconcile the tool table with the processes that are actually
        // running: a tool whose process has ended (idle timeout, runtime
        // budget, or an unexpected exit) leaves `Active` and cools down here,
        // publishing the same `net.toolkit.state` change a deactivation does.
        // One snapshot read plus a transition per ended activation, and
        // idempotent — see `ToolManager::tick`.
        self.manager.tick();

        // Nothing else to do this tick. Returning `Ok(())` schedules another
        // tick (the worker paces them at 10 ms), which is this strand's idle
        // loop.
        Ok(())
    }
}

/// `(strand name, bus)` pairs already queued in this process.
///
/// Two registration paths exist while this conversion lands: the canonical
/// [`register_strands`] / [`ToolManager::register_strand`], and the legacy
/// [`subscribe_activation_requests`](crate::ToolManager::subscribe_activation_requests)
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
static QUEUED: OnceLock<Mutex<Vec<(&'static str, Weak<BusPublisher>, FaultPolicy)>>> =
    OnceLock::new();

fn queued_registry() -> &'static Mutex<Vec<(&'static str, Weak<BusPublisher>, FaultPolicy)>> {
    QUEUED.get_or_init(|| Mutex::new(Vec::new()))
}

/// The fault policy this strand was queued with on `bus`, if it already was.
fn queued_policy(publisher: &Arc<BusPublisher>) -> Option<FaultPolicy> {
    let mut entries = queued_registry().lock();
    entries.retain(|(_, queued_bus, _)| queued_bus.strong_count() > 0);
    let publisher = Arc::downgrade(publisher);
    entries
        .iter()
        .find(|(name, queued_publisher, _)| *name == NAME && queued_publisher.ptr_eq(&publisher))
        .map(|(_, _, policy)| *policy)
}

fn mark_queued(publisher: &Arc<BusPublisher>, faults: FaultPolicy) {
    queued_registry()
        .lock()
        .push((NAME, Arc::downgrade(publisher), faults));
}

/// Queue the toolkit strand on `bus`, at most once per bus.
///
/// Idempotent: a second call is a no-op — the first registration wins, and a
/// differing fault policy is warned about rather than silently ignored (a drill
/// that was never armed would otherwise look like a supervisor that did not
/// restart). So the legacy shim and [`register_strands`] can both run without
/// the kernel's collision panic. Returns
/// [`StrandRegistrationError::Engaged`] if the bus has already engaged — see
/// [`register_strands`] for the ordering contract.
pub fn queue_strand(
    bus: &mut Bus,
    publisher: &Arc<BusPublisher>,
    manager: &Arc<ToolManager>,
    faults: FaultPolicy,
) {
    if let Some(queued) = queued_policy(publisher) {
        if queued != faults {
            tracing::warn!(
                strand = NAME,
                queued = ?queued,
                requested = ?faults,
                "the toolkit strand was already queued with a different fault policy; \
                 the first registration wins"
            );
        }
        return;
    }
    bus.register_spec(ToolkitStrand::spec(Arc::clone(manager), faults));
    mark_queued(publisher, faults);
}

/// Register the toolkit's activation loop on `bus`, with the node's deployment
/// configuration.
///
/// This is the composition root's entry point (recipe §3.6): call it while the
/// bus is still idle, before `Bus::engage_supervision()`. The manager is passed
/// in (rather than built here) because the node that owns it registers the
/// tool manifests on it — the strand must drive *that* manager, not a fresh one.
///
/// The fault policy comes from [`CRASH_AFTER_REQUESTS_ENV`]; unset (the
/// production default) means no injection, and an armed drill is logged loudly.
pub fn register_strands(bus: &mut Bus, publisher: &Arc<BusPublisher>, manager: &Arc<ToolManager>) {
    let faults = FaultPolicy::from_env();
    if faults.is_injected() {
        // A deliberately armed fault must never look like a real one in the
        // logs, and must be impossible to leave on by accident without a trace.
        tracing::warn!(
            policy = ?faults,
            env = CRASH_AFTER_REQUESTS_ENV,
            "toolkit strand fault injection ARMED — the strand will crash on purpose"
        );
    }
    queue_strand(bus, publisher, manager, faults)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fault must never be armable by a typo — absent/zero/unparsable all mean
    /// `None`. `parse` is the testable half of `from_env` (recipe §6c).
    #[test]
    fn fault_policy_never_arms_on_a_bad_value() {
        assert_eq!(FaultPolicy::parse(None), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("   ")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("0")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("requests")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("-2")), FaultPolicy::None);
        assert_eq!(
            FaultPolicy::parse(Some(" 3 ")),
            FaultPolicy::CrashAfterRequests(3)
        );
        assert!(FaultPolicy::parse(Some("3")).is_injected());
        assert!(!FaultPolicy::None.is_injected());
    }

    #[test]
    fn fault_policy_trips_exactly_at_its_threshold() {
        let policy = FaultPolicy::CrashAfterRequests(2);
        assert_eq!(policy.tripped(0), None);
        assert_eq!(policy.tripped(1), None);
        let reason = policy.tripped(2).expect("trips at the threshold");
        assert!(
            reason.contains("injected fault") && reason.contains(CRASH_AFTER_REQUESTS_ENV),
            "the reason must name the drill that caused it: {reason}"
        );
        assert_eq!(FaultPolicy::None.tripped(99), None);
    }

    /// The replay guard: the first sighting is accepted, every repeat is not —
    /// and the memory stays bounded however long the loop runs.
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
        assert_eq!(seen.len(), SEEN_CAPACITY, "the record must stay bounded");
        assert!(
            seen.first_sight(1_000_000),
            "an id never seen before is still accepted"
        );
    }

    /// Size contract (recipe §5.4): the kernel replays its last 32 messages per
    /// `TypeId` to a restarted generation, so the durable record must remember
    /// strictly more than those 32 — a tail-sized record would let the oldest
    /// replayed message through, and handling an activation twice spends a
    /// second budget slot.
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
        // Every id of a full replay tail is still recognised *after* the tail
        // has been filled: nothing was evicted to make room for the tail itself.
        for id in &tail {
            assert!(
                !seen.first_sight(*id),
                "a full replay tail must be refused in its entirety"
            );
        }
        assert_eq!(seen.len(), KERNEL_REPLAY_TAIL);
    }
}
