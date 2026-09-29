//! The cluster's two standing recv loops as supervised Spiderweb **strands**.
//!
//! Both loops used to be `tokio::spawn`ed tasks holding a
//! [`BusSubscription`](spiderweb::BusPublisher):
//!
//! * [`MembershipManager::subscribe_membership_grants`](crate::MembershipManager::subscribe_membership_grants)
//!   consumed `net.cluster.membership.granted` and applied each
//!   [`MembershipGrant`](imperium_protocol::MembershipGrant) after verifying the
//!   operator's hybrid signature.
//! * [`ConfigManager::subscribe_config_responses`](crate::ConfigManager::subscribe_config_responses)
//!   consumed `net.cluster.config.fetch_response` and applied each
//!   [`ConfigurationFetchResponse`](imperium_protocol::ConfigurationFetchResponse)
//!   after verifying the operator's signature over `(data || version)`.
//!
//! They are now strands — [`MembershipGrantStrand`] and
//! [`ConfigResponseStrand`] — registered through
//! [`Bus::register_spec`](spiderweb::Bus::register_spec) by
//! [`register_strands`], which means the spider owns them: a crash becomes a
//! `LifecycleEvent::Crashed`, is restarted three times, and is quarantined on
//! the fourth. See the pilot (`imperium-net-lightcone`) for the general
//! recipe.
//!
//! # What is (and is not) preserved
//!
//! The strands are thin adapters over the managers: the same service methods
//! run in the same order, with the same fail-closed semantics and the same log
//! lines. Neither loop ever published anything, so neither strand does either.
//!
//! Three mechanics change, all deliberately:
//!
//! * **Filtering moves into the strand.** Spiderweb routes strand deliveries by
//!   `TypeId`, not by socket name: a strand declaring an input of type
//!   [`BusEvent`] receives *every* `BusEvent` published on the bus, so the old
//!   kernel-side prefix filter (`bus.subscribe("net.cluster.membership.granted")`)
//!   becomes the `event.topic.starts_with(..)` test inside `run`. Semantics are
//!   identical; only the location of the comparison moved.
//! * **The pending-buffer replay is deduped on [`BusEvent::id`].** The kernel
//!   keeps a bounded tail (32 messages per `TypeId`) so a *late* subscriber can
//!   be caught up, and a restarted strand is a late subscriber. These two loops
//!   are the highest-risk case in the whole migration: their effect is a
//!   signature-verified **state change**, not an observation. A replayed
//!   [`MembershipGrant`] would re-run the verification and re-apply the grant,
//!   and a replayed [`ConfigurationFetchResponse`] would re-apply a fetched
//!   configuration — the exact class of double-effect the recipe's §5.4 warns
//!   about. [`SeenIds`] is therefore a **durable** (factory-shared, never
//!   per-generation) record of the ids this strand already applied, sized well
//!   above the 32-deep tail.
//! * **One strand serves every manager wired to its bus.** The old world had one
//!   loop *per manager instance*, but a strand name is a kernel-global, unique,
//!   `&'static str` resource — three nodes simulated on one bus (the cluster
//!   tests) cannot each own a strand called `imperium-net-cluster.membership`.
//!   [`ClusterLinks`] is the bus-scoped registry of the managers wired to that
//!   bus, and the strands fan an event out to every one of them — which is
//!   exactly the union of what the old per-manager loops did, since each of them
//!   matched the same topic and applied the same message to its own manager
//!   (fail-closed, each verifying against its own operator key and cluster id).
//!
//! # Wiring
//!
//! Manager ownership and strand registration are separated, because a node
//! builds its managers wherever it likes (the CLI builds none today; the
//! runtime's deployment path and the tests build several):
//!
//! * [`register_strands`] queues **both** strand specs on a bus. Call it before
//!   the kernel's run loop; the
//!   composition root does. On a bus with no managers yet the strands are idle —
//!   they drain their inbox and apply nothing.
//! * [`attach_membership`] / [`attach_config`] wire one manager into that bus's
//!   registry. They wire, they do not queue: the specs come from
//!   [`register_strands`], and wiring and queueing may happen in either order
//!   because both reach the same bus-scoped [`ClusterLinks`].
//! * The legacy `subscribe_membership_grants` /
//!   `subscribe_config_responses` methods on the managers are kept so existing
//!   call sites keep compiling: they wire, queue (with the env policy) and return
//!   an inert handle. They no longer spawn anything.
//!
//! Registration is idempotent per bus, and the *first* call's fault policy wins
//! (a differing policy is warned about, never silently ignored).

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};

use imperium_protocol::{BusEvent, Message};
use parking_lot::Mutex;
use spiderweb::{Bus, BusPublisher};
use spiderweb::{BusHandle, Socket, Strand, StrandError, StrandSpec};

use crate::topics::{CONFIG_FETCH_RESPONSE, MEMBERSHIP_GRANTED};
use crate::{ConfigManager, MembershipManager};

/// Subsystem identifier. Fixed, `&'static str` (Spiderweb requires it), and equal
/// to the name the `net.cluster.ready` message carries, so one identifier works
/// in the topic table, the kernel's log, and the spider's log.
pub const NAME: &str = "imperium-net-cluster";

/// Strand name of the membership-grant loop.
///
/// Two strands live in this crate, so the subsystem identifier alone cannot name
/// both (the kernel panics on a duplicate name); the role is appended instead.
pub const MEMBERSHIP_STRAND: &str = "imperium-net-cluster.membership";

/// Strand name of the config fetch-response loop.
pub const CONFIG_STRAND: &str = "imperium-net-cluster.config";

/// Environment variable that arms a deliberate fault, for supervision drills:
/// `IMPERIUM_CLUSTER_CRASH_AFTER_MESSAGES=<n>` makes every strand instance
/// return [`StrandError::Crashed`] once it has *handled* `n` messages — handled
/// meaning delivered to the managers wired to its bus, whether each of them
/// accepted the message or rejected it fail-closed.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. It exists so the restart/quarantine path can be exercised
/// end-to-end against the real strands instead of a stand-in, and so an operator
/// can drill the supervisor on a live node. Both strands read it; each counts its
/// *own* handled messages, so a drill only fires on the loop it feeds.
pub const CRASH_AFTER_MESSAGES_ENV: &str = "IMPERIUM_CLUSTER_CRASH_AFTER_MESSAGES";

/// How a cluster strand instance should fault, for drills and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Apply normally. The production default.
    #[default]
    None,
    /// Deliberately crash after handling `n` messages (see
    /// [`CRASH_AFTER_MESSAGES_ENV`]). The count is per strand *instance*, so a
    /// restarted instance crashes again after its own `n`th message — which is
    /// what lets a drill drive the full
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
        match raw.map(str::trim).and_then(|v| v.parse::<u32>().ok()) {
            Some(n) if n > 0 => FaultPolicy::CrashAfterMessages(n),
            _ => FaultPolicy::None,
        }
    }

    /// Whether this policy injects a fault (used to warn loudly at boot).
    pub fn is_injected(&self) -> bool {
        !matches!(self, FaultPolicy::None)
    }

    /// The crash reason for an instance that has just applied `handled`
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

/// How many recent [`BusEvent::id`]s one strand remembers.
///
/// The kernel's replay tail is 32 messages per `TypeId` (recipe §5.4); 256 is
/// eight times that, so a restart cannot out-run the guard even if a burst of
/// other `BusEvent`s separates this strand's own messages in the tail.
pub const SEEN_CAPACITY: usize = 256;

/// Durable replay guard: the ids one strand has already applied.
///
/// Deliberately **not** per generation. A restarted strand is a late subscriber
/// and the kernel replays it the recent tail — of messages the *previous*
/// generation already handled. A per-generation history would be empty at
/// exactly the moment it is needed, and the effect here is a signature-verified
/// state change, so the history is shared by every generation through the spec's
/// factory: durable state, shared through the `Arc`, exactly like the managers
/// themselves (recipe §3.2).
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
    /// one already applied by this strand.
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

    /// Whether nothing has been applied yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SeenIds {
    fn default() -> Self {
        Self::new()
    }
}

/// The managers wired to one bus, plus the strand state that must outlive a
/// generation.
///
/// This is the durable half of both strands. It is created once per bus by
/// [`links_for`] and captured by the strand factories, so every restarted
/// generation applies events to the *same* managers with the *same* replay
/// history — restart resumes the subsystem rather than reloading an empty one.
///
/// A manager is identified by its `Arc` (pointer equality), so a repeated
/// `subscribe_*` call adds nothing and cannot turn one manager into two
/// consumers of the same event.
pub struct ClusterLinks {
    membership: Mutex<Vec<Arc<MembershipManager>>>,
    config: Mutex<Vec<Arc<ConfigManager>>>,
    /// Replay guards, shared across generations (see [`SeenIds`]).
    seen_membership: Arc<SeenIds>,
    seen_config: Arc<SeenIds>,
    queue: Mutex<QueueState>,
}

#[derive(Default)]
struct QueueState {
    /// Whether both specs have been queued on this bus.
    queued: bool,
    /// The fault policy they were queued with (the first call wins).
    faults: Option<FaultPolicy>,
}

impl ClusterLinks {
    pub fn new() -> Self {
        Self {
            membership: Mutex::new(Vec::new()),
            config: Mutex::new(Vec::new()),
            seen_membership: Arc::new(SeenIds::new()),
            seen_config: Arc::new(SeenIds::new()),
            queue: Mutex::new(QueueState::default()),
        }
    }

    /// Wire `manager` in. Returns `true` if it was not already wired.
    pub fn add_membership(&self, manager: Arc<MembershipManager>) -> bool {
        let mut managers = self.membership.lock();
        if managers.iter().any(|known| Arc::ptr_eq(known, &manager)) {
            return false;
        }
        managers.push(manager);
        true
    }

    /// Wire `manager` in. Returns `true` if it was not already wired.
    pub fn add_config(&self, manager: Arc<ConfigManager>) -> bool {
        let mut managers = self.config.lock();
        if managers.iter().any(|known| Arc::ptr_eq(known, &manager)) {
            return false;
        }
        managers.push(manager);
        true
    }

    /// The membership managers wired to this bus (a snapshot).
    pub fn membership_managers(&self) -> Vec<Arc<MembershipManager>> {
        self.membership.lock().clone()
    }

    /// The config managers wired to this bus (a snapshot).
    pub fn config_managers(&self) -> Vec<Arc<ConfigManager>> {
        self.config.lock().clone()
    }

    /// How many membership managers are wired to this bus.
    pub fn membership_len(&self) -> usize {
        self.membership.lock().len()
    }

    /// How many config managers are wired to this bus.
    pub fn config_len(&self) -> usize {
        self.config.lock().len()
    }

    /// The membership strand's durable replay guard (observability for tests).
    pub fn seen_membership(&self) -> &Arc<SeenIds> {
        &self.seen_membership
    }

    /// The config strand's durable replay guard (observability for tests).
    pub fn seen_config(&self) -> &Arc<SeenIds> {
        &self.seen_config
    }
}

impl Default for ClusterLinks {
    fn default() -> Self {
        Self::new()
    }
}

/// `(publisher, links)` pairs already wired in this process.
///
/// Keyed by [`Weak<BusPublisher>`]: the composition root mints **one** publisher
/// per kernel and shares it, so publisher identity *is* bus identity. A dropped
/// publisher is pruned, and because a live `Weak` keeps its allocation alive, an
/// address cannot be recycled behind a stale entry — a fresh bus in the same
/// test process is never mistaken for an already-wired one, so managers of one
/// bus are never handed another bus's events. (The same hazard and the same
/// answer as the transport conversion's lane registry.)
static LINKS: OnceLock<StdMutex<Vec<(Weak<BusPublisher>, Arc<ClusterLinks>)>>> = OnceLock::new();

fn registry() -> &'static StdMutex<Vec<(Weak<BusPublisher>, Arc<ClusterLinks>)>> {
    LINKS.get_or_init(|| StdMutex::new(Vec::new()))
}

/// The [`ClusterLinks`] for `publisher`, created on first use.
pub fn links_for(publisher: &Arc<BusPublisher>) -> Arc<ClusterLinks> {
    // Poison-tolerant: the guarded value is a plain registry, so recovering the
    // inner guard is strictly safer than cascading a panic through every later
    // registration.
    let mut registry = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // A publisher that has been dropped can never publish again; the strands it
    // left running hold their own `Arc<ClusterLinks>`, so pruning here only
    // forgets the wiring, it never tears down a live strand.
    registry.retain(|(publisher, _)| publisher.strong_count() > 0);

    let key = Arc::downgrade(publisher);
    if let Some((_, links)) = registry.iter().find(|(known, _)| known.ptr_eq(&key)) {
        return Arc::clone(links);
    }
    let links = Arc::new(ClusterLinks::new());
    registry.push((key, Arc::clone(&links)));
    links
}

/// Queue one strand spec, at most once per bus.
///
/// Idempotent: a second call for the same bus is a no-op — the first
/// registration wins, and a differing fault policy is warned about rather than
/// silently ignored (a drill that was never armed would otherwise look like a
/// supervisor that did not restart). So [`register_strands`] and the legacy
/// `subscribe_*` shims can all run without the kernel's duplicate-name panic.
pub(crate) fn queue_strands(bus: &mut Bus, links: &Arc<ClusterLinks>, faults: FaultPolicy) {
    let mut state = links.queue.lock();
    if state.queued {
        if state.faults != Some(faults) {
            tracing::warn!(
                queued = ?state.faults,
                requested = ?faults,
                "cluster strands were already queued with a different fault policy; \
                 the queued policy stays in force"
            );
        }
        return;
    }

    // The membership spec first, then the config spec. Both go into the kernel's
    // spec list; the kernel installs them when its run loop starts.
    bus.register_spec(MembershipGrantStrand::spec(
        Arc::clone(links),
        Arc::clone(&links.seen_membership),
        faults,
    ));
    bus.register_spec(ConfigResponseStrand::spec(
        Arc::clone(links),
        Arc::clone(&links.seen_config),
        faults,
    ));

    state.queued = true;
    state.faults = Some(faults);
}

/// Queue this crate's two supervised strands on `bus`.
///
/// # Call this *before* the kernel's run loop starts
///
/// Strand specs are installed by `Bus::run_until`, which the composition root
/// drives. Registering later is not merely refused, it is impossible: the bus is
/// moved onto the run-loop thread, so a spec queued afterwards could not reach
/// it. The compiler enforces the ordering the old runtime error used to.
///
/// A bus with no managers wired yet is a valid, expected state (the CLI owns no
/// cluster identity today): the strands are installed, tick, and apply nothing —
/// see [`attach_membership`] / [`attach_config`] for wiring a node's managers.
///
/// The fault policy comes from [`FaultPolicy::from_env`] (see
/// [`CRASH_AFTER_MESSAGES_ENV`]); it is [`FaultPolicy::None`] unless an operator
/// armed a drill, and an armed drill is logged loudly.
pub fn register_strands(bus: &mut Bus, publisher: &Arc<BusPublisher>) {
    register_strands_with(bus, publisher, FaultPolicy::from_env())
}

/// [`register_strands`] with an explicit fault policy — how a supervision drill
/// arms the strands without touching the process environment.
pub fn register_strands_with(bus: &mut Bus, publisher: &Arc<BusPublisher>, faults: FaultPolicy) {
    if faults.is_injected() {
        // A deliberately armed fault must never look like a real one in the
        // logs, and must be impossible to leave on by accident without a trace.
        tracing::warn!(
            policy = ?faults,
            env = CRASH_AFTER_MESSAGES_ENV,
            "cluster fault injection ARMED — the strands will crash on purpose"
        );
    }
    let links = links_for(publisher);
    queue_strands(bus, &links, faults)
}

/// Wire one membership manager into `bus`'s supervised membership-grant loop.
///
/// Returns whether the manager was newly wired (`false` if it already was).
/// The manager's events are applied by the strand — fail-closed, signature
/// verified, replayed events deduped.
///
/// This wires, it does not *queue*: the strand specs come from
/// [`register_strands`] (or from a legacy `subscribe_*` shim, which does both),
/// and the fault policy belongs to whoever queues. Wiring and queueing may
/// happen in either order — both reach the same bus-scoped [`ClusterLinks`].
pub fn attach_membership(publisher: &Arc<BusPublisher>, manager: &Arc<MembershipManager>) -> bool {
    links_for(publisher).add_membership(Arc::clone(manager))
}

/// Wire one config manager into `bus`'s supervised config loop — the config half
/// of [`attach_membership`].
pub fn attach_config(publisher: &Arc<BusPublisher>, manager: &Arc<ConfigManager>) -> bool {
    links_for(publisher).add_config(Arc::clone(manager))
}

/// The `net.cluster.membership.granted` loop as a strand.
///
/// Owns its state: the managers and the replay guard are shared with whatever
/// built them (`Arc`, so a restart resumes the same membership tables and still
/// recognises the replay), the fault policy is `Copy`, and the applied counter
/// is per instance (so a restart resets the drill). Nothing is borrowed from
/// outside, which is what makes the strand restartable — the kernel's factory
/// call produces a fresh, independent instance.
pub struct MembershipGrantStrand {
    links: Arc<ClusterLinks>,
    seen: Arc<SeenIds>,
    faults: FaultPolicy,
    /// Messages this *instance* has handled (delivered to the wired managers),
    /// for the fault drill.
    handled: u32,
}

impl MembershipGrantStrand {
    pub fn new(links: Arc<ClusterLinks>, seen: Arc<SeenIds>, faults: FaultPolicy) -> Self {
        Self {
            links,
            seen,
            faults,
            handled: 0,
        }
    }

    /// The restartable spec for this strand, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec).
    pub fn spec(links: Arc<ClusterLinks>, seen: Arc<SeenIds>, faults: FaultPolicy) -> StrandSpec {
        StrandSpec::new(MEMBERSHIP_STRAND, move || -> Box<dyn Strand> {
            Box::new(MembershipGrantStrand::new(
                Arc::clone(&links),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for MembershipGrantStrand {
    fn name(&self) -> &str {
        MEMBERSHIP_STRAND
    }

    fn inputs(&self) -> &[Socket] {
        // The socket name is documentation for the lifecycle event and the web
        // graph; routing is by `BusEvent`'s `TypeId` (see the module docs).
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(MEMBERSHIP_GRANTED)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        // The old loop applied grants and logged; it published nothing, and
        // neither does this strand.
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick and
        // let the worker join. This is also where the old loop's
        // `Err(BusError::Closed) => break` went: a closed subscription meant the
        // process was going away, and `is_shutting_down` is that signal now.
        // Nothing below blocks, so there is no bounded-blocking section to
        // shorten.
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on. Draining by socket name instead (`recv::<BusEvent>(name)`)
        // would leave every non-matching carrier in the inbox forever, growing it
        // one event per unrelated publish — the inbox is a mailbox, not a filter.
        //
        // `?` is infallible in practice: the inbox only ever holds payloads whose
        // `TypeId` matched this strand's declared input, and a genuine kernel
        // fault still surfaces as `Crashed` and is supervised.
        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            // The prefix filter the kernel used to apply for the old
            // `bus.subscribe("net.cluster.membership.granted")` subscription.
            if !event.topic.starts_with(MEMBERSHIP_GRANTED) {
                continue;
            }
            // The old loop's message-variant gate: any other payload on a
            // matching topic was ignored then too.
            let Message::MembershipGrant(ref grant) = event.message else {
                continue;
            };

            // The managers wired to this bus. An unwired bus applies nothing —
            // and deliberately does *not* record the id, so a manager wired later
            // is not silently starved of a message this strand never delivered.
            let managers = self.links.membership_managers();
            if managers.is_empty() {
                continue;
            }

            // Replay guard (recipe §5.4): a restarted generation is replayed the
            // recent tail, which the previous generation already applied.
            // Re-running the operator-signature check and re-applying the grant
            // would be a second, replayed state change — exactly what the guard
            // exists to prevent.
            if !self.seen.first_sight(event.id.0.as_u128()) {
                tracing::debug!(
                    event_id = %event.id.0,
                    peer = ?grant.peer_id,
                    "ignoring a replayed membership grant; it was already applied"
                );
                continue;
            }

            // The old loop body, verbatim, per wired manager: verify-and-apply,
            // log the outcome, never let one manager's rejection stop another.
            for manager in &managers {
                match manager.apply_grant(grant) {
                    Ok(()) => {
                        tracing::info!(peer = ?grant.peer_id, "applied verified membership grant");
                    }
                    Err(e) => {
                        tracing::warn!(
                            peer = ?grant.peer_id,
                            error = %e,
                            "rejected membership grant: invalid operator signature"
                        );
                    }
                }
            }

            self.handled = self.handled.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.handled) {
                // Diagnostic-only path; see `FaultPolicy`. Nothing this strand
                // does is published, so a `Crashed` tick loses no work: every
                // effect above is already in the shared manager.
                return Err(StrandError::Crashed(reason));
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick
        // (the worker paces them at 10ms), which is this strand's idle loop.
        Ok(())
    }
}

/// The `net.cluster.config.fetch_response` loop as a strand.
///
/// Same shape and the same durable-state reasoning as
/// [`MembershipGrantStrand`]: the config managers and the replay guard are
/// shared through the factory, so a restart resumes the same configuration
/// state and still recognises a replayed response instead of re-applying it.
pub struct ConfigResponseStrand {
    links: Arc<ClusterLinks>,
    seen: Arc<SeenIds>,
    faults: FaultPolicy,
    handled: u32,
}

impl ConfigResponseStrand {
    pub fn new(links: Arc<ClusterLinks>, seen: Arc<SeenIds>, faults: FaultPolicy) -> Self {
        Self {
            links,
            seen,
            faults,
            handled: 0,
        }
    }

    /// The restartable spec for this strand, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec).
    pub fn spec(links: Arc<ClusterLinks>, seen: Arc<SeenIds>, faults: FaultPolicy) -> StrandSpec {
        StrandSpec::new(CONFIG_STRAND, move || -> Box<dyn Strand> {
            Box::new(ConfigResponseStrand::new(
                Arc::clone(&links),
                Arc::clone(&seen),
                faults,
            ))
        })
    }
}

impl Strand for ConfigResponseStrand {
    fn name(&self) -> &str {
        CONFIG_STRAND
    }

    fn inputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(CONFIG_FETCH_RESPONSE)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        if bus.is_shutting_down() {
            return Ok(());
        }

        let events = bus.recv_all::<BusEvent>()?;

        for (_socket, event) in events {
            if !event.topic.starts_with(CONFIG_FETCH_RESPONSE) {
                continue;
            }
            let Message::ConfigFetchResp(ref resp) = event.message else {
                continue;
            };

            let managers = self.links.config_managers();
            if managers.is_empty() {
                continue;
            }

            // Replay guard: a replayed response must not be re-verified and
            // re-applied. (The version gate inside `apply_fetched_config` is a
            // second, independent line of defence — it rejects anything not
            // newer than the local config — but it only protects state that a
            // manager has already reached. The guard protects every manager the
            // replay would otherwise reach, and keeps the replay from being
            // logged as a fresh application.)
            if !self.seen.first_sight(event.id.0.as_u128()) {
                tracing::debug!(
                    event_id = %event.id.0,
                    version = resp.version,
                    "ignoring a replayed config fetch response; it was already applied"
                );
                continue;
            }

            for manager in &managers {
                match manager.apply_fetched_config(resp) {
                    Ok(()) => {
                        tracing::info!(version = resp.version, "applied fetched config");
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "config fetch response rejected");
                    }
                }
            }

            self.handled = self.handled.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.handled) {
                return Err(StrandError::Crashed(reason));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_net_crypto::{HybridEd25519Mldsa, HybridVerifyingKey};
    use imperium_protocol::{ClusterId, PeerId};
    use rand::rngs::OsRng;
    use std::time::{Duration, Instant};

    /// A fault must never be armable by a typo — absent/zero/unparsable all mean
    /// `None`.
    #[test]
    fn fault_policy_never_arms_on_a_bad_value() {
        assert_eq!(FaultPolicy::parse(None), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("0")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("nope")), FaultPolicy::None);
        assert_eq!(FaultPolicy::parse(Some("-1")), FaultPolicy::None);
        assert_eq!(
            FaultPolicy::parse(Some(" 2 ")),
            FaultPolicy::CrashAfterMessages(2)
        );
        assert!(!FaultPolicy::None.is_injected());
        assert!(FaultPolicy::CrashAfterMessages(1).is_injected());
    }

    /// The drill trips exactly at its threshold, and never before it.
    #[test]
    fn fault_policy_trips_at_its_threshold() {
        let policy = FaultPolicy::CrashAfterMessages(2);
        assert!(policy.tripped(1).is_none());
        let reason = policy.tripped(2).expect("the second message trips it");
        assert!(reason.contains("injected fault"), "{reason}");
        assert!(reason.contains("2 message"), "{reason}");
        // `None` never trips, however much work the instance does.
        assert!(FaultPolicy::None.tripped(u32::MAX).is_none());
    }

    /// The replay guard accepts an id once and treats every repeat as a replay,
    /// and it stays bounded well above the kernel's 32-deep tail.
    #[test]
    fn seen_ids_accept_once_then_treat_repeats_as_replays() {
        let seen = SeenIds::new();
        assert!(seen.is_empty());
        assert!(seen.first_sight(7));
        assert!(!seen.first_sight(7), "the same id is a replay");
        assert!(seen.first_sight(8));
        assert_eq!(seen.len(), 2);

        assert!(
            SEEN_CAPACITY > 32,
            "the guard must out-size the replay tail"
        );
        for id in 0..(SEEN_CAPACITY as u128 + 10) {
            seen.first_sight(1_000 + id);
        }
        assert_eq!(seen.len(), SEEN_CAPACITY, "the guard must stay bounded");
    }

    /// Managers are wired by identity: a repeated subscription adds nothing, and
    /// separate buses keep separate manager sets.
    #[test]
    fn links_are_per_bus_and_dedupe_managers_by_identity() {
        fn verifying_key() -> HybridVerifyingKey {
            let mut rng = OsRng;
            let (_sk, vk) = HybridEd25519Mldsa::generate_keypair(&mut rng);
            vk
        }

        let publisher_a = Arc::new(Bus::open().publisher());
        let publisher_b = Arc::new(Bus::open().publisher());
        let links_a = links_for(&publisher_a);
        let links_b = links_for(&publisher_b);
        assert!(!Arc::ptr_eq(&links_a, &links_b), "each bus owns its wiring");
        assert!(
            Arc::ptr_eq(&links_a, &links_for(&publisher_a)),
            "one per bus"
        );

        let manager = Arc::new(MembershipManager::new(
            ClusterId::new(),
            PeerId::new(),
            verifying_key(),
        ));
        assert!(links_a.add_membership(Arc::clone(&manager)));
        assert!(
            !links_a.add_membership(Arc::clone(&manager)),
            "the same manager is wired once, never twice"
        );
        assert_eq!(links_a.membership_len(), 1);
        assert_eq!(
            links_b.membership_len(),
            0,
            "wiring does not leak across buses"
        );

        let config = Arc::new(ConfigManager::new(
            ClusterId::new(),
            PeerId::new(),
            verifying_key(),
        ));
        assert!(links_a.add_config(Arc::clone(&config)));
        assert!(!links_a.add_config(Arc::clone(&config)));
        assert_eq!(links_a.config_len(), 1);
        assert_eq!(links_b.config_len(), 0);
    }

    /// The two strand names are distinct (the kernel panics on a collision) and
    /// share the subsystem prefix, so one identifier still greps.
    #[test]
    fn strand_names_are_distinct_and_share_the_subsystem_prefix() {
        assert_ne!(MEMBERSHIP_STRAND, CONFIG_STRAND);
        for name in [NAME, MEMBERSHIP_STRAND, CONFIG_STRAND] {
            assert!(name.starts_with("imperium-net-cluster"), "{name}");
        }
    }

    /// A spec is queued, not started: nothing runs until the run loop starts.
    ///
    /// The old form of this test also asserted `!bus.supervision_running()`.
    /// That assertion is now impossible to state *and* impossible to violate:
    /// `register_spec` only appends to the kernel's spec list, and the only
    /// thing that installs or starts a spec is `Bus::run_until(&mut self)`,
    /// which consumes the bus. There is no runtime flag left to read, because
    /// there is no state in which a registered spec is running without the bus
    /// having been handed to a run loop.
    #[test]
    fn queuing_specs_starts_nothing() {
        let mut bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        register_strands_with(&mut bus, &publisher, FaultPolicy::None);
        // Idempotent: a second composition-root call must not trip the kernel's
        // duplicate-name panic.
        register_strands_with(&mut bus, &publisher, FaultPolicy::None);
    }

    /// Registration is ordered before the run loop by **ownership**, not by a
    /// runtime refusal.
    ///
    /// The old test asserted that an engaged bus returned
    /// `StrandRegistrationError::Engaged`. That error cannot exist any more:
    /// `Bus::run_until` takes the bus by `&mut` and the composition root moves it
    /// onto the run-loop thread, so "register a spec after the loop started" is a
    /// borrow-check error rather than a value a program can hold. What this test
    /// proves instead is the positive side of the same ordering — the specs
    /// queued before the loop are exactly the ones that get installed.
    #[test]
    fn specs_queued_before_the_run_loop_are_the_ones_installed() {
        use spiderweb::{BusHandle, LifecycleEvent, Socket, Strand, StrandError, SYS_LIFECYCLE};

        /// Records the kernel's `Registered` stream.
        struct Registrar {
            log: Arc<StdMutex<Vec<String>>>,
        }

        impl Strand for Registrar {
            fn name(&self) -> &str {
                "test.cluster-registrar"
            }

            fn inputs(&self) -> &[Socket] {
                const SOCKS: [Socket; 1] = [Socket::new::<LifecycleEvent>(SYS_LIFECYCLE)];
                &SOCKS
            }

            fn outputs(&self) -> &[Socket] {
                &[]
            }

            fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
                for (_socket, event) in bus.recv_all::<LifecycleEvent>()? {
                    if let LifecycleEvent::Registered { name, .. } = event {
                        self.log
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(name);
                    }
                }
                Ok(())
            }
        }

        let registered = Arc::new(StdMutex::new(Vec::<String>::new()));
        let mut bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        register_strands_with(&mut bus, &publisher, FaultPolicy::None);
        bus.register_spec(spiderweb::StrandSpec::new("test.cluster-registrar", {
            let log = Arc::clone(&registered);
            move || -> Box<dyn Strand> {
                Box::new(Registrar {
                    log: Arc::clone(&log),
                })
            }
        }));

        let mut supervision = crate::test_supervision::Supervision::engage(bus);
        let deadline = Instant::now() + Duration::from_secs(20);
        while registered.lock().unwrap().len() < 3 {
            assert!(
                Instant::now() < deadline,
                "the three queued specs must all be installed: {:?}",
                registered.lock().unwrap()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        supervision.shutdown();

        let names = registered.lock().unwrap().clone();
        for expected in [MEMBERSHIP_STRAND, CONFIG_STRAND, "test.cluster-registrar"] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} must be installed from the queue: {names:?}"
            );
        }
    }
}
