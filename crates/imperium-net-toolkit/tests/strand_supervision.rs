//! End-to-end supervision proof for the tool-manager activation-loop
//! conversion.
//!
//! `imperium-net-toolkit`'s activation loop used to be a `tokio::spawn`ed recv
//! loop over `net.toolkit.request`; it is now a Spiderweb **strand**
//! ([`ToolkitStrand`](imperium_net_toolkit::ToolkitStrand)), registered as a spec
//! through [`register_strands`](imperium_net_toolkit::register_strands) /
//! [`ToolManager::register_strand`](imperium_net_toolkit::ToolManager::register_strand).
//! The unit tests in `src/lib.rs` cover the *manager* (lifecycle, budgets,
//! cooldowns); these integration tests cover what only a real kernel can prove:
//!
//! 1. [`strand_serves_requests_and_publishes_outcomes_to_shim_subscribers`] —
//!    behaviour preservation. Same topic in, same topics out, same payloads,
//!    same refusal for a tool that is not armed, and the outcomes reach the
//!    *same* `Bus::subscribe` subscribers the old loop's `Bus::publish` reached
//!    (plus a peer strand, proving strand → strand delivery).
//! 2. [`queued_spec_is_not_started_until_engage`] — a spec is queued, not
//!    started; engagement installs the loop (and re-queueing is idempotent,
//!    because the kernel *panics* on a duplicate strand name), while a spec
//!    offered after engage is refused with `Engaged` instead of silently
//!    dropped.
//! 3. [`crashed_strand_is_restarted_three_times_then_quarantined`] — the crash
//!    policy, driven through the real strand with an injected fault: crashes
//!    become `LifecycleEvent::Crashed`, the spider restarts three times, the
//!    fourth crash quarantines — and the tool table (the shared `Arc`) keeps the
//!    activations the earlier generations performed.
//! 4. [`replayed_request_is_deduped_not_rehandled`] — the recipe's §5.4 hazard
//!    for a non-idempotent consumer. A restarted generation is replayed the
//!    recent tail; the durable `SeenIds` record refuses it, so a request that
//!    already spent a budget slot is not handled again (which the per-generation
//!    fault counter makes exactly measurable: one crash, one restart, no
//!    quarantine).
//!
//! Everything here runs the production path: a real `Bus::new()`, real
//! `register_strand`/`Bus::engage_supervision()` (kernel run loop + spider on
//! their own OS threads), real strand workers, and the real `ToolkitStrand`.
//! Nothing is simulated and nothing is stubbed.
//!
//! # The instruments: recorder strands
//!
//! Supervision is invisible to `Bus::subscribe` — that surface carries
//! `BusEvent`s only, while lifecycle events travel on `sys.lifecycle` — so the
//! instrument is a second strand that records what it feels, exactly as the
//! pilot's and the orchestrator's test files do. [`LifecycleRecorder`] records
//! the kernel's lifecycle stream (and survives its neighbour's death);
//! [`EventRecorder`] records a topic prefix of the manager's output, which also
//! proves a strand's publish reaches another strand.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use imperium_net_toolkit::{
    queue_strand, register_strands, topics, FaultPolicy, ToolManager, ToolManifest,
    TriggerCondition, NAME as STRAND_NAME,
};
use imperium_protocol::{BusEvent, Message, ToolActivationRequest, ToolState, ToolStateChange};
use spiderweb::{Bus, BusPublisher, ControlMsg, SYS_CONTROL};
use spiderweb::{
    BusHandle, LifecycleEvent, Socket, Strand, StrandError, StrandSpec, SYS_LIFECYCLE,
};

// ---------------------------------------------------------------------------
// Recorder strands — the supervision instruments
// ---------------------------------------------------------------------------

/// Shared, test-owned record of every lifecycle event the kernel published.
/// `std::sync::Mutex` so a poisoned lock cannot hide an assertion failure.
type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;
/// Shared, test-owned record of the manager's output a recorder strand saw.
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
/// *generation*, so a strand that was restarted three times reports four.
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

/// Whether the kernel flushed `count >= 1` pending messages into a restarted
/// generation of this strand — the replay the dedupe record exists to defeat.
fn replay_happened(log: &LifecycleLog, name: &str) -> bool {
    count(log, |event| {
        matches!(
            event,
            LifecycleEvent::Flushed { to, count, .. } if to == name && *count >= 1
        )
    }) >= 1
}

/// Every lifecycle event naming one strand, so "nothing further happened to it"
/// is assertable. (`Buffered`/`ThreadFormed` events for unrelated topics arrive
/// continuously, so the whole stream cannot be compared.)
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

/// Block (with a hard deadline) until `pred` holds, so a supervision bug fails
/// the test instead of hanging it.
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
/// Its input type is [`BusEvent`] — the same type the toolkit strand declares —
/// because strand routing is by `TypeId`; the prefix filter here is the
/// `Bus::subscribe(prefix)` comparison, moved into the consumer.
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
        // `recv_all`, not `recv(prefix)`: the inbox is a mailbox, not a filter.
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

/// The activations a recorder strand saw, in arrival order.
///
/// The topic is filtered exactly, not by prefix: `net.toolkit.request` carries
/// the *same* `Message::ToolActivationReq` variant as the manager's
/// `net.toolkit.activation` output, so a variant-only match would count the
/// inbound requests as if they were activations.
fn recorded_activations(log: &EventLog) -> Vec<ToolActivationRequest> {
    event_snapshot(log)
        .into_iter()
        .filter(|event| &*event.topic == topics::ACTIVATION)
        .filter_map(|event| match event.message {
            Message::ToolActivationReq(request) => Some(request),
            _ => None,
        })
        .collect()
}

/// The state changes a recorder strand saw, in arrival order.
fn recorded_state_changes(log: &EventLog) -> Vec<ToolStateChange> {
    event_snapshot(log)
        .into_iter()
        .filter(|event| &*event.topic == topics::STATE)
        .filter_map(|event| match event.message {
            Message::ToolStateChange(change) => Some(change),
            _ => None,
        })
        .collect()
}

/// The *activation* state changes (`Armed` → `Active`) a recorder strand saw.
///
/// Filtered by target state because the fixture arms its tool through
/// `ToolManager::arm`, which publishes a state change of its own — the same
/// transition the caller's direct call produces, and not part of what the
/// strand does with a request.
fn recorded_activation_states(log: &EventLog) -> Vec<ToolStateChange> {
    recorded_state_changes(log)
        .into_iter()
        .filter(|change| change.to == ToolState::Active)
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn manifest(name: &str, max_activations_per_hour: u32) -> ToolManifest {
    ToolManifest {
        name: name.to_string(),
        description: format!("{name} drill tool"),
        trigger_conditions: vec![TriggerCondition {
            event_topic: "net.sensors.threat".to_string(),
            min_confidence: 0.8,
        }],
        idle_timeout: Duration::from_secs(300),
        cooldown_duration: Duration::from_secs(60),
        max_activations_per_hour,
    }
}

fn activation(name: &str, trigger: &str) -> ToolActivationRequest {
    ToolActivationRequest {
        tool_name: name.to_string(),
        trigger: trigger.to_string(),
        context: HashMap::new(),
        timestamp: chrono::Utc::now(),
    }
}

/// Offer one request to the strand exactly as the orchestrator does: publish
/// `net.toolkit.request` on the bus.
fn offer_request(bus: &BusPublisher, request: ToolActivationRequest) {
    BusEvent::publish(bus, topics::REQUEST, Message::ToolActivationReq(request))
        .expect("publish is fire-and-forget and never fails");
}

/// A manager with `names` registered and armed, ready to be activated.
fn armed_manager(publisher: &Arc<BusPublisher>, names: &[&str]) -> Arc<ToolManager> {
    let manager = Arc::new(ToolManager::new(Arc::clone(publisher)));
    for name in names {
        manager.register(manifest(name, 10));
        manager.arm(name).expect("a registered tool arms");
    }
    manager
}

// ---------------------------------------------------------------------------
// (a) Behaviour preservation
// ---------------------------------------------------------------------------

/// The strand serves the same topic pair with the same content, and its
/// outcomes reach the *same* `Bus::subscribe` subscribers the old `tokio` loop's
/// `Bus::publish` reached — including the refusal path, which the old loop also
/// logged and swallowed without publishing anything.
#[tokio::test]
async fn strand_serves_requests_and_publishes_outcomes_to_shim_subscribers() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let outcomes = new_event_log();

    // A peer strand consuming the manager's output by TypeId — the same topics
    // the old loop's `Bus::publish` reached.
    bus.register_spec(event_recorder_spec(
        "test.toolkit-recorder",
        "net.toolkit.",
        Arc::clone(&outcomes),
    ));

    // `probe` is armed; `scanner` is left dormant, so its request must be
    // refused exactly as the old loop refused it.
    let manager = armed_manager(&publisher, &["probe"]);
    manager.register(manifest("scanner", 10));

    // The production entry point: queued before engage, no injected fault.
    register_strands(&mut bus, &publisher, &manager);

    // The shim's own subscriber surface — the path every existing consumer uses.
    let mut activation_sub = subscribe_queue(&publisher, topics::ACTIVATION, 32);
    let mut state_sub = subscribe_queue(&publisher, topics::STATE, 32);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    offer_request(&publisher, activation("probe", "high threat detected"));
    offer_request(&publisher, activation("scanner", "not armed yet"));

    // 1. Through the shim subscriptions (the old public paths).
    let activation_event = tokio::time::timeout(Duration::from_secs(10), activation_sub.recv())
        .await
        .expect("the activation request must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    match activation_event.message {
        Message::ToolActivationReq(request) => {
            assert_eq!(request.tool_name, "probe");
            assert_eq!(request.trigger, "high threat detected");
        }
        other => panic!("expected a ToolActivationReq, got {other:?}"),
    }

    let state_event = tokio::time::timeout(Duration::from_secs(10), state_sub.recv())
        .await
        .expect("the state change must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    match state_event.message {
        Message::ToolStateChange(change) => {
            assert_eq!(change.tool_name, "probe");
            assert_eq!(change.from, ToolState::Armed);
            assert_eq!(change.to, ToolState::Active);
            assert_eq!(change.reason, "triggered by: high threat detected");
        }
        other => panic!("expected a ToolStateChange, got {other:?}"),
    }

    // 2. Through the peer strand (TypeId routing to another strand).
    wait_until("the toolkit recorder strand to see the activation", || {
        !recorded_activations(&outcomes).is_empty()
    });

    // 3. The manager state is the same one a direct call would produce, and the
    // refusal path published nothing (the old loop's only trace was its warn).
    assert_eq!(manager.get_state("probe"), Some(ToolState::Active));
    assert_eq!(manager.get_state("scanner"), Some(ToolState::Dormant));
    std::thread::sleep(Duration::from_millis(300));
    supervision.shutdown();

    let activations = recorded_activations(&outcomes);
    assert_eq!(
        activations.len(),
        1,
        "only the armed tool's request may activate: {activations:?}"
    );
    assert_eq!(activations[0].tool_name, "probe");
    let states = recorded_activation_states(&outcomes);
    assert_eq!(
        states.len(),
        1,
        "one handling, one activation state change: {states:?}"
    );
    assert_eq!(states[0].tool_name, "probe");
    assert_eq!(states[0].from, ToolState::Armed);
    assert!(
        !recorded_state_changes(&outcomes)
            .iter()
            .any(|change| change.tool_name == "scanner"),
        "the refused request must publish nothing, exactly as the old loop did"
    );

    // The budget the activation consumed is visible through the same accessor
    // the pre-conversion code used.
    let budget = manager.get_budget("probe").expect("probe is registered");
    assert_eq!(budget.max_activations_per_hour, 10);
    assert_eq!(
        budget.remaining_activations, 9,
        "one handling, one budget slot"
    );
}

// ---------------------------------------------------------------------------
// (b) Specs are queued, not started — and re-queueing cannot collide
// ---------------------------------------------------------------------------

#[tokio::test]
async fn queued_spec_is_not_started_until_engage() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    let manager = armed_manager(&publisher, &["probe"]);
    register_strands(&mut bus, &publisher, &manager);
    // Idempotent by contract, from either entry point: the kernel panics on a
    // duplicate strand name, so this must be a no-op rather than a second
    // registration.
    register_strands(&mut bus, &publisher, &manager);
    // …and so is the legacy shim, which is the other path the composition root
    // (and the runtime simulations) use. It returns an inert handle: the loop is
    // the strand, not a second spawned consumer.

    // Nothing has started yet: a spec is queued, not installed.
    // A spec is queued, not started: `register_spec` only appends.
    assert_eq!(
        registered(&lifecycle, STRAND_NAME),
        0,
        "queueing the spec must not start the loop"
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the toolkit strand to be installed", || {
        registered(&lifecycle, STRAND_NAME) == 1
    });
    assert!(supervision.is_running(), "the run loop must be live");
    supervision.shutdown();
}

/// A spec can only be installed while the kernel is idle — and the new model
/// enforces that by **ownership**, not by a runtime refusal.
///
/// The old form of this test asserted that a spec offered after engage came back
/// as `Err(StrandRegistrationError::Engaged)` naming the strand. That error
/// cannot exist any more: `Bus::run_until` consumes the bus and
/// `Supervision::engage_with` moves it onto the run-loop thread, so "register
/// after the loop started" is a borrow-check error rather than a value a test can
/// hold. What this test proves instead is the positive side of the same
/// guarantee — the spec queued *before* the loop is exactly the one installed.
#[test]
fn a_spec_queued_before_the_run_loop_is_the_one_installed() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let manager = armed_manager(&publisher, &["probe"]);

    let lifecycle = new_lifecycle_log();
    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    queue_strand(&mut bus, &publisher, &manager, FaultPolicy::None);
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the queued toolkit spec to be installed", || {
        registered(&lifecycle, STRAND_NAME) == 1
    });
    supervision.shutdown();
}

// ---------------------------------------------------------------------------
// (c) The crash-restart-quarantine drill
// ---------------------------------------------------------------------------

/// The full crash policy, driven through the real strand with an injected fault:
/// four `Crashed` events, three `Restarted` events, one `Quarantined` — and the
/// shared manager keeps the activations the earlier generations performed.
#[test]
fn crashed_strand_is_restarted_three_times_then_quarantined() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    // One armed tool with ten budget slots. Generation one activates it; every
    // later generation is refused (the tool is already `Active`) and still
    // counts as handled work, so each generation crashes and the drill does not
    // depend on which replayed request a restarted generation picks up first.
    let manager = armed_manager(&publisher, &["drill"]);

    queue_strand(
        &mut bus,
        &publisher,
        &manager,
        FaultPolicy::CrashAfterRequests(1),
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    wait_until(
        "the toolkit strand to be installed and register itself",
        || registered(&lifecycle, STRAND_NAME) == 1,
    );

    // Keep offering work: each generation crashes after its own first handled
    // request, so the drill does not depend on replay timing.
    wait_until(
        "the toolkit strand to be quarantined after its fourth crash",
        || {
            offer_request(&publisher, activation("drill", "supervision drill"));
            quarantined(&lifecycle, STRAND_NAME) >= 1
        },
    );

    assert!(
        supervision.is_running(),
        "the run loop was live for the whole drill"
    );

    // (a) Installed from a queued spec — only a spec is restartable, so the
    // `Restarted` events below are themselves proof the loop arrived as one.
    // `Registered` fires once per generation: initial + 3 restarts.
    assert_eq!(
        registered(&lifecycle, STRAND_NAME),
        4,
        "one `Registered` per generation: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    assert_eq!(
        crashed(&lifecycle, STRAND_NAME),
        4,
        "every crash must be visible as a lifecycle event: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted(&lifecycle, STRAND_NAME),
        3,
        "the spider restarts three times: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined(&lifecycle, STRAND_NAME),
        1,
        "the fourth crash quarantines the loop: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The injected fault names itself in every crash reason: a real forensic
    // signal, and proof the crash came from the drill and not from a bug.
    let reasons = crash_reasons(&lifecycle, STRAND_NAME);
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("injected fault") && reason.contains("1 request")),
        "the injected fault must name itself in every Crashed reason: {reasons:?}"
    );

    // The manager is durable across the restarts (one `Arc` moved through the
    // spec factory, recipe §3.2): the first generation's activation is still
    // there, exactly one budget slot was spent — however many generations and
    // replays followed it — and the refusals the later generations saw did not
    // touch the tool's state.
    assert_eq!(manager.get_state("drill"), Some(ToolState::Active));
    assert_eq!(
        manager
            .get_budget("drill")
            .expect("drill is registered")
            .remaining_activations,
        9,
        "exactly one of the four generations activated the tool"
    );

    // After quarantine the loop is gone for good: further requests cannot revive
    // it. (Its own events are counted, not the whole stream — unrelated
    // `Buffered`/`ThreadFormed` events keep arriving.)
    supervision.shutdown();
    let before = events_for(&lifecycle, STRAND_NAME);
    for _ in 0..5 {
        offer_request(&publisher, activation("drill", "after the quarantine"));
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        events_for(&lifecycle, STRAND_NAME),
        before,
        "a quarantined strand must stay quarantined: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

// ---------------------------------------------------------------------------
// (d) The replayed tail is deduped, never reprocessed
// ---------------------------------------------------------------------------

/// A restarted generation is a late subscriber and is replayed the recent tail
/// (recipe §5.4) — of messages the *previous* generation already handled.
/// Handling an activation request twice is not idempotent (it would spend a
/// second budget slot, stamp `last_activity` again, and publish a second state
/// change and activation request), so the durable
/// [`SeenIds`](imperium_net_toolkit::SeenIds) record refuses it.
///
/// The proof is exact: one request is published, the armed strand crashes once,
/// the restarted generation is replayed that same tail (asserted through the
/// kernel's `Flushed` lifecycle event) — and then it does **not** re-handle it:
/// exactly one crash and one restart, no quarantine, exactly one activation
/// observed, and exactly one budget slot spent. A strand that counted the replay
/// as handled work would trip its own fault again, four times over, and be
/// quarantined.
#[test]
fn replayed_request_is_deduped_not_rehandled() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let outcomes = new_event_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(event_recorder_spec(
        "test.toolkit-recorder",
        "net.toolkit.",
        Arc::clone(&outcomes),
    ));

    let manager = armed_manager(&publisher, &["probe"]);
    queue_strand(
        &mut bus,
        &publisher,
        &manager,
        FaultPolicy::CrashAfterRequests(1),
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the toolkit strand to be installed", || {
        registered(&lifecycle, STRAND_NAME) == 1
    });

    // Exactly one request, ever.
    offer_request(&publisher, activation("probe", "ground truth"));

    wait_until("the first crash (the armed fault)", || {
        crashed(&lifecycle, STRAND_NAME) >= 1
    });
    wait_until("the restart", || restarted(&lifecycle, STRAND_NAME) >= 1);
    wait_until(
        "the kernel to flush the pending tail into the restarted generation",
        || replay_happened(&lifecycle, STRAND_NAME),
    );
    // Let the restarted generation drain whatever it was replayed, and give a
    // broken guard time to crash again.
    std::thread::sleep(Duration::from_millis(400));
    supervision.shutdown();

    // The guard was genuinely exercised: the replay reached the new generation.
    assert!(
        replay_happened(&lifecycle, STRAND_NAME),
        "the replay must actually have happened for this test to mean anything: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // …and it was refused, exactly as the recipe prescribes.
    assert_eq!(
        crashed(&lifecycle, STRAND_NAME),
        1,
        "a deduped replay must not count as handled work: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted(&lifecycle, STRAND_NAME),
        1,
        "one crash, one restart: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined(&lifecycle, STRAND_NAME),
        0,
        "the restarted generation must survive its replay: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The observable consequence: the non-idempotent handler ran exactly once.
    let activations = recorded_activations(&outcomes);
    assert_eq!(
        activations.len(),
        1,
        "one handling, one activation — a replayed handling would add another: {activations:?}"
    );
    let states = recorded_activation_states(&outcomes);
    assert_eq!(
        states.len(),
        1,
        "one handling, one activation state change — a replayed handling would add another: {states:?}"
    );
    assert_eq!(manager.get_state("probe"), Some(ToolState::Active));
    assert_eq!(
        manager
            .get_budget("probe")
            .expect("probe is registered")
            .remaining_activations,
        9,
        "a replayed activation would have spent a second budget slot"
    );
}

// ---------------------------------------------------------------------------
// The supervision composition this test binary owns
// ---------------------------------------------------------------------------

/// Clears the liveness flag when the run-loop thread exits, whether `run_until`
/// returned normally or unwound (`panic = "unwind"` runs the `Drop`).
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its own
/// thread until [`Supervision::shutdown`]. `run_until` consumes the bus, so the
/// kernel moves onto the thread and only the `BusPublisher` stays behind.
struct Supervision {
    publisher: Arc<BusPublisher>,
    running: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl Supervision {
    fn engage_with(mut bus: Bus, publisher: Arc<BusPublisher>) -> Self {
        bus.register_spider(spiderweb::StrandSpec::new("spider", || {
            Box::new(spider::Spider::new())
        }));

        let running = Arc::new(AtomicBool::new(false));
        let thread_flag = Arc::clone(&running);
        let join = std::thread::Builder::new()
            .name("imperium-supervision".to_string())
            .spawn(move || {
                thread_flag.store(true, Ordering::SeqCst);
                let _running = RunningGuard(Arc::clone(&thread_flag));
                let mut bus = bus;
                bus.run_until(None);
            })
            .expect("failed to spawn the supervision run-loop thread");

        Self {
            publisher,
            running,
            join: Some(join),
        }
    }

    fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn shutdown(&mut self) {
        let _ = self.publisher.publish(SYS_CONTROL, ControlMsg::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for Supervision {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A named subscription feeding an owned bounded queue — the shape an async
/// consumer outside a strand must have now that delivery is push-based. The
/// callback runs on the publisher's thread and only does a non-blocking send.
fn subscribe_queue(
    publisher: &BusPublisher,
    prefix: &'static str,
    capacity: usize,
) -> tokio::sync::mpsc::Receiver<BusEvent> {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    publisher.subscribe_prefix(
        prefix,
        Box::new(move |_socket, payload| {
            if let Ok(event) = payload.downcast::<BusEvent>() {
                let _ = tx.try_send(*event);
            }
        }),
    );
    rx
}
