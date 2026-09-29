//! End-to-end supervision proof for the transport hardening-lane conversion.
//!
//! `imperium-net-transport`'s third standing recv loop —
//! `HardeningController::subscribe_hardening_profiles`, which subscribed
//! `net.transport.hardening.apply` and applied a `ProtocolHardeningProfile` to
//! the controller — used to be a `tokio::spawn`ed task. It is a Spiderweb
//! **strand** now ([`HardeningStrand`]), the third strand of
//! `imperium_net_transport::strand`, queued by
//! [`register_strands`](imperium_net_transport::register_strands) or by
//! [`queue_hardening`](imperium_net_transport::queue_hardening). See
//! the pilot (`imperium-net-lightcone`); the unit tests in
//! `src/strand.rs` cover the filters and the fault-policy parsing, and
//! `tests/orchestrator_supervision.rs` is the sibling file for the other two
//! lanes. These tests cover what only a real kernel can prove:
//!
//! 1. [`hardening_lane_applies_profiles_and_publishes_status_to_shim_subscribers`] —
//!    behaviour preservation: the same topic in, the same status topic out, the
//!    same accept *and* reject semantics, and the profile lands on the *same*
//!    `HardeningController` the composition root owns (so `active_profile()`
//!    still answers).
//! 2. [`register_strands_wires_the_hardening_lane_too`] — one call site wires
//!    all three strands; a spec is queued, not started; and re-queueing from the
//!    legacy shim is idempotent, with the composition root's own controller
//!    winning when it registered first (the CLI's order).
//! 3. [`crashed_hardening_lane_is_restarted_three_times_then_quarantined`] — the
//!    crash policy, driven through the real lane with an injected fault: four
//!    `Crashed`, three `Restarted`, one `Quarantined`.
//! 4. [`replayed_profile_is_deduped_not_reapplied`] — the recipe's §5.4 hazard
//!    for a non-idempotent consumer: a restarted generation is replayed the
//!    recent tail, and applying a profile twice publishes a second acceptance
//!    status. The durable `SeenIds` record refuses the replay, which the status
//!    count makes exactly measurable.
//!
//! Everything here runs the production path: a real `Bus::new()`, real
//! `queue_hardening`/`Bus::register_strand(spec)`, real `Bus::engage_supervision()`
//! (kernel run loop + spider on their own OS threads), real strand workers, and
//! the real [`HardeningStrand`]. Nothing is simulated and nothing is stubbed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use imperium_net_transport::strand::{
    queue_hardening, HardeningFaultPolicy, HARDENING_STRAND, PROTOCOL_EVENTS_STRAND,
    THREAT_ASSESSMENTS_STRAND,
};
use imperium_net_transport::{register_strands, HardeningController};
use imperium_protocol::{BusEvent, Message, ProtocolHardeningProfile, ProtocolHardeningStatus};
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
/// Shared, test-owned record of the controller's output a recorder strand saw.
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
/// is assertable.
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

/// The hardening statuses a recorder strand saw, in arrival order.
///
/// The topic is filtered exactly: `net.transport.hardening.apply` carries
/// profiles and `net.transport.hardening.status` carries statuses, and a
/// prefix-only match would mix them.
fn recorded_statuses(log: &EventLog) -> Vec<ProtocolHardeningStatus> {
    event_snapshot(log)
        .into_iter()
        .filter(|event| &*event.topic == "net.transport.hardening.status")
        .filter_map(|event| match event.message {
            Message::ProtocolHardeningStatus(status) => Some(status),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A valid profile with a reason that identifies the publisher, so a test can
/// tell one apply from another.
fn profile(reason: &str) -> ProtocolHardeningProfile {
    ProtocolHardeningProfile {
        reason: reason.to_string(),
        ..HardeningController::resilience_profile(Some("xray".to_string()))
    }
}

/// A profile `HardeningController::validate` must refuse (padding overhead above
/// the 50% ceiling) — the old loop's reject path.
fn invalid_profile() -> ProtocolHardeningProfile {
    let mut profile = HardeningController::balanced_profile(None);
    profile.reason = "over budget".to_string();
    profile.traffic_morph.cover_traffic_ppm = 200_000;
    profile
}

/// Offer one profile to the lane exactly as the orchestrator and the control
/// surface do: publish `net.transport.hardening.apply` on the bus.
fn offer_profile(bus: &BusPublisher, profile: ProtocolHardeningProfile) {
    BusEvent::publish(
        bus,
        "net.transport.hardening.apply",
        Message::ProtocolHardeningProfile(profile),
    )
    .expect("publish is fire-and-forget and never fails");
}

// ---------------------------------------------------------------------------
// (a) Behaviour preservation
// ---------------------------------------------------------------------------

/// The lane applies what the old loop applied, through the same topic pair, to
/// the *same* controller instance the composition root holds — and the reject
/// path is preserved: the status is published as `accepted: false` and the
/// previously applied profile survives.
#[tokio::test]
async fn hardening_lane_applies_profiles_and_publishes_status_to_shim_subscribers() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let statuses = new_event_log();

    bus.register_spec(event_recorder_spec(
        "test.hardening-recorder",
        "net.transport.hardening.",
        Arc::clone(&statuses),
    ));

    // The controller the composition root owns: the lane must drive *this* one.
    let controller = Arc::new(HardeningController::new(Arc::clone(&publisher)));
    queue_hardening(
        &mut bus,
        &publisher,
        &controller,
        HardeningFaultPolicy::None,
    );

    // The shim's own subscriber surface — the path every existing consumer uses.
    let mut status_sub = subscribe_queue(&publisher, "net.transport.hardening.status", 64);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // 1. The accept path.
    offer_profile(&publisher, profile("lane accepts"));

    let accepted = tokio::time::timeout(Duration::from_secs(10), status_sub.recv())
        .await
        .expect("the hardening status must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    match accepted.message {
        Message::ProtocolHardeningStatus(status) => {
            assert_eq!(status.profile_id, "resilience-rf-inspired");
            assert_eq!(status.protocol_name.as_deref(), Some("xray"));
            assert!(status.accepted);
            assert_eq!(status.reason, "profile accepted");
        }
        other => panic!("expected a ProtocolHardeningStatus, got {other:?}"),
    }
    assert_eq!(
        controller
            .active_profile()
            .expect("the accepted profile must be the controller's active one")
            .reason,
        "lane accepts",
        "the lane must drive the controller the composition root owns"
    );

    // 2. The reject path: an invalid profile is refused with the same error text
    // the old loop warned with, and the active profile is untouched.
    let before = controller.active_profile().expect("active");
    offer_profile(&publisher, invalid_profile());

    let refused = tokio::time::timeout(Duration::from_secs(10), status_sub.recv())
        .await
        .expect("the rejection status must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    match refused.message {
        Message::ProtocolHardeningStatus(status) => {
            assert!(!status.accepted);
            assert!(
                status
                    .reason
                    .contains("cover traffic budget must be at or below 10%"),
                "the refusal must carry the validator's reason: {}",
                status.reason
            );
        }
        other => panic!("expected a ProtocolHardeningStatus, got {other:?}"),
    }
    assert_eq!(
        controller.active_profile().map(|p| p.reason),
        Some(before.reason.clone()),
        "a refused profile must not replace the active one"
    );

    // 3. Through the peer strand (TypeId routing to another strand).
    wait_until("the hardening recorder strand to see both statuses", || {
        recorded_statuses(&statuses).len() >= 2
    });
    supervision.shutdown();

    let seen = recorded_statuses(&statuses);
    assert_eq!(seen.len(), 2, "one handling, one status: {seen:?}");
    assert!(seen[0].accepted);
    assert!(!seen[1].accepted);
}

// ---------------------------------------------------------------------------
// (b) One call site wires all three strands; re-queueing cannot collide
// ---------------------------------------------------------------------------

/// `register_strands(&bus)` — the supervisor's single call — queues the
/// orchestrator's two lanes **and** the hardening lane, installs nothing until
/// `engage_supervision()`, and coexists with the legacy
/// `subscribe_hardening_profiles` shim that the CLI and the runtime simulations
/// still call: the first registration wins, so the composition root's own
/// controller is the one the lane drives.
#[tokio::test]
async fn register_strands_wires_the_hardening_lane_too() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let statuses = new_event_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(event_recorder_spec(
        "test.hardening-recorder",
        "net.transport.hardening.",
        Arc::clone(&statuses),
    ));

    // The CLI's order: the composition root's own controller queues the lane
    // first, so the lane drives *that* controller …
    let controller = Arc::new(HardeningController::new(Arc::clone(&publisher)));
    queue_hardening(
        &mut bus,
        &publisher,
        &controller,
        HardeningFaultPolicy::from_env(),
    );
    // … and the single crate-level call picks up the same lane without a
    // duplicate-name panic.
    register_strands(&mut bus, &publisher);

    // Nothing has started yet: specs are queued, not installed. (`register_spec`
    // only appends; only `run_until` installs, and it consumes the bus.)
    assert_eq!(
        registered(&lifecycle, HARDENING_STRAND),
        0,
        "queueing the spec must not start the hardening lane"
    );
    assert_eq!(registered(&lifecycle, PROTOCOL_EVENTS_STRAND), 0);
    assert_eq!(registered(&lifecycle, THREAT_ASSESSMENTS_STRAND), 0);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("all three transport strands to be installed", || {
        registered(&lifecycle, HARDENING_STRAND) == 1
            && registered(&lifecycle, PROTOCOL_EVENTS_STRAND) == 1
            && registered(&lifecycle, THREAT_ASSESSMENTS_STRAND) == 1
    });
    assert!(supervision.is_running(), "the run loop must be live");

    // The winning registration is the composition root's controller.
    offer_profile(&publisher, profile("first registration wins"));
    wait_until("the lane to apply the profile", || {
        controller
            .active_profile()
            .is_some_and(|applied| applied.reason == "first registration wins")
    });
    supervision.shutdown();

    let seen = recorded_statuses(&statuses);
    assert_eq!(seen.len(), 1, "one apply, one status: {seen:?}");
    assert!(seen[0].accepted);
}

// ---------------------------------------------------------------------------
// (c) The crash-restart-quarantine drill
// ---------------------------------------------------------------------------

/// The hardening lane's full crash policy, driven through the real strand with
/// an injected fault: four `Crashed` events, three `Restarted` events, one
/// `Quarantined` — and the controller the composition root owns kept the work of
/// every generation that ran before the quarantine.
#[test]
fn crashed_hardening_lane_is_restarted_three_times_then_quarantined() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    let controller = Arc::new(HardeningController::new(Arc::clone(&publisher)));
    queue_hardening(
        &mut bus,
        &publisher,
        &controller,
        HardeningFaultPolicy::CrashAfterProfiles(1),
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until(
        "the hardening lane to be installed and register itself",
        || registered(&lifecycle, HARDENING_STRAND) == 1,
    );

    // Each generation crashes after its own first applied profile, so the drill
    // does not depend on replay timing.
    let mut index = 0u32;
    wait_until(
        "the hardening lane to be quarantined after its fourth crash",
        || {
            offer_profile(&publisher, profile(&format!("drill {index}")));
            index = index.saturating_add(1);
            quarantined(&lifecycle, HARDENING_STRAND) >= 1
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
        registered(&lifecycle, HARDENING_STRAND),
        4,
        "one `Registered` per generation: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    assert_eq!(
        crashed(&lifecycle, HARDENING_STRAND),
        4,
        "every crash must be visible as a lifecycle event: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted(&lifecycle, HARDENING_STRAND),
        3,
        "the spider restarts three times: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined(&lifecycle, HARDENING_STRAND),
        1,
        "the fourth crash quarantines the lane: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The injected fault names itself in every crash reason: a real forensic
    // signal, and proof the crash came from the drill and not from a bug.
    let reasons = crash_reasons(&lifecycle, HARDENING_STRAND);
    assert!(
        reasons
            .iter()
            .all(|reason| reason.contains("injected fault") && reason.contains("1 profile")),
        "the injected fault must name itself in every Crashed reason: {reasons:?}"
    );

    // The controller is durable across the restarts: the last generation's
    // profile is still the active one, and it is a `drill` profile — the lane
    // really was applying work between crashes.
    let active = controller
        .active_profile()
        .expect("a generation applied a profile before crashing");
    assert!(
        active.reason.starts_with("drill "),
        "the active profile must be one this drill published: {}",
        active.reason
    );

    // After quarantine the lane is gone for good: further profiles cannot revive
    // it. (Its own events are counted, not the whole stream — unrelated
    // `Buffered`/`ThreadFormed` events keep arriving.)
    supervision.shutdown();
    let before = events_for(&lifecycle, HARDENING_STRAND);
    for offset in 0..5 {
        offer_profile(
            &publisher,
            profile(&format!("after the quarantine {offset}")),
        );
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        events_for(&lifecycle, HARDENING_STRAND),
        before,
        "a quarantined lane must stay quarantined: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_ne!(
        controller.active_profile().map(|p| p.reason),
        Some("after the quarantine 4".to_string()),
        "a quarantined lane must not keep applying profiles"
    );
}

// ---------------------------------------------------------------------------
// (d) The replayed tail is deduped, never reapplied
// ---------------------------------------------------------------------------

/// A restarted generation is a late subscriber and is replayed the recent tail
/// (recipe §5.4) — of messages the *previous* generation already handled.
/// `HardeningController::apply` is not idempotent in what it publishes (a second
/// apply of the same profile emits a second `net.transport.hardening.status`
/// with a fresh `active_at`), so the durable
/// [`SeenIds`](imperium_net_transport::strand::SeenIds) record refuses it.
///
/// The proof is observable: one profile is published, the armed lane crashes
/// once, the restarted generation is replayed that same profile (asserted
/// through the kernel's `Flushed` lifecycle event) — and exactly one acceptance
/// status is ever published. A lane that re-applied the replay would publish two.
#[test]
fn replayed_profile_is_deduped_not_reapplied() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let statuses = new_event_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(event_recorder_spec(
        "test.hardening-recorder",
        "net.transport.hardening.",
        Arc::clone(&statuses),
    ));

    let controller = Arc::new(HardeningController::new(Arc::clone(&publisher)));
    queue_hardening(
        &mut bus,
        &publisher,
        &controller,
        HardeningFaultPolicy::CrashAfterProfiles(1),
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until("the hardening lane to be installed", || {
        registered(&lifecycle, HARDENING_STRAND) == 1
    });

    // Exactly one profile, ever.
    offer_profile(&publisher, profile("ground truth"));

    wait_until("the first crash (the armed fault)", || {
        crashed(&lifecycle, HARDENING_STRAND) >= 1
    });
    wait_until("the restart", || {
        restarted(&lifecycle, HARDENING_STRAND) >= 1
    });
    wait_until(
        "the kernel to flush the pending tail into the restarted generation",
        || replay_happened(&lifecycle, HARDENING_STRAND),
    );
    // Let the restarted generation drain whatever it was replayed, and give a
    // broken guard time to crash again.
    std::thread::sleep(Duration::from_millis(400));
    supervision.shutdown();

    // The guard was genuinely exercised: the replay reached the new generation.
    assert!(
        replay_happened(&lifecycle, HARDENING_STRAND),
        "the replay must actually have happened for this test to mean anything: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // …and it was refused, exactly as the recipe prescribes.
    assert_eq!(
        crashed(&lifecycle, HARDENING_STRAND),
        1,
        "a deduped replay must not count as handled work: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted(&lifecycle, HARDENING_STRAND),
        1,
        "one crash, one restart: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined(&lifecycle, HARDENING_STRAND),
        0,
        "the restarted generation must survive its replay: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The observable consequence: the non-idempotent handler ran exactly once.
    let seen = recorded_statuses(&statuses);
    assert_eq!(
        seen.len(),
        1,
        "one apply, one status — a replayed apply would publish a second: {seen:?}"
    );
    assert!(seen[0].accepted);
    assert_eq!(
        controller.active_profile().map(|p| p.reason),
        Some("ground truth".to_string())
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
        bus.register_spider(StrandSpec::new(
            "spider",
            || Box::new(spider::Spider::new()),
        ));

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
/// consumer outside a strand must have now that delivery is push-based.
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
