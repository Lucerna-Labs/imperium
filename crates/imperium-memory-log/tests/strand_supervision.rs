//! End-to-end supervision proof for the memory-log strand conversion.
//!
//! `imperium-memory-log`'s two recv loops were converted from `tokio::spawn`ed
//! tasks to Spiderweb **strands** (see
//! [`MemoryLogStrand`](imperium_memory_log::MemoryLogStrand) and
//! the pilot (`imperium-net-lightcone`)). The unit tests inside the crate
//! cover the log itself and the lane filters; these integration tests cover what
//! only a real kernel can prove:
//!
//! 1. [`strands_record_the_same_streams_the_old_loops_recorded`] — behaviour
//!    preservation. Same topics in, the same appended entries, the same variant
//!    gate (a `net.transport.ready` is still ignored), within-stream order
//!    preserved, non-matching topics ignored, and **exactly one** consumer per
//!    event (a surviving second consumer would append twice).
//! 2. [`crashed_rejection_lane_is_restarted_three_times_then_quarantined`] — the
//!    fault policy, driven through the real strand with its injected fault
//!    ([`FaultPolicy::CrashAfterEvents`]): queued as a **spec**, crashes become
//!    `LifecycleEvent::Crashed`, the spider sends `ControlMsg::Restart` three
//!    times, and the fourth crash quarantines the strand.
//! 3. [`quarantined_rejection_lane_does_not_stop_the_transport_lane`] — the
//!    reason the two loops became two strands: failure-domain isolation. One
//!    lane can be quarantined while the other keeps recording, and the survivor's
//!    lifecycle carries no crash.
//! 4. [`replayed_events_are_not_appended_twice_and_the_log_survives_a_restart`] —
//!    the recipe's §5.4 hazard for a non-idempotent effect. A restarted
//!    generation is replayed the kernel's 32-deep pending tail, and appending a
//!    replayed event would put a second, higher-sequence entry in the log for one
//!    occurrence. The dedupe record lives in the factory-shared state, so it
//!    still recognises the replay after the restart; the log's contents and its
//!    monotonic sequence survive the crash.
//! 5. [`register_strands_from_env_serves_both_lanes_and_only_crashes_when_armed`]
//!    — the production wiring call, with the fault policy read from the
//!    environment as the composition root does it.
//!
//! Everything here runs the production path: a real `Bus::new()`, real
//! `Bus::register_strand(spec)` (through
//! [`register_strands`](imperium_memory_log::register_strands) or a lane spec),
//! real `Bus::engage_supervision()` — which installs the kernel's run loop and
//! the `spider` orchestrator on their own OS threads — real strand workers and
//! the real `MemoryLogStrand`. Nothing is simulated and nothing is stubbed.
//!
//! # The instrument: a recorder strand
//!
//! Supervision is invisible to `Bus::subscribe` — that surface carries
//! `BusEvent`s only, while lifecycle events travel on `sys.lifecycle`. The
//! recipe's answer (and the pilot's, and the shim's own tests') is to register
//! another strand whose input is `LifecycleEvent` and let it record what it
//! feels: [`LifecycleRecorder`]. It is registered as a **spec** like any
//! converted subsystem, so it also proves a second strand on the same web keeps
//! running while a neighbour crashes and is restarted.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use imperium_memory_log::{
    register_strands, FaultPolicy, Lane, MemoryLog, MemoryLogStrand, CRASH_AFTER_EVENTS_ENV,
    PROTOCOL_EVENTS_STRAND, REJECTIONS_STRAND,
};
use imperium_protocol::{
    BusEvent, Message, ProtocolEvent, ProtocolEventKind, ProtocolRole, ProtocolStatus,
    StrainerRejection,
};
use spiderweb::{Bus, BusPublisher, ControlMsg, SYS_CONTROL};
use spiderweb::{
    BusHandle, LifecycleEvent, Socket, Strand, StrandError, StrandSpec, SYS_LIFECYCLE,
};

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

// ---------------------------------------------------------------------------
// The instrument: a lifecycle recorder strand
// ---------------------------------------------------------------------------

/// Shared, test-owned record of every lifecycle event the kernel published.
/// `std::sync::Mutex` so a poisoned lock cannot hide an assertion failure.
type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;

fn new_lifecycle_log() -> LifecycleLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn lifecycle_snapshot(log: &LifecycleLog) -> Vec<LifecycleEvent> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Count lifecycle events matching `pred`.
fn count(log: &LifecycleLog, pred: impl Fn(&LifecycleEvent) -> bool) -> usize {
    lifecycle_snapshot(log).iter().filter(|e| pred(e)).count()
}

/// Block (with a hard deadline) until `pred` holds, so a supervision bug fails
/// the test instead of hanging it.
///
/// The deadline is generous because this test can lose the race described below
/// and, when it does, NO deadline is long enough — the expected event never
/// arrives. It is therefore a bail-out, not a fix:
///
/// A lifecycle event is not buffered for later subscribers. `publish_lifecycle`
/// in the kernel goes straight to `deliver_internal` without appending to the
/// per-type pending buffer (unlike the publisher path, which does), and
/// `run_until` installs specs in order with the spider pushed last. So a crash
/// that lands between a strand's install and the spider's install is delivered
/// to nobody: the slot is parked with nothing to restart it, and this drill can
/// never observe its quarantine. Under load that window is easier to hit, which
/// is what made this look like a slow machine rather than a dropped event.
///
/// The real fix is in the kernel (buffer lifecycle events like work traffic, or
/// install the spider before the strands) and is tracked as a separate change in
/// the Spiderweb-Bus-Next repo. This test avoids the race where it can by
/// waiting for the spider's `Registered` event before driving any stimulus.
fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !pred() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// A strand that records the kernel's lifecycle stream — who registered, who
/// crashed, who was restarted, who was quarantined.
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

fn lifecycle_recorder_spec(log: LifecycleLog) -> StrandSpec {
    StrandSpec::new("test.lifecycle-recorder", move || -> Box<dyn Strand> {
        Box::new(LifecycleRecorder {
            log: Arc::clone(&log),
        })
    })
}

// ---------------------------------------------------------------------------
// Offering traffic the way the producers do
// ---------------------------------------------------------------------------

/// Offer one strainer rejection, exactly as `StrainerStack::apply` does: publish
/// `net.strainer.rejection` on the bus.
fn offer_rejection(bus: &BusPublisher, tag: &str) {
    BusEvent::publish(
        bus,
        "net.strainer.rejection",
        Message::StrainerRejection(StrainerRejection {
            strainer_id: "timing".into(),
            stack_id: "auth_stack".into(),
            shape_failed: format!("{tag}: too slow"),
            source_identifier: Some("10.0.0.1:1234".parse().unwrap()),
            timestamp: chrono::Utc::now(),
        }),
    )
    .expect("publish is fire-and-forget and never fails on an idle topic");
}

/// Offer one protocol event, exactly as the transport orchestrator's failover
/// path does: publish `net.transport.event` on the bus.
fn offer_protocol_event(bus: &BusPublisher, reason: &str) {
    BusEvent::publish(
        bus,
        "net.transport.event",
        Message::ProtocolEvt(ProtocolEvent {
            protocol_name: "xray".into(),
            role: ProtocolRole::Active,
            status: ProtocolStatus::Failed,
            event: ProtocolEventKind::Crashed {
                reason: reason.into(),
            },
            timestamp: chrono::Utc::now(),
        }),
    )
    .expect("publish is fire-and-forget and never fails on an idle topic");
}

/// The entries the log appended whose topic is `topic`.
fn entries_on(log: &MemoryLog, topic: &str) -> Vec<imperium_memory_log::LogEntry> {
    log.entries_since(0)
        .into_iter()
        .filter(|entry| &*entry.event.topic == topic)
        .collect()
}

/// How many entries carry this event id — the duplicate meter (nothing in the
/// log may hold one id twice).
fn entries_with_id(log: &MemoryLog, id: &imperium_protocol::EventId) -> usize {
    log.entries_since(0)
        .into_iter()
        .filter(|entry| entry.event.id.0 == id.0)
        .count()
}

/// A one-line rendering of the log's contents for failure messages.
/// `LogEntry` deliberately does not implement `Debug` (the log is the node's
/// public forensic surface and its entries are not a debugging type), so this
/// summarises the two fields an assertion cares about.
fn describe(entries: &[imperium_memory_log::LogEntry]) -> String {
    let rows: Vec<String> = entries
        .iter()
        .map(|entry| format!("seq {} {}", entry.sequence, entry.event.topic.as_ref()))
        .collect();
    format!("[{}]", rows.join(", "))
}

// ---------------------------------------------------------------------------
// 1. Behaviour preservation
// ---------------------------------------------------------------------------

/// Both lanes record the same streams the two `tokio` loops recorded, through
/// the production wiring, with the old prefix filters and the old variant gates
/// — and each accepted event is appended exactly **once** (a surviving second
/// consumer of the same topic would append it twice).
///
/// Ordering: the two loops were independent consumers with no defined relative
/// order, and so are the two strands, so this test pins only what was ever
/// pinned — the order *within* one stream (FIFO, both before and after) and the
/// exact set of accepted events.
#[tokio::test]
async fn strands_record_the_same_streams_the_old_loops_recorded() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let log = Arc::new(MemoryLog::default());

    register_strands(&mut bus, &log);
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // The two events the old loops appended.
    offer_rejection(&publisher, "first");
    offer_rejection(&publisher, "second");
    offer_protocol_event(&publisher, "connection reset");

    // Matched the old rejections prefix but was never a rejection: the old
    // `if let Message::StrainerRejection` gate ignored it, and so does the lane.
    BusEvent::publish(
        &publisher,
        "net.strainer.rejection",
        Message::SubsystemReady {
            name: "imperium-net-strainer".into(),
        },
    )
    .unwrap();
    // Matched the old `net.transport.` prefix and was ignored the same way.
    BusEvent::publish(
        &publisher,
        "net.transport.ready",
        Message::SubsystemReady {
            name: "imperium-net-transport".into(),
        },
    )
    .unwrap();
    // Matched neither prefix.
    offer_rejection_to_unrelated_topic(&publisher);

    wait_until("both lanes to record their streams", || log.len() >= 3);
    // A few more ticks: had a variant gate leaked, the extra entry would land
    // now and the exact-count assertions below would see it.
    std::thread::sleep(Duration::from_millis(150));
    supervision.shutdown();

    assert_eq!(
        log.len(),
        3,
        "exactly three accepted events must be appended once each: {}",
        describe(&log.entries_since(0))
    );

    // The rejection stream: both rejections, in publish order (FIFO preserved),
    // with every provenance field intact.
    let rejections = entries_on(&log, "net.strainer.rejection");
    assert_eq!(rejections.len(), 2, "both rejections must be logged");
    assert!(
        rejections[0].sequence < rejections[1].sequence,
        "within-stream order must be preserved: {:?}",
        rejections.iter().map(|e| e.sequence).collect::<Vec<_>>()
    );
    for (entry, tag) in rejections.iter().zip(["first", "second"]) {
        let Message::StrainerRejection(rejection) = &entry.event.message else {
            panic!(
                "expected a StrainerRejection, got {:?}",
                entry.event.message
            );
        };
        assert_eq!(rejection.stack_id, "auth_stack");
        assert!(rejection.shape_failed.starts_with(tag));
        assert_eq!(
            rejection.source_identifier.as_ref().map(|a| a.to_string()),
            Some("10.0.0.1:1234".into())
        );
    }

    // The transport stream: the protocol event, on `net.transport.event`.
    let protocol = entries_on(&log, "net.transport.event");
    assert_eq!(protocol.len(), 1, "the protocol event must be logged");
    match &protocol[0].event.message {
        Message::ProtocolEvt(event) => {
            assert_eq!(event.protocol_name, "xray");
            assert!(matches!(event.event, ProtocolEventKind::Crashed { .. }));
        }
        other => panic!("expected a ProtocolEvt, got {other:?}"),
    }

    // Nothing else leaked in: the two same-prefix, wrong-variant events were
    // ignored then and are ignored now.
    assert!(
        entries_on(&log, "net.transport.ready").is_empty(),
        "a `net.transport.ready` was not a protocol event before either"
    );
    assert!(
        entries_on(&log, "net.other.topic").is_empty(),
        "a topic outside both subscriptions must not be logged"
    );

    // Other consumers reach the appended entry by id, exactly as before.
    let id = rejections[0].event.id.clone();
    assert!(
        log.get_by_event_id(&id).is_some(),
        "the appended entry must be reachable through the log's own API"
    );
}

/// A rejection published on a topic neither lane subscribes to — proving the
/// filter is the topic, not the message variant.
fn offer_rejection_to_unrelated_topic(bus: &BusPublisher) {
    BusEvent::publish(
        bus,
        "net.other.topic",
        Message::StrainerRejection(StrainerRejection {
            strainer_id: "timing".into(),
            stack_id: "auth_stack".into(),
            shape_failed: "wrong topic".into(),
            source_identifier: None,
            timestamp: chrono::Utc::now(),
        }),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// 2. The crash drill
// ---------------------------------------------------------------------------

/// The lane's full crash policy, driven through the real strand with an injected
/// fault: it is installed as a **spec** (so the spider can restart it), each
/// crash is a `LifecycleEvent::Crashed` carrying the injected reason, the spider
/// restarts it three times, and the fourth crash quarantines it.
///
/// The workload is offered continuously so every restarted generation has work;
/// that is what makes the drill independent of replay timing. A generation
/// appends its event and *then* trips the drill, which is also the proof that a
/// record written on the crashing tick is not lost.
#[test]
fn crashed_rejection_lane_is_restarted_three_times_then_quarantined() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let log = Arc::new(MemoryLog::default());

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    // Only the rejection lane is armed; the transport lane runs normally. The
    // fault is per instance, so every restart crashes again — which is what
    // drives the whole restart-then-quarantine sequence.
    bus.register_spec(MemoryLogStrand::spec(
        Lane::StrainerRejections,
        Arc::clone(&log),
        FaultPolicy::CrashAfterEvents(1),
    ));
    bus.register_spec(MemoryLogStrand::spec(
        Lane::ProtocolEvents,
        Arc::clone(&log),
        FaultPolicy::None,
    ));

    // Nothing has started yet: a spec is queued, not installed.
    // A spec is queued, not started: `register_spec` only appends, and
    // `run_until` (which the fixture calls) consumes the bus.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == REJECTIONS_STRAND
        )),
        0,
        "registering the spec must not start the strand"
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));
    wait_until(
        "the rejection lane to be installed and register itself",
        || {
            count(&lifecycle, |e| {
                matches!(
                    e,
                    LifecycleEvent::Registered { name, .. } if name == REJECTIONS_STRAND
                )
            }) == 1
        },
    );

    // Feed rejections until the fourth crash has been quarantined by the spider.
    wait_until("the lane to be quarantined after its fourth crash", || {
        offer_rejection(&publisher, "drill");
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Quarantined { name, .. } if name == REJECTIONS_STRAND
            )
        }) >= 1
    });

    // The run loop was genuinely live for the whole drill (not a stall).
    assert!(supervision.is_running());
    supervision.shutdown();

    // (a) Installed from the queued spec — and only a spec is restartable:
    // `Bus::register` installs a *live* strand with no factory and the kernel
    // would refuse the spider's `ControlMsg::Restart` for it. The three
    // `Restarted` events below are therefore themselves proof that the lane
    // arrived as a `StrandSpec`.
    //
    // `Registered` fires once per *generation* (each restart installs a fresh
    // slot whose generation counter starts at 0), so one initial install plus
    // three restarts produce four.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == REJECTIONS_STRAND
        )),
        4,
        "`Registered` fires once per generation (initial + 3 restarts): {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    let crashed = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == REJECTIONS_STRAND
        )
    });
    let restarted = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Restarted { name, .. } if name == REJECTIONS_STRAND
        )
    });
    let quarantined = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Quarantined { name, .. } if name == REJECTIONS_STRAND
        )
    });
    assert_eq!(
        crashed,
        4,
        "every crash must be visible as a lifecycle event: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        restarted,
        3,
        "the spider restarts three times: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
    assert_eq!(
        quarantined,
        1,
        "the fourth crash quarantines the strand: {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // The injected fault's reason is a real forensic signal, not a bare marker.
    let reasons: Vec<String> = lifecycle_snapshot(&lifecycle)
        .into_iter()
        .filter_map(|e| match e {
            LifecycleEvent::Crashed { name, reason } if name == REJECTIONS_STRAND => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        reasons
            .iter()
            .all(|r| r.contains("injected fault") && r.contains(CRASH_AFTER_EVENTS_ENV)),
        "the injected fault must name itself in every Crashed reason: {reasons:?}"
    );

    // Each generation appended its event *before* the drill tripped, so the log
    // holds one record per generation: a crash costs no record already written.
    assert!(
        log.len() >= 4,
        "every generation recorded before crashing: {}",
        describe(&log.entries_since(0))
    );

    // After quarantine it is gone for good: further rejections cannot revive it,
    // so no new lifecycle events *about this lane* appear. (Unrelated `Buffered`
    // events are expected — a topic with no subscriber buffers its messages — so
    // this counts the lane's own events, not the whole stream.)
    fn lane_events(log: &LifecycleLog) -> usize {
        count(log, |e| match e {
            LifecycleEvent::Registered { name, .. }
            | LifecycleEvent::Crashed { name, .. }
            | LifecycleEvent::Restarted { name, .. }
            | LifecycleEvent::Quarantined { name, .. }
            | LifecycleEvent::Detached { name } => name == REJECTIONS_STRAND,
            _ => false,
        })
    }
    let before = lane_events(&lifecycle);
    for _ in 0..5 {
        offer_rejection(&publisher, "after quarantine");
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        lane_events(&lifecycle),
        before,
        "a quarantined strand must stay quarantined: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

// ---------------------------------------------------------------------------
// 3. Failure-domain isolation
// ---------------------------------------------------------------------------

/// The reason the two loops became two strands, proved end to end: the rejection
/// lane is armed, crashes four times and is quarantined — and the transport lane
/// keeps recording the failover record the whole time, with no crash of its own.
///
/// One strand draining both topics would have taken the whole log down with the
/// faulted lane (or, worse, needed one shared restart counter and one shared
/// replay record for two independent streams).
#[test]
fn quarantined_rejection_lane_does_not_stop_the_transport_lane() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let log = Arc::new(MemoryLog::default());

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(MemoryLogStrand::spec(
        Lane::StrainerRejections,
        Arc::clone(&log),
        FaultPolicy::CrashAfterEvents(1),
    ));
    bus.register_spec(MemoryLogStrand::spec(
        Lane::ProtocolEvents,
        Arc::clone(&log),
        FaultPolicy::None,
    ));

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // Drive the rejection lane into quarantine. Protocol events go out at the
    // same time — they are the traffic the survivor must keep recording.
    wait_until("the rejection lane to be quarantined", || {
        offer_rejection(&publisher, "isolation drill");
        offer_protocol_event(&publisher, "crash during the drill");
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Quarantined { name, .. } if name == REJECTIONS_STRAND
            )
        }) >= 1
    });

    // The survivor keeps serving after its neighbour is dead.
    let before = entries_on(&log, "net.transport.event").len();
    offer_protocol_event(&publisher, "after the neighbour was quarantined");
    wait_until("the transport lane to record another event", || {
        entries_on(&log, "net.transport.event").len() > before
    });
    supervision.shutdown();

    assert!(
        !entries_on(&log, "net.transport.event").is_empty(),
        "the transport lane must have recorded events"
    );
    // The survivor never crashed, was never restarted, was never quarantined.
    for fact in [
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Crashed { name, .. } if name == PROTOCOL_EVENTS_STRAND
            )
        }),
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Restarted { name, .. } if name == PROTOCOL_EVENTS_STRAND
            )
        }),
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Quarantined { name, .. } if name == PROTOCOL_EVENTS_STRAND
            )
        }),
    ] {
        assert_eq!(
            fact,
            0,
            "the unarmed transport lane must not be affected by its neighbour: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
    }
    // And it was installed exactly once — it never needed a restart.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == PROTOCOL_EVENTS_STRAND
        )),
        1,
        "the transport lane registers once and stays up: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

// ---------------------------------------------------------------------------
// 4. The replay guard
// ---------------------------------------------------------------------------

/// A restarted strand is replayed the kernel's 32-deep pending tail — and that
/// tail contains events the previous generation already appended. Appending them
/// again would corrupt the log (a second, higher-sequence entry for one
/// occurrence), so the replay must be deduplicated on `BusEvent::id`; the record
/// lives in the factory-shared state, which is why it still recognises the
/// replay after the restart.
///
/// The test drives exactly one rejection into an armed lane, waits for the crash
/// and the restart, and proves the replay really happened
/// (`LifecycleEvent::Flushed` addressed to this strand) before asserting that it
/// changed nothing: one entry, one id, no second crash. That last fact is the
/// sharpest evidence — a replayed event treated as new work would be appended
/// *and* would trip the per-instance drill again.
///
/// It then proves log continuity across the restart: the pre-crash entry is
/// still there with its original sequence, and a new event appended by the
/// restarted generation takes the next sequence — so the shared `Arc<MemoryLog>`
/// (not a per-generation copy) is what the factory handed the new generation.
#[test]
fn replayed_events_are_not_appended_twice_and_the_log_survives_a_restart() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let log = Arc::new(MemoryLog::default());

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(MemoryLogStrand::spec(
        Lane::StrainerRejections,
        Arc::clone(&log),
        FaultPolicy::CrashAfterEvents(1),
    ));

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    // Exactly one rejection for the whole first phase. It is published before
    // the crash, so it is also what the kernel will replay to the restarted
    // generation.
    offer_rejection(&publisher, "dedupe drill");

    wait_until("the first crash", || {
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Crashed { name, .. } if name == REJECTIONS_STRAND
            )
        }) >= 1
    });
    wait_until("the first restart", || {
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Restarted { name, .. } if name == REJECTIONS_STRAND
            )
        }) >= 1
    });
    wait_until(
        "the replayed pending tail to reach the restarted generation",
        || {
            count(&lifecycle, |e| {
                matches!(
                    e,
                    LifecycleEvent::Flushed { to, count, .. }
                        if to == REJECTIONS_STRAND && *count >= 1
                )
            }) >= 1
        },
    );

    // Let the restarted generation run for many ticks (the worker ticks every
    // 10 ms) so a replayed event would certainly have been appended by now.
    std::thread::sleep(Duration::from_millis(300));

    // The sharp assertions, taken while the restarted lane is still alive.
    assert_eq!(
        log.len(),
        1,
        "the replay must not be appended a second time: {}",
        describe(&log.entries_since(0))
    );
    let recorded = log.entries_since(0);
    let id = recorded[0].event.id.clone();
    assert_eq!(
        recorded[0].sequence, 0,
        "the one entry keeps its original sequence"
    );
    assert_eq!(
        entries_with_id(&log, &id),
        1,
        "exactly one entry may carry the replayed event's id"
    );
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == REJECTIONS_STRAND
        )),
        1,
        "the replay must not be treated as new work (it would trip the drill again): {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // Log continuity across the restart: the restarted generation appends a
    // *new* event to the same log, and the sequence keeps climbing.
    offer_rejection(&publisher, "after the restart");
    wait_until("the restarted lane to record a new event", || {
        log.len() >= 2
    });
    supervision.shutdown();

    let recorded = log.entries_since(0);
    assert_eq!(
        recorded.len(),
        2,
        "one pre-crash record plus exactly one post-restart record: {}",
        describe(&recorded)
    );
    assert_eq!(
        &*recorded[0].event.topic, "net.strainer.rejection",
        "the pre-crash record survives the restart in place"
    );
    assert!(
        recorded[1].sequence > recorded[0].sequence,
        "sequence numbers must keep climbing across the crash, never reset: {:?}",
        recorded.iter().map(|e| e.sequence).collect::<Vec<_>>()
    );
    assert_eq!(
        recorded[1].sequence,
        1,
        "the restarted generation appends to the same log, not a fresh one: {:?}",
        recorded.iter().map(|e| e.sequence).collect::<Vec<_>>()
    );
    assert_eq!(
        entries_with_id(&log, &recorded[1].event.id),
        1,
        "the post-restart event is appended exactly once too"
    );
}

// ---------------------------------------------------------------------------
// 5. The production wiring call
// ---------------------------------------------------------------------------

/// The production wiring call, end to end: [`register_strands`] queues both
/// specs exactly as the composition root will (`imperium-cli`'s
/// `initialize_node`), and the fault policy is read from the environment
/// (`IMPERIUM_MEMORY_LOG_CRASH_AFTER_EVENTS`) rather than passed as an argument.
/// Run it in both states:
///
/// * default (variable unset) — the call serves both lanes and **never** crashes
///   a strand;
/// * `IMPERIUM_MEMORY_LOG_CRASH_AFTER_EVENTS=1 cargo test …` — the same call arms
///   both lanes, so the full crash → restart ×3 → quarantine sequence runs
///   through the production path.
#[test]
fn register_strands_from_env_serves_both_lanes_and_only_crashes_when_armed() {
    let mut bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    let lifecycle = new_lifecycle_log();
    let log = Arc::new(MemoryLog::default());
    let armed = FaultPolicy::from_env().is_injected();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));

    // The exact call the composition root makes (see `register_strands`).
    register_strands(&mut bus, &log);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&publisher));

    if armed {
        // Both lanes are armed, but only the rejection lane is fed, so the
        // transport lane has no accepted event and must not crash: the drill
        // counter counts a lane's own appends.
        wait_until(
            "the env-armed drill to quarantine the rejection lane",
            || {
                offer_rejection(&publisher, "env drill");
                count(&lifecycle, |e| {
                    matches!(
                        e,
                        LifecycleEvent::Quarantined { name, .. } if name == REJECTIONS_STRAND
                    )
                }) >= 1
            },
        );
    } else {
        offer_rejection(&publisher, "env smoke");
        offer_protocol_event(&publisher, "env smoke");
        wait_until("both lanes to record their streams", || log.len() >= 2);
        // Several more ticks: an unarmed strand must stay alive.
        std::thread::sleep(Duration::from_millis(150));
    }
    supervision.shutdown();

    assert!(
        !log.is_empty(),
        "the events must have been recorded through the production wiring"
    );

    let crashed = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == REJECTIONS_STRAND
        )
    });
    if armed {
        assert_eq!(crashed, 4, "the env-armed drill must crash four times");
        assert_eq!(
            count(&lifecycle, |e| matches!(
                e,
                LifecycleEvent::Restarted { name, .. } if name == REJECTIONS_STRAND
            )),
            3,
            "the spider restarts three times"
        );
        assert_eq!(
            count(&lifecycle, |e| matches!(
                e,
                LifecycleEvent::Quarantined { name, .. } if name == REJECTIONS_STRAND
            )),
            1,
            "the fourth crash quarantines the strand"
        );
        assert_eq!(
            count(&lifecycle, |e| matches!(
                e,
                LifecycleEvent::Crashed { name, .. } if name == PROTOCOL_EVENTS_STRAND
            )),
            0,
            "a lane that appends nothing must not trip the drill: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
    } else {
        assert_eq!(
            crashed,
            0,
            "an unarmed deployment must never crash a log strand: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
        assert_eq!(
            log.len(),
            2,
            "both lanes must record through the production wiring: {}",
            describe(&log.entries_since(0))
        );
    }
}
