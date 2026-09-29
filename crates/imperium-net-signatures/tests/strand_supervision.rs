//! End-to-end supervision proof for the signature-extraction strand conversion.
//!
//! `imperium-net-signatures`' extraction loop used to be a `tokio::spawn`ed recv
//! loop holding a `BusSubscription` for `net.signatures.extraction_request`. It
//! is now a Spiderweb **strand** ([`ExtractionStrand`]); see
//! the pilot (`imperium-net-lightcone`) for the recipe and
//! `crates/imperium-net-lightcone/tests/pilot_supervision.rs` for the pilot this
//! file follows. The crate's unit tests cover the *service*; these integration
//! tests cover the part only a real kernel can prove:
//!
//! 1. [`extraction_strand_serves_requests_and_publishes_to_shim_subscribers`]
//!    and [`extraction_strand_publishes_extraction_failed_to_shim_subscribers`]
//!    — behaviour preservation. Same topic in, same topics out, same candidate
//!    payloads (persisted to the same store, staged in the same staging area),
//!    and the events reach the *same* `Bus::subscribe` subscribers the old
//!    `tokio` loop's `Bus::publish` reached.
//! 2. [`crashed_extraction_strand_is_restarted_three_times_then_quarantined`] —
//!    the fault policy, driven through the real strand with its injected fault
//!    ([`FaultPolicy::CrashAfterRequests`]): registered as a **spec**, crashes
//!    become `LifecycleEvent::Crashed`, the spider sends `ControlMsg::Restart`
//!    three times, and the fourth crash quarantines the strand.
//! 3. [`replayed_extraction_requests_are_deduplicated_across_a_restart`] — the
//!    replay guard. A restarted strand is a late subscriber and is handed the
//!    kernel's pending tail, which contains requests it already handled;
//!    extraction stages candidates, so a replay must not run the handler. This
//!    test also proves state continuity: the candidate the first generation
//!    staged and persisted is still there, in the *same* `Arc`-shared store and
//!    staging area, after the crash.
//!
//! Everything here runs the production path: a real `Bus::new()`, real
//! `Bus::register_strand(spec)`, real `Bus::engage_supervision()` (which
//! installs the kernel's run loop and the `spider` orchestrator on their own OS
//! threads), real strand workers, and the real `ExtractionStrand`. Nothing is
//! simulated and nothing is stubbed.
//!
//! # The instrument: recorder strands
//!
//! Supervision is invisible to `Bus::subscribe` — that surface carries
//! `BusEvent`s only, while lifecycle events travel on `sys.lifecycle`. The
//! recipe's answer is to register another strand whose input is
//! `LifecycleEvent` and let it record what it feels. That is what
//! [`LifecycleRecorder`] is, and it doubles as proof that a *second* strand on
//! the same web keeps running while the extraction strand crashes and is
//! restarted. [`CandidateRecorder`] does the same for the strand's own output,
//! so the thread-safe assertions below need no async runtime and prove
//! strand → strand delivery.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use imperium_memory_log::MemoryLog;
use imperium_net_signatures::{
    register_strands, topics, CandidateStatus, ExtractionLoop, ExtractionStrand, FaultPolicy,
    StagingArea, NAME as EXTRACTION_NAME,
};
use imperium_protocol::{BusEvent, EventId, Message, SignatureCandidatePending, StrainerRejection};
use imperium_store::Store;
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

/// Shared, test-owned record of every `candidate_pending` the strand published.
type CandidateLog = Arc<Mutex<Vec<SignatureCandidatePending>>>;

fn new_lifecycle_log() -> LifecycleLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn new_candidate_log() -> CandidateLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn lifecycle_snapshot(log: &LifecycleLog) -> Vec<LifecycleEvent> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn candidate_snapshot(log: &CandidateLog) -> Vec<SignatureCandidatePending> {
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

/// A strand that records the extraction strand's `candidate_pending` output.
///
/// Its input type is [`BusEvent`] — the same type the extraction strand
/// declares — because strand routing is by `TypeId`; the topic prefix here *is*
/// the old `bus.subscribe(topics::CANDIDATE_PENDING)` filter, moved into the
/// consumer. It therefore also proves strand → strand delivery: one strand's
/// publish reaches another.
struct CandidateRecorder {
    log: CandidateLog,
}

impl Strand for CandidateRecorder {
    fn name(&self) -> &str {
        "test.candidate-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::CANDIDATE_PENDING)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // `recv_all`, not `recv(topics::CANDIDATE_PENDING)`: the inbox is a
        // mailbox, not a filter. Draining by socket name would leave every
        // non-matching carrier (all the request traffic) in the inbox forever.
        for (socket, event) in bus.recv_all::<BusEvent>()? {
            if !socket.starts_with(topics::CANDIDATE_PENDING) {
                continue;
            }
            if let Message::SignatureCandidatePending(pending) = event.message {
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(pending);
            }
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

fn candidate_recorder_spec(log: CandidateLog) -> StrandSpec {
    StrandSpec::new("test.candidate-recorder", move || -> Box<dyn Strand> {
        Box::new(CandidateRecorder {
            log: Arc::clone(&log),
        })
    })
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

// ---------------------------------------------------------------------------
// The subsystem under test, wired the way the node wires it
// ---------------------------------------------------------------------------

/// A bus carrying the extraction loop's real durable state, plus one strainer
/// rejection already in the memory log so a request for [`Fixture::trigger`]
/// extracts a real candidate instead of failing.
struct Fixture {
    bus: Option<Bus>,
    publisher: Arc<BusPublisher>,
    store: Arc<Store>,
    memory_log: Arc<MemoryLog>,
    staging: Arc<StagingArea>,
    trigger: EventId,
}

impl Fixture {
    fn new() -> Self {
        let bus = Bus::open();
        let publisher = Arc::new(bus.publisher());
        let store = Arc::new(Store::in_memory());
        let memory_log = Arc::new(MemoryLog::new(1000));
        let staging = Arc::new(StagingArea::new(Arc::clone(&publisher)));

        // The rejection the extraction request will point at. Its `EventId` is
        // what `MemoryLog::get_by_event_id` resolves.
        let rejection = BusEvent::new(
            "net.strainer.rejection",
            Message::StrainerRejection(StrainerRejection {
                strainer_id: "auth_outer".into(),
                stack_id: "xray_stack".into(),
                shape_failed: "oversized".into(),
                source_identifier: None,
                timestamp: Utc::now(),
            }),
        );
        let trigger = rejection.id.clone();
        memory_log.append(rejection);

        Self {
            bus: Some(bus),
            publisher,
            store,
            memory_log,
            staging,
            trigger,
        }
    }

    /// The bus kernel, taken out so the composition can consume it. Each fixture
    /// has exactly one.
    fn take_bus(&mut self) -> Bus {
        self.bus.take().expect("the fixture's bus is taken once")
    }

    /// The extraction loop over this fixture's shared state — the same four
    /// `Arc`s `imperium-cli`'s `initialize_node` hands it.
    fn extraction_loop(&self) -> Arc<ExtractionLoop> {
        Arc::new(ExtractionLoop::new(
            Arc::clone(&self.publisher),
            Arc::clone(&self.store),
            Arc::clone(&self.memory_log),
            Arc::clone(&self.staging),
        ))
    }

    /// Offer one extraction request for the fixture's triggering event, minting
    /// a fresh `BusEvent` id each call (so it is genuinely new work, not a
    /// replay).
    fn request(&self, reason: &str) {
        self.request_for(vec![self.trigger.clone()], reason);
    }

    /// Offer one extraction request for arbitrary event ids.
    fn request_for(&self, triggering_event_ids: Vec<EventId>, reason: &str) {
        BusEvent::publish(
            &self.publisher,
            topics::REQUEST,
            Message::ExtractionRequest(imperium_protocol::ExtractionRequest {
                triggering_event_ids,
                reason: reason.into(),
                requested_by: "operator".into(),
            }),
        )
        .expect("publish is fire-and-forget and never fails on an idle topic");
    }
}

// ---------------------------------------------------------------------------
// Behaviour preservation
// ---------------------------------------------------------------------------

/// The strand serves the same topic pair with the same effect, and its output
/// reaches the same `Bus::subscribe` subscribers the old `tokio` loop fed —
/// proving the strand's publish path (the kernel's `deliver`, which fans out to
/// named subscribers as well as to TypeId-matched strands) is equivalent to the
/// old `Bus::publish`'s.
#[tokio::test]
async fn extraction_strand_serves_requests_and_publishes_to_shim_subscribers() {
    let mut fixture = Fixture::new();
    let candidates = new_candidate_log();

    // A second strand on the same web, consuming the extraction strand's output
    // by TypeId.
    let mut bus = fixture.take_bus();
    bus.register_spec(candidate_recorder_spec(Arc::clone(&candidates)));

    // The extraction loop itself: no injected fault, the production policy.
    bus.register_spec(ExtractionStrand::spec(
        fixture.extraction_loop(),
        FaultPolicy::None,
    ));

    // The shim's own subscriber surface — the path every existing consumer of
    // `net.signatures.candidate_pending` uses, and the path the pre-conversion
    // loop's `Bus::publish` reached.
    let mut named_subscription = subscribe_queue(&fixture.publisher, topics::CANDIDATE_PENDING, 32);

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&fixture.publisher));

    fixture.request("suspicious pattern");

    let event = tokio::time::timeout(Duration::from_secs(10), named_subscription.recv())
        .await
        .expect("candidate_pending must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    assert_eq!(&*event.topic, topics::CANDIDATE_PENDING);

    let Message::SignatureCandidatePending(pending) = event.message else {
        panic!("expected SignatureCandidatePending");
    };

    // Through the peer strand (TypeId routing to another strand).
    wait_until(
        "the candidate recorder strand to see the notification",
        || !candidate_snapshot(&candidates).is_empty(),
    );

    supervision.shutdown();

    // Same effect, through the same shared state: the candidate is persisted
    // under the same key and staged as `Pending`, with the requester carried
    // through the same as before.
    let key = format!("signature_candidate:{}", pending.candidate_id);
    assert!(fixture.store.exists(&key), "candidate must be persisted");
    assert_eq!(pending.requested_by, "operator");
    assert_eq!(fixture.staging.pending_count(), 1);

    let seen = candidate_snapshot(&candidates);
    assert_eq!(seen.len(), 1, "one request, one notification");
    assert_eq!(seen[0].candidate_id, pending.candidate_id);
    assert_eq!(seen[0].requested_by, "operator");
}

/// The failure path is preserved too: a request naming events the memory log
/// does not hold still answers on `net.signatures.extraction_failed`, with the
/// same reason text.
#[tokio::test]
async fn extraction_strand_publishes_extraction_failed_to_shim_subscribers() {
    let mut fixture = Fixture::new();
    let mut named_subscription = subscribe_queue(&fixture.publisher, topics::EXTRACTION_FAILED, 32);

    let mut bus = fixture.take_bus();
    bus.register_spec(ExtractionStrand::spec(
        fixture.extraction_loop(),
        FaultPolicy::None,
    ));
    let mut supervision = Supervision::engage_with(bus, Arc::clone(&fixture.publisher));

    fixture.request_for(vec![EventId::new()], "nonexistent events");

    let event = tokio::time::timeout(Duration::from_secs(10), named_subscription.recv())
        .await
        .expect("extraction_failed must arrive through the shim subscription")
        .expect("subscription must not lag or close");
    assert_eq!(&*event.topic, topics::EXTRACTION_FAILED);

    let Message::ExtractionFailed(failed) = event.message else {
        panic!("expected ExtractionFailed");
    };
    assert!(failed.reason.contains("no triggering events"));
    assert_eq!(fixture.staging.pending_count(), 0);

    supervision.shutdown();
}

// ---------------------------------------------------------------------------
// The crash-restart proof
// ---------------------------------------------------------------------------

/// The full crash policy, driven through the real strand with an injected
/// fault: it is installed as a **spec** (so the spider can restart it), each
/// crash is a `LifecycleEvent::Crashed` carrying the injected reason, the
/// spider restarts it three times, and the fourth crash quarantines it — while
/// candidates keep being extracted, persisted and staged, because every
/// generation shares the same `Arc<ExtractionLoop>` (and through it the same
/// store, memory log and staging area).
#[test]
fn crashed_extraction_strand_is_restarted_three_times_then_quarantined() {
    let mut fixture = Fixture::new();
    let lifecycle = new_lifecycle_log();
    let candidates = new_candidate_log();
    let mut bus = fixture.take_bus();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(candidate_recorder_spec(Arc::clone(&candidates)));

    // The strand, armed to crash after the first request each instance
    // handles. The fault is per instance, so every restart crashes again —
    // which is what drives the whole restart-then-quarantine sequence.
    bus.register_spec(ExtractionStrand::spec(
        fixture.extraction_loop(),
        FaultPolicy::CrashAfterRequests(1),
    ));

    // Nothing has started yet: a spec is queued, not installed — `register_spec`
    // only appends to the kernel's spec list, and only `run_until` installs.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == EXTRACTION_NAME
        )),
        0,
        "registering the spec must not start the strand"
    );

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&fixture.publisher));
    wait_until(
        "the extraction strand to be installed and register itself",
        || {
            count(&lifecycle, |e| {
                matches!(
                    e,
                    LifecycleEvent::Registered { name, .. } if name == EXTRACTION_NAME
                )
            }) == 1
        },
    );

    // Feed requests until the fourth crash has been quarantined by the spider.
    // A fresh request is offered on every poll so a restarted instance always
    // has work; the replayed pending tail would also do it, but publishing
    // keeps the drill independent of buffer timing.
    wait_until(
        "the strand to be quarantined after its fourth crash",
        || {
            fixture.request("drill");
            count(&lifecycle, |e| {
                matches!(
                    e,
                    LifecycleEvent::Quarantined { name, .. } if name == EXTRACTION_NAME
                )
            }) >= 1
        },
    );

    // The recorder is another strand, so give it a tick to drain the last
    // generation's notification *before* stopping the loop — that is what makes
    // the work-flow assertions below deterministic instead of timing-dependent,
    // and it fails loudly if a generation produced nothing at all.
    wait_until(
        "the candidate recorder to see a notification from every generation",
        || candidate_snapshot(&candidates).len() >= 4,
    );

    // The run loop was genuinely live for the whole drill (not a stall).
    assert!(supervision.is_running());
    supervision.shutdown();

    // (a) Installed from the queued spec — and only a spec can be restarted:
    // `Bus::register` installs a *live* strand with no factory, and the kernel
    // would refuse the spider's `ControlMsg::Restart` for it. So the three
    // `Restarted` events below are themselves proof the strand arrived as a
    // `StrandSpec`.
    //
    // The kernel emits `Registered` once per *generation* (each restart builds a
    // fresh slot whose generation counter starts at 0), so one initial install
    // plus three restarts produce four.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == EXTRACTION_NAME
        )),
        4,
        "`Registered` fires once per generation (initial + 3 restarts): {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    let crashed = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == EXTRACTION_NAME
        )
    });
    let restarted = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Restarted { name, .. } if name == EXTRACTION_NAME
        )
    });
    let quarantined = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Quarantined { name, .. } if name == EXTRACTION_NAME
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

    // The restarts are numbered 1, 2, 3 — a real cadence, not a counter reset.
    let attempts: Vec<u32> = lifecycle_snapshot(&lifecycle)
        .into_iter()
        .filter_map(|e| match e {
            LifecycleEvent::Restarted { name, attempt } if name == EXTRACTION_NAME => Some(attempt),
            _ => None,
        })
        .collect();
    assert_eq!(attempts, vec![1, 2, 3]);

    // The injected fault's reason is a real forensic signal, not a bare marker.
    let reasons: Vec<String> = lifecycle_snapshot(&lifecycle)
        .into_iter()
        .filter_map(|e| match e {
            LifecycleEvent::Crashed { name, reason } if name == EXTRACTION_NAME => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        reasons
            .iter()
            .all(|r| r.contains("injected fault") && r.contains("1 request(s)")),
        "the injected fault must name itself in every Crashed reason: {reasons:?}"
    );

    // Work flowed through every generation, into the *same* shared state: at
    // least one candidate per generation, each persisted in the same store.
    let staged = candidate_snapshot(&candidates);
    assert!(
        staged.len() >= 4,
        "every generation must have staged a candidate before crashing, saw {}",
        staged.len()
    );
    assert!(
        staged.iter().all(|p| p.requested_by == "operator"),
        "the requester must survive each restart"
    );
    assert!(
        staged.iter().all(|p| fixture
            .store
            .exists(&format!("signature_candidate:{}", p.candidate_id))),
        "every staged candidate must be persisted through the shared store"
    );
    assert!(
        fixture.staging.pending_count() >= staged.len(),
        "staging {} / pending {}",
        staged.len(),
        fixture.staging.pending_count()
    );

    // After quarantine it is gone for good: further requests cannot revive it,
    // so no new lifecycle events *about this strand* appear. (Unrelated
    // `Buffered` events are expected — a topic with no subscriber buffers its
    // messages — so this counts the strand's own events, not the whole stream.)
    fn strand_events(log: &LifecycleLog) -> usize {
        count(log, |e| match e {
            LifecycleEvent::Registered { name, .. }
            | LifecycleEvent::Crashed { name, .. }
            | LifecycleEvent::Restarted { name, .. }
            | LifecycleEvent::Quarantined { name, .. }
            | LifecycleEvent::Detached { name } => name == EXTRACTION_NAME,
            _ => false,
        })
    }
    let before = strand_events(&lifecycle);
    for _ in 0..5 {
        fixture.request("after quarantine");
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        strand_events(&lifecycle),
        before,
        "a quarantined strand must stay quarantined: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

// ---------------------------------------------------------------------------
// The production wiring call
// ---------------------------------------------------------------------------

/// The production wiring call, end to end: [`register_strands`] queues the spec
/// exactly as the composition root will (`imperium-cli`'s `initialize_node`),
/// and the fault policy is read from the environment
/// (`IMPERIUM_SIGNATURES_CRASH_AFTER_REQUESTS`) rather than passed as an
/// argument. Run it in both states:
///
/// * default (variable unset) — the queueing call serves requests, publishes to
///   shim subscribers, and **never** crashes the strand;
/// * `IMPERIUM_SIGNATURES_CRASH_AFTER_REQUESTS=1 cargo test …` — the same call
///   arms the strand, so the full crash → restart ×3 → quarantine sequence runs
///   through the production path.
#[test]
fn register_strands_from_env_serves_requests_and_only_crashes_when_armed() {
    let mut fixture = Fixture::new();
    let lifecycle = new_lifecycle_log();
    let candidates = new_candidate_log();
    let armed = FaultPolicy::from_env().is_injected();

    let mut bus = fixture.take_bus();
    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(candidate_recorder_spec(Arc::clone(&candidates)));

    // The exact call the composition root makes (see `register_strands`).
    register_strands(&mut bus, &fixture.extraction_loop());

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&fixture.publisher));

    if armed {
        wait_until("the env-armed drill to quarantine the strand", || {
            fixture.request("env drill");
            count(&lifecycle, |e| {
                matches!(
                    e,
                    LifecycleEvent::Quarantined { name, .. } if name == EXTRACTION_NAME
                )
            }) >= 1
        });
    } else {
        fixture.request("env smoke");
        wait_until("the candidate recorder to see the notification", || {
            !candidate_snapshot(&candidates).is_empty()
        });
        // Several more ticks: an unarmed strand must stay alive.
        std::thread::sleep(Duration::from_millis(150));
    }
    supervision.shutdown();

    assert!(
        fixture.staging.pending_count() >= 1,
        "the request must have been extracted through the production wiring"
    );

    let crashed = count(&lifecycle, |e| {
        matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == EXTRACTION_NAME
        )
    });
    if armed {
        assert_eq!(crashed, 4, "the env-armed drill must crash four times");
        assert_eq!(
            count(&lifecycle, |e| matches!(
                e,
                LifecycleEvent::Restarted { name, .. } if name == EXTRACTION_NAME
            )),
            3,
            "the spider restarts three times"
        );
        assert_eq!(
            count(&lifecycle, |e| matches!(
                e,
                LifecycleEvent::Quarantined { name, .. } if name == EXTRACTION_NAME
            )),
            1,
            "the fourth crash quarantines the strand"
        );
    } else {
        assert_eq!(
            crashed,
            0,
            "an unarmed deployment must never crash the strand: {:?}",
            lifecycle_snapshot(&lifecycle)
        );
    }
}

/// A restarted strand is replayed the kernel's pending tail — and that tail
/// contains requests the previous generation already handled. Extraction is not
/// idempotent (it mints a candidate, persists it and stages it for review), so
/// the replay must be deduplicated on `BusEvent::id`; the dedupe record lives in
/// the factory-shared state, which is why it still recognises the request after
/// the restart.
///
/// The test drives exactly one request into an armed strand, waits for the crash
/// and the restart, and proves the replay really happened
/// (`LifecycleEvent::Flushed` for this strand) before asserting that it changed
/// nothing: one candidate staged, one notification published, no second crash.
/// That last fact — no second crash — is the sharpest evidence, because a
/// replayed request treated as new work would run the handler *and* trip the
/// fault again.
#[test]
fn replayed_extraction_requests_are_deduplicated_across_a_restart() {
    let mut fixture = Fixture::new();
    let lifecycle = new_lifecycle_log();
    let candidates = new_candidate_log();
    let mut bus = fixture.take_bus();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(candidate_recorder_spec(Arc::clone(&candidates)));
    bus.register_spec(ExtractionStrand::spec(
        fixture.extraction_loop(),
        FaultPolicy::CrashAfterRequests(1),
    ));

    let mut supervision = Supervision::engage_with(bus, Arc::clone(&fixture.publisher));

    // Exactly one request for the whole test. It is published before the crash,
    // so it is also what the kernel will replay to the restarted generation.
    fixture.request("dedupe drill");

    wait_until("the first crash", || {
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Crashed { name, .. } if name == EXTRACTION_NAME
            )
        }) >= 1
    });
    wait_until("the first restart", || {
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Restarted { name, .. } if name == EXTRACTION_NAME
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
                        if to == EXTRACTION_NAME && *count >= 1
                )
            }) >= 1
        },
    );

    // Let the restarted generation run for many ticks (the worker ticks every
    // 10 ms) so a replayed request would certainly have been handled by now.
    std::thread::sleep(Duration::from_millis(300));
    supervision.shutdown();

    assert_eq!(
        candidate_snapshot(&candidates).len(),
        1,
        "the replay must not publish a second candidate_pending: {:?}",
        candidate_snapshot(&candidates)
    );
    assert_eq!(
        fixture.staging.pending_count(),
        1,
        "the replay must not stage a second candidate"
    );
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Crashed { name, .. } if name == EXTRACTION_NAME
        )),
        1,
        "the replay must not be treated as new work (it would crash again): {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // State continuity: the candidate the first generation staged is still
    // reachable through the shared state, and the store key it wrote is intact.
    let staged = candidate_snapshot(&candidates);
    assert!(
        fixture
            .store
            .exists(&format!("signature_candidate:{}", staged[0].candidate_id)),
        "the persisted candidate must survive the crash"
    );
    assert_eq!(
        fixture
            .staging
            .candidate(staged[0].candidate_id)
            .map(|snapshot| snapshot.status),
        Some(CandidateStatus::Pending),
        "the staged candidate must survive the crash in the same staging area"
    );
}
