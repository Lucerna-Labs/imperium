//! End-to-end supervision proof for the pilot strand conversion.
//!
//! `imperium-net-lightcone`'s observer loop was the first Imperium subsystem
//! converted from a `tokio::spawn`ed recv loop to a Spiderweb **strand**
//! (see [`strand`](imperium_net_lightcone::LightconeStrand)). The unit tests in
//! `lib.rs` cover the *service*; these integration tests cover the part only a
//! real kernel can prove:
//!
//! 1. [`pilot_strand_serves_frames_and_publishes_receipts_to_named_subscribers`]
//!    — behaviour preservation. Same topic in, same topic out, same receipt
//!    content, and the receipt reaches the *same* named subscribers the old
//!    `tokio` loop's publish reached.
//! 2. [`crashed_pilot_is_restarted_three_times_then_quarantined`] — the crash
//!    policy, driven through the real pilot with its injected fault
//!    ([`FaultPolicy::CrashAfterFrames`]): registered as a **spec**, crashes
//!    become `LifecycleEvent::Crashed`, the spider sends `ControlMsg::Restart`
//!    three times, and the fourth crash quarantines the strand.
//! 3. [`pilot_ledger_continues_across_a_restart`] — the restarted instance
//!    resumes the *same* world and ledger, so receipt sequences keep increasing
//!    across the crash boundary instead of restarting at 1.
//!
//! Everything here runs the production path: a real `spiderweb::Bus`, real
//! `Bus::register_spec`, real `Bus::register_spider` with the real
//! `spider::Spider`, and a real `Bus::run_until` on its own OS thread. Nothing
//! is simulated and nothing is stubbed. This file owns that composition
//! itself, because a test binary *is* the process owner here — exactly the role
//! the CLI plays in production.
//!
//! # The instrument: recorder strands
//!
//! Supervision is invisible to a named subscriber — that surface carries
//! `BusEvent`s only, while lifecycle events travel on `sys.lifecycle`. The
//! answer is to register another strand whose input is `LifecycleEvent` and let
//! it record what it feels. That is what [`LifecycleRecorder`] is, and it
//! doubles as proof that a *second* strand on the same web keeps running while
//! the pilot crashes and is restarted. [`ReceiptRecorder`] does the same for
//! the pilot's own output, so the thread-safe assertions below need no async
//! runtime.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use imperium_net_lightcone::{
    topics, FaultPolicy, LightconeService, LightconeStrand, NAME as PILOT_NAME,
};
use imperium_protocol::{BusEvent, LightconeFrameFormat, LightconeReceipt, Message};
use spiderweb::{
    Bus, BusHandle, BusPublisher, ControlMsg, LifecycleEvent, Socket, Strand, StrandError,
    StrandSpec, SYS_CONTROL, SYS_LIFECYCLE,
};

/// Strand name the `spider` orchestrator is registered under — the same name
/// the CLI's composition root uses in production.
const SPIDER_STRAND_NAME: &str = "spider";

// ---------------------------------------------------------------------------
// The supervision composition this test binary owns
// ---------------------------------------------------------------------------

/// Clears the liveness flag when the run-loop thread exits, whether
/// `run_until` returned normally or unwound — the workspace keeps
/// `panic = "unwind"`, so `Drop` runs either way.
struct RunningGuard(Arc<AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its
/// own thread until `shutdown`.
///
/// This is the native composition: the kernel's run loop *consumes* the bus
/// (`run_until(&mut self, ..)`), so the bus moves onto the run thread and the
/// rest of the process keeps a `BusPublisher` — the one shareable handle.
struct Supervisor {
    /// Shareable publish/subscribe handle onto the same kernel.
    publisher: BusPublisher,
    /// True while the run-loop thread is inside `run_until`.
    running: Arc<AtomicBool>,
    /// Taken by `shutdown`, so a second call is a no-op rather than a double
    /// join.
    join: Option<JoinHandle<()>>,
}

impl Supervisor {
    /// Install `specs` plus the `spider` orchestrator and start the run loop.
    fn engage(mut bus: Bus, specs: impl IntoIterator<Item = StrandSpec>) -> Self {
        for spec in specs {
            bus.register_spec(spec);
        }
        bus.register_spider(StrandSpec::new(SPIDER_STRAND_NAME, || {
            Box::new(spider::Spider::new())
        }));
        let publisher = bus.publisher();

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

    /// Ask the kernel to stop over `sys.control`, then join the run-loop
    /// thread. The kernel bounds its own worker joins, so this returns.
    fn shutdown(&mut self) {
        let _ = self.publisher.publish(SYS_CONTROL, ControlMsg::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// A named subscription with an owned bounded queue — the shape an async
/// consumer outside a strand must now have, because native delivery is push
/// based and the bus keeps no per-subscriber queue of its own.
fn subscribe_queue(
    publisher: &BusPublisher,
    prefix: &'static str,
    capacity: usize,
) -> std::sync::mpsc::Receiver<BusEvent> {
    // A bounded std channel: Spiderweb delivers by push callback, no async runtime involved.
    let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
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
// Recorder strands — the supervision instruments
// ---------------------------------------------------------------------------

/// Shared, test-owned record of every lifecycle event the kernel published.
/// `std::sync::Mutex` so a poisoned lock cannot hide an assertion failure.
type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;

/// Shared, test-owned record of every Lightcone receipt the pilot published.
type ReceiptLog = Arc<Mutex<Vec<LightconeReceipt>>>;

fn new_lifecycle_log() -> LifecycleLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn new_receipt_log() -> ReceiptLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn lifecycle_snapshot(log: &LifecycleLog) -> Vec<LifecycleEvent> {
    log.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn receipt_snapshot(log: &ReceiptLog) -> Vec<LightconeReceipt> {
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

/// A strand that records the pilot's receipts.
///
/// Its input type is [`BusEvent`] — the same type the pilot declares — because
/// strand routing is by `TypeId`; the topic prefix here *is* the old
/// `bus.subscribe(topics::RECEIPT)` filter, moved into the consumer (exactly
/// the trade the pilot made for its own input). It therefore also proves the
/// second half of the conversion's contract: one strand's publish reaches
/// another strand.
struct ReceiptRecorder {
    log: ReceiptLog,
}

impl Strand for ReceiptRecorder {
    fn name(&self) -> &str {
        "test.receipt-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::RECEIPT)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // `recv_all`, not `recv(topics::RECEIPT)`: the inbox is a mailbox, not
        // a filter. Draining by socket name would leave every non-matching
        // carrier (all the frame traffic) in the inbox forever.
        for (socket, event) in bus.recv_all::<BusEvent>()? {
            if !socket.starts_with(topics::RECEIPT) {
                continue;
            }
            if let Message::LightconeReceipt(receipt) = event.message {
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(receipt);
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

fn receipt_recorder_spec(log: ReceiptLog) -> StrandSpec {
    StrandSpec::new("test.receipt-recorder", move || -> Box<dyn Strand> {
        Box::new(ReceiptRecorder {
            log: Arc::clone(&log),
        })
    })
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// A structurally valid Ethernet + IPv4 + UDP frame, so the observer decodes
/// real structure and the world admits it (a receipt, not a malformed skip).
fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 14];
    f[12] = 0x08;
    f[13] = 0x00; // ethertype IPv4
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = 20 + 8 + payload.len();
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = 17; // UDP
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let ck = checksum(&ip);
    ip[10..12].copy_from_slice(&ck.to_be_bytes());
    let mut udp = vec![0u8; 8];
    udp[0..2].copy_from_slice(&9000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&9001u16.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&ip);
    f.extend_from_slice(&udp);
    f.extend_from_slice(payload);
    f
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&b) = chunks.remainder().first() {
        sum += (b as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Offer one frame to the pilot, exactly as a transport layer would: publish
/// `net.lightcone.frame` on the bus.
fn offer_frame(publisher: &BusPublisher, direction: u8, payload: &[u8]) {
    let bytes = udp_frame(payload);
    let frame = Message::LightconeStructure(LightconeService::structure_from_frame(
        direction,
        LightconeFrameFormat::Ethernet,
        &bytes,
        None,
    ));
    publisher
        .publish(topics::FRAME, BusEvent::new(topics::FRAME, frame))
        .expect("publish is fire-and-forget and never fails on an idle topic");
}

// ---------------------------------------------------------------------------
// Behaviour preservation
// ---------------------------------------------------------------------------

/// The pilot serves the same topic pair with the same receipt content, and its
/// receipts reach the same *named* subscribers the old `tokio` loop fed —
/// proving the strand's publish path (the kernel's deliver, which fans out to
/// named subscribers after TypeId routing) is equivalent to an external
/// publisher's.
#[test]
fn pilot_strand_serves_frames_and_publishes_receipts_to_named_subscribers() {
    let bus = Bus::open();
    let receipts = new_receipt_log();

    // The consumer surface every existing consumer of `net.lightcone.receipt`
    // uses: a prefix subscription feeding an owned bounded queue. Registered
    // before the run loop starts so no receipt can be missed.
    let named = subscribe_queue(&bus.publisher(), topics::RECEIPT, 64);

    // A second strand on the same web, consuming the pilot's output by TypeId;
    // plus the pilot itself, with no injected fault (the production policy).
    let service = Arc::new(LightconeService::new().expect("the world loads (untrained with no role set)"));
    let mut supervisor = Supervisor::engage(
        bus,
        [
            receipt_recorder_spec(Arc::clone(&receipts)),
            LightconeStrand::spec(service, FaultPolicy::None),
        ],
    );
    wait_until("the supervision run loop to start", || {
        supervisor.is_running()
    });

    offer_frame(&supervisor.publisher, 0, b"inbound");
    offer_frame(&supervisor.publisher, 1, b"outbound");
    offer_frame(&supervisor.publisher, 0, b"inbound again");

    // 1. Through the named subscription (the old public path).
    let mut delivered = Vec::new();
    for _ in 0..3 {
        let event = named
            .recv_timeout(Duration::from_secs(10))
            .expect("receipt must arrive through the named subscription, with the queue open");
        assert_eq!(&*event.topic, topics::RECEIPT);
        match event.message {
            Message::LightconeReceipt(receipt) => delivered.push(receipt),
            other => panic!("expected a LightconeReceipt, got {other:?}"),
        }
    }

    // 2. Through the peer strand (TypeId routing to another strand).
    wait_until(
        "the receipt recorder strand to see all three receipts",
        || receipt_snapshot(&receipts).len() >= 3,
    );

    supervisor.shutdown();

    // Same topic in and out, same sequencing, same self-attested passivity the
    // service's own unit tests assert — now observed across the bus.
    assert_eq!(
        delivered.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(delivered[0].direction, 0);
    assert_eq!(delivered[1].direction, 1);
    assert!(delivered.iter().all(|r| r.passive && !r.holds_verdict));
    assert!(
        delivered.iter().all(|r| !r.path.is_empty()),
        "a decoded UDP frame must carry its real path"
    );

    // And the strand-side observer saw the same receipts in the same order.
    let seen = receipt_snapshot(&receipts);
    assert_eq!(
        seen.iter().take(3).map(|r| r.sequence).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert_eq!(
        (&seen[0].query_sha256, &seen[0].path, seen[0].admitted),
        (&delivered[0].query_sha256, &delivered[0].path, delivered[0].admitted),
        "both observers must see the identical receipt"
    );
}

// ---------------------------------------------------------------------------
// The crash-restart proof
// ---------------------------------------------------------------------------

/// The pilot's full crash policy, driven through the real strand with an
/// injected fault: it is installed as a **spec** (so the spider can restart
/// it), each crash is a `LifecycleEvent::Crashed` carrying the injected reason,
/// the spider restarts it three times, and the fourth crash quarantines it.
///
/// The receipts keep flowing up to the last crash, which is also the proof that
/// a strand's outbox is delivered on the very tick it returns
/// `StrandError::Crashed` (the kernel flushes the outbox because `run` returned
/// rather than panicked).
#[test]
fn crashed_pilot_is_restarted_three_times_then_quarantined() {
    let mut bus = Bus::open();
    let lifecycle = new_lifecycle_log();
    let receipts = new_receipt_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(receipt_recorder_spec(Arc::clone(&receipts)));

    // The pilot, armed to crash after the first frame each instance observes.
    // The fault is per instance, so every restart crashes again — which is what
    // drives the whole restart-then-quarantine sequence.
    let service = Arc::new(LightconeService::new().expect("the world loads (untrained with no role set)"));
    bus.register_spec(LightconeStrand::spec(
        Arc::clone(&service),
        FaultPolicy::CrashAfterFrames(1),
    ));

    // Nothing has started yet: a spec is queued, not installed. There is no run
    // loop at all until `Supervisor::engage` below — nothing can tick, so no
    // strand can register.
    assert_eq!(
        count(&lifecycle, |e| matches!(
            e,
            LifecycleEvent::Registered { name, .. } if name == PILOT_NAME
        )),
        0,
        "registering the spec must not start the strand"
    );

    let mut supervisor = Supervisor::engage(bus, Vec::new());
    wait_until("the pilot to be installed and register itself", || {
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Registered { name, .. } if name == PILOT_NAME
            )
        }) == 1
    });

    // Feed frames until the fourth crash has been quarantined by the spider.
    // Frames are offered continuously so a restarted instance always has work;
    // the replayed pending tail would also do it, but publishing keeps the
    // drill independent of buffer timing.
    wait_until("the pilot to be quarantined after its fourth crash", || {
        offer_frame(&supervisor.publisher, 0, b"drill");
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Quarantined { name, .. } if name == PILOT_NAME
            )
        }) >= 1
    });

    // The run loop was genuinely live for the whole drill (not a stall).
    assert!(supervisor.is_running());
    supervisor.shutdown();

    // (a) Installed from the queued spec — and only a spec can be restarted:
    // `Bus::register` installs a *live* strand with no factory, and the kernel
    // would refuse the spider's `ControlMsg::Restart` for it ("Restart for
    // non-restartable or unknown strand"). So the three `Restarted` events
    // below are themselves proof the pilot arrived as a `StrandSpec`.
    //
    // The kernel emits `Registered` once per *generation* (each restart builds a
    // fresh slot whose generation counter starts at 0), so one initial install
    // plus three restarts produce four.
    let registered = count(
        &lifecycle,
        |e| matches!(e, LifecycleEvent::Registered { name, .. } if name == PILOT_NAME),
    );
    assert_eq!(
        registered,
        4,
        "`Registered` fires once per generation (initial + 3 restarts): {:?}",
        lifecycle_snapshot(&lifecycle)
    );

    // (b)+(c)+(d) Four crashes, three restarts, then quarantine.
    let crashed = count(
        &lifecycle,
        |e| matches!(e, LifecycleEvent::Crashed { name, .. } if name == PILOT_NAME),
    );
    let restarted = count(
        &lifecycle,
        |e| matches!(e, LifecycleEvent::Restarted { name, .. } if name == PILOT_NAME),
    );
    let quarantined = count(
        &lifecycle,
        |e| matches!(e, LifecycleEvent::Quarantined { name, .. } if name == PILOT_NAME),
    );
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
            LifecycleEvent::Crashed { name, reason } if name == PILOT_NAME => Some(reason),
            _ => None,
        })
        .collect();
    assert!(
        reasons
            .iter()
            .all(|r| r.contains("injected fault") && r.contains("1 frame")),
        "the injected fault must name itself in every Crashed reason: {reasons:?}"
    );

    // Receipts were delivered before the crashes: the pilot was doing its job
    // right up to (and including) the tick it crashed on.
    assert!(
        !receipt_snapshot(&receipts).is_empty(),
        "the pilot must have published receipts before crashing"
    );

    // After quarantine it is gone for good: further frames cannot revive it, so
    // no new lifecycle events *about the pilot* appear. (Unrelated `Buffered`
    // events are expected — a topic with no subscriber buffers its messages —
    // so this counts the pilot's own events, not the whole stream.)
    fn pilot_events(log: &LifecycleLog) -> usize {
        count(log, |e| match e {
            LifecycleEvent::Registered { name, .. }
            | LifecycleEvent::Crashed { name, .. }
            | LifecycleEvent::Restarted { name, .. }
            | LifecycleEvent::Quarantined { name, .. }
            | LifecycleEvent::Detached { name } => name == PILOT_NAME,
            _ => false,
        })
    }
    let before = pilot_events(&lifecycle);
    for _ in 0..5 {
        offer_frame(&supervisor.publisher, 0, b"after quarantine");
    }
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(
        pilot_events(&lifecycle),
        before,
        "a quarantined strand must stay quarantined: {:?}",
        lifecycle_snapshot(&lifecycle)
    );
}

/// A restarted instance resumes the *same* world and ledger: the spec's factory
/// hands each generation an `Arc` clone of one `LightconeService`, so receipt
/// sequences keep climbing across the crash boundary instead of resetting.
///
/// This is the property that makes the conversion safe for stateful subsystems:
/// the strand owns its loop state (here a per-instance frame counter), while the
/// durable state (here the world + sequenced ledger) is shared through the
/// factory, exactly as the recipe prescribes.
#[test]
fn pilot_ledger_continues_across_a_restart() {
    let mut bus = Bus::open();
    let lifecycle = new_lifecycle_log();
    let receipts = new_receipt_log();

    bus.register_spec(lifecycle_recorder_spec(Arc::clone(&lifecycle)));
    bus.register_spec(receipt_recorder_spec(Arc::clone(&receipts)));

    let service = Arc::new(LightconeService::new().expect("the world loads (untrained with no role set)"));
    bus.register_spec(LightconeStrand::spec(
        Arc::clone(&service),
        FaultPolicy::CrashAfterFrames(1),
    ));

    let mut supervisor = Supervisor::engage(bus, Vec::new());

    // Drive exactly past the first crash and its restart, then stop feeding and
    // let the restarted instance drain whatever it was replayed.
    wait_until("the first crash", || {
        offer_frame(&supervisor.publisher, 0, b"first");
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Crashed { name, .. } if name == PILOT_NAME
            )
        }) >= 1
    });
    wait_until("the first restart", || {
        count(&lifecycle, |e| {
            matches!(
                e,
                LifecycleEvent::Restarted { name, .. } if name == PILOT_NAME
            )
        }) >= 1
    });
    std::thread::sleep(Duration::from_millis(300));
    supervisor.shutdown();

    let sequences: Vec<u64> = receipt_snapshot(&receipts)
        .iter()
        .map(|r| r.sequence)
        .collect();
    assert!(
        sequences.len() >= 2,
        "the restarted instance must keep observing: {sequences:?}"
    );
    assert!(
        sequences.windows(2).all(|w| w[0] < w[1]),
        "sequences must be strictly monotonic across the restart, never reset: {sequences:?}"
    );
    assert!(
        sequences[0] == 1,
        "the first receipt of the first instance is 1: {sequences:?}"
    );

    // `info()` agrees: the shared service counted both generations' observations.
    let info = service.info();
    assert_eq!(info.world, "untrained");
    assert_eq!(
        info.rx,
        sequences.len() as u64,
        "the ledger the strand writes through is the one the spec shared"
    );
}
