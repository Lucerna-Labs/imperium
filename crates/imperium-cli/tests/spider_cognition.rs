//! The intrusion-alarm capability harness: the spider's cognitive engine, driven
//! by **real Imperium strands**.
//!
//! Stages 1–4 of the strand arc turned the standing recv loops into supervised
//! strands and made the cognitive engine *armable* (`IMPERIUM_SPIDER_COGNITION`,
//! see the deleted `imperium-bus` shim). This file answers the only question that
//! matters
//! about an alarm: **does it fire on a real intrusion, and does it stay silent on
//! the same node behaving well?** A detector that never fires and a detector that
//! always fires both fail; so every claim below is two-sided, measured with the
//! same configuration and the same bounded window.
//!
//! # What is real here, and what is stimulus
//!
//! Real, unmodified production code:
//!
//! * `imperium-net-lightcone`'s strand — the pilot conversion, driven through its
//!   production path (`net.lightcone.frame` in → structured receipt out).
//! * `imperium-memory-log`'s rejection lane — a second real converted strand,
//!   driven through its production path (`net.strainer.rejection`).
//! * the CLI's own composition (`imperium_cli::supervision`): a real
//!   `spiderweb::Bus`, real `register_spec` calls, real strand workers, and the
//!   real kernel run loop — the same composition an operator's node runs.
//! * the real cognitive spider (`Spider::with_cognition`), registered by the shim
//!   exactly as `IMPERIUM_SPIDER_COGNITION=1` registers it.
//!
//! Stimulus (labelled as such wherever it appears):
//!
//! * **The stuck node.** The lightcone strand is armed with
//!   `FaultPolicy::StallAfterFrames` — an env-gated drill that makes the strand
//!   stop draining its inbox for a bounded window while staying alive. That is
//!   the shape the engine's heartbeat path exists to catch, and the only way to
//!   drive it deterministically. Nothing arms it by accident: the default is
//!   `None`, and an unparsable value is `None`.
//! * **The vibration rhythm node** ([`RHYTHM_NODE`]). Nothing in Imperium emits
//!   `Vibration` today — there is no highway and no preload in this workspace —
//!   so the vibration branch of the engine is exercised by a test-owned stimulus
//!   strand, and the node it names is deliberately *not* a strand. Its numbers
//!   are a test stimulus, not production telemetry.
//!
//! # The instruments
//!
//! Supervision and the alarm are invisible to `Bus::subscribe` (that surface
//! carries `BusEvent`s only). Everything here is observed the way the recipe and
//! the shim's docs prescribe: recorder **strands**, registered as specs like any
//! converted subsystem, whose inputs are the typed reserved sockets —
//! `sys.control` for the alarm itself, `sys.lifecycle` for what the kernel did
//! about it. No test parses a log line.
//!
//! # The discrimination matrix
//!
//! Every row is a test below; the alarm's configuration is identical unless a row
//! says otherwise, and the *only* thing a row changes is the stimulus.
//!
//! | Test | Node state / stimulus | Expected |
//! |---|---|---|
//! | `stuck_real_strand_trips_...` (control phase) | real node advancing, steady frames | **0** alerts |
//! | `stuck_real_strand_trips_...` (intrusion phase) | real node stalled, frames still offered | ≥1 alert naming it, no `Crashed` |
//! | `stuck_real_strand_trips_...` (same run!) | real neighbour advancing throughout | **0** alerts ever |
//! | `a_strand_that_never_advanced_is_never_called_stuck` | real node registered, fed nothing | **0** alerts (thin evidence) |
//! | `a_strand_that_worked_and_then_went_quiet_is_flagged_as_stuck` | real node worked, then went quiet | ≥1 alert — the pinned limit |
//! | `a_deviation_without_a_baseline_abstains` | stimulus deviation, no baseline | **0** alerts |
//! | `the_same_deviation_with_a_baseline_alerts` | the same deviation, baseline learned | ≥1 `SetTransfer`, exactly one per episode |
//! | `the_same_stuck_stimulus_is_silent_with_cognition_off` | the intrusion, cognition **OFF** | **0** control messages |
//! | `an_invalid_cognitive_config_degrades_to_cognition_off` | the intrusion, config rejected by `validate()` | **0** control messages |
//! | `restarting_a_stuck_strand_forks_it_rather_than_curing_it` | the intrusion's remedy path | the old instance is still alive (finding) |

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use imperium_cli::supervision::{cognition_config_from, Supervision, SPIDER_STRAND_NAME};
use imperium_memory_log::{
    topics as memory_log, FaultPolicy as MemoryLogFaults, Lane as MemoryLogLane, MemoryLog,
    MemoryLogStrand,
};
use imperium_net_lightcone::{
    topics as lightcone, FaultPolicy as LightconeFaults, LightconeService, LightconeStrand,
    NAME as LIGHTCONE_NAME, STALL_WINDOW_MS,
};
use imperium_protocol::BusEvent;
use imperium_protocol::{LightconeFrameFormat, LightconeReceipt, Message, StrainerRejection};
use spider::CognitiveConfig;
use spiderweb::{
    BusHandle, BusPublisher, ControlMsg, LifecycleEvent, Socket, Strand, StrandError, StrandSpec,
    Vibration, SYS_CONTROL, SYS_LIFECYCLE, SYS_VIBRATION,
};

// ---------------------------------------------------------------------------
// The alarm's parameters, shared by every test
// ---------------------------------------------------------------------------

/// The heartbeat-staleness threshold this harness arms deliberately high, so the
/// *healthy* phase cannot trip it: the lightcone strand is stalled only after
/// more frames than the control phase can possibly deliver.
const CONTROL_PHASE_FRAMES: u64 = 110;

/// The stall threshold used by the tests. Above [`CONTROL_PHASE_FRAMES`] (so the
/// control phase cannot arm the drill) and reachable in ~1 s of intrusion-phase
/// traffic (so the intrusion phase cannot fail to arm it).
const STALL_AFTER_FRAMES: u32 = 140;

/// How long the alarm gets to fire after the intrusion begins — and, in the
/// silent cases, how long *nothing* may appear. The same constant on both sides
/// on purpose: firing inside the window and silence across a longer window are
/// then the same measurement, not two different ones.
const ALERT_WINDOW: Duration = Duration::from_secs(4);

/// The silent cases' intrusion phase: longer than [`ALERT_WINDOW`] plus the
/// ~0.6 s the stimulus needs to arm, so "no alert" is a strictly stronger
/// statement than the firing case's alert.
const SILENCE_PHASE: Duration = Duration::from_secs(6);

/// The healthy (control) phase for the real nodes. Long enough that the engine
/// has ~30 ticks of a rising heartbeat for every node (so a baseline exists and
/// the stall detector is armed), and long enough that the engine's whole
/// corroboration sequence (`heartbeat_stall_ticks` 8 + `min_corroboration` 2,
/// ~0.7 s at a ~60 ms tick) would have been caught inside it — if the alarm fired
/// on anything at all, this is where it would fire.
const HEALTHY_PHASE: Duration = Duration::from_secs(2);

/// How long to keep driving after an intrusion has been detected, to show that
/// the alert does not become a stream while the episode lasts.
const QUIET_WINDOW: Duration = Duration::from_secs(2);

/// Hard deadline for a `wait`-style condition. Deliberately generous: this file
/// runs beside ~60 other test binaries, each with its own tokio runtime and its
/// own supervised kernel, so a drill that settles in a second alone can take tens
/// of seconds under load. A tight deadline would measure machine pressure, not
/// the alarm (the same reasoning as `imperium-memory-log`'s supervision test).
const WAIT_DEADLINE: Duration = Duration::from_secs(120);

/// The temperature at which a test offers one frame to the lightcone: faster than
/// the lightcone strand's own ~10 ms tick, so a node that is *not* stalled always
/// has work (its heartbeat keeps rising) and a node that *is* stalled visibly
/// accumulates it. Kept as slow as it can be while satisfying that: every
/// published message also costs the kernel a `ThreadFormed` lifecycle event and
/// the spider a log line, so a faster stimulus floods stdout and measures the
/// terminal rather than the alarm.
const OFFER_INTERVAL: Duration = Duration::from_millis(20);

/// The stimulus node for the vibration path. Not a strand name, on purpose: the
/// vibration branch must be exercised without also feeding the heartbeat path.
const RHYTHM_NODE: &str = "test.rhythm-node";

/// The magnitude the rhythm stimulus emits steadily, and the deviation it emits
/// to test the alarm. Five times the baseline is a relative magnitude surprise of
/// 4.0 against the engine's `surprise_band` of 0.5 — unambiguous by arithmetic,
/// not by luck.
const STEADY_MAGNITUDE: u64 = 1_000;
const DEVIATING_MAGNITUDE: u64 = 5_000;

// ---------------------------------------------------------------------------
// Recorder strands: the instruments
// ---------------------------------------------------------------------------

/// Every `ControlMsg` that crossed `sys.control` while the harness ran.
///
/// This is the alarm's own surface — the spider's only way to say anything — so
/// it is what "the alarm fired" means. `std::sync::Mutex` so a poisoned lock
/// cannot hide an assertion failure.
type AlertLog = Arc<Mutex<Vec<ControlMsg>>>;

/// Every `LifecycleEvent` the kernel published: registration, crashes, and — the
/// part that proves the kernel *executed* an alert — restarts and quarantines.
type LifecycleLog = Arc<Mutex<Vec<LifecycleEvent>>>;

/// `(sequence, query_sha256)` for every receipt the real lightcone published.
/// The query hash is `hash(frame)`, so it identifies the frame the node observed:
/// two receipts carrying the same query hash are two *observations of one frame*,
/// which is what makes double-processing measurable.
type ReceiptLog = Arc<Mutex<Vec<(u64, String)>>>;

fn new_alert_log() -> AlertLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn new_lifecycle_log() -> LifecycleLog {
    Arc::new(Mutex::new(Vec::new()))
}

fn new_receipt_log() -> ReceiptLog {
    Arc::new(Mutex::new(Vec::new()))
}

/// Records every `ControlMsg` on `sys.control`.
///
/// It also drains the frame traffic the harness drives, and that is not an
/// accident: the engine flags *any* strand whose drained-message counter stops
/// rising, and it restarts what it flags. A restarted recorder is replayed the
/// kernel's control-message tail (see the kernel's `install_slot` → `subscribe`
/// flush), so every restart would append a fresh copy of the alerts already
/// recorded — inflating exactly the numbers this instrument exists to report. By
/// taking a share of the steady traffic the harness already generates, the
/// instrument stays a live, advancing node and its log stays exact.
///
/// (That the instrument *needs* this is itself the finding pinned by
/// `a_strand_that_worked_and_then_went_quiet_is_flagged_as_stuck`: an idle node
/// is alerted on, restarted, and re-armed, once per ~0.7 s, forever.)
struct AlertRecorder {
    log: AlertLog,
}

impl Strand for AlertRecorder {
    fn name(&self) -> &str {
        "test.alert-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        // Routing is by `TypeId`, so this feels every control message on the web
        // — the spider's, the kernel's, and the shutdown request — and (for the
        // reason above) every work message the harness drives.
        const SOCKS: [Socket; 2] = [
            Socket::new::<ControlMsg>(SYS_CONTROL),
            Socket::new::<BusEvent>(lightcone::FRAME),
        ];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Control messages are the measurement; the work traffic is only what
        // keeps this strand visibly alive, so it is drained and discarded.
        let _ = bus.recv_all::<BusEvent>()?;
        for (_socket, message) in bus.recv_all::<ControlMsg>()? {
            self.log
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(message);
        }
        Ok(())
    }
}

/// Records the kernel's lifecycle stream.
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

/// Records the real lightcone strand's output — the proof that the node under
/// test is doing its job (and, when it stops, that it stopped).
struct ReceiptRecorder {
    log: ReceiptLog,
}

impl Strand for ReceiptRecorder {
    fn name(&self) -> &str {
        "test.receipt-recorder"
    }

    fn inputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(lightcone::RECEIPT)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        for (socket, event) in bus.recv_all::<BusEvent>()? {
            if !socket.starts_with(lightcone::RECEIPT) {
                continue;
            }
            if let Message::LightconeReceipt(receipt) = event.message {
                let LightconeReceipt {
                    sequence,
                    query_sha256,
                    ..
                } = receipt;
                self.log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push((sequence, query_sha256));
            }
        }
        Ok(())
    }
}

/// **Test stimulus** for the vibration path (see the module docs: nothing in
/// Imperium emits `Vibration`).
///
/// Emits one `Vibration::Backpressure` for [`RHYTHM_NODE`] on every tick, so each
/// of the spider's own ticks observes exactly one arrival of the current
/// magnitude: the arrival *cadence* is steady by construction and only the
/// magnitude can deviate, which makes the stimulus deterministic. A real emitter
/// is edge-triggered (it sends only when depth changes); this one is
/// level-triggered because it is a stimulus, not telemetry.
struct RhythmStimulus {
    magnitude: Arc<AtomicU64>,
    emitted: Arc<AtomicU64>,
}

impl Strand for RhythmStimulus {
    fn name(&self) -> &str {
        "test.rhythm-stimulus"
    }

    fn inputs(&self) -> &[Socket] {
        &[]
    }

    fn outputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<Vibration>(SYS_VIBRATION)];
        &SOCKS
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        if bus.is_shutting_down() {
            return Ok(());
        }
        let queued = self.magnitude.load(Ordering::Relaxed) as usize;
        bus.publish_static(
            SYS_VIBRATION,
            Vibration::Backpressure {
                node: RHYTHM_NODE.to_string(),
                queued,
                in_flight: queued / 2,
                capacity: 4096,
            },
        )?;
        self.emitted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// What the harness should register beyond the instruments. Each test states
/// exactly which real nodes and which stimuli it needs.
struct Wiring {
    /// The real lightcone strand's fault policy (production default: `None`).
    lightcone_faults: LightconeFaults,
    /// Register the real memory-log rejection lane as a second, always-advancing
    /// real node.
    memory_log_lane: bool,
    /// Register the vibration stimulus strand.
    rhythm_stimulus: bool,
}

impl Default for Wiring {
    fn default() -> Self {
        Wiring {
            lightcone_faults: LightconeFaults::None,
            memory_log_lane: false,
            rhythm_stimulus: false,
        }
    }
}

/// A live harness: one real `Bus`, real strands, a real run loop, and the
/// instruments that make the alarm observable.
struct Harness {
    publisher: Arc<BusPublisher>,
    alerts: AlertLog,
    lifecycle: LifecycleLog,
    receipts: ReceiptLog,
    /// The stimulus magnitude (only meaningful when the stimulus was wired).
    magnitude: Arc<AtomicU64>,
    /// Frames offered by this harness, so each frame's bytes are unique and
    /// double-observation is measurable.
    frames_offered: AtomicU64,
    supervision: Supervision,
}

impl Harness {
    /// Wire the requested real strands and instruments, then engage a run loop
    /// with `cognition` — the same operation `IMPERIUM_SPIDER_COGNITION` performs
    /// for an operator, with the configuration supplied in code so no test races
    /// the process environment.
    fn start(cognition: CognitiveConfig, wiring: Wiring) -> Self {
        let mut bus = spiderweb::Bus::open();
        let publisher = Arc::new(bus.publisher());
        let alerts = new_alert_log();
        let lifecycle = new_lifecycle_log();
        let receipts = new_receipt_log();
        let magnitude = Arc::new(AtomicU64::new(STEADY_MAGNITUDE));

        // Instruments first. Specs are installed in registration order, so the
        // recorders must be queued before the nodes they observe — and before the
        // spider, which the shim registers last of all.
        bus.register_spec(StrandSpec::new("test.alert-recorder", {
            let alerts = Arc::clone(&alerts);
            move || -> Box<dyn Strand> {
                Box::new(AlertRecorder {
                    log: Arc::clone(&alerts),
                })
            }
        }));
        bus.register_spec(StrandSpec::new("test.lifecycle-recorder", {
            let lifecycle = Arc::clone(&lifecycle);
            move || -> Box<dyn Strand> {
                Box::new(LifecycleRecorder {
                    log: Arc::clone(&lifecycle),
                })
            }
        }));
        bus.register_spec(StrandSpec::new("test.receipt-recorder", {
            let receipts = Arc::clone(&receipts);
            move || -> Box<dyn Strand> {
                Box::new(ReceiptRecorder {
                    log: Arc::clone(&receipts),
                })
            }
        }));

        // The node under test: the real Lightcone observer strand, on its
        // production topic pair.
        let service = Arc::new(LightconeService::new().expect("embedded world verifies"));
        bus.register_spec(LightconeStrand::spec(service, wiring.lightcone_faults));

        // The healthy neighbour: a second real converted strand, whose heartbeat
        // rises for as long as the harness drives it.
        if wiring.memory_log_lane {
            let log = Arc::new(MemoryLog::default());
            bus.register_spec(MemoryLogStrand::spec(
                MemoryLogLane::StrainerRejections,
                log,
                MemoryLogFaults::None,
            ));
        }

        if wiring.rhythm_stimulus {
            let magnitude = Arc::clone(&magnitude);
            let emitted = Arc::new(AtomicU64::new(0));
            bus.register_spec(StrandSpec::new(
                "test.rhythm-stimulus",
                move || -> Box<dyn Strand> {
                    Box::new(RhythmStimulus {
                        magnitude: Arc::clone(&magnitude),
                        emitted: Arc::clone(&emitted),
                    })
                },
            ));
        }

        let supervision = Supervision::engage(bus, cognition);

        let harness = Harness {
            publisher,
            alerts,
            lifecycle,
            receipts,
            magnitude,
            frames_offered: AtomicU64::new(0),
            supervision,
        };

        // The spider is installed **after** every strand spec, and a lifecycle
        // event published before its subscriber exists is lost (the kernel
        // buffers work traffic for late subscribers, but `publish_lifecycle`
        // bypasses that buffer). So no stimulus may start until the spider is
        // demonstrably online — otherwise a crash in the install window would be
        // invisible and the very first measurement would be meaningless.
        harness.wait_until("the spider to register", || {
            harness.lifecycle_count(|event| {
                matches!(event, LifecycleEvent::Registered { name, .. } if name == SPIDER_STRAND_NAME)
            }) == 1
        });
        harness
    }

    /// Offer one frame to the real lightcone strand, exactly as a transport layer
    /// would: publish `net.lightcone.frame`. Each frame's payload is unique, so a
    /// receipt identifies the frame it came from.
    fn offer_frame(&self, tag: &str) {
        let serial = self.frames_offered.fetch_add(1, Ordering::SeqCst);
        BusEvent::publish(
            &self.publisher,
            lightcone::FRAME,
            Message::LightconeStructure(LightconeService::structure_from_frame(
                0,
                LightconeFrameFormat::Ethernet,
                &udp_frame(format!("{tag}-{serial}").as_bytes()),
                None,
            )),
        )
        .expect("publish is fire-and-forget and never fails on an idle topic");
    }

    /// Offer one strainer rejection to the real memory-log rejection lane: its
    /// production input, so the neighbour's heartbeat keeps rising.
    fn offer_rejection(&self, tag: &str) {
        BusEvent::publish(
            &self.publisher,
            memory_log::STRAINER_REJECTION,
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

    /// Drive both real nodes for `window`: frames to the lightcone, rejections to
    /// the memory-log lane.
    fn drive_for(&self, window: Duration, tag: &str) {
        let deadline = Instant::now() + window;
        while Instant::now() < deadline {
            self.offer_frame(tag);
            self.offer_rejection(tag);
            std::thread::sleep(OFFER_INTERVAL);
        }
    }

    /// Drive both real nodes until `pred` holds, with a hard deadline so a
    /// supervision bug fails the test instead of hanging it.
    fn drive_until(&self, what: &str, tag: &str, mut pred: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT_DEADLINE;
        while !pred() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            self.offer_frame(tag);
            self.offer_rejection(tag);
            std::thread::sleep(OFFER_INTERVAL);
        }
    }

    /// Block until `pred` holds, without offering traffic (used only where the
    /// stimulus is silence).
    fn wait_until(&self, what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT_DEADLINE;
        while !pred() {
            assert!(Instant::now() < deadline, "timed out waiting for: {what}");
            std::thread::sleep(OFFER_INTERVAL);
        }
    }

    fn alert_snapshot(&self) -> Vec<ControlMsg> {
        self.alerts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The control messages that name `node` (via `Restart`/`Quarantine`/
    /// `SetTransfer`). `Shutdown` names nothing and is never an alert.
    fn alerts_for(&self, node: &str) -> Vec<ControlMsg> {
        self.alert_snapshot()
            .into_iter()
            .filter(|message| control_target(message) == Some(node))
            .collect()
    }

    fn alert_count(&self) -> usize {
        self.alert_snapshot().len()
    }

    fn lifecycle_count(&self, pred: impl Fn(&LifecycleEvent) -> bool) -> usize {
        self.lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|event| pred(event))
            .count()
    }

    /// Every lifecycle event seen so far, for failure messages.
    fn lifecycle_snapshot(&self) -> Vec<LifecycleEvent> {
        self.lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn receipt_count(&self) -> usize {
        self.receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// How many receipts are a *second* observation of a frame already recorded
    /// (same `query_sha256`, i.e. same frame bytes, different sequence).
    ///
    /// The kernel replays its bounded 32-message tail to a late subscriber, so a
    /// handful of duplicates is normal and expected after a restart; anything far
    /// above that is two live strand instances observing the same traffic.
    fn duplicate_receipts(&self) -> usize {
        let receipts = self
            .receipts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for (_sequence, query) in receipts.iter() {
            *seen.entry(query.as_str()).or_insert(0) += 1;
        }
        seen.values().map(|count| count - 1).sum()
    }

    fn set_magnitude(&self, magnitude: u64) {
        self.magnitude.store(magnitude, Ordering::SeqCst);
    }

    /// Print what this case measured, as one line on stdout. The harness's
    /// assertions are the gate; this line is the evidence a reader (or a report)
    /// needs — visible with `--nocapture`. `std::io::stdout` is used rather than
    /// `println!` so it goes to the same captured stream under libtest.
    fn report(&self, case: &str) {
        use std::io::Write;
        let alerts = self.alert_snapshot();
        let mut per_node: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for message in &alerts {
            *per_node
                .entry(control_target(message).unwrap_or("<shutdown>").to_string())
                .or_insert(0) += 1;
        }
        let _ = writeln!(
            std::io::stdout(),
            "[harness] {case}: control_msgs={} per_node={per_node:?} lightcone_receipts={} \
             duplicate_receipts={} frames_offered={}",
            alerts.len(),
            self.receipt_count(),
            self.duplicate_receipts(),
            self.frames_offered.load(Ordering::SeqCst),
        );
    }

    /// Stop the run loop and assert it is really stopped and joined, so no test
    /// leaves threads behind. Takes `&self` because a test may still want to read
    /// the recorded evidence afterwards (`shutdown` is idempotent).
    fn shutdown(&mut self) {
        self.supervision.shutdown();
        assert!(
            !self.supervision.is_running(),
            "supervision must be stopped and joined before the test ends"
        );
    }
}

/// The node a control message names, if any.
fn control_target(message: &ControlMsg) -> Option<&str> {
    match message {
        ControlMsg::Restart { name } => Some(name),
        ControlMsg::Quarantine { name, .. } => Some(name),
        ControlMsg::SetTransfer { node, .. } => Some(node),
        ControlMsg::Shutdown => None,
    }
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

/// A structurally valid Ethernet + IPv4 + UDP frame, so the observer decodes real
/// structure and the world admits it (a receipt, not a malformed skip). Copied
/// from the pilot's own test, because the harness drives the pilot's production
/// path and nothing else.
fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 14];
    f[12] = 0x08;
    f[13] = 0x00;
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total = 20 + 8 + payload.len();
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
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

// ---------------------------------------------------------------------------
// The configuration every discrimination test shares
// ---------------------------------------------------------------------------

/// Cognition armed with the validated engine defaults — the same object
/// [`imperium_cli::supervision::cognition_config_from_env`] produces for
/// `IMPERIUM_SPIDER_COGNITION=1`, without touching the process environment.
fn armed() -> CognitiveConfig {
    cognition_config_from(Some("1"), None, None)
}

// ---------------------------------------------------------------------------
// 1 + 2 + 3: intrusion trips, control is silent, same config, same run
// ---------------------------------------------------------------------------

/// **The discrimination test.** One bus, one configuration, one cognitive spider,
/// two real strands — and the only difference between the phases is the stimulus.
///
/// * Control phase: both real nodes are driven at a steady pace. The engine has
///   ~30 ticks to learn their heartbeats. **Nothing may appear on `sys.control`.**
/// * Intrusion phase: the lightcone strand's env-gated stall arms (it stops
///   draining while staying registered and uncrashed) while the harness keeps
///   offering frames. **An alert naming it must appear inside `ALERT_WINDOW`** —
///   and the healthy neighbour must still be silent, which is what separates
///   "the alarm fired on the intrusion" from "the alarm fired on everything".
/// * Quiet window: the stall is still in progress, and the alert must not become
///   a stream (change-only emission + CONSERVE).
#[test]
fn stuck_real_strand_trips_the_alarm_and_its_healthy_neighbour_stays_silent() {
    let mut harness = Harness::start(
        armed(),
        Wiring {
            lightcone_faults: LightconeFaults::StallAfterFrames {
                after: STALL_AFTER_FRAMES,
                millis: STALL_WINDOW_MS,
            },
            memory_log_lane: true,
            rhythm_stimulus: false,
        },
    );

    // --- Control: steady, normally-paced operation ---------------------------
    harness.drive_for(HEALTHY_PHASE, "control");
    harness.report("control-phase (both real nodes advancing)");

    let control_alerts = harness.alert_count();
    assert_eq!(
        control_alerts,
        0,
        "the alarm must be silent while both real nodes are advancing: {:?}",
        harness.alert_snapshot()
    );
    assert!(
        harness.receipt_count() > 0,
        "the lightcone node must have served real frames during the control phase"
    );
    assert!(
        harness.frames_offered.load(Ordering::SeqCst) <= CONTROL_PHASE_FRAMES,
        "the control phase must not reach the stall threshold"
    );

    // --- Intrusion: the same node, the same config, a stuck stimulus ---------
    harness.drive_until(
        "an alert naming the stalled lightcone node",
        "intrusion",
        || !harness.alerts_for(LIGHTCONE_NAME).is_empty(),
    );

    // Inside the window *and* inside the deadline: the wait above is bounded by
    // WAIT_DEADLINE, and this asserts the stronger claim the harness promises.
    let intrusion_alerts = harness.alerts_for(LIGHTCONE_NAME);
    assert!(
        !intrusion_alerts.is_empty(),
        "the stuck node must be named within the alert window: {:?}",
        harness.alert_snapshot()
    );
    assert!(
        intrusion_alerts.iter().any(
            |message| matches!(message, ControlMsg::Restart { name } if name == LIGHTCONE_NAME)
        ),
        "a rhythm deviation is a redirect, not a kill: expected Restart, got {:?}",
        intrusion_alerts
    );

    // The intrusion was caught on a node that never crashed: this is the whole
    // point of the heartbeat path — a stuck strand is not a Crashed strand.
    assert_eq!(
        harness.lifecycle_count(|event| matches!(
            event,
            LifecycleEvent::Crashed { name, .. } if name == LIGHTCONE_NAME
        )),
        0,
        "the drill must not crash the node: a stuck node is alive"
    );
    // ...and the kernel executes the alert (the alarm's remedy path). The kernel
    // polls `sys.control` every ~50 ms, so the resulting `Restarted` lifecycle
    // event lands a tick later than the alert itself: wait for it rather than
    // racing it.
    harness.drive_until(
        "the kernel to act on the alert (a Restarted lifecycle event)",
        "intrusion",
        || {
            harness.lifecycle_count(|event| {
                matches!(event, LifecycleEvent::Restarted { name, .. } if name == LIGHTCONE_NAME)
            }) >= 1
        },
    );

    // --- Discriminate: the healthy neighbour was driven the whole time ------
    assert!(
        harness
            .alerts_for("imperium-memory-log-rejections")
            .is_empty(),
        "a node that kept advancing must never be named: {:?}",
        harness.alert_snapshot()
    );

    // --- Quiet window: the episode is still running, and the alert must not
    //     become a stream (GATE is change-only, CONSERVE caps the budget).
    //
    // At most one *new* alert is expected, not zero: the alert restarted the
    // node, and the fresh instance stalls again once it has seen its own
    // threshold (the old, sleeping instance is still alive — see
    // `restarting_a_stuck_strand_forks_it_rather_than_curing_it`), so a second,
    // separate episode is a legitimate second alert. A stream would be one alert
    // per tick; the bound here is one per ~2 s window.
    let before_quiet = harness.alerts_for(LIGHTCONE_NAME).len();
    harness.drive_for(QUIET_WINDOW, "quiet");
    let after_quiet = harness.alerts_for(LIGHTCONE_NAME).len();
    assert!(
        after_quiet <= before_quiet + 1,
        "a continuing episode must not flood the control channel: {before_quiet} -> {after_quiet} \
         ({:?})",
        harness.alert_snapshot()
    );

    assert!(
        harness.supervision.is_running(),
        "the run loop must have been live for the whole drill"
    );
    harness.report("stall-intrusion");
    harness.shutdown();
}

// ---------------------------------------------------------------------------
// 4: a node that never advanced is never called stuck
// ---------------------------------------------------------------------------

/// Thin evidence abstains. The engine's heartbeat rule is explicit: a node that
/// never made progress has no baseline, and "never progressed" is not the same
/// observation as "stopped progressing" — idle is not stuck.
///
/// The lightcone node is registered here and fed nothing at all, while the real
/// neighbour is driven for the whole alert window. Zero alerts may name it.
#[test]
fn a_strand_that_never_advanced_is_never_called_stuck() {
    let mut harness = Harness::start(
        armed(),
        Wiring {
            lightcone_faults: LightconeFaults::None,
            memory_log_lane: true,
            rhythm_stimulus: false,
        },
    );

    // Drive only the neighbour: the node under test is silent by design.
    let deadline = Instant::now() + ALERT_WINDOW;
    while Instant::now() < deadline {
        harness.offer_rejection("warmup");
        std::thread::sleep(OFFER_INTERVAL);
    }

    assert_eq!(
        harness.receipt_count(),
        0,
        "precondition: the idle node must have done no work"
    );
    assert!(
        harness.alerts_for(LIGHTCONE_NAME).is_empty(),
        "a node with no baseline must not be called stuck: {:?}",
        harness.alert_snapshot()
    );
    harness.report("never-advanced");
    harness.shutdown();
}

// ---------------------------------------------------------------------------
// Finding: idle-after-work is indistinguishable from stuck
// ---------------------------------------------------------------------------

/// **A pinned limit, asserted so it cannot be forgotten.** The heartbeat path has
/// no model of a node's *expected* traffic: a strand whose drained-message
/// counter rises and then stops rising for more than `heartbeat_stall_ticks`
/// (>8 ticks, ~0.5 s) is "alive but not advancing", and it is alerted on — even
/// though the only thing that happened is that the harness stopped feeding it.
///
/// That is the engine behaving as documented ("a node whose counter stalls while
/// it is alive is stuck"), and it is also why this alarm is additive and
/// defaults-off: in a live node, quiescence is common and an alarm that fires on
/// quiescence is unusable without an expected-rate model for heartbeats. The test
/// exists to keep that fact measured rather than assumed.
///
/// It also measures the *loop*, which is the sharper half of the finding: the
/// alert's remedy is `ControlMsg::Restart`, the kernel installs a fresh slot, and
/// the fresh slot is immediately replayed the pending tail of work traffic — so
/// the restarted instance registers as *advancing* again, goes quiet again, and
/// is alerted on again. An idle node therefore does not get one alert; it gets a
/// restart every ~0.7 s for as long as it stays idle. (Observed in this suite:
/// five restarts in 4 s for the harness's own recorder strands before they were
/// kept busy — see `AlertRecorder`.)
#[test]
fn a_strand_that_worked_and_then_went_quiet_is_flagged_as_stuck() {
    let mut harness = Harness::start(
        armed(),
        Wiring {
            lightcone_faults: LightconeFaults::None,
            memory_log_lane: false,
            rhythm_stimulus: false,
        },
    );

    // Let the node work, so it has a heartbeat baseline...
    harness.drive_for(Duration::from_millis(600), "settle");
    let receipts_before = harness.receipt_count();
    assert!(
        receipts_before > 0,
        "precondition: the node must have processed real work"
    );
    assert!(
        harness.alerts_for(LIGHTCONE_NAME).is_empty(),
        "precondition: it must not have been named while it was advancing"
    );

    // ...and then withhold its only input. Nothing else changes: same config,
    // same node, same run loop. The node is neither crashed nor detached.
    let deadline = Instant::now() + ALERT_WINDOW;
    while Instant::now() < deadline && harness.alerts_for(LIGHTCONE_NAME).is_empty() {
        std::thread::sleep(OFFER_INTERVAL);
    }

    assert!(
        !harness.alerts_for(LIGHTCONE_NAME).is_empty(),
        "the engine flags any silence-after-progress as stuck; if this ever stops \
         being true the model has changed and this finding must be re-derived: {:?}",
        harness.alert_snapshot()
    );
    assert_eq!(
        harness.lifecycle_count(|event| matches!(
            event,
            LifecycleEvent::Crashed { name, .. } if name == LIGHTCONE_NAME
        )),
        0,
        "the flagged node never crashed — the alert is about liveness, not death"
    );

    // The loop: the kernel obliged the alert by installing a fresh instance, the
    // kernel replayed the pending work tail to it, so the node advanced again,
    // fell quiet again, and was flagged again — with no new stimulus from this
    // test. Waiting rather than asserting immediately keeps this independent of
    // how fast the machine happens to be ticking.
    harness.wait_until(
        "the alarm to flag the node a second time (the restart loop)",
        || harness.alerts_for(LIGHTCONE_NAME).len() >= 2,
    );
    assert!(
        harness.lifecycle_count(|event| matches!(
            event,
            LifecycleEvent::Restarted { name, .. } if name == LIGHTCONE_NAME
        )) >= 1,
        "the first alert must have been executed as a real restart: {:?}",
        harness.lifecycle_snapshot()
    );

    harness.report("idle-after-work-loop");
    harness.shutdown();
}

// ---------------------------------------------------------------------------
// 5: the vibration path, with its warmup boundary
// ---------------------------------------------------------------------------

/// How long the rhythm stimulus is left steady before it deviates.
///
/// Safety margin, not a phase boundary: the boundary is a *configuration*
/// (`warmup_events`, see [`steady_then_deviate`]), because a wall-clock phase
/// would measure the machine. This only has to be long enough for the spider to
/// observe the steady value at least once — at most one arrival is observed per
/// ~60 ms tick, so 1.5 s is ≥ 2 observations even if the machine is several times
/// slower than nominal, and ≥ 20 observations on an idle one.
const STEADY_PHASE: Duration = Duration::from_millis(1_500);

/// Emit a steady rhythm, then an unambiguous 5x deviation, and report every
/// control message that named [`RHYTHM_NODE`] while the deviation ran.
///
/// The only knob that changes between the two tests below is `warmup_events`, so
/// the two runs are the two sides of the engine's thin-evidence rule:
///
/// * `warmup_events` = 2 (the engine's floor; `validate()` rejects 1): a baseline
///   exists after two observations, so the deviation is corroborated and alerts.
/// * `warmup_events` = 1_000_000: no wall clock this test could wait out would
///   give the node a baseline, so "thin evidence" is a property of the
///   configuration rather than a race — the deviation must abstain for the whole
///   observation window, however fast or slow the machine is.
///
/// The magnitudes make the deviation arithmetic, not luck: a relative magnitude
/// surprise of `|5000 - 1000| / 1000 = 4.0` against the engine's `surprise_band`
/// of `0.5`.
fn steady_then_deviate(warmup_events: u64) -> Vec<ControlMsg> {
    let mut cognition = armed();
    cognition.warmup_events = warmup_events;

    let mut harness = Harness::start(
        cognition,
        Wiring {
            lightcone_faults: LightconeFaults::None,
            memory_log_lane: false,
            rhythm_stimulus: true,
        },
    );

    // Steady: the stimulus is already at STEADY_MAGNITUDE when it starts. The
    // phases are driven (not slept through) so the instruments stay advancing
    // nodes and their counts stay exact — see `AlertRecorder`.
    harness.drive_for(STEADY_PHASE, "rhythm");
    harness.set_magnitude(DEVIATING_MAGNITUDE);
    let steady_alerts = harness.alerts_for(RHYTHM_NODE);

    harness.drive_for(ALERT_WINDOW, "rhythm");
    let alerts = harness.alerts_for(RHYTHM_NODE);

    // A steady rhythm is not an intrusion at either setting: if this ever fires,
    // the alarm has a false-positive mode that dominates everything else.
    assert!(
        steady_alerts.is_empty(),
        "a steady rhythm must never be named (warmup_events = {warmup_events}): {steady_alerts:?}"
    );

    // With a baseline, the episode is one alert, not a stream: the deviation is
    // continuous for the whole window, so GATE's change-only rule and CONSERVE's
    // budget are what keep this number small (a stream would be one per tick).
    // The instrument is exact here because no recorder was restarted during the
    // run (see `AlertRecorder`).
    if !alerts.is_empty() {
        assert_eq!(
            alerts.len(),
            1,
            "a continuing deviation must not re-fire (warmup_events = {warmup_events}): {alerts:?}"
        );
    }

    harness.report(&format!("rhythm-deviation(warmup_events={warmup_events})"));
    harness.shutdown();
    alerts
}

/// **Thin evidence abstains, even on an unambiguous deviation.**
///
/// Nothing in the engine can call a deviation a deviation before it knows the
/// mean, so a node with too few observations must be silent — and this run makes
/// "too few" hold for the entire observation window by configuration, so the
/// result cannot be a machine-speed artefact.
#[test]
fn a_deviation_without_a_baseline_abstains() {
    let alerts = steady_then_deviate(1_000_000);
    assert!(
        alerts.is_empty(),
        "the alarm must abstain while the node has no baseline: {alerts:?}"
    );
}

/// **The same deviation, with a baseline, is the intrusion.** Same stimulus, same
/// window, same wiring — the only difference from the test above is that the
/// engine was allowed to learn a rhythm first.
#[test]
fn the_same_deviation_with_a_baseline_alerts() {
    let alerts = steady_then_deviate(2);
    assert!(
        !alerts.is_empty(),
        "the same deviation, with a baseline, must be named"
    );
    assert!(
        alerts.iter().all(|message| matches!(
            message,
            ControlMsg::SetTransfer { node, .. } if node == RHYTHM_NODE
        )),
        "unexplained congestion is routed around, not killed: {alerts:?}"
    );
}

// ---------------------------------------------------------------------------
// D42, direction 1: the default is OFF, on the same stimulus
// ---------------------------------------------------------------------------

/// **The default behaviour, on the identical stimulus.** Cognition OFF is what
/// every deployment gets (and what `Bus::engage_supervision` does with no
/// environment set at all). Under it the same stuck node — same fault policy,
/// same thresholds, same run-loop wiring — must produce *nothing* on
/// `sys.control`: not an alert, not a redirect, nothing.
///
/// The silent window is strictly longer than [`ALERT_WINDOW`], so this is not a
/// weaker measurement than the firing case above.
#[test]
fn the_same_stuck_stimulus_is_silent_with_cognition_off() {
    let mut harness = Harness::start(
        CognitiveConfig::default(),
        Wiring {
            lightcone_faults: LightconeFaults::StallAfterFrames {
                after: STALL_AFTER_FRAMES,
                millis: STALL_WINDOW_MS,
            },
            memory_log_lane: true,
            rhythm_stimulus: false,
        },
    );

    // The stimulus is identical to the firing case; only the spider differs.
    harness.drive_for(SILENCE_PHASE, "cognition-off");

    assert_eq!(
        harness.alert_count(),
        0,
        "with cognition off the control channel carries no cognitive traffic at all: {:?}",
        harness.alert_snapshot()
    );
    // The node really was driven into the stall: it served frames first...
    assert!(
        harness.receipt_count() > 0,
        "the node must have worked before it stalled"
    );
    // ...and it is neither crashed nor quarantined: with cognition off the crash
    // wall is all there is, and nothing crashed.
    assert_eq!(
        harness.lifecycle_count(|event| matches!(
            event,
            LifecycleEvent::Crashed { name, .. } | LifecycleEvent::Quarantined { name, .. }
                if name == LIGHTCONE_NAME
        )),
        0,
        "nothing may happen to the node but silence: {:?}",
        harness.lifecycle_snapshot()
    );

    harness.report("cognition-off");
    harness.shutdown();
}

// ---------------------------------------------------------------------------
// D42, direction 2: an invalid configuration degrades to OFF, not to a crash
// ---------------------------------------------------------------------------

/// A configuration the engine's `validate()` rejects must not fail the node and
/// must not arm a judge: cognition falls back to OFF (with an error log), the run
/// loop still engages, and the same stuck stimulus stays silent — the identical
/// measurement as the default-off case, which is what makes "off" a behaviour
/// rather than a hope.
#[test]
fn an_invalid_cognitive_config_degrades_to_cognition_off() {
    // `warmup_events = 1` is rejected by the engine's own validation, so this is
    // exactly the "operator typo" the fail-safe path exists for.
    let invalid = cognition_config_from(Some("1"), Some("1"), None);
    assert!(invalid.validate().is_err(), "precondition: invalid config");
    assert!(
        invalid.enabled,
        "precondition: the request said 'armed' — only validation refuses it"
    );

    let mut harness = Harness::start(
        invalid,
        Wiring {
            lightcone_faults: LightconeFaults::StallAfterFrames {
                after: STALL_AFTER_FRAMES,
                millis: STALL_WINDOW_MS,
            },
            memory_log_lane: true,
            rhythm_stimulus: false,
        },
    );

    assert!(
        harness.supervision.is_running(),
        "an invalid cognitive config must not stop the node's supervision"
    );

    harness.drive_for(SILENCE_PHASE, "invalid-config");

    assert_eq!(
        harness.alert_count(),
        0,
        "an invalid config degrades to cognition OFF, so nothing is alerted on: {:?}",
        harness.alert_snapshot()
    );
    harness.report("invalid-config-degraded-to-off");
    harness.shutdown();
}

// ---------------------------------------------------------------------------
// Finding: what the alarm's remedy does to a stuck-but-alive node
// ---------------------------------------------------------------------------

/// **The alarm's remedy, measured.** A `ControlMsg::Restart` is a real restart
/// for a *dead* strand: the kernel installs a fresh slot from the factory. It is
/// not one for a *stuck* strand, because nothing in safe Rust can kill the
/// sleeping worker: the kernel's `restart_slot` builds a new slot and never
/// signals the old one, so the old worker keeps its inbox subscription and
/// resumes draining when its stall ends.
///
/// That is measurable, and this test measures it: the same frame observed twice
/// (identical `query_sha256` — the frame's hash — with two different sequence
/// numbers) can only happen if two live instances processed it. The kernel's
/// bounded replay tail is 32 messages, so anything far above that is not replay.
///
/// What the alarm *does* do correctly here is unchanged by this: it names the
/// stuck node while the node never crashed. What it cannot do is cure it — a
/// finding for the architecture, not a defect this harness can fix.
#[test]
fn restarting_a_stuck_strand_forks_it_rather_than_curing_it() {
    const STALL_MS: u64 = 4_000;

    let mut harness = Harness::start(
        armed(),
        Wiring {
            lightcone_faults: LightconeFaults::StallAfterFrames {
                after: STALL_AFTER_FRAMES,
                millis: STALL_MS,
            },
            memory_log_lane: false,
            rhythm_stimulus: false,
        },
    );

    harness.drive_until(
        "an alert naming the stalled lightcone node",
        "fork-drill",
        || !harness.alerts_for(LIGHTCONE_NAME).is_empty(),
    );

    // Drive past the end of the stall window: the (not-killed) first instance
    // wakes up and drains everything that piled up in its inbox.
    harness.drive_for(
        Duration::from_millis(STALL_MS) + Duration::from_secs(2),
        "fork-drill",
    );
    harness.shutdown();

    let duplicates = harness.duplicate_receipts();
    assert!(
        harness.receipt_count() > 0,
        "precondition: the node served real frames"
    );
    assert!(
        duplicates > 64,
        "the stalled instance is still alive and observing: {duplicates} duplicate \
         frame observations (the kernel's replay tail can explain at most 32) — if \
         this ever drops to the replay tail alone, the kernel has learned to stop a \
         stuck worker and this finding must be re-derived"
    );
    harness.report("restart-fork");
}
