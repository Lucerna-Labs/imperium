//! Append-only event log: the node's forensic record of what happened.
//!
//! Two streams feed it, and each has its own supervised Spiderweb **strand**
//! ([`MemoryLogStrand`], one per [`Lane`]) instead of the `tokio::spawn`ed recv
//! loop it used to have:
//!
//! | Lane | Consumes | Appends |
//! |---|---|---|
//! | [`Lane::StrainerRejections`] | `net.strainer.rejection` | `Message::StrainerRejection` |
//! | [`Lane::ProtocolEvents`] | `net.transport.` (prefix) | `Message::ProtocolEvt` |
//!
//! A crash in a lane is now visible to the spider as a `LifecycleEvent::Crashed`,
//! is restarted three times, and is quarantined on the fourth — instead of
//! killing the recv loop silently while the log quietly stopped recording. See
//! [`register_strands`] for the composition root's one call, and
//! the pilot (`imperium-net-lightcone`) for the general recipe.
//!
//! The log itself is unchanged and remains usable (and testable) without a bus:
//! [`MemoryLog::append`], its monotonic sequence numbers, its capacity and its
//! eviction policy are the same as before, and the strands share the caller's
//! `Arc<MemoryLog>` — they do not build their own — so every existing consumer
//! (`entries_since`, `get_by_event_id`, the extraction loop, the projection)
//! reads exactly the log the composition root wired.

mod strand;

pub use strand::{
    FaultPolicy, Lane, MemoryLogStrand, SeenIds, CRASH_AFTER_EVENTS_ENV, PROTOCOL_EVENTS_STRAND,
    REJECTIONS_STRAND,
};

use std::collections::VecDeque;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use imperium_protocol::BusEvent;
use parking_lot::RwLock;
use spiderweb::Bus;

/// Bus topics of this subsystem. General → specific, per `BUS_CONVENTIONS.md`.
///
/// These are the two strings the pre-conversion recv loops passed to
/// `Bus::subscribe`; they are named here once because three things must agree on
/// them: the publishers (the strainer, the transport orchestrator), the strands'
/// declared input sockets, and the lane filters.
///
/// `TRANSPORT_PREFIX` is a **prefix**, not a topic: the old loop subscribed to
/// `net.transport.` and matched every topic under it (`net.transport.event`,
/// `net.transport.decision`, …), ignoring the ones whose payload was not a
/// `Message::ProtocolEvt`. The strand keeps that prefix comparison and that
/// variant gate, so the set of accepted events is identical.
pub mod topics {
    /// Where `StrainerStack` publishes rejections.
    pub const STRAINER_REJECTION: &str = "net.strainer.rejection";
    /// The transport namespace the log records protocol events from.
    pub const TRANSPORT_PREFIX: &str = "net.transport.";
}

#[derive(Clone)]
pub struct LogEntry {
    pub event: BusEvent,
    pub logged_at: DateTime<Utc>,
    pub sequence: u64,
}

pub struct MemoryLog {
    entries: RwLock<VecDeque<LogEntry>>,
    next_seq: RwLock<u64>,
    max_entries: usize,
}

impl MemoryLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(VecDeque::with_capacity(max_entries)),
            next_seq: RwLock::new(0),
            max_entries,
        }
    }

    pub fn append(&self, event: BusEvent) -> u64 {
        let mut seq = self.next_seq.write();
        let sequence = *seq;
        *seq += 1;

        let entry = LogEntry {
            event,
            logged_at: Utc::now(),
            sequence,
        };

        let mut entries = self.entries.write();
        if entries.len() >= self.max_entries {
            entries.pop_front();
        }
        entries.push_back(entry);
        sequence
    }

    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    pub fn entries_since(&self, since_seq: u64) -> Vec<LogEntry> {
        self.entries
            .read()
            .iter()
            .filter(|e| e.sequence >= since_seq)
            .cloned()
            .collect()
    }

    pub fn get_by_event_id(&self, event_id: &imperium_protocol::EventId) -> Option<LogEntry> {
        self.entries
            .read()
            .iter()
            .find(|e| e.event.id.0 == event_id.0)
            .cloned()
    }
}

/// Queue this subsystem's supervised strands on `bus`.
///
/// # Call this *before* the kernel's run loop starts
///
/// Strand specs are installed by `Bus::run_until`. Registering later is not
/// merely refused, it is impossible: the composition root moves the `&mut Bus`
/// onto the run-loop thread, so a spec queued afterwards could not be handed to
/// it at all. The compiler enforces the ordering the old runtime error used to.
///
/// # Why this takes the log, not just the bus
///
/// The log is durable state the node owns and reads elsewhere: the composition
/// root builds one `Arc<MemoryLog>`, hands it to the signature extraction loop,
/// to the projection and to the operator surface, and keeps it. Building one
/// here would give the strands a *different* log than the rest of the node, so
/// the caller passes the one it already wired. The strands share it through
/// their factories, which is what makes a restart append to the same
/// monotonically-sequenced log instead of starting a parallel one.
///
/// # The fault policy
///
/// Read from [`FaultPolicy::from_env`] (see [`CRASH_AFTER_EVENTS_ENV`]) and
/// applied to **both** lanes; it is [`FaultPolicy::None`] unless an operator
/// armed a drill, and an armed drill is logged loudly. Tests that need one lane
/// armed and the other not build the spec directly with
/// [`MemoryLogStrand::spec`].
///
/// # Idempotence
///
/// This is *not* idempotent: a strand name is a kernel-global resource and
/// queuing the same name twice panics inside the kernel (recipe §5.8, a boot
/// failure). The composition root must call it exactly once.
pub fn register_strands(bus: &mut Bus, log: &Arc<MemoryLog>) {
    let faults = FaultPolicy::from_env();
    if faults.is_injected() {
        // A deliberately armed fault must never look like a real one in the
        // logs, and must be impossible to leave on by accident without a trace.
        tracing::warn!(
            policy = ?faults,
            env = CRASH_AFTER_EVENTS_ENV,
            "memory log fault injection ARMED — both log strands will crash on purpose"
        );
    }
    for lane in Lane::ALL {
        bus.register_spec(MemoryLogStrand::spec(lane, Arc::clone(log), faults));
    }
}

impl Default for MemoryLog {
    fn default() -> Self {
        Self::new(100_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperium_protocol::{EmergencyShutdown, Message};
    use spiderweb::{BusPublisher, ControlMsg, StrandSpec, SYS_CONTROL};
    use std::sync::Arc;
    use std::thread;

    fn make_event(topic: &str) -> BusEvent {
        BusEvent::new(
            topic.to_string(),
            Message::EmergencyShutdown(EmergencyShutdown {
                reason: "test".into(),
                triggered_at: Utc::now(),
                active_protocol: None,
                standby_protocol: None,
            }),
        )
    }

    #[test]
    fn append_returns_monotonic_sequences() {
        let log = MemoryLog::new(100);
        let s0 = log.append(make_event("a"));
        let s1 = log.append(make_event("b"));
        let s2 = log.append(make_event("c"));
        assert_eq!(s0, 0);
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
    }

    #[test]
    fn len_and_is_empty() {
        let log = MemoryLog::new(100);
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
        log.append(make_event("x"));
        assert!(!log.is_empty());
        assert_eq!(log.len(), 1);
    }

    fn seqs(entries: &[LogEntry]) -> Vec<u64> {
        entries.iter().map(|e| e.sequence).collect()
    }

    #[test]
    fn overflow_evicts_oldest() {
        let log = MemoryLog::new(3);
        let _s0 = log.append(make_event("a"));
        let _s1 = log.append(make_event("b"));
        let _s2 = log.append(make_event("c"));
        assert_eq!(log.len(), 3);

        let _s3 = log.append(make_event("d"));
        assert_eq!(log.len(), 3);

        let entries = log.entries_since(0);
        assert_eq!(seqs(&entries), vec![1, 2, 3]);
    }

    #[test]
    fn entries_since_filters_correctly() {
        let log = MemoryLog::new(100);
        for _ in 0..5 {
            log.append(make_event("t"));
        }
        assert_eq!(seqs(&log.entries_since(3)), vec![3, 4]);
        assert_eq!(seqs(&log.entries_since(0)), vec![0, 1, 2, 3, 4]);
        assert!(log.entries_since(100).is_empty());
    }

    #[test]
    fn entries_since_on_empty_log() {
        let log = MemoryLog::new(100);
        assert!(log.entries_since(0).is_empty());
    }

    #[test]
    fn entries_since_returns_full_entries() {
        let log = MemoryLog::new(100);
        log.append(make_event("topic.a"));
        log.append(make_event("topic.b"));

        let entries = log.entries_since(0);
        assert_eq!(entries.len(), 2);
        assert_eq!(&*entries[0].event.topic, "topic.a");
        assert_eq!(&*entries[1].event.topic, "topic.b");
        assert_eq!(entries[0].sequence, 0);
        assert_eq!(entries[1].sequence, 1);
    }

    #[test]
    fn entries_since_releases_lock() {
        let log = MemoryLog::new(100);
        log.append(make_event("first"));

        let entries = log.entries_since(0);
        assert_eq!(entries.len(), 1);

        // If the lock were held, this append would deadlock
        log.append(make_event("second"));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn default_capacity() {
        let log = MemoryLog::default();
        assert_eq!(log.max_entries, 100_000);
        assert!(log.is_empty());
    }

    #[test]
    fn logged_at_is_populated() {
        let log = MemoryLog::new(10);
        let before = Utc::now();
        log.append(make_event("t"));
        let after = Utc::now();

        let entries = log.entries.read();
        let entry = &entries[0];
        assert!(entry.logged_at >= before);
        assert!(entry.logged_at <= after);
    }

    #[test]
    fn event_content_preserved() {
        let log = MemoryLog::new(10);
        log.append(make_event("my.topic"));

        let entries = log.entries.read();
        let entry = &entries[0];
        assert_eq!(&*entry.event.topic, "my.topic");
        match &entry.event.message {
            Message::EmergencyShutdown(es) => {
                assert_eq!(es.reason, "test");
            }
            other => panic!("unexpected message variant: {:?}", other),
        }
    }

    #[test]
    fn concurrent_appends_no_sequence_collision() {
        let log = Arc::new(MemoryLog::new(10_000));
        let mut handles = vec![];

        for _ in 0..4 {
            let log = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                let mut seqs = vec![];
                for _ in 0..250 {
                    seqs.push(log.append(make_event("concurrent")));
                }
                seqs
            }));
        }

        let mut all_seqs: Vec<u64> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        all_seqs.sort();
        all_seqs.dedup();
        assert_eq!(all_seqs.len(), 1000, "all sequences must be unique");
        assert_eq!(log.len(), 1000);
    }

    #[test]
    fn overflow_under_concurrency() {
        let log = Arc::new(MemoryLog::new(50));
        let mut handles = vec![];

        for _ in 0..4 {
            let log = Arc::clone(&log);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    log.append(make_event("flood"));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            log.len(),
            50,
            "capacity must be respected under concurrency"
        );
    }

    #[test]
    fn get_by_event_id_returns_matching_entry() {
        let log = MemoryLog::new(100);
        let event = make_event("test.topic");
        let target_id = event.id.clone();
        log.append(make_event("other"));
        log.append(event);
        log.append(make_event("other2"));

        let found = log.get_by_event_id(&target_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().event.id.0, target_id.0);

        let missing = log.get_by_event_id(&imperium_protocol::EventId::new());
        assert!(missing.is_none());
    }

    /// Block (with a hard deadline) until `pred` holds, so a supervision bug
    /// fails the test instead of hanging it. The strand worker ticks every
    /// 10 ms, so the wait is normally a few ticks.
    fn wait_until(what: &str, mut pred: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !pred() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for: {what}"
            );
            thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    /// The supervision composition this test binary owns: install the queued
    /// specs plus the `spider` orchestrator, then run the kernel's loop on its
    /// own thread. Returns the shareable publisher and the run-loop thread.
    fn engage(bus: &mut Bus) -> (BusPublisher, thread::JoinHandle<()>) {
        bus.register_spider(StrandSpec::new(
            "spider",
            || Box::new(spider::Spider::new()),
        ));
        let publisher = bus.publisher();
        // The run loop consumes the bus, so the bus itself moves onto the
        // thread; `publisher` is the one shareable handle that stays behind.
        let mut bus = std::mem::replace(bus, Bus::open());
        let join = thread::spawn(move || bus.run_until(None));
        (publisher, join)
    }

    /// Ask the kernel to stop and join its run loop.
    fn shutdown(publisher: &BusPublisher, join: thread::JoinHandle<()>) {
        let _ = publisher.publish(SYS_CONTROL, ControlMsg::Shutdown);
        let _ = join.join();
    }

    /// The rejection lane, driven exactly as the composition root wires it:
    /// [`register_strands`] queues both lane specs, the kernel's run loop
    /// installs them, and the published rejection lands in the *caller's* log.
    ///
    /// This replaces `subscribe_strainer_rejections_records_events`, which
    /// spawned the recv loop; it asserts the same observable behaviour (one
    /// event in, exactly one appended entry, same message variant) through the
    /// strand instead of the task. `len() == 1` after one publish is also the
    /// double-consumer check: two consumers would append it twice.
    #[test]
    fn strainer_rejection_lane_appends_through_the_supervised_strand() {
        use imperium_protocol::StrainerRejection;

        let mut bus = Bus::open();
        let log = Arc::new(MemoryLog::new(100));

        register_strands(&mut bus, &log);
        let (publisher, join) = engage(&mut bus);

        publisher
            .publish(
                topics::STRAINER_REJECTION,
                BusEvent::new(
                    topics::STRAINER_REJECTION,
                    Message::StrainerRejection(StrainerRejection {
                        strainer_id: "timing".into(),
                        stack_id: "xray_stack".into(),
                        shape_failed: "too slow".into(),
                        source_identifier: None,
                        timestamp: Utc::now(),
                    }),
                ),
            )
            .unwrap();

        wait_until("the rejection to reach the log", || log.len() == 1);
        shutdown(&publisher, join);

        assert_eq!(log.len(), 1);
        let entries = log.entries_since(0);
        assert!(matches!(
            entries[0].event.message,
            Message::StrainerRejection(_)
        ));
        assert_eq!(&*entries[0].event.topic, "net.strainer.rejection");
    }

    /// The protocol-event lane, same wiring, same assertions: a
    /// `net.transport.event` is appended once, and the lane's prefix filter
    /// (`net.transport.`) is the one the old named subscription used.
    ///
    /// Replaces `subscribe_protocol_events_records_events`.
    #[test]
    fn protocol_event_lane_appends_through_the_supervised_strand() {
        use imperium_protocol::{ProtocolEvent, ProtocolEventKind, ProtocolRole, ProtocolStatus};

        let mut bus = Bus::open();
        let log = Arc::new(MemoryLog::new(100));

        register_strands(&mut bus, &log);
        let (publisher, join) = engage(&mut bus);

        publisher
            .publish(
                "net.transport.event",
                BusEvent::new(
                    "net.transport.event",
                    Message::ProtocolEvt(ProtocolEvent {
                        protocol_name: "xray".into(),
                        role: ProtocolRole::Active,
                        status: ProtocolStatus::Running,
                        event: ProtocolEventKind::Started,
                        timestamp: Utc::now(),
                    }),
                ),
            )
            .unwrap();

        wait_until("the protocol event to reach the log", || log.len() == 1);
        shutdown(&publisher, join);

        assert_eq!(log.len(), 1);
        let entries = log.entries_since(0);
        assert!(matches!(entries[0].event.message, Message::ProtocolEvt(_)));
        assert_eq!(&*entries[0].event.topic, "net.transport.event");
    }
}
