//! The Lightcone observer loop as a supervised Spiderweb **strand**.
//!
//! This is the pilot conversion: the loop used to be a `tokio::spawn`ed task
//! holding a subscription for [`topics::FRAME`](crate::topics::FRAME). It is now
//! a [`Strand`], registered as a [`StrandSpec`] on the Spiderweb kernel, which
//! means the spider owns it: a crash becomes a `LifecycleEvent::Crashed`, is
//! restarted three times, and is quarantined on the fourth.
//!
//! # What is (and is not) preserved
//!
//! The strand is a thin adapter over [`LightconeService`]: the same service
//! methods run in the same order and the same messages go in and out on the
//! same topics, minted with [`BusEvent::new`] exactly as an external publisher
//! does.
//!
//! Two mechanics change, both deliberately:
//!
//! * **Filtering moves into the strand.** Spiderweb routes deliveries by
//!   `TypeId`, so this strand drains the shared [`BusEvent`] inbox and accepts
//!   only the exact frame socket/topic and typed structural message. Raw
//!   packet bytes never enter that inbox.
//! * **The pending-buffer replay.** The kernel keeps a bounded tail (32) of each
//!   message type so a *late* subscriber can be caught up. A restarted strand is
//!   a late subscriber, so after a crash it can replay recent observations.
//!   Duplicate observation is harmless here (the Lightcone is passive: it
//!   records what the exact graph admitted, twice, and never judges), but a
//!   conversion whose effect is *not* idempotent must dedupe on
//!   `event.id` — this is called out in the recipe.

use std::sync::Arc;
use std::time::{Duration, Instant};

use imperium_protocol::{BusEvent, Message};
use spiderweb::{BusHandle, Socket, Strand, StrandError, StrandSpec};

use crate::{topics, LightconeService, WireDirection};

/// Strand name. Fixed, `&'static str` (Spiderweb requires it), and equal to the
/// subsystem name used by the `net.lightcone.ready` message so one identifier
/// works in the topic table, the kernel's log, and the spider's log.
pub const NAME: &str = "imperium-net-lightcone";

/// Environment variable that arms a deliberate fault, for supervision drills:
/// `IMPERIUM_LIGHTCONE_CRASH_AFTER_FRAMES=<n>` makes every strand instance
/// return [`StrandError::Crashed`] once it has observed `n` frames.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. It exists so the restart/quarantine path can be exercised
/// end-to-end against the real pilot instead of a stand-in, and so an operator
/// can drill the supervisor on a live node.
pub const CRASH_AFTER_FRAMES_ENV: &str = "IMPERIUM_LIGHTCONE_CRASH_AFTER_FRAMES";

/// Environment variable that arms the **stuck-node** drill:
/// `IMPERIUM_LIGHTCONE_STALL_AFTER_FRAMES=<n>` makes every strand instance stop
/// draining its inbox once it has observed `n` frames, for
/// [`STALL_WINDOW_MS`], and then resume.
///
/// A stall is a different failure from a crash, and the reason this drill
/// exists: the strand stays **alive** — registered, ticking, never `Crashed` —
/// while it stops advancing. From outside, the only evidence is
/// `BusStats::per_strand[..].processed` flatlining, which is exactly what the
/// spider's cognitive engine polls as a heartbeat (that is the signal this
/// drill exists to test), and which nothing in Imperium could see before it.
///
/// Unset (or `0`, or unparsable) means no injection — the default in every
/// deployment. An operator arms it to prove the alarm fires on their node; the
/// capability harness arms it to prove the same thing against the real strand.
pub const STALL_AFTER_FRAMES_ENV: &str = "IMPERIUM_LIGHTCONE_STALL_AFTER_FRAMES";

/// How long an armed stall lasts, in milliseconds.
///
/// Long on purpose: it is a *stimulus*, not a deadline. A stall must outlive
/// the observer's whole corroboration sequence (the spider ticks every ~60 ms
/// and needs ~11 ticks of a flat heartbeat), with margin enough that a loaded
/// machine slows the observer rather than ending the stimulus. It is bounded on
/// purpose too: a strand that blocked forever could never be joined (recipe
/// §5.6). The stall loop additionally re-checks `is_shutting_down` every 20 ms,
/// so an engaged stall never delays shutdown.
pub const STALL_WINDOW_MS: u64 = 8_000;

/// How long each slice of a stall lasts before the shutdown flag is re-checked.
const STALL_SLICE: Duration = Duration::from_millis(20);

/// How a Lightcone strand instance should fault, for drills and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FaultPolicy {
    /// Observe normally. The production default.
    #[default]
    None,
    /// Deliberately crash after observing `n` frames. The count is per strand
    /// *instance*, so a restarted instance crashes again after its own `n`th
    /// frame — which is what lets a drill drive the full
    /// crash → restart ×3 → quarantine sequence.
    CrashAfterFrames(u32),
    /// Deliberately stop advancing while staying alive: once `after` frames have
    /// been observed, sleep for `millis` **without draining the inbox**, then
    /// resume. One-shot per instance (an instance that has stalled once does not
    /// stall again, so a drill converges instead of looping) and shutdown-aware.
    StallAfterFrames { after: u32, millis: u64 },
}

impl FaultPolicy {
    /// Read the policy from [`CRASH_AFTER_FRAMES_ENV`] and
    /// [`STALL_AFTER_FRAMES_ENV`]. Absent/zero/invalid means that drill is not
    /// armed: a typo must never misbehave a node.
    pub fn from_env() -> Self {
        Self::parse(
            std::env::var(CRASH_AFTER_FRAMES_ENV).ok().as_deref(),
            std::env::var(STALL_AFTER_FRAMES_ENV).ok().as_deref(),
        )
    }

    /// The parsing half of [`FaultPolicy::from_env`], without process-env
    /// access so it can be tested without racing other tests.
    ///
    /// If *both* drills are armed the crash wins: a crash is the harsher
    /// stimulus, and a strand that crashed cannot also stall.
    pub fn parse(crash_after: Option<&str>, stall_after: Option<&str>) -> Self {
        if let Some(frames) = positive_count(crash_after) {
            return FaultPolicy::CrashAfterFrames(frames);
        }
        if let Some(frames) = positive_count(stall_after) {
            return FaultPolicy::StallAfterFrames {
                after: frames,
                millis: STALL_WINDOW_MS,
            };
        }
        FaultPolicy::None
    }

    /// Whether this policy injects a fault (used to warn loudly at boot).
    pub fn is_injected(&self) -> bool {
        !matches!(self, FaultPolicy::None)
    }

    /// The environment variable that armed this policy, for an exact boot log.
    pub fn source_env(&self) -> Option<&'static str> {
        match self {
            FaultPolicy::None => None,
            FaultPolicy::CrashAfterFrames(_) => Some(CRASH_AFTER_FRAMES_ENV),
            FaultPolicy::StallAfterFrames { .. } => Some(STALL_AFTER_FRAMES_ENV),
        }
    }

    /// The crash reason for an instance that has just observed `frames_seen`
    /// frames, or `None` while this instance should keep running.
    fn tripped(&self, frames_seen: u32) -> Option<String> {
        match self {
            FaultPolicy::None | FaultPolicy::StallAfterFrames { .. } => None,
            FaultPolicy::CrashAfterFrames(n) if frames_seen >= *n => Some(format!(
                "injected fault: crashed after {frames_seen} frame(s) ({CRASH_AFTER_FRAMES_ENV} = {n})"
            )),
            FaultPolicy::CrashAfterFrames(_) => None,
        }
    }

    /// How long this instance should stall, given the frames it has observed and
    /// whether it has already served its one stall.
    fn stall(&self, frames_seen: u32, already_stalled: bool) -> Option<u64> {
        match self {
            FaultPolicy::StallAfterFrames { after, millis }
                if !already_stalled && frames_seen >= *after =>
            {
                Some(*millis)
            }
            _ => None,
        }
    }
}

/// Parse an optional positive frame count. Absent, empty, zero, negative and
/// unparsable all mean "this drill is not armed".
fn positive_count(raw: Option<&str>) -> Option<u32> {
    match raw.map(str::trim).and_then(|v| v.parse::<u32>().ok()) {
        Some(n) if n > 0 => Some(n),
        _ => None,
    }
}

/// The Lightcone observer loop as a strand.
///
/// Owns its state: the service is shared with whatever built it (`Arc`), the
/// fault policy is `Copy`, and the frame counter is per instance. Nothing is
/// borrowed from outside, which is what makes a strand restartable — the
/// kernel's factory call produces a fresh, independent instance.
pub struct LightconeStrand {
    service: Arc<LightconeService>,
    faults: FaultPolicy,
    /// Frames this *instance* has observed. Per-instance by construction, so a
    /// restart resets it.
    frames_seen: u32,
    /// Whether this instance has already served its one
    /// [`FaultPolicy::StallAfterFrames`] stall. Per-instance like
    /// `frames_seen`; it exists so a drill stalls once and then converges
    /// rather than stalling on every tick.
    stalled: bool,
}

impl LightconeStrand {
    pub fn new(service: Arc<LightconeService>, faults: FaultPolicy) -> Self {
        Self {
            service,
            faults,
            frames_seen: 0,
            stalled: false,
        }
    }

    /// The restartable spec for this strand, ready for
    /// [`Bus::register_spec`](spiderweb::Bus::register_spec).
    ///
    /// The factory captures an `Arc<LightconeService>` clone, so every restarted
    /// instance runs against the same world and the same ledger — restart
    /// resumes observation of the same causal geometry rather than reloading a
    /// different one. The ledger's sequence numbers therefore remain monotonic
    /// across crashes.
    pub fn spec(service: Arc<LightconeService>, faults: FaultPolicy) -> StrandSpec {
        StrandSpec::new(NAME, move || -> Box<dyn Strand> {
            Box::new(LightconeStrand::new(Arc::clone(&service), faults))
        })
    }
}

impl Strand for LightconeStrand {
    fn name(&self) -> &str {
        NAME
    }

    fn inputs(&self) -> &[Socket] {
        // The socket name is documentation for the lifecycle event and the web
        // graph; routing is by `BusEvent`'s `TypeId` (see the module docs).
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::FRAME)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::RECEIPT)];
        &SOCKS
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        // Cooperative shutdown: the kernel is winding down, so end this tick
        // and let the worker join (draining instead would delay shutdown).
        if bus.is_shutting_down() {
            return Ok(());
        }

        // `recv_all` drains every `BusEvent` in the inbox, whatever socket it
        // arrived on. Draining by socket name instead (`recv::<BusEvent>(name)`)
        // would keep every non-matching carrier in the inbox forever, growing it
        // one event per bus publish — the inbox is a mailbox, not a filter.
        //
        // `?` is infallible here in practice: the inbox only ever contains
        // payloads whose `TypeId` matched this strand's declared input, so the
        // only error variant (`TypeMismatch`) cannot fire. A genuine kernel
        // fault still surfaces as `Crashed` and is supervised.
        let events = bus.recv_all::<BusEvent>()?;

        for (socket, event) in events {
            if socket != topics::FRAME || event.topic.as_ref() != topics::FRAME {
                continue;
            }
            let Message::LightconeStructure(observation) = event.message else {
                continue;
            };

            let Some(direction) = WireDirection::from_u8(observation.direction) else {
                self.service.note_delivery_failure();
                continue;
            };
            match self.service.observe_structure(
                direction,
                observation.format,
                observation.observation_kind,
                observation.seeds,
                observation.query_hash,
            ) {
                Ok(record) => {
                    let message = self.service.to_message(&record);
                    // Mint the payload exactly as an external publisher does
                    // (`BusEvent::new` on the same topic), so subscribers —
                    // named and strand — see the same message with the same
                    // `id`/`timestamp` semantics. The socket name IS the topic
                    // here, so prefix subscribers on `net.lightcone.receipt`
                    // match it by content.
                    let event = BusEvent::new(topics::RECEIPT, Message::LightconeReceipt(message));
                    if let Err(err) = bus.publish(topics::RECEIPT, event) {
                        self.service.note_delivery_failure();
                        tracing::warn!(error = %err, "lightcone receipt publish failed");
                    }
                }
                Err(err) => {
                    tracing::debug!(error = %err, "lightcone observation failed");
                }
            }

            self.frames_seen = self.frames_seen.saturating_add(1);
            if let Some(reason) = self.faults.tripped(self.frames_seen) {
                // Diagnostic-only path; see `FaultPolicy`.
                return Err(StrandError::Crashed(reason));
            }
        }

        // The stuck-node drill (diagnostic-only; see
        // [`FaultPolicy::StallAfterFrames`]): after `after` frames, stop
        // draining — the inbox keeps filling while this tick sleeps — and stay
        // alive. That is the "alive but not advancing" shape a heartbeat reader
        // sees as `processed` standing still.
        //
        // The sleep is chopped into shutdown-aware slices, so a stalled strand
        // still joins promptly and can never hold up a node shutdown (recipe
        // §5.6: blocking inside `run` is bounded, never indefinite).
        if let Some(millis) = self.faults.stall(self.frames_seen, self.stalled) {
            self.stalled = true;
            tracing::warn!(
                millis,
                env = STALL_AFTER_FRAMES_ENV,
                "lightcone stalled on purpose — alive, registered, and not advancing \
                 (heartbeat-staleness drill)"
            );
            let deadline = Instant::now() + Duration::from_millis(millis);
            while Instant::now() < deadline {
                if bus.is_shutting_down() {
                    break;
                }
                bus.sleep(STALL_SLICE);
            }
        }

        // Nothing to do this tick. Returning `Ok(())` schedules another tick
        // (the worker paces them at 10ms), which is this strand's idle loop.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A typo — or any absent/zero/negative value — must leave *both* drills
    /// unarmed. This is the property that makes the drills safe to ship in
    /// production code.
    #[test]
    fn fault_policy_absent_zero_or_invalid_means_none() {
        for (crash, stall) in [
            (None, None),
            (Some(""), Some("")),
            (Some("   "), Some("   ")),
            (Some("0"), Some("0")),
            (Some("many"), Some("frames")),
            (Some("-1"), Some("-1")),
            (Some("1.5"), Some("1.5")),
            (Some("ture"), Some("stall")),
        ] {
            let policy = FaultPolicy::parse(crash, stall);
            assert_eq!(
                policy,
                FaultPolicy::None,
                "crash={crash:?} stall={stall:?} must not arm a drill"
            );
            assert!(!policy.is_injected());
            assert_eq!(policy.source_env(), None);
        }
    }

    #[test]
    fn fault_policy_parses_a_positive_count_and_trips_from_there() {
        let policy = FaultPolicy::parse(Some(" 2 "), None);
        assert_eq!(policy, FaultPolicy::CrashAfterFrames(2));
        assert!(policy.is_injected());
        assert_eq!(policy.source_env(), Some(CRASH_AFTER_FRAMES_ENV));
        assert!(policy.tripped(1).is_none(), "not yet at the threshold");
        let reason = policy.tripped(2).expect("threshold reached");
        assert!(
            reason.contains("injected fault") && reason.contains(CRASH_AFTER_FRAMES_ENV),
            "the reason must name the drill that caused it: {reason}"
        );
    }

    /// The stall drill: armed from its own variable, bounded by
    /// [`STALL_WINDOW_MS`], and one-shot per instance.
    #[test]
    fn fault_policy_parses_a_stall_and_stalls_once_per_instance() {
        let policy = FaultPolicy::parse(None, Some(" 3 "));
        assert_eq!(
            policy,
            FaultPolicy::StallAfterFrames {
                after: 3,
                millis: STALL_WINDOW_MS
            }
        );
        assert!(policy.is_injected());
        assert_eq!(policy.source_env(), Some(STALL_AFTER_FRAMES_ENV));

        assert!(policy.stall(2, false).is_none(), "not yet at the threshold");
        assert_eq!(
            policy.stall(3, false),
            Some(STALL_WINDOW_MS),
            "the stall is bounded, never indefinite"
        );
        assert!(
            policy.stall(3, true).is_none(),
            "one stall per instance: a drill must converge, not loop"
        );

        // A stall never crashes, and a crash never stalls.
        assert!(policy.tripped(100).is_none());

        // The window must outlive the observer's corroboration sequence: the
        // spider ticks every ~60 ms and needs ~11 flat ticks (~0.7 s), and a
        // stimulus that ends sooner would measure the machine, not the alarm.
        assert!(
            STALL_WINDOW_MS >= 5_000,
            "the stall window is a stimulus and needs real margin"
        );
    }

    /// Both drills armed is an operator mistake; the harsher one wins, and the
    /// parse is exhaustive so a typo in one cannot arm the other.
    #[test]
    fn crash_drill_wins_when_both_drills_are_armed() {
        assert_eq!(
            FaultPolicy::parse(Some("1"), Some("1")),
            FaultPolicy::CrashAfterFrames(1)
        );
        assert_eq!(
            FaultPolicy::parse(None, Some("4")),
            FaultPolicy::StallAfterFrames {
                after: 4,
                millis: STALL_WINDOW_MS
            }
        );
    }
}
