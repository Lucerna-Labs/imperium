//! The supervision composition this crate's tests own.
//!
//! Production owns it in exactly one place — the CLI's composition root, which
//! opens the kernel, registers every strand spec, registers the `spider`
//! orchestrator and drives `run_until` on its own thread. An in-crate test
//! module is a process owner too, so this is that composition written out for
//! tests.
//!
//! It is deliberately **not** shared across crates: `[dev-dependencies]` are
//! per-crate, and a shared supervision crate would be the facade this cutover
//! deleted. Spiderweb is the bus; this is the composition, and the process that
//! owns it writes it.

use std::sync::Arc;
use std::thread::JoinHandle;

use spiderweb::{Bus, BusPublisher, ControlMsg, StrandSpec, SYS_CONTROL};

/// Strand name the `spider` orchestrator is registered under — the same name the
/// CLI's composition root uses in production.
pub const SPIDER_STRAND_NAME: &str = "spider";

/// One Spiderweb kernel with the `spider` orchestrator installed, run on its own
/// thread until [`Supervision::shutdown`].
pub struct Supervision {
    /// The shareable handle onto the running kernel.
    pub publisher: Arc<BusPublisher>,
    join: Option<JoinHandle<()>>,
}

impl Supervision {
    /// Install the `spider` orchestrator and start the run loop.
    ///
    /// Takes the bus **by value** because `run_until(&mut self, ..)` consumes it:
    /// a kernel cannot be shared as `Arc` *and* consumed by a run loop, which is
    /// the whole reason the old design needed a state machine to bridge it.
    pub fn engage_with(mut bus: Bus, publisher: Arc<BusPublisher>) -> Self {
        bus.register_spider(StrandSpec::new(SPIDER_STRAND_NAME, || {
            Box::new(spider::Spider::new())
        }));

        let join = std::thread::Builder::new()
            .name("imperium-supervision".to_string())
            .spawn(move || {
                let mut bus = bus;
                bus.run_until(None);
            })
            .expect("failed to spawn the supervision run-loop thread");

        Self {
            publisher,
            join: Some(join),
        }
    }

    /// Ask the kernel to stop over `sys.control`, then join the run-loop thread.
    /// Idempotent: the join handle is taken once.
    pub fn shutdown(&mut self) {
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

/// A named subscription with an owned bounded queue.
///
/// This is the shape an asynchronous consumer outside a strand must now have:
/// native delivery is push-based, the kernel keeps no per-subscriber queue, and
/// a callback runs on the publisher's thread. So the consumer owns the queue and
/// the callback only does a non-blocking send into it — exactly the trade the
/// cutover doc records. A full queue drops the event (the callback increments
/// nothing and simply returns); the tests here size the queue so that cannot
/// happen, because what they assert is delivery, not backpressure.
pub fn subscribe_queue(
    publisher: &BusPublisher,
    prefix: &'static str,
    capacity: usize,
) -> tokio::sync::mpsc::Receiver<imperium_protocol::BusEvent> {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    publisher.subscribe_prefix(
        prefix,
        Box::new(move |_socket, payload| {
            if let Ok(event) = payload.downcast::<imperium_protocol::BusEvent>() {
                let _ = tx.try_send(*event);
            }
        }),
    );
    rx
}

/// A kernel plus its publisher — the composition root's first act, written out
/// for tests that register specs and publish through the shared handle.
pub fn open() -> (Bus, Arc<BusPublisher>) {
    let bus = Bus::open();
    let publisher = Arc::new(bus.publisher());
    (bus, publisher)
}
