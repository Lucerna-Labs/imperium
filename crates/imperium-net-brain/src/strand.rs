//! The brain's supervised receipt loop (DOOR-TWO-BRAIN-PRECOMMIT-2026-10-21.md).
//!
//! A Spiderweb strand, supervised exactly like the lightcone strand (3 restarts, then quarantine),
//! that reads `net.lightcone.receipt` and feeds each receipt to [`BrainService::observe`]. It
//! consumes door one's record; it never publishes a verdict and never changes door one.

use std::sync::Arc;

use imperium_protocol::{BusEvent, Message};
use spiderweb::{BusError, BusHandle, BusPublisher, Socket, Strand, StrandError, StrandSpec};

use crate::BrainService;

pub const NAME: &str = "imperium-net-brain";

pub mod topics {
    pub const READY: &str = "net.brain.ready";
    /// door one's receipts, the brain's input (owned by the lightcone).
    pub const RECEIPT: &str = "net.lightcone.receipt";
}

pub struct BrainStrand {
    service: Arc<BrainService>,
    last_refresh: Option<std::time::Instant>,
}

/// How often the brain re-reads this host's own addresses from the kernel (setting).
pub const OWN_ADDRESS_REFRESH: std::time::Duration = std::time::Duration::from_secs(1);
/// The directory where door two keeps evidence across restarts (setting).
pub const STATE_ENV: &str = "IMPERIUM_BRAIN_STATE";

impl BrainStrand {
    pub fn spec(service: Arc<BrainService>) -> StrandSpec {
        StrandSpec::new(NAME, move || -> Box<dyn Strand> {
            Box::new(BrainStrand { service: Arc::clone(&service), last_refresh: None })
        })
    }
}

impl Strand for BrainStrand {
    fn name(&self) -> &str {
        NAME
    }

    fn inputs(&self) -> &[Socket] {
        const SOCKS: [Socket; 1] = [Socket::new::<BusEvent>(topics::RECEIPT)];
        &SOCKS
    }

    fn outputs(&self) -> &[Socket] {
        &[]
    }

    fn run(&mut self, bus: &mut BusHandle) -> Result<(), StrandError> {
        if bus.is_shutting_down() {
            return Ok(());
        }
        // Keep the host's own addresses current: a fresh TUN address is known as soon as it exists.
        if self.last_refresh.map_or(true, |t| t.elapsed() >= OWN_ADDRESS_REFRESH) {
            self.service.set_own_addresses(crate::own_addresses_from_proc());
            self.last_refresh = Some(std::time::Instant::now());
        }
        for (socket, event) in bus.recv_all::<BusEvent>()? {
            if socket != topics::RECEIPT || event.topic.as_ref() != topics::RECEIPT {
                continue;
            }
            if let Message::LightconeReceipt(receipt) = event.message {
                self.service.observe(&receipt);
            }
        }
        Ok(())
    }
}

/// Publish readiness and return the brain strand spec (the caller registers it before the run loop,
/// like the lightcone). `Ok(None)` when no role is set (door two has nothing to learn for).
pub fn init_with_service(
    publisher: &BusPublisher,
) -> Result<Option<(StrandSpec, Arc<BrainService>)>, BusError> {
    let role = match std::env::var(imperium_net_pathworld::ROLE_ENV) {
        Ok(r) if !r.is_empty() && r != imperium_net_pathworld::UNTRAINED => r,
        _ => return Ok(None),
    };
    let Some(paths) = imperium_net_pathworld::role_paths_from_env(&role) else {
        tracing::error!(%role, "brain: no embedded pack for role");
        return Ok(None);
    };
    let world = match imperium_net_pathworld::PathWorld::from_env() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(?e, "brain: role world failed to build");
            return Ok(None);
        }
    };
    let mut service = BrainService::from_world(&world, paths);
    if let Ok(dir) = std::env::var(STATE_ENV) {
        if !dir.is_empty() {
            let _ = std::fs::create_dir_all(&dir);
            service = service.with_state(std::path::Path::new(&dir).join(format!("{role}.evidence.pathpack")));
        }
    }
    service.set_own_addresses(crate::own_addresses_from_proc());
    let service = Arc::new(service);
    let ready = BusEvent::new(topics::READY, Message::SubsystemReady { name: NAME.into() });
    publisher.publish(topics::READY, ready)?;
    tracing::info!(%role, "door two (brain) initialized");
    Ok(Some((BrainStrand::spec(Arc::clone(&service)), service)))
}
