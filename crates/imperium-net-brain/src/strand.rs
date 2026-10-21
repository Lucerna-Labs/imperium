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
}

impl BrainStrand {
    pub fn spec(service: Arc<BrainService>) -> StrandSpec {
        StrandSpec::new(NAME, move || -> Box<dyn Strand> {
            Box::new(BrainStrand { service: Arc::clone(&service) })
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
    let Some(paths) = imperium_net_pathworld::role_pack_paths(&role) else {
        tracing::error!(%role, "brain: no embedded pack for role");
        return Ok(None);
    };
    let world = match imperium_net_pathworld::PathWorld::embedded(&role) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(?e, "brain: role world failed to build");
            return Ok(None);
        }
    };
    let service = Arc::new(BrainService::from_world(&world, paths));
    let ready = BusEvent::new(topics::READY, Message::SubsystemReady { name: NAME.into() });
    publisher.publish(topics::READY, ready)?;
    tracing::info!(%role, "door two (brain) initialized");
    Ok(Some((BrainStrand::spec(Arc::clone(&service)), service)))
}
