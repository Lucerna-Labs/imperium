mod stack;
mod strainers;

pub use stack::{StrainerRegistry, StrainerStack};
pub use strainers::{
    AuthShapeInnerStrainer, AuthShapeOuterStrainer, ByteJitterStrainer, TimingStrainer,
    TruncationStrainer,
};

use std::collections::HashMap;
use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use imperium_protocol::{BusEvent, Message};
use spiderweb::{BusError, BusPublisher};

#[derive(Clone, Debug)]
pub struct StrainerInput {
    pub data: Vec<u8>,
    pub source: Option<SocketAddr>,
    pub context: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StrainerEffect {
    /// Response delayed by a distribution-sampled amount. The strainer records
    /// the sampled delay synchronously and never sleeps; applying the delay on
    /// the wall clock belongs to the transport-layer consumer.
    TimingDelay {
        jitter_ms: u64,
        delay_ms: u64,
    },
    ByteJitter {
        byte_count: usize,
    },
    Truncation {
        max_length: usize,
    },
}

impl StrainerEffect {
    pub fn method_tag(&self) -> String {
        match *self {
            StrainerEffect::TimingDelay { delay_ms, .. } => {
                format!("timing_delay_{}ms", delay_ms)
            }
            StrainerEffect::ByteJitter { byte_count } => {
                format!("byte_jitter_{}_bytes", byte_count)
            }
            StrainerEffect::Truncation { max_length } => {
                format!("truncated_to_{}", max_length)
            }
        }
    }
}

impl std::fmt::Display for StrainerEffect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.method_tag())
    }
}

#[derive(Clone, Debug)]
pub enum StrainerOutput {
    Passed(Vec<u8>),
    Rejected {
        reason: String,
    },
    Degraded {
        data: Vec<u8>,
        effect: StrainerEffect,
    },
}

impl StrainerOutput {
    pub fn is_passed(&self) -> bool {
        matches!(self, StrainerOutput::Passed(_))
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, StrainerOutput::Rejected { .. })
    }

    pub fn data(&self) -> Option<&[u8]> {
        match self {
            StrainerOutput::Passed(d) | StrainerOutput::Degraded { data: d, .. } => Some(d),
            StrainerOutput::Rejected { .. } => None,
        }
    }
}

pub trait Strainer: Send + Sync {
    fn id(&self) -> &str;
    fn shape_filtered(&self) -> &str;
    fn apply(&self, input: StrainerInput) -> StrainerOutput;
}

pub async fn init(publisher: &BusPublisher) -> Result<(), BusError> {
    let ready = BusEvent::new(topics::READY, Message::SubsystemReady { name: NAME.into() });
    publisher.publish(topics::READY, ready)?;
    tracing::info!("imperium-net-strainer initialized");
    Ok(())
}

/// This subsystem's bus topics, general → specific per `BUS_CONVENTIONS.md`.
pub mod topics {
    /// Readiness announcement, published once by [`init`].
    pub const READY: &str = "net.strainer.ready";
    /// Per-frame rejection, published by [`StrainerStack::emit_rejection`].
    pub const REJECTION: &str = "net.strainer.rejection";
}

/// The subsystem name used in the readiness message and in logs.
pub const NAME: &str = "imperium-net-strainer";
