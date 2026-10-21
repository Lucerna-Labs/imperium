//! Which way a frame travelled on the wire (a wire property, used by the passive lightcone
//! observation boundary and the host bridge).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireDirection {
    Inbound,
    Outbound,
}
