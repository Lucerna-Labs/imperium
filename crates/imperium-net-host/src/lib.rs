//! Host interface adapter for Imperium.
//!
//! Host-side pieces:
//!
//! - [`tun`] — a Linux TUN device, created and configured through `ioctl`,
//!   with no netlink dependency.
//! - [`bridge`] — the glue that carries real IP packets between that device
//!   and the [`imperium_net_mesh`] daemon.
//! - [`firewall`] — an opt-in, host-wide nftables egress guard.
//!
//! ## Scope, deliberately
//!
//! The bridge assigns the interface an address and a netmask and brings it up.
//! That is enough for the kernel to install its own *connected* route for the
//! tunnel subnet, so two peers can reach each other with no route command at
//! all. It does **not** touch the default route, does not install any route,
//! and does not touch the host firewall. Routing real traffic through the
//! tunnel is a separate, opt-in step, because getting it wrong cuts the host
//! off from the network it is using to reach the peer. [`HostKillSwitch`] is
//! also opt-in: it blocks non-loopback egress only after an explicit Engage.
//! Arming alone does not change host traffic. It requires CAP_NET_ADMIN and
//! libnftables; failure to install must refuse the opt-in startup.
//!
//! ## MTU arithmetic
//!
//! The mesh frame ceiling is `hardening::MAX_WIRE_SIZE` and the
//! hardener emits anything larger unquantized. A frame carries
//! `10 (header) + payload + 1 (sentinel) + pad`, and the AEAD adds a 16-byte
//! tag, so a TUN MTU of 1280 leaves ~200 bytes of headroom inside the ceiling
//! even before the length-hiding padding lands on a bucket. 1280 is also the
//! IPv6 minimum MTU, so the same value works for both families.

pub mod bridge;
pub mod firewall;
pub mod route;
pub mod tun;

pub use bridge::{BridgeHandle, BridgeStats, HostBridge, HostError};
pub use firewall::{HostGuardError, HostGuardMode, HostKillSwitch};
pub use imperium_net_mesh::{Destination, DestinationError};
pub use route::{Ipv4Route, RouteError, RouteGuard};
pub use tun::{TunDevice, TunError};

/// Default tunnel MTU. See the module note on the arithmetic.
pub const DEFAULT_MTU: u32 = 1280;

/// Default netmask, giving each tunnel a /24 so the kernel installs a
/// connected route for the tunnel subnet and peers reach each other directly.
pub const DEFAULT_NETMASK: &str = "255.255.255.0";
