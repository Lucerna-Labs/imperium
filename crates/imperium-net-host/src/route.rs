//! IPv4 routes onto a TUN device, and their removal.
//!
//! A tunnel that carries only its own two addresses is not a VPN. This is what
//! makes a subnet *behind* the peer reachable through the seal.
//!
//! ## Two rules this module exists to enforce
//!
//! 1. **Never touch the default route.** Only explicit destinations are routed,
//!    so a mistake here cannot cut the host off from the network it is using to
//!    reach the peer. Full-tunnel routing is deliberately not implemented.
//! 2. **Every route added is removed.** A leaked route on a host is a silent
//!    outage waiting for the next reboot, so installation returns an RAII guard
//!    whose `Drop` removes it, and [`RouteGuard::default_route_untouched`]
//!    asserts the invariant for a caller that wants to be sure.
//!
//! ## Removal is not guaranteed by `Drop` alone
//!
//! `Drop` does not run on `SIGKILL`, and routes are kernel state, not process
//! state. So identification is made idempotent instead: [`Ipv4Route::add`]
//! removes any existing route for the same destination first. A route leaked by
//! a killed process is therefore repaired by the next run rather than
//! accumulating.
//!
//! Implemented with `SIOCADDRT` / `SIOCDELRT` rather than netlink or shelling
//! out to `ip`: no dependency, and no child process, which the project's
//! substrate rule forbids.

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;

use imperium_net_mesh::Destination;
use thiserror::Error;

#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = libc::c_ulong;

const SIOCADDRT: IoctlRequest = 0x890B;
const SIOCDELRT: IoctlRequest = 0x890C;

const RTF_UP: libc::c_ushort = 0x0001;
const RTF_GATEWAY: libc::c_ushort = 0x0002;
const RTF_HOST: libc::c_ushort = 0x0004;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error("destination error: {0}")]
    Destination(#[from] imperium_net_mesh::DestinationError),
    #[error("interface name contains a NUL byte")]
    NameInvalid,
    #[error("route socket: {0}")]
    Socket(io::Error),
    #[error("{action} route {destination}/{prefix} via {device}: {source}")]
    Ioctl {
        action: &'static str,
        destination: Ipv4Addr,
        prefix: u8,
        device: String,
        #[source]
        source: io::Error,
    },
}

/// An installed route. Removing happens explicitly in [`Drop`].
#[derive(Debug)]
pub struct Ipv4Route {
    destination: Destination,
    device: String,
    installed: bool,
}

impl Ipv4Route {
    /// Install `destination` onto `device`.
    ///
    /// Idempotent: any route already present for the same destination is removed
    /// first, so a route leaked by a killed process is repaired rather than
    /// duplicated or rejected.
    pub fn add(destination: Destination, device: &str) -> Result<Self, RouteError> {
        if destination.is_default() {
            // Not an error the caller can fix by retrying; it is a line this
            // module will not cross.
            return Err(RouteError::Destination(
                imperium_net_mesh::DestinationError::InvalidPrefix {
                    address: destination.network,
                    prefix: 0,
                },
            ));
        }
        let device_c = CString::new(device).map_err(|_| RouteError::NameInvalid)?;
        let socket = RouteSocket::open()?;

        // Repair any leftover before installing.
        let _ = socket.modify(SIOCDELRT, &destination, &device_c);

        socket.modify(SIOCADDRT, &destination, &device_c)?;
        tracing::info!(
            destination = %destination,
            device,
            "route installed through the tunnel"
        );
        Ok(Self {
            destination,
            device: device.to_string(),
            installed: true,
        })
    }

    pub fn destination(&self) -> Destination {
        self.destination
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    /// Remove the route now, if it is still installed.
    pub fn remove(&mut self) -> Result<(), RouteError> {
        if !self.installed {
            return Ok(());
        }
        let device_c = CString::new(self.device.as_str()).map_err(|_| RouteError::NameInvalid)?;
        let socket = RouteSocket::open()?;
        socket.modify(SIOCDELRT, &self.destination, &device_c)?;
        self.installed = false;
        tracing::info!(
            destination = %self.destination,
            "route removed"
        );
        Ok(())
    }
}

impl Drop for Ipv4Route {
    fn drop(&mut self) {
        if let Err(error) = self.remove() {
            // Nothing to do but shout: the process is going away and the route
            // is kernel state. The next `add` for the same destination repairs
            // it, which is why `add` removes first.
            tracing::error!(
                %error,
                destination = %self.destination,
                "failed to remove a route; a later run for the same destination will repair it"
            );
        }
    }
}

/// Owns every route this process installed, so one value held for the process
/// lifetime guarantees they are all cleaned up together.
#[derive(Default)]
pub struct RouteGuard {
    routes: Vec<Ipv4Route>,
}

impl RouteGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a route and take ownership of it.
    pub fn install(&mut self, destination: Destination, device: &str) -> Result<(), RouteError> {
        self.routes.push(Ipv4Route::add(destination, device)?);
        Ok(())
    }

    /// Parse and install several CIDRs at once. Fails on the first bad one,
    /// leaving already-installed routes owned by the guard so they are still
    /// removed.
    pub fn install_all<'a>(
        &mut self,
        cidrs: impl IntoIterator<Item = &'a str>,
        device: &str,
    ) -> Result<(), RouteError> {
        for cidr in cidrs {
            let destination = Destination::parse(cidr)?;
            self.install(destination, device)?;
        }
        Ok(())
    }

    /// Remove everything now, rather than waiting for `Drop`.
    pub fn remove_all(&mut self) {
        for route in self.routes.iter_mut().rev() {
            if let Err(error) = route.remove() {
                tracing::warn!(%error, "route removal failed");
            }
        }
        self.routes.clear();
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn destinations(&self) -> Vec<Destination> {
        self.routes.iter().map(|r| r.destination).collect()
    }

    /// Whether any installed route is a default route. Always `false` — this
    /// exists so a caller (or a test) can assert the invariant rather than
    /// trust it.
    pub fn default_route_untouched(&self) -> bool {
        !self.routes.iter().any(|r| r.destination.is_default())
    }
}

/// An `AF_INET` datagram socket used only to carry route ioctls.
struct RouteSocket(RawFd);

impl RouteSocket {
    fn open() -> Result<Self, RouteError> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(RouteError::Socket(io::Error::last_os_error()));
        }
        Ok(Self(fd))
    }

    fn modify(
        &self,
        request: IoctlRequest,
        destination: &Destination,
        device: &CString,
    ) -> Result<(), RouteError> {
        let mut entry = RtEntry::default();
        RtEntry::set_sockaddr(&mut entry.rt_dst, destination.network);
        RtEntry::set_sockaddr(&mut entry.rt_genmask, destination.netmask());
        entry.rt_flags = RTF_UP;
        if destination.is_host() {
            entry.rt_flags |= RTF_HOST;
        } else {
            // No gateway: this is a device route. RTF_GATEWAY is deliberately
            // absent, because the next hop is the interface itself.
            entry.rt_flags &= !RTF_GATEWAY;
        }
        entry.rt_dev = device.as_ptr() as *mut libc::c_char;

        let result = unsafe { libc::ioctl(self.0, request, &mut entry as *mut RtEntry) };
        if result < 0 {
            return Err(RouteError::Ioctl {
                action: if request == SIOCADDRT {
                    "add"
                } else {
                    "remove"
                },
                destination: destination.network,
                prefix: destination.prefix,
                device: device.to_string_lossy().into_owned(),
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

impl Drop for RouteSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// `struct rtentry` as glibc defines it, so `repr(C)` gives the kernel the
/// layout it expects.
#[repr(C)]
struct RtEntry {
    rt_pad1: libc::c_ulong,
    rt_dst: libc::sockaddr,
    rt_gateway: libc::sockaddr,
    rt_genmask: libc::sockaddr,
    rt_flags: libc::c_ushort,
    rt_pad2: libc::c_short,
    rt_pad3: libc::c_ulong,
    rt_tos: libc::c_uchar,
    rt_class: libc::c_uchar,
    rt_pad4: [libc::c_short; 3],
    rt_metric: libc::c_ushort,
    rt_dev: *mut libc::c_char,
    rt_mtu: libc::c_ulong,
    rt_window: libc::c_ulong,
    rt_irtt: libc::c_ushort,
}

impl Default for RtEntry {
    fn default() -> Self {
        Self {
            rt_pad1: 0,
            rt_dst: sockaddr_zero(),
            rt_gateway: sockaddr_zero(),
            rt_genmask: sockaddr_zero(),
            rt_flags: 0,
            rt_pad2: 0,
            rt_pad3: 0,
            rt_tos: 0,
            rt_class: 0,
            rt_pad4: [0; 3],
            rt_metric: 0,
            rt_dev: std::ptr::null_mut(),
            rt_mtu: 0,
            rt_window: 0,
            rt_irtt: 0,
        }
    }
}

impl RtEntry {
    fn set_sockaddr(slot: &mut libc::sockaddr, address: Ipv4Addr) {
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        // `s_addr` is the address in network byte order; writing the octets
        // natively places them in memory in exactly that order.
        sin.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &sin as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            )
        };
        let target = unsafe {
            std::slice::from_raw_parts_mut(
                slot as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr>(),
            )
        };
        target.copy_from_slice(bytes);
    }
}

fn sockaddr_zero() -> libc::sockaddr {
    unsafe { std::mem::zeroed() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_route_is_recognised_and_refused() {
        let d = Destination::parse("0.0.0.0/0").unwrap();
        assert!(d.is_default(), "0.0.0.0/0 is the default route");
        // And installing one is refused outright, before any syscall.
        let error = Ipv4Route::add(d, "lo").expect_err("must refuse the default route");
        assert!(matches!(
            error,
            RouteError::Destination(imperium_net_mesh::DestinationError::InvalidPrefix {
                prefix: 0,
                ..
            })
        ));
    }

    #[test]
    fn the_guard_reports_an_untouched_default_route_when_empty() {
        let guard = RouteGuard::new();
        assert!(guard.is_empty());
        assert!(guard.default_route_untouched());
    }

    #[test]
    fn rtentry_has_the_kernel_layout() {
        // glibc's struct rtentry is 120 bytes on x86_64. If this ever changes,
        // the ioctl would be handed a struct the kernel misreads, so assert it.
        if std::mem::size_of::<libc::c_ulong>() == 8 {
            assert_eq!(std::mem::size_of::<RtEntry>(), 120);
        }
        assert_eq!(std::mem::size_of::<libc::sockaddr>(), 16);
    }

    #[test]
    fn sockaddr_encoding_places_octets_in_network_order() {
        let mut slot = sockaddr_zero();
        RtEntry::set_sockaddr(&mut slot, Ipv4Addr::new(10, 88, 0, 0));
        let bytes = unsafe { std::slice::from_raw_parts(&slot as *const _ as *const u8, 16) };
        assert_eq!(&bytes[..2], &(libc::AF_INET as u16).to_ne_bytes());
        assert_eq!(&bytes[4..8], &[10, 88, 0, 0]);
    }

    /// Requires CAP_NET_ADMIN. Run inside an unprivileged user namespace, or as
    /// root: `mesh-privileged route-test`.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN to install a route"]
    fn install_and_remove_a_route_on_loopback() {
        let destination = Destination::parse("198.51.100.0/24").unwrap();
        let mut guard = RouteGuard::new();
        guard
            .install(destination, "lo")
            .expect("install route on loopback");
        assert_eq!(guard.len(), 1);
        assert!(guard.default_route_untouched());
        // Installing twice must not fail: `add` removes any leftover first.
        guard
            .install(destination, "lo")
            .expect("re-install is idempotent");
        assert_eq!(guard.len(), 2);
        guard.remove_all();
        assert!(guard.is_empty());
    }
}
