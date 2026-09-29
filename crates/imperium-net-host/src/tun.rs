//! A Linux TUN device, created and configured with `ioctl`.
//!
//! Deliberately dependency-light: `TUNSETIFF`, `SIOCSIFMTU`, `SIOCSIFADDR`,
//! `SIOCSIFNETMASK` and `SIOCSIFFLAGS` are all plain `ioctl` calls, so no
//! netlink crate is needed. This keeps the privileged, `unsafe` surface inside
//! one file in one crate, out of the portable mesh transport.
//!
//! Creating the device requires `CAP_NET_ADMIN` (in practice: root). Every
//! failure here is returned, never panicked, because the common failure is
//! simply "you are not root".

use std::ffi::CString;
use std::fmt;
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;

/// `ioctl` request type differs between glibc and musl.
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = libc::c_ulong;

const IFNAMSIZ: usize = 16;
/// `struct ifreq` is 16 (name) + 24 (union) on Linux.
const IFREQ_LEN: usize = 40;

const IFF_TUN: libc::c_short = 0x0001;
/// No packet-info header: the device carries bare IP packets.
const IFF_NO_PI: libc::c_short = 0x1000;
const IFF_UP: libc::c_short = 0x1;
const IFF_RUNNING: libc::c_short = 0x40;

const TUNSETIFF: IoctlRequest = 0x4004_54ca;
const SIOCSIFMTU: IoctlRequest = 0x8922;
const SIOCSIFFLAGS: IoctlRequest = 0x8914;
const SIOCSIFADDR: IoctlRequest = 0x8916;
const SIOCSIFNETMASK: IoctlRequest = 0x891c;

#[derive(Debug, Error)]
pub enum TunError {
    #[error("cannot open /dev/net/tun: {0} (is the tun module loaded and are you root?)")]
    Open(io::Error),
    #[error("interface name {0:?} is too long (max {max} characters)", max = IFNAMSIZ - 1)]
    NameTooLong(String),
    #[error("interface name contains a NUL byte")]
    NameInvalid,
    #[error("TUNSETIFF failed: {0} (CAP_NET_ADMIN / root is required)")]
    Create(io::Error),
    #[error("interface configuration failed: {0}")]
    Configure(io::Error),
    #[error("no free interface name available")]
    NoFreeName,
}

/// A configured, up TUN interface.
///
/// The device is non-persistent: dropping it (or closing the fd) destroys the
/// interface, which is why the address and MTU are applied here rather than
/// left to an external script.
pub struct TunDevice {
    fd: RawFd,
    name: String,
    mtu: u32,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    nonblocking: AtomicBool,
}

impl fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunDevice")
            .field("name", &self.name)
            .field("mtu", &self.mtu)
            .field("address", &self.address)
            .field("netmask", &self.netmask)
            .finish()
    }
}

impl TunDevice {
    /// Create a TUN interface named `name` (or `name0`, `name1`, … if taken),
    /// assign `address/netmask`, set `mtu`, and bring it up.
    pub fn create(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u32,
    ) -> Result<Self, TunError> {
        let mut last_error = None;
        // `TUNSETIFF` with an existing name either attaches to an existing
        // interface or fails; trying suffixed names makes repeated runs work.
        for candidate in candidate_names(name) {
            match Self::create_named(&candidate, address, netmask, mtu) {
                Ok(device) => return Ok(device),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(TunError::NoFreeName))
    }

    fn create_named(
        name: &str,
        address: Ipv4Addr,
        netmask: Ipv4Addr,
        mtu: u32,
    ) -> Result<Self, TunError> {
        let path = CString::new("/dev/net/tun").expect("static path has no NUL");
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(TunError::Open(io::Error::last_os_error()));
        }

        let mut request = IfReq::new(name)?;
        request.set_flags(IFF_TUN | IFF_NO_PI);
        if let Err(error) = ioctl_ifreq(fd, TUNSETIFF, &mut request) {
            unsafe { libc::close(fd) };
            return Err(TunError::Create(error));
        }
        // The kernel echoes the interface actually attached.
        let actual_name = request.name_string();

        // Interface configuration goes through an AF_INET socket, not the tun fd.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if sock < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TunError::Configure(error));
        }

        let result = (|| -> Result<(), TunError> {
            // Address first, then netmask, so the kernel creates the
            // connected route with the right prefix.
            let mut req = IfReq::new(&actual_name)?;
            req.set_sockaddr_in(address);
            ioctl_ifreq(sock, SIOCSIFADDR, &mut req).map_err(TunError::Configure)?;

            let mut req = IfReq::new(&actual_name)?;
            req.set_sockaddr_in(netmask);
            ioctl_ifreq(sock, SIOCSIFNETMASK, &mut req).map_err(TunError::Configure)?;

            let mut req = IfReq::new(&actual_name)?;
            req.set_mtu(mtu);
            ioctl_ifreq(sock, SIOCSIFMTU, &mut req).map_err(TunError::Configure)?;

            // Bring up last: the interface comes up already addressed.
            let mut req = IfReq::new(&actual_name)?;
            req.set_flags(IFF_UP | IFF_RUNNING);
            ioctl_ifreq(sock, SIOCSIFFLAGS, &mut req).map_err(TunError::Configure)?;
            Ok(())
        })();

        unsafe { libc::close(sock) };
        if let Err(error) = result {
            unsafe { libc::close(fd) };
            return Err(error);
        }

        Ok(Self {
            fd,
            name: actual_name,
            mtu,
            address,
            netmask,
            nonblocking: AtomicBool::new(false),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    pub fn netmask(&self) -> Ipv4Addr {
        self.netmask
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Switch the fd between blocking and non-blocking reads.
    ///
    /// The bridge needs non-blocking (it drives the fd through
    /// `AsyncFd`); a blocking reader is more convenient for a smoke test.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let updated = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, updated) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
        Ok(())
    }

    pub fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // Closing the fd tears the interface down.
        unsafe { libc::close(self.fd) };
    }
}

impl std::os::unix::io::AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Candidate interface names, so a second run on a host where the first
/// interface still exists can still succeed.
fn candidate_names(base: &str) -> Vec<String> {
    // Linux interface names are limited to 15 characters.
    let base: String = base.chars().take(IFNAMSIZ - 2).collect();
    let mut names = vec![base.clone()];
    for suffix in 0..8 {
        names.push(format!("{base}{suffix}"));
    }
    names
}

/// `struct ifreq` with its anonymous union flattened into a plain buffer.
#[repr(C)]
struct IfReq {
    name: [libc::c_char; IFNAMSIZ],
    data: [u8; IFREQ_LEN - IFNAMSIZ],
}

impl IfReq {
    fn new(name: &str) -> Result<Self, TunError> {
        if name.contains('\0') {
            return Err(TunError::NameInvalid);
        }
        if name.len() >= IFNAMSIZ {
            return Err(TunError::NameTooLong(name.to_string()));
        }
        let mut ifr = Self {
            name: [0; IFNAMSIZ],
            data: [0; IFREQ_LEN - IFNAMSIZ],
        };
        for (slot, byte) in ifr.name.iter_mut().zip(name.as_bytes()) {
            *slot = *byte as libc::c_char;
        }
        Ok(ifr)
    }

    fn name_string(&self) -> String {
        let bytes: Vec<u8> = self
            .name
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn set_mtu(&mut self, mtu: u32) {
        let mtu = mtu as i32;
        self.data[..4].copy_from_slice(&mtu.to_ne_bytes());
    }

    fn set_flags(&mut self, flags: libc::c_short) {
        self.data[..2].copy_from_slice(&flags.to_ne_bytes());
    }

    fn set_sockaddr_in(&mut self, address: Ipv4Addr) {
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_family = libc::AF_INET as libc::sa_family_t;
        // `s_addr` holds the address in network byte order; writing the octets
        // natively puts them in memory in exactly that order.
        sin.sin_addr.s_addr = u32::from_ne_bytes(address.octets());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &sin as *const _ as *const u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            )
        };
        let len = bytes.len().min(self.data.len());
        self.data[..len].copy_from_slice(&bytes[..len]);
    }
}

fn ioctl_ifreq(fd: RawFd, request: IoctlRequest, ifr: &mut IfReq) -> io::Result<()> {
    let result = unsafe { libc::ioctl(fd, request, ifr as *mut IfReq) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_is_the_kernel_size() {
        assert_eq!(std::mem::size_of::<IfReq>(), IFREQ_LEN);
        assert_eq!(std::mem::size_of::<libc::sockaddr_in>(), 16);
    }

    #[test]
    fn names_are_validated_before_any_syscall() {
        // 15 characters is the kernel maximum (IFNAMSIZ - 1).
        assert!(IfReq::new("fifteen-chars-x").is_ok());
        assert!(matches!(
            IfReq::new("sixteen-chars-xx"),
            Err(TunError::NameTooLong(_))
        ));
        assert!(matches!(
            IfReq::new("bad\0name"),
            Err(TunError::NameInvalid)
        ));
        assert!(IfReq::new("imperium0").is_ok());
    }

    #[test]
    fn name_round_trips_through_the_struct() {
        let ifr = IfReq::new("imp0").unwrap();
        assert_eq!(ifr.name_string(), "imp0");
    }

    #[test]
    fn sockaddr_encoding_puts_octets_in_memory_order() {
        let mut ifr = IfReq::new("imp0").unwrap();
        ifr.set_sockaddr_in(Ipv4Addr::new(10, 77, 0, 1));
        // sin_family (AF_INET = 2) then port (0) then the address octets.
        assert_eq!(&ifr.data[..2], &(libc::AF_INET as u16).to_ne_bytes());
        assert_eq!(&ifr.data[4..8], &[10, 77, 0, 1]);
    }

    #[test]
    fn candidate_names_stay_within_the_kernel_limit() {
        for name in candidate_names("imperium-tunnel") {
            assert!(name.len() < IFNAMSIZ, "{name} is too long");
        }
    }

    /// Requires root. Ignored by default so `cargo test` stays unprivileged.
    #[test]
    #[ignore = "requires CAP_NET_ADMIN (root) to create a TUN interface"]
    fn create_and_configure_a_real_tun_device() {
        let device = TunDevice::create(
            "imptest",
            Ipv4Addr::new(10, 77, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            1280,
        )
        .expect("create TUN");
        assert_eq!(device.mtu(), 1280);
        assert!(device.name().starts_with("imptest"));
        device.set_nonblocking(true).unwrap();
        assert!(device.is_nonblocking());
    }
}
