//! Exact kernel-held IP packets. Queue loss stays closed when nft has no bypass.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::queue_wire::{self as wire, HeldPacket};

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub enum KernelDisposition {
    Discard = 0,
    Release = 1,
}

pub struct PacketQueue {
    owner: u64,
    fd: OwnedFd,
    queue: u16,
    sequence: u32,
    pending: VecDeque<HeldPacket>,
    outstanding: std::collections::HashSet<u32>,
}

impl PacketQueue {
    pub fn bind(queue: u16, capacity: u32) -> io::Result<Self> {
        if queue == 0 || capacity == 0 || capacity > 4096 {
            return Err(wire::invalid("queue number/capacity out of bounds"));
        }
        // SAFETY: socket creates a fresh descriptor; failure is checked before ownership.
        let raw =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 12) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a new descriptor owned exclusively by this instance.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: zero is a valid sockaddr_nl initial representation; family is set below.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: address and its exact size are valid for the duration of bind.
        if unsafe {
            libc::bind(
                raw,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let receive_buffer: libc::c_int = 4 * 1024 * 1024;
        // SAFETY: passes a live descriptor and correctly sized integer option.
        if unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&receive_buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&receive_buffer) as u32,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut reader = Self {
            owner: NEXT_OWNER
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| wire::invalid("queue owner identity exhausted"))?,
            fd,
            queue,
            sequence: 0,
            pending: VecDeque::new(),
            outstanding: Default::default(),
        };
        let mut command = Vec::new();
        wire::attribute(1, &[1, 0, 0, 0], &mut command); // bind this queue, never unbind other readers
        reader.request(wire::CONFIG, &command)?;
        let mut settings = Vec::new();
        let mut copy = 65_535u32.to_be_bytes().to_vec();
        copy.push(2); // COPY_PACKET
        wire::attribute(2, &copy, &mut settings);
        wire::attribute(3, &capacity.to_be_bytes(), &mut settings);
        wire::attribute(4, &5u32.to_be_bytes(), &mut settings); // mask FAIL_OPEN | GSO
        wire::attribute(5, &4u32.to_be_bytes(), &mut settings); // GSO only; never fail-open
        reader.request(wire::CONFIG, &settings)?;
        Ok(reader)
    }

    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        // SAFETY: zero is a valid sockaddr_nl initialization; destination is kernel PID 0.
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: buffers/address live for the syscall and sizes match their allocations.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        };
        if sent < 0 {
            Err(io::Error::last_os_error())
        } else if sent as usize != bytes.len() {
            Err(wire::invalid("short netlink send"))
        } else {
            Ok(())
        }
    }

    fn datagram(&self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        let mut descriptor = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is valid and unique; timeout is bounded to c_int.
        let ready = unsafe {
            libc::poll(
                &mut descriptor,
                1,
                timeout.as_millis().min(i32::MAX as u128) as i32,
            )
        };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            return Ok(None);
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(wire::invalid("kernel queue socket error"));
        }
        let mut bytes = vec![0u8; 131_072];
        // SAFETY: zeroed sockaddr_nl is initialized by recvfrom and checked below.
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&sender) as libc::socklen_t;
        // SAFETY: the kernel writes only into the allocated buffers; MSG_TRUNC detects oversize.
        let length = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_TRUNC,
                (&mut sender as *mut libc::sockaddr_nl).cast(),
                &mut size,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize > bytes.len()
            || size as usize != std::mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as u16
            || sender.nl_pid != 0
            || sender.nl_groups != 0
        {
            return Err(wire::invalid("truncated or non-kernel netlink datagram"));
        }
        bytes.truncate(length as usize);
        Ok(Some(bytes))
    }

    fn remember(&mut self, mut packet: HeldPacket) -> io::Result<()> {
        if self.outstanding.len() >= 4096 || !self.outstanding.insert(packet.id) {
            return Err(wire::invalid("queue capacity or duplicate packet ID"));
        }
        packet.owner = self.owner;
        self.pending.push_back(packet);
        Ok(())
    }

    fn request(&mut self, kind: u16, attributes: &[u8]) -> io::Result<()> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| wire::invalid("queue sequence exhausted"))?;
        let sequence = self.sequence;
        self.send(&wire::envelope(kind, sequence, self.queue, attributes))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "kernel queue acknowledgement timeout",
                ));
            }
            let Some(bytes) = self.datagram(remaining)? else {
                continue;
            };
            let mut acknowledged = false;
            for message in wire::messages(&bytes)? {
                if message.kind == wire::PACKET {
                    self.remember(wire::packet(message.body, self.queue)?)?;
                } else if message.kind == 2 && message.sequence == sequence {
                    wire::ack(&message)?;
                    acknowledged = true;
                } else {
                    return Err(wire::invalid("unexpected netlink message/acknowledgement"));
                }
            }
            if acknowledged {
                return Ok(());
            }
        }
    }

    pub fn receive(&mut self, timeout: Duration) -> io::Result<Option<HeldPacket>> {
        if let Some(packet) = self.pending.pop_front() {
            return Ok(Some(packet));
        }
        let Some(bytes) = self.datagram(timeout)? else {
            return Ok(None);
        };
        for message in wire::messages(&bytes)? {
            if message.kind != wire::PACKET {
                return Err(wire::invalid("unexpected queue message"));
            }
            self.remember(wire::packet(message.body, self.queue)?)?;
        }
        Ok(self.pending.pop_front())
    }

    /// Consumes the exact held packet once. This OS operation owns no causal judgment.
    pub fn finish(&mut self, packet: HeldPacket, disposition: KernelDisposition) -> io::Result<()> {
        if packet.owner != self.owner
            || packet.queue != self.queue
            || !self.outstanding.contains(&packet.id)
        {
            return Err(wire::invalid("unowned held packet"));
        }
        let mut value = (disposition as u32).to_be_bytes().to_vec();
        value.extend_from_slice(&packet.id.to_be_bytes());
        let mut attributes = Vec::new();
        wire::attribute(2, &value, &mut attributes);
        self.request(wire::VERDICT, &attributes)?;
        self.outstanding.remove(&packet.id);
        Ok(())
    }
}
