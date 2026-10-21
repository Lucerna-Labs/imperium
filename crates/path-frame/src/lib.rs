//! PATHGATE adapter (path-lightcone/PATHGATE-1-PRECOMMIT.md). The kernel queue hands over a bare IP
//! packet (no link header) and the netfilter hook it was held at. `path-sense` reads Linux cooked
//! captures (SLL2), so the adapter puts a 20-byte SLL2 shim in front: the EtherType from the IP
//! version nibble, the rest zero (sense reads nothing else of it). Direction: held at OUTPUT (3) or
//! POSTROUTING (4) is outbound; PREROUTING (0), INPUT (1) and FORWARD (2) are inbound.

use path_sense::{sense, Path, Sym, F_DIR, F_DPORT, F_DST, F_L4, F_LINK, F_SPORT, F_SRC};
use std::net::{IpAddr, SocketAddr};

/// The SLL2-shimmed frame of a bare IP packet, or None when it is not IPv4/IPv6.
pub fn shim(ip: &[u8]) -> Option<Vec<u8>> {
    let ether: u16 = match ip.first()? >> 4 {
        4 => 0x0800,
        6 => 0x86dd,
        _ => return None,
    };
    let mut f = Vec::with_capacity(20 + ip.len());
    f.extend_from_slice(&ether.to_be_bytes());
    f.extend_from_slice(&[0u8; 18]);
    f.extend_from_slice(ip);
    Some(f)
}

/// The path of a kernel-held packet.
pub fn held_path(ip: &[u8], hook: u8) -> Option<Path> {
    sense(&shim(ip)?, matches!(hook, 3 | 4))
}

/// The path of an Ethernet II frame (EtherType at bytes 12..14, payload from 14).
pub fn ethernet_path(frame: &[u8], outbound: bool) -> Option<Path> {
    if frame.len() < 14 {
        return None;
    }
    let mut f = Vec::with_capacity(20 + frame.len() - 14);
    f.extend_from_slice(&frame[12..14]);
    f.extend_from_slice(&[0u8; 18]);
    f.extend_from_slice(&frame[14..]);
    sense(&f, outbound)
}

fn ip_value(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u32::from(a) as u128,
        IpAddr::V6(a) => u128::from(a),
    }
}

/// The path of a UDP datagram known only by its socket addresses (an application's own datagram,
/// read without its IP header): the same symbols `sense` gives the captured packet. `None` when
/// the two addresses are of different families or the local address is unspecified.
pub fn socket_path(outbound: bool, local: SocketAddr, peer: SocketAddr) -> Option<Path> {
    let link: u128 = match (local.ip(), peer.ip()) {
        (IpAddr::V4(_), IpAddr::V4(_)) => 0x0800,
        (IpAddr::V6(_), IpAddr::V6(_)) => 0x86dd,
        _ => return None,
    };
    if local.ip().is_unspecified() {
        return None;
    }
    let (src, dst) = if outbound { (local, peer) } else { (peer, local) };
    let s = |field, value| Sym { field, value };
    Some(vec![
        s(F_DIR, outbound as u128),
        s(F_LINK, link),
        s(F_L4, 17),
        s(F_SRC, ip_value(src.ip())),
        s(F_DST, ip_value(dst.ip())),
        s(F_SPORT, src.port() as u128),
        s(F_DPORT, dst.port() as u128),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shim_matches_a_captured_frame() {
        let mut ip = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        ip.extend_from_slice(&[0x13, 0x88, 0xb3, 0xaf, 0, 8, 0, 0]);
        let mut captured = vec![0x08, 0x00];
        captured.extend_from_slice(&[7u8; 18]); // other SLL2 header bytes differ; sense ignores them
        captured.extend_from_slice(&ip);
        assert_eq!(held_path(&ip, 0), sense(&captured, false));
        assert_eq!(held_path(&ip, 3), sense(&captured, true));
        assert!(held_path(&[0x15, 0, 0], 0).is_none());
        // The same packet as an Ethernet frame, and as a socket datagram.
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        assert_eq!(ethernet_path(&eth, false), sense(&captured, false));
        let local: SocketAddr = "10.0.0.2:45999".parse().unwrap();
        let peer: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        assert_eq!(socket_path(false, local, peer), sense(&captured, false));
        assert!(socket_path(false, "0.0.0.0:45999".parse().unwrap(), peer).is_none());
        assert!(socket_path(false, "[::1]:1".parse().unwrap(), peer).is_none());
    }
}
