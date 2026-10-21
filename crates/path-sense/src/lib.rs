//! PATHCONE (path-lightcone/PATHCONE-1-PRECOMMIT.md): the sensor. A captured frame (Linux cooked
//! capture v2, SLL2: a 20-byte header whose first two bytes are the EtherType) plus its direction
//! becomes its **path**: the ordered structural symbols a packet presents — direction, link type,
//! L4 protocol, source and destination address, source and destination port, TCP flag set, ICMP
//! type/code, or for ARP the operation and the two protocol addresses. Payload bytes are never
//! read. A frame that cannot be parsed has no path (and so, at the gate, no pass).

pub const F_DIR: u8 = 0;
pub const F_LINK: u8 = 1;
pub const F_L4: u8 = 2;
pub const F_SRC: u8 = 3;
pub const F_DST: u8 = 4;
pub const F_SPORT: u8 = 5;
pub const F_DPORT: u8 = 6;
pub const F_TCPF: u8 = 7;
pub const F_ICMP: u8 = 8;
pub const F_ARPOP: u8 = 9;
pub const F_FRAG: u8 = 10;

/// One structural symbol: which field, and its value (addresses fit in 128 bits).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Sym {
    pub field: u8,
    pub value: u128,
}

pub type Path = Vec<Sym>;

fn sym(field: u8, value: u128) -> Sym {
    Sym { field, value }
}

fn be(b: &[u8]) -> u128 {
    b.iter().fold(0u128, |a, &x| (a << 8) | x as u128)
}

/// The path of an SLL2 frame captured in direction `outbound`.
pub fn sense(frame: &[u8], outbound: bool) -> Option<Path> {
    if frame.len() < 20 {
        return None;
    }
    let ether = be(&frame[0..2]) as u16;
    let p = &frame[20..];
    let mut path = vec![sym(F_DIR, outbound as u128), sym(F_LINK, ether as u128)];
    match ether {
        0x0800 => {
            if p.len() < 20 || p[0] >> 4 != 4 {
                return None;
            }
            let ihl = (p[0] & 0x0f) as usize * 4;
            if ihl < 20 || p.len() < ihl {
                return None;
            }
            let proto = p[9];
            path.push(sym(F_L4, proto as u128));
            path.push(sym(F_SRC, be(&p[12..16])));
            path.push(sym(F_DST, be(&p[16..20])));
            let frag = be(&p[6..8]) as u16 & 0x1fff;
            if frag != 0 {
                path.push(sym(F_FRAG, 1));
                return Some(path);
            }
            transport(proto, &p[ihl..], &mut path)?;
        }
        0x86dd => {
            if p.len() < 40 || p[0] >> 4 != 6 {
                return None;
            }
            let next = p[6];
            path.push(sym(F_L4, next as u128));
            path.push(sym(F_SRC, be(&p[8..24])));
            path.push(sym(F_DST, be(&p[24..40])));
            transport(next, &p[40..], &mut path)?;
        }
        0x0806 => {
            if p.len() < 28 {
                return None;
            }
            path.push(sym(F_ARPOP, be(&p[6..8])));
            path.push(sym(F_SRC, be(&p[14..18])));
            path.push(sym(F_DST, be(&p[24..28])));
        }
        _ => {}
    }
    Some(path)
}

fn transport(proto: u8, t: &[u8], path: &mut Path) -> Option<()> {
    match proto {
        6 => {
            if t.len() < 20 {
                return None;
            }
            path.push(sym(F_SPORT, be(&t[0..2])));
            path.push(sym(F_DPORT, be(&t[2..4])));
            path.push(sym(F_TCPF, (t[13] & 0x3f) as u128));
        }
        17 => {
            if t.len() < 8 {
                return None;
            }
            path.push(sym(F_SPORT, be(&t[0..2])));
            path.push(sym(F_DPORT, be(&t[2..4])));
        }
        1 | 58 => {
            if t.len() < 4 {
                return None;
            }
            path.push(sym(F_ICMP, be(&t[0..2])));
        }
        _ => {}
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sll2(ether: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 20];
        f[0..2].copy_from_slice(&ether.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn udp4_path_and_truncation() {
        let mut ip = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        ip.extend_from_slice(&[0x13, 0x88, 0xb3, 0xaf, 0, 8, 0, 0]); // 5000 -> 45999
        let p = sense(&sll2(0x0800, &ip), false).unwrap();
        assert_eq!(p.iter().find(|s| s.field == F_DPORT).unwrap().value, 45999);
        assert_eq!(p.iter().find(|s| s.field == F_SRC).unwrap().value, 0x0a00_0001);
        assert!(sense(&sll2(0x0800, &ip[..24]), false).is_none());
        assert!(sense(&[0u8; 10], true).is_none());
    }
}
