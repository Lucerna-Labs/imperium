//! CONSOLIDATE-1 (path-lightcone/CONSOLIDATE-1-PRECOMMIT.md), door two: **self versus non-self**
//! (borrowed from immunology). For a packet door one did not admit, read whether the machine
//! itself explains it, by identity, never by timing:
//!
//! * `OwnAddress` — outbound, the source is one of this host's own addresses, and the path
//!   matches a trained path everywhere except that source address;
//! * `AuthenticatedTunnel` — inbound on a TUN interface (only the mesh writes there, after the
//!   AEAD authenticates the peer), and the path matches a trained path everywhere except its
//!   source address;
//! * `Unexplained` — anything else: novelty in a port, destination or protocol, or anything that
//!   arrived on a physical link (including a spoof of this host's own address).
//!
//! It is a reading; whether to consolidate is the orchestrator's.

use path_sense::{Path, F_SRC};
use path_world::World;
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cause {
    OwnAddress,
    AuthenticatedTunnel,
    Unexplained,
}

/// What the host knows about itself in one episode, read from its own kernel.
#[derive(Clone, Debug, Default)]
pub struct SelfReadings {
    /// Every address on this host's interfaces (path value form).
    pub own_addresses: HashSet<u128>,
    /// Interface indexes of TUN devices.
    pub tunnels: HashSet<u32>,
}

/// The cause of one judged packet. `hook`: the netfilter hook it was held at (3/4 outbound);
/// `in_if`: its input interface index.
pub fn cause(path: &Path, hook: u8, in_if: u32, readings: &SelfReadings, allow: &World) -> Cause {
    let Some(src_at) = path.iter().position(|s| s.field == F_SRC) else { return Cause::Unexplained };
    let explained = allow.matches_except(path, &[src_at]);
    let outbound = matches!(hook, 3 | 4);
    if outbound && readings.own_addresses.contains(&path[src_at].value) && explained {
        Cause::OwnAddress
    } else if !outbound && readings.tunnels.contains(&in_if) && explained {
        Cause::AuthenticatedTunnel
    } else {
        Cause::Unexplained
    }
}

/// CONSOLIDATE-1 / door two: the self/non-self law with identity supplied by the **channel**, the
/// cleanest in-repo signal. `inbound_authenticated` means the caller vouches this inbound packet
/// arrived through an already-authenticated channel (e.g. a decapsulated tunnel packet, post-AEAD)
/// — a signal an outside attacker cannot forge. A drop is self only when the path matches a trained
/// path everywhere except its source and either it is outbound from one of the host's own
/// addresses, or it is inbound through that authenticated channel.
pub fn cause_vouched(
    path: &Path,
    outbound: bool,
    own_addresses: &HashSet<u128>,
    inbound_authenticated: bool,
    allow: &World,
) -> Cause {
    let Some(src_at) = path.iter().position(|s| s.field == F_SRC) else { return Cause::Unexplained };
    if !allow.matches_except(path, &[src_at]) {
        return Cause::Unexplained;
    }
    if outbound && own_addresses.contains(&path[src_at].value) {
        Cause::OwnAddress
    } else if !outbound && inbound_authenticated {
        Cause::AuthenticatedTunnel
    } else {
        Cause::Unexplained
    }
}

#[cfg(test)]
mod vouched_tests {
    use super::*;
    use path_sense::Sym;

    fn p(dir: u128, src: u128, dport: u128) -> Path {
        [(0u8, dir), (1, 0x0800), (2, 17), (3, src), (4, 0xc633_6402), (5, 51000), (6, dport)].iter().map(|&(f, v)| Sym { field: f, value: v }).collect()
    }

    #[test]
    fn channel_identity_classifies_self_and_refuses_forgery() {
        let own = 0xc000_0202u128;
        let allow = World::train(&[p(0, 0xc000_0201, 45998), p(1, own, 45998)]);
        let owns: HashSet<u128> = [own].into_iter().collect();
        // Inbound through the authenticated channel, novel source, trained otherwise: self.
        assert_eq!(cause_vouched(&p(0, 0xdead, 45998), false, &owns, true, &allow), Cause::AuthenticatedTunnel);
        // Same shape but NOT vouched (e.g. an un-authenticated inbound datagram): unexplained.
        assert_eq!(cause_vouched(&p(0, 0xdead, 45998), false, &owns, false, &allow), Cause::Unexplained);
        // Outbound from our own address: self.
        assert_eq!(cause_vouched(&p(1, own, 45998), true, &owns, false, &allow), Cause::OwnAddress);
        // Novelty beyond the source, even vouched: unexplained.
        assert_eq!(cause_vouched(&p(0, 0xdead, 45996), false, &owns, true, &allow), Cause::Unexplained);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use path_sense::Sym;

    fn mld(dir: u128, src: u128) -> Path {
        [(0, dir), (1, 0x86dd), (2, 0), (3, src), (4, 0xff02_0000_0000_0000_0000_0000_0000_0016)].iter().map(|&(field, value)| Sym { field, value }).collect()
    }

    #[test]
    fn identity_explains_only_novel_self_sources() {
        let old_id = 0xfe80_0000_0000_0000_215b_c6fd_0250_bb56;
        let fresh = 0xfe80_0000_0000_0000_d3a3_71b3_3d62_7939;
        let allow = World::train(&[mld(1, old_id), mld(0, old_id)]);
        let mut r = SelfReadings::default();
        r.own_addresses.insert(fresh);
        r.tunnels.insert(7);
        assert_eq!(cause(&mld(1, fresh), 3, 0, &r, &allow), Cause::OwnAddress);
        assert_eq!(cause(&mld(1, 0xfe80_0bad), 3, 0, &r, &allow), Cause::Unexplained, "not our address");
        assert_eq!(cause(&mld(0, 0xfe80_0bad), 0, 7, &r, &allow), Cause::AuthenticatedTunnel);
        assert_eq!(cause(&mld(0, fresh), 0, 2, &r, &allow), Cause::Unexplained, "our own address arriving on a physical link is a spoof");
        let mut novel = mld(1, fresh);
        novel[4].value = 0xff02_0000_0000_0000_0000_0000_0000_0099;
        assert_eq!(cause(&novel, 3, 0, &r, &allow), Cause::Unexplained, "novelty beyond the address");
    }
}
