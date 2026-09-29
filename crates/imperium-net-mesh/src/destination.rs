//! A destination prefix: what a peer is responsible for.
//!
//! Lives in the mesh crate rather than the host crate because "which prefixes
//! does this peer serve" is a property of the peer, and it is what decides
//! which peer a packet goes to. Installing the route is a host concern and
//! lives in `imperium-net-host`; the prefix itself is not.
//!
//! The type is pure — no I/O, no syscalls — so it is testable everywhere.

use std::net::Ipv4Addr;

/// A destination prefix to reach through a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destination {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DestinationError {
    #[error("invalid CIDR {0:?}: expected an address and prefix, e.g. 10.88.0.0/24")]
    InvalidCidr(String),
    #[error("invalid prefix length {prefix} for {address}")]
    InvalidPrefix { address: Ipv4Addr, prefix: u8 },
}

impl Destination {
    /// Parse `a.b.c.d/prefix`, e.g. `10.88.0.0/24` or `10.88.0.7/32`.
    ///
    /// The network is masked to the prefix, so `10.88.0.7/24` becomes
    /// `10.88.0.0/24` rather than silently installing something the kernel
    /// would reject.
    pub fn parse(text: &str) -> Result<Self, DestinationError> {
        let (address, prefix) = text
            .split_once('/')
            .ok_or_else(|| DestinationError::InvalidCidr(text.to_string()))?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| DestinationError::InvalidCidr(text.to_string()))?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| DestinationError::InvalidCidr(text.to_string()))?;
        if prefix > 32 {
            return Err(DestinationError::InvalidPrefix { address, prefix });
        }
        Ok(Self {
            network: mask(address, prefix),
            prefix,
        })
    }

    /// The netmask as an address, for `rt_genmask`.
    ///
    /// Returns the mask itself, not an address masked by it. Returning
    /// `0.0.0.0` here would be read by the kernel as "matches everything",
    /// which is a default route in all but name.
    pub fn netmask(&self) -> Ipv4Addr {
        if self.prefix == 0 {
            return Ipv4Addr::UNSPECIFIED;
        }
        let mask = if self.prefix >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.prefix)
        };
        Ipv4Addr::from(mask.to_be_bytes())
    }

    /// Whether this is a single host route, which needs `RTF_HOST`.
    pub fn is_host(&self) -> bool {
        self.prefix == 32
    }

    /// Whether this is a default route. Refused by everything that installs
    /// routes: routing everything through one peer is a different feature with
    /// a different failure mode.
    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }

    /// Whether `address` falls inside this prefix.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        mask(address, self.prefix) == self.network
    }
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Mask `address` to `prefix` bits.
pub fn mask(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let bits = u32::from_be_bytes(address.octets());
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from((bits & mask).to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_masks_to_the_prefix() {
        let d = Destination::parse("10.88.0.0/24").unwrap();
        assert_eq!(d.network, Ipv4Addr::new(10, 88, 0, 0));
        assert_eq!(d.prefix, 24);
        assert_eq!(d.netmask(), Ipv4Addr::new(255, 255, 255, 0));

        // A host inside the range is masked to the network, not kept raw.
        let d = Destination::parse("10.88.0.7/24").unwrap();
        assert_eq!(d.network, Ipv4Addr::new(10, 88, 0, 0));

        let d = Destination::parse("10.88.0.7/32").unwrap();
        assert_eq!(d.network, Ipv4Addr::new(10, 88, 0, 7));
        assert!(d.is_host());
    }

    #[test]
    fn malformed_cidrs_are_refused() {
        for bad in [
            "10.88.0.0",
            "10.88.0.0/",
            "/24",
            "not an address/24",
            "10.88.0.0/33",
        ] {
            assert!(Destination::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn the_netmask_is_never_zero_for_a_real_prefix() {
        for prefix in 1..=32u8 {
            let d = Destination {
                network: Ipv4Addr::new(10, 88, 0, 0),
                prefix,
            };
            assert_ne!(
                d.netmask(),
                Ipv4Addr::UNSPECIFIED,
                "prefix /{prefix} produced a zero netmask"
            );
        }
        let cases = [
            (1u8, [128, 0, 0, 0]),
            (8, [255, 0, 0, 0]),
            (24, [255, 255, 255, 0]),
            (30, [255, 255, 255, 252]),
            (32, [255, 255, 255, 255]),
        ];
        for (prefix, expected) in cases {
            let d = Destination {
                network: Ipv4Addr::UNSPECIFIED,
                prefix,
            };
            assert_eq!(d.netmask(), Ipv4Addr::from(expected), "prefix /{prefix}");
        }
    }

    #[test]
    fn containment_matches_the_prefix_not_the_string() {
        let d = Destination::parse("10.88.0.0/24").unwrap();
        assert!(d.contains(Ipv4Addr::new(10, 88, 0, 1)));
        assert!(d.contains(Ipv4Addr::new(10, 88, 0, 255)));
        assert!(!d.contains(Ipv4Addr::new(10, 88, 1, 0)));
        assert!(!d.contains(Ipv4Addr::new(10, 87, 255, 255)));

        // A /32 contains exactly one address.
        let host = Destination::parse("10.88.0.7/32").unwrap();
        assert!(host.contains(Ipv4Addr::new(10, 88, 0, 7)));
        assert!(!host.contains(Ipv4Addr::new(10, 88, 0, 8)));

        // A /0 contains everything, which is why it is refused elsewhere.
        let all = Destination::parse("0.0.0.0/0").unwrap();
        assert!(all.is_default());
        assert!(all.contains(Ipv4Addr::new(203, 0, 113, 9)));
    }

    #[test]
    fn overlapping_prefixes_are_distinguishable_by_length() {
        // The two prefixes a peer-selection search must order correctly.
        let wide = Destination::parse("10.0.0.0/8").unwrap();
        let narrow = Destination::parse("10.88.0.0/16").unwrap();
        let address = Ipv4Addr::new(10, 88, 4, 4);
        assert!(wide.contains(address));
        assert!(narrow.contains(address));
        assert!(
            narrow.prefix > wide.prefix,
            "the narrower prefix must win the longest-match search"
        );
    }
}
