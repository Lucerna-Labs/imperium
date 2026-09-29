//! Source-validating gate for the handshake path.
//!
//! The expensive part of accepting a Hello is a hybrid Ed25519 + ML-DSA-65
//! signature verification — multi-kilobyte key material and deep stack frames.
//! Before this gate, **any** decodable Hello from **any** address forced that
//! work: the sender controls `expires_at_unix`, so the cheap expiry rejection
//! inside `IdentityBinding::verify` is not a gate the attacker cannot lift.
//!
//! Two mechanisms, both cheap:
//!
//! 1. **A cookie.** The responder answers an ungated Hello with an HMAC over the
//!    sender's source address, and verifies nothing else. The sender must echo a
//!    MAC computed over that cookie *and* its own Hello before verification runs.
//!    That proves the sender can receive at the address it claims — which a
//!    spoofed source cannot — and it costs one HMAC instead of a post-quantum
//!    signature check.
//!
//! 2. **A per-source token bucket.** A cookie does not stop a flood from a
//!    *real* address, because a real source can complete the round trip. The
//!    bucket bounds how much verification work any one source can compel.
//!
//! Neither is authentication. Authentication remains the operator-signed
//! identity binding; this only decides who may *ask* to be authenticated.
//!
//! ## Why the MAC covers the Hello
//!
//! The gate MAC is `HMAC(cookie, hello_datagram)`, not `HMAC(cookie, "")`. A MAC
//! covering only the cookie could be lifted off one datagram and replayed on
//! another, so the gate would validate the sender's address without binding it
//! to the material being verified. Binding it means a completed round trip
//! admits exactly the Hello that was sent.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Length of the cookie the responder hands out.
pub const COOKIE_LEN: usize = 16;
/// Length of the MAC a sender echoes back.
pub const GATE_MAC_LEN: usize = 32;

/// How often the cookie secret rotates. Verification accepts the current and
/// the previous secret, so a rotation never invalidates a cookie in flight.
const ROTATE_EVERY: Duration = Duration::from_secs(60);

/// Handshake admissions one source address gets per `WINDOW`.
const BURST: f64 = 8.0;
const WINDOW_SECS: f64 = 10.0;

/// Cap on tracked source addresses. The rate limiter must not become a memory
/// exhaustion vector when an attacker sprays source addresses: stale entries are
/// pruned periodically, and crossing the cap forces an immediate prune rather
/// than growth.
const MAX_TRACKED_SOURCES: usize = 8192;

struct Bucket {
    tokens: f64,
    last: Instant,
}

struct Inner {
    secret: [u8; 32],
    previous: Option<[u8; 32]>,
    rotated_at: Instant,
    buckets: HashMap<IpAddr, Bucket>,
    last_prune: Instant,
}

/// The gate. One per daemon; holds its own random secret, so a cookie minted by
/// one node is meaningless to another.
pub struct HandshakeGate {
    inner: Mutex<Inner>,
}

impl HandshakeGate {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self {
            inner: Mutex::new(Inner {
                secret,
                previous: None,
                rotated_at: Instant::now(),
                buckets: HashMap::new(),
                last_prune: Instant::now(),
            }),
        }
    }

    /// Rotate the cookie secret if the epoch has elapsed. Returns whether it
    /// rotated. Called from the daemon's tick.
    pub fn rotate_if_due(&self, now: Instant) -> bool {
        let mut inner = self.inner.lock();
        if now.duration_since(inner.rotated_at) < ROTATE_EVERY {
            return false;
        }
        let mut next = [0u8; 32];
        OsRng.fill_bytes(&mut next);
        inner.previous = Some(inner.secret);
        inner.secret = next;
        inner.rotated_at = now;
        true
    }

    /// Mint a cookie binding `source` to the current secret. One HMAC and no
    /// per-source allocation, so an attacker cannot make the responder allocate
    /// just by sending Hellos.
    pub fn cookie(&self, source: SocketAddr) -> [u8; COOKIE_LEN] {
        let inner = self.inner.lock();
        cookie_mac(&inner.secret, source)
    }

    /// Whether `cookie` is one this node minted for exactly `source`, under the
    /// current or the previous secret.
    pub fn cookie_is_mine(&self, cookie: &[u8], source: SocketAddr) -> bool {
        if cookie.len() != COOKIE_LEN {
            return false;
        }
        let inner = self.inner.lock();
        let mut ok = constant_time_eq(&cookie_mac(&inner.secret, source), cookie);
        if let Some(previous) = inner.previous {
            ok |= constant_time_eq(&cookie_mac(&previous, source), cookie);
        }
        ok
    }

    /// The MAC a sender echoes: `HMAC(cookie, hello_datagram)`.
    pub fn mac_for(cookie: &[u8], hello_datagram: &[u8]) -> [u8; GATE_MAC_LEN] {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(cookie).expect("HMAC accepts a key of any length");
        mac.update(hello_datagram);
        mac.finalize().into_bytes().into()
    }

    /// Whether a returned MAC is the right one for this cookie and this Hello.
    pub fn mac_is_valid(cookie: &[u8], hello_datagram: &[u8], claimed: &[u8]) -> bool {
        if claimed.len() != GATE_MAC_LEN {
            return false;
        }
        constant_time_eq(&Self::mac_for(cookie, hello_datagram), claimed)
    }

    /// Whether `mac` is the correct gate MAC for `hello_datagram` from `source`.
    ///
    /// The cookie itself is not carried on the wire, and does not need to be:
    /// it is `HMAC(secret, source)`, so the responder recomputes it for the
    /// address the datagram arrived from. That means the gate holds **no
    /// per-handshake state at all** — nothing for an attacker to exhaust.
    ///
    /// Accepts the previous epoch's cookie as well, so a rotation does not break
    /// a handshake already in flight.
    pub fn mac_valid_for_source(
        &self,
        source: SocketAddr,
        hello_datagram: &[u8],
        mac: &[u8],
    ) -> bool {
        if mac.len() != GATE_MAC_LEN {
            return false;
        }
        let inner = self.inner.lock();
        let mut ok = Self::mac_is_valid(&cookie_mac(&inner.secret, source), hello_datagram, mac);
        if let Some(previous) = inner.previous {
            ok |= Self::mac_is_valid(&cookie_mac(&previous, source), hello_datagram, mac);
        }
        ok
    }

    /// Token bucket. `true` means this source may proceed to the full handshake
    /// path. Bounds the work a single address can compel, which the cookie
    /// cannot do on its own.
    pub fn admit(&self, source: IpAddr, now: Instant) -> bool {
        let mut inner = self.inner.lock();

        // Periodic prune: drop buckets that have refilled completely.
        if now.duration_since(inner.last_prune) >= Duration::from_secs_f64(WINDOW_SECS) {
            inner.buckets.retain(|_, bucket| {
                let elapsed = now.duration_since(bucket.last).as_secs_f64();
                bucket.tokens + elapsed * (BURST / WINDOW_SECS) < BURST
            });
            inner.last_prune = now;
        }
        // Hard bound. Pruning is not enough on its own: a spray arriving at a
        // single instant leaves every bucket un-refilled, so the retain above
        // removes nothing and the map would grow without limit. Evict the
        // stalest entries instead.
        if inner.buckets.len() >= MAX_TRACKED_SOURCES {
            evict_stalest(&mut inner.buckets, MAX_TRACKED_SOURCES / 2);
        }

        let bucket = inner.buckets.entry(source).or_insert_with(|| Bucket {
            tokens: BURST,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * (BURST / WINDOW_SECS)).min(BURST);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Number of source addresses currently tracked. Exposed so a test can prove
    /// the limiter stays bounded under a source spray.
    pub fn tracked_sources(&self) -> usize {
        self.inner.lock().buckets.len()
    }
}

impl Default for HandshakeGate {
    fn default() -> Self {
        Self::new()
    }
}

fn cookie_mac(secret: &[u8; 32], source: SocketAddr) -> [u8; COOKIE_LEN] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(secret).expect("HMAC accepts a key of any length");
    match source.ip() {
        IpAddr::V4(v4) => mac.update(&v4.octets()),
        IpAddr::V6(v6) => mac.update(&v6.octets()),
    }
    // The port too: a cookie is bound to the exact endpoint, so it cannot be
    // replayed from the same host on a different port.
    mac.update(&source.port().to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; COOKIE_LEN];
    out.copy_from_slice(&full[..COOKIE_LEN]);
    out
}

/// Remove entries until the map is at or below `target`, dropping the ones
/// whose buckets were touched longest ago.
fn evict_stalest(buckets: &mut HashMap<IpAddr, Bucket>, target: usize) {
    if buckets.len() <= target {
        return;
    }
    let mut ages: Vec<(IpAddr, Instant)> = buckets
        .iter()
        .map(|(ip, bucket)| (*ip, bucket.last))
        .collect();
    ages.sort_by_key(|(_, last)| *last);
    let remove = ages.len() - target;
    for (ip, _) in ages.into_iter().take(remove) {
        buckets.remove(&ip);
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 7], port))
    }

    #[test]
    fn a_cookie_is_accepted_for_its_own_endpoint_and_nothing_else() {
        let gate = HandshakeGate::new();
        let cookie = gate.cookie(addr(4000));
        assert!(gate.cookie_is_mine(&cookie, addr(4000)));
        // A different port is a different endpoint.
        assert!(!gate.cookie_is_mine(&cookie, addr(4001)));
        // A different host.
        assert!(!gate.cookie_is_mine(&cookie, SocketAddr::from(([10, 0, 0, 8], 4000))));
        // Truncated or empty.
        assert!(!gate.cookie_is_mine(&cookie[..COOKIE_LEN - 1], addr(4000)));
        assert!(!gate.cookie_is_mine(&[], addr(4000)));
    }

    #[test]
    fn a_cookie_from_a_different_node_is_rejected() {
        let issuer = HandshakeGate::new();
        let other = HandshakeGate::new();
        let cookie = issuer.cookie(addr(4000));
        assert!(
            !other.cookie_is_mine(&cookie, addr(4000)),
            "cookies must not transfer between nodes: the secret is per-process"
        );
    }

    #[test]
    fn rotation_keeps_a_cookie_valid_for_one_more_epoch() {
        let gate = HandshakeGate::new();
        let source = addr(4000);
        let before = gate.cookie(source);

        // Not due yet: a rotation must not happen on every tick.
        assert!(!gate.rotate_if_due(Instant::now()));

        // Due: one epoch has passed.
        let first = Instant::now() + ROTATE_EVERY + Duration::from_secs(1);
        assert!(gate.rotate_if_due(first));
        // The cookie handed out just before rotation must still verify, or a
        // handshake already in flight would fail for no reason.
        assert!(gate.cookie_is_mine(&before, source));
        let after = gate.cookie(source);
        assert_ne!(before, after, "rotation must change the cookie");
        assert!(gate.cookie_is_mine(&after, source));

        // A second rotation drops the original secret, and with it the original
        // cookie — while the one minted under the intervening secret survives.
        let second = first + ROTATE_EVERY + Duration::from_secs(1);
        assert!(gate.rotate_if_due(second));
        assert!(!gate.cookie_is_mine(&before, source));
        assert!(gate.cookie_is_mine(&after, source));
    }

    #[test]
    fn the_mac_binds_the_cookie_to_this_exact_hello() {
        let gate = HandshakeGate::new();
        let source = addr(4000);
        let cookie = gate.cookie(source);
        let hello = b"{\"peer_id\":\"a\"}";
        let other_hello = b"{\"peer_id\":\"b\"}";

        let mac = HandshakeGate::mac_for(&cookie, hello);
        assert!(HandshakeGate::mac_is_valid(&cookie, hello, &mac));
        // The same cookie over a different Hello must not validate, or the gate
        // would admit material it never saw.
        assert!(!HandshakeGate::mac_is_valid(&cookie, other_hello, &mac));
        assert!(!HandshakeGate::mac_is_valid(&cookie, hello, &mac[..31]));
    }

    #[test]
    fn an_invented_cookie_is_rejected_before_any_mac_is_considered() {
        let gate = HandshakeGate::new();
        let source = addr(4000);
        // An attacker can compute a self-consistent MAC over its own cookie, so
        // the MAC alone proves nothing. The cookie check is what rejects it.
        let invented = [0xAAu8; COOKIE_LEN];
        let mac = HandshakeGate::mac_for(&invented, b"hello");
        assert!(HandshakeGate::mac_is_valid(&invented, b"hello", &mac));
        assert!(
            !gate.cookie_is_mine(&invented, source),
            "the responder must reject an invented cookie regardless of its MAC"
        );
    }

    #[test]
    fn the_bucket_admits_a_burst_then_refuses() {
        let gate = HandshakeGate::new();
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let now = Instant::now();

        let mut admitted = 0;
        for _ in 0..BURST as usize {
            if gate.admit(ip, now) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, BURST as usize, "the whole burst must be admitted");
        assert!(
            !gate.admit(ip, now),
            "the next attempt in the same instant must be refused"
        );

        // A second source is unaffected by the first source's exhaustion.
        let other: IpAddr = "10.0.0.8".parse().unwrap();
        assert!(gate.admit(other, now));
    }

    #[test]
    fn the_bucket_refills_over_time() {
        let gate = HandshakeGate::new();
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let now = Instant::now();
        for _ in 0..BURST as usize {
            gate.admit(ip, now);
        }
        assert!(!gate.admit(ip, now));
        // A full window restores the whole burst.
        assert!(gate.admit(ip, now + Duration::from_secs_f64(WINDOW_SECS)));
    }

    #[test]
    fn a_source_spray_cannot_grow_memory_without_bound() {
        let gate = HandshakeGate::new();
        // The worst case: every address arrives at the same instant, so no
        // bucket has refilled and periodic pruning removes nothing. Only the
        // hard eviction bound can stop the map growing here.
        let now = Instant::now();
        for i in 0..(MAX_TRACKED_SOURCES as u32 * 3) {
            gate.admit(IpAddr::from(i.to_be_bytes()), now);
        }
        assert!(
            gate.tracked_sources() <= MAX_TRACKED_SOURCES,
            "tracked sources grew past the cap: {}",
            gate.tracked_sources()
        );
        // And a fresh source is still admitted after all that.
        assert!(gate.admit("192.0.2.9".parse().unwrap(), now));
    }
}
