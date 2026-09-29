//! Datagram typing and codec for the mesh wire.
//!
//! Two kinds of datagram share one UDP socket, so the first byte is the
//! discriminant:
//!
//! ```text
//! data frame:          [0x03][flags u8][counter u64 LE] || payload || 0x00 || pad
//! handshake datagram:  [0x02][kind u8][body]
//! ```
//!
//! The data frame is exactly what `hardening.rs` produces (its `FRAME_VERSION`
//! is 3) and is unchanged here. The handshake envelope is new: without a
//! discriminant a receive loop could not tell a Hello from a data frame except
//! by relying on a first byte never colliding with the frame version, and that
//! is not a contract anyone can hold.
//!
//! ## Why the handshake body is binary, not JSON
//!
//! It was JSON, and `serde_json` encodes `Vec<u8>` as an array of decimal
//! integers — about 3.5 bytes on the wire per byte of payload. A Hello is
//! roughly 12 KB of hybrid post-quantum material, and it was being sent as a
//! **43 KB** datagram. Encoding it by hand costs the JSON dependency on the
//! handshake path and removes that inflation entirely.
//!
//! ## Fragmentation
//!
//! Even at 12 KB a handshake datagram exceeds any ordinary path MTU, and IP
//! fragmentation is exactly the thing middleboxes drop. Handshake datagrams are
//! therefore split into `FRAGMENT_CHUNK`-sized pieces and reassembled, so a
//! Hello survives a network that will not carry a 12 KB datagram.
//!
//! Reassembly is attacker-reachable, so every dimension is bounded: fragment
//! count, total message size, concurrent partial messages, and age. See
//! [`Reassembler`].

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use imperium_protocol::{MeshHello, MeshHelloResponse};
use parking_lot::Mutex;
use thiserror::Error;
use uuid::Uuid;

/// First byte of a handshake datagram.
pub const DATAGRAM_HANDSHAKE: u8 = 0x02;
/// First byte of an encrypted data frame. Mirrors `hardening::FRAME_VERSION`.
pub const DATAGRAM_FRAME: u8 = 0x03;

/// Bytes of message carried per fragment. With the 2-byte envelope and the
/// 8-byte fragment header this keeps a fragment datagram inside 1500 bytes
/// after IP and UDP headers.
pub const FRAGMENT_CHUNK: usize = 1200;

/// Largest number of fragments one message may be split into, which bounds a
/// reassembled message at `MAX_FRAGMENTS * FRAGMENT_CHUNK`.
const MAX_FRAGMENTS: usize = 64;

/// Concurrent partial messages held per peer address.
const MAX_PARTIALS_PER_SOURCE: usize = 4;

/// Concurrent partial messages held in total.
const MAX_PARTIALS: usize = 32;

/// How long an incomplete message is kept before being dropped.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Which handshake message a handshake datagram carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeKind {
    /// An ungated Hello. Answered with a cookie, never verified directly.
    Hello,
    /// The responder's reply. Verified against the recipient's outstanding Hello.
    HelloResponse,
    /// A cookie proving nothing; it only binds the sender's source address.
    Cookie,
    /// A Hello carrying a gate MAC over its own bytes.
    GatedHello,
    /// One piece of a larger handshake datagram.
    Fragment,
}

impl HandshakeKind {
    fn tag(self) -> u8 {
        match self {
            HandshakeKind::Hello => 1,
            HandshakeKind::HelloResponse => 2,
            HandshakeKind::Cookie => 3,
            HandshakeKind::GatedHello => 4,
            HandshakeKind::Fragment => 5,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(HandshakeKind::Hello),
            2 => Some(HandshakeKind::HelloResponse),
            3 => Some(HandshakeKind::Cookie),
            4 => Some(HandshakeKind::GatedHello),
            5 => Some(HandshakeKind::Fragment),
            _ => None,
        }
    }
}

/// What an inbound datagram is, decided from its leading bytes alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DatagramKind {
    Handshake(HandshakeKind),
    Frame,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("datagram is empty")]
    Empty,
    #[error("unknown handshake kind tag: {0}")]
    UnknownHandshakeKind(u8),
    #[error("handshake datagram is malformed")]
    Malformed,
    #[error("handshake datagram is truncated")]
    Truncated,
    #[error("message is too large to fragment")]
    TooLarge,
}

/// Classify a datagram without decoding it. `None` means the bytes are not a
/// shape this mesh speaks, which is the normal case for a stray datagram and
/// must not be treated as a protocol error.
pub fn classify(bytes: &[u8]) -> Option<DatagramKind> {
    match *bytes.first()? {
        DATAGRAM_FRAME => Some(DatagramKind::Frame),
        DATAGRAM_HANDSHAKE => {
            let tag = *bytes.get(1)?;
            HandshakeKind::from_tag(tag).map(DatagramKind::Handshake)
        }
        _ => None,
    }
}

/// Split a handshake datagram into its kind and body, without decoding.
pub fn split_handshake(bytes: &[u8]) -> Result<(HandshakeKind, &[u8]), WireError> {
    if bytes.is_empty() {
        return Err(WireError::Empty);
    }
    if bytes[0] != DATAGRAM_HANDSHAKE {
        return Err(WireError::Malformed);
    }
    let tag = *bytes.get(1).ok_or(WireError::Malformed)?;
    let kind = HandshakeKind::from_tag(tag).ok_or(WireError::UnknownHandshakeKind(tag))?;
    let body = bytes.get(2..).ok_or(WireError::Malformed)?;
    Ok((kind, body))
}

// --- cookie ---------------------------------------------------------------

/// A cookie datagram: `[0x02][3][cookie bytes]`.
///
/// Binary rather than structured because it carries no structure — it is one
/// opaque MAC the sender must echo.
pub fn encode_cookie(cookie: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + cookie.len());
    out.push(DATAGRAM_HANDSHAKE);
    out.push(HandshakeKind::Cookie.tag());
    out.extend_from_slice(cookie);
    out
}

pub fn decode_cookie(bytes: &[u8]) -> Result<&[u8], WireError> {
    let (kind, body) = split_handshake(bytes)?;
    if kind != HandshakeKind::Cookie || body.is_empty() {
        return Err(WireError::Malformed);
    }
    Ok(body)
}

// --- Hello and HelloResponse ---------------------------------------------

pub fn encode_hello(hello: &MeshHello) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new();
    w.uuid(&hello.peer_id.0);
    w.addr(hello.endpoint);
    w.bytes(&hello.classical_pubkey);
    w.bytes(&hello.pqc_pubkey);
    w.uuid(&hello.session_id.0);
    w.bytes(&hello.identity_vk);
    w.bytes(&hello.identity_grant);
    w.bytes(&hello.handshake_signature);
    Ok(wrap(HandshakeKind::Hello, w.finish()))
}

pub fn decode_hello(bytes: &[u8]) -> Result<MeshHello, WireError> {
    let (kind, body) = split_handshake(bytes)?;
    if kind != HandshakeKind::Hello {
        return Err(WireError::Malformed);
    }
    let mut r = Reader::new(body);
    let hello = MeshHello {
        peer_id: imperium_protocol::PeerId(r.uuid()?),
        endpoint: r.addr()?,
        classical_pubkey: r.bytes()?.to_vec(),
        pqc_pubkey: r.bytes()?.to_vec(),
        session_id: imperium_protocol::SessionId(r.uuid()?),
        identity_vk: r.bytes()?.to_vec(),
        identity_grant: r.bytes()?.to_vec(),
        handshake_signature: r.bytes()?.to_vec(),
    };
    r.expect_end()?;
    Ok(hello)
}

pub fn encode_hello_response(response: &MeshHelloResponse) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new();
    w.uuid(&response.peer_id.0);
    w.addr(response.endpoint);
    w.bytes(&response.classical_pubkey);
    w.bytes(&response.pqc_ciphertext);
    w.uuid(&response.session_id.0);
    w.bytes(&response.identity_vk);
    w.bytes(&response.identity_grant);
    w.bytes(&response.handshake_signature);
    Ok(wrap(HandshakeKind::HelloResponse, w.finish()))
}

pub fn decode_hello_response(bytes: &[u8]) -> Result<MeshHelloResponse, WireError> {
    let (kind, body) = split_handshake(bytes)?;
    if kind != HandshakeKind::HelloResponse {
        return Err(WireError::Malformed);
    }
    let mut r = Reader::new(body);
    let response = MeshHelloResponse {
        peer_id: imperium_protocol::PeerId(r.uuid()?),
        endpoint: r.addr()?,
        classical_pubkey: r.bytes()?.to_vec(),
        pqc_ciphertext: r.bytes()?.to_vec(),
        session_id: imperium_protocol::SessionId(r.uuid()?),
        identity_vk: r.bytes()?.to_vec(),
        identity_grant: r.bytes()?.to_vec(),
        handshake_signature: r.bytes()?.to_vec(),
    };
    r.expect_end()?;
    Ok(response)
}

/// Length of the datagram `hello` will produce on the wire.
pub fn handshake_datagram_len(hello: &MeshHello) -> usize {
    encode_hello(hello).map(|v| v.len()).unwrap_or(0)
}

/// Length of the datagram `response` will produce on the wire.
pub fn handshake_response_datagram_len(response: &MeshHelloResponse) -> usize {
    encode_hello_response(response)
        .map(|v| v.len())
        .unwrap_or(0)
}

// --- gated Hello ----------------------------------------------------------

/// A gated Hello: `[0x02][4][hello_len u32 LE][hello datagram][gate mac]`.
///
/// The original Hello datagram is carried **verbatim** rather than re-encoded,
/// so the MAC covers exactly the bytes that were sent and there is no
/// canonicalisation question about how a re-encoded Hello might differ.
pub fn encode_gated_hello(hello_datagram: &[u8], gate_mac: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut w = Writer::new();
    w.u32(
        hello_datagram
            .len()
            .try_into()
            .map_err(|_| WireError::TooLarge)?,
    );
    w.raw(hello_datagram);
    w.raw(gate_mac);
    Ok(wrap(HandshakeKind::GatedHello, w.finish()))
}

/// Split a gated Hello into the exact Hello datagram it carries and the gate
/// MAC over it. Performs no verification — the caller checks the MAC against
/// the source before anything expensive runs.
pub fn split_gated_hello(bytes: &[u8]) -> Result<(&[u8], &[u8]), WireError> {
    let (kind, body) = split_handshake(bytes)?;
    if kind != HandshakeKind::GatedHello {
        return Err(WireError::Malformed);
    }
    let mut r = Reader::new(body);
    let len = r.u32()? as usize;
    let hello = r.take(len)?;
    let mac = r.rest();
    if mac.is_empty() {
        return Err(WireError::Malformed);
    }
    Ok((hello, mac))
}

// --- fragmentation --------------------------------------------------------

/// Split a handshake datagram into fragment datagrams.
///
/// Returns the datagram unchanged, in a one-element vector, when it already
/// fits — so the caller does not need to know whether fragmentation happened.
/// Only handshake datagrams are fragmented; data frames are already bounded by
/// the frame ceiling.
pub fn fragment(datagram: &[u8], message_id: u32) -> Result<Vec<Vec<u8>>, WireError> {
    if datagram.len() <= FRAGMENT_CHUNK {
        return Ok(vec![datagram.to_vec()]);
    }
    let chunks: Vec<&[u8]> = datagram.chunks(FRAGMENT_CHUNK).collect();
    if chunks.len() > MAX_FRAGMENTS {
        return Err(WireError::TooLarge);
    }
    let count = chunks.len() as u16;
    let mut out = Vec::with_capacity(chunks.len());
    for (index, chunk) in chunks.into_iter().enumerate() {
        let mut w = Writer::new();
        w.u32(message_id);
        w.u16(index as u16);
        w.u16(count);
        w.raw(chunk);
        out.push(wrap(HandshakeKind::Fragment, w.finish()));
    }
    Ok(out)
}

/// A fragment's header, for the reassembler.
pub fn split_fragment(bytes: &[u8]) -> Result<(u32, u16, u16, &[u8]), WireError> {
    let (kind, body) = split_handshake(bytes)?;
    if kind != HandshakeKind::Fragment {
        return Err(WireError::Malformed);
    }
    let mut r = Reader::new(body);
    let message_id = r.u32()?;
    let index = r.u16()?;
    let count = r.u16()?;
    let chunk = r.rest();
    // The chunk length must be bounded, not merely non-empty. Without this the
    // documented reassembled-message bound (MAX_FRAGMENTS * FRAGMENT_CHUNK) is
    // false: a fragment may carry up to a full datagram, so one partial message
    // could reach tens of megabytes and the table hundreds, all sized from
    // attacker input on an unauthenticated path.
    if count == 0
        || index >= count
        || count as usize > MAX_FRAGMENTS
        || chunk.is_empty()
        || chunk.len() > FRAGMENT_CHUNK
    {
        return Err(WireError::Malformed);
    }
    Ok((message_id, index, count, chunk))
}

struct Partial {
    count: u16,
    received: usize,
    total_bytes: usize,
    chunks: Vec<Option<Vec<u8>>>,
    started: Instant,
}

/// Reassembles fragmented handshake datagrams.
///
/// Every dimension is bounded because this is reachable by any datagram from
/// any address: a message may have at most `MAX_FRAGMENTS` fragments, a source
/// may have at most `MAX_PARTIALS_PER_SOURCE` messages in flight, the table
/// holds at most `MAX_PARTIALS`, and an incomplete message older than
/// `REASSEMBLY_TIMEOUT` is dropped. Without the per-source bound a single
/// address could fill the table and starve every other peer.
pub struct Reassembler {
    inner: Mutex<HashMap<(SocketAddr, u32), Partial>>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Feed one fragment. Returns the complete datagram when this fragment
    /// finished the message.
    pub fn accept(
        &self,
        source: SocketAddr,
        message_id: u32,
        index: u16,
        count: u16,
        chunk: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock();
        inner.retain(|_, partial| now.duration_since(partial.started) < REASSEMBLY_TIMEOUT);
        if inner.len() >= MAX_PARTIALS && !inner.contains_key(&(source, message_id)) {
            return None;
        }

        let per_source = inner.keys().filter(|(addr, _)| *addr == source).count();
        if per_source >= MAX_PARTIALS_PER_SOURCE && !inner.contains_key(&(source, message_id)) {
            return None;
        }

        let partial = inner
            .entry((source, message_id))
            .or_insert_with(|| Partial {
                count,
                received: 0,
                total_bytes: 0,
                chunks: vec![None; count as usize],
                started: now,
            });
        // A message that changes its own fragment count mid-flight is not one
        // we are willing to assemble.
        if partial.count != count {
            inner.remove(&(source, message_id));
            return None;
        }

        let slot = partial.chunks.get_mut(index as usize)?;
        if slot.is_none() {
            partial.total_bytes += chunk.len();
            partial.received += 1;
            *slot = Some(chunk.to_vec());
        }

        let complete = partial.received == partial.count as usize;
        if !complete {
            return None;
        }
        let partial = inner.remove(&(source, message_id))?;
        let mut out = Vec::with_capacity(partial.total_bytes);
        for piece in partial.chunks.into_iter() {
            out.extend_from_slice(&piece?);
        }
        Some(out)
    }

    /// Number of partial messages currently held. Exposed so a test can prove
    /// the table stays bounded.
    pub fn pending(&self) -> usize {
        self.inner.lock().len()
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

// --- primitives -----------------------------------------------------------

fn wrap(kind: HandshakeKind, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(DATAGRAM_HANDSHAKE);
    out.push(kind.tag());
    out.extend_from_slice(&body);
    out
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }
    /// Length-prefixed bytes.
    fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.raw(v);
    }
    fn uuid(&mut self, v: &Uuid) {
        self.raw(v.as_bytes());
    }
    fn addr(&mut self, addr: SocketAddr) {
        match addr.ip() {
            IpAddr::V4(v4) => {
                self.buf.push(4);
                self.raw(&v4.octets());
            }
            IpAddr::V6(v6) => {
                self.buf.push(6);
                self.raw(&v6.octets());
            }
        }
        self.u16(addr.port());
    }
    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        if end > self.buf.len() {
            return Err(WireError::Truncated);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(
            self.take(2)?.try_into().expect("length checked"),
        ))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("length checked"),
        ))
    }
    fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        self.take(len)
    }
    fn uuid(&mut self) -> Result<Uuid, WireError> {
        Uuid::from_slice(self.take(16)?).map_err(|_| WireError::Malformed)
    }
    fn addr(&mut self) -> Result<SocketAddr, WireError> {
        let family = self.take(1)?[0];
        let ip = match family {
            4 => {
                let octets: [u8; 4] = self.take(4)?.try_into().expect("length checked");
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                let octets: [u8; 16] = self.take(16)?.try_into().expect("length checked");
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(WireError::Malformed),
        };
        let port = self.u16()?;
        Ok(SocketAddr::new(ip, port))
    }
    fn rest(&mut self) -> &'a [u8] {
        let slice = &self.buf[self.pos..];
        self.pos = self.buf.len();
        slice
    }
    /// Reject trailing bytes: a datagram that decodes with leftovers was not
    /// produced by this encoder, and silently ignoring the remainder would let
    /// two different datagrams decode to the same message.
    fn expect_end(&self) -> Result<(), WireError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hello() -> MeshHello {
        MeshHello {
            peer_id: imperium_protocol::PeerId::new(),
            endpoint: "127.0.0.1:9000".parse().unwrap(),
            classical_pubkey: vec![1; 32],
            pqc_pubkey: vec![2; 1184],
            session_id: imperium_protocol::SessionId::new(),
            identity_vk: vec![3; 1984],
            identity_grant: vec![4; 5413],
            handshake_signature: vec![5; 3373],
        }
    }

    fn sample_response() -> MeshHelloResponse {
        MeshHelloResponse {
            peer_id: imperium_protocol::PeerId::new(),
            endpoint: "[::1]:9001".parse().unwrap(),
            classical_pubkey: vec![6; 32],
            pqc_ciphertext: vec![7; 1088],
            session_id: imperium_protocol::SessionId::new(),
            identity_vk: vec![8; 1984],
            identity_grant: vec![9; 5413],
            handshake_signature: vec![10; 3373],
        }
    }

    #[test]
    fn hello_round_trips_and_is_not_inflated() {
        let hello = sample_hello();
        let wire = encode_hello(&hello).unwrap();
        assert_eq!(
            classify(&wire),
            Some(DatagramKind::Handshake(HandshakeKind::Hello))
        );

        let decoded = decode_hello(&wire).unwrap();
        assert_eq!(decoded.peer_id, hello.peer_id);
        assert_eq!(decoded.session_id, hello.session_id);
        assert_eq!(decoded.endpoint, hello.endpoint);
        assert_eq!(decoded.classical_pubkey, hello.classical_pubkey);
        assert_eq!(decoded.pqc_pubkey, hello.pqc_pubkey);
        assert_eq!(decoded.identity_vk, hello.identity_vk);
        assert_eq!(decoded.identity_grant, hello.identity_grant);
        assert_eq!(decoded.handshake_signature, hello.handshake_signature);

        // The whole point of dropping JSON: the datagram is the size of its
        // material plus a small header, not several times that.
        let material = 32 + 1184 + 1984 + 5413 + 3373;
        assert!(
            wire.len() < material + 128,
            "encoded hello is {} bytes for {material} bytes of material",
            wire.len()
        );
        assert_eq!(wire.len(), handshake_datagram_len(&hello));
    }

    #[test]
    fn hello_response_round_trips() {
        let response = sample_response();
        let wire = encode_hello_response(&response).unwrap();
        let decoded = decode_hello_response(&wire).unwrap();
        assert_eq!(decoded.peer_id, response.peer_id);
        assert_eq!(decoded.endpoint, response.endpoint);
        assert_eq!(decoded.pqc_ciphertext, response.pqc_ciphertext);
        assert_eq!(decoded.identity_grant, response.identity_grant);
        assert_eq!(wire.len(), handshake_response_datagram_len(&response));
    }

    #[test]
    fn truncated_and_overlong_datagrams_fail_closed() {
        let wire = encode_hello(&sample_hello()).unwrap();
        assert!(matches!(
            decode_hello(&wire[..wire.len() - 1]),
            Err(WireError::Truncated)
        ));
        // Trailing bytes mean this was not produced by this encoder.
        let mut extra = wire.clone();
        extra.push(0);
        assert!(matches!(decode_hello(&extra), Err(WireError::Malformed)));
        // Wrong kind.
        assert!(matches!(
            decode_hello_response(&wire),
            Err(WireError::Malformed)
        ));
    }

    #[test]
    fn a_frame_and_a_hello_are_distinguishable() {
        let mut frame = vec![DATAGRAM_FRAME, 0x00];
        frame.extend_from_slice(&7u64.to_le_bytes());
        frame.push(0x00);
        assert_eq!(classify(&frame), Some(DatagramKind::Frame));
        assert_eq!(
            classify(&encode_hello(&sample_hello()).unwrap()),
            Some(DatagramKind::Handshake(HandshakeKind::Hello))
        );
    }

    #[test]
    fn unknown_and_truncated_datagrams_are_rejected_not_guessed() {
        assert_eq!(classify(&[]), None);
        assert_eq!(classify(&[0x99, 0x01]), None);
        assert_eq!(classify(&[DATAGRAM_HANDSHAKE]), None);
        assert_eq!(classify(&[DATAGRAM_HANDSHAKE, 0x7f]), None);
        assert_eq!(
            split_handshake(&[DATAGRAM_HANDSHAKE, 0x7f]),
            Err(WireError::UnknownHandshakeKind(0x7f))
        );
    }

    #[test]
    fn a_small_datagram_is_not_fragmented() {
        let small = encode_cookie(&[7u8; 16]);
        let pieces = fragment(&small, 1).unwrap();
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0], small, "a fitting datagram is passed through");
    }

    #[test]
    fn a_large_datagram_survives_fragmentation_and_reassembly() {
        let hello = sample_hello();
        let wire = encode_hello(&hello).unwrap();
        assert!(wire.len() > FRAGMENT_CHUNK, "this should need fragments");

        let pieces = fragment(&wire, 42).unwrap();
        assert!(pieces.len() > 1);
        for piece in &pieces {
            assert!(
                piece.len() <= FRAGMENT_CHUNK + 10,
                "fragment is {} bytes, over the chunk size",
                piece.len()
            );
            assert_eq!(
                classify(piece),
                Some(DatagramKind::Handshake(HandshakeKind::Fragment))
            );
        }

        let source: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let now = Instant::now();
        let reassembler = Reassembler::new();
        let mut complete = None;
        // Deliberately out of order, which is normal for UDP.
        for piece in pieces.iter().rev() {
            let (id, index, count, chunk) = split_fragment(piece).unwrap();
            if let Some(datagram) = reassembler.accept(source, id, index, count, chunk, now) {
                complete = Some(datagram);
            }
        }
        let complete = complete.expect("all fragments arrived");
        assert_eq!(complete, wire, "reassembly must be byte-exact");
        // And the reassembled datagram decodes as the original message.
        let decoded = decode_hello(&complete).unwrap();
        assert_eq!(decoded.identity_grant, hello.identity_grant);
        assert_eq!(reassembler.pending(), 0, "nothing left behind");
    }

    #[test]
    fn a_duplicate_fragment_does_not_corrupt_reassembly() {
        let wire = encode_hello(&sample_hello()).unwrap();
        let pieces = fragment(&wire, 7).unwrap();
        let source: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let now = Instant::now();
        let reassembler = Reassembler::new();

        let mut complete = None;
        for piece in &pieces {
            let (id, index, count, chunk) = split_fragment(piece).unwrap();
            if let Some(d) = reassembler.accept(source, id, index, count, chunk, now) {
                complete = Some(d);
            }
            // Replay the same fragment; it must be ignored, not appended.
            let (id, index, count, chunk) = split_fragment(piece).unwrap();
            assert!(reassembler
                .accept(source, id, index, count, chunk, now)
                .is_none());
        }
        assert_eq!(complete.expect("complete"), wire);
    }

    #[test]
    fn an_incomplete_message_is_dropped_rather_than_held_forever() {
        let wire = encode_hello(&sample_hello()).unwrap();
        let pieces = fragment(&wire, 3).unwrap();
        let source: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let reassembler = Reassembler::new();
        let now = Instant::now();

        // Everything except the last fragment.
        for piece in &pieces[..pieces.len() - 1] {
            let (id, index, count, chunk) = split_fragment(piece).unwrap();
            assert!(reassembler
                .accept(source, id, index, count, chunk, now)
                .is_none());
        }
        assert_eq!(reassembler.pending(), 1);

        // Once past the timeout the partial is swept, so a peer that abandons a
        // handshake cannot pin memory.
        let late = now + REASSEMBLY_TIMEOUT + Duration::from_secs(1);
        let (id, index, count, chunk) = split_fragment(&pieces[0]).unwrap();
        assert!(reassembler
            .accept(source, id, index, count, chunk, late)
            .is_none());
        assert_eq!(
            reassembler.pending(),
            1,
            "the stale one was swept, a new one began"
        );
    }

    #[test]
    fn one_source_cannot_fill_the_reassembly_table() {
        let source: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let reassembler = Reassembler::new();
        let now = Instant::now();
        // Start many distinct messages, each incomplete.
        for id in 0..64u32 {
            reassembler.accept(source, id, 0, 4, &[1u8; 100], now);
        }
        assert!(
            reassembler.pending() <= MAX_PARTIALS_PER_SOURCE,
            "one address held {} partials",
            reassembler.pending()
        );
        // A different source is unaffected.
        let other: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        reassembler.accept(other, 1, 0, 4, &[1u8; 100], now);
        assert!(reassembler.pending() > MAX_PARTIALS_PER_SOURCE);
    }

    #[test]
    fn an_absurd_fragment_count_is_refused() {
        // A fragment claiming more pieces than we will ever assemble.
        let mut w = Writer::new();
        w.u32(1);
        w.u16(0);
        w.u16(MAX_FRAGMENTS as u16 + 1);
        w.raw(b"x");
        let datagram = wrap(HandshakeKind::Fragment, w.finish());
        assert_eq!(split_fragment(&datagram), Err(WireError::Malformed));

        // Index at or beyond the count.
        let mut w = Writer::new();
        w.u32(1);
        w.u16(4);
        w.u16(4);
        w.raw(b"x");
        let datagram = wrap(HandshakeKind::Fragment, w.finish());
        assert_eq!(split_fragment(&datagram), Err(WireError::Malformed));
    }

    #[test]
    fn a_gated_hello_carries_the_verbatim_hello() {
        let hello = encode_hello(&sample_hello()).unwrap();
        let mac = [9u8; 32];
        let gated = encode_gated_hello(&hello, &mac).unwrap();
        let (carried, carried_mac) = split_gated_hello(&gated).unwrap();
        assert_eq!(carried, hello.as_slice(), "byte-for-byte, not re-encoded");
        assert_eq!(carried_mac, &mac);
        // A gated hello with no MAC is refused.
        let mut w = Writer::new();
        w.u32(hello.len() as u32);
        w.raw(&hello);
        let no_mac = wrap(HandshakeKind::GatedHello, w.finish());
        assert_eq!(split_gated_hello(&no_mac), Err(WireError::Malformed));
    }
}
