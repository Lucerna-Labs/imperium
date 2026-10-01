//! Bounded Linux NFQUEUE UAPI codec. Kernel transport only; no traffic policy.

use std::io;

pub(crate) const PACKET: u16 = 0x0300;
pub(crate) const VERDICT: u16 = 0x0301;
pub(crate) const CONFIG: u16 = 0x0302;
const MAX_PACKET: usize = 65_535;

#[derive(Debug)]
pub struct HeldPacket {
    pub(crate) owner: u64,
    pub(crate) queue: u16,
    pub(crate) id: u32,
    pub family: u8,
    pub hook: u8,
    pub hardware_protocol: u16,
    pub input_interface: Option<u32>,
    pub output_interface: Option<u32>,
    pub skb_info: u32,
    pub(crate) payload: Vec<u8>,
}

impl HeldPacket {
    pub fn bytes(&self) -> &[u8] {
        &self.payload
    }
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn checksum_pending(&self) -> bool {
        self.skb_info & 1 != 0
    }
}

pub(crate) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn native_u16(bytes: &[u8]) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(
        bytes.try_into().map_err(|_| invalid("u16 length"))?,
    ))
}
fn native_u32(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes.try_into().map_err(|_| invalid("u32 length"))?,
    ))
}
fn network_u32(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| invalid("attribute u32 length"))?,
    ))
}

pub(crate) struct Message<'a> {
    pub kind: u16,
    pub sequence: u32,
    pub body: &'a [u8],
}

pub(crate) fn messages(mut bytes: &[u8]) -> io::Result<Vec<Message<'_>>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(invalid("truncated netlink header"));
        }
        let length = native_u32(&bytes[..4])? as usize;
        let aligned = length
            .checked_add(3)
            .ok_or_else(|| invalid("netlink length overflow"))?
            & !3;
        if length < 16 || aligned > bytes.len() || native_u16(&bytes[6..8])? & 2 != 0 {
            return Err(invalid("invalid netlink length or multipart flag"));
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(invalid("nonzero netlink padding"));
        }
        out.push(Message {
            kind: native_u16(&bytes[4..6])?,
            sequence: native_u32(&bytes[8..12])?,
            body: &bytes[16..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(out)
}

pub(crate) fn packet(body: &[u8], queue: u16) -> io::Result<HeldPacket> {
    if body.len() < 4 || body[1] != 0 || u16::from_be_bytes([body[2], body[3]]) != queue {
        return Err(invalid("wrong NFQUEUE header/version/queue"));
    }
    if ![2, 10].contains(&body[0]) {
        return Err(invalid("unrepresented queue address family"));
    }
    let mut attributes = &body[4..];
    let (mut header, mut payload, mut capture_len) = (None, None, None);
    let (mut input, mut output, mut skb) = (None, None, None);
    let mut seen = [false; 256];
    while !attributes.is_empty() {
        if attributes.len() < 4 {
            return Err(invalid("truncated netlink attribute"));
        }
        let length = usize::from(native_u16(&attributes[..2])?);
        let kind = native_u16(&attributes[2..4])? & 0x3fff;
        let aligned = (length + 3) & !3;
        if length < 4 || aligned > attributes.len() {
            return Err(invalid("invalid attribute length"));
        }
        if attributes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(invalid("nonzero attribute padding"));
        }
        if let Some(value) = seen.get_mut(usize::from(kind)) {
            if *value {
                return Err(invalid("duplicate queue attribute"));
            }
            *value = true;
        }
        let value = &attributes[4..length];
        match kind {
            1 if value.len() == 7 => header = Some(value),
            1 => return Err(invalid("packet header size")),
            5 => input = Some(network_u32(value)?),
            6 => output = Some(network_u32(value)?),
            10 if !value.is_empty() && value.len() <= MAX_PACKET => payload = Some(value),
            10 => return Err(invalid("empty or oversized queue payload")),
            13 => capture_len = Some(network_u32(value)? as usize),
            14 => skb = Some(network_u32(value)?),
            _ => {}
        }
        attributes = &attributes[aligned..];
    }
    let header = header.ok_or_else(|| invalid("missing packet ID"))?;
    let payload = payload.ok_or_else(|| invalid("missing queue payload"))?;
    if capture_len.is_some_and(|length| length != payload.len()) {
        return Err(invalid("truncated kernel packet copy"));
    }
    let protocol = u16::from_be_bytes([header[4], header[5]]);
    if !matches!((body[0], protocol), (2, 0x0800) | (10, 0x86dd)) || header[6] > 4 {
        return Err(invalid("packet family/protocol/hook mismatch"));
    }
    Ok(HeldPacket {
        owner: 0,
        queue,
        id: network_u32(&header[..4])?,
        family: body[0],
        hook: header[6],
        hardware_protocol: protocol,
        input_interface: input,
        output_interface: output,
        skb_info: skb.unwrap_or(0),
        payload: payload.to_vec(),
    })
}

pub(crate) fn attribute(kind: u16, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

pub(crate) fn envelope(kind: u16, sequence: u32, queue: u16, attributes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + attributes.len());
    out.extend_from_slice(&((20 + attributes.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&5u16.to_ne_bytes()); // REQUEST | ACK
    out.extend_from_slice(&sequence.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&[0, 0]); // AF_UNSPEC, NFNETLINK_V0
    out.extend_from_slice(&queue.to_be_bytes());
    out.extend_from_slice(attributes);
    out
}

pub(crate) fn ack(message: &Message<'_>) -> io::Result<()> {
    if message.kind != 2 || message.body.len() < 4 {
        return Err(invalid("missing kernel acknowledgement"));
    }
    let error = i32::from_ne_bytes(
        message.body[..4]
            .try_into()
            .map_err(|_| invalid("ack size"))?,
    );
    if error == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(
            error.checked_neg().ok_or_else(|| invalid("ack errno"))?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut out = vec![2, 0, 0, 7];
        attribute(1, &[0, 0, 0, 42, 8, 0, 3], &mut out);
        attribute(5, &3u32.to_be_bytes(), &mut out);
        attribute(10, &[0x45, 0, 0, 4], &mut out);
        attribute(13, &4u32.to_be_bytes(), &mut out);
        attribute(14, &1u32.to_be_bytes(), &mut out);
        out
    }

    #[test]
    fn exact_packet_identity_and_metadata() {
        let p = packet(&fixture(), 7).unwrap();
        assert_eq!(p.id(), 42);
        assert_eq!(p.hook, 3);
        assert_eq!(p.input_interface, Some(3));
        assert_eq!(p.bytes(), &[0x45, 0, 0, 4]);
        assert!(p.checksum_pending());
    }

    #[test]
    fn packet_copy_and_attribute_failures_never_yield_packet() {
        let original = fixture();
        for length in 0..original.len() {
            // A subset ending before optional attributes may be valid; every
            // cut within mandatory header/payload or an attribute must fail.
            if length < 32 || length % 4 != 0 {
                assert!(packet(&original[..length], 7).is_err(), "cut {length}");
            }
        }
        assert!(packet(&original, 8).is_err());
        let mut bad = original.clone();
        bad[0] = 10;
        assert!(packet(&bad, 7).is_err());
        bad = original.clone();
        bad[1] = 1;
        assert!(packet(&bad, 7).is_err());
        bad = original.clone();
        bad[4..6].copy_from_slice(&3u16.to_ne_bytes());
        assert!(packet(&bad, 7).is_err());
        bad = original.clone();
        attribute(10, &[1], &mut bad);
        assert!(packet(&bad, 7).is_err());
        let mut truncated = vec![2, 0, 0, 7];
        attribute(1, &[0, 0, 0, 42, 8, 0, 3], &mut truncated);
        attribute(10, &[1], &mut truncated);
        attribute(13, &2u32.to_be_bytes(), &mut truncated);
        assert!(packet(&truncated, 7).is_err());
        let mut no_id = vec![2, 0, 0, 7];
        attribute(10, &[1], &mut no_id);
        assert!(packet(&no_id, 7).is_err());
    }

    #[test]
    fn malformed_envelopes_and_kernel_errors_fail() {
        let good = envelope(CONFIG, 9, 7, &[]);
        let decoded = messages(&good).unwrap();
        assert_eq!(decoded[0].sequence, 9);
        for length in 0..good.len() {
            if length != 0 {
                assert!(messages(&good[..length]).is_err());
            }
        }
        let mut bad = good;
        bad[..4].copy_from_slice(&15u32.to_ne_bytes());
        assert!(messages(&bad).is_err());
        let error = (-libc::EPERM).to_ne_bytes();
        assert_eq!(
            ack(&Message {
                kind: 2,
                sequence: 1,
                body: &error
            })
            .unwrap_err()
            .raw_os_error(),
            Some(libc::EPERM)
        );
        assert!(ack(&Message {
            kind: CONFIG,
            sequence: 1,
            body: &[0; 4]
        })
        .is_err());
    }
}
