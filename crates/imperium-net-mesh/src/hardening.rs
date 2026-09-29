//! Length-hiding frame normalization for the mesh data path.
//!
//! Wire shape, per frame:
//!
//! ```text
//! [version u8][flags u8][counter u64 LE] || stuffed_payload || 0x00 sentinel || pseudorandom pad
//! ```
//!
//! The payload is AEAD ciphertext (see `crypto`): the counter is the frame's
//! nonce and rides in the clear so the receiver can decrypt and check replay
//! before anything else.
//!
//! - The payload carries no length field of any kind. The receiver recovers
//!   the payload boundary by scanning for the first unescaped `0x00` sentinel,
//!   so an observer cannot read the original length out of the frame — it is
//!   not there. Payload `0x00` bytes are escaped (`0x00 -> 0x00 0x01`, PPP
//!   style); escaping overhead is absorbed by the padding budget.
//! - Total frame size is quantized to the profile's padding shape (buckets,
//!   envelope window, uniform additive). Wire sizes collapse to a small set
//!   that does not vary with payload content.
//! - Padding bytes are pseudorandom (deterministic per packet sequence
//!   number), not zero runs, so the pad region is not identifiable by eye.
//! - `flags & FLAG_COVER` marks a cover frame: pure padding, empty payload,
//!   emitted at the profile's `cover_traffic_ppm` rate to blur volume and
//!   timing. Receivers drop cover frames.
//!
//! The overhead budget (`max_padding_overhead_ppm`) is deliberately NOT
//! applied per packet: clamping a padded frame back toward its original
//! length reintroduces exactly the fine-grained size variance this layer
//! exists to remove. The budget bounds the profile's shape choice at
//! validation time instead (see `HardeningController::validate`).
//!
//! Frames larger than the largest allowed shape (see `MAX_WIRE_SIZE`) are emitted
//! unquantized; upstream should fragment payloads before they reach the
//! mesh session.

use std::collections::HashMap;
use std::time::Duration;

use imperium_protocol::{PaddingDistribution, ProtocolHardeningProfile};

const FRAME_VERSION: u8 = 3;
const FLAG_COVER: u8 = 0x01;
/// version + flags + counter
const HEADER_LEN: usize = 10;
/// version + flags + counter + payload + sentinel
const MIN_FRAME_LEN: usize = HEADER_LEN + 1;

/// Ceiling on any quantized frame size.
///
/// This is the frame, and the frame travels inside a UDP datagram, which travels
/// inside an IP packet. A 1_500-byte path MTU therefore has to cover
/// `20 (IP) + 8 (UDP) + frame`, leaving **1_472** for the frame. The earlier
/// value of 1_500 counted the frame alone, so a frame at the ceiling produced a
/// 1_528-byte datagram that fragmented at the IP layer — the very thing
/// fragmentation at this layer exists to avoid.
const MAX_WIRE_SIZE: usize = 1_472;

/// Escaping allowance for the payload's `0x00` bytes.
///
/// The payload is AEAD ciphertext, so roughly one byte in 256 is zero and is
/// escaped as two bytes — an expansion of about 0.4%, plus room to spare. A
/// payload of *pathologically* all-zero bytes would expand twofold, but AEAD
/// output is not that, and the ceiling is stated against ciphertext.
const STUFFING_ALLOWANCE: usize = 8;

/// The largest TUN MTU whose sealed frame still fits a 1_500-byte path MTU.
///
/// A TUN hands over an IP packet, which is sealed (adding a 16-byte AEAD tag)
/// and framed (`10`-byte header, `1`-byte sentinel, then escaping and padding).
/// So the packet may be at most
/// `1_472 - 10 - 1 - 16 - 8 = 1_437` bytes. Above this the frame exceeds the
/// ceiling and is emitted unpadded at its true size, and the outer datagram
/// fragments.
pub const MAX_SAFE_TUN_MTU: usize = MAX_WIRE_SIZE - HEADER_LEN - 1 - 16 - STUFFING_ALLOWANCE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardenedPayload {
    pub bytes: Vec<u8>,
    pub delay: Duration,
    pub cover: bool,
}

/// What a receiver gets back from a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveredFrame {
    pub payload: Vec<u8>,
    pub cover: bool,
    pub counter: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HardenerStats {
    pub frames: u64,
    pub cover_frames: u64,
    pub payload_bytes: u64,
    pub wire_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct MeshHardener {
    profile: ProtocolHardeningProfile,
    packet_seq: u64,
    /// Cover-frame rate accumulators in 1e-6 units, ONE PER LINK: each real
    /// packet adds `cover_traffic_ppm`; crossing 1e6 emits one cover frame.
    ///
    /// Per link, not shared. A single accumulator crossed the threshold once and
    /// emitted on whichever link happened to be offered first, so every other
    /// link stayed silent — leaving them distinguishable by their silence, which
    /// is precisely what cover traffic exists to remove. Keyed by a caller
    /// supplied token (the peer), so a rekey does not reset the budget and the
    /// table is bounded by the peer count.
    cover_budgets_micro: HashMap<u64, u64>,
    stats: HardenerStats,
}

impl MeshHardener {
    pub fn new(profile: ProtocolHardeningProfile) -> Self {
        Self {
            profile,
            packet_seq: 0,
            cover_budgets_micro: HashMap::new(),
            stats: HardenerStats::default(),
        }
    }

    pub fn profile_id(&self) -> &str {
        &self.profile.profile_id
    }

    pub fn stats(&self) -> HardenerStats {
        self.stats.clone()
    }

    pub fn harden_payload(
        &mut self,
        counter: u64,
        payload: Vec<u8>,
        cover: bool,
    ) -> HardenedPayload {
        self.packet_seq = self.packet_seq.saturating_add(1);

        // NOTE: no key accounting here. This layer shaped frames and nothing
        // else; its byte counter and epoch label were never read by anyone, and
        // the "rekeying" they appeared to perform was a counter increment. The
        // real budget is `session_max_bytes` in `session.rs`, enforced when a
        // frame is sealed and rotated by re-handshaking. `RekeyPolicy.
        // max_key_bytes` is validated and reported by `imperium-net-transport`,
        // and is deliberately NOT enforced on this path.
        let hardened = self.build_frame(counter, payload, cover, self.packet_seq);
        self.stats.frames = self.stats.frames.saturating_add(1);
        self.stats.cover_frames = self.stats.cover_frames.saturating_add(u64::from(cover));
        self.stats.payload_bytes = self
            .stats
            .payload_bytes
            .saturating_add(hardened.payload_len as u64);
        self.stats.wire_bytes = self
            .stats
            .wire_bytes
            .saturating_add(hardened.outcome.bytes.len() as u64);
        hardened.outcome
    }

    /// Deterministic cover-frame decision: true each time the accumulated
    /// `cover_traffic_ppm` budget crosses one full packet. A ppm of
    /// 1_000_000 covers every real frame; 0 never does. The caller seals and
    /// frames the cover payload itself — this layer only decides.
    /// Whether this LINK should emit a cover frame now.
    ///
    /// `link` is a stable per-peer token, so each link accrues its own budget
    /// and every link gets cover rather than only the first one offered.
    pub fn should_emit_cover_for(&mut self, link: u64) -> bool {
        let budget = self.cover_budgets_micro.entry(link).or_insert(0);
        *budget = budget.saturating_add(u64::from(self.profile.traffic_morph.cover_traffic_ppm));
        if *budget < 1_000_000 {
            return false;
        }
        *budget -= 1_000_000;
        true
    }

    fn build_frame(
        &self,
        counter: u64,
        payload: Vec<u8>,
        cover: bool,
        packet_seq: u64,
    ) -> FrameOutcome {
        let payload_len = payload.len();
        let mut stuffed = Vec::with_capacity(payload.len() + payload.len() / 128 + 1);
        for &byte in &payload {
            if byte == 0x00 {
                stuffed.push(0x00);
                stuffed.push(0x01);
            } else {
                stuffed.push(byte);
            }
        }

        let content_len = MIN_FRAME_LEN + stuffed.len();
        let target = wire_target(content_len, &self.profile.traffic_morph, packet_seq);
        let pad_len = target.saturating_sub(content_len);

        let mut frame = Vec::with_capacity(target);
        frame.push(FRAME_VERSION);
        frame.push(if cover { FLAG_COVER } else { 0 });
        frame.extend_from_slice(&counter.to_le_bytes());
        frame.extend_from_slice(&stuffed);
        frame.push(0x00);
        if pad_len > 0 {
            fill_pseudorandom(&mut frame, pad_len, packet_seq);
        }

        let jitter_delay_ms = deterministic_jitter(
            self.profile.traffic_morph.jitter_floor_ms,
            self.profile.traffic_morph.jitter_ceiling_ms,
            packet_seq,
        );

        FrameOutcome {
            outcome: HardenedPayload {
                bytes: frame,
                delay: Duration::from_millis(u64::from(jitter_delay_ms)),
                cover,
            },
            payload_len: payload_len as u64,
        }
    }

    /// Decode a frame produced by `harden_payload`. Returns `None` for bytes
    /// that are not a v3 frame (callers may fall back to treating them as a
    /// raw payload).
    pub fn recover_frame(bytes: &[u8]) -> Option<RecoveredFrame> {
        if bytes.len() < MIN_FRAME_LEN || bytes[0] != FRAME_VERSION {
            return None;
        }
        let cover = bytes[1] & FLAG_COVER != 0;
        let counter = u64::from_le_bytes(bytes[2..10].try_into().ok()?);

        let mut payload = Vec::with_capacity(bytes.len());
        let mut i = HEADER_LEN;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == 0x00 {
                if i + 1 < bytes.len() && bytes[i + 1] == 0x01 {
                    payload.push(0x00);
                    i += 2;
                    continue;
                }
                // Unescaped sentinel: payload ends, everything after is pad.
                return Some(RecoveredFrame {
                    payload,
                    cover,
                    counter,
                });
            }
            payload.push(byte);
            i += 1;
        }
        // Malformed (no sentinel) — reject rather than guess a boundary.
        None
    }

    /// Backward-compatible recovery: v2 frames yield their payload (cover
    /// frames yield an empty payload); anything else passes through as-is.
    pub fn recover_payload(bytes: &[u8]) -> Vec<u8> {
        match Self::recover_frame(bytes) {
            Some(frame) => frame.payload,
            None => bytes.to_vec(),
        }
    }
}

struct FrameOutcome {
    outcome: HardenedPayload,
    payload_len: u64,
}

/// Quantized total wire size for a frame whose content (header + stuffed
/// payload + sentinel) occupies `content_len` bytes.
fn wire_target(
    content_len: usize,
    morph: &imperium_protocol::TrafficMorphProfile,
    packet_seq: u64,
) -> usize {
    let target = match &morph.padding {
        PaddingDistribution::None => content_len,
        PaddingDistribution::Fixed { bytes } => content_len + usize::from(*bytes),
        PaddingDistribution::Bucketed { buckets } => buckets
            .iter()
            .copied()
            .map(usize::from)
            .filter(|bucket| *bucket >= content_len)
            .min()
            .unwrap_or(content_len),
        PaddingDistribution::Envelope {
            min_bytes,
            max_bytes,
        } => {
            let lower = content_len.max(usize::from(*min_bytes));
            let upper = usize::from(*max_bytes).max(lower);
            usize::from(deterministic_range(
                u16::try_from(lower.min(u16::MAX as usize)).unwrap_or(u16::MAX),
                u16::try_from(upper.min(u16::MAX as usize)).unwrap_or(u16::MAX),
                packet_seq,
            ))
            .max(lower)
        }
    };
    // Content is never truncated, and quantized shapes stay under the
    // conservative packet envelope.
    target.max(content_len).min(MAX_WIRE_SIZE.max(content_len))
}

/// Header bytes for an unquantized fallback frame (no hardener applied):
/// still a valid v3 frame, just unpadded. Ciphertext is 0x00-stuffed like
/// the hardened path so `recover_frame` round-trips arbitrary ciphertext
/// (previously raw ciphertext containing 0x00 truncated at recovery — an
/// intermittent decrypt failure whenever the AEAD output happened to
/// contain a zero byte).
pub fn fallback_frame(counter: u64, ciphertext: &[u8], cover: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(MIN_FRAME_LEN + ciphertext.len() + 8);
    frame.push(FRAME_VERSION);
    frame.push(u8::from(cover) * FLAG_COVER);
    frame.extend_from_slice(&counter.to_le_bytes());
    for &byte in ciphertext {
        if byte == 0x00 {
            frame.push(0x00);
            frame.push(0x01);
        } else {
            frame.push(byte);
        }
    }
    frame.push(0x00);
    frame
}

fn deterministic_jitter(floor_ms: u16, ceiling_ms: u16, packet_seq: u64) -> u16 {
    deterministic_range(floor_ms, ceiling_ms, packet_seq ^ 0xA5A5)
}

fn deterministic_range(min: u16, max: u16, seed: u64) -> u16 {
    if min >= max {
        return min;
    }

    let value = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    let span = u64::from(max - min) + 1;
    min + ((value >> 32) % span) as u16
}

/// Deterministic per-packet pseudorandom pad bytes: no zero runs, no shared
/// pattern across packets. The receiver never reproduces these — it stops at
/// the sentinel — so only the sender needs the stream. Pad bytes avoid both
/// `0x00` and `0x01` so a pad byte directly after the sentinel can never be
/// mistaken for an escaped-zero continuation.
fn fill_pseudorandom(frame: &mut Vec<u8>, pad_len: usize, packet_seq: u64) {
    let mut state = packet_seq
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0xD1B5_4A32_D192_ED0);
    for _ in 0..pad_len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        frame.push(((state >> 33) as u8) % 254 + 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use imperium_protocol::{
        FecPolicy, PaddingDistribution, PathHoppingPolicy, ProbeDeceptionMode,
        ProbeDeceptionPolicy, ProbeFailureMode, ProbeResistancePolicy, RekeyPolicy,
        TrafficMorphProfile,
    };

    fn test_profile() -> ProtocolHardeningProfile {
        morph_profile(PaddingDistribution::Envelope {
            min_bytes: 128,
            max_bytes: 512,
        })
    }

    fn morph_profile(padding: PaddingDistribution) -> ProtocolHardeningProfile {
        ProtocolHardeningProfile {
            profile_id: "mesh-test".to_string(),
            protocol_name: Some("mesh".to_string()),
            traffic_morph: TrafficMorphProfile {
                profile_id: "mesh-test-morph".to_string(),
                padding,
                max_padding_overhead_ppm: 500_000,
                jitter_floor_ms: 1,
                jitter_ceiling_ms: 3,
                cover_traffic_ppm: 0,
                packet_batching_window_ms: 0,
            },
            rekey: RekeyPolicy {
                max_key_age_seconds: 600,
                max_key_bytes: 1_048_576,
                threat_triggered: true,
                stagger_window_ms: 0,
            },
            probe_resistance: ProbeResistancePolicy {
                authenticated_first_packet_required: true,
                unauthenticated_failure_mode: ProbeFailureMode::ConstantShapeReject,
                min_response_delay_ms: 0,
                max_response_delay_ms: 0,
                decoy_response_budget_per_hour: 0,
            },
            probe_deception: ProbeDeceptionPolicy {
                enabled: false,
                mode: ProbeDeceptionMode::Disabled,
                min_confidence: 1.0,
                response_budget_per_source_per_hour: 0,
                min_delay_ms: 0,
                max_delay_ms: 0,
                max_transcript_bytes: 0,
                persona_rotation_seconds: 3_600,
                log_transcripts: false,
            },
            path_hopping: PathHoppingPolicy {
                enabled: true,
                min_dwell_seconds: 60,
                max_dwell_seconds: 300,
                burn_score_threshold: 0.8,
                packet_loss_threshold_ppm: 50_000,
                jitter_threshold_ms: 80,
            },
            fec: FecPolicy {
                enabled: true,
                data_shards: 8,
                parity_shards: 2,
                loss_threshold_ppm: 20_000,
                max_overhead_ppm: 250_000,
            },
            applied_at: Utc::now(),
            reason: "test profile".to_string(),
        }
    }

    #[test]
    fn hardens_and_recovers_payload() {
        let mut hardener = MeshHardener::new(test_profile());
        let original = br#"{"ping":1}"#.to_vec();

        let hardened = hardener.harden_payload(1, original.clone(), false);
        assert!(hardened.bytes.len() > original.len());
        assert_eq!(MeshHardener::recover_payload(&hardened.bytes), original);
    }

    #[test]
    fn the_hardener_does_no_key_accounting() {
        // The frame-shaping layer counts bytes for nothing and rotates no keys.
        // This pins that, so a future byte counter cannot quietly reappear here
        // and be mistaken for rekeying: the budget lives in `session.rs`.
        let mut profile = test_profile();
        profile.rekey.max_key_bytes = 1_048_576;
        let mut hardener = MeshHardener::new(profile);

        let mut frames = 0;
        for counter in 0..64 {
            let payload = vec![0xABu8; 4096];
            let hardened = hardener.harden_payload(counter, payload, false);
            assert!(!hardened.bytes.is_empty());
            frames += 1;
        }
        assert_eq!(frames, 64, "every frame is emitted; no budget interrupts");
    }

    #[test]
    fn zero_bytes_in_payload_survive_escaping() {
        let mut hardener = MeshHardener::new(morph_profile(PaddingDistribution::Bucketed {
            buckets: vec![256, 512],
        }));
        let original = vec![0x00, 0x01, 0x00, 0x00, 0xFF, 0x00];

        let hardened = hardener.harden_payload(1, original.clone(), false);
        assert_eq!(hardened.bytes.len(), 256);
        let recovered = MeshHardener::recover_frame(&hardened.bytes).unwrap();
        assert_eq!(recovered.payload, original);
        assert!(!recovered.cover);
    }

    #[test]
    fn wire_sizes_collapse_to_bucket_set() {
        let buckets = vec![64u16, 256, 768, 1_200];
        let mut hardener = MeshHardener::new(morph_profile(PaddingDistribution::Bucketed {
            buckets: buckets.clone(),
        }));

        let mut seen = std::collections::BTreeSet::new();
        for i in 0..500usize {
            // Pseudorandom payload sizes 1..=1_100 with pseudorandom content,
            // including 0x00-heavy stretches. Stuffed content stays under the
            // largest bucket.
            let len = 1 + (i.wrapping_mul(2654435761) % 1_100);
            let payload: Vec<u8> = (0..len).map(|j| ((i * 31 + j) % 256) as u8).collect();
            let hardened = hardener.harden_payload(i as u64, payload.clone(), false);
            assert_eq!(MeshHardener::recover_payload(&hardened.bytes), payload);
            seen.insert(hardened.bytes.len());
        }

        // Every observed wire size is a bucket — content never leaks a
        // distinct size.
        let allowed: Vec<usize> = buckets.iter().map(|b| usize::from(*b)).collect();
        for size in &seen {
            assert!(
                allowed.contains(size),
                "wire size {size} is not a declared bucket"
            );
        }
        // And the table actually collapses variety, not just passes through.
        assert!(seen.len() <= buckets.len());
    }

    #[test]
    fn no_length_metadata_on_the_wire() {
        let mut hardener = MeshHardener::new(morph_profile(PaddingDistribution::Bucketed {
            buckets: vec![512],
        }));
        let hardened = hardener.harden_payload(1, b"size-sensitive payload".to_vec(), false);

        // No length fields, no profile identity, no JSON remnants on the wire.
        let needle = b"original_len";
        assert!(hardened.bytes.windows(needle.len()).all(|w| w != needle));
        assert!(!hardened.bytes.windows(4).any(|w| w == b"mesh"));
        assert!(!hardened.bytes.windows(4).any(|w| w == b"test"));
        // Constant wire size regardless of payload length under the cap.
        let shorter = hardener.harden_payload(2, b"tiny".to_vec(), false);
        assert_eq!(hardened.bytes.len(), shorter.bytes.len());
    }

    #[test]
    fn the_safe_tun_mtu_keeps_a_sealed_frame_inside_a_path_mtu() {
        // The ceiling plus the outer IP and UDP headers must still fit an
        // ordinary path MTU, or every full-size frame fragments.
        assert!(
            MAX_WIRE_SIZE + 20 + 8 <= 1_500,
            "frame ceiling {} plus outer headers exceeds a 1_500-byte path MTU",
            MAX_WIRE_SIZE
        );

        // A packet from a TUN at the safe MTU, sealed, must fit the ceiling.
        // A sealed packet is the plaintext plus the 16-byte AEAD tag, and its
        // bytes are pseudorandom — an all-zero payload would double under
        // escaping and is not what AEAD output looks like.
        let mut hardener = MeshHardener::new(morph_profile(PaddingDistribution::Bucketed {
            buckets: vec![256, 1_200, 1_500],
        }));
        let ciphertext: Vec<u8> = (0..MAX_SAFE_TUN_MTU + 16)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 16) as u8)
            .collect();
        let hardened = hardener.harden_payload(1, ciphertext, false);
        assert!(
            hardened.bytes.len() <= MAX_WIRE_SIZE,
            "a packet at the safe MTU produced a {} byte frame, over the {MAX_WIRE_SIZE} ceiling",
            hardened.bytes.len()
        );
        // A padding bucket above the ceiling must be clamped down to it.
        assert_eq!(hardened.bytes.len(), MAX_WIRE_SIZE);
    }

    #[test]
    fn oversized_payload_emits_unquantized_frame() {
        let mut hardener = MeshHardener::new(morph_profile(PaddingDistribution::Bucketed {
            buckets: vec![256, 512],
        }));
        let original = vec![9u8; 2_000];

        let hardened = hardener.harden_payload(1, original.clone(), false);
        assert!(hardened.bytes.len() >= 2_000);
        assert_eq!(MeshHardener::recover_payload(&hardened.bytes), original);
    }

    #[test]
    fn envelope_mode_sizes_stay_inside_window() {
        let mut hardener = MeshHardener::new(morph_profile(PaddingDistribution::Envelope {
            min_bytes: 200,
            max_bytes: 900,
        }));

        for i in 0..200 {
            let len = 1 + (i % 150);
            let payload = vec![0x42; len];
            let hardened = hardener.harden_payload(i as u64, payload, false);
            assert!(
                hardened.bytes.len() >= 200 && hardened.bytes.len() <= 900,
                "wire size {} outside envelope",
                hardened.bytes.len()
            );
        }
    }

    #[test]
    fn cover_frames_emit_at_configured_rate_and_recover_as_cover() {
        let mut profile = morph_profile(PaddingDistribution::Bucketed {
            buckets: vec![256, 512],
        });
        profile.traffic_morph.cover_traffic_ppm = 250_000; // one per four

        let mut hardener = MeshHardener::new(profile);
        let mut covers = 0;
        for i in 0..400u64 {
            hardener.harden_payload(i, b"x".to_vec(), false);
            if hardener.should_emit_cover_for(0) {
                let cover = hardener.harden_payload(10_000 + covers as u64, Vec::new(), true);
                covers += 1;
                assert!(cover.cover);
                let recovered = MeshHardener::recover_frame(&cover.bytes).unwrap();
                assert!(recovered.cover);
                assert!(recovered.payload.is_empty());
                assert!(covers_on_bucket_boundary(&cover.bytes.len(), &[256, 512]));
            }
        }
        assert_eq!(
            covers, 100,
            "expected exactly one cover frame per four real frames"
        );

        // Zero budget never covers; full budget covers every frame.
        let mut never = MeshHardener::new(morph_profile(PaddingDistribution::None));
        never.profile_mut().traffic_morph.cover_traffic_ppm = 0;
        for i in 0..10 {
            never.harden_payload(i, b"x".to_vec(), false);
            assert!(!never.should_emit_cover_for(0));
        }

        let mut always = MeshHardener::new(morph_profile(PaddingDistribution::None));
        always.profile_mut().traffic_morph.cover_traffic_ppm = 1_000_000;
        for i in 0..10 {
            always.harden_payload(i, b"x".to_vec(), false);
            assert!(always.should_emit_cover_for(0));
        }
    }

    /// Cover must reach EVERY link, not just the first one offered.
    ///
    /// A single shared accumulator crossed its threshold once and emitted on
    /// whichever link happened to be presented first, so the others never sent
    /// cover at all — leaving them distinguishable by their silence, which is the
    /// one thing cover traffic exists to prevent. This is the test that was
    /// missing; the previous cover test used a single link and could not see it.
    #[test]
    fn cover_reaches_every_link_not_only_the_first() {
        let mut profile = morph_profile(PaddingDistribution::None);
        profile.traffic_morph.cover_traffic_ppm = 250_000; // one per four

        let mut hardener = MeshHardener::new(profile);
        let mut per_link = [0u32; 3];

        // Three links, offered in a fixed order, each credited with one real
        // frame per round — which is what the daemon does for established peers.
        for _round in 0..400u32 {
            for (link, count) in per_link.iter_mut().enumerate() {
                if hardener.should_emit_cover_for(link as u64) {
                    *count += 1;
                }
            }
        }

        assert!(
            per_link.iter().all(|count| *count > 0),
            "every link must receive cover, got {per_link:?}"
        );
        let first = per_link[0];
        assert!(
            per_link.iter().all(|count| *count == first),
            "cover must be distributed evenly across links, got {per_link:?}"
        );
        assert_eq!(first, 100, "one cover frame per four real frames, per link");
    }

    fn covers_on_bucket_boundary(size: &usize, buckets: &[u16]) -> bool {
        buckets.iter().any(|b| usize::from(*b) == *size)
    }

    #[test]
    fn malformed_and_foreign_frames_rejected_or_passed_through() {
        // Not a v2 frame: passthrough.
        let raw = b"plain-bytes".to_vec();
        assert_eq!(MeshHardener::recover_payload(&raw), raw);
        assert!(MeshHardener::recover_frame(&raw).is_none());

        // v3 header but no sentinel: rejected by recover_frame.
        let mut truncated = vec![3u8, 0];
        truncated.extend_from_slice(&99u64.to_le_bytes());
        truncated.extend_from_slice(b"payload-without-sentinel");
        assert!(MeshHardener::recover_frame(&truncated).is_none());

        // The fallback frame is a valid recoverable v3 frame.
        let fb = fallback_frame(7, b"sealed", false);
        let recovered = MeshHardener::recover_frame(&fb).unwrap();
        assert_eq!(recovered.counter, 7);
        assert_eq!(recovered.payload, b"sealed");
    }

    #[test]
    fn overhead_budget_does_not_clamp_shape() {
        // Regression: the old per-packet overhead clamp collapsed bucketed
        // padding back to near-original sizes. A 100-byte payload under the
        // balanced preset's table must land on the 256 bucket, not ~108.
        let mut profile = morph_profile(PaddingDistribution::Bucketed {
            buckets: vec![64, 256, 768, 1_200],
        });
        profile.traffic_morph.max_padding_overhead_ppm = 80_000;

        let mut hardener = MeshHardener::new(profile);
        let hardened = hardener.harden_payload(1, vec![0xAB; 100], false);
        assert_eq!(hardened.bytes.len(), 256);
    }

    #[test]
    fn stats_track_frames_and_overhead() {
        let mut hardener = MeshHardener::new(morph_profile(PaddingDistribution::Bucketed {
            buckets: vec![256],
        }));
        hardener.harden_payload(1, vec![1u8; 100], false);
        hardener.harden_payload(2, vec![2u8; 100], true);

        let stats = hardener.stats();
        assert_eq!(stats.frames, 2);
        assert_eq!(stats.cover_frames, 1);
        assert_eq!(stats.payload_bytes, 200);
        assert_eq!(stats.wire_bytes, 512);
    }

    /// Test-only profile mutation helper.
    impl MeshHardener {
        fn profile_mut(&mut self) -> &mut ProtocolHardeningProfile {
            &mut self.profile
        }
    }
}
