# VPN cryptographic freeze

This file freezes the VPN trust path while behavior work continues around it.
The current goal is a **functional** VPN protocol that can then be improved; no
cryptographic mutation is required to pursue that goal.

## Frozen files and hashes

These files must not change cryptographic semantics during Stages 1-4:

| File | SHA-256 |
|---|---|
| `crates/imperium-net-crypto/src/kex.rs` | `7e72edb1072860cb565bb880929d85180db9280f8d2f856cc393a126c9496284` |
| `crates/imperium-net-crypto/src/lib.rs` | `6da8cf9b7e6f16aa33758f0a1e395d7bcbc03e8e6dbd7be33f941ae9b316ebd7` |
| `crates/imperium-net-crypto/src/sign.rs` | `fee2988b664407e426e8f9754a943052c16d424db3ee3ee44624dd0756fec954` |
| `crates/imperium-net-mesh/src/handshake.rs` | `72b8984d8db760d0a27fd18b7e36316c8e8341325067e27abe19b1ae87ea61cd` |
| `crates/imperium-net-mesh/src/crypto.rs` | `46ce09d3171e67c49549bc36dab0ac3c38ad9842c71caa011f8a3eef89b72560` |
| `crates/imperium-net-mesh/src/session.rs` | `4e1f98ca450652b141d38898dd1fbc125f34bb907b32fff013b52642abda162a` |
| `crates/imperium-net-mesh/src/wire.rs` | `e2ba1fba72e16f6832aad67ebe1f5b01746a4056d83a7312c17b55ccee189dd7` |
| `crates/imperium-net-mesh/src/destination.rs` | `0184044b8404d9d32f38a5add43b1f4def0c38738a2a6ba39790a7e19702afaf` |
| `crates/imperium-net-mesh/src/gate.rs` | `3e65c2503fd133e241742b873099a30ef0332d13b81f8ef407eb41f2036e010f` |
| `crates/imperium-net-mesh/src/hardening.rs` | `699235d83151ae6d93e2485c881605002093d0cf804adc0119b0a442f2b967e4` |
| `crates/imperium-protocol/src/lib.rs` | `3b36fcf53e1711d67f28204efa62d3a0d7c75c85e31a326f15cbee6bcc5a9af8` |

Scope of freeze:

- Hybrid X25519+ML-KEM-768 key exchange, including KDF salts/labels/info strings.
- Hybrid Ed25519+ML-DSA-65 signatures, bindings, identity/cluster checks, and
  membership admission semantics.
- Direction-key derivation, AEAD algorithm and use, nonce layout, counters, replay
  acceptance, rotation/rekey semantics, and key handling/zeroization.
- Handshake verification order, mutual-dial handling, transcript coverage, and
  failure semantics.
- Wire discriminants, fragmentation bounds, nested-fragment refusal, unknown-byte
  behavior, MTU ceiling arithmetic, and TUN/default-route refusal.
- Cover rate/shape, padding buckets/envelope, persona behavior, payload bytes,
  and all private/crypto material handling.
- Existing `ProbeProfile` non-fusion constraints.

 Rust-format-only edits may be documented separately; any cryptographic semantic
 change must be proposed, reviewed, re-hashed, and recorded here before use.

## Redacted tap schema for functional VPN telemetry

These taps are the only behavioral input new atom crates may consume. They emit
fixed, bounded, non-linkable observations; they never carry behavioral
conclusions.

### TimingTap

- `frame_counter: u64`
- `inter_arrival_bucket: u8`
- `delay_bucket: u8`
- `jitter_ceiling_ms: u16`
- `cadence_sufficient: bool`
- `coalesced: bool`

Purpose: pacing/jitter observations without destination, session, address, or
payload information.

### LongevityTap

- `session_epoch: u64`
- `bytes_sealed_bucket: u8`
- `idle_bucket: u8`
- `rotation_due: bool`
- `reauth_required: bool`
- `expiry_reason_code: u8`

Purpose: session lifetime, rotation cadence, idle/expiry classes. No keys,
seeds, nonces/counters, identities, or traffic payload.

### RouteTap

- `destination_class: u8`
- `prefix_length: u8`
- `candidate_count: u8`
- `best_prefix_length: u8`
- `rebind_count: u8`
- `path_stable: bool`

Purpose: longest-prefix/path choice among real established candidates. No
addresses, hostnames, payload routes, labels, or guessed/unknown destinations.

### Global redactions

The following are prohibited in all taps, events, logs, or derived records:

- user plaintext or ciphertext body bytes;
- private keys, seeds, session keys, AEAD nonces/counters beyond already-visible
  operational accounting, and identity private material;
- cookies beyond length/class and raw address-keyed linkable identifiers;
- free-form logs, free-form strings, dynamic topics, and dynamic vocabulary;
- labels, threat names, verdicts, fused scores, target mappings, admission or
  revocation conclusions, and revocation semantics.

Tap schemas use static field layouts and static topic/socket names only. Any
schema change requires versioning, blind-corpus regeneration, and an updated
frozen-metrics table.
