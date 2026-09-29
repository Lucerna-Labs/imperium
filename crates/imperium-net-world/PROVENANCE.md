# Network Lightcone provenance

This crate vendors the exact passive runtime and embedded pack from the
standalone **network-lightcone** project:

- Source: `/home/jesse/Desktop/Projects/network-lightcone-standalone`
  (derived from Atom OS snapshot `db5f6624ac35ebe040d769511555f41fa2923c14`)
- World: `atom-network-causal-v4`, schema 3, revision 4
- Scope: 208 source-bound network and defensive control concepts,
  188 typed causal relationships, 29 pinned sources
- Platform: `local_diagnostic`, **`sealed = false`** (deliberately unsealed)

| Artifact | SHA-256 |
|---|---|
| `src/world.bin` | `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf` |
| `evidence/manifest.json` files.world.bin | `7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf` |
| geometry.json | `2375f3dd1700fcb7aac1de7d5f64b25a8c9bc7a739d107fcc94da1b159ecc2fa` |
| world.json | `06dd1dbe35847a1e13146a0d8dfc2bc70bc9f27f44b07354ceba83d077fb9ff2` |

The copied `manifest.json` and `training.json` under `evidence/` retain the
complete local diagnostic receipt.

## What changed from the previous vendored revision

The prior vendored pack was `atom-network-causal-v3` (`e6a97fde…`, 63 concepts /
66 relationships) with a runtime capped at `MAX_NODES = 128` / `MAX_EDGES = 256`.
The v4 world does not fit that cap, so the runtime was replaced together with
the pack: `MAX_NODES = 256` / `MAX_EDGES = 512`, with the receipt bitmaps sized
from `NODE_WORDS` / `EDGE_WORDS` rather than hardcoded widths. The admission
algorithm, policy, receipt digest domain and passivity guarantees are unchanged.

The v3 crate is preserved verbatim at `.lightcone-v3-backup/` for recovery
(Imperium is not a git repository, so that directory is the recovery path).

## Use

Imperium uses it only for passive exact-graph admission and receipts. The
Lightcone does not score, judge, authorize or block. Mesh framing, AEAD, replay
checks, strainers, sensors and policy remain separate owners. `imperium-net-observer`
supplies structural wire observations (Ethernet, ARP, IPv4, IPv6, UDP, TCP,
ICMPv4/v6, Neighbor Discovery); payload text cannot select world nodes.
