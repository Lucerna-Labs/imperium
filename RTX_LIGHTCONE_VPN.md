# Historical v3 RTX Lightcone integration

This document and `RTX_LIGHTCONE_INTEGRATION_RECEIPT.json` record the 2026-09-21
v3 loopback integration. Their `e6a97fde…` pack hash and no-TUN limitation are
historical. They are not the active pack or a seal receipt.

The current checkout embeds the **v4** `local_diagnostic` world
(`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`,
208 concepts, 188 relations, 48D, `sealed=false`). Active mesh UDP and host
TUN paths now offer bounded structural observations to a supervised passive
Lightcone strand. The shared bus carries structure and the original-byte hash,
not raw application payload. `vpn lightcone status` exposes live receipts,
strand lifecycle, and observer drops. Run `scripts/mesh-multipeer-test.sh` for
an isolated whole-cluster check before considering any seal. See
`crates/imperium-net-world/PROVENANCE.md` for current pack provenance.

## Historical installed boundary

Imperium vendors the exact local-GPU Atom network world in
`crates/imperium-net-world`.

- source Atom OS commit: `db5f662`
- device: NVIDIA GeForce RTX 5070 Ti through JAX 0.11.2
- world pack SHA-256:
  `e6a97fde814d04ea4a5b306b19aad2cf98d370fbedd0d364dadd11cf497d4eae`
- geometry SHA-256:
  `d65547632653e42c3288c2ccda663577daee71bbcc1b7ccac291c0a265e32689`
- status: `local_diagnostic`, `sealed=false`

`MeshTransport` verifies this pack when constructed. Imperium mesh startup
also verifies it and records the pack hash. Every outbound hardened/encrypted
datagram and every inbound wire datagram receives an immutable passive
admission receipt. Payload bytes cannot select graph nodes or mutate the world.

Lightcone does not reject traffic. Imperium's v3 frame parser, session AEAD,
replay window, strainers, envelope sensor, kill switch, and host policy retain
their separate authority.

## Safe loopback test

`crates/imperium-net-mesh/tests/rtx_world_vpn_safety.rs` uses real Tokio UDP
sockets bound only to `127.0.0.1`. No datagram can leave the computer.

The fixtures are inert byte strings. They resemble a SYN sweep label, path
traversal request, SQL injection, script tag, and high-volume repeated bytes,
but no shell, SQL engine, browser, filesystem operation, or external address is
invoked.

Observed result:

- one valid encrypted mesh frame accepted and decrypted;
- one replay rejected;
- one tampered encrypted frame rejected;
- five unauthenticated probe-shaped datagrams rejected at mesh framing;
- five inert malicious-looking fixtures rejected by the strainer stack, with
  five rejection events published on the typed bus;
- four hostile traffic-shape controls outside the normality envelope;
- sixteen held-out benign controls inside the envelope;
- one outbound and eight inbound RTX-world observations retained with the exact
  pack hash;
- payload text unable to inject Lightcone seeds;
- complete Imperium workspace test suite passed.

Run:

    cargo test -p imperium-net-mesh --test rtx_world_vpn_safety -- --nocapture
    cargo test

## Evidence boundary

This proves the RTX world is connected to Imperium's encrypted UDP mesh and
that the local rejection owners refuse the tested inert fixtures. It does not
prove that all malicious traffic is detectable, and it does not claim the
passive Lightcone performed rejection. The checkout currently implements a
mesh runtime and loopback/live UDP primitives rather than a host TUN adapter;
this test therefore validates the owning Imperium mesh boundary without
altering the host VPN route or sending external traffic.
