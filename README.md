# Imperium

Imperium is an adaptive defensive VPN cluster runtime. It runs as one Rust
workspace and one `imperium` binary, with subsystems communicating through the
typed in-process bus in `imperium-protocol`.

The active build includes:

- cluster membership, bootstrap tokens, config gossip, and hybrid PQC signing/key exchange
- mesh peer/session management over direct UDP, with authenticated address rebinding;
  STUN, coordinated probing, and relay selection currently produce plans but have no
  live mesh probe executor
- transport hardening profiles with rekeying, FEC, and probe deception
- a mesh data-path kill switch for the configured split-tunnel routes; it does
  not guard host DNS, firewall, or traffic outside the mesh
- an opt-in Linux host egress guard (`--host-guard`): Armed permits ordinary
  traffic, explicit Engage blocks non-loopback output, and Disarm restores it
- length-hiding frame normalization on the mesh data path: bucket/envelope packet-size
  quantization, sentinel-delimited payloads with no length fields on the wire, pseudorandom
  padding, and deterministic cover traffic (`imperium-net-mesh`)
- session AEAD on the mesh data path: ChaCha20-Poly1305 with HKDF-split direction keys,
  counter nonces, and a 64-frame sliding replay window (`imperium-net-mesh`)
- the normality envelope sensor: a one-class anomaly model trained exclusively on normal
  network activity (robust MAD trimming excludes poisoned windows at fit time), SHA-256
  digested, publishing ThreatAssessment for anything outside the learned envelope
  (`imperium-net-sensors`)
- the **unsealed v4 network Lightcone** has 208 concepts, 188 relations, 48D
  geometry, and an observer-only spatial `(x,y,z,w)` shadow. Its current
  runtime path emits exact-graph receipts; the trained-world traffic filter
  gate requested by Jesse is not yet wired. The active mesh offers UDP sends and
  receives plus host TUN packet observations through a bounded queue. Only
  structural metadata and a hash of the original bytes reach the shared bus;
  the supervised Lightcone strand emits sequenced receipts. Drops and receipt
  failures remain visible. The world is `local_diagnostic`, `sealed=false`.
  The current code does not yet enforce Jesse's corrected design that
  untrained/unadmitted network traffic cannot pass (`imperium-net-world`,
  `imperium-net-observer`, and `imperium-net-lightcone`). The older in-memory
  `NetworkWorldTap` is a separate diagnostic path, not the supervised receipt
  stream.
- the older ring propagation experiment remains available through the legacy
  `imperium-net-mesh::lightcone` API for compatibility and adversarial
  research. Its recorded geometry/calibration holes remain visible in the
  `lightcone_adversary_*` tests; it is not the authoritative RTX world
- sensor/signature flow, operator-gated signature extraction, and dormant toolkit activation
- auto VPN cluster deployment orchestration with Ordo-facing apply/status controls

The old watchtower subsystem has been removed. Closed-loop extraction is driven
by deterministic sensors or operator-selected events, then gated by operator
approval.

## Build And Test

```bash
cargo check
cargo test
cargo build --release -p imperium-cli
cargo test -p imperium-net-mesh --test rtx_world_vpn_safety
cargo test -p imperium-net-mesh --test lightcone_live_bus
scripts/mesh-multipeer-test.sh  # isolated three-node TUN/Lightcone check
```

See `LIGHTCONE-CLUSTER-ACCEPTANCE.md` for the measured v4 cluster run,
fault drills, and limits before any sealing decision.

Simulation coverage lives in:

- `crates/imperium-runtime/tests/hardening_simulation.rs`
- `crates/imperium-runtime/tests/cluster_vpn_simulation.rs`
- `crates/imperium-runtime/tests/bus_topic_pairs.rs`

The sibling `ordo-device-peer` project is the Ordo bridge:

```bash
cargo check
cargo test
```

## Run

Start the runtime (headless), or with the operator console:

```bash
cargo run -p imperium-cli -- node start        # headless
cargo run -p imperium-cli -- node start --gui  # operator console
```

To enable the live Xray/AmneziaWG process controls, supply exact installed
backend binaries, configs, activation commands, and active-path probes in a
profile JSON file, then start with
`--transport-profiles <path> --active-profile <id>`. See
[the live transport schema](crates/imperium-net-transport/LIVE-TRANSPORT.md).
The node refuses a configured transport that fails its startup or path probe.
No backend binary or configuration is bundled.

`--host-guard` separately installs an owner-scoped nftables guard and requires
CAP_NET_ADMIN plus libnftables. It starts Armed without blocking host traffic.
`vpn killswitch engage` applies host blocking before the mesh command; Arm and
Disarm resume the mesh first and then allow host traffic. `vpn health` reports
the host mode and whether host egress is blocked separately from mesh health.

## Operator Console

`--gui` opens the Imperium console, an in-process egui crate
(`imperium-gui`) that subscribes to the same typed bus events every other
subsystem sees and publishes the same operator commands the control socket
dispatches — one process, one runtime, one bus, per the thesis.

The console provides a dashboard (orchestrator state, kill switch, threat
telemetry, deployment status), a live threat feed, the signature approval
gate (approve/reject staged candidates), transport controls (mesh kill switch
and hardening presets), and a filterable bus
activity view. Closing the console window shuts the node down cleanly.
Profile rotation and active transport selection require a successfully started
live transport runtime. Aggressive NAT probing remains unavailable until its
runtime handler is present.

The runtime exposes its control surface at a Unix domain socket:

```text
$XDG_RUNTIME_DIR/imperium/control.sock
```

falling back to `/tmp/imperium-<uid>/control.sock` when `XDG_RUNTIME_DIR` is unset
or not owner-private.
The socket directory is owner-only, the socket is mode `0600`, and the server
checks each connecting process's Unix credentials. A live server's socket is
never replaced by a second node.

The control socket accepts lines such as:

```text
vpn health
vpn lightcone status
vpn profile rotate [protocol]
vpn transport set-active <protocol>
vpn nat aggressive on|off
vpn killswitch arm|disarm|engage [reason]
vpn masque configure <json>
vpn hardening preset balanced|resilience|fortress [protocol]
vpn hardening apply <json>
vpn deployment apply <json>
vpn deployment status
vpn toolkit activate <tool> [trigger]
signatures pending
signatures approve <candidate_id>
signatures reject <candidate_id> [reason]
signatures extract <event_id>[,<event_id>...]
signatures show <candidate_id>
shutdown
```

`vpn health` reports the bound mesh socket, runner, established peers, and host
bridge separately. Without `--mesh-bind`, it returns `status: unavailable`.
When `--host-guard` is enabled, it also reports `host_guard_installed`,
`host_guard_mode`, and `host_egress_blocked`; the host guard is unavailable by
default.
`vpn lightcone status` reports the current v4 pack identity, strand lifecycle,
receipt counts by direction and frame format, bounded observer drops, and
`sealed: false`. It reports `filter_enforced: false` and
`filter_mode: diagnostic_only` while forwarding is receipt-only. `working`
describes strand and receipt activity; it does not prove filtering, network
security, or a sealed world.
Profile rotation and active transport selection apply only with explicitly
configured live profiles. Their replies report `ok` after the backend and
active traffic path probes pass; absent profiles, failed probes, and missing
alternates return `status: error`. The Xray/AmneziaWG boundary still requires
a live test with the operator's installed binaries and configs. Aggressive NAT
probing returns an error while its runtime executor is unavailable.

`vpn deployment apply <json>` publishes a typed `VpnDeploymentPlan`.
`vpn deployment status` publishes a typed `VpnDeploymentStatusRequest`; the
runtime responds with the latest deployment status, or an explicit empty-state
status if no deployment has run yet.

`signatures pending` and `signatures show <candidate_id>` read from the live
runtime staging area when the node is running.

## Ordo Integration

The sibling `ordo-device-peer` project advertises Imperium as an
Ordo-controllable VPN peer. Its `imperium_vpn` adapter maps typed
`VpnControlCommand` values to the control socket commands above, including:

- `DeploymentApply { plan_json }`
- `DeploymentStatus`
- NAT, hardening, kill switch, MASQUE, toolkit, signature, and shutdown controls

The NAT aggressive control is currently unavailable at the node boundary and
returns an explicit error to callers.

The bridge depends on `ordo-protocol` and `ordo-transport` from the
`Ordo-Light-Working` sources.

## Ship Notes

Current release verification:

- `cargo check` passes for Imperium
- `cargo test` passes for Imperium
- `cargo check` passes for `ordo-device-peer`
- `cargo test` passes for `ordo-device-peer`

Platform: Linux only. The control surface is a Unix domain socket (see Run
section); Windows support was removed.
