# Imperium adversarial review — 2026-09-30

## Scope and verdict

This is a team review of the active nested checkout on
`work/unsealed-lightcone` at `765da8957d69bd75916d29931cd081c5848722ca`.
We inspected the networking, NAT, host boundary, cluster, cryptography,
Lightcone world, Atom components, secrets/persistence, runtime, controls,
toolkit, CLI, and GUI. Adjacent checkouts and the real host's network rules
were outside scope. Production source was not edited.

**Release decision: not ready as an all-traffic causal security filter or a
reliable automatic VPN cluster.** The embedded v4 Lightcone is passive,
`local_diagnostic`, `sealed=false`, and `filter_enforced=false`. The real
three-VM test delivered an undeclared UDP flow. Several other defects are
source-confirmed and need isolated reproductions before exploitability or
frequency claims can be widened. This report identifies current ownership
and repair order; it does not substitute a conventional rule engine for the
passive Lightcone.

## Fresh checks and prior measured evidence

| Boundary | Result and claim limit |
| --- | --- |
| `cargo test --offline --workspace --quiet` | Exit 0 on this checkout. Privileged host-guard tests and the documented failing Guard bypass acceptance remain ignored; a green suite does not clear those gates. |
| `cargo fmt --all -- --check` | Exit 0. |
| Two isolated same-UID nodes, one private control pathname | The second server logged `control socket already has a live server`, but its node continued running. The original socket still answered. Both owned processes stopped. This demonstrates missing fail-closed duplicate startup. The GUI cross-node action is a source-traced consequence, not a clicked GUI exploit. |
| `Store::open` with a private fixture path | `file_created=false recovered_after_reopen=false`; no persistence despite a successful `put`. |
| Standalone CLI commands with a synthetic non-existent UUID | `cluster approve` and `signatures approve` both exited 0 and printed “dispatched” without connecting to a node. This proves their misleading local acknowledgements, not an actual approval. |
| RustSec snapshot against `Cargo.lock` | 658 registry package entries; 138 advisory-version pairs checked, nine potential matches and zero unsupported range checks. These are package matches, not demonstrated reachable exploits. YARA-X's separate upstream advisory is not in that RustSec snapshot. |
| Existing committed three-VM run | All eight IPv4/IPv6 input/output/forward/loopback paths passed 3/3 baseline, 0/3 no-listener guest NFQUEUE, 3/3 recovery. All three native mesh nodes produced v4 receipts; the receiver obtained the tagged undeclared UDP packet. See `LIGHTCONE-VM-OUTCOME.md` and `evidence/lightcone-vm-20260930-phase1/`. This run preceded the present code-review turn; no second VM run is claimed. |
| GUI visual evidence | Existing native captures at 960×640 and 1360×852 were inspected. Production GUI code did not change after those captures. A new keyboard, screen-reader, scaling, or configured-backend interaction run was not performed. |

The new reproducible probe source and full process logs are retained under
the ignored `target/adversarial-review-20260930/` directory. Small selected
results and their hashes are in `evidence/adversarial-review-20260930/`.
No operator key, guest disk, private process profile, or credential was copied
into Git evidence.

## Critical security and protection failures

| ID | Finding and evidence | Required repair and acceptance |
| --- | --- | --- |
| S1 | **An admitted malicious peer can collide with another peer's session ID.** `crates/imperium-net-mesh/src/session.rs:275-288` checks duplicate peer IDs but overwrites `sessions[session_id]`. Live responder adoption uses the Hello's ID (`daemon.rs:1415-1444`), and send resolves the original peer through that ID (`daemon.rs:1937-1945`). The scenario requires an admitted peer able to choose/observe the ID. The exact plaintext-delivery exploit was not executed. | Atomically reject a session ID already owned by another peer; verify peer/session ownership at seal and address lookup. Add a three-peer isolated regression with no attacker receipt of a victim frame. |
| S2 | **A replayed or delayed valid Hello replaces an established session before key confirmation.** `daemon.rs:1415-1444` removes the incumbent before validating that the new initiator can use its key. Normal duplicate delivery can also do this. | Bind fresh attempts to a responder challenge, make retransmission idempotent, and preserve the incumbent until a confirmed new session exists. Test duplicate and replay after establishment. |
| S3 | **The shared operator signing key sits on every mesh node.** `imperium-cli/src/main.rs:837-889` loads and passes it into every daemon, which mints its own operator binding. Live admission at `net-mesh/src/daemon.rs:1347-1366` reads configured peers; it does not consult `MembershipManager` or revocation. A compromised node compromises the issuing trust root. | Separate issuer custody from node runtime: provision certified per-node identities and distribute only the operator verification key. Enforce current membership and revocation in the live handshake. |
| S4 | **The requested causal filter is absent.** Mesh UDP and inbound TUN packets are observed after I/O (`net-mesh/src/daemon.rs`, `net-host/src/bridge.rs:312-320`). The active Lightcone returns receipts but never owns a packet verdict. V4 gives identical neighborhoods to matched different endpoints and ACK progressions and lacks a positive packet-to-authorized-flow path (`net-lightcone/tests/filter_feasibility.rs:77-141`). The receiving VM's undeclared UDP arrival independently confirms non-enforcement. | Train and validate a new condition-sensitive, packet-bound world with real host facts; hold packets at a separately owned synchronous host boundary. Unknown, unsupported, late and unexamined traffic must fail closed. Preserve passive geometry and keep the world unsealed while expanding it. |
| S5 | **A delayed mesh send can pass after mesh-only Engage acknowledgement.** `daemon.rs:1933-1945` tests kill state before `seal_for_peer`, which can sleep (`1912-1915`), then sends without a final synchronized check. Cover frames have a similar delayed path. This is source-confirmed; the race was not injected in this review. | Cancel pending sends and synchronize the final send point with Engage. Verify data and cover traffic under forced jitter. The optional host guard is a separate explicit operator control. |
| S6 | **Inbound peer pins and source ranges lack full enforcement.** The key pin is checked in HelloResponse but not incoming Hello (`daemon.rs:1361-1377,1668-1689`). `net-host/src/bridge.rs:297-312` writes authenticated payloads without checking that source IP belongs to `MeshInbound.peer_id`. | Verify pins in both handshake roles before session replacement. Bind inbound source prefixes to the authenticated peer at the TUN write boundary. |
| S7 | **Wire framing exposes protected metadata.** `net-mesh/src/hardening.rs:205-211,233-254` exposes the cover flag and a clear sentinel marking ciphertext length; ciphertext length minus the AEAD tag reveals plaintext length. Flipping the unauthenticated cover flag can turn a valid data frame into discarded cover after authentication. | Replace the current frame format with bounded framing whose content length, cover designation, and padding are authenticated and encrypted. Recheck MTU and IPv4/IPv6 overhead against worst-case byte expansion. |

## Runtime, NAT, and operational defects

| ID | Finding and evidence | Required repair |
| --- | --- | --- |
| R1 | **Two nodes can share one apparent control surface.** The second socket bind returns (`imperium-cli/src/control.rs:632-641`); `main.rs:658-695` continues and can launch a GUI with that same pathname. The isolated two-node probe reproduced the bind refusal and continued second node. | Await control startup and abort duplicate startup, or assign a verified per-instance endpoint. A console must only address the node whose state it displays. |
| R2 | **SIGTERM skips orderly teardown.** The coordinator waits for Ctrl-C only (`imperium-runtime/src/lib.rs:295-297`). `main.rs:713-719` then owns backend/guard cleanup. An engaged nftables table is deliberately persistent without Drop (`net-host/src/firewall.rs:39-41`). | Route SIGTERM through the same bounded shutdown path and test inside a private network namespace. Do not infer guard cleanup from TUN routes disappearing automatically. |
| R3 | **Production deployment reports synthetic convergence.** `imperium-runtime/src/deployment.rs:103-323` constructs temporary managers, fabricates sessions without handshakes (explicit comment at 224-227), and reports `accepted=true` with their count. | Replace the production handler with actual remote provisioning, receipt and rollback. Keep the simulation available only as a plainly labeled rehearsal. |
| R4 | **Standalone administrator commands acknowledge actions without applying them.** `imperium-cli/src/main.rs:1401-1479` prints success for membership/signature actions. Token minting makes a fresh unrelated cluster/key; import only parses JSON. Two no-node commands were reproduced with exit 0. | Connect these commands to the running private service and await applied/rejected outcomes. Mint/import against the real persistent cluster identity. |
| R5 | **Automatic failover does not drive the live transport.** `net-transport/src/orchestrator.rs:209-239,555-569` changes labels and publishes `net.transport.command`, which has no active consumer. Manual `LiveTransportRuntime` transitions are real but subscribe to other requests. | Use the verified manual transition executor for automatic failover and publish success only after a live path probe. Test an actual child failure. |
| R6 | **Responder-side budget rotation strands a session.** `net-mesh/src/daemon.rs:1895-1908,2046-2059` removes a spent session, while accept-only peers have no address with which to initiate (`842-855`). Existing tests only exhaust the dialer. | Implement authenticated renewal from either side or preserve a verified reconnect endpoint; test both directions. |
| R7 | **Automatic NAT probing, relay path execution, and MASQUE tunnel activation are planning/configuration paths.** NAT's CLI currently reports unavailable; `net-transport/src/masque.rs:44-66` does not open a tunnel. | Complete real probe/selection/execution and receiver-side path checks before enabling controls or claiming traversal. Keep planned, configured and established states separate. |
| R8 | **An unauthenticated IP can consume handshake reassembly capacity.** Fragment assembly occurs before the normal gate; `net-mesh/src/wire.rs:391-397` uses IP:port as the “source” quota. Changing eight source ports can fill 32 slots for their lifetime. | Apply address-level/fair limits and early admission before expensive allocation. Retain existing finite global bounds. |
| R9 | **Startup can miss the default mesh hardening profile.** Initialization publishes before the daemon subscribes (`imperium-cli/src/main.rs:613-645`; `net-transport/src/lib.rs:49-54`); the native bus has no replay. | Apply the profile directly before enabling the mesh and verify the actual data-plane state. |
| R10 | **Additional boundary gaps:** roaming tries only the first eight sessions (`daemon.rs:1957-1975`); the pre-session host queue lacks an establishment wake (`net-host/src/bridge.rs:207-225`); public in-place rekey retains the old replay window (`net-mesh/src/session.rs:130-149`). | Add fair authenticated session demultiplexing, queue wake/timeout, and replay epoch reset. Label in-place rekey a library defect: the active daemon currently replaces sessions instead. |

## Detection, storage, claims and interface

| ID | Finding and evidence | Required repair |
| --- | --- | --- |
| F1 | **Sensing and Guard are mostly disconnected from production traffic.** The CLI registers the signature activation strand, but no production caller of `SignatureEngineSensor::scan`, `ProbeSensor`, `EnvelopeSensor`, `StrainerStack`, or `Guard::knock` was found. | Wire packet/event producers at each owner boundary, verify actual scans/effects, then report detection coverage. Approval readiness alone is not traffic inspection. |
| F2 | **The store cannot persist.** `imperium-store/src/lib.rs:29-31` discards its path. The node builds `Store::in_memory` (`imperium-cli/src/main.rs:1123`); extracted signatures, memory log and cluster simulation state are likewise process local. The independent reopen probe confirmed loss. | Implement tested durable storage and restore for state that must survive, with explicit private permissions, corruption handling, and recovery checks. Keep volatile data labeled as such. |
| F3 | **Secrets and forensic components are unfinished.** `imperium-secrets-broker` holds only an unused vault field, `imperium-secrets-threshold` contains comments, `imperium-secrets-audit` only data types, and `imperium-memory-projection` only stores an `Arc`. Vault sealing is a Boolean around a plaintext memory store. | Complete and test these boundaries before claiming threshold signing, persistent secret custody, or a forensic projection. Do not equate software zeroization of returned values with full store protection. |
| F4 | **The two default toolkit actions perform no capture.** `imperium-cli/src/main.rs:1231-1255` registers only manifests; the toolkit treats them as state-only. | Add bounded, supervised executors and return a real artifact/completion receipt. Retain the existing executor-capable toolkit. |
| F5 | **GUI status can be stale or misleading.** It does not consume `TransportControlStatus`, keeps Rotate profiles disabled, and can display an old host-block confirmation after another client disarms (`gui/src/lib.rs:165`; `views/transport.rs:65,186`). Lightcone status also estimates backlog from published minus receipt count, which duplicate replay can mask (`imperium-cli/src/control.rs:901-923`). | Subscribe to confirmed state, expose freshness and unknown status, and count unique packet observations and acknowledgements. Test keyboard/scaling/screen-reader behavior. |
| F6 | **Atom evidence does not support some stated acceptance.** Chaos position evaluation discards the computed state and supplies constant taps (`imperium-atom-eval/src/main.rs:499-534`). Longevity and route order variants do not execute their named compositions (`longevity-engine/src/lib.rs:97-113`; `route-engine/src/lib.rs:96-112`). The no-copy VPN observer is only constructed in its test, despite `STATUS.md`'s live-integration claim. | Preserve the failed/invalid receipts, correct the actual mechanisms and claims, and rerun frozen matched order, chaos, domain, base-only/no-base, and ablation controls. Connect a validated observer at the real frame boundary only after those gates. No physical quantum or no-copy security claim follows from these local experiments. |
| F7 | **Additional library correctness:** the Guard source tag can reset its budget (an ignored failing test already records this), `immutable-stack::fork_report` compares equal values rather than shared `Arc` identity, and its step receipt labels cumulative payment as per-step absorption. | Fix the measured invariant and add focused regressions. These are currently separate library boundaries, not active mesh protections. |
| F8 | **GUI shutdown and concurrency still need exercise.** Control steps of a complete kill-switch transition can interleave; managed wrapper descendants may survive direct-child termination; a GUI can outlive backend shutdown. | Serialize the whole transition, own child process groups, and test shutdown with an open window in an isolated session. |

The saved 960×640 and 1360×852 screenshots show a consistent dark palette,
clear navigation, and no visible clipping in those frames. Transport has
considerable empty space and status text is small. The greatest usability
problem is accurate safety information: a prominent current protection state
should distinguish active mesh, actual detection, host block, and causal
filter enforcement. A zero threat count or a green initialized subsystem
must not imply those functions are active.

## Dependency triage

The `Cargo.lock` match against the downloaded RustSec advisory database found
nine potential advisory-version matches. They include affected `anyhow 1.0.102`,
`crossbeam-epoch 0.9.18`, `memmap2 0.9.10`, `rsa 0.9.10`, and `wasmtime 43.0.2`
(three advisories), plus unmaintained `bincode 2.0.1` and `ttf-parser 0.25.1`.
One Wasmtime entry describes a [filesystem sandbox escape](https://rustsec.org/advisories/RUSTSEC-2026-0269.html).
These are **package matches**, not confirmed vulnerable operations in the
running Imperium path. In particular, `rsa` is transitive through YARA-X;
the examined hybrid handshake does not call RSA private-key operations.
Feature/API reachability and the final resolved dependency graph need a
follow-up gate during upgrades.

Separately, locked `yara-x 1.17.0` falls under its maintainer's
[unsafe deserialization advisory](https://github.com/VirusTotal/yara-x/security/advisories/GHSA-2jx3-ff3v-j7jj),
fixed in 1.19.0. We found no application call to the affected
`Rules::deserialize` API. Upgrade and recheck compatibility before expanding
untrusted rule loading. The current `ml-dsa 0.1.0` is newer than the patched
floor in [RUSTSEC-2025-0144](https://rustsec.org/advisories/RUSTSEC-2025-0144.html);
do not classify that historical advisory as a current package match.

## Keep, repair, replace

**Keep and harden:** the hybrid Ed25519/ML-DSA checks, role-separated AEAD
keys and replay-window placement, finite handshake resource bounds,
longest-prefix multi-peer routing, the owner-private same-UID control socket,
supervised strands, explicit no-filter GUI warning, exact-world hash loader,
manual backend transition executor, and reproducible VM lab. Tests and
source support these narrow behaviors, not a formal crypto proof or general
production readiness.

**Repair in place:** session-map ownership, handshake replay/freshness,
responder rekey, inbound pin/source checks, atomic kill-switch ordering,
startup profile application, real automatic failover, truthful GUI/control
state, persistent store, sensing wiring, and Atom experiment mechanics.

**Replace the owning implementation:** synthetic production deployment with
real provisioning and receipts; exposed wire length/cover framing with an
authenticated format; the v5 trainer objective that drops polarity and
conditions with a versioned condition-aware experiment. Preserve the passive
Lightcone and its failed evidence rather than turning it into a verdict engine.

## Acceptance sequence and limits

1. Freeze source and acceptance cases for S1–S7. Execute three-peer
   session-ownership, replay, wrong-pin, responder-rekey, jitter/Engage,
   source-prefix, fragment capacity, and exact receiver tests in disposable
   environments. Preserve each failure.
2. Make every operator action report an applied state from the intended node.
   Exercise duplicate GUI/control startup, SIGTERM recovery, concurrent
   Engage/Disarm, real-child automatic failover, real NAT traversal and
   synthetic-vs-live deployment status.
3. Train a fresh conditioned network world with matched positive, negative,
   unknown and held-out flow cases. Then test the separately owned synchronous
   release gate across the specified host/VM paths. The existing NFQUEUE
   no-listener control proves interception feasibility only; no accept/drop
   listener or causal gate is installed by this review.
4. Reassess package advisories at the resolved, feature-aware call paths and
   verify persistence, restart recovery, GUI status freshness and accessibility.
5. Only after those gates should release wording change. Keep Lightcone
   `sealed=false` and `filter_enforced=false` throughout this expansion.

The attempted delegated live session-collision attack reproduction was
rejected by automatic cybersecurity review as a possible risk; it was not
executed. A narrower in-memory follow-up was unavailable because the worker
service returned a model-access error. S1 is therefore a source-traced
high-priority finding awaiting safe reproduction. Other source-only issues
above are explicitly distinguished from the fresh runtime probes and the
earlier real-VM acceptance. No production behavior was changed in this review.
