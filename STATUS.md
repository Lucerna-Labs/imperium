# STATUS — what works, what doesn't, what needs improvement

One source of truth for the Imperium build state. Append dated entries; do not
rewrite history. Every claim here names its evidence: a gate output, a hash, or
an explicit "UNVERIFIED". Anything without evidence is a belief, not a fact.

Rules for entries: state the observation, the command that produced it, and the
boundary of what it proves. Failed results are preserved alongside passes —
deleting a failure deletes the reason the next design is shaped the way it is.

---

## Legend

- **GREEN** — gate ran, passed, numbers recorded.
- **RED** — gate ran, failed, numbers recorded, owner assigned.
- **PENDING** — gate not yet run or not yet verified by the person signing this file.
- **INFORMATION** — structural fact about the tree (layout, provenance, design), not a test result.
- **LIMIT** — an explicitly known boundary of something that otherwise works.

---

## 2026-09-26 — Spiderweb cutover, Phases 0–1 (verified by operator session)

### INFORMATION — bus vendored into the repository

Spiderweb-Bus-Next is vendored at `vendor/spiderweb-bus/`: 89 files, 1.3 MB.
Whole-tree copy of the **working tree** (`git archive HEAD` would have dropped
the cognitive engine — all 9 untracked files were verified present after copy).

- Source HEAD: `b9e336cb3393164ee80520138928493d84e6a290` (2026-06-27).
- Working state frozen: 79 files modified, 9 untracked.
- Provenance: `vendor/spiderweb-bus/PROVENANCE.md` (lightcone format).
- The `../../../../Spiderweb-Bus-Next/…` path deps are gone from all workspace
  manifests. 41 workspace members: 26 Imperium + 15 vendored.

### GREEN — vendored bus tests inside Imperium's workspace

`cargo test -p spiderweb -p spider`, all 15 vendored members building.
**197 passed / 0 failed / 3 ignored across 46 suites.** Includes the untracked
cognitive engine's `cognitive.rs` (16) and `cognitive_bus.rs` (4), plus the
lifecycle/recovery/install-order suites.

### GREEN — the existing Imperium workspace still compiles

`cargo check --workspace` clean at the Phase 1 checkpoint (exit 0), after the
vendoring and the `imperium-bus` dependency redirect to `{ workspace = true }`.
No consumer touched at that point.

### INFORMATION — pre-change recovery

`.spiderweb-pre-vendor-backup/` holds `imperium-bus/` (3 files), all 26 member
manifests, root `Cargo.toml`/`Cargo.lock`, and `.bus-backup/`, with
`MANIFEST.md` recording hashes and copy-pasteable restore commands. Imperium is
not a git repository; that directory is the recovery path. A lockfile package
collision surfaced during wiring (external `spider` vs vendored `spider` both
`v0.1.0`) and was resolved by the redirect, not by regenerating the lock.

---

## 2026-09-26 — Spiderweb cutover, Phase 2 (in progress, worker running)

Cutover design and ownership model recorded at `SPIDERWEB-CUTOVER.md` (root).

### GREEN — all 14 Imperium crates converted to the native bus

`cargo check --workspace` verified by operator: **0 errors, 0 warnings.**
The `Arc<Bus>` + `Mutex<Supervision>` ownership model is gone from production
code. `crates/imperium-bus` is **deleted**, its root-manifest line removed.
Subsystems depend on the vendored `spiderweb` directly; the
"never depend on `spiderweb`" mandate died with `STRAND-CONVERSION.md`.

### GREEN — spider registered natively with cognition policy intact

`crates/imperium-cli/src/supervision.rs` owns `SPIDER_STRAND_NAME`, all four
cognition env vars (`IMPERIUM_SPIDER_COGNITION`, warmup, heartbeat-stall),
`cognition_config_from*` and the `SpiderSeed` (crash-wall-only default / cognitive
opt-in). `kernel.register_spider(…)` verified in source; all nine
`*_supervision.rs` files register the real `spider::Spider`; the
`the_same_stuck_stimulus_is_silent_with_cognition_off` control still exists.

### GREEN — network-lightcone intact through the cutover

`crates/imperium-net-world/src/world.bin` hashes `7afb2e711601cd52…`,
matching `PROVENANCE.md`. Still wired into the mesh via
`crates/imperium-net-mesh/src/world_lightcone.rs` and its `Cargo.toml:18`.
`cargo test -p imperium-net-lightcone`: **13 unit + 3 supervision tests pass**
(crash → restart×3 → quarantine against the native kernel). All three
`lightcone_adversary_*` tests and `pilot_supervision.rs` present.

### GREEN — lightcone supervision pilot (earlier, pre-cutover)

First crate converted; `tests/pilot_supervision.rs` proved the lifecycle
end-to-end in a prior session.

### RED — `imperium-runtime` integration targets fail and one hangs

Measured with bounded per-target runs, `--test-threads=1`:

| target | result |
|---|---|
| `--lib` | **HANGS** — no test output within 90s (was masked inside the workspace run) |
| `integration` | 4 passed, **3 FAILED** |
| `cluster_vpn_simulation` | 0 passed, **2 FAILED** (20.31s — looks like a convergence loop that never converges) |
| `hardening_simulation` | 6 passed, **1 FAILED** |
| `bus_topic_pairs` | 3 passed, 0 failed |

Leading hypothesis (not yet proven): a `subscribe_prefix` callback only fires
once the kernel is running, while the shim handed back subscriptions that were
already registered — events published before the loop thread starts are simply
gone, and a consumer waits forever. Needs confirmation against the worker's fix.

Also unresolved in the same area, from worker report: `imperium-net-transport`
(2 supervision files) and `imperium-net-toolkit` (3 test targets) test errors.
`cargo test --workspace` therefore **cannot run yet**; any workspace-wide test
total claimed before these compile is meaningless, and the earlier
`state-tests-green` snapshot meant *compiles*, not *passes* — recorded here so
the distinction survives.

### LIMIT — backpressure changed owners

`Err(BusError::Lagged(n))` no longer exists for Imperium code; native callbacks
never lag and there is no per-subscriber queue. A slow consumer now silently
drops instead of being told a gap occurred. `imperium-runtime`'s `select!` loop
and `imperium-gui` must own explicit bounded queues. This is the correct fix
(the property belongs to the consumer) but it is a behaviour change, and under
load it surfaces as flakiness — watch for it in exactly those two crates.

### PENDING — end-to-end boot proof

The gate that turns "wired in" into "running": bounded
`cargo run -q -p imperium-cli -- node start` showing
`[kernel] 🕸️ <name> registered (N inputs, M outputs)` with `spider` among them.
Not run. Also pending: `cargo tree -p imperium-cli` confirming zero
`imperium-bus` edges, and the vendored 197 re-check after the cutover edits.

---

## 2026-09-26 — VPN trust path (verified by source reading)

### INFORMATION — the trust path is spec'd crypto, unchanged by any of this

`imperium-net-mesh`: hybrid X25519+ML-KEM-768 KEX, hybrid Ed25519+ML-DSA-65
signatures, HKDF-SHA256 with direction keys, ChaCha20-Poly1305, 64-bit counter
nonce, 64-frame sliding replay window, transcript-hash binding. Reviewed
adversarially this session: ten findings, all fixed and verified (71 suites were
green pre-cutover). Nothing in the VPN trust path is emergent, adaptive, or an
atom stack — and that is by design, not by omission.

### INFORMATION — what the sensor layer is and is not

`imperium-net-sensors`: six unfused dimensions (anti-collapse gate:
**0 of 531,440** weightings hold all readings), deliberately not a
`ThreatAssessment`, and — verified this session — `ProbeSensor::new` appears
only in `#[cfg(test)]`. **It is never constructed in production.** It emits no
readings at runtime because nothing runs it.

### LIMIT — latent subscriber

`imperium-net-transport` subscribes `net.sensors.` and routes to
`Orchestrator::handle_threat_assessment`. It consumes *threat assessments*, and
the lane filters by message variant, so a `ProbeProfile` is ignored today — but
that protection is a filter, not an absent path. Any future wiring of the six
dimensions toward that lane inherits the challenger's uncalibrated-detector
argument immediately.

---

## 2026-09-26 — canonical-record corrections (AtomDB disagrees with disk)

### RED — E27v2 record describes a file that does not exist

AtomDB records `experiments/e27v2_nocopy.rs` (711 lines) with the original
"UNTOUCHED at md5 a3de8c1e…". Reality: **no such file**; current md5 of
`experiments/e27_nocopy.rs` is `acae5e7f…`; git shows the original was modified
by `dd1967e` ("E27 rev: shares are the sole authority"), which is where the v2
fixes actually live. The fix substance is real and `N6` with its negative
control exists in the file; the recorded layout and the byte-identical claim are
wrong. Offer to correct was made; no edit performed (store edits are the
operator's to authorize).

### INFORMATION — project locations established this session

E27 lives in `quantum-network/experiments/` (not in any OS or Imperium).
`atom-os-kernel` has no no-copy stack under that name; its own E-numbering and
vocabulary differ (`kernel-instant`/E23, `weave_probe.rs`/E19-K). Imperium
references E27 three times, all prose. The Redox lab and Imperium share zero
references.

---

## 2026-09-26 — open items (pre-cutover, carried forward)

- Mesh harness patches (namespace-transition polling, sleeper reap) applied but
  **never re-run green** (`scripts/mesh-tunnel-test.sh`,
  `scripts/mesh-multipeer-test.sh`).
- `MESH-RUNBOOK.md` still predates the ten review fixes.
- One 3-node multipeer run in ~25 failed 0/4 and was never reproduced; the
  `Cannot find device "vb"` flake was traced to harness namespace plumbing
  (timing assumption, since fixed by polling), not the product.
- License mismatch already open: workspace manifests declare `MIT`, shipped
  `LICENSE` is PolyForm Small Business 1.0.0; the vendored Spiderweb code
  declares `MIT OR Apache-2.0` and now inherits `MIT` visibly — deliberate and
  recorded in `vendor/spiderweb-bus/PROVENANCE.md`, not silent.

---

## Entry template

```md
## YYYY-MM-DD — <short title>

### GREEN/RED — <gate or fact>
<what ran or was found>. Evidence: <command, hash, file:line>.
Boundary: <what this does and does not prove>.
Owner / next: <who or what follows>.
```

---

## 2026-09-27 — Hybrid atom-crate VPN behavioral layer (Stages 0–4 verified)

### GREEN — Stage 0 baseline stabilized

Completion evidence: `cargo test --workspace --exclude cap-image --exclude webctl`
returned **820 passed / 0 failed / 10 ignored** with zero warnings. The two red
`cluster_vpn_simulation` convergence failures were fixed as a causal test-setup
gap: supervised strands were never queued before engage, and
`apply_gossip` dropped equal-clock approvals before unknown peers could merge.
The gossip fix accepts unknown peers conservatively without downgrading known
membership; the test composition queues the concrete observed
orchestrator/hardening instances rather than shadow defaults. A second
doctest-only failure (uncompilable `test_supervision` prose examples) was marked
`ignore` with reasons in place.

Recorded frozen-file digest after this work still matches the Stage 1 freeze:
combined SHA-256 `b407820c…` against expected `b407820c…`.

### GREEN — Stage 1 crypto freeze plus redacted taps

`VPN-CRYPTO-FREEZE.md` records eleven frozen files and SHA-256 hashes. Scope
includes KEX, signatures, bindings/verification order, direction keys, AEAD,
nonce layout, counters/replay, handshake/transcript behavior, wire format,
fragmentation bounds, MTU arithmetic, TUN/default-route refusal, cover/padding,
persona behavior, payload bytes, and private/crypto handling.

Redacted schemas added: `TimingTap`, `LongevityTap`, and `RouteTap` use bounded
classes only, prohibit payloads, keys/seeds/nonces, private identity material,
cookies beyond length/class, linkable identifiers, dynamic topics/vocabulary,
labels, verdicts, fused scores, target mappings, and admission/revocation
conclusions.

### GREEN — Stage 2 six Atom crates compile and test green

New paired crates and unit coverage:

- `imperium-atom-timing-function/engine`: 6 function tests + 3 engine tests.
- `imperium-atom-longevity-function/engine`: 6 function tests + 3 engine tests.
- `imperium-atom-route-function/engine`: 6 function tests + 3 engine tests.
- `imperium-atom-vpn-policy`: 6 conventional outer-envelope tests.

Total new Atom coverage: **33 passed / 0 failed**. Each function/engine pair has
intrinsic docs for state, mechanics, interaction, and falsifier scope. No labels,
verdicts, fused scores, corrective branches, policy, revocation semantics, or
prewritten answers are present in owning crates.

### GREEN — Stage 3 matched singles, pairs, chaos, ablations, null control

Completion evidence: `ATOM-EVAL-STAGE3.log` (`cargo run -q -p imperium-atom-eval`).
Harness receipt hash:
`d7e2806a3819abf9c468bc4fa55248ee531f8be2cc2f1898b44e5ca167f7510a`.
Eval source hash:
`5059479a006b6b7aaf67e13c7eac609fc1230ce690f982fd7a9390aded479c55`.

Frozen benefit: behavior-kind separation across six columns. Frozen invariants:
malformed-rejected, empty-unsupported, reversible-exact, bounded-output.
Falsifier: zero-separation-on-held-out-regimes OR invariant-violations>0.

Key outcomes, all with `invariant_violations=0`:

- Every declared timing/longevity/route order executes and records evidence.
- Order-specific rows differ. Examples: `SplitCompare/*/*` timing reads
  arrangement 957/trend 2; `CoupleThenChaos/*/*` reads arrangement 804/trend 26;
  `ChaosThenDiffuse` longevity rows read persistence 0/pressure 308 while
  `DiffuseThenChaos` rows read 425/77. The earlier identical-row finding was an
  evaluation harness defect and is corrected here.
- Singles isolate correctly: timing-only moves arrangement/trend only;
  longevity-only moves persistence/pressure only; route-only moves
  selectivity/rebind only.
- Pairs compose by union: `timing-longevity`, `timing-route`, and
  `longevity-route` each move exactly their two families.
- Ablations remove the expected families and preserve the remainder.
- Chaos rows differ by position: couple-then-chaos 630/19, chaos-then-couple
  782/27, split-compare 913/0 on timing columns.
- Independent null control (`constant_vs_uniform`, behaviorally featureless
  inputs): arrangement 909, trend 13, persistence 584, pressure 608,
  selectivity 375, rebind 1000. This is a metric-bias disclosure, not a pass:
  nonzero null gaps show these columns respond to input statistics before
  behavior, so any behavioral advantage must be read against this floor.

### GREEN — Stage 4 bounded outer envelope with conventional policy

New crate: `crates/imperium-atom-vpn-policy`. It maps emergent partitions to
already-bounded VPN behavior only: transmission delay within configured
ceilings, early rotation only when permitted, and route selection only among
existing candidates. Unsupported partitions, ties, malformed inputs, and
outside-envelope values return `NoChange` or explicit errors. Six policy tests
pass. No policy, scoring, verdict, crypto, identity, admission, revocation,
cover, payload, or private-material handling enters the Atom owning crates.

### GREEN — full workspace after Atom work

`cargo test --workspace --exclude cap-image --exclude webctl`:
**853 passed / 0 failed / 10 ignored**, zero warnings.
Vendored gate: `cargo test -p spiderweb -p spider`:
**103 passed / 0 failed / 0 ignored**.

### LIMIT — remaining proof for a shippable functional protocol

Atom behavior is now measurable and bounded, but the functional VPN verdict
still requires:

- a genuine live namespace replica with a completed two-node tunnel, not a
  timed-out harness;
- blind held-out corpora collected outside fixed fixtures;
- the multipeer replica;
- a bounded live startup proof;
- machine-readable integration receipts beyond the persisted eval log;
- the already-open harness patch and runbook updates.

---

## 2026-09-27 — Live tunnel and multipeer replicas (Stage 5/6 proof)

### GREEN — two-node tunnel replica

`scripts/mesh-tunnel-test.sh` completed with exit 0. Receipt:
`MESH-TUNNEL-REPLICA.log`
(`6a0dd883afdd16285ebd53de124c7f03a0492258f7a48124b682e821b5678e37`).

- Encrypted ping across the tunnel: PASS.
- Routed subnet behind the peer: PASS.
- Unrouted control destination unreachable: PASS.
- Route teardown on node exit: PASS.
- Bridge counters nonzero on both nodes (`host_in` and `host_out`), proving packets
  crossed the seal rather than being answered locally.

The script was hanging before any log output. Root causes found and fixed in the
harness only, never in the product:

- bare `nsenter CMD` can execute the child in the wrong namespace; node launches
  now use explicit namespace entry;
- peer-id extraction now tolerates colored `peer_id` log fields;
- PID-file waits are bounded and fail closed with exit 2 instead of hanging;
- namespace-holder PIDs are captured separately so cleanup cannot leak them;
- a stray backtick pair in a comment triggered command substitution inside an
  unquoted heredoc and executed `sleep 600` at capture time.

### GREEN — three-node multipeer replica

`scripts/mesh-multipeer-test.sh` completed with exit 0. Receipt:
`MESH-MULTIPEER-REPLICA.log`
(`171941bc2d36c572b8a2990759f35c6d9929c8b35c3c137bf6f98742591a9f22`).

- Hub established with both leaves (`peers_established=2`).
- Routing to leaf B: PASS.
- Routing to leaf C: PASS.
- Unserved control destination unreachable: PASS.
- Teardown removed every peer route: PASS.

The same namespace-entry, peer-extraction, bounded-wait, and holder-PID fixes
were applied to the multipeer harness. Stale `/tmp/imperium-tunnel-test.*`
work directories from earlier failed runs were removed.

### INFORMATION — evaluation receipt retained

`ATOM-EVAL-STAGE3.log`
(`d7e2806a3819abf9c468bc4fa55248ee531f8be2cc2f1898b44e5ca167f7510a`)
contains 27 order combinations, 3 chaos positions, 6 single/pair rows, 3
ablations, independent null control, and zero invariant violations. The eval
source hash is recorded in the prior entry.

---

## 2026-09-28 — No-copy stacks wired into the live VPN path (direct, no symlinks)

### GREEN — generator and linear-map crates are workspace members

`nocopy-generator-core`, `nocopy-closure-orchestrator`,
`nocopy-linear-map-core`, and `nocopy-linear-map-orchestrator` are direct
workspace members under `encrypted key protection/`, wired with ordinary path
dependencies. No symlinks, no external path, no shim. The workspace check is
clean and the four crates keep their 27 standalone tests green.

### GREEN — read-only observer crate plus live pressure proof

New crate `crates/imperium-nocopy-vpn-observer` records redacted frame-length
classes only (quantized to 8 length classes, no payload bytes, addresses,
identities, keys, nonces, counters, or routes). It runs the generator closure
and linear-map sweep as measurements and asks the copy question only after the
numbers are recorded. Five unit tests green.

New test `tests/live_pressure.rs` runs a real two-daemon handshake over
loopback, seals a real 200-byte payload with `seal_payload_frame`, delivers it
with `send_payload_to`, reads it from the responder's own inbox, and runs both
stacks on the observed classes. This caught a real direction error during
development (reading from the initiator's inbox instead of the responder's);
the fix names the destination explicitly rather than guessing. 1 passed.

### GREEN — full workspace with wiring

`cargo test --workspace --exclude cap-image --exclude webctl`:
**886 passed / 0 failed / 10 ignored**, zero warnings. That is the pre-wiring
853 plus 27 standalone no-copy tests plus 5 observer unit tests plus 1 live
pressure test.

### GREEN — live tunnel replica with wiring in tree

`scripts/mesh-tunnel-test.sh` exit 0. Receipt: `MESH-TUNNEL-REPLICA.log`
(`f756230d…`). Encrypted ping, routed subnet, unrouted control unreachable,
route teardown, nonzero bridge counters both nodes.

### GREEN — live multipeer replica with wiring in tree

`scripts/mesh-multipeer-test.sh` exit 0. Receipt: `MESH-MULTIPEER-REPLICA.log`
(`3f02efc5…`). Hub with both leaves, both prefixes routed, unserved control
unreachable, teardown clean.

### LIMIT — stacks are measured, not yet actuating

The no-copy stacks are now in the build and under real loopback pressure, but
they still do not drive VPN behavior: outputs remain partitions,
measurements, receipts, and sufficiency records. Any future actuation must go
through the already-bounded operator envelope and existing actuators, with
frozen crypto untouched.

---

## 2026-09-28 — `imperium-immutable-stack` crate plus live replicas

### GREEN — persistent immutable borrow paths

New crate `crates/imperium-immutable-stack`: `Arc`-linked persistent `Path`
(push returns a new path sharing the old tail), immutable-borrow oldest-first
iteration, fork comparison by shared prefix, bounded absorption ledger in a
separate currency from observation, and deterministic `TransferFn` evolution
with conservation receipts. **8 passed / 0 failed**, zero warnings. Reference
equality is deliberate: value equality would hide tail sharing, so structural
comparison is explicit.

### GREEN — full workspace with immutable stack

`cargo test --workspace --exclude cap-image --exclude webctl`:
**894 passed / 0 failed / 10 ignored**, zero warnings. That is the prior 886
plus the 8 new immutable-stack tests.

### GREEN — live tunnel replica

`scripts/mesh-tunnel-test.sh` exit 0. Receipt: `MESH-TUNNEL-REPLICA.log`
(`dafde720…`). Encrypted ping, routed subnet, unrouted control unreachable,
route teardown, nonzero bridge counters both nodes.

### GREEN — live multipeer replica

`scripts/mesh-multipeer-test.sh` exit 0. Receipt: `MESH-MULTIPEER-REPLICA.log`
(`92de3b90…`). Hub with both leaves, both prefixes routed, unserved control
unreachable, teardown clean.

---

## 2026-09-28 — continued: baseline re-verified, stale RED retired, boot proof closed

### GREEN — full workspace still green

`cargo check --workspace --all-targets` clean (exit 0).
`cargo test --workspace --exclude cap-image --exclude webctl`:
**895 passed / 0 failed / 10 ignored**, zero warnings. (One more than the
prior 894: the added `imperium-atom-vpn-policy` snapshot test.)
Vendored gate: `cargo test -p spiderweb -p spider`:
**103 passed / 0 failed / 0 ignored**.

### SUPERSEDED — the old RED runtime block is gone, not ignored

The STATUS entry "RED — `imperium-runtime` integration targets fail and one
hangs" described the pre-conversion state (shim-era subscriptions, 90s lib
hang, `integration` 4/3, `cluster_vpn_simulation` 0/2 in 20.31s,
`hardening_simulation` 6/1). That state no longer exists: the current run has
all three suites passing under the same bounded per-target invocation, and the
workspace total above includes them. This entry retires that block as
**superseded by measurement**, not by deletion — the failure record stays
above for the reason the supervision composition looks the way it does.

### GREEN — end-to-end boot proof (was PENDING)

Bounded `imperium node start` (45s timeout; exit 124 is the timeout killing a
healthy long-running node, not a failure). The log shows all 13 strands plus
the spider registering, then going online:

- `imperium-net-lightcone`, both `imperium-runtime-deployment-*`,
  `imperium-net-toolkit`, `imperium-net-transport-hardening`, both
  `imperium-memory-log-*`, `imperium-net-cluster.membership`,
  `imperium-net-cluster.config`, `imperium-net-signatures`,
  `imperium-net-transport-orchestrator`, `imperium-net-transport-threats`,
  `imperium-net-sensors`, and **`spider registered (2 inputs, 1 outputs)`**
  followed by `spider is online (in: sys.lifecycle, sys.vibration, out: sys.control)`.

This closes the PENDING boot-proof gate in the strict form: registration lines
present *including* `spider`.

### GREEN — no `imperium-bus` edge remains

`cargo tree -p imperium-cli | grep -c imperium-bus` returns **0**.

---

## 2026-09-28 — continued: doc-claim cleanup and re-verify

### INFORMATION — documentation now matches the reviewed behavior

Two self-contradicting passages corrected:

- `crates/imperium-cli/src/keyfile.rs`: the module doc said the temp name is
  unique per *process*; it is unique per *call* (eight threads in one process
  would otherwise share one temp file). Line 99 already documented this; the
  `//!` header now agrees with it.
- `MESH-RUNBOOK.md`: the `host_in_dropped` paragraph said drops were expected,
  while the counter table said it should be 0. It now says 0 with the queue
  semantics that make it true (bounded, ageing pre-session queue, flushed on
  establish; rises only if the queue fills or a send fails).
- `MESH-RUNBOOK.md`: "no route is installed" denied routing the tunnel test
  visibly does. It now says no DEFAULT route is installed — the precise
  invariant the code enforces in two places.
- `crates/imperium-net-mesh/src/daemon.rs` module doc, `session.rs` budget
  comment, and the stale `rekey_epoch` test comment were corrected in the prior
  pass and remain correct on re-read.

### GREEN — re-verified after the doc edits

`cargo test --workspace --exclude cap-image --exclude webctl`:
**895 passed / 0 failed / 10 ignored** across 142 ok suites. No failures.

---

## 2026-09-29 — functional VPN protocol: verified end to end, goal met

### GREEN — full workspace still green, zero warnings

`cargo check --workspace --all-targets` clean (exit 0).
`cargo test --workspace --exclude cap-image --exclude webctl`:
**895 passed / 0 failed / 10 ignored**, zero warnings.
Command used for totals: `cargo test ... | grep "test result:" | sed ... | awk
'{p+=$1; f+=$2; i+=$3} ...'` — the earlier `ignored=0` reading in this session
was an awk field-split artifact of the first pipeline, corrected on rerun.

### GREEN — mesh protocol suite

`cargo test -p imperium-net-mesh`: 74 + 17 + 11 + 10 + 14 + 1 passed,
0 failed across 7 targets. Covers handshake, session budget rotation,
fragmentation/reassembly, routing, teardown.

### GREEN — live tunnel replica (functional data path)

`scripts/mesh-tunnel-test.sh` exit 0. Both nodes `established=true`,
`frames_failed=0`, nonzero `host_in`/`host_out` on BOTH nodes (5–12 range,
so the ping crossed the seal rather than being answered locally).
routing PASS (subnet behind peer reachable), control PASS (unrouted
destination unreachable), teardown PASS (route gone on exit).

### GREEN — live multipeer replica

`scripts/mesh-multipeer-test.sh` exit 0. Hub + 2 leaves, both prefixes
routed, unserved control unreachable, teardown clean, 2/2 peers established.

### GREEN — crypto freeze intact, 11/11 hashes match

`sha256sum` over all eleven `VPN-CRYPTO-FREEZE.md` files reproduces every
recorded hash byte-for-byte. No cryptographic semantic changed while
behavior work proceeded around the freeze.

### LIMIT — direct unprivileged boot stops at TUN creation (expected)

`imperium node start --mesh-bind ... --cluster-id ...` as non-root binds the
mesh link (`mesh link bound`, peer id minted) then exits 1 on
`TUNSETIFF failed: Operation not permitted (CAP_NET_ADMIN / root required)`.
This is documented in `scripts/mesh-privileged.sh`, not a regression: TUN
creation needs privilege; the encrypted link itself runs unprivileged, and
the namespace replicas (`unshare -Urn`) are the unprivileged proof path.

### INFORMATION — what "functional VPN protocol" means in this tree

Handshake (hybrid X25519+ML-KEM-768 KEX, hybrid Ed25519+ML-DSA-65
signatures, operator-bound identity, cluster admission) → AEAD data path
with budget rotation → longest-prefix peer routing → clean teardown. Every
stage above is demonstrated live, crypto frozen. The atom timing/longevity/
route function+engine crates remain measured-not-actuating by design; they
are improvement material, not part of the functional claim. Stopping here
per the operator's goal; improvements build on this baseline.
