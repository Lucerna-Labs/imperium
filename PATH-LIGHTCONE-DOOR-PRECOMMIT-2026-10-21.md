# Door one: the path lightcone replaces the v4/v5 network worlds (passive)

**Status: PRECOMMITTED, 2026-10-21, before any code. Branch `work/path-lightcone-door`.**

## Jesse's direction

> "I want the lightcone to be the first door, and brain to exist as the next step."

> "I really wanted to avoid hashes and depend on immutable atom stacks, cognitive/brain engines."

- He chose **"passive swap only"**: Imperium records what the path world admits and never blocks.
  `filter_enforced` stays `false`, as he said: "you are correct, leave it".
- The brain, door two, is the next stage. It is not part of this change.

## Why the swap

**The v4/v5 worlds never read their geometry when admitting** (0 of 244 decisions changed, see
STATUS). They never decide anything: every use of them is a receipt, a display, or the dead
`flow_policy.rs`, whose own test cannot load the current world.

**The path world is measured in network-lightcone (Lucerna-Labs/network-lightcone,
`path-lightcone/`):**
- offline: 0.94–0.95 held-out pass, and every exact-field mutation dropped;
- in the kernel: the kernel outcome equals the offline verdict on 5196 of 5196 packets;
- **in this repo's own three-VM lab** (PATHGATE-3): every trained case passes live, 5/5 live
  negatives are stopped, and the gate fails closed when killed.

## What changes

1. **The path crates are vendored, unchanged,** from network-lightcone `ffcede9`, with a
   PROVENANCE note: `crates/path-sense`, `path-world`, `path-admit`, `path-frame`. Two new crates
   join them:
   - `path-pack`: a text codec for a list of trained paths, fail-closed on any malformed line;
   - `path-frame` gains `ethernet_path` and `socket_path` (a UDP datagram's path from its socket
     addresses).
2. **`imperium-net-pathworld`** (new) replaces `imperium-net-world`:
   - it embeds the three lab roles' training packs (hub, source, receiver), built from
     `evidence/lightcone-vm-io-20261001` with PATHCONE-1's split;
   - it trains the allow world (context folding, run 6) and the deny world at load;
   - **the role is chosen by `IMPERIUM_LIGHTCONE_ROLE`.** With none set, the world is
     **untrained** and empty: nothing is admitted ("only trained paths can pass");
   - **there are no hash pins.** The world is immutable once built: it has no mutating API.
3. **`imperium-net-observer`:** the 48-D seed mapping is removed, and frames become paths:
   - Ethernet → `ethernet_path`;
   - TUN raw IP → `held_path`;
   - mesh datagram → `socket_path`, from the peer address, the mesh socket's port, and the local
     address the kernel routes to that peer (a UDP connect probe, which sends no packets);
   - `FlowMetadata` / `parse_raw_ip_flow` are unchanged.
4. **`imperium-protocol`:**
   - `LightconeStructure.seeds` becomes `path`;
   - `LightconeReceipt` drops `pack_sha256`, `receipt_sha256`, `seeds`, `nodes`, `edges`,
     `excluded` and `hop_frontier`, and gains `world`, `path`, `admitted`, `denied` and
     `learned_positions`;
   - `query_sha256` stays: it is the correlation identity with captures, not an integrity pin;
   - **no crypto type or wire format changes.**
5. **`imperium-net-lightcone`:** the service admits paths. The ledger, strand, supervision,
   quarantine and fault drills are kept as they are.
6. **`imperium-net-mesh`:**
   - the worker builds paths;
   - the duplicate `MeshTransport` world tap and `world_lightcone.rs` are removed, which also
     removes the startup panic on pack verification;
   - **`flow_policy.rs` is removed** (no call site);
   - **no line of** `handshake.rs`, `crypto.rs`, `session.rs`, `wire.rs`, `destination.rs`,
     `gate.rs` or `hardening.rs` changes.
7. **CLI `vpn lightcone status` and the GUI:**
   - they report path-world facts: role, trained paths, folds, deny paths;
   - `filter_enforced: false`, `filter_mode: "diagnostic_only"`, `passive: true`,
     `sealed: false` are kept;
   - the GUI's `lightcone_v4_receipt_seen` becomes `lightcone_receipt_seen`.
8. **Removed:**
   - `crates/imperium-net-world` (including `v5/`), and `.lightcone-v3-backup` references in
     docs;
   - the negative-result tests `filter_feasibility.rs` and `v5_condition_evidence.rs`;
   - `rtx_world_vpn_safety.rs`.

   Every v4-fact test is rewritten against the path world.

## Predictions

- **D1:** `cargo test --workspace --offline` passes.
- **D2:** the frozen crypto files are byte-identical to `work/unsealed-lightcone`.
- **D3:** nothing in the workspace references `imperium_net_world` or `imperium-net-world`
  anymore.
- **D4:** the existing VM lab (`scripts/lightcone-vm-test.sh --io`) completes with:
  - a complete healthy delivery baseline;
  - the measurement block/recovery control passing;
  - quarantine still reached by the crash drill;
  - receipts present on all three roles.

  Run with `IMPERIUM_LIGHTCONE_ROLE` set per guest.
- **D5:** in that run, ≥ 0.95 of the receipts for the healthy arm's packets on the lab links say
  `admitted: true`; the injected-crash arm's quarantine is unchanged.
- **D6:** with no role set, `vpn lightcone status` reports the world as untrained, every receipt
  says `admitted: false`, and the node runs normally.

**Note for the freeze doc:** `VPN-CRYPTO-FREEZE.md` pins a hash for `imperium-protocol/src/lib.rs`
that was already stale before this change (pinned `3b36fcf5…`, actual `f9daa7d2…`). Jesse rejects
hash pinning as the integrity mechanism. The doc's hash table is left for him to retire or rewrite.
This change alters only the protocol file's lightcone types, not crypto semantics.

## The seal, later (Jesse, 2026-10-21)

> "Because the lightcone will eventually be sealed by the TPUs, once everything is proven to work,
> the seal makes it immutable, so hackers can't get around it."

**This change keeps the world `sealed: false`.** It is shaped so that sealing slots in later
without another rewrite:
- the world comes only from a pack, through one loader;
- it has no mutating API after load;
- a TPU-trained, sealed pack can replace the lab packs at that single point.

No sealing mechanism is built or claimed here.

## Results (2026-10-21): 5 of 6 hold. D5 FAILED, and the failure is fully explained

| # | Prediction | Result |
|---|---|---|
| D1 | the workspace tests pass | **MEASURED:** `cargo test --workspace --offline`: **952 passed, 0 failed** (12 ignored, all marked ignored before this change) |
| D2 | the frozen crypto files are byte-identical | **MEASURED:** 0 diff lines in `imperium-net-crypto` and in mesh `handshake`, `crypto`, `session`, `wire`, `destination`, `gate`, `hardening`. `transport.rs` lost only the 22 lines of the duplicate tap; its `seal_for_session` / `open_for_session` calls are untouched |
| D3 | no reference to the old world remains | **MEASURED:** none in `.rs`, `.toml`, `.py` or `.sh` |
| D4 | the VM IO lab completes | **MEASURED** (`scripts/lightcone-vm-test.sh --io`, exit 0, `evidence/door-one-vm-io-20261021/`) — see below |
| D5 | ≥ 0.95 of the healthy arm's receipts admitted | **FAILED:** hub 0.914 (405/443), source 0.882 (202/229), receiver 0.882 (202/229) |
| D6 | untrained: nothing admitted, the node runs | **MEASURED** by tests: `untrained_world_admits_nothing`, and the CLI status test (world `"untrained"`). The node, strand and live bus run with no role set (`lightcone_live_bus`, `pilot_supervision`) |

**D4 in detail:**
- the healthy delivery baseline is complete;
- the measurement block/recovery control passes;
- the crash drill quarantines all three roles;
- every role reports `working: true` with its trained world (hub 777, source 468, receiver 472
  paths) and `filter_enforced: false`;
- application integrity: 46/46 IDs received in both the healthy and quarantined arms.

The passive door changed no delivery.

### D5 diagnosis (after the run)

**Every receipt not admitted belongs to one of the two one-example classes** that network-lightcone
PATHCONE-1 run 6 had already named:
1. **The lab's own control stimulus:** 20 datagrams per guest, sent by `packet_io.py` from each guest
   to itself on `lo`, at port 41000, from a fresh client port each run. Training holds one example
   of it.
2. **The fresh tunnel interfaces' link-local MLD reports (143) and router solicitations (133):**
   hub 18, source 7, receiver 7.

**All other receipts were admitted: 809 of 809** (hub 405/405, source 202/202, receiver
202/202). That covers every case packet and all real mesh traffic.

The 0.95 prediction did not account for the share of the lab's own stimulus in a short run. It is
recorded as FAILED, not relabelled.

**Learning these one-example classes** (Jesse: "it should learn, or we will be stuck with not 100
percent compatibility") is the next stage's job: door two, the brain, learning new normal. It is
not done by loosening door one.
