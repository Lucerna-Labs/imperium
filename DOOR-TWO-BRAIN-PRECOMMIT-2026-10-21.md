# Door two in Imperium: the brain that learns self-caused new normal, and the reseal ceremony

**Status: PRECOMMITTED, 2026-10-21, branch `work/path-lightcone-door`, before the brain code.**

Builds on CONSOLIDATE-1 (network-lightcone `path-lightcone/CONSOLIDATE-1-PRECOMMIT.md`), proven in
the three-VM lab: the brain reads door one's drops, consolidates **self-caused** new normal, and
door one relearns it with its own law (fresh tunnel addresses went from 16/6/6 drops to 0/0/0;
6 adversarial shapes all refused).

## Scope (Jesse: "yes to all")

1. **Wire consolidation into Imperium in-repo.** A brain service + supervised strand that reads
   `net.lightcone.receipt`, classifies each **drop** by cause, and accumulates self-caused
   evidence.
2. **The reseal ceremony:** a gated review that turns accumulated evidence into a candidate pack
   only when it is add-only and deny-clean, and only on explicit approval. The TPU seal and the
   swap at door one's single loader stay external (Jesse's seal), unchanged by this.
3. The `authenticated_tunnel`-trusts-a-compromised-peer limit stays recorded as door two's next
   piece; not addressed here.

## Identity on the bus (no frozen-file change, no new host plumbing)

A receipt carries the path, `admitted`, and `direction`. It does **not** carry the interface, and
adding one would touch the frozen `imperium-protocol`. The brain instead uses the mesh's own
knowledge as the identity signal, which is a *stronger* signal than "arrived on a TUN":

- **`own_addresses`:** this host's addresses.
- **`authenticated_sources`:** the tunnel-peer addresses the mesh has authenticated (from the peer
  table, behind the frozen AEAD).

New reading in `path-self` (the self/non-self law stays in one crate):

```
cause_by_identity(path, outbound, own_addresses, authenticated_sources, allow) -> Cause
```

- `OwnAddress`: outbound, source ∈ own_addresses, and the path matches a trained path everywhere
  except its source.
- `AuthenticatedTunnel`: inbound, source ∈ authenticated_sources, same match-except-source.
- `Unexplained`: everything else (a spoof of our own address inbound is not in
  authenticated_sources, so Unexplained).

The existing interface-based `cause` is kept for the offline lab tooling.

## Crates

- **vendor** `path-self`, `path-consolidate` into `crates/` (PROVENANCE, like the other path-*).
- **`imperium-net-brain`** (new): `BrainService`:
  - holds the role world's trained paths + deny world (from `imperium-net-pathworld`),
    `own_addresses`, `authenticated_sources`;
  - `observe(&LightconeReceipt)`: on a drop, classify; keep self-caused paths as evidence
    (bounded, de-duplicated);
  - `candidate()` → the add-only, deny-checked candidate paths (via `path-consolidate`);
  - `review()` → a `CandidateReview { added, refused_by_deny, kept_old, admits_evidence,
    deny_clean }`: the ceremony's precondition check;
  - a supervised **strand** on `net.lightcone.receipt` (same supervision as the lightcone strand),
    and `net.brain.candidate` status it publishes.
- **CLI:** `vpn brain status` → evidence count, candidate size, review flags. No auto-swap.

## Predictions

- **B1:** `cargo test --workspace --offline` passes (new crate tested; nothing else regresses).
- **B2:** the frozen crypto files stay byte-identical to `work/unsealed-lightcone`.
- **B3 (unit, replaying CONSOLIDATE-1's shapes as receipts):** `cause_by_identity` classifies
  `own_address`, `authenticated_tunnel` and 6 adversarial shapes exactly as the lab's interface
  `cause` did; the candidate is add-only, admits every self-caused path, and 0 adversarial.
- **B4:** `review()` reports `deny_clean = true` and refuses (no candidate emitted) if any evidence
  path the deny world matches is present.
- **B5:** the brain never blocks or mutates door one: it only reads receipts and emits a candidate;
  `filter_enforced` stays false, and door one's world is unchanged by the brain.

## Results (2026-10-21)

| # | Prediction | Result |
|---|---|---|
| B1 | workspace tests pass | **MEASURED:** 957 passed, 0 failed (12 ignored). +5 over door one, all new brain/path-self tests |
| B2 | frozen crypto byte-identical | **MEASURED:** empty diff vs `work/unsealed-lightcone` across all frozen files |
| B3 | identity classification + consolidation correct | **MEASURED** (unit): `own_address` learned; a spoof of our own address inbound, and novelty beyond the source, both `Unexplained`; candidate add-only, admits all evidence, 0 adversarial |
| B4 | `review()` gates on deny-clean | **MEASURED** (unit): `deny_clean`, `add_only`, `admits_all_evidence` all reported |
| B5 | the brain never blocks or mutates door one | **HOLDS by construction:** it only reads `net.lightcone.receipt` and accumulates a candidate; `filter_enforced` stays false; door one's world is untouched |

**Landed:** `crates/imperium-net-brain` (`BrainService` + supervised `BrainStrand` on
`net.lightcone.receipt`), vendored `path-self` (+ `cause_by_identity`) and `path-consolidate`, and
`imperium_net_pathworld::role_pack_paths`. The brain strand is registered in the node before the
run loop, beside door one.

### Honest scope note: `authenticated_tunnel` needs interface telemetry

The receipt carries the path and `direction`, not the interface. On the bus, identity is by
address:
- **`own_address` (outbound) works** — the host knows its own addresses, including fresh ones, so
  it learns its outbound self-caused drops. In the CONSOLIDATE-1 lab this class covered the
  **source and receiver** roles entirely.
- **`authenticated_tunnel` (inbound) does not work by address**, because the packets to learn have
  a *novel* source (a fresh tunnel link-local), which is not a known peer address. Only the
  **interface** the packet arrived on distinguishes a genuine TUN-sourced ND from an attacker's
  look-alike on a physical link — which is exactly how the lab's interface-based `cause` did it,
  and why structure alone must not be trusted here (adversary A2). So the hub's inbound ND is left
  `Unexplained` in-repo for now.

**The next scoped step** (door two, continued): thread `input_interface` and a `tunnel` marker on
the lightcone `LightconeStructure`/`LightconeReceipt` (lightcone telemetry, not a crypto change)
from the host bridge through the daemon, so `authenticated_tunnel` works in-repo as it did in the
lab. Recorded, not faked.

**Also deferred (low-risk):** `vpn brain status` (evidence count, candidate size, review flags).
The service handle is held; the strand already runs. Threading the read-only surface through the
command dispatch is a follow-up.

## Continuation (2026-10-21): channel identity, the reseal gate, and the status surface

Finishing the three steps that were left after the first increment:

1. **`authenticated_tunnel` now works in-repo, with no new protocol field.** An **inbound `RawIp`**
   receipt is only ever a packet the mesh decapsulated and wrote to the host TUN *after* the frozen
   AEAD authenticated the peer (`imperium-net-host/src/bridge.rs:320`). An outside attacker cannot
   produce one — their traffic is an unvouched `MeshDatagram` that fails AEAD. So "inbound + RawIp"
   is the authenticated-tunnel signal, already on the receipt. `path-self::cause_vouched` takes an
   `inbound_authenticated` flag; the brain sets it from `direction == inbound && frame_format ==
   RawIp`. The host's own TUN link-local ND is outbound `RawIp` from an own address, already
   `own_address`. (Limit unchanged: an authenticated-but-compromised peer is trusted — now explicit
   in the test: an inbound `RawIp` claiming our own address is vouched, because only a peer could
   have sent it.)
2. **The reseal gate** (`BrainService::reseal_to(path, approved)`): writes the candidate pack
   **only when** the review passes (add-only, deny-clean, admits all evidence) **and** the operator
   approves. The TPU seal and the swap at door one's single loader stay external. Unit-tested:
   refuses without approval (writes nothing), writes a decodable pack with approval.
3. **`vpn brain status`** on the control surface: role, observed / self-caused / unexplained
   counts, evidence size, candidate size, the review flags, and `reseal_ready`. Read-only;
   `passive: true`, `changes_door_one: false`. `BrainService` is threaded through `initialize_node`
   and `ControlState`.

**Measured:** workspace **958 passed, 0 failed** (12 ignored); frozen crypto diff **0 lines**.

**Still open (door two, continued):** the full reseal ceremony beyond the gate (a candidate VM run
+ the TPU seal + the swap), and tightening the authenticated-but-compromised-peer trust. Both are
recorded, neither faked.

## Tightening the compromised-peer trust (2026-10-21): corroboration

The `authenticated_tunnel` trust accepts any inbound decapsulated packet, so a compromised peer
could present self-shaped novelty. Added a **corroboration** guard (the continuation-count idea
again): an inbound-tunnel **shape** (a trained template with its source position freed) becomes
evidence only after **`CORROBORATION_MIN = 2` distinct sources** have presented it. Buffered until
then; a single peer presenting one shape — even repeatedly — never enters the candidate
(`corroboration_tests::one_peer_cannot_inject_a_shape_alone`). Outbound `own_address` (our own
host) commits immediately, no corroboration.

**What it does and does not stop (honest):**
- **Stops:** a single compromised peer that does not vary its source, and a passive injector on one
  tunnel, from filling the candidate with a novel shape alone.
- **Does not fully stop:** a compromised peer that varies the source address inside its own
  decapsulated packets can corroborate itself, because the receipt carries the source address, not
  the authenticated *peer identity* (that lives in the mesh session, off the receipt). The full fix
  needs the peer identity threaded onto the lightcone receipt, then corroboration keyed by distinct
  *peers*. Recorded, not faked.
- **Backstop regardless:** nothing reaches door one without the operator-approved, deny-checked
  reseal gate, and door one's own context law still needs ≥ 3 distinct values to fold.
- **Tradeoff:** in a single-peer mesh, inbound-tunnel shapes from the lone peer are never
  corroborated, so that learning falls to the operator's review; outbound own-host learning is
  unaffected.

Workspace after this step: **958 passed, 0 failed**; frozen crypto diff **0 lines**.

---

# LIVE-BRAIN-1: door two running inside live Imperium nodes

**Status: PRECOMMITTED, 2026-10-21, before the code below.**

**Two gaps found by reading the code before the run, fixed first:**
1. **The brain never learned its own addresses** (`set_own_addresses` had no caller), so outbound
   `own_address` learning could not happen live. **Fix:** the brain strand re-reads this host's
   addresses from the kernel every second (`/proc/net/if_inet6` for IPv6; the `LOCAL` /32 entries
   of `/proc/net/fib_trie` for IPv4). That way a fresh TUN address is known as soon as it exists.
2. **The brain forgot on restart.** Its evidence lived in memory, so it could never collect
   addresses across restarts. **Fix:** with `IMPERIUM_BRAIN_STATE=<dir>`, the evidence is kept in
   `<dir>/<role>.evidence.pathpack` (a `path-pack`). It is rewritten when evidence grows, and
   reloaded at start. The file holds evidence only, never a rule; corroboration still applies to
   new inbound shapes.

**The run:** Imperium's three-VM lab (`scripts/lightcone-vm/brain_live.py`). 3 episodes, each a
fresh node start (fresh TUNs), with the trained cases. After each episode the driver reads each
node's `vpn brain status` through its control socket.

**Predictions:**
- **L1:** every node reports the brain active with its role.
- **L2:** the hub's `self_caused` > 0 from corroborated inbound tunnel traffic.
- **L3:** source and receiver have `self_caused` > 0 via `own_address` (their fresh TUN
  link-local housekeeping).
- **L4:** evidence persists and grows across episodes on every role.
- **L5:** after episode 3, every role's review is `add_only`, `deny_clean` and
  `admits_all_evidence`, and `reseal_ready` is true.
- **L6:** delivery is unaffected: every case echoes every attempt in every episode.

## LIVE-BRAIN-1 results (2026-10-21, `evidence/live-brain-1-20261021/`): all six hold

Imperium's three-VM lab (`scripts/lightcone-vm/brain_live.py`): three fresh node starts, door one
and door two running inside every node.

| episode | role | observed | self-caused | unexplained | evidence (persisted) | review | reseal_ready |
|---|---|---|---|---|---|---|---|
| 1 | hub | 424 | 16 | 2 | 5 | add-only, deny-clean, admits all | true |
| 1 | source | 209 | 2 | 5 | 1 | all true | true |
| 1 | receiver | 209 | 2 | 5 | 1 | all true | true |
| 2 | hub | 414 | 14 | 3 | **10** | all true | true |
| 2 | source | 205 | 4 | 3 | **3** | all true | true |
| 2 | receiver | 205 | 2 | 5 | **2** | all true | true |
| 3 | hub | 412 | 14 | 4 | **14** | all true | true |
| 3 | source | 203 | 3 | 4 | **5** | all true | true |
| 3 | receiver | 203 | 4 | 3 | **4** | all true | true |

- **L1** the brain is active on every node with its role. **HOLDS.**
- **L2** the hub learns from corroborated inbound tunnel traffic (`self_caused` 16, 14, 14).
  **HOLDS.**
- **L3** source and receiver learn their own outbound housekeeping via `own_address`
  (`self_caused` 2–4 per episode). **HOLDS.**
- **L4** evidence persists and grows across restarts: hub 5→10→14, source 1→3→5,
  receiver 1→2→4. (The counters reset at each restart; the evidence file carries over.) **HOLDS.**
- **L5** after episode 3, every review is add-only, deny-clean and admits all evidence, with
  `reseal_ready: true`. **HOLDS.**
- **L6** delivery is unaffected: 49/49 echoed in every episode. **HOLDS.**

The small `unexplained` count is not consolidated, correctly: it is traffic with no identity-linked
cause, such as the lab's own `lo` control stimulus, seen as an un-vouched mesh datagram.

**Door two now runs live inside Imperium.** It reads door one, learns self-caused new normal
across restarts, and keeps a reseal-ready candidate. It never changes door one or delivery.

---

# RESEAL-1: the first reseal ceremony (approved by Jesse, 2026-10-21)

**Status: PRECOMMITTED, 2026-10-21, before any RESEAL-1 code.**

**The approval:** Jesse wrote "Approved" for the reseal. It does **not** cover enforcement on the
real host: `filter_enforced` stays `false`, and no host rule is touched.

## The ceremony

**1. Write.** `imperium-net-brain/examples/reseal.rs ROLE EVIDENCE OUT`:
- loads the role's door-one paths and LIVE-BRAIN-1's persisted evidence
  (`evidence/live-brain-1-20261021/<role>.evidence.pathpack`);
- writes the candidate through `BrainService::reseal_to(out, approved = true)`, so the gate's
  review (add-only, deny-clean, admits all evidence) must pass, or nothing is written.

**2. Offline "loosened nothing" check, same example.** For every trained path, make the
exact-field mutations:
- an untrained port;
- an untrained source address;
- the UDP/TCP swap.

The candidate world must admit **no more** of them than the old world.

**3. VM test.** Door one loads the candidates through its single loader, by a new override
`IMPERIUM_LIGHTCONE_PACK_DIR=<dir>` (`<dir>/<role>.pathpack`, fail-closed on a malformed pack).
This is the same seam the TPU-sealed pack will use. Then the three-VM lab (`brain_live.py`, with
the override) runs fresh node starts with live traffic.

**4. Swap.** Only if steps 1–3 pass, the candidates replace the embedded lab packs in
`imperium-net-pathworld/packs/`, still **`sealed: false`** and revertible in git.

**5. Seal.** The **TPU seal is external** (Jesse's path) and is not done here.

## Predictions

- **R1:** the gate writes a candidate for every role. Every review passes, and every candidate
  contains every old path.
- **R2:** offline, every role's candidate admits exactly as many mutated paths as the old world
  does: 0 more.
- **R3:** in the VM test with the candidates, each role's `self_caused` in its first episode is
  lower than in LIVE-BRAIN-1's episode 1 (hub 16, source 2, receiver 2). Door one admits fresh
  housekeeping it used to drop.
- **R4:** delivery is 49/49 in every episode.
- **R5:** after the swap, the workspace tests pass (the trained-path counts in the tests updated
  to the new packs), and the frozen crypto diff is still 0.

## RESEAL-1 method change (before the code): R2 is structural

**R2, revised:** compare the wildcard positions of the candidate world with the old world's, using
the world's own diagnostics (`folded_fields`, `wild_contexts`).
- **Allowed:** new learned positions at the **source address** (field 3), which is what
  CONSOLIDATE-1 measured door one learning.
- **Refused:** any new wildcard at link, protocol, destination, ports, TCP flags or ICMP type
  (fields 1, 2, 4–8). That would be loosening, and it **stops the swap**.

This replaces generating altered packets. The exact-field mutation tests were already measured
live in PATHGATE-1/2/3 and offline in CONSOLIDATE-1.

## RESEAL-1 results (2026-10-21, `evidence/reseal-1-20261021/`): the first reseal is done (unsealed)

| step | result |
|---|---|
| R1 write via gate | **HOLDS.** hub 777→791 (+14), source 468→473 (+5), receiver 472→476 (+4); every review add-only, deny-clean, admits all evidence |
| R2 loosened nothing (structural) | **HOLDS.** new wildcards only at the source address (field 3) on every role; 0 new at any other field |
| R3 fewer first-episode self-caused drops | hub **16→0**, source **2→0** (HOLD); receiver 2→1→0 across episodes (ties in ep1, then closes — a single-peer inbound shape corroborates slowly; no regression) |
| R4 delivery unaffected | **HOLDS.** 49/49 echoed in every episode |
| R5 swap: tests + frozen crypto | **HOLDS.** workspace 962 passed, 0 failed; frozen crypto diff 0 |

The candidates are now door one's embedded world (`imperium-net-pathworld/packs/`), **`sealed:
false`**. A loader override `IMPERIUM_LIGHTCONE_PACK_DIR` was added (fail-closed), the seam the VM
test used and the TPU-sealed pack will use. The reseal is revertible in git.

**The TPU seal (step 5) is external and not done here.** Enforcement on the real host remains off
(`filter_enforced: false`); Jesse's approval covered the reseal only.
