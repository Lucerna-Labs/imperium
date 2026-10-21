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
