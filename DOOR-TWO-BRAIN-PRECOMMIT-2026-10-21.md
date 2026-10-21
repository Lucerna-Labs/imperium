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
