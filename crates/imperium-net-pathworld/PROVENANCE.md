# Provenance

- **`crates/path-sense`, `path-world`, `path-admit`, `path-frame` and `path-pack`** are vendored
  unchanged from Lucerna-Labs/network-lightcone, `path-lightcone/`, at commit `85e1f2d`
  (2026-10-21).
- **`packs/*.pathpack`** were built there by `pathpack` from this repo's
  `evidence/lightcone-vm-io-20261001/healthy-<role>-packets.jsonl`, with PATHCONE-1's training
  split (case attempts below 6, plus background): hub 777, source 468, receiver 472 paths.
- **The measurements behind the law** are in that repo's `path-lightcone/PATHCONE-1-PRECOMMIT.md`
  and `PATHGATE-1-PRECOMMIT.md`.

The world stays diagnostic and unsealed.

## Reseal 1 (2026-10-21)

The embedded packs were resealed from door one's original training plus door two's **self-caused**
evidence from LIVE-BRAIN-1 (`imperium/evidence/live-brain-1-20261021/`), through the brain's gate
(add-only, deny-clean) and the RESEAL-1 ceremony (Jesse approved; offline structure check; VM
test). Counts: hub 777→791, source 468→473, receiver 472→476. The only new learned positions are
at the source address (fresh tunnel link-local addresses). The world stays **`sealed: false`**; the
TPU seal is a later, external step. Revert: `git checkout <pre-reseal> -- packs/`.
