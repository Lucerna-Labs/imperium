# Spiderweb bus provenance

This directory vendors the **working tree** of the standalone
**Spiderweb-Bus-Next** project, so that Imperium's message bus is code inside
this repository rather than a path dependency on a sibling directory.

- Source: `/home/jesse/Desktop/Projects/Spiderweb-Bus-Next`
- Upstream HEAD: `b9e336cb3393164ee80520138928493d84e6a290` — 2026-06-27,
  "Spiderweb Bus — a layered, organic in-process message bus for Rust"
- License: `MIT OR Apache-2.0` (dual; see the note under *Use*)
- Scope: 15 workspace members (14 crates under `crates/`, 1 tool under
  `tools/`), 89 files, 1.3 MB of source
- Test weight vendored with it: 16 integration test files / 3,831 lines, plus
  16 inline `#[cfg(test)]` modules

## ⚠️ This is a working tree, not a commit

**The vendored revision is not a commit and cannot be reproduced from one.**
Upstream's working tree does not match `b9e336c`:

- **79 files modified** (+20,341 / −19,912) relative to HEAD
- **9 files untracked — and the untracked set is the cognitive engine**

```
crates/spider/src/conserve.rs          (102 lines)
crates/spider/src/engine.rs            (798 lines)
crates/spider/src/gate.rs              (186 lines)
crates/spider/tests/cognitive.rs       (490 lines)
crates/spider/tests/cognitive_bus.rs   (240 lines)
crates/spiderweb/tests/lifecycle_replay.rs        (109 lines)
crates/spiderweb/tests/named_subscriptions.rs     (394 lines)
crates/spiderweb/tests/spider_install_order.rs    (94 lines)
spider-cognitive-engine.md             (500 lines, design doc)
```

A `git archive`, a submodule checkout, or any git-based export would have
produced a tree **without the cognitive engine and without three of the kernel's
test files**. The copy was therefore taken from the filesystem, and the nine
files above were verified present and byte-identical afterwards.

Consequence, stated plainly: this vendoring freezes a mid-development state.
Syncing with upstream later is a filesystem diff against a moving target, not
a fast-forward to a known commit.

## Artifacts

| Artifact | SHA-256 |
|---|---|
| `PROVENANCE/upstream-Cargo.toml` (upstream root manifest, verbatim) | `98a444dd22511a0ae0cade68f21c2a39b14e07335c1d4f617411c34f372c3fc7` |
| `crates/spiderweb/src/lib.rs` (the kernel, 4,608 lines) | `b06a2d563d1c200eacd0e0016792dffbefadd29fae2e8995c8800fcf4e2ce241` |
| `crates/spider/src/lib.rs` | `c8adece508de36edf13128c825866354d84a0b773c445f8743c59768c61d3812` |
| `crates/spider/src/engine.rs` (untracked upstream) | `21e9f20f1011d4518f0e32600537085e04f981d72569b4f97b1cd7572200b98b` |
| `crates/spider/src/gate.rs` (untracked upstream) | `34fc78802dda71e946d04621775d1aad8d59d3088ac787aa9e762effc86dd92f` |
| `crates/spider/src/conserve.rs` (untracked upstream) | `5b9e171e9955db00fd53937eba7d753a6a6def8388dc832a77e0bb0d35b8bd10` |
| `spider-cognitive-engine.md` (untracked upstream) | `5e255bd4c80a206d4e32368d55ad2f55b6dfd1585d5088ba10e6b3ff4a072132` |

`PROVENANCE/upstream-Cargo.toml` is upstream's root manifest kept **verbatim**
so the delta introduced by merging this tree into Imperium's workspace stays
auditable. The working copy of that manifest is deleted (see *Workspace
integration*), because two `[workspace]` tables cannot both exist.

`target/` (2.7 GB of upstream build artifacts) and `.git/` were excluded from
the copy. Nothing else was.

## What this replaces

Two things, both removed by this vendoring:

1. **The out-of-workspace path dependency.** `crates/imperium-bus/Cargo.toml`
   pointed at `../../../../Spiderweb-Bus-Next/crates/{spiderweb,spider}` — a
   sibling directory outside the repository, at an unpinnable revision (path
   dependencies cannot pin a commit). That is the structural weakness this
   change closes.
2. **The compatibility shim.** `crates/imperium-bus` had grown to 1,837 lines
   whose stated design goal was a "BYTE-IDENTICAL public API — zero call-site
   changes across 14 crates", preserving the signatures of the `tokio::broadcast`
   bus it replaced. `STRAND-CONVERSION.md` mandated that every subsystem depend
   on `imperium-bus` and never on `spiderweb` directly. That mandate is what this
   directory makes obsolete.

The prior state is preserved at `.spiderweb-pre-vendor-backup/` for recovery,
with its own `MANIFEST.md` recording hashes and restore commands
(**Imperium is not a git repository, so that directory is the recovery path**).

## Workspace integration

These are the only edits made to the vendored tree, all recorded so a future
diff against upstream stays honest:

| Edit | Why |
|---|---|
| Root `Cargo.toml` removed; kept at `PROVENANCE/upstream-Cargo.toml` | Two `[workspace]` tables cannot coexist; the members are declared in Imperium's root instead |
| `[workspace.dependencies]` hoisted into Imperium's root manifest | Members reference `spiderweb.workspace = true` etc., which resolves against Imperium's root |

No `.rs` file in this tree was modified.

## Use

Imperium uses this as its message bus: typed publish/subscribe, the supervision
plane (strand threads, panic capture, restart ×3 then quarantine), and the
`spider` orchestrator with its optional cognitive engine.

The bus does not decide policy. Wire framing, AEAD, replay checks, key material,
strainers, sensors and operational policy remain separate owners in
`crates/imperium-*`.

**License note.** Upstream is dual `MIT OR Apache-2.0`. Every member manifest
declares `license.workspace = true`, and once these crates join Imperium's
workspace that resolves to Imperium's workspace value (`MIT`). MIT is one of the
two licenses offered upstream, so the choice is permitted — but it is a change
of declared license, it is recorded here deliberately rather than silently, and
it interacts with the already-open mismatch between Imperium's manifests
(`license = "MIT"`) and its shipped `LICENSE` (PolyForm Small Business 1.0.0),
flagged in `crates/imperium-net-toolkit/CLAMAV-SENSOR.md`.
