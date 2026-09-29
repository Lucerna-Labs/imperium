# Spiderweb cutover — removing `imperium-bus`

Status: **Phase 1 complete** (vendoring). Phase 2 designed here, not yet executed.
Authority: Jesse, 2026-09-26 — *"we will not be using an imperium bus, it will be
100 percent Spiderweb-Bus-Next."*

## The decision

`crates/imperium-bus` is **deleted**, not renamed, not stripped, not wrapped.
There is no bus crate of ours. Spiderweb-Bus-Next *is* the bus, vendored at
`vendor/spiderweb-bus/` (see its `PROVENANCE.md`).

Subsystem crates depend on the vendored `spiderweb` (and `spider`) directly. The
mandate in `crates/imperium-bus/STRAND-CONVERSION.md` — *"Do not add a direct
`spiderweb` dependency to the subsystem crate"* — is the thing this cutover
reverses, and that file goes with the crate.

## Why the shim existed at all

Not for convenience. **Spiderweb's run loop consumes the bus**: `Bus::run_until(&mut self, …)`.
Imperium's composition is `Arc<Bus>` handed to nine crates, and then
`bus.engage_supervision()` on one of them. A value cannot be both shared as
`Arc` and consumed by a run loop.

`imperium-bus`'s private `enum Supervision { Idle(SpiderwebBus), Engaged(state) }`
in a `Mutex` is precisely the workaround: hold the kernel idle while everyone
else collects `Arc`s, then move it to the run thread on engage. That state
machine, `SupervisionHandle`, the idempotent engage and the `RunningGuard` exist
**only** to bridge that ownership mismatch.

Its second job was API preservation: a "BYTE-IDENTICAL public API — zero call-site
changes across 14 crates", keeping the signatures of the `tokio::broadcast` bus
it replaced. `BusSubscription`, the `tokio::sync::mpsc` bridge, the
`dropped: Arc<AtomicU64>` counter and the `allow`-style `BusError::{Lagged,Closed}`
are that job. Native delivery is push-based with no per-subscriber queue, so
those types have no native counterpart — they can only be deleted, not translated.

## Target ownership model

| Role | Today | After |
|---|---|---|
| Who owns the kernel | `Arc<Bus>` (shim), kernel parked in a `Mutex` | **one** `&mut spiderweb::Bus`, on the thread that runs the loop |
| Everyone else publishes/subscribes with | `Arc<Bus>` | **`Arc<BusPublisher>`** — see the correction below |
| Subsystem registration | `register_strands(&Arc<Bus>)` | `register_strands(&mut spiderweb::Bus)` — `register_spec` needs `&mut self` |
| Receiving events | `BusSubscription::recv().await` (pull, async) | `BusHandle::recv::<T>(socket)` **inside** a strand tick |
| Asynchronous consumption outside a strand | mpsc bridge in the shim | the consumer owns its own queue, explicitly |

That last row is the one real behaviour change and it should not be hidden:
**`Err(BusError::Lagged(n))` ceases to exist for Imperium code.** Native
callbacks never lag, so a consumer that is too slow simply is not protected by
the bus. `imperium-runtime`'s `tokio::select!` loop and `imperium-gui` must own
an explicit bounded queue to keep the property they currently get for free.
That is the honest fix — the property belongs to the consumer, not the bus.

### Corrections found during execution (verified against the vendored source)

- **`BusPublisher` is NOT `Clone`** in the vendored revision — no derive, no
  `impl Clone for` anywhere in `crates/spiderweb`. It has `&self` methods but is
  not itself shareable. The native shareable handle is **`Arc<BusPublisher>`**,
  and that is what the migration uses. `Bus::publisher()` mints a fresh one per
  call (cheap — it clones the kernel's inner `Arc`), so the composition root must
  **mint once and share that `Arc`**. Publisher identity is the only bus identity
  available, so anything keying a registry on `Weak<Bus>` must re-key onto
  `Weak<BusPublisher>` (done for `imperium-net-cluster` and `imperium-net-toolkit`).
- **`Bus::register_spec` returns `()`, not `Result`.** `StrandRegistrationError`
  has no native counterpart and is deleted. The order it enforced is now enforced
  by *ownership*: `run_until(&mut self)` consumes the bus, so registering a spec
  after the loop started is a borrow-check error, not a runtime value. Stronger,
  but not expressible as a test — `imperium-net-cluster`'s
  `registering_after_engage_is_refused` was replaced by
  `specs_queued_before_the_run_loop_are_the_ones_installed`.
- **`register_clone_type::<BusEvent>()` must run before the first publish**, or
  the kernel panics *at delivery time* rather than at registration. `BusEvent::new`
  now does it once behind a `Once`, which gives `imperium-protocol` a `spiderweb`
  dependency. Accepted deliberately: it is Imperium's own envelope registering
  itself with the bus's global registry, not a bus facade, and it removes a
  runtime-panic class across roughly 40 publish sites.

## The migration, in four classes

1. **Registration signatures** — `bus: &Arc<Bus>` → `bus: &mut spiderweb::Bus`,
   across 9 crates: `imperium-runtime/deployment`, `imperium-net-cluster`,
   `imperium-net-transport`, `imperium-net-toolkit`, `imperium-memory-log`,
   `imperium-net-sensors`, `imperium-net-signatures`, `imperium-net-lightcone`,
   plus the CLI composition root (`crates/imperium-cli/src/main.rs`, ~9 call sites).
2. **Error type** — delete the re-defined `imperium_bus::BusError`; use
   `spiderweb::BusError`, which adds a `TypeMismatch` variant. ~12 `match` sites
   in 6 crates (`net-mesh/transport.rs`, `net-mesh/daemon.rs`,
   `runtime/lib.rs`, `net-transport/controller.rs`, `gui/lib.rs`, `cli/main.rs`).
   The native type is non-exhaustively reachable, so those matches need a `_` arm.
3. **Receive loops** — 30 files containing `.recv()` become strand ticks or
   owned queues. `imperium-gui`, `imperium-net-guard`, `imperium-net-mesh` and
   `imperium-net-strainer` are the four that never converted to strands and are
   therefore the real work; the other nine already are.
4. **Dynamic topics** — the shim's `Box::leak` interner existed because native
   routing keys are `&'static str` while two call families `format!` their topic
   (`net.transport.event.{kind}`, `runtime.subsystem.ready.{name}`). Those need a
   bounded set of static socket names, enumerated at compile time.

**Also deleted, no replacement needed:** seven `let _sub = bus.subscribe("net.x.")`
keep-alive lines (in `net-guard`, `net-transport`, `net-mesh`, `net-signatures`,
`net-strainer`, `net-cluster`, `net-sensors`). They were load-bearing under
`broadcast` — dropping a `Receiver` closed the channel — and became inert the
moment the bus was Spiderweb-backed, because the callback is registered in the
kernel and there is no unregister. They have been no-ops since 2026-09-24.

## Order of work

Do not delete the crate first. The crate is the only thing that compiles today;
removing it turns a working tree into a non-building one for the whole migration.

1. Move the supervision *composition* to the CLI (it is the process owner): open
   the bus, register specs, register the spider, `run_until` on a thread.
   Keep the crate until this compiles.
2. Convert one subsystem end-to-end as the worked example, including its tests.
   `imperium-net-lightcone` is the recommended pilot — smallest, already a
   strand, and its `pilot_supervision.rs` already proves the lifecycle.
3. Convert the remaining registration sites (`&Arc<Bus>` → `&mut Bus`).
4. Convert the four non-strand consumers, starting with `imperium-net-strainer`
   and `imperium-net-guard` (single-file, keep-alive-only).
5. `imperium-gui` and `imperium-runtime` last — they are the two that need an
   **owned queue** to preserve backpressure.
6. Delete `crates/imperium-bus/` and `STRAND-CONVERSION.md`.
7. Gates: `cargo test --workspace` zero warnings, bounded live boot confirming
   `[kernel] 🕸️ <name> registered (N inputs, M outputs)`, then the mesh live
   scripts.

## What is at risk

- **No git in this repository.** `.spiderweb-pre-vendor-backup/` covers the
  vendoring change; take a fresh backup before step 6.
- **Push vs pull is a semantic change, not a mechanical one.** Failure mode is
  changed delivery behaviour, which surfaces as flakiness under load rather than
  as a compile error. The two crates that own queues (runtime, gui) are where to
  look first if something behaves differently.
- **`SPIDER_STRAND_NAME`, the cognition env vars** (`IMPERIUM_SPIDER_COGNITION`,
  `IMPERIUM_SPIDER_WARMUP_EVENTS`, `IMPERIUM_SPIDER_HEARTBEAT_STALL_TICKS`) and
  the spider seeding logic are Imperium policy that happened to live in the
  shim. They need an owner — the CLI is the natural one — and they are the part
  of the shim that is *not* compatibility scaffolding.
- **`crates/imperium-bus/src/lib.rs:88`** cites a capability harness at
  `crates/imperium-bus/tests/cognition_intrusion.rs` that does not exist; the
  real end-to-end test is `crates/imperium-cli/tests/spider_cognition.rs`. Move
  or drop the reference when the crate goes.
