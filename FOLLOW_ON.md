# Near-term follow-on items

Tracked items from prior rounds. Completed items are marked; open items remain
as implementation targets.

## 1. ~~Two-phase signature activation~~ (completed Round 5)

Implemented in `imperium-net-sensors/signature_engine.rs`. Engine subscribes to
`net.signatures.approved`, fetches candidate from store, compiles via yara-x,
publishes `SignatureActivated` or `SignatureActivationFailed`. Covered by
integration test 5 and three unit tests.

## 2. ~~CLI dead-topic commands~~ (completed Round 5)

Fixed in `imperium-cli/control.rs`. Removed dead `cli.signatures.*` publishers.
Pipe handler now publishes to correct `net.signatures.*` topics. Added extract,
show, and reject commands. Covered by 11 unit tests and live pipe verification.

## 3. ~~Cross-platform control surface~~ (completed Round 6; Windows removed)

Round 6 added a Unix socket path alongside the Windows named pipe in
`imperium-cli/control.rs` (`#[cfg(unix)]` `UnixListener` module,
`#[cfg(windows)]` named-pipe module, shared platform-agnostic
`dispatch_command_with_staging`, identical `serve_with_staging` entry point).
Windows support was subsequently dropped entirely — Imperium is Linux-only —
so the control surface is the Unix domain socket alone
(`$XDG_RUNTIME_DIR/imperium/control.sock`, `/tmp/imperium-control.sock` fallback).

## 4. ~~Watchtower-initiated extraction path~~ (removed)

The watchtower subsystem has been removed. Signature extraction remains
operator-triggered through `net.signatures.extraction_request`, and candidates
still require operator approval before activation.

## Superseded 2026-09-22

All items above are completed or removed; this file is retained as history.
Live work now tracks under the current work packages: operator-loop
restoration, fusion wiring, and the authenticated handshake. See
`BUS_CONVENTIONS.md` (drift supplement 2026-09-22) and `devnotes.md`
(Windows-path cleanup 2026-09-22) for the latest doc state.
