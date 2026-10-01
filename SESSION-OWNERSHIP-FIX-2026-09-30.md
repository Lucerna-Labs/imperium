# Session ownership collision fix — 2026-09-30

The saved pre-fix in-memory probe showed that two peers could map to one
`SessionId` while the stored owner and address silently switched to the second
peer. See `evidence/adversarial-review-20260930/session_consistency_result.json`.

`SessionManager::create_session` and `adopt_session` now hold both session
indexes under write locks while checking and inserting. An active peer rejects
a second session, and a claimed ID already in use returns `SessionIdInUse`
without changing either index. Removal holds both write locks and removes the
peer index only if it still refers to the removed ID. The live daemon verifies
that the peer/session indexes agree before choosing an address or sealing a
payload for a peer. These are changes to session ownership; the Lightcone world
and its unsealed diagnostic status are untouched.

The same standalone probe now reports `duplicate_accepted=false`, retains the
first peer mapping, creates no second mapping, and leaves both stored owner and
address with the first peer. The exact after-fix observations, source hashes,
and command are in
`evidence/adversarial-review-20260930/session_consistency_after_fix.json`.

Verification completed at the changed boundary:

- Nine focused session tests passed after the first collision guard. The final
  full mesh package run passed 94 library tests, including all current session
  ownership and concurrent adoption/creation tests, plus every integration
  group after the send-time ownership checks.
- `cargo fmt --all -- --check` and the current CLI build passed.
- The existing three-node test ran in an unprivileged user/network namespace.
  Both peer tunnels passed 3/3 ICMP, the unserved route stayed unreachable,
  every route was removed at teardown, and v4 passive/unsealed receipt checks
  passed with zero counted handoff drops.

The earlier automatic review rejection of a live three-peer plaintext-delivery
attack test still limits that exact claim. The test here proves the internal
map no longer accepts a collision and that legitimate three-node traffic still
works. Other security review findings, including replayed Hellos, operator key
distribution, and the unenforced Lightcone filter, remain open in
`ADVERSARIAL-REVIEW-2026-09-30.md`.
