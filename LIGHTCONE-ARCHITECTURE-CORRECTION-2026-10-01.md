# Rejected architecture substitution — 2026-10-01

Jesse explicitly required the trained causal geometry itself to constrain
packet passage, with Lightcone passive and unsealed. He rejected the repeated
substitution of a conventional filter and the presentation of additional
endpoint/service policy choices as requirements of his architecture.

## Confirmed error

Assistant commits `35b8902` and `f1ffa52` introduced a v6 world with hand-authored
CIDR/service profiles, condition matching, and a terminal graph node used to
create a transferable relationship. The trained coordinates were serialized
and checked for integrity, but did not supply that passage constraint. The
subsequent uncommitted host/mesh wiring continued that same substitution.

The local training/conditional fixture results validate that implementation's
own rules. They do not demonstrate Jesse's requested geometric filter and
must not be used as acceptance evidence for it. The instruction to explain
static filters was not permission to replace Lightcone with a static policy
engine. Treating it as permission was the assistant's mistake.

## Corrective action

The complete committed history, both diffs and 31 current file copies were
preserved and hash-verified in the private recovery snapshot:

`/home/jesse/Documents/Codex Reinstall Backup 2026-09-30/projects/imperium-rejected-v6-f1ffa52-126b2b2d/`

Only the 21 identified assistant-change paths were restored to `2bb1e8c`.
The ten untracked implementation/artifact files were moved into that snapshot
without deleting them. The v6 implementation is removed from the active build;
its history remains recoverable. No history was rewritten.

The generic kernel packet-holding transport at `2bb1e8c` remains an unconnected
OS transport component. It is not a Lightcone admission mechanism and is not
an accepted substitute for one. No production packet gate was installed by
the rejected v6 work.

The original v4 world remains unchanged and unsealed, SHA-256
`7afb2e711601cd529640e840e57e8dda48bedccc00ebc16000bba7af74d385cf`.
The real VM ingress/egress measurements remain valid evidence of the current
forwarding path's independence from the Lightcone strand. Arrival at an
undeclared port alone must not be called a geometric-filter failure: Jesse
did not define causal relation as membership in a separately invented service
permission list.

## Governing direction for further work

- Follow the user's supplied architecture. Do not introduce a conventional
  allowlist, classifier, condition-policy engine, or extra permission model as
  a replacement for geometric admission.
- Inspect and measure the actual Lightcone mechanism before claiming it
  provides the required constraint. If a capability is absent, report that
  exact absence rather than silently substituting another architecture.
- Network plumbing may connect geometry-admitted data to real transmission;
  it must not independently decide the causal relationship first.
- Keep the world unsealed. Retain failed/rejected evidence honestly.

The requested functional geometric filter is still incomplete. This correction
repairs the unauthorized design direction; it makes no functionality claim.
