# imperium-net-guard

A **no-pass guard**: a gate that refuses *passage*, not a function. It does
not care what an actor wants inside — there is no inside for them. It admits
or it does not, and a failed knock is indistinguishable from silence.

This is the first of the synthetic behavioral stacks. It is dumb and
deterministic per THESIS.md: it admits or it doesn't, and it never decides
policy. The cryptographic verifier behind it keeps all authority; the guard's
job is to stand in front of the verifier and make forcing the gate pointless.

## Honest label (in-band)

This binds **every knocker** — every software or remote actor that must speak
through the probe. It does **not** bind:

- a stolen operator key used cleanly once (that is `imperium-handshake`'s
  problem, not the guard's), or
- a side channel around the gate (that is the oracle stack's problem).

Stated plainly because an unconditional-sounding claim that only holds
in-band is the failure mode this label exists to prevent.

## Report shape — the two blocks every stack carries

### PRINCIPLE LIMIT

Stated in the exchange vocabulary. Each stack's limit is a formal statement,
enforced structurally and pinned by test. Principles create functions; the
block is what transfers to the next stack.

**P1 — Conservation (flux).** For every source `s`, over the current window:

```
spent(s) + remaining(s) = B
```

where `B` is a construction-time constant. "Spent" is a flux across the
ledger boundary, driven by the source's own effort. The ledger is **windowed**,
not per-token-forever: each window is a closed accounting boundary, `spent`
resets with the window, and a token is valid only within its window. Exact per
window; post-window a token is rejected by the window clock, not by memory.

**P2 — Indistinguishability (no-oracle lemma).** For all failing knocks
`k1`, `k2`, whatever the reason:

```
output(k1) ≡ output(k2)   (byte-identical)
bucket(k1)  = bucket(k2)  (same timing bucket)
```

The reason (bad token / reused token / over-budget / bad shape) is visible
**internally** to the operator and **invisible externally** to the knocker.
That duality is the whole gate.

**P3 — No free admission.** `admit(s)` is reachable only via:

```
valid_unused_token(s) ∧ shape_pass(knock) ∧ in_budget(s)
```

Removing any conjunct individually yields a silent reject. The failed conjunct
is named in the internal log; the external output stays identical (P2).

### CRITICALITY

**Axis:** the per-source attempt budget `B`.

- **Too ordered** (`B` too small): one honest operator on a flaky link
  retries, trips the avalanche, and is locked into the lie. Availability
  collapses — a false-lockout blackout.
- **Too chaotic** (`B` too large): the avalanche never trips; the illusion is
  decorative.

**Knife-edge — the rate gap, not the balance point.** For an adversarial
system, criticality *inverts*: honest and adversarial rates are separated, not
balanced.

```
K = (A − L) / σ_L
```

`L` = honest knock count to succeed (1, by design); `A` = avalanche trip
budget; `σ_L` = honest knock jitter (retries, bad weather, network flap).
**Maximize `K`.** Below roughly 6σ the guard locks out its own operator on a
bad day. Threshold-detection is just the adversary measuring `K` by sliding
along the axis.

**Construction-time only.** Criticality is a build-time property,
re-established by rebuilding, never by runtime adjustment — runtime tuning
would be the threshold drift THESIS forbids.

**Slow variable governs.** Tune the standing ledger state, not the
per-request budget.

### The named tradeoff (limiting reagent)

Legitimate knocks spend from the same budget as adversarial ones, and P2
forbids distinguishing them from outside. Under an imitation storm the budget
is consumed by knockers the guard must not refuse, and the endpoint goes dark
for its real operator. Conservation says this is unfixable, only *payable*.

**Payer declared: Option A.** The operator pays with a scarce second factor
they hold and the imitator does not — the persisted operator key from
`imperium-handshake` authenticates the honest knock. The *failure* side stays
indistinguishable (P2); only the honest path carries proof.

## The chain

```
normalized input
 → critical gate
 → zone ledger
 → hysteresis trip
 → cognitive judge   (advisory classification only; never acts)
 → deterministic rule maps classification → action
 → bounded avalanche
 → derived face
 → split-envelope fiction
 → camouflaged output
```

Every layer takes its observables from the shared source id, **independently**
— no layer reads another layer's output. Layer observables do not correlate;
only the internal burned-source pointer does.

The cognitive judge is the E36 pattern: deterministic walls decide the clear
cases, and the judge classifies the gray zone after them, reading strained
context only, **abstaining toward sinking** (over-sink is visible and
recoverable; under-sink leaks invisibly and permanently). The judge emits a
zone classification and nothing else — a deterministic rule maps it to an
action.

## Status

Design complete; implementation in progress. Gates are named for what they
prove, not what they exercise.
