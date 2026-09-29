# ClamAV as a Sensor, Not a Scanner

**Status:** proposal. Nothing here is implemented, and this document changes no
code. Every claim about existing behaviour carries a `file:line` citation and was
read from the tree at the time of writing. Where the text proposes rather than
describes, it says **Proposed**.

**The idea, in the operator's words:** *"i had planned to use clamav not for
virus but as sensors to create an alert system."*

So: ClamAV's machinery as a signal source feeding an alert path — not as an
antivirus that quarantines files.

---

## 0. The short version

The valuable part of this idea is not ClamAV. It is that the alert path is
missing a producer, and ClamAV is a plausible producer.

Two facts in the current tree make that concrete:

1. The cognitive spider's GATE can reach `Quarantine` **only** from an external
   typed warrant (`gate.rs:43-49`, `gate.rs:159-164`), and **no subsystem in
   Imperium supplies one**. `note_verdict` exists as an API and is called from
   exactly one place outside its own definition: a unit test
   (`crates/spider/src/engine.rs:422`, `crates/spider/tests/cognitive.rs:227`).
2. The one live detection→action chain in the node today is a hair-trigger: a
   single byte-pattern match is published with `confidence: 1.0`
   (`crates/imperium-net-sensors/src/signature_engine.rs:151-158`), and the
   orchestrator burns the active protocol on any assessment at or above
   `burn_threshold` (default `0.8`, `crates/imperium-net-transport/src/orchestrator.rs:56`,
   consumed at `crates/imperium-net-transport/src/orchestrator.rs:453-469`).

Fact 1 is the argument for doing this work. Fact 2 is the argument for doing it
carefully: a false-positive-prone matcher wired into the existing shape would
burn the cluster's transport on one bad signature.

**Recommendation in one line:** land the finding message and the verdict bridge
first, with a stand-in finding and no ClamAV; then add ClamAV as a **dormant**
matcher over **our** signature vocabulary (option a), with the vendored corpus
arriving later as an operator-signed, operator-cadenced rotation set (option d).
Do not start with the always-on daemon (option b) or with bytecode (option c).

---

## 1. What "ClamAV as a sensor" can concretely mean

Four readings of the idea. Each is a different amount of work, a different
deployment cost, and a different relationship to the blueprint's YARA decision
(`BLUEPRINT.md:389-396`).

| # | Reading | Work | Fit |
|---|---|---|---|
| a | ClamAV's matcher driven by *our* signatures | author a signature-format bridge; dormant invocation shape; output parser; a finding message | Keeps one vocabulary. Cannot be a continuous sensor — needs a bounded artifact. Detection value is zero *unless* the vendored corpus is also loaded. |
| b | `clamd` INSTREAM as a scan service over the mesh / strainer-rejection stream | a resident daemon; a byte source that does not exist yet; stream framing; per-stream budget; the same finding message | The only reading that is a true always-on sensor. Also the only reading that needs a byte source the architecture does not have (§1b). |
| c | ClamAV bytecode signatures as programmable detection logic | authoring toolchain we do not control; sandbox behaviour to verify; a signature-supply policy for bytecode | Highest sophistication, highest verification cost, least auditable by this project's own review flow (thesis #7's operator approval is hard to apply to opaque bytecode). |
| d | `freshclam` as a rotating signature pipeline | a rotation cadence, a signing/provenance story per bundle, a version/digest surface on the bus | Thesis #8 applied to detection, and genuinely useful — but as stated it is a *feed*, which collides with thesis #10 (§1d). |

### (a) ClamAV's matcher driven by our signatures

The matcher is the cheap part; "our signatures" is the expensive part. ClamAV's
engine consumes its own database formats (hex and logical signatures), not YARA.
Our rules are YARA text (`crates/imperium-net-signatures/src/extractor.rs`
produces rule text; the engine compiles with `yara_x`,
`crates/imperium-net-sensors/src/signature_engine.rs:125-137`). A bridge from our
vocabulary to ClamAV's is a strict-subset translation with different offset and
condition semantics — real work, and a translation that can drift silently.

Worse, if the bridge is faithful then (a) adds **no detection power at all**.
ClamAV and YARA are both deterministic matchers; given the same bytes and the
same rule text they return the same answer. What (a) buys in that configuration
is an independent *implementation* of matching — a matcher-bug detector, which is
a legitimate test tool and not an alert source. The added information only
appears once ClamAV's own corpus is loaded alongside ours, because then the
matcher knows things our rules do not. That makes (a) and (d) one thing, not two,
and it is the reason the recommendation sequences them.

Where (a) fits cleanly: **barely at all as a stream sensor**, and **very well as a
dormant tool that inspects a bounded artifact** — a capture file, a quarantine
staging directory, an extracted binary. That is the shape `imperium-net-toolkit`
already models: a manifest with trigger conditions, an idle timeout, a cooldown,
and an hourly activation budget (`crates/imperium-net-toolkit/src/lib.rs:111-118`).

### (b) `clamd` INSTREAM as a scan service

This is the reading that matches "sensors monitoring network and system" most
literally, and it needs the most from the substrate.

It needs a byte source. Nothing in the running node feeds bytes to a sensor:

- `SignatureEngineSensor::scan` is called only from tests
  (`crates/imperium-net-sensors/src/signature_engine.rs:114-169` is the
  implementation; every caller in the tree is a test).
- `EnvelopeSensor` is constructed only inside its own tests
  (`crates/imperium-net-sensors/src/envelope.rs:843`); `evaluate_window` has no
  production caller (`crates/imperium-net-sensors/src/envelope.rs:565`).
- `ClassifierSensor` is re-exported (`crates/imperium-net-sensors/src/lib.rs:7`)
  and never instantiated outside its unit tests.

The one production path where raw wire frames exist is the lightcone strand's
frame lane (`crates/imperium-net-lightcone/src/lib.rs:56-58`), and it is
contractually content-blind: *"The frame is never modified. Structure is read from
bounded wire fields only — payload text cannot select world nodes."*
(`crates/imperium-net-lightcone/src/lib.rs:112-113`). Putting a content-reading
matcher on that lane would put a payload-reading organ inside the geometry lane.
**Proposed:** if (b) is ever built, the scanner is a *separate* strand that
declares the same frame socket; the lightcone's contract is not widened.

Two more hard limits on (b):

- A strainer rejection is a *fact about shape*, not the bytes that failed:
  `StrainerRejection` carries `shape_failed: String` and an optional
  `source_identifier: Option<SocketAddr>` and nothing else
  (`crates/imperium-protocol/src/lib.rs:583-589`). To feed ClamAV from that
  stream you must first capture the rejected frame, which nothing does today.
- Thesis #4 is unambiguous that strainers never modify forwarded user traffic
  (`THESIS.md:61`). A scanner hanging off the strainer path is not itself a
  modification, but the captured bytes are user bytes; the scope question in §6
  applies with full force.

### (c) ClamAV bytecode signatures

Bytecode signatures are the most interesting fit for "programmable detection
logic" and the weakest fit for this project's review discipline. Thesis #7
requires that signatures be *reviewable by the operator* and that no signature is
promoted automatically (`THESIS.md:81-88`). A hex pattern or a YARA rule can be
read and judged by a human; opaque bytecode cannot be judged with the same
confidence, and this project does not control the compiler toolchain that
produces it. **Proposed:** out of scope until (a) and (d) exist and the review
flow has been exercised on readable signatures. The properties of ClamAV's
bytecode toolchain should be *verified against the version we would pin* before
any claim about it is written down; this document makes none.

### (d) `freshclam` as a rotating signature pipeline

Thesis #8 is the right frame — *"The architecture's primitives are static;
everything composed from them rotates"* (`THESIS.md:90-94`) — and a detection
vocabulary that rotates on the operator's cadence is exactly the right thing.

But there is a collision with thesis #10 that must be resolved, not glossed:
*"No external dependencies for runtime correctness. No phone-home, no telemetry,
no auto-update of signatures or models from vendor infrastructure."*
(`THESIS.md:101-105`). `freshclam` in its normal mode is a daemon that
auto-updates from vendor mirrors. That is the thing #10 rules out.

**Proposed resolution:** `freshclam` runs as a **bundle fetcher, operator-armed
and operator-signed** — the operator decides when to rotate, the fetched bundle
is pinned with a version and digest, the digest is what the finding records, and
the node never depends on the fetch succeeding. Under that reading, (d) is
thesis-compliant and is the mechanism by which (a) gains its detection value. If
the operator's intent was a self-updating daemon instead, that is a thesis
amendment, not an implementation detail, and should be decided as one.

### Recommendation for the first increment

**(a), with the vendored corpus deliberately not loaded on the first pass**, and
with the sequence below respected:

1. First land the finding message and the verdict bridge (§2, §3) with a stand-in
   finding. No ClamAV, no process, no signature bridge. This is the cheapest
   part and it closes the biggest gap — the spider's unfilled verdict input and
   the absent alert record (§7).
2. Then land (a): dormant manifest, bounded artifact, our rules only, EICAR plus
   a bundled rule as the acceptance gate. The purpose of this pass is to make the
   epistemic path real end to end, **not** to make a detection claim.
3. Then add (d) as the rotation mechanism, which is what makes (a) actually know
   something our rules do not.
4. (b) and (c) are later, and (b) is gated on a byte-source decision that does
   not exist yet.

Why not the other three first: (b) cannot run without a byte source that does not
exist; (c) cannot be reviewed under the operator-approval law; (d) alone is a feed
with no matcher to feed, and it carries the thesis #10 question above.

---

## 2. The epistemic path: finding to message to topic to consumer

### What the existing sources are, class by class

| Source | What it publishes | Epistemic class | Citation |
|---|---|---|---|
| Classifier micro-model | `ThreatAssessment { source: Classifier, confidence }` on `net.sensors.threat` | statistical score | `crates/imperium-net-sensors/src/classifier.rs:88-105` |
| Normality envelope | `ThreatAssessment { source: Heuristic { name: "envelope-vN" }, confidence = 0.5 + 0.5 * severity }` on `net.sensors.threat` | statistical score | `crates/imperium-net-sensors/src/envelope.rs:584-620` |
| Signature engine | `ThreatAssessment { source: SignatureEngine, confidence: 1.0 }` on `net.sensors.signature_match` | structural fact, expressed in the score field | `crates/imperium-net-sensors/src/signature_engine.rs:151-163` |
| Lightcone | a receipt of `[u8; 32]` digests and `[u64; …]` words on `net.lightcone.receipt` — **no score field exists** | geometric fact | `crates/imperium-net-lightcone/src/lib.rs:111-127`; `crates/imperium-net-world/src/lib.rs:333-343` |
| **ClamAV finding (Proposed)** | a finding with a rule identity, a subject digest, and a disposition band; **no confidence** | external verdict / foreign-provenance match | this document |

The law these classes are held to is stated twice in the tree. In the fusion
code: *"Geometric impossibility FACTS and statistical envelope SCORES are
separate epistemic classes and are never fused into one number here"*
(`crates/imperium-net-sensors/src/fusion.rs:31-35`). In the spider's GATE: the
verdict type *"has deliberately no scalar 'score' variant — that would violate
the anti-collapse law"* (`crates/spider/src/gate.rs:41-44`).

### Where a ClamAV finding sits

It is a **fifth class**, and the distinction matters: not a score of ours, not a
fact of ours, not geometry — a **match from a foreign vocabulary, reported by
name**. Its trust is different in kind from the other four. Our signature
engine's match is structural ground truth *because we authored the rule*; a
vendored corpus match is a claim by someone else's table of names, and the honest
description of the fact is "this deployment's substrate resembles something a
third party called bad".

That is why it must not be a `ThreatAssessment`. The struct's shape forces the
collapse: it has `confidence: f64` (`crates/imperium-protocol/src/lib.rs:750-757`)
and the fusion code branches on that field
(`crates/imperium-net-sensors/src/fusion.rs:58-101`). A finding published as a
`ThreatAssessment` would be fused — and note the live consequence of the existing
shape: `signature_engine.rs:153` sets `confidence: 1.0`, the orchestrator burns
the active protocol at `confidence >= burn_threshold`
(`crates/imperium-net-transport/src/orchestrator.rs:453-469`, default `0.8` at
`:56`), and the burn path promotes standby and quarantines the previously active
protocol (`crates/imperium-net-transport/src/orchestrator.rs:192-232`). A
false-positive-prone matcher sharing that shape burns the cluster's transport on
one match. This document treats that as the central hazard of the whole idea.

### The finding message, and why it is a new message type

**Proposed.** A new `imperium-protocol` variant (new message types are *designed,
not improvised* — `THESIS.md:28`), carrying:

- **engine identity** — which matcher, and the version string of the binary that
  produced it, so a finding is attributable to the thing that made it.
- **rule identity** — the rule id, plus which layer it came from, `Bundled` or
  `Extracted`, mirroring `SignatureLayer`
  (`crates/imperium-net-sensors/src/signature_engine.rs:36-40`). Thesis #7
  requires the two layers stay visibly distinct in every view
  (`THESIS.md:86-88`).
- **corpus provenance** — whether the matching signature is ours or from a
  vendored bundle, plus that bundle's version and digest. This is the field that
  makes (d) auditable and makes the operator's rotation decision meaningful.
- **subject** — a digest of what was scanned, the subject kind (path, captured
  stream, memory image), and a bounded locator; not the bytes, not a full path.
- **disposition band** — an enum: a match, a clean scan, the engine unavailable,
  the engine errored. **Never a float.** Justified by `crates/spider/src/gate.rs:41-44`
  and `crates/imperium-net-sensors/src/fusion.rs:31-35`.
- **the activation that produced it** — the tool name and activation identity, so
  the finding joins to the budget slot it spent
  (`crates/imperium-net-toolkit/src/lib.rs:459-513`).

Deliberately absent: `confidence`, and `SuggestedAction`
(`crates/imperium-protocol/src/lib.rs:767-773`). A sensor reports; the
deterministic policy decides (`THESIS.md:36-39`).

### The topic, and why the topic *is* the boundary

**Proposed:** `net.sensors.clamav`, not `net.sensors.threat`.

This is not cosmetic. The transport orchestrator's threat lane consumes the topic
prefix `net.sensors.` (`crates/imperium-net-transport/src/strand.rs:137`) and
funnels matched messages into `handle_threat_assessment`
(`crates/imperium-net-transport/src/strand.rs:248-270`), which aggregates
assessments into a per-remote-address window
(`crates/imperium-net-transport/src/orchestrator.rs:364-400`) and acts on the
fused result (`crates/imperium-net-transport/src/orchestrator.rs:402-451`).
Sharing the topic *is* fusion. A distinct topic plus a distinct message type
means the orchestrator's lane receives the event and drops it at its message gate
(`crates/imperium-net-transport/src/strand.rs:248-253`) until someone
deliberately teaches the policy about it — which is the correct default.

### The consumers

| Consumer | What it does with a finding | Status |
|---|---|---|
| Alert surface (§7) | raises an operator-visible alert record | **does not exist** |
| `imperium-memory-log` | durable event history, and input to operator-selected extraction | a lane pattern exists to copy: `crates/imperium-memory-log/src/strand.rs:147-158` |
| Operator-approved extraction | a human may select the finding's triggering events and ask for a rule | exists (`THESIS.md:81-88`); automatic promotion is forbidden |
| Verdict bridge (§3) | converts a strand-shaped finding into the spider's typed warrant | **half missing** |
| Orchestrator policy | nothing, until a deterministic rule is written for this class | deliberately out of reach |

---

## 3. The verdict path to the spider

This is the whole point of the exercise, so it is worth naming the join exactly
and then being blunt about what is absent.

### The join, named

The path, with each hop's citation:

1. A `Verdict` is constructed — `Verdict::{Benign, Threat}`
   (`crates/spider/src/gate.rs:46-49`).
2. It is handed to the engine: `CognitiveEngine::note_verdict(&mut self, node,
   verdict)` (`crates/spider/src/engine.rs:422-424`), which stores it in
   `pending_verdict` (`crates/spider/src/engine.rs:358`).
3. On the tick, the engine reads it into `Candidate.verdict`
   (`crates/spider/src/engine.rs:615-625`; the field at
   `crates/spider/src/gate.rs:133`).
4. `gate()` turns `Some(Verdict::Threat)` into `Decision::Block`
   (`crates/spider/src/gate.rs:159-164`).
5. `Decision::control()` maps a `Block` to `ControlMsg::Quarantine { name, reason }`
   (`crates/spider/src/gate.rs:86-99`).
6. The strand publishes it on `SYS_CONTROL` (`crates/spider/src/lib.rs:295-300`)
   and the kernel executes it.

**That is the join: `note_verdict` plus the message that carries the verdict into
the strand's `run` loop.** Everything upstream of step 2 and downstream of step 6
already works.

### What is missing, item by item

**(i) No carrier type.** The spider's observable inputs are `LifecycleEvent` and
`Vibration` only (`crates/spider/src/lib.rs:120-129`). `Vibration` has exactly two
variants — backpressure and starvation (`crates/spiderweb/src/lib.rs:271-292`) —
and neither is a warrant. There is no socket a verdict could arrive on.

**(ii) No call site.** `note_verdict` appears exactly twice in the spider
repository: at its own definition (`crates/spider/src/engine.rs:422`) and in a
unit test (`crates/spider/tests/cognitive.rs:227`). The strand defines forwarding
helpers for `note_registered`, `note_detached`, `note_quarantined`,
`note_vibration`, and `note_heartbeat` (`crates/spider/src/lib.rs:310-335`) — and
**no helper for a verdict**. The loop never calls it.

**(iii) No producer.** Nothing in Imperium publishes a verdict, and nothing in
the Imperium workspace mentions ClamAV at all outside the excluded `reference/`
tree (`Cargo.toml:30` excludes it; the only ClamAV code in this repository is
`reference/cloakwise/src/security/threat_detection.rs:285-313`, which is prior
art for a dormant scanner tool, not part of the workspace).

**(iv) The ordering blocks the reflex — this is the sharpest one.** The GATE
consults the verdict *inside* the deviating branch only: the verdict is read at
`crates/spider/src/engine.rs:615-618`, inside the block entered when
`ev.deviating` is true, and an uncorroborated candidate abstains **before** the
verdict is examined (`crates/spider/src/gate.rs:152-158`), with
`min_corroboration` defaulting to 2 (`crates/spider/src/engine.rs:119`). So a
`Threat` verdict about a node that is *not* intrinsically misbehaving is never
consulted — the comment says so: *"an uncorroborated sample abstains without
spending the verdict"* (`crates/spider/src/engine.rs:616-617`). The idea of a
known-bad signature causing an instant quarantine is therefore **not reachable
today, and not merely for want of a producer**: it contradicts the GATE's
ordering. Reaching it is a spyder-repository design change, not an Imperium
change, and it must be argued on its own merits.

**(v) The subject has no name.** `ControlMsg::Quarantine { name, … }` names a
**strand of the web**. The kernel's job is to execute it against a strand slot —
and the whole supervision design is built on that (`(since-deleted) crates/imperium-bus/src/lib.rs:88-92`;
the (since-deleted) `crates/imperium-bus/STRAND-CONVERSION.md` §4 lists
`ControlMsg::{Restart{name}, Quarantine{name, reason}, Shutdown, SetTransfer{node, policy}}`).
Today's web has a known, small set of strand names — `imperium-net-lightcone`
(`crates/imperium-net-lightcone/src/strand.rs:46`), `imperium-net-sensors`
(`crates/imperium-net-sensors/src/strand.rs:64`), `imperium-net-toolkit`
(`crates/imperium-net-toolkit/src/strand.rs:91`), `imperium-net-signatures`
(`crates/imperium-net-signatures/src/strand.rs:78`), `imperium-net-cluster`
(`crates/imperium-net-cluster/src/strand.rs:94`), the transport lanes
(`crates/imperium-net-transport/src/strand.rs:163-174`), the memory-log lanes
(`crates/imperium-memory-log/src/strand.rs:121-124`), and the deployment lanes
(`crates/imperium-runtime/src/deployment/strand.rs:154-158`).

A ClamAV finding is about **bytes**. Bytes are not a strand. So the missing join
is two halves, and they are very different sizes:

- **Mechanical (small):** one message type, one socket added to the spider's
  `inputs()`, one forwarding helper, one `note_verdict` call in the loop. Nameable
  and bounded. It lives in the Spiderweb repository, not this one.
- **Semantic (large, undecided):** *which node does this finding name?* There is
  no answer in the tree, and inventing one by habit would be the mistake.

### What is reachable, stage by stage

| Finding subject | Today | After the mechanical join | After a naming decision |
|---|---|---|---|
| Our own strand's integrity (signature DB digest mismatch, engine refuses to load, repeated engine errors) | nothing — no producer | **can reach `Quarantine`**, because the subject is a strand and the deviation is real | already reachable |
| A remote peer's stream | nothing | nothing — a remote address is not a strand name | needs a decision: the mesh/cluster notion of a peer is not the kernel's naming scheme |
| A file or artifact on this host | nothing | nothing | needs a decision, and "quarantine the scanner" is the wrong answer |

The honest reading of the requirement: the spider's `Quarantine` is a
**containment action on our own web**, not a verdict about a remote adversary.
The two roles that a ClamAV finding most naturally plays are therefore different
targets:

- **Containment (the spider):** the finding that says *our own detector is
  compromised* — a mutated signature database, an engine that cannot load, a
  scanner that keeps failing. That is strand-shaped, it is genuinely
  survivable-surprise material for the web, and it is a real defensive verdict.
  It is also the only ClamAV finding that can reach `Quarantine` without
  inventing naming. One consequence to know first: quarantining the toolkit
  strand stops it reconciling process state, but its supervisor thread still
  runs and still stops the processes it owns — supervision of a loop and of its
  subprocesses are deliberately separate concerns
  (`crates/imperium-net-toolkit/src/strand.rs:73-76`). Quarantining the toolkit
  is therefore not a way to stop a running scan.
- **Threat response (the orchestrator):** a finding about an artifact or a
  stream. The existing consumer for "something is wrong, react" is the
  orchestrator's burn/rotation path (`crates/imperium-net-transport/src/orchestrator.rs:453-469`),
  and thesis #6's rotation posture (`THESIS.md:73-79`) is the house answer for a
  suspected compromise. Routing a file finding at the spider's GATE would
  misdescribe the subject.

**Proposed first verdict to prove the join:** the sensor's own integrity, as
above. It is small, it is testable, it produces real corroborated deviation, and
it does not require the naming decision to be made under time pressure.

---

## 4. Always-on sensor or dormant tool

Stated as a fork with consequences. The blueprint's decision, for reference:
YARA is the matching engine, *"BSD-licensed (no GPL entanglement with the
single-binary deployment story), designed for byte-pattern matching against
streams, lighter than ClamAV at runtime"*, and *"ClamAV stays as a dormant tool
(Phase 7) for heavy-scan activations"* (`BLUEPRINT.md:391-396`).

### The GPL and deployment cost, first class

Facts: the workspace declares `license = "MIT"` (`Cargo.toml:34`); the repository
ships a PolyForm Small Business 1.0.0 `LICENSE` (`LICENSE:1`) — a mismatch worth
resolving independently, because it changes what "entanglement" means. ClamAV is
an external binary in every prior art we have
(`reference/cloakwise/src/security/threat_detection.rs:292` invokes
`/usr/bin/clamscan`). We never link ClamAV into our Rust crates, so the GPL
question is a **distribution** question — what we ship, and whether the operator
installs ClamAV themselves — not a linkage question about our binary.

The blueprint's phrase "single-binary deployment story" is the crux, and the
end state it refers to is *"one binary: `imperium`, with Imperium capabilities
present as crates in the workspace"* (`BLUEPRINT.md:17`). An external binary
called by a tool does not break that story any more than calling `xray` does: the
transport controllers already own a `ManagedProcess` for external binaries
(`crates/imperium-net-transport/src/controller.rs:8`, `:55`, `:133`), which the
blueprint explicitly sanctions (`BLUEPRINT.md:188-199`, `:211-215`).

Thesis #1's prohibition deserves a precise reading: it forbids *"spawning child
processes for 'the UI' or 'the orchestrator'"* (`THESIS.md:30`). It is a
prohibition on moving the substrate and the decision-maker out of process. A tool
that an operator arms is not the orchestrator. So ClamAV-as-tool is
architecturally sanctioned; ClamAV-as-a-service-that-decides would not be.

### The case for always-on

An alert system needs the sensor present when the event happens. A dormant
sensor's view of the past is bounded by what was retained, and **nothing retains
bytes** in this tree:

- the lightcone keeps geometry, not payload — a receipt is digests and words
  (`crates/imperium-net-world/src/lib.rs:333-343`), and the contract says the
  frame is never modified and payload text cannot select nodes
  (`crates/imperium-net-lightcone/src/lib.rs:112-113`);
- a strainer rejection keeps a shape description string, not the offending frame
  (`crates/imperium-protocol/src/lib.rs:583-589`);
- the memory log records events, not frame bodies (`crates/imperium-memory-log/src/strand.rs:147-158`).

So a dormant scanner triggered by a bus event scans *nothing* — the event names a
shape, and the bytes are gone. This is a structural argument, not a preference:
**dormancy and byte-level alerting are in tension unless something buffers.**

### The case for dormant

- Phase 7's acceptance criterion is explicit: *"Forensics tools start dormant
  (zero resource usage)"* (`BLUEPRINT.md:524-528`).
- A resident `clamd` means a daemon, a signature database in memory and on disk,
  a socket, and a new failure surface — on a node whose whole design is a small
  number of supervised strands.
- Thesis #3's floor test (`THESIS.md:51`) is easiest to satisfy with a tool that
  is simply absent when unused.
- An always-on ClamAV reopens the YARA-vs-ClamAV decision, because an always-on
  ClamAV *is* a second stream matcher and now competes with Phase 4's job.

### Engaging the blueprint's four reasons honestly

| Reason | Verdict of this document |
|---|---|
| BSD vs GPL entanglement | **Partially disagrees.** No linkage occurs; the cost is distributional. Keep it as a real cost, but it is not decisive on its own, and the `MIT` manifest versus PolyForm `LICENSE` mismatch should be settled first. |
| Designed for byte-pattern matching against streams | **Agrees**, and it is why ClamAV should not be the always-on stream matcher. |
| Lighter than ClamAV at runtime | **Agrees**, and it is the same conclusion. |
| ClamAV stays a dormant tool for heavy-scan activations | **Agrees with the placement, disagrees with the job.** Phase 7 tools are forensic: activated *after* something was noticed, over artifacts (`BLUEPRINT.md:502-530`). A sensor must be *present at event time*. These are different roles, and the blueprint never assigned ClamAV the sensor role — it assigned it the heavy-scan role. |

The synthesis: the blueprint's decision stands and does not need reversing. What
this document proposes is a **third role** the blueprint did not enumerate — a
dormant matcher whose *findings are live*. The matcher is expensive and stays
dormant; the finding path is cheap and stays up. That preserves both the YARA
decision and the Phase 7 dormancy criterion while giving the idea a home.

**Recommendation:** dormant, per the blueprint, with the finding path live. If
the operator wants an always-on byte-level sensor, the honest price is a resident
clamd *and* a capture policy for frames — and that price should be paid only
after the first increment proves the finding path is worth feeding.

---

## 5. Prerequisite: the managed-process lifecycle

Stated plainly, and stated as of this writing — because it changed while this
document was being written. A concurrent workstream landed real process
execution for the toolkit during it.

### What is true now

The toolkit really runs processes. A manifest attaches a `ToolProgram` — binary,
argv template, environment, working directory, resource budget, graceful-stop
window, health-check interval — through `ToolManifest::with_program`
(`crates/imperium-net-toolkit/src/lib.rs:141-148`; the program type at
`:168-189`). `activate` passes the same gates as before and then **spawns the
declared binary** through `imperium_managed_process::ManagedProcess`
(`crates/imperium-net-toolkit/src/lib.rs:459-513`; the spawn at `:500`),
`deactivate` stops it gracefully (`:534`), and the pid is readable (`:703`). The
sync-strand / async-process seam is closed by a dedicated supervisor thread with
its own single-threaded runtime that owns every process
(`crates/imperium-net-toolkit/src/proc.rs:235`, `:245`, `:280`, `:294`, `:306`).
What the manager observes is `ProcessPhase` (`:130`), `StopCause` (`:94`) and
`ToolProcessReport` (`:145-156`), and `ToolManager::tick` turns a stop outcome
into the reason text of the state change that cools the tool down
(`crates/imperium-net-toolkit/src/lib.rs:586-611`).

### What is still true, and what it means for this idea

- **No tool declares a program at boot.** The composition root registers two
  manifests and neither attaches a program
  (`crates/imperium-cli/src/main.rs:352-377`), so a booting node still spawns no
  tool process. The crate's module docs state the same from the other side:
  *"A tool that declares **no** program keeps the original behaviour: activation
  is a state transition only."* (`crates/imperium-net-toolkit/src/lib.rs:29-32`).
- **A process's output is a log line, not a message.** `ManagedProcess` pipes
  stdout and stderr into the tracing log
  (`crates/imperium-managed-process/src/lib.rs:134-135`, `:148-172`), and
  `ToolProcessReport` carries process *state* only — phase, pid, start time,
  outcome, detail (`crates/imperium-net-toolkit/src/proc.rs:145-156`). A tool's
  *findings* therefore do not reach the bus at all. **The finding producer is
  still entirely unwritten**, and it is the piece this idea actually needs: an
  output parser that turns scanner output into the finding message, and a
  decision about whether the scanner should write structured output instead of
  prose we parse.
- **The activation topic still has no production consumer.**
  `net.toolkit.activation` is published
  (`crates/imperium-net-toolkit/src/lib.rs:508-511`) and observed only by tests
  (`crates/imperium-runtime/tests/hardening_simulation.rs:735`; the topic table
  at `(since-deleted) crates/imperium-bus/src/lib.rs:1047`). The spawn is the supervisor
  thread's effect, not a bus consumer's.
- **The declarative triggers still have no production caller.** `check_trigger`
  (`crates/imperium-net-toolkit/src/lib.rs:727`) is called only from its own
  tests (`:922-928`); the orchestrator publishes tool requests directly
  (`crates/imperium-net-transport/src/orchestrator.rs:576-593`). The blueprint's
  *"activate when `ThreatAssessment` with severity > 0.8 lands on the bus"*
  (`BLUEPRINT.md:521`) remains declarative-only.

### What a ClamAV tool would declare

A `ToolProgram` for the scanner binary, with an argv template whose context
carries the artifact locator, a budget with a `max_runtime`, an idle timeout in
the manifest, and an hourly activation budget — entirely through the interface
above, with nothing ClamAV-specific in the toolkit. The argv template's
`{{context.KEY}}` placeholders (`crates/imperium-net-toolkit/src/lib.rs:159-161`)
are how the activation request's context reaches the process, which is how the
finding's subject gets to the scanner.

### Why this document does not depend on that landing

The design's contract is the **finding on the bus**, and the first step in §1
needs no process at all. Step 1 mints a stand-in finding and drives the verdict
bridge — where the gaps actually are (§3, §7). When the scanner is wired, it
plugs into a socket already proved to carry something.

One discipline carried over from the front of this repository: the spider's
capability harness asserts on the wire *"instead of parsing log lines"*
(`(since-deleted) crates/imperium-bus/src/lib.rs:87-89`). The same rule applies here. A ClamAV
finding must be a message, and no control decision may be made by grepping the
scanner's stdout.

---

## 6. Honest limits

### What it cannot see

- **Bytes.** Nothing in the running node feeds bytes to a sensor (§1b). A
  content matcher with no content is an interface, not a detector.
- **Plaintext scope.** This is the largest limit and it constrains the idea's
  original framing. An antivirus organ reads files and memory; a VPN's forwarded
  user traffic is a ciphertext tunnel, and thesis #4 forbids touching forwarded
  user traffic at all (`THESIS.md:61`). The plaintext that exists inside this
  process is the *user's* traffic, and the system's stated posture is local-first
  and minimal (`THESIS.md:101-105`). The honest scope for a ClamAV organ here is
  therefore: **our own substrate** — bundled and extracted signature files, model
  files, unit/binary artifacts, staging and quarantine directories, captured
  forensics output — plus any byte stream an operator explicitly designates. Not
  the users' payloads. Any claim that this is a network sensor should be made
  only after the capture question is answered in writing.
- **Zero-days and unknown-bad.** A signature-bound matcher is silent on anything
  outside its vocabulary. This is the reason to keep it strictly additive.
- **Intent.** A match says an artifact resembles something named; it says nothing
  about who sent it or why.

### What it cannot decide

- It cannot convict. A vendored corpus match is a claim by a foreign vocabulary,
  and the false-positive cost is a burned transport (§2). The GATE's own posture
  is the right one to borrow: *"surprise alone justifies a redirect, not a kill"*
  (`crates/spider/src/gate.rs:144-146`).
- It cannot promote signatures. Automated promotion is forbidden
  (`THESIS.md:84`), and a vendored match is explicitly not our vocabulary to
  promote.

### Additive, not load-bearing

The test for every component is *"pull this component out. Does the system still
function at a known-good floor?"* (`THESIS.md:51`). For this work:

- With the ClamAV tool unregistered and the finding topic silent, the node must
  boot identically, pass the same tests, and behave as it does today. The
  precedent for that discipline is the cognition switch: default off, arming
  logged loudly, an invalid config degrading to off
  (`(since-deleted) crates/imperium-bus/src/lib.rs:43-53`).
- With the whole sensor removed, what remains is the deterministic floor:
  strainer geometry, the orchestrator's four-state policy, hybrid PQC, and
  operator-approved signatures. That floor is load-bearing; this is not.
- The sensor's own documentation should claim this the way the envelope does:
  *"pulling it out leaves the deterministic floor untouched (THESIS principles 3
  and 5)"* (`crates/imperium-net-sensors/src/envelope.rs:19-21`).

A footnote that matters for honesty: the substrate the ClamAV organ would defend
is *already* the thing most capable of breaking it — a mutated signature database
or a replaced binary turns the sensor into a source of adversary-shaped findings.
The alert budget (`crates/spider/src/conserve.rs:1-25`) bounds the damage the
alarm can do; the operator's approval flow bounds the damage a signature can do.
The organ itself is not trusted.

---

## 7. The alert-events gap this exposes

### What an alert is today

It is a `ControlMsg` on `sys.control` plus a log line, and the bus crate says so
explicitly, including that no other channel is needed: *"An alert is a
`strand::ControlMsg` on `sys.control` plus a spider log line; there is no separate
notification channel, and none is needed"* (`(since-deleted) crates/imperium-bus/src/lib.rs:59-62`).
The doc's suggested way to observe alerts is a **test-shaped recorder strand**
registered with a `ControlMsg` input (`(since-deleted) crates/imperium-bus/src/lib.rs:64-85`).

That is true for tests. In production nothing subscribes to `sys.control`. The
only observers in the tree are test recorders
(`crates/imperium-cli/tests/spider_cognition.rs:205`). Two consequences:

- **No alert record exists.** The alarm's output is a control-plane message
  addressed to the kernel. There is no raised/acknowledged/cleared lifecycle, no
  retention, no dedup across a strand restart, and nothing an operator can query
  after the fact.
- **The existing operator surfaces see something else.** The GUI consumes
  `BusEvent`s (`crates/imperium-gui/src/lib.rs:274`) and renders a threats table
  from `ThreatAssessment` rows (`crates/imperium-gui/src/views/threats.rs:1-48`;
  state rows at `crates/imperium-gui/src/lib.rs:411-416`). `ControlMsg` is not a
  `BusEvent` payload, so a spider `Quarantine` never appears there. The CLI has
  no status or alert command at all — `NodeAction` offers only `Start`
  (`crates/imperium-cli/src/main.rs:40-48`).

So the system senses, decides, and acts, and the operator's view of the decision
is a log line.

### The gap, named

The gap is not "we need notifications". It is that **the decision and its record
are the same object, and that object is not addressed to a human.** `ControlMsg`
is addressed to the kernel, which consumes it by acting. There is no separate
artifact that says *an alert was raised, here is its evidence, here is what the
system did about it, here is whether it is still open.*

### Options for closing it, not a design

Named, not designed — the alert system is not built, and Jesse said so.

| Option | Shape | What it must respect | Cost |
|---|---|---|---|
| A. Alert event on a `net.*` topic | a new payload carrying the decision, its class, its evidence ids, and its outcome; rendered by the existing threat-feed surface | the three epistemic classes must survive into the UI — a geometric fact and a statistical score must not be drawn as one percentage | one message type, one producer, one view |
| B. A memory-log lane | the established pattern for durable event history (`crates/imperium-memory-log/src/strand.rs:147-158`) | retention and projection semantics; alerts are not free text | a lane + a topic; gains history for free |
| C. A control-socket query | a read-only command over the existing control surface (`crates/imperium-cli/src/control.rs:30-36`) | no new process, no new port (`THESIS.md:30`) | small, but only useful once something retains state |
| D. A `sys.control`-observing production strand | the bus doc's own recorder pattern, promoted from test to production, minting alert records for A/B/C to read | the kernel already executes every control message, so this is an observer, never a decider | small; it is the only option that can see what the kernel was actually told |

Constraints all four share: the operator is the final authority
(`THESIS.md:96-99`); no new process or localhost service (`THESIS.md:30`); no
notification path that becomes a phone-home (`THESIS.md:101-105`).

One thing to decide before building any of them: **whether an alert is an event
or a state.** A `Quarantine` is a transition; "the sensor is compromised" is a
condition with a lifetime. The GATE's own emission discipline is edge-triggered —
one alert per episode, and only on a change (`crates/spider/src/engine.rs:632-643`).
Whatever surface is chosen should preserve that property rather than turning an
episode into a stream.

---

## 8. Tensions found while writing this

Recorded rather than resolved. Each is a place where the idea, the blueprint, and
the thesis do not yet agree.

| # | Tension | Where it bites |
|---|---|---|
| 1 | **Instant quarantine from a known-bad match is unreachable.** The GATE reads a verdict only after corroborated intrinsic deviation (`crates/spider/src/engine.rs:615-625`), so an external warrant cannot convict a well-behaved node. | The two-tier reflex the idea implies is a Spiderweb design change, not an Imperium one. |
| 2 | **The verdict's subject has no name.** `Quarantine` names a strand; a finding names bytes. | §3; needs an operator decision, not a coding decision. |
| 3 | **`freshclam` as a live feed collides with thesis #10** (`THESIS.md:101-105`). | §1d; resolvable as operator-armed, operator-signed rotation, but that reading should be confirmed. |
| 4 | **An always-on ClamAV reopens YARA-vs-ClamAV** (`BLUEPRINT.md:391-396`). | §4; avoided by keeping the matcher dormant and the finding path live. |
| 5 | **Phase 7's dormancy criterion conflicts with event-time sensing** (`BLUEPRINT.md:524-528` vs §1b's missing byte source). | §4; the "dormant matcher, live findings" split is the proposed answer. |
| 6 | **The blueprint's `ThreatAssessment` never became the shape it described.** The blueprint promises `id`, `severity`, `evidence_event_ids`, and a `Combined` source (`BLUEPRINT.md:365-372`); the struct has none of them (`crates/imperium-protocol/src/lib.rs:743-757`). | Any design that assumes evidence ids exist is building on a field that is not there. Evidence linkage has to be added deliberately. |
| 7 | **The current code breaks its own anti-collapse law at one point.** A deterministic byte-pattern match is published as `confidence: 1.0` (`crates/imperium-net-sensors/src/signature_engine.rs:153`), a structural fact in the statistical field — and that value is load-bearing for the burn gate (`crates/imperium-net-transport/src/orchestrator.rs:453`). | §2. Not this document's job to fix, but a ClamAV finding must not inherit the pattern. |
| 8 | **The toolkit's process lifecycle landed mid-document, but its output does not reach the bus.** A tool's stdout goes to the tracing log (`crates/imperium-managed-process/src/lib.rs:148-172`), and `ToolProcessReport` carries state only (`crates/imperium-net-toolkit/src/proc.rs:145-156`). Separately, the declarative triggers have no production caller (`crates/imperium-net-toolkit/src/lib.rs:727`), and no default tool declares a program (`crates/imperium-cli/src/main.rs:352-377`). | §5; the lifecycle prerequisite is met, the finding producer is not — which is exactly the step §1 orders first. |
| 9 | **The manifest says `MIT`; the shipped `LICENSE` is PolyForm** (`Cargo.toml:34` vs `LICENSE:1`). | §4's GPL reasoning is only as meaningful as this answer. |

---

## 9. Decisions that are the operator's

1. **Does the sensor's subject set include user payloads?** If no, this is a
   host-substrate sensor and the "monitoring network and system" framing should be
   narrowed in the same breath (§6).
2. **Is `freshclam` operator-cadenced rotation or a live feed?** A live feed is a
   thesis amendment (§1d).
3. **What does a content finding name, if anything, when it needs to be acted
   on?** The spider can quarantine strands; the orchestrator can rotate
   protocols. A file is neither (§3).
4. **Is the alert surface an event, a state record, or both** — and is it the GUI
   extended, the memory log plus a query, or a fourth thing (§7)?

Until 3 and 4 are answered, the right first move remains the one in §1: make the
finding and the verdict path real with a stand-in, and let ClamAV plug into a
socket that has already been proved to carry something.
