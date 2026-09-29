# Transfers — rules worth adopting from Jesse's sibling projects

Reading notes, kept because these projects independently solved problems this
workspace solved by hand, or state a rule this workspace is missing. Each entry
gives the rule, its source, and where it lands here. Rules are quoted verbatim
where the wording is the point.

---

## 1. The transport-invariance law

**Source:** `atom block chain/crates/atom-video-standalone`, round 21
(`ATOM_EXPERIMENTS.md`, "transport invariance: move structure, never epistemic
status"). Verification: 18,244 LOC, 29 research rounds, 222 lib + 10 acceptance
+ 10 two-process integration tests green.

**The rule:** move structure, never epistemic status. Four parts:

1. **Duplicates are idempotent, and "same-identity-different-bytes fails closed,
   never first/last-wins."**
2. **"Transport never mentions Grounded, Contested, Agreed, or Unsupported."**
   Epistemic status is derived by the receiver, never read off the wire.
3. **"Structural completeness and epistemic grounding stay separate quantities
   — no `complete=true` shortcut feeds grounding."**
4. **Cycles and contests are never transported** — the local detector re-derives
   them ("no cycle flag transported").

Their TG6 demonstrates the consequence: identical bytes delivered to two
receivers yield *different* epistemic status (one grounded, one unsupported),
because grounding is local.

**Where it lands here.** This generalizes the per-strand `dedupe on
BusEvent.id` that was written 13 times during the strand conversion
(`crates/imperium-bus/STRAND-CONVERSION.md` §5.4) into one rule — and names a
case this workspace never considered: **same id, different bytes**. Today each
converted strand treats "seen this id" as sufficient; under rule 1 it must also
fail closed when the bytes differ for the same id.

**Open question it raises about existing work.** `LightconeReceipt` currently
carries `passive: true` and `holds_verdict: false` **on the wire** as doctrine
flags (see `crates/imperium-net-lightcone/src/lib.rs`), and the v4 pack manifest
carries `sealed` / `platform` the same way. By this law that is the forbidden
move: a transported epistemic claim. The mitigation already present is that both
are constants nothing consumes, so they carry no forgeable information. The
principled form is for the receiver to derive passivity. Needs a deliberate
decision, not a default.

---

## 2. The perception gate: a grammar must never grow a shape name

**Source:** same project, round 12 ("the Atom Normal Form: five shapes, one
grammar, no names"). Gate NF3 is the evidence: `Grouped` and `StripGrouped` —
two different discovery mechanisms — collapse to the **same** `Shared` node.

**The rule:** *"the grammar must never grow a shape name; a shape it cannot
express would demand a PRIMITIVE generalization."*

**The vocabulary is data, not opcodes:** `Scope` (Path | Extent — where),
`Anchor` (values that start chains, carried *with* the member rather than
derived per level), `Relation` (Constant = terminal fold | Chain = nested
relation-of-relations), `Membership` (Shared: one subtree, many scopes),
`Exception`, `Literal`. Encodings with no names: Rows → Constant-over-Path,
Rects → Constant-over-Extent, Recursive → Chain-over-Path, Grouped/Strips →
Shared, Mixed/Literal → per-scope Literals.

Their one-line statement of the anti-collapse law:
*"Discovery mechanisms stay separate; the knowledge they produce speaks one
language."*

They also **refused** to merge their transition-side vocabulary with their
storage-side one, because *"the two grammars describe different things — state
TRANSITIONS vs stored STATE — and premature merging was the round-4 lesson."*

**Where it lands here.** This is a **checkable gate** for the open
instructed-vs-uninstructed perception fork (`crates/imperium-net-sensors/src/probe.rs`,
the `contrast_forms_distinctions_without_instructions` experiment). If a
perception layer's vocabulary grows a shape name, it has become a classifier.
Adopt the rule regardless of what gets built next: it makes the fork decidable
instead of arguable.

It is also further along than the rank-based contrast proposed as the next step
— it *is* a nameless relational representation, already built and gated.

---

## 3. `ChaosPlan` + a pure applier, instead of N env-gated fault policies

**Source:** same project, round 23. `ChaosPlan` (drop / dup / hold / corrupt)
built by named constructors such as `ChaosPlan::round23_mix(n)`, applied by a
pure function `apply_chaos(&batch, &plan)`.

**Where it lands here.** This replaces **eight** ad-hoc env-gated fault policies
written during the strand conversions:

| Policy | Env var |
|---|---|
| lightcone `FaultPolicy` | `IMPERIUM_LIGHTCONE_CRASH_AFTER_FRAMES` / `_STALL_AFTER_FRAMES` |
| signatures | `IMPERIUM_SIGNATURES_CRASH_AFTER_REQUESTS` |
| transport | `IMPERIUM_TRANSPORT_ORCHESTRATOR_CRASH_AFTER_MESSAGES` |
| memory-log | `IMPERIUM_MEMORY_LOG_CRASH_AFTER_EVENTS` |
| deployment | `IMPERIUM_DEPLOYMENT_CRASH_AFTER_MESSAGES` |
| toolkit | `IMPERIUM_TOOLKIT_*` |
| cluster | `IMPERIUM_CLUSTER_CRASH_AFTER_MESSAGES` |
| spider | `IMPERIUM_SPIDER_COGNITION` and thresholds |

One plan type, one pure applier, named scenarios. Consolidation is mechanical.

---

## 4. An authority-separation taxonomy to audit against

**Source:** same project, rounds 16–29. Each is a claim-authority separation,
and each is made **structural** (types/IR), not merely documented — the same
discipline as this workspace's anti-collapse law, applied systematically.

| Round | Separation |
|---|---|
| 16 | observed ≠ derived (made structural) |
| 18 | grounding never on the wire (identity survives storage) |
| 21 | transported knowledge ≠ transported epistemic status |
| 24 | **who sent it ≠ what it means** (authenticity *without* epistemic authority) — plus a caught crypto error: secret-prefix MAC replaced by HMAC-SHA256 |
| 26 | physical separation is not epistemic separation |
| 27 | **peer ≠ key ≠ session ≠ knowledge** |
| 28 | location hint ≠ identity ≠ authority |
| 29 | the route/path has no identity or epistemic authority |

**Where it lands here.** Rounds 24/27/28 map onto the authenticated-handshake
work (operator-signed identities bound into the KEX) — same insight, further
systematized. The list is usable as an audit checklist for Imperium's own
authority surfaces.

---

## Shared vocabulary confirmed independently

- **"The ONLY framing the network understands (it never looks inside)"** — the
  same discipline as the guard (shape checks, never content), the probe
  observer (bounded fields only; payload text cannot select nodes), and the
  strand conversion's prefix filter.
- **Validate everything, then insert atomically, per fragment** — their
  `FragmentReceiver` decodes → validates *all* records first → inserts
  atomically; a multi-record fragment with one bad record contributes **zero**
  records. Matches the guard's all-or-nothing admission.
- **Falsification rule kept:** a shape the grammar cannot express demands a
  primitive generalization, never a new name. Same removal/demotion discipline
  as the guard's "if it generates nothing, cut it."

## Method notes

- 29 rounds, local git per-round commits, originals left untouched, the
  standalone built as a separate crate. Same demotion-not-deletion rule used
  across this workspace.
- Two round-21 catches are recorded **in test comments rather than worked
  around** — a failed first construction is preserved as the finding. Same
  standard as the guard's unminted-token bug and E27's N6 gate.
