# The Agent Ontology: A Static, Signed Crosswalk From Agent Actions to Governance Controls

*Cyber Warrior Network*

*Draft v1 - prepared for the agents4science 2026 / arXiv cs.CR track. Not peer reviewed.*

---

## Abstract

Autonomous agents now execute side-effecting actions - running arbitrary code,
exporting records, deploying changes - faster than any human review loop, yet for
most deployed agents there is no machine-readable record of which governance
control answers for each action. We present OpenAgentOntology (OAO), an
open-source tool and small standard that reads an agent's own source (text and
AST, never executing it) and emits a typed graph of what the agent can do, a
confidence-tagged crosswalk from each side-effecting action to controls in NIST
SP 800-53r5, the EU AI Act, the OWASP LLM Top 10 (2025), the NIST AI RMF, and
MITRE ATT&CK, a 0-100 Trust Profile with a four-tier band, and an Ed25519
cert-only receipt that any party can verify offline and that fails the instant
one byte of evidence is altered. The crosswalk is deliberately three-layered: an
ASSERTED control is emitted only on an exact match against a fixed ten-reason
table; otherwise a verb heuristic yields an INFERRED or AMBIGUOUS mapping; an
action that matches nothing is reported UNGOVERNED. No code path constructs a
framework id. We scanned five agents. On the two most-starred autonomous coding
agents on GitHub - open-interpreter (~58k stars) and gpt-engineer (~54k stars) -
zero of their 21 and 6 side-effecting actions respectively resolved to any
asserted control; both scored UNGOVERNED 15/100, and `exec` (arbitrary code
execution, mapping to MITRE ATT&CK T1059) was governed by nothing. We verified
both committed receipts and confirmed each fails verification under a one-field
tamper. As a measured before/after, the autonomous remediation agent (AgentFDE)
moved a reference agent from UNGOVERNED 41 to HARDENED 88. OAO frames the
ungoverned autonomous agent as an insider threat onboarded on purpose, and offers
the first instrument that turns that gap into a number and a signed artifact.

---

## 1. Introduction

An autonomous agent is, operationally, a new employee you did not interview, that
works at machine speed, and that you cannot fire. It can move money, export
regulated records, ship code to production, and shut systems down. For a human
with that authority, an organization maintains an explicit record of which
control answers for each sensitive action: separation of duties on the wire
transfer, an approval gate on the production change, a named owner on the
high-blast-radius operation. For the agent doing the same work, that record
usually does not exist in any form a machine can read - it lives, if anywhere, in
a slide, a spreadsheet that is already stale, or someone's memory.

This is the governance gap. The agent stack was built in three conceptual layers,
and the industry shipped two of them. The first layer is the agent frameworks
(LangChain, CrewAI, AutoGen, MCP) that optimize capability - how to build agents
that can do more. The second is observability (tracing, evals, OpenTelemetry-style
instrumentation) that optimizes hindsight - what the agent did on a given run.
The missing third layer is accountability: for each thing the agent can do,
*which control answers for it, before it runs.* Capability does not measure that.
Observability measures it only after the fact, one execution at a time, and only
for the path that happened to execute. Neither layer can tell you, statically,
that an agent which can `exec` arbitrary code has no gate on that capability at
all.

We call the missing layer the Agent Ontology: a typed, signed map of every action
an agent can take and the governance control that answers for each one. The
reframe that makes it tractable is that a single guardrail is not "a Rego rule" -
a wire-transfer dual-control check is, simultaneously, NIST 800-53 AC-5
(Separation of Duties), EU AI Act Article 14 (Human oversight), and OWASP LLM06
(Excessive Agency). Auditors, regulators, and boards each speak a different one of
those vocabularies. The Agent Ontology maps an action once, to a shared internal
vocabulary, and emits the right control identifier for whichever framework the
reader cares about - so the same control is not re-translated five ways by hand.

The framing we adopt throughout is the insider threat onboarded on purpose. An
agent with `exec` and no gate is not a malicious insider, but it has an insider's
access and an insider's blast radius, and it was granted that access deliberately,
with no compensating control recorded. The point of OAO is not to assert that any
scanned agent is malicious or even badly built - the agents we scan are excellent
engineering. The point is that the mapping from their actions to the controls that
should answer for them is absent from their own source, which makes the gap
invisible until something measures it.

### Contributions

1. **A small standard for the Agent Ontology** (Section 3): 13 node types and 13
   edge types drawn as the static-observable subset of a Universal Agentic
   Ontology, with provenance on every node, edge, and mapping.
2. **A three-layer, fabrication-safe crosswalk** from agent actions to five real
   governance frameworks: an ASSERTED table of ten canonical deny reasons, an
   INFERRED verb-heuristic downgrade layer, and an explicit UNGOVERNED outcome -
   structured so no code path can construct a control id (Section 3).
3. **A MITRE ATT&CK advisory-enrichment layer** that attaches the adversary
   technique a SOC already hunts to each canonical reason, by construction never
   counted toward the score (Section 3).
4. **An Ed25519 cert-only receipt** with byte-for-byte offline verification and a
   demonstrated tamper test, so a passing grade cannot be forged (Section 3, 5).
5. **A real-world measurement** of five agents, including the two most-starred
   autonomous coding agents on GitHub, with a measured remediation before/after
   (Sections 4-5).

Everything in this paper is reproducible from the committed artifacts and the
pinned upstream commits; every number is either directly measured by running the
tool or transcribed from a committed signed scan, and projected quantities are
labeled.

---

## 2. Background and related work

OAO sits beside several established bodies of work; it does not replace any of
them. We cite standards and frameworks by their own published identifiers and do
not attribute claims to invented secondary literature.

**AI TRiSM (Trust, Risk and Security Management).** The industry framing of AI
trust as a lifecycle concern - governance, observability, security, and model
operations - motivates a static accountability layer that complements runtime
controls. OAO occupies the governance-mapping slice: it does not enforce, observe
at runtime, or operate models; it maps actions to controls before runtime.

**NIST SP 800-53r5 and the NIST AI RMF.** OAO's asserted control identifiers are
drawn from NIST SP 800-53 Revision 5 - among them AC-3 (Access Enforcement), AC-4
(Information Flow Enforcement), AC-5 (Separation of Duties), AC-6 (Least
Privilege), CM-3 (Configuration Change Control), CM-4 (Impact Analyses), CM-5
(Access Restrictions for Change), RA-2 (Security Categorization), and SC-7
(Boundary Protection). The NIST AI RMF functions (GOVERN, MAP, MEASURE, MANAGE)
appear as advisory mappings only, because a risk-management function is a posture,
not an exact technical control.

**EU AI Act (Regulation (EU) 2024/1689).** OAO maps human-oversight obligations to
Article 14 and data-governance obligations to Article 10. The README and demo also
reference Article 50 (transparency) at the product layer; the crosswalk's asserted
mappings in this version use Articles 10 and 14.

**OWASP LLM Top 10 (2025).** OAO uses LLM02 (Sensitive Information Disclosure) for
regulated-egress actions and LLM06 (Excessive Agency) for unbounded-authority and
weak-heuristic actions. LLM06 is the single stub a weak/overloaded verb can
resolve to, and never a specific 800-53 identifier.

**MITRE ATT&CK.** Each canonical reason carries the adversary technique it
mitigates - e.g. T1059 (Command and Scripting Interpreter), T1048 (Exfiltration
Over Alternative Protocol), T1485 (Data Destruction), T1543 (Create or Modify
System Process), T1078 (Valid Accounts) - so a SOC analyst reads the finding in
the language they already hunt in. These are advisory and never inflate the score.

**Agent tracing and evaluation.** Tracing and eval tooling answer "what did this
agent do, and how well, on these runs?" OAO answers a different, static question:
"what can this agent do, and which control answers for each capability, before it
runs?" The two compose - a trace tells you a path executed; an ontology tells you
that path had no gate. OAO is the pre-flight inspection; tracing is the flight
recorder.

The novel position OAO occupies is the static, fabrication-safe, signed crosswalk
itself: a single artifact that is typed (so it is a graph, not a list),
multi-framework (so each reader gets their language), honesty-tiered (so a guess
is never dressed as an assertion), and tamper-evident (so a grade cannot be
forged). We are not aware of an existing open tool that produces exactly this
artifact for arbitrary agent source.

---

## 3. Method

OAO is a deterministic pipeline: a path goes in, a governed result comes out. The
stages are ingest -> generate -> validate -> score -> receipt -> badge. No stage
executes the ingested code, and the core pipeline makes no network call.

### 3.1 The ontology vocabulary

The schema is the static-observable subset of a Universal Agentic Ontology. It
defines **13 node types** - Actor, Agent, Capability, Tool, Task, Workflow,
Decision, Policy, Gate, Evidence, Outcome, Resource, Domain - and **13 edge
types** - OWNS, DELEGATES_TO, HAS_CAPABILITY, USES, EXECUTES, PART_OF, PRODUCES,
MAKES, GOVERNED_BY, SUPPORTED_BY, ENFORCES, GATED_BY, OPERATES_ON. A node is
`{id, type, name, props, provenance}`; an edge is `{src, rel, dst, provenance}`.
Every node, edge, and mapping carries a provenance value - EXTRACTED (explicit in
the source), INFERRED (a strong single-domain verb matched a heuristic), or
AMBIGUOUS (only a weak/overloaded verb matched). The assembled OntologyDoc
serializes deterministically (nodes sorted by id, edges by `(src, rel, dst)`,
action maps by subject id, frameworks sorted), which is what makes the receipt
hash reproducible across runs and across languages.

Ingest reads repos (extracting tool decorators such as `@tool`, `@function_tool`,
`@mcp.tool`, and verb-named functions such as `exec`, `run_*`, `delete_*`,
`send_*`, `deploy_*`), MCP manifests, LangChain/CrewAI specs, OpenAPI documents,
Rego policy, and workflow YAML. Generate assembles the typed graph and drops any
dangling edge (an edge whose endpoint is not a node); if one survived into
validation it would fail closed.

### 3.2 The three-layer crosswalk

Each Capability/Decision/Gate or side-effecting action is resolved by
`map_action(label, source_reason)` in a fixed order.

**Layer 1 - ASSERTED table (exact).** If the source named a reason (a Rego deny
key, a guardrail name, an eval expected reason) and that reason is one of the ten
canonical reasons, OAO returns that reason's control mappings verbatim, at
provenance EXTRACTED, with the table's `asserted`/`advisory` confidence untouched,
and `matched_via = asserted_table`. The ten canonical reasons and a representative
asserted control each:

| canonical reason | representative asserted controls |
|---|---|
| `dual_control_required` | NIST 800-53 AC-5; EU AI Act Art 14; OWASP LLM06 |
| `over_threshold` | NIST 800-53 AC-3, AC-6; EU AI Act Art 14; OWASP LLM06 |
| `beneficiary_unverified` | NIST 800-53 AC-3; EU AI Act Art 10; OWASP LLM06 |
| `human_review_required` | EU AI Act Art 14; OWASP LLM06 |
| `classification_above_ceiling` | NIST 800-53 RA-2, AC-4; EU AI Act Art 10; OWASP LLM02 |
| `out_of_scope_domain` | NIST 800-53 AC-6, AC-3; OWASP LLM06 |
| `regulated_egress_blocked` | NIST 800-53 AC-4, SC-7; EU AI Act Art 10; OWASP LLM02 |
| `change_freeze_active` | NIST 800-53 CM-3, CM-5; OWASP LLM06 |
| `approval_required` | NIST 800-53 CM-3; EU AI Act Art 14; OWASP LLM06 |
| `high_blast_needs_named_approver` | NIST 800-53 CM-4, AC-5; EU AI Act Art 14 |

**Layer 2 - heuristic (inferred or ambiguous).** With no source-named reason, the
action label is run against an ordered list of verb regexes. A strong,
single-domain verb (`pay`, `export`, `delete`, `deploy`, `migrate`, `approve`,
`terminate`, `escalate`, ...) selects the matching canonical reason but
**downgrades** its asserted controls to `confidence = inferred`, `provenance =
INFERRED`, with the basis rewritten to name the inferring verb. A weak or
overloaded verb (`process`, `update`, `run`, `execute`, `modify`, `write`,
`store`, `submit`, `commit`, ...) yields at most a single OWASP LLM06 stub at
`confidence = ambiguous`, `provenance = AMBIGUOUS` - never a specific 800-53 id.
The regex boundary is deliberately non-`\b` so a verb matches at the head of a
snake_case label (`export_records`, `wire_transfer`).

**Layer 3 - UNGOVERNED.** A label that matches neither layer returns empty
mappings, `matched_via = none`, and the validator emits a non-blocking
`W_UNGOVERNED` warning. This is the honest outcome for `exec`-like raw verbs that
the strong heuristic deliberately refuses to claim a clean 1:1 control for.

**The fabrication invariants.** Two properties hold by construction: (1)
`map_action` never constructs a framework-id string - it only re-emits identifiers
that already live in the asserted table, so there is no path to invent `AC-99`; and
(2) `asserted`/`advisory` confidence is reserved for Layer-1 source-named matches,
so anything auto-detected is `inferred` or `ambiguous`. The badge shows asserted
controls only.

### 3.3 MITRE ATT&CK advisory enrichment

Each canonical reason additionally carries one MITRE ATT&CK technique at
`advisory` confidence (e.g. `regulated_egress_blocked` -> T1048;
`change_freeze_active` -> T1485; `approval_required` -> T1543;
`dual_control_required` -> T1078; `human_review_required` -> T1059). Advisory
mappings are informative for a SOC reader but are never counted toward coverage,
rigor, or breadth, so attaching the adversary technique cannot inflate the trust
score. This is the mechanism that lets every action carry the technique a SOC
already hunts while keeping the headline grade honest.

### 3.4 Validation (fail-closed)

`validate(doc)` returns `(ok, findings)`; `ok` is false if any error-level finding
exists. Error codes void the artifact: `E_EMPTY` (zero nodes), `E_NODE_TYPE`
(unknown node type), `E_EDGE_REL` (unknown edge rel), `E_DANGLING` (edge endpoint
not a node), `E_FRAMEWORK` (a mapping framework outside the allowed set),
`E_ASSERTED` (an asserted mapping missing `fw`/`id`/`name`/`basis`), `E_FAKE_ID`
(an asserted `(fw, id)` pair not in the asserted table), and `E_NONASCII`
(non-ASCII anywhere that flows into signed evidence). `E_FAKE_ID` is the backstop:
even if a typo smuggled an unknown id past Layer 1, it fails here. Warn codes
(`W_UNGOVERNED`, `W_AMBIGUOUS`) do not block but feed the Trust Profile.

### 3.5 The receipt: Ed25519, cert-only, offline-verifiable

The receipt is a tamper-evident record of one scan. The evidence object is the
deterministic `OntologyDoc.to_dict()` plus a compact summary header. Canonical
JSON is `json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)`.
The receipt computes `evidence_hash = sha256(canon(evidence))`, builds a small
body that commits to that hash (atom_id, type, decision, evidence_hash,
signed_at), and signs `canon(body)` with an Ed25519 key. Verification needs no
network and no database: recompute the evidence hash and compare, then verify the
signature over the rebuilt body with the embedded public key. Because everything
in evidence is ASCII and the serialization is sorted, a browser or any Ed25519
tool reproduces the Python hash byte-for-byte. If the `cryptography` library is
absent, the receipt is emitted unsigned and explicitly flagged - the tool never
fakes a signature.

The tamper property is the point. Edit any field of the evidence - for instance,
flip a `matched_via` from `none` to `asserted_table` to fake a better grade for
`exec` - and the recomputed `evidence_hash` no longer matches the committed one,
so verification returns `ok: False` with reason "evidence_hash mismatch -- evidence
was altered." A passing grade therefore cannot be forged without breaking the
receipt. We demonstrate this on real committed receipts in Section 5.

### 3.6 The Trust Profile: four tiers, four weighted subscores

The score is a weighted sum of four subscores, each in 0-100:

- **coverage (weight 0.45)** - of the governed actions, the fraction with at least
  one ASSERTED control. This dominates because an ungoverned high-risk action is
  the entire failure mode.
- **rigor (weight 0.25)** - of the actions that mapped to anything, the fraction
  that are asserted rather than heuristic-only. This penalizes guesswork so weak
  verb matches cannot inflate a grade.
- **breadth (weight 0.15)** - distinct asserted frameworks present, capped at a
  ceiling of 4 so breadth cannot paper over thin coverage.
- **structure (weight 0.15)** - is the graph typed and connected (edges present,
  every endpoint resolves, more than one node)?

The four tier bands are **SOVEREIGN >= 90, HARDENED >= 75, DEVELOPING >= 50,
UNGOVERNED < 50**. An ontology with zero governed actions cannot earn a governed
tier: coverage and rigor are defined as 0, so it floors at UNGOVERNED - the honest
answer that there was nothing to govern and therefore nothing proven. The score
and tier live inside the signed evidence, so the badge cannot be inflated after
the fact without breaking the signature.

---

## 4. Data and experimental setup

We scanned five agents across two classes.

**Reference agents (in-repo).** Three example agents shipped with OAO, scanned at
the repository state used for this paper:
- `examples/sample_agent` - a small agent with capabilities and one gate but no
  declared governance reasons on most actions.
- `examples/hardened_agent` - the same archetype with a declared canonical reason
  on every action.
- `examples/agent_fde` - the autonomous remediation agent (AgentFDE) itself,
  defined to the standard so the tool that does the governing is itself governed.

**Real-world agents (committed signed scans).** The two most-starred autonomous
coding agents on GitHub, scanned at pinned upstream commits, with the full output
committed under `docs/scans/`:
- `OpenInterpreter/open-interpreter` at commit `e00f08e` (~58k stars; runs code
  and shell on the host).
- `gpt-engineer-org/gpt-engineer` at commit `a90fcd5` (~54k stars; autonomous code
  generation).

Star counts are approximate, move over time, and are not part of the signed
evidence. Per the project's discipline of not re-cloning, the real-world numbers
in this paper are transcribed directly from the committed `trust_profile.json` and
`receipt.json` artifacts; the reference-agent numbers are produced by running the
tool in-process at paper time.

**Reproducibility and honesty controls.** The pipeline is deterministic - the
same OAO version on the same input yields the same ontology and the same
`evidence_hash`. Analysis is static: AST parse plus text read, with no execution
of the target and no network call in the core pipeline. The crosswalk cannot
construct a framework id, and asserted confidence is reserved for exact table
matches. The test suite - **93 tests, all passing at paper time** (measured;
the README's "80 tests" predates suite growth) - mechanically asserts the honesty
guarantees: no framework outside the allowed set, no fabricated control id,
auto-detected mappings never `asserted`, and an independent (JS-style)
canonicalizer reproducing the receipt hash so a browser verifier agrees
byte-for-byte. Validation findings reported by the tool for `sample_agent` flag
three ungoverned actions, consistent with the score below.

---

## 5. Results

### 5.1 The headline table

All numbers below are measured. Reference-agent rows are from an in-process run at
paper time; real-world rows are transcribed verbatim from the committed signed
scans. "Stars" is the asterisked approximate column.

| Agent | Stars* | Score | Tier | Governed actions | Asserted | Heuristic-only | Ungoverned | Nodes | Edges | Asserted frameworks |
|---|---|---|---|---|---|---|---|---|---|---|
| `examples/sample_agent` | - | 41 | UNGOVERNED | 16 | 3 | 10 | 3 | 20 | 19 | 3 |
| `examples/hardened_agent` | - | 93 | SOVEREIGN | 15 | 14 | 0 | 1 | 16 | 15 | 3 |
| `examples/agent_fde` (AgentFDE) | - | 94 | SOVEREIGN | 18 | 17 | 0 | 1 | 19 | 18 | 3 |
| `open-interpreter` @e00f08e | ~58k | 15 | UNGOVERNED | 21 | **0** | 20 | 1 | 22 | 21 | 0 |
| `gpt-engineer` @a90fcd5 | ~54k | 15 | UNGOVERNED | 6 | **0** | 5 | 1 | 7 | 6 | 0 |

Subscore detail for the reference agents (coverage / rigor / breadth / structure):
sample_agent 19 / 23 / 75 / 100; hardened_agent 93 / 100 / 75 / 100; agent_fde
94 / 100 / 75 / 100. For both real-world agents the committed trust profile records
breadth 0, coverage 0, rigor 0, structure 100 - a fully-connected, fully-typed
graph (structure 100) carrying zero asserted controls (coverage and rigor 0). The
asserted-frameworks count is 0 for both real-world agents because a framework is
counted only when at least one asserted mapping touches it; all of their mappings
are heuristic.

### 5.2 The headline finding

**Zero asserted controls resolve for the two most-starred autonomous coding agents
on GitHub.** Of open-interpreter's 21 side-effecting actions, 0 are asserted, 20
are heuristic-only (INFERRED/AMBIGUOUS), and 1 is UNGOVERNED. Of gpt-engineer's 6,
0 are asserted, 5 are heuristic-only, and 1 is UNGOVERNED. Both score UNGOVERNED
15/100. This is the textbook definition of an ungoverned agent, measured from its
own source.

The specific finding that anchors the framing: in open-interpreter, the `exec`
action - arbitrary code execution on the host - is the UNGOVERNED one. It matched
no canonical reason, so its mapping set is empty and `matched_via = none`. In the
advisory layer, autonomous execution without oversight is exactly the kind of
behavior MITRE ATT&CK catalogs as T1059 (Command and Scripting Interpreter), the
technique a SOC already hunts; yet in the agent's own source there is no declared
control answering for it. In gpt-engineer, the parallel UNGOVERNED action is
`post_data`. Data-egress actions in both agents (`send_telemetry`, `export_*`,
`upload`, `send_learning`) land on the information-flow and boundary controls
(NIST 800-53 AC-4, SC-7) and the Exfiltration technique (T1048) - but only as
INFERRED guesses from the verb. Because no one *declared* those mappings, they
cannot be relied on for audit, which is why they do not move the asserted count
off zero.

### 5.3 The receipt is verifiable and tamper-evident

We verified both committed real-world receipts from the certificate alone, with no
network. Each returned `{ok: True, hash_ok: True, sig_ok: True, signed: True}` -
the evidence hash recomputed correctly and the Ed25519 signature verified against
the embedded public key. We then ran the tamper test described in Section 3.5: in
each receipt we flipped the UNGOVERNED action's `matched_via` from `none` to
`asserted_table` - a lie that would inflate the grade - and re-verified. Both
returned `{ok: False, hash_ok: False, reason: "evidence_hash mismatch -- evidence
was altered"}`. The grade cannot be forged without breaking the receipt. (We note
one cosmetic discrepancy unrelated to verification: the committed
open-interpreter receipt's `atom_id` is `oao-OPENINTERPRE-433522f130`, derived
from its `evidence_hash`, whereas the prose reproduction note in the docs cites a
different atom_id; the atom_id depends on the evidence-hash prefix and is not the
verification anchor, which is the hash and signature we confirmed.)

### 5.4 Remediation as a measured before/after

AgentFDE runs the full forward-deployed-engineer loop autonomously - scan, triage
the gaps, generate governance (an agent declaration plus a fail-closed Rego stub),
re-score to prove the tier jump, and notarize - without ever executing the target.
Run on `examples/sample_agent`, the measured result is:

| | Tier | Score |
|---|---|---|
| before | UNGOVERNED | 41 |
| after | HARDENED | 88 |

Of the agent's 16 actions, 3 were asserted before remediation; AgentFDE produced
10 auto-remediations and left 3 still open for a human (the raw-verb actions it
deliberately will not auto-assert). The remediation is real governance, not a
stub: the four artifacts it writes (a governance YAML binding each action to a
canonical reason, a fail-closed Rego policy, an onboarding report, and a signed
receipt) are themselves scannable, and AgentFDE is itself a governed agent that
scores SOVEREIGN 94. The measured jump from UNGOVERNED 41 to HARDENED 88 is the
end-to-end demonstration that the gap OAO measures is also closeable, and that the
closure is provable in the same currency - a re-scored, signed receipt.

### 5.5 Interpretation

A low score does not mean the tool failed; it means the agent's actions have no
asserted control, which is the honest finding for nearly every agent shipping
today. The contrast across the table makes the mechanism legible: the same agent
archetype scores UNGOVERNED 41 with no declared reasons (sample_agent) and
SOVEREIGN 93 once every action declares one (hardened_agent), and the real-world
agents - which declare nothing - sit below even the undeclared example at
UNGOVERNED 15, because they carry more side-effecting actions and zero asserted
coverage. The number is doing exactly what an accountability instrument should: it
moves only when declared, sourced governance is present.

---

## 6. Threats to validity

We state these plainly; an instrument that maps governance has to be honest about
its own coverage.

**Static analysis cannot see runtime behavior.** OAO reads source, not execution.
It reports what an agent *can* do as visible in code, not what it *does* on any
run. An action gated only by runtime configuration, environment, or an external
policy server that OAO does not ingest will look ungoverned even if it is
controlled in deployment. Conversely, a control present in source may be bypassed
at runtime. OAO is the pre-flight inspection, not the flight recorder, and it
should be read as such.

**Runtime tool registration under-extracts.** OAO extracts the action surface from
decorators and verb-named functions. It does not yet resolve tools registered at
runtime - e.g. servers that build their tool list inside a `list_tools()` handler
rather than declaring it statically. Scanning such a target under-extracts (it
finds the static surface only). This is a documented limitation, not a silent one,
and runtime-registry resolution is on the roadmap.

**The INFERRED heuristic is verb-regex brittle.** Layer 2 keys on verb tokens. A
genuinely dangerous action with an innocuous name (`helper`, `process_item`) may
fall through to the weak/ambiguous path or to UNGOVERNED, and a benign action with
a strong verb (`delete_temp_file`) may be downgraded onto change-control controls
that do not really apply. The design mitigates this by labeling every heuristic
result as a guess and excluding it from the asserted count - so brittleness costs
recall and precision in the INFERRED layer, but cannot fabricate an asserted
control. The honest claim is narrow: asserted coverage is trustworthy; inferred
coverage is a prompt to confirm.

**The crosswalk is single-source.** The asserted table is one fixed mapping from
ten canonical reasons to controls, transcribed from CWN's internal control map.
Two organizations' GRC teams may map the same reason to different control sets, and
the published control text for any framework can change. OAO addresses this by
construction - every output ships the verbatim note that mappings are proposed and
must be confirmed against current published control text, and enterprise control
ids are mapped at onboarding by a GRC team, never auto-asserted - but the
single-source mapping is still a modeling choice a reviewer should weigh.

**Selection of two real-world agents.** The headline real-world result rests on two
agents, chosen for being the most-starred autonomous coding agents. They are not a
random sample, and "zero asserted controls" is a finding about these two scanned at
these commits, not a measured population statistic. We label any
beyond-the-sample claim as projected; the measured claim is exactly the two rows in
the table.

**Scoring weights are a design choice.** The 0.45/0.25/0.15/0.15 weights and the
four tier floors encode a judgment that coverage dominates. They are defensible and
deterministic, but they are not derived from an external ground truth, so the
absolute score is interpretable only relative to the rubric, not as a calibrated
probability of harm.

---

## 7. Discussion and future work

The measured results suggest the governance gap is not an edge case but the modal
state of deployed autonomous agents: the most-starred examples carry zero asserted
controls in their own source. Making that gap a typed, signed number changes what a
buyer, an auditor, or a CI gate can do with it. The same machinery already runs as
a pull-request check that fails when the trust tier drops or a new EU AI Act Article
14 gap appears, which turns the static measurement into a regression test on
governance.

Several directions follow.

**Graph-grounded semantic crosswalk.** The current Layer 2 is a verb regex. A
graph-grounded crosswalk - resolving an action against a semantic map of
capabilities and controls rather than a surface token - would raise INFERRED
recall and precision without weakening the asserted invariant, since the asserted
table remains the only path to asserted confidence. This directly addresses the
brittleness threat in Section 6.

**The hosted notary and registry.** The open-source tool mints a self-signed
receipt offline. A hosted notary and registry (a separate service, not in the OSS
repo) would add cross-organization verification and a public trust ledger, so a
receipt minted by one team is checkable by another and an agent's tier can be
re-scored continuously as its source changes. The local tool stands alone; the
registry is the network effect on top, and the open-core boundary is explicit in
the standard.

**An OAO MCP server.** Exposing the scan as an MCP tool would let an agent platform
query, in-loop, whether a proposed action has an asserted control before it
executes - moving OAO from a CI-time inspection toward a runtime pre-flight gate,
while keeping enforcement in the policy engine where it belongs.

**Broader corpora and runtime-registry resolution.** Resolving runtime-registered
tools and scanning a larger, sampled corpus of agents would convert the two-agent
finding into a population estimate with a stated confidence - turning a vivid
example into a measured prevalence.

---

## 8. Conclusion

Autonomous agents act faster than review and, for most deployments, with no
machine-readable record of which control answers for each action. OpenAgentOntology
supplies that record: it reads an agent's own source without executing it, types
the result as a graph, maps each side-effecting action to NIST 800-53, the EU AI
Act, the OWASP LLM Top 10, the NIST AI RMF, and MITRE ATT&CK through a three-layer
crosswalk that can never fabricate a control id, scores a four-tier Trust Profile,
and signs the whole thing into an Ed25519 receipt that verifies offline and fails
on a single altered byte. Pointed at the two most-starred autonomous coding agents
on GitHub, it found zero asserted controls across their 21 and 6 side-effecting
actions - `exec`, arbitrary code execution, governed by nothing - and we confirmed
both signed scans verify and both fail under tamper. We also showed the gap is
closeable and the closure is provable: an autonomous remediation agent moved a
reference agent from UNGOVERNED 41 to HARDENED 88, re-scored and re-signed. The
Agent Ontology is the accountability layer the agent stack skipped; this work makes
it measurable, and makes the measurement something you cannot fake.

*Logs explain. Receipts prove.*

---

## References (standards and frameworks, by identifier)

- NIST SP 800-53, Revision 5 - Security and Privacy Controls for Information
  Systems and Organizations. Controls referenced: AC-3 (Access Enforcement), AC-4
  (Information Flow Enforcement), AC-5 (Separation of Duties), AC-6 (Least
  Privilege), CM-3 (Configuration Change Control), CM-4 (Impact Analyses), CM-5
  (Access Restrictions for Change), RA-2 (Security Categorization), SC-7 (Boundary
  Protection).
- NIST AI Risk Management Framework (AI RMF 1.0). Functions referenced: GOVERN,
  MAP, MEASURE, MANAGE.
- Regulation (EU) 2024/1689 (EU AI Act). Articles referenced: Article 10 (Data and
  data governance), Article 14 (Human oversight), Article 50 (Transparency).
- OWASP Top 10 for Large Language Model Applications (2025). Risks referenced:
  LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency).
- MITRE ATT&CK. Techniques and tactics referenced: T1048 (Exfiltration Over
  Alternative Protocol), T1059 (Command and Scripting Interpreter), T1078 (Valid
  Accounts), T1485 (Data Destruction), T1490 (Inhibit System Recovery), T1530
  (Data from Cloud Storage), T1543 (Create or Modify System Process), T1098
  (Account Manipulation), TA0010 (Exfiltration).
- NIST FIPS 204 (ML-DSA / Module-Lattice-Based Digital Signature Standard) -
  referenced as the post-quantum signature the hosted notary adds over the same
  hash; not exercised by the open-source receipt in this paper.
- Ed25519 (Edwards-curve Digital Signature Algorithm, RFC 8032) - the signature
  scheme of the cert-only receipt.

*All control identifiers above are cited by their own published names; OAO never
constructs a framework id and emits only identifiers present in its fixed asserted
table. Mappings are proposed and confidence-tagged; confirm against current
published control text before relying on them for audit.*
