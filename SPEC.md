# The OpenAgentOntology Standard — v0.1.1

A small, deterministic standard for describing what an AI agent can DO and which
governance controls each action answers to. One ontology, every framework.

This document is the contract. The reference implementation is the
`openagentontology` Python package in this repository. Where the prose and the
code disagree, the code in `openagentontology/schema.py`, `crosswalk.py`,
`validate.py`, and `receipt.py` wins.

---

## 0. Design rules

1. **Static-observable only.** The schema covers what a TEXT or AST parse can
   see in a repo, MCP manifest, agent spec, OpenAPI document, Rego policy, or
   workflow YAML. Runtime-only facts (what an agent actually did) are out of
   scope — that is the job of a receipt, not an ontology.
2. **Never fabricate a control id.** Auto-detected mappings are `INFERRED` or
   `AMBIGUOUS`. `asserted` confidence is reserved for exact, well-established
   matches drawn from the fixed asserted table. No code path constructs a
   framework id string.
3. **Provenance on everything.** Every node, edge, and mapping carries how it
   was derived.
4. **ASCII inside signed evidence.** Anything that flows into the receipt hash
   is ASCII so a JavaScript verifier reproduces the Python `sha256`.
5. **Fail closed.** A structurally broken or fabrication-tainted ontology fails
   validation and does not earn a badge.

---

## 1. The public schema

Derived from the Universal Agentic Ontology (UAO). The standard exposes the
static-observable subset of the UAO `types` / `links` / `actions` vocabulary.

### 1.1 Node types (`NODE_TYPES`)

```
Actor  Agent  Capability  Tool  Task  Workflow
Decision  Policy  Gate  Evidence  Outcome  Resource  Domain
```

A **Node** is `{ id, type, name, props, provenance }`. `type` MUST be one of the
above. `props` is a free-form object (e.g. `{"action": "wire_transfer"}`).

### 1.2 Link types (`LINK_TYPES`)

```
OWNS  DELEGATES_TO  HAS_CAPABILITY  USES  EXECUTES  PART_OF
PRODUCES  MAKES  GOVERNED_BY  SUPPORTED_BY  ENFORCES  GATED_BY  OPERATES_ON
```

An **Edge** is `{ src, rel, dst, provenance }`. `rel` MUST be one of the above.
Both endpoints MUST resolve to a node id — an edge to a missing node is
**dangling** and is dropped at generation time; if one survives into validation
it fails closed (`E_DANGLING`).

### 1.3 Action types (`ACTION_TYPES`)

The UAO actions an agent or forward-deployed engineer can exercise:

```
provision_agent  assign_capability  execute_task  make_decision
enforce_gate  deploy_workflow  derive_ontology
```

### 1.4 Provenance (`PROVENANCE`)

| value       | meaning                                                          |
|-------------|------------------------------------------------------------------|
| `EXTRACTED` | explicit in the source (a Rego deny key, a tool name, a guardrail)|
| `INFERRED`  | a strong, single-domain verb in an action label matched a heuristic |
| `AMBIGUOUS` | only a weak / overloaded / side-effecting verb matched           |

### 1.5 The OntologyDoc

```
OntologyDoc {
  source        string   # the path or identifier ingested
  source_kind   string   # repo | mcp | langchain | crewai | openapi | rego | workflow
  nodes         Node[]
  edges         Edge[]
  action_maps   ActionMap[]
  frameworks    string[]  # distinct frameworks with at least one asserted mapping
  note          string    # the verbatim confirmation note (section 4)
}
```

`OntologyDoc.to_dict()` is **deterministic**: nodes sorted by id, edges by
`(src, rel, dst)`, action_maps by `subject_id`, frameworks sorted. This is what
makes the receipt `evidence_hash` reproducible across runs and across languages.

---

## 2. The cross-walk format

The cross-walk turns one Capability / Decision / Gate into a set of framework
controls. It is **two-layer** and fabrication-safe.

### 2.1 A Mapping

```
Mapping {
  fw          string   # MUST be in ALLOWED_FRAMEWORKS
  id          string   # the control id, drawn from the asserted table only
  name        string   # the human control name
  basis       string   # the sourced rationale (ASCII, inside signed evidence)
  confidence  string   # asserted | advisory | inferred | ambiguous
  provenance  string   # EXTRACTED | INFERRED | AMBIGUOUS
}
```

`ALLOWED_FRAMEWORKS`:

```
NIST SP 800-53r5   EU AI Act   OWASP LLM Top 10 (2025)
NIST AI RMF   MITRE ATT&CK   OCSF   NICE
```

### 2.2 An ActionMap

```
ActionMap {
  subject_id   string         # the node id this resolves
  label        string         # the action label that was matched
  mappings     Mapping[]
  matched_via  string         # asserted_table | heuristic | none
}
```

### 2.3 Resolution order

1. **Layer 1 — asserted table.** If the source named a reason (a Rego deny key,
   a guardrail name, an eval expected reason) and that reason is in the asserted
   table, return its mappings verbatim with provenance `EXTRACTED` and the
   table's `asserted` / `advisory` confidence untouched. `matched_via =
   asserted_table`.
2. **Layer 2 — heuristic.** Otherwise run the action label against an ordered
   list of verb regexes.
   - A **strong** single-domain verb (`pay`, `export`, `deploy`, `delete`,
     `approve`, ...) downgrades the matching reason's asserted controls to
     `confidence = inferred`, `provenance = INFERRED`, with the basis rewritten
     to name the inferring verb.
   - A **weak / overloaded** verb (`process`, `update`, `run`, ...) yields at
     most a single OWASP `LLM06` "Excessive Agency" stub at `confidence =
     ambiguous`, `provenance = AMBIGUOUS`. Never a specific 800-53 id.
3. **No match.** Empty mappings, `matched_via = none`. The validator emits a
   `W_UNGOVERNED` warning (does not block).

### 2.4 The asserted table

The asserted table is the canonical reason-to-control map, transcribed 1:1 from
CWN's `CWN's canonical control map`. Ten canonical reasons. Examples:

| reason                          | asserted controls                                    |
|---------------------------------|------------------------------------------------------|
| `dual_control_required`         | NIST 800-53 AC-5; EU AI Act Art 14; OWASP LLM06      |
| `over_threshold`                | NIST 800-53 AC-3, AC-6; EU AI Act Art 14             |
| `beneficiary_unverified`        | NIST 800-53 AC-3; EU AI Act Art 10; OWASP LLM06      |
| `human_review_required`         | EU AI Act Art 14; OWASP LLM06                        |
| `classification_above_ceiling`  | NIST 800-53 RA-2, AC-4; EU AI Act Art 10; OWASP LLM02|
| `out_of_scope_domain`           | NIST 800-53 AC-6, AC-3; OWASP LLM06                  |
| `regulated_egress_blocked`      | NIST 800-53 AC-4, SC-7; EU AI Act Art 10; OWASP LLM02|
| `change_freeze_active`          | NIST 800-53 CM-3, CM-5; OWASP LLM06                  |
| `approval_required`             | NIST 800-53 CM-3; EU AI Act Art 14; OWASP LLM06      |
| `high_blast_needs_named_approver`| NIST 800-53 CM-4, AC-5; EU AI Act Art 14            |

These are **proposed** mappings (section 4). The id strings live only in this
table; the heuristic layer can re-emit them but never invent new ones.

---

## 3. Validation (fail-closed)

`validate(doc) -> (ok, findings)`. `ok` is false if any error-level finding
exists.

**ERROR codes (void the artifact):**

| code          | trigger                                                       |
|---------------|---------------------------------------------------------------|
| `E_EMPTY`     | the ontology has zero nodes                                    |
| `E_NODE_TYPE` | a node type is not in `NODE_TYPES`                             |
| `E_EDGE_REL`  | an edge rel is not in `LINK_TYPES`                            |
| `E_DANGLING`  | an edge endpoint id is not a node                             |
| `E_FRAMEWORK` | a mapping `fw` is outside `ALLOWED_FRAMEWORKS`                |
| `E_ASSERTED`  | an `asserted` mapping is missing `fw` / `id` / `name` / `basis`|
| `E_FAKE_ID`   | an `asserted` `(fw, id)` pair is not in the asserted table     |
| `E_NONASCII`  | non-ASCII in any mapping field, basis, node text, or the note |

**WARN codes (do not block; the Trust Profile reads them):**

| code           | trigger                                              |
|----------------|------------------------------------------------------|
| `W_UNGOVERNED` | a Decision/Gate/Capability with `matched_via = none` |
| `W_AMBIGUOUS`  | at least one ambiguous mapping is present             |

`E_FAKE_ID` is the backstop: even if a typo smuggled an unknown id past Layer 1,
it fails here. A clean ontology is one where every asserted id is one the
standard already vouches for.

---

## 4. The confidence and provenance discipline

Every output ships with this confirmation note, verbatim:

> Proposed CWN mappings, confidence-tagged. Confirm against the current
> published control text before relying on them for audit. Enterprise control
> ids are mapped at onboarding by your GRC team, never auto-asserted.

- `asserted` — well-established, exact-fit control. Survives validation.
- `advisory` — plausible but the GRC team must confirm (e.g. a MITRE tactic, an
  AI RMF function). Carried from Layer 1 only.
- `inferred` — produced by a strong heuristic verb hit; an honest downgrade.
- `ambiguous` — produced by a weak heuristic hit; an OWASP LLM06 stub at most.

The badge shows asserted controls by default so it stays honest. Inferred and
ambiguous mappings are visible in the full ontology, never on the headline chip.

---

## 5. The receipt format

The receipt is an Ed25519 cert-only proof that THIS ontology was produced. It is
self-signed by the local tool. Cross-organization verification against CWN's
hosted notary/registry is a separate hosted service, not part of this standard.

### 5.1 Canonical JSON

```
canon(obj) = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True)
```

Identical to CWN's `escape_plan_service._canon`. A browser verifier MUST use the
same canonicalization (sorted keys, no whitespace, ASCII) to reproduce the hash.

### 5.2 Body

```
body {
  atom_id        string   # oao-<sha256(source)[:12]>
  type           "OpenAgentOntologyReceipt"
  version        "0.1.1"
  tier           string   # the Trust Profile tier
  score          int      # the Trust Profile score, 0..100
  evidence_hash  string   # sha256( canon(evidence) ), hex
  signed_at      string   # ISO 8601 UTC
}
```

- `evidence_hash = sha256(canon(evidence)).hexdigest()`
- `signature_b64 = base64( Ed25519.sign( canon(body) ) )`

The signature is over `canon(body)`; `body` commits to the evidence by hash.
This is the exact pattern from `escape_plan_service.mint_specimen_receipt`.

### 5.3 Evidence

The evidence object is the deterministic `OntologyDoc.to_dict()` plus the Trust
Profile dict and a compact citable-refs list. Because `to_dict()` is sorted, the
same ontology always hashes to the same value.

### 5.4 The full receipt

```
receipt = body + {
  evidence            object   # the deterministic evidence
  alg                 "Ed25519"
  signature_b64       string   # "" if cryptography is unavailable (unsigned, flagged)
  verify_pubkey_b64   string   # raw Ed25519 public key, base64
  note_pq             string   # production receipts add ML-DSA-65 over the same hash
}
```

If `cryptography` is unavailable the receipt is emitted **unsigned** with an
explicit flag — the tool never silently fakes a signature.

### 5.5 Verifying

Anyone can verify from the cert alone, with no network and no database:

1. Recompute `sha256(canon(receipt.evidence))` and compare to
   `receipt.evidence_hash`.
2. Rebuild `body` (drop `evidence`, `alg`, `signature_b64`, `verify_pubkey_b64`,
   `note_pq`), recompute `canon(body)`, and verify `signature_b64` against
   `verify_pubkey_b64` with Ed25519.

---

## 6. The Trust Profile

A 0–100 score and a tier, computed from the validated ontology. Tiers:

```
SOVEREIGN   HARDENED   DEVELOPING   UNGOVERNED
```

The profile rewards breadth of asserted framework coverage and governed
decision points, and penalizes ungoverned and ambiguous actions. The score and
tier are inside the signed evidence, so the badge cannot be inflated after the
fact without breaking the signature.

---

## 7. The badge

A shareable SVG. It shows the tier, the score, the count of distinct asserted
frameworks, and a short list of citable control refs (e.g. `NIST 800-53 AC-5`).
It is honest by construction: it reads from the signed evidence and shows
asserted controls only.

---

## 8. Open-core boundary

This standard and its reference implementation produce the **local** ontology,
Trust Profile, badge, and self-signed receipt — entirely offline. CWN's hosted
notary and registry, which perform cross-organization verification and maintain
a public trust ledger, are a separate hosted service and are **not** covered by
this standard or this repository.

---

## 9. Sovereignty Extensions (v0.1.1)

Five crosswalk rationale entries document how Trust Gate's sovereignty
capabilities map to OAO constructs. These are **not** new deny-key reasons in
the asserted table; they are structural patterns that compositions of existing
reasons can enforce. All control mappings in these entries are `advisory` --
asserted confidence remains reserved for the ten canonical deny-key reasons.

Full rationale for each entry is in `docs/crosswalk-rationale/`.

| Entry | Service | OAO Pattern | Wave |
|---|---|---|---|
| `two_phase_decision_gate` | DecisionGateService | Gate GATED_BY Policy; Decision GOVERNED_BY Gate | W0 |
| `egress_receipt_required` | EgressGateService | Gate ENFORCES Policy; Evidence PRODUCES receipt | W1 |
| `vendor_exit_drill` | ExitDrillService | Evidence (drill receipt); Outcome (PASS/FAIL) | W2 |
| `loreatom_adjudication` | LoreAtom pipeline | Decision GOVERNED_BY Policy (promotion gate) | W3 |
| `reference_node_federation` | Reference node pattern | Resource GOVERNED_BY Policy (data sovereignty) | W4 |

### 9.1 Design notes

- **Advisory only.** These entries map to NIST 800-53, EU AI Act, and OWASP
  controls at advisory confidence. Promoting any to asserted would require
  adding a new canonical deny-key reason to the asserted table, which is a
  breaking change.
- **Structural, not behavioral.** Each entry documents an implementation
  architecture (two-phase commit, per-call receipt, drill-based verification,
  human-in-loop adjudication, pointer-only federation) rather than a runtime
  deny decision. The deny decisions use the existing ten reasons; these
  entries describe the mechanisms that enforce them.
- **Provenance trail.** Each sovereignty service produces signed receipts. The
  receipt format is identical to section 5 (Ed25519, canonical JSON, same
  `evidence_hash` construction). Sovereignty receipts are distinguishable by
  their `type` field (e.g. `ExitDrillReceipt`, `EgressReceipt`).
