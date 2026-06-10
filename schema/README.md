# The Agent Ontology Standard

> *An Agent Ontology is a typed, signed map of every action an AI agent can take — and the
> governance control that answers for each one.*

This directory is the **open standard** behind OpenAgentOntology. The three JSON files are
generated directly from the reference implementation (`python schema/_gen_schema.py`), so the
published vocabulary can never drift from the code that produces it.

If you are building an agent framework, a policy engine, an observability tool, or a registry,
you can emit or consume this format. The standard is the layer every one of those can map *to* —
the way traces map to OpenTelemetry.

## What's here

| File | What it defines |
|---|---|
| [`agent-ontology-v0.1.0.schema.json`](./agent-ontology-v0.1.0.schema.json) | JSON Schema for an ontology document — nodes, edges, action-maps, the trust profile, and the receipt |
| [`crosswalk-v0.1.0.json`](./crosswalk-v0.1.0.json) | The core: **10 canonical deny-reasons** mapped 1:1 to well-established framework controls, plus the verb heuristics |
| [`frameworks-v0.1.0.json`](./frameworks-v0.1.0.json) | The 7 allowed frameworks, the 4 trust tiers + their floors, the scoring weights, and the type vocabulary |

## The vocabulary (v0.1.0)

- **13 node types** — `Actor`, `Agent`, `Capability`, `Tool`, `Task`, `Workflow`, `Decision`,
  `Policy`, `Gate`, `Evidence`, `Outcome`, `Resource`, `Domain`.
- **13 edge types** — `OWNS`, `DELEGATES_TO`, `HAS_CAPABILITY`, `USES`, `EXECUTES`, `PART_OF`,
  `PRODUCES`, `MAKES`, `GOVERNED_BY`, `SUPPORTED_BY`, `ENFORCES`, `GATED_BY`, `OPERATES_ON`.
- **10 canonical deny-reasons** — each mapped to real controls across **7 frameworks**
  (NIST SP 800-53r5 · EU AI Act · OWASP LLM Top 10 (2025) · NIST AI RMF · MITRE ATT&CK · OCSF · NICE).
- **4 trust tiers** — `SOVEREIGN` (≥90) · `HARDENED` (≥75) · `DEVELOPING` (≥50) · `UNGOVERNED` (<50).

## The three confidence levels (honest by construction)

A control is only ever **asserted** when an action declares a canonical reason that exists in
the crosswalk — an exact, auditable match. A verb heuristic that *guesses* a reason produces an
**inferred** mapping (confirm it). A weak/overloaded verb produces an **ambiguous** stub. The
standard never permits a fabricated control id, and the badge counts asserted controls only.

## Citing the standard

```
OpenAgentOntology Agent Ontology Standard v0.1.0.
Cyber Warrior Network. https://agent-ontology.cyberwarriornetwork.com/schema/v0.1
```

Receipts reference this standard so each one self-describes against the published vocabulary.

## Versioning & governance

The standard is **semver**ed; this is `v0.1.0`. Breaking changes to node/edge types, the
canonical-reason set, or the crosswalk bump the minor (pre-1.0) or major (post-1.0) version, and
ship a new dated file alongside the old one — published ontologies and receipts stay valid
against the version they were minted under. The reference implementation, the conformance tests
(`tests/`), and this schema are versioned together.

Proposals to add a canonical reason or a framework open as a PR that (1) adds the mapping to the
reference `ASSERTED_TABLE` with a sourced `basis` for every control, and (2) regenerates this
directory. No mapping is accepted without a citation to the published control text.

---

*The org chart for your non-human workforce. No Receipt. No Trust.*
