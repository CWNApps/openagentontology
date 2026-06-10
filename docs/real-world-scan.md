# Real-world scan — what OpenAgentOntology finds on the agents people actually run

> We pointed OpenAgentOntology at the two most-starred autonomous coding agents on GitHub.
> Both came back **UNGOVERNED** — **zero** of their side-effecting actions resolve to an
> *asserted* control. Every number below is reproducible from a pinned upstream commit, and
> the result of each scan is an Ed25519 receipt you can verify offline (and that fails
> verification the instant anyone edits it).

This is not a synthetic example. These are real repositories, scanned as-is. The artifacts in
[`docs/scans/`](./scans/) are the literal output — ontology, trust profile, badge, and a
signed receipt — committed so a reviewer can verify them without trusting us or even running
the tool.

---

## Results

| Target | What it is | Stars* | Governed actions | Asserted | Inferred | Ungoverned | **Verdict** |
|---|---|---|---|---|---|---|---|
| [`OpenInterpreter/open-interpreter`](https://github.com/OpenInterpreter/open-interpreter) `@e00f08e` | runs code & shell on your machine | ~58k | 21 | **0** | 20 | 1 | **UNGOVERNED 15/100** |
| [`gpt-engineer-org/gpt-engineer`](https://github.com/gpt-engineer-org/gpt-engineer) `@a90fcd5` | autonomous code generation | ~54k | 6 | **0** | 5 | 1 | **UNGOVERNED 15/100** |

<sub>*Star counts are approximate and move over time; they are not part of the signed evidence.</sub>

The point is not that these are *bad* projects — they are excellent. The point is that an
agent which can run arbitrary code has, in its own source, **no declared mapping from its
actions to the controls that are supposed to answer for them.** That gap was invisible until
you could measure it. Now it is a number.

---

## open-interpreter — the full crosswalk

OpenAgentOntology parsed **144 Python files via AST (never executing them)** and extracted the
agent's side-effecting surface. Each row is a real function in the repo; the controls are
*proposed* mappings (confidence-tagged), not auto-asserted:

| Action (real function) | Verdict | Proposed controls |
|---|---|---|
| `exec` | **UNGOVERNED** | (none — no control matched) |
| `run` | INFERRED | OWASP LLM06 |
| `run_applescript` | INFERRED | OWASP LLM06 |
| `run_applescript_capture` | INFERRED | OWASP LLM06 |
| `run_text_llm` / `run_tool_calling_llm` / `run_function_calling_llm` | INFERRED | OWASP LLM06 |
| `run_server` / `run_auth_server` / `run_async_main` | INFERRED | OWASP LLM06 |
| `delete_event` | INFERRED | NIST 800-53 CM-3, CM-5, OWASP LLM06 |
| `migrate_app_directory` / `migrate_profile` / `migrate_user_app_directory` | INFERRED | NIST 800-53 CM-3, EU AI Act Art 14, OWASP LLM06 |
| `export_to_markdown` | INFERRED | NIST 800-53 AC-4, SC-7, EU AI Act Art 10 |
| `send` / `send_message` / `send_output` / `send_past_conversations` | INFERRED | NIST 800-53 AC-4, SC-7, EU AI Act Art 10 |
| `send_telemetry` | INFERRED | NIST 800-53 AC-4, SC-7, EU AI Act Art 10 |
| `terminate` | INFERRED | EU AI Act Art 14, OWASP LLM06 |

**Read this the way an auditor would:** `exec` — arbitrary code execution — has *nothing*
answering for it. `send_telemetry` ships data outward and lands on the information-flow /
boundary controls (AC-4, SC-7) but only as an **inferred** guess from the verb — no one
*declared* that mapping, so it can't be relied on for audit. Twenty of twenty-one actions are
inferred; one is ungoverned; none are asserted. That is the textbook definition of an
ungoverned agent, measured from its own code.

Full machine-readable output:
[`docs/scans/open-interpreter/ontology.json`](./scans/open-interpreter/ontology.json) ·
[`trust_profile.json`](./scans/open-interpreter/trust_profile.json) ·
[`badge.svg`](./scans/open-interpreter/badge.svg) ·
[`receipt.json`](./scans/open-interpreter/receipt.json)

---

## The receipt is the proof — verify it three ways

Every scan emits an Ed25519 **cert-only** receipt: the ontology's deterministic content is
hashed, a small signed body commits to that hash, and the signature verifies from the
certificate alone — no database, no network, no trusting CWN.

**1 — Verify with the tool:**
```bash
python -c "import json; from openagentontology.receipt import verify_receipt; \
print(verify_receipt(json.load(open('docs/scans/open-interpreter/receipt.json'))))"
# {'ok': True, 'hash_ok': True, 'sig_ok': True, 'signed': True,
#  'reason': 'hash valid and Ed25519 signature verified from the cert alone'}
```

**2 — Verify the hash independently** (any language; this is plain SHA-256 over canonical JSON):
```python
import json, hashlib
r = json.load(open("docs/scans/open-interpreter/receipt.json"))
canon = json.dumps(r["evidence"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
assert hashlib.sha256(canon.encode()).hexdigest() == r["evidence_hash"]   # passes
```

**3 — Prove it's tamper-evident.** Edit the evidence to fake a better grade and re-verify:
```python
r["evidence"]["ontology"]["action_maps"][1]["matched_via"] = "asserted_table"  # lie about exec
verify_receipt(r)
# {'ok': False, 'hash_ok': False,
#  'reason': 'evidence_hash mismatch -- evidence was altered'}
```
You cannot forge a higher score. Change one byte of the ontology and the receipt stops
verifying. This is the line between a **log** (something you write) and a **receipt**
(evidence that commits to exactly what was scanned).

---

## Reproduce it yourself

```bash
# 1. clone the exact commit we scanned
git clone https://github.com/OpenInterpreter/open-interpreter.git
git -C open-interpreter checkout e00f08e

# 2. from the directory that CONTAINS the clone, scan it by its folder name
python -m openagentontology open-interpreter
```

Same OpenAgentOntology version + same upstream commit + scanned as `open-interpreter` ⇒ you
reproduce the **identical** `evidence_hash` and atom_id `oao-OPENINTERPRE-7139be5c9a`, and the
**identical** verdict (UNGOVERNED 15/100, 21 actions, 0 asserted). The findings are
path-independent; only the signature differs, because you sign with your own key (verify ours
from the committed certificate).

---

## How to read a low score (and how to fix it)

A low score does **not** mean the tool failed — it means the agent's actions have no asserted
control, which is the honest finding for almost every agent shipping today. To move an action
from INFERRED/UNGOVERNED to ASSERTED, declare the canonical reason it's governed by and wire
the matching policy gate. See [`examples/hardened_agent/`](../examples/hardened_agent/): the
same shape of agent, but every action declares a reason — it scores **SOVEREIGN 93/100**.

Before → after, on the same agent archetype:

| | Declared governance | Asserted | Verdict |
|---|---|---|---|
| `examples/sample_agent` | none | 3/16 | UNGOVERNED 41 |
| **real agents (above)** | none | **0** | **UNGOVERNED 15** |
| `examples/hardened_agent` | every action | 14/15 | SOVEREIGN 93 |

---

## Honest limitations (so the claim survives scrutiny)

OpenAgentOntology extracts the action surface from **decorators**
(`@tool`, `@function_tool`, `@tool_node`, `@kernel_function`, `@mcp.tool`) and from
**verb-named functions** (`exec`, `run_*`, `delete_*`, `send_*`, `deploy_*`, …). It does **not**
yet resolve tools that are registered **at runtime** — e.g. the official MCP reference servers
build their tool list inside a `list_tools()` handler rather than declaring it statically.
Scanning [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers)
therefore under-extracts (it finds the static surface only). Runtime tool-registry resolution
is on the roadmap. We would rather state this than have you discover it — a tool that maps
governance has to be honest about its own coverage.

---

*Generated by OpenAgentOntology v0.1.0. The scans above are committed verbatim under
[`docs/scans/`](./scans/). No Receipt. No Trust.*
