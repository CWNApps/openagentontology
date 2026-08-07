# OpenAgentOntology

**The OpenTelemetry for agent governance.** Point it at any agent and it tells
you what that agent can do — and which governance control answers for each
action — in one ontology that speaks every framework at once: NIST 800-53, EU AI
Act, OWASP LLM Top 10, and **MITRE ATT&CK** — every action carries the technique
your SOC already hunts (`exec` → T1059, egress → T1048, destructive change → T1485).

**By [Cyber Warrior Network](https://cyberwarriornetwork.com)** · Home: [agent-ontology.cyberwarriornetwork.com](https://agent-ontology.cyberwarriornetwork.com) · Live demo: [cwnapps.github.io/openagentontology](https://cwnapps.github.io/openagentontology/)

```
SOVEREIGN  ·  score 93  ·  3 frameworks  ·  NIST 800-53 AC-5 · EU AI Act Art 14 · OWASP LLM06
```
<sub>(the real output of `examples/hardened_agent` — reproducible)</sub>

Your agent can move money, export records, and ship code. Today, the only record
of which control governs each of those actions lives in a slide, a spreadsheet,
or someone's head. OpenAgentOntology reads the agent's own source and writes that
record down — typed, scored, signed, and the same every time.

This is the first **Agent Ontology** — a missing layer of the agent stack.
**[Read the manifesto →](./docs/MANIFESTO.md)** · **[Read the paper (preprint PDF) →](./docs/OAO_paper_v2.pdf)**

> **Paper:** *The Agent Ontology: A Static, Signed, Fabrication-Safe Crosswalk From Agent Actions to Governance Controls* — measured on five agents, with figures, a formal model, a tamper matrix, and a non-agentic false-positive baseline. Every number reproduces with `python paper/experiments.py`. Preprint PDF above; an arXiv cs.CR version is forthcoming.

---

## Proof: it works on agents people actually run

We pointed it at the two most-starred autonomous coding agents on GitHub — both came back
**UNGOVERNED**, with **zero** of their side-effecting actions resolved to an asserted control:

| Target | Side-effecting actions | Asserted | Verdict |
|---|---|---|---|
| [`OpenInterpreter/open-interpreter`](https://github.com/OpenInterpreter/open-interpreter) `@e00f08e` | 21 | **0** | **UNGOVERNED 15/100** |
| [`gpt-engineer-org/gpt-engineer`](https://github.com/gpt-engineer-org/gpt-engineer) `@a90fcd5` | 6 | **0** | **UNGOVERNED 15/100** |

`exec` — arbitrary code execution — mapped to **no control at all**. The scans, the signed
receipts, and a three-way verification (including a tamper test that fails on a single edited
byte) are committed under **[docs/real-world-scan.md](./docs/real-world-scan.md)** —
reproducible from the pinned commits above.

---

## Map once, speak every framework

A wire-transfer guardrail is not "a Rego rule." It is NIST 800-53 AC-5
*Separation of Duties*, EU AI Act Article 14 *Human oversight*, and OWASP
LLM06 *Excessive Agency* — all at once. Auditors, regulators, and your board
each speak a different one of those languages.

OpenAgentOntology maps each agent action **once**, to a shared ontology, and
emits the right control id for whichever framework the reader cares about. You
stop re-translating the same control five ways.

It ingests:

- **Repos** — source trees with agents, tools, and policies
- **MCP servers** — tool manifests
- **LangChain / CrewAI agents** — declarative agent specs
- **OpenAPI** — the HTTP surface an agent calls
- **Rego** — fail-closed policy with deny keys
- **Workflow YAML** — multi-step agent flows

It maps each agent action to:

- The **Universal Agentic Ontology** (typed nodes: Agent, Capability, Decision, Gate, ...)
- **NIST SP 800-53r5** · **EU AI Act** · **OWASP LLM Top 10 (2025)** · **NIST AI RMF** · **MITRE ATT&CK** · **OCSF** · **NICE**

Then it validates the ontology, scores a **Trust Profile**, and emits a shareable
**SVG badge** plus an **Ed25519 cert-only receipt** you can verify with no server
and no database.

---

## Quickstart

```bash
pip install openagentontology
openagentontology path/to/your-agent
```

Pure Python, two runtime dependencies (`pyyaml`, `cryptography`).

Add the post-quantum legs with `pip install "openagentontology[pq]"` — see
[Verify a receipt yourself](#verify-a-receipt-yourself) for what each backend actually signs.

Prefer to run it from source, or want the bundled example?

```bash
git clone https://github.com/CWNApps/openagentontology
cd openagentontology
PYTHONPATH=. python -m openagentontology examples/sample_agent
```

Either way it prints the ontology summary, the Trust Profile, and writes the badge and
the signed receipt next to the source. Run it against your own agent by swapping the
path.

---

## What you get

| Output | What it is |
|--------|------------|
| **Ontology** | UAO-typed nodes and edges for every actor, agent, capability, tool, decision, and gate it found |
| **Cross-walk** | Each capability / decision / gate mapped to its framework controls, confidence-tagged |
| **Trust Profile** | A 0–100 score and a tier: `SOVEREIGN` / `HARDENED` / `DEVELOPING` / `UNGOVERNED` |
| **Badge** | A shareable SVG showing tier, score, framework count, and citable control refs |
| **Receipt** | A cert-only proof of the ontology, verifiable from the cert alone — Ed25519 always, plus post-quantum **ML-DSA-65** (FIPS 204) and **SLH-DSA** (FIPS 205) legs when the `[pq]` extra is installed |

---

## CWN AgentFDE — one-command onboarding

A human Forward Deployed Engineer scans your agent, finds the ungoverned actions, writes the
policy gates, and proves the tier moved. **AgentFDE does it autonomously:**

```bash
PYTHONPATH=. python -m openagentontology.fde your-agent-dir/
```

It runs the full loop — scan → triage the gaps → generate the governance → re-score to prove the
tier jump → notarize → hand off an onboarding report — and writes four artifacts next to your agent:

| File | What it is |
|------|------------|
| `governance.agent.yaml` | a declaration binding each action to a canonical reason; scans **asserted** |
| `governance.rego` | a fail-closed policy stub to wire into your runtime |
| `ONBOARDING.md` | the FDE handoff: before/after tier, what was auto-remediated, what still needs you |
| `receipt.json` | the signed, offline-verifiable receipt of the projected state |

On `examples/sample_agent` it moves **UNGOVERNED 41 → HARDENED 88**, and the generated manifest
is real governance, not a stub — it scans **SOVEREIGN 96** on its own. AgentFDE never executes
your code, and it's a governed agent itself ([`examples/agent_fde`](./examples/agent_fde/),
SOVEREIGN 94): the tool governs the tool that does the governing.

---

## Use it as a PR check

Drop [`.github/workflows/agent-governance.yml`](./.github/workflows/agent-governance.yml)
into any repo. On every pull request it scans the head and the base branch, posts the
Trust Profile as a comment, flags any **new ungoverned high-risk action** and any **new
EU AI Act Article 14** (human-oversight) gap, and **fails the check if the trust tier
dropped**. The gate logic is in [`ci/pr_check.py`](./ci/pr_check.py) — pure stdlib, so it
is testable and easy to read:

```bash
PYTHONPATH=. python -m openagentontology .       --json --no-receipt > head.scan.json
PYTHONPATH=. python -m openagentontology ../base --json --no-receipt > base.scan.json
python ci/pr_check.py --head head.scan.json --base base.scan.json --report report.md
# exit 0 = pass, 1 = governance regression, 2 = usage error
```

---

## Use it as an MCP server

Let your agent govern agents. The MCP server exposes the pipeline as four read-only tools so
any MCP client (Claude Desktop, Cursor, Claude Code) can scan an agent, map an action, or
verify a receipt inline — without ever executing the agent it is scanning.

```bash
git clone https://github.com/CWNApps/openagentontology && cd openagentontology
pip install -e ".[mcp]"
python -m openagentontology.mcp_server      # stdio transport
```

Add it to a client (Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "openagentontology": { "command": "python", "args": ["-m", "openagentontology.mcp_server"] }
  }
}
```

Tools: `oao_scan_agent(path)` · `oao_map_action(label, source_reason?)` ·
`oao_verify_receipt(receipt)` · `oao_explain()`. All read-only, local-path only (no clone,
no network), every list capped — the server cannot be turned into an SSRF or exec primitive.

---

## Tests

The suite is runnable with **no install step** (a `conftest.py` puts the package on the
path):

```bash
pip install pytest          # the only test-time dependency beyond the two runtime deps
pytest                      # 152 tests: crosswalk rigor, ingest safety, e2e, receipt, CI gate,
                            # risk profile, SARIF, golden fixtures, mutation, Proof Lab demo
```

The tests prove the honesty guarantees mechanically: no framework outside the allowed set,
no fabricated control id, auto-detected mappings are never `asserted`, and the receipt's
Python hash is reproduced by an **independent** (JS-style) canonicalizer so a browser
verifier agrees byte-for-byte.

---

## Honest by construction

Auto-detected mappings never claim more than they know.

- A control is marked **asserted** only on an exact, well-established match drawn
  from a fixed table. The tool never constructs a framework id string.
- Everything detected by heuristic is tagged **inferred** (a strong, single-domain
  verb) or **ambiguous** (a weak, overloaded verb) — and the badge shows asserted
  controls only.
- Every node, edge, and mapping carries its provenance: `EXTRACTED`, `INFERRED`,
  or `AMBIGUOUS`.
- Every run ships with the note: *"Proposed mappings, confidence-tagged; confirm
  against published control text."*

A structurally broken or fabrication-tainted ontology **fails validation** and
earns no badge. See [SPEC.md](./SPEC.md) for the full standard.

---

## Verify a receipt yourself

**One command, one file, no clone, no account.**

```bash
pip install cryptography            # the only hard requirement
curl -sO https://raw.githubusercontent.com/CWNApps/openagentontology/441104cc5c872ebda3e7cc6ab9edf2834931ace7/verify_receipt.py
sha256sum verify_receipt.py   # 17fd9d47b4b7f165b1a13771310d2098718d4a304542fcf282cac3b5565f7480
python verify_receipt.py autogen
```

`cryptography` is needed for the Ed25519 leg. The post-quantum legs additionally
need `oqs` (`pip install liboqs-python`); without it they report `SKIP` and are
never counted as passing. **The sample output below shows all three legs, so it
is what you get with `oqs` installed** — with only `cryptography`, the two PQ
rows read `SKIP` and the verdict still comes out `VERIFIED` on the Ed25519 leg.
Corrupt material in a PQ leg is a `FAIL` either way; a missing backend is a
skip, malformed bytes never are.

**Why a commit hash and not `main`.** A branch moves; a commit does not. The one
thing this page asks you to run locally is the one thing you should be able to
pin and hash before running it — piping an unpinned URL into your interpreter is
exactly the trust we are arguing you should not have to extend. Read the file
first if you like: it is ~300 lines of stdlib plus `cryptography`, and it imports
nothing from this package.

> The hash above is the file as **git stores and GitHub serves it** (LF endings).
> If you have the repo cloned on Windows, your working copy will be CRLF and will
> hash differently while being byte-identical in content. Hash what you
> downloaded, not what git checked out for you.

```
  receipt   oao-AUTOGEN-8e9684e60b
  decision  GOVERNED:UNGOVERNED

  [PASS] evidence hash   recomputed sha256 over canonical evidence matches
  [PASS] Ed25519         signature valid over the canonical body
  [PASS] ML-DSA-65       ML-DSA-65 signature valid
  [PASS] SLH-DSA         SLH-DSA signature valid

  [PASS] issuer          key matches OpenAgentOntology (CWN) scan signer

  VERIFIED - downloaded from GitHub, then verified locally.
  Unaltered since it was signed by the published OpenAgentOntology key.
  Checked on your machine. No CWN server was contacted or trusted.
```

Swap `autogen` for any scan name in [`docs/scans/`](docs/scans). Point it at a
local file and it makes **no network call at all**:

```bash
python verify_receipt.py docs/scans/crewai/receipt.json   # zero network calls
```

The packaged `oao-verify` console script is wired in `pyproject.toml` but is
**not on PyPI yet** — the published `0.2.0` wheel predates it. Until the next
release, use the file directly as shown above. When it does ship, pin the
version (`uvx --from openagentontology==<version> oao-verify`) rather than
resolving whatever PyPI serves that day.

Exit code `0` verified, `1` verification failed, `2` usage error -- so it drops
straight into CI.

**Try to break it.** Every one of these exits non-zero:

| What you do | What you get |
|---|---|
| change a number inside `evidence` | `FAIL evidence hash` -- hash mismatch |
| corrupt any signature leg | `FAIL` on that leg -- a broken leg is tamper, never a skip |
| strip the signatures entirely | `NOT VERIFIED - carries NO signature` |
| forge one with **your own** key | `NOT VERIFIED - signed by an UNKNOWN key` |
| keep our published key in the file, delete the signature it belongs to, and sign with your own PQ key | `NOT VERIFIED` -- provenance is credited to the leg that actually verified, never to a key string sitting unused in the receipt |

That last row is there because it once did the opposite. Independent review
found a receipt could keep CWN's Ed25519 *public key* while dropping the
Ed25519 *signature*, carry an attacker-signed ML-DSA leg, and print `VERIFIED —
Unaltered since it was signed by the published OpenAgentOntology key`. Keys are
now pinned per algorithm and identity follows the verified leg.

That last row is the one that matters. A receipt carries its own public key, so
"the signature checks out" only proves it is unaltered since *somebody* signed
it -- anyone can generate a key and sign a fabrication. The verifier pins the
published OpenAgentOntology signing key and **fails by default** on anything
else, so a forged receipt cannot exit 0 in your CI. Pass `--any-issuer` to check
integrity alone; it prints `INTEGRITY ONLY`, never `VERIFIED`.

### Why this matters

The standard objection to every tamper-evident audit log is that the vendor
hosts the log, so the vendor's word is doing the work. A receipt you can only
check by asking the vendor is that objection restated, not answered.

`verify_receipt.py` imports **nothing** from this package and nothing from CWN.
It reproduces the canonicalisation from the spec below and checks the signature
on your machine, against a signing key pinned in the script that you can compare
against any receipt we have published.

If we altered a receipt after signing it, you would see `FAIL`. If our servers
disappeared tomorrow, every receipt we have ever issued still verifies. And if
someone hands you a receipt we did **not** sign, you get `NOT VERIFIED` rather
than a green check -- which is the part a verifier that trusted the key inside
the receipt could never tell you.

### The mechanics


The receipt is signed over canonical JSON (`sort_keys`, no whitespace, ASCII), so
a browser or any Ed25519 tool reproduces the Python hash exactly:

1. Recompute `sha256` over the canonical evidence and compare to `evidence_hash`.
2. Verify the signature over the canonical body with the embedded public key.

No network. No trusting our logs. If `cryptography` is absent the receipt is
emitted unsigned and clearly flagged — never a faked signature.

**Post-quantum legs.** A signature you trust today should still hold when the curve
falls — otherwise an adversary can *harvest now, decrypt later*: store the receipt and
forge it once a quantum computer breaks Ed25519. So with `pip install "openagentontology[pq]"`
the receipt is **hybrid triple-signed** over the same body: Ed25519 + **ML-DSA-65**
(NIST FIPS 204, lattice) + **SLH-DSA** (NIST FIPS 205, hash-based — survives a lattice break).
Each leg signs identical bytes, so any single one verifying proves authenticity, and a verifier
that can check a leg and finds it broken reports tamper. The legs are additive: a receipt with
no PQ legs (or a verifier with no PQ backend) still checks Ed25519 and the hash exactly as before.

---

## Security

The pipeline **never executes ingested code**. Sources are read as text or parsed
as an AST. There are **no network calls** in the core pipeline — the receipt is
signed locally. Nothing you point it at runs.

---

## Open-core

This open-source tool produces everything **locally**: the ontology, the Trust
Profile, the badge, and a self-signed receipt — entirely offline.

CWN's hosted **notary and registry** is a separate service (not in this repo). It
performs cross-organization verification and maintains a public trust ledger, so
a receipt minted by one team can be checked by another. The local tool stands on
its own; the registry is the network effect on top.

| | OpenAgentOntology (this repo) | CWN Notary & Registry (hosted) |
|---|---|---|
| Ontology + cross-walk | yes | yes |
| Trust Profile + badge | yes | yes |
| Self-signed receipt | yes | yes |
| Graph-grounded resolution + live threat signals | — | yes |
| Verified-or-abstain gate (PROCEED / FLAG / ESCALATE) | — | yes |
| Cross-org verification | — | yes |
| Public trust ledger | — | yes |
| Continuous re-scoring | — | yes |

The hosted layer resolves each scanned action through a live control graph and runs a
deterministic **verified-or-abstain gate** that turns every resolution into a runtime action —
PROCEED, PROCEED-FLAGGED, or ESCALATE to a human when governance is not grounded enough to act
on. The gate composes *above* the signed receipt; it never replaces the cryptographic proof. A
worked output is committed at [docs/scans/open-interpreter/graph_resolutions.json](./docs/scans/open-interpreter/graph_resolutions.json)
(15 of open-interpreter's 21 actions escalate) and rendered live in the demo's Graph Model Preview.

---

## Standard

OpenAgentOntology defines the **Agent Ontology** category. The machine-readable standard —
JSON Schema, the canonical reason→control crosswalk, frameworks, tiers, and scoring weights —
lives in [`schema/`](./schema/), generated from the code so it can never drift. The prose
specification is [SPEC.md](./SPEC.md); the case for the category is [the manifesto](./docs/MANIFESTO.md).
The reference [CWN AgentFDE](./examples/agent_fde/) — the agent that operationalizes all of this —
is itself defined to the standard and scores SOVEREIGN. The standard is versioned; this is `v0.2.0`.

### Standards documents

The honesty contract behind the standard, each verified against the code and tests:

- **[Claims and non-claims](./docs/CLAIMS_AND_NON_CLAIMS.md)**: the six claims this tool
  makes, the seven it deliberately does not, and the test that pins each one.
- **[Threat model](./docs/THREAT_MODEL.md)**: protected assets, trust boundaries, and six
  receipt-tampering scenarios with their verified verification outcomes.
- **[Crosswalk rationale](./docs/crosswalk-rationale/)**: one file per canonical reason
  (ten total), with the boundary to its neighbors, the real controls it maps to, and a
  true-positive plus false-positive example for each.
- **[Reproducibility](./docs/REPRODUCIBILITY.md)**: exact commands to re-run the suite,
  the example scans, and the two real-world scans from their pinned commits, and to verify
  the committed triple-signed receipts including the post-quantum legs.

---

## FAQ

**How is this different from OPA (or any policy engine)?**
OPA *enforces* policy at runtime — it's the gate that returns allow/deny. OpenAgentOntology
*maps* your agent's actions to the controls that should govern them and shows which ones have
**no gate at all** — then translates each into NIST 800-53 / EU AI Act / OWASP so every reader
gets their own language. OPA is the lock; OAO is the audit that finds the doors with no lock.
They compose: OAO ingests your Rego as input, and an action behind an OPA gate with a canonical
deny reason scores **ASSERTED**. OAO doesn't enforce — it tells you where enforcement is missing.

**How is this different from tracing / observability (LangSmith, OpenTelemetry)?**
Tracing tells you what your agent *did* on one run. OAO tells you — statically, before it runs —
what it *can* do and which control answers for each action. Observability is the flight recorder;
OAO is the pre-flight inspection.

**Does it run my agent's code?**
No. AST parse + text read only. It never executes anything; the core pipeline makes no network
calls. Nothing you point it at runs.

**"Inferred" sounds like guessing — why trust it?**
Because it's labeled as a guess. A verb heuristic (`send_*` → egress controls) is tagged
**INFERRED** so you confirm it; only an exact, declared canonical reason becomes **ASSERTED**.
The badge counts asserted controls only, and the tool never fabricates a framework id.

**Can I fake a passing score?**
No. The receipt is Ed25519-signed over a hash of the exact ontology. Edit one action to inflate
the grade and verification fails (`evidence_hash mismatch`). You can't change the score without
breaking the receipt — see [docs/real-world-scan.md](./docs/real-world-scan.md) for the tamper test.

---

## License

[Apache-2.0](./LICENSE). Built by [Cyber Warrior Network](https://cyberwarriornetwork.com).

*Logs explain. Receipts prove.*
