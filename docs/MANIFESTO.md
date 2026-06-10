# The Agent Ontology

*The org chart for your non-human workforce.*

---

Your agent took twenty-one actions today. It ran code. It sent data outward. It could delete
records and call shutdown. For each of those actions, one question decides whether you have a
company tomorrow: **which control answers for it?**

For most agents shipping right now, the honest answer is *nothing*. And until this tool, there
was no way to even ask the question — let alone prove the answer.

## The layer the industry skipped

The agent stack was built in three layers. The industry shipped two.

| Layer | What it optimizes | State |
|---|---|---|
| **Frameworks** — LangChain, CrewAI, AutoGen, MCP | how to *build* agents → **capability** | crowded |
| **Observability** — LangSmith, OpenTelemetry, evals | what agents *did* → **hindsight** | crowded |
| **Agent Ontology** | what each action is *allowed* to do, and who *answers* → **accountability** | empty — until now |

For two years, every repo, every demo, and every dollar went up the **capability curve** —
agents that can `exec`, wire money, deploy code, touch PHI. The win condition was always *"look
what it can do."*

Nobody drew the other curve. For each thing the agent can do, *what control answers?* That
question doesn't make a demo cooler, so nobody asked it. It was the seatbelt in the muscle-car
era — invisible, until the crash.

**The gap between those two curves is the entire risk.** An Agent Ontology is the first
instrument that measures it.

## The reframe

A wire-transfer guardrail is not "a Rego rule." It is NIST 800-53 AC-5 *Separation of Duties*,
EU AI Act Article 14 *Human Oversight*, and OWASP LLM06 *Excessive Agency* — all at once.
Auditors, regulators, and your board each speak a different one of those languages, and today
someone re-translates the same control five different ways, by hand, in a spreadsheet that's
already stale.

An Agent Ontology maps each action **once** and speaks every framework. It is the Rosetta Stone
for agent governance.

## What it is

> *An Agent Ontology is a typed, signed map of every action an AI agent can take — and the
> governance control that answers for each one.*

It reads your agent's own source — never executing it — and writes down, per action, which
control is asserted, which is only inferred (a guess to confirm), and which is **ungoverned**.
Then it scores the whole agent on a 0–100 scale (`SOVEREIGN` / `HARDENED` / `DEVELOPING` /
`UNGOVERNED`) and signs the result with an Ed25519 receipt you can verify offline — one that
fails verification the instant anyone edits it.

Three analogies, because the category is new:

- **The org chart for AI.** Every company knows who's accountable for what — for its humans.
  None has one for the workers it didn't hire and can't fire.
- **The safety data sheet.** Every chemical in a lab ships with an SDS: what it does, what
  controls it. Your agent ships with a README and nothing. This is the SDS for autonomous software.
- **The building inspection, not the smoke-detector log.** Observability tells you about the
  fire after it starts. The Agent Ontology finds the room with no sprinkler before anyone
  strikes a match.

## The proof

We pointed it at the two most-starred autonomous coding agents on GitHub — the ones people
actually run.

| Agent | Side-effecting actions | Asserted controls | Verdict |
|---|---|---|---|
| `open-interpreter` (~58k★) | 21 | **0** | **UNGOVERNED 15/100** |
| `gpt-engineer` (~54k★) | 6 | **0** | **UNGOVERNED 15/100** |

`exec` — arbitrary code execution on your machine — answered to no control at all. Both scans,
both signed receipts, and a tamper test that fails on a single edited byte, are committed under
[real-world-scan.md](./real-world-scan.md). This is not a slide. It's evidence.

## Why it's a standard, not a feature

A control plane that *runs* your agent cannot credibly grade its own governance — that's the
auditee attesting to its own controls, separation of duties you'd never accept on a trading
desk. Accountability has to be independent, cross-vendor, and tamper-evident, or it's worth
nothing. So the vocabulary is published as an open standard — [the schema](../schema/) — that
any framework, policy engine, or registry can emit to. The way traces map to OpenTelemetry,
agent actions map to the Agent Ontology.

The reference implementation even governs *itself*: the agent that does the governing — the
[CWN AgentFDE](../examples/agent_fde/) — is defined to this standard and scores **SOVEREIGN 94**.
We don't ask you to do anything the tool doesn't do to its own author.

---

**Frameworks make agents powerful. Observability tells you what they did. The Agent Ontology
tells you who answers.**

*No Receipt. No Trust.*
