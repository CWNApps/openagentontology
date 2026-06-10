# Launch playbook — OpenAgentOntology

The headline is the proof, not the pitch: *we scanned the top AI agents on GitHub, mapped every
action to MITRE ATT&CK, and found their most dangerous actions answer to no control at all.*
Every post below leads with a number a reader can verify in one click. Precision matters here:
the claim is zero *declared* governance bindings (every control we surface, we had to infer),
and the single most dangerous action ungoverned even by that inference. Do not say "no control
answers for any action" -- the heuristic layer maps most verbs, and a reader who runs the tool
will see that.

> Live URLs (already inlined below): repo `https://github.com/CWNApps/openagentontology` ·
> demo `https://cwnapps.github.io/openagentontology/`. Swap the demo to the custom domain
> (`agent-ontology.cyberwarriornetwork.com`) once DNS is pointed.

---

## 1. Show HN

**Title:** `Show HN: Map every AI agent action to the control that answers (NIST, EU AI Act, MITRE ATT&CK)`

**Body:**
We kept asking a question nobody had a tool for: when your AI agent runs code, wires money, or
exports data — which control answers for it? So we built one.

OpenAgentOntology reads an agent's source (AST + text, never executes it), and writes down, per
action, the governance control that governs it — in NIST 800-53, EU AI Act, OWASP LLM Top 10,
and MITRE ATT&CK at once. It scores the agent 0–100 and signs an Ed25519 receipt you verify
offline (edit one action to fake a better grade and verification fails).

We ran it on the two most-starred autonomous coding agents on GitHub. open-interpreter (58k★)
and gpt-engineer (54k★): **zero** of their side-effecting actions resolve to an asserted control.
`exec` — arbitrary code execution on the host — maps to MITRE **T1059** and is governed by
nothing. The scans, signed receipts, and a tamper test are committed in the repo, reproducible
from a pinned commit.

It's open-core (Apache-2.0): the tool, the schema/standard, and a one-command remediation agent
(AgentFDE) are all in the repo. Run it on your own agent:

    git clone https://github.com/CWNApps/openagentontology && cd openagentontology
    PYTHONPATH=. python -m openagentontology ../your-agent

Demo (5 real agents, toggle them): https://cwnapps.github.io/openagentontology/
Repo + signed scans: https://github.com/CWNApps/openagentontology

Happy to answer anything about the crosswalk, the receipt format, or why we kept the core
stdlib-only and offline.

---

## 2. X / LinkedIn thread

**Hook (post 1):**
Everyone's auditing the AI *model*. Nobody's auditing the *agent*.

We scanned the 2 most-starred AI coding agents on GitHub.
Neither declares a single governance binding. Every control we found, we had to infer.
And the most dangerous thing each one does answers to nothing:
`exec` → MITRE T1059 → governed by nothing, not even a guess. 🧵

**2.** Your model didn't wire the money. Your *agent* did. Frameworks made agents capable;
tracing told you what they did *after*. Nobody mapped what each action is *allowed* to do — or
who answers when it acts. That gap is the whole risk.

**3.** open-interpreter (58k★): 21 side-effecting functions. `exec`, `run_applescript`,
`send_telemetry`, `delete_event`. Asserted controls: **0**. gpt-engineer (54k★): same verdict.
Not cherry-picked — both, published, reproducible.

**4.** OpenAgentOntology reads the agent's code (never runs it) and maps every action to NIST
800-53 / EU AI Act / OWASP LLM Top 10 / **MITRE ATT&CK** — the language your SOC already hunts.
Then it signs a tamper-evident receipt you verify offline.

**5.** And it fixes it. Point AgentFDE at an agent and it scans → finds the ungoverned actions →
writes the policy gates → re-scores → hands you a signed report. Our sample agent: UNGOVERNED 41
→ HARDENED 88, in one command.

**6.** Open-core, Apache-2.0. Run it on your agent, post your score:
https://github.com/CWNApps/openagentontology · demo: https://cwnapps.github.io/openagentontology/

You don't get sued for what your AI thought. You get sued for what it did.

---

## 3. LinkedIn longform (CEO voice)

**The insider threat you onboarded on purpose.**

Every enterprise deploying AI agents is onboarding the perfect insider threat — deliberately. An
agent holds standing credentials, acts faster than any human can review, and is trusted by
default. It's the only insider with root access you hired on purpose and can't fire,
background-check, or even watch act.

For two years the industry made that insider more capable (LangChain, AutoGPT, MCP) and
better-observed after the fact (tracing, evals). Nobody mapped what it's *allowed* to do, or who
answers when it acts.

So we measured it. We pointed our scanner at the two most-starred autonomous coding agents on
GitHub. Neither declares a single governance binding; every control the scan surfaced, it had to
infer from a verb name. And the most dangerous action each one takes, `exec`, arbitrary code
execution on the host, maps to MITRE ATT&CK T1059 and is governed by nothing, not even by inference.

That's not a bug in those projects. It's the state of every agent shipping today, finally
measured. Knight Capital lost $440M in 45 minutes from one unguarded automated deploy — and that
was a dumb script, not an agent that can reason about how to cover its tracks.

OpenAgentOntology is the map: every agent action → the control that answers, in NIST, EU AI Act,
OWASP, and MITRE ATT&CK, signed and reproducible. It's open-source, today. Run it on your agent.
Get your number. Fix the red ones.

https://github.com/CWNApps/openagentontology · https://cwnapps.github.io/openagentontology/

*No Receipt. No Trust.*

---

## Sequence
- **T+0:** Show HN (Tue–Thu, 8–10am ET) + the X thread same hour.
- **T+2h:** LinkedIn longform.
- **T+1d:** r/netsec + r/MachineLearning (link the HN thread, lead with the ATT&CK finding).
- **T+2d:** the manifesto ([../MANIFESTO.md](../MANIFESTO.md)) as a standalone Substack post.
- Throughout: respond to every HN/issue comment within the hour; add a README badge; track stars + runs.
