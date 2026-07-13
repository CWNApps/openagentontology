# two_phase_decision_gate

A sovereignty crosswalk entry documenting the PREVIEW-then-COMMIT decision pattern
implemented by Trust Gate's `DecisionGateService`. This is not one of the ten canonical
deny-key reasons in `ASSERTED_TABLE`; it is a structural pattern that compositions of
those reasons can enforce.

## Definition

A high-risk action passes through two explicit phases before execution:

1. **PREVIEW** -- the agent requests an ExecutionPermit describing what it intends to do.
   The gate evaluates policy, computes blast radius, and returns a permit object containing
   the scope, constraints, and expiry. No side effects occur.
2. **COMMIT** -- the agent submits the permit back to the gate. The gate re-validates the
   permit (not expired, scope unchanged, policy still satisfied) and only then allows the
   action to proceed. A receipt is minted on commit.

The two-phase split prevents single-call execution of high-risk actions. An agent cannot
skip PREVIEW and jump to COMMIT; the permit is the proof that policy evaluation happened.

## OAO mapping

| OAO construct | Instance | Relationship |
|---|---|---|
| Gate | `decision_gate` | GATED_BY Policy (the OPA rule set that evaluates the permit request) |
| Decision | `execution_permit` | GOVERNED_BY Gate (the permit is the Decision artifact the gate produces) |
| Evidence | `commit_receipt` | PRODUCES receipt on successful commit phase |
| Policy | `blast_radius_policy` | ENFORCES the threshold and scope constraints checked at PREVIEW |

Graph pattern:

```
(Agent)-[:MAKES]->(Decision:execution_permit)
(Decision)-[:GOVERNED_BY]->(Gate:decision_gate)
(Gate)-[:GATED_BY]->(Policy:blast_radius_policy)
(Gate)-[:PRODUCES]->(Evidence:commit_receipt)
```

## Included action types

- Any action whose blast radius exceeds the configured threshold (e.g. production
  deployments, schema migrations, agent definition changes, policy mutations).
- Tasks that modify shared state visible to other agents or external systems.
- Heuristic alignment: actions that would trigger `approval_required` or
  `high_blast_needs_named_approver` in the canonical deny-key table are strong candidates
  for the two-phase gate.

## Excluded action types (the boundary)

- Read-only queries and side-effect-free computations do not require a permit.
- Actions already governed by a dedicated gate (e.g. `dual_control_required` for financial
  transactions) use their own protocol; two-phase is an additional structural layer, not a
  replacement.
- Internal logging, metrics emission, and receipt minting are downstream of the commit and
  are not themselves gated.

## Rationale

Single-call execution conflates evaluation and action into one step. If the evaluation
logic has a bug or the agent races past a transient policy relaxation, the action has
already happened. The two-phase split creates an auditable gap: the permit is evidence that
policy was consulted, and the commit is evidence that the permit was valid at execution
time. This maps directly to NIST 800-53 CM-3 (change control) and EU AI Act Art 14 (human
oversight checkpoints) because the PREVIEW phase is the natural insertion point for a human
to inspect or veto.

## Primary controls

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | CM-3 | Configuration Change Control | advisory |
| NIST SP 800-53r5 | CM-4 | Impact Analyses | advisory |
| EU AI Act | Art 14 | Human oversight | advisory |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | advisory |

All advisory: the two-phase pattern is a structural enforcement mechanism that strengthens
existing deny-key controls. The canonical deny-key reason (e.g. `approval_required`) is
what resolves to asserted; this entry documents the implementation architecture.

## Implementation reference

- Service: `DecisionGateService` (Trust Gate sovereignty wave 0)
- Permit object: `ExecutionPermit { scope, constraints, expiry, policy_snapshot_hash }`
- Commit validation: permit not expired, scope matches request, policy hash unchanged
