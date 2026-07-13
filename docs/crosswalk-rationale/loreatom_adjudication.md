# loreatom_adjudication

A sovereignty crosswalk entry documenting the knowledge-quality adjudication pattern for
LoreAtom nodes in Trust Gate's knowledge graph. This is not a deny-key reason; it is a
governance pattern ensuring that harvested knowledge enters the graph as `candidate` and
requires explicit human-in-loop promotion before it becomes trusted.

## Definition

A LoreAtom is a knowledge node harvested from agent interactions, research outputs, or
operational telemetry. By default, every harvested LoreAtom enters the graph with status
`candidate`. The adjudication pattern enforces:

1. **Default candidate** -- no harvested knowledge is automatically trusted. The harvest
   process writes `status: candidate` unconditionally; there is no code path that writes
   `status: promoted` at harvest time.
2. **Explicit promotion** -- a human reviewer (or a delegated agent with explicit
   authorization) calls `promote(atom_id, caller_id, reason)`. The promotion records WHO
   promoted, WHEN, and WHY. The reason field is mandatory and non-empty.
3. **Explicit rejection** -- `reject(atom_id, caller_id, reason)` marks the atom as
   `rejected` with the same provenance trail. Rejected atoms remain in the graph
   (append-only) but are excluded from downstream queries.
4. **Caller identity binding** -- the `caller_id` on promote/reject is verified against
   the authenticated session, not self-declared by the caller. This prevents an agent from
   promoting its own harvested knowledge.

## OAO mapping

| OAO construct | Instance | Relationship |
|---|---|---|
| Decision | `loreatom_promotion` | the promote/reject decision on a candidate atom |
| Policy | `adjudication_policy` | GOVERNED_BY: requires caller_id + non-empty reason + status=candidate |
| Gate | `promotion_gate` | enforces that only authorized callers can transition status |
| Evidence | `adjudication_receipt` | PRODUCES receipt recording the decision, caller, and reason |

Graph pattern:

```
(Decision:loreatom_promotion)-[:GOVERNED_BY]->(Policy:adjudication_policy)
(Gate:promotion_gate)-[:ENFORCES]->(Policy:adjudication_policy)
(Decision)-[:PRODUCES]->(Evidence:adjudication_receipt)
```

## Included action types

- LoreAtom harvest operations (always produce candidate-status nodes).
- Promote calls that transition a LoreAtom from `candidate` to `promoted`.
- Reject calls that transition a LoreAtom from `candidate` to `rejected`.
- Bulk review workflows where a reviewer triages multiple candidate atoms.

## Excluded action types (the boundary)

- Reading or querying LoreAtoms (even candidates) is not an adjudication action.
- Creating a LoreAtom is a harvest, not a decision -- the harvest is the input to the
  adjudication pipeline, not part of it.
- Editing a promoted LoreAtom's content is a separate mutation concern. Adjudication governs
  the status transition, not content changes.

## Rationale

Unsupervised knowledge accumulation is a trust liability. If an agent can harvest a claim
from a web page and that claim automatically enters the trusted knowledge graph, every
downstream decision that queries the graph inherits the unverified claim. The candidate
default plus mandatory human adjudication creates a quality gate on knowledge. This maps to
EU AI Act Art 14 (human oversight) because the promotion decision is the human oversight
checkpoint for knowledge quality. It also maps to NIST 800-53 CM-3 (configuration change
control) because promoting a LoreAtom changes the configuration of the knowledge graph that
other agents depend on.

## Primary controls

| Framework | Control | Name | Confidence |
|---|---|---|---|
| EU AI Act | Art 14 | Human oversight | advisory |
| NIST SP 800-53r5 | CM-3 | Configuration Change Control | advisory |
| NIST SP 800-53r5 | AC-6 | Least Privilege | advisory |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | advisory |

All advisory: the adjudication pattern is a knowledge-governance mechanism. AC-6 applies
because the promotion capability is restricted to authorized callers (least privilege on
who may change knowledge status). LLM06 applies because auto-promotion would be excessive
agency -- the agent harvesting knowledge should not also approve it.

## Implementation reference

- Service: LoreAtom adjudication pipeline (Trust Gate sovereignty wave 3)
- Status transitions: `candidate -> promoted` (via promote), `candidate -> rejected` (via reject)
- Mandatory fields on transition: `caller_id` (authenticated), `reason` (non-empty string)
- Graph constraint: append-only (rejected atoms are never deleted, only filtered from queries)
