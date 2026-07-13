# egress_receipt_required

A sovereignty crosswalk entry documenting the per-call egress receipt pattern implemented
by Trust Gate's `EgressGateService`. Extends the canonical `regulated_egress_blocked`
deny-key reason with a structural receipt-per-egress requirement.

## Definition

Every outbound data movement from an agent is classified, gated, and receipted:

1. **Classify** -- the egress gate inspects the outbound payload and assigns a data
   classification (PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED).
2. **Gate** -- RESTRICTED data is blocked unconditionally. Other classifications are
   checked against destination allowlists and policy constraints.
3. **Receipt** -- every LLM call or external API invocation that passes the gate produces a
   signed receipt recording the classification, destination, timestamp, and policy snapshot.
   Blocked calls also produce a receipt (with a DENY verdict) so the block itself is
   auditable.

The key property: there is no unreceipted egress. Even a successfully allowed call leaves a
cryptographic trace.

## OAO mapping

| OAO construct | Instance | Relationship |
|---|---|---|
| Gate | `egress_gate` | ENFORCES Policy (the data classification and destination rules) |
| Policy | `data_classification_policy` | defines PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED tiers |
| Evidence | `egress_receipt` | PRODUCES receipt per outbound call (ALLOW or DENY) |
| Capability | `outbound_call` | GATED_BY Gate (every external-facing capability is subject) |

Graph pattern:

```
(Capability:outbound_call)-[:GATED_BY]->(Gate:egress_gate)
(Gate)-[:ENFORCES]->(Policy:data_classification_policy)
(Gate)-[:PRODUCES]->(Evidence:egress_receipt)
```

## Included action types

- All LLM provider calls (prompt and completion payloads cross the trust boundary).
- External API invocations, webhook deliveries, file exports, email sends.
- Data federation queries to external systems where query parameters may contain
  sensitive context.
- Heuristic alignment: every action that would trigger `regulated_egress_blocked` in the
  canonical deny-key table, plus all allowed egress that the deny-key table would pass
  silently (the receipt requirement closes that gap).

## Excluded action types (the boundary)

- Internal service-to-service calls within the trust boundary are not egress. The boundary
  is defined by the deployment topology, not by network hops.
- Reads from external systems (ingress) are a separate concern; this entry covers outbound
  data movement only.
- Receipt minting itself is not recursive -- the receipt is an append-only evidence write,
  not an egress event.

## Rationale

The canonical `regulated_egress_blocked` reason handles the DENY case: regulated data is
blocked from leaving. But allowed egress is invisible unless receipted. An organization
that only logs denials cannot answer "what data DID leave, and when?" after the fact. The
per-call receipt closes this gap: every egress event, whether allowed or denied, is a
signed evidence record. This directly supports NIST 800-53 AU-3 (content of audit records)
and SC-7 (boundary protection) because the receipt IS the audit record for that boundary
crossing.

## Primary controls

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | AC-4 | Information Flow Enforcement | advisory |
| NIST SP 800-53r5 | SC-7 | Boundary Protection | advisory |
| NIST SP 800-53r5 | AU-3 | Content of Audit Records | advisory |
| EU AI Act | Art 10 | Data and data governance | advisory |
| OWASP LLM Top 10 (2025) | LLM02 | Sensitive Information Disclosure | advisory |

All advisory: the receipt-per-egress pattern is a structural extension of the
`regulated_egress_blocked` deny-key reason. The deny-key resolves to asserted; this entry
documents the receipt architecture that makes both ALLOW and DENY auditable.

## Implementation reference

- Service: `EgressGateService` (Trust Gate sovereignty wave 1)
- Classification tiers: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
- Receipt fields: `{ classification, destination, verdict, timestamp, policy_hash, payload_hash }`
- RESTRICTED = unconditional block + DENY receipt
