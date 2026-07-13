# reference_node_federation

A sovereignty crosswalk entry documenting the federated reference-node pattern in Trust
Gate's knowledge graph. This is not a deny-key reason; it is a data-sovereignty pattern
ensuring that cross-organization references never replicate PII or sensitive data into the
local graph.

## Definition

A reference node is a pointer to an entity that lives in an external system of record
(SOR). Instead of replicating the entity's data into the local graph, the reference node
carries only:

- `external_sor_id` -- the identifier in the external system (e.g. a CRM record id, an
  HR system employee id, a partner's agent registry id).
- `source_domain` -- the domain or system that owns the canonical record (e.g.
  `crm.internal`, `partner.acme.io`, `registry.oao`).

The reference node explicitly does NOT carry: names, email addresses, classification
labels, financial data, health data, or any field that would constitute PII or regulated
data if the graph were exported or shared. Federated queries resolve the reference at
query time by calling back to the SOR, never by reading replicated data from the graph.

## OAO mapping

| OAO construct | Instance | Relationship |
|---|---|---|
| Resource | `reference_node` | the pointer-only node in the local graph |
| Policy | `data_sovereignty_policy` | GOVERNED_BY: no PII in reference nodes, resolution via SOR callback |
| Domain | `source_domain` | the external system of record that owns the canonical data |
| Gate | `federation_gate` | enforces that writes to reference nodes contain only pointer fields |

Graph pattern:

```
(Resource:reference_node)-[:GOVERNED_BY]->(Policy:data_sovereignty_policy)
(Resource)-[:OPERATES_ON]->(Domain:source_domain)
(Gate:federation_gate)-[:ENFORCES]->(Policy:data_sovereignty_policy)
```

## Included action types

- Creating a reference node (must contain only `external_sor_id` and `source_domain`).
- Federated resolution queries that resolve a reference node by calling the SOR at query
  time.
- Cross-organization graph federation where one organization's agents reference another's
  entities without data replication.
- Export and sharing of graph subsets that include reference nodes (safe because no PII is
  embedded).

## Excluded action types (the boundary)

- Full entity replication (copying an external record into the local graph with all its
  fields) is the opposite of this pattern and is what the policy prevents.
- Internal entities that ARE owned by the local system are regular nodes, not reference
  nodes. The reference-node pattern applies only to externally owned data.
- Query-time resolution (the SOR callback) is a read operation governed by the SOR's own
  access controls, not by the federation gate. The gate governs what is STORED, not what
  is QUERIED.

## Rationale

Data replication creates sovereignty problems: if organization A copies organization B's
employee records into its own graph, A now holds PII it did not originate, cannot
authoritatively update, and must independently comply with deletion requests for. The
reference-node pattern eliminates this by design: the local graph holds only opaque
pointers. This maps to EU AI Act Art 10 (data governance) because the pattern enforces
data minimization by construction -- the graph cannot leak data it never held. It also maps
to NIST 800-53 AC-4 (information flow enforcement) because the federation gate controls
what data flows INTO the graph from external sources, not just what flows out.

## Primary controls

| Framework | Control | Name | Confidence |
|---|---|---|---|
| EU AI Act | Art 10 | Data and data governance | advisory |
| NIST SP 800-53r5 | AC-4 | Information Flow Enforcement | advisory |
| NIST SP 800-53r5 | SC-7 | Boundary Protection | advisory |
| NIST SP 800-53r5 | MP-6 | Media Sanitization | advisory |

All advisory: the federation pattern is a data-sovereignty mechanism, not a deny-key gate.
MP-6 applies because reference nodes make graph exports inherently sanitized -- there is no
PII to scrub because it was never stored. AC-4 applies to the inbound direction (what data
is allowed to enter the graph), complementing `regulated_egress_blocked` which covers the
outbound direction.

## Implementation reference

- Pattern: Reference node federation (Trust Gate sovereignty wave 4)
- Node schema: `{ external_sor_id: string, source_domain: string }` (no other fields permitted)
- Federation gate: validates on write that reference nodes contain only pointer fields
- Query resolution: SOR callback at query time with caller authentication
- Export safety: reference nodes export as opaque pointers; no PII in any export artifact
