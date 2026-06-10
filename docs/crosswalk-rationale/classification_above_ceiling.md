# classification_above_ceiling

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). A mapping is ASSERTED only when the source names this
reason verbatim; the verb heuristic below yields INFERRED at best.

## Definition

The agent is about to HANDLE data classified above the ceiling it is cleared for --
restricted, confidential, regulated-sensitive (PHI, PII), or formally classified material.
The gate enforces the categorization of the resource: data above the ceiling is refused
regardless of where it would go.

## Included action types

- Capabilities that read, process, summarize, or transform data carrying a sensitivity
  label above the agent's clearance.
- Gates that compare a data classification label against the agent's ceiling (the PHI
  classification gate pattern).
- Heuristic tokens (Layer 2, INFERRED only): `pii`, `ssn`, `secret`, `credential`,
  `password`, `classif`, `classify`, `confidential`, `restricted`, `redact`.

## Excluded action types (the boundary)

- Moving data OUT to an unapproved destination is `regulated_egress_blocked` -- the
  ceiling governs what may be HANDLED at all; egress governs where data may GO. An export
  of permitted-classification data to a forbidden endpoint is an egress problem, not a
  ceiling problem.
- Reaching a system outside the agent's authority is `out_of_scope_domain` (authority over
  systems, not sensitivity of data).
- A transaction value limit is `over_threshold`.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | RA-2 | Security Categorization | asserted |
| NIST SP 800-53r5 | AC-4 | Information Flow Enforcement | asserted |
| EU AI Act | Art 10 | Data and data governance | asserted |
| OWASP LLM Top 10 (2025) | LLM02 | Sensitive Information Disclosure | asserted |

## Advisory MITRE mapping

MITRE ATT&CK T1530 (Data from Cloud Storage), advisory: handling data above a
classification ceiling maps to sensitive-data access. Advisory mappings are informative and
never counted toward coverage or the badge.

## True positive

A healthcare data agent declares `reason: classification_above_ceiling` on its
`phi_data_classification_gate` so any request touching records above the agent's PHI
clearance is refused. The gate resolves ASSERTED to RA-2 / AC-4 / Art 10 / LLM02. This is
exactly the `phi_data_classification_gate` in `examples/hardened_agent/agent.yaml`.

## False positive

An ML helper exposes `classify_support_tickets(batch)`. The token `classify` fires the
heuristic and proposes data-classification controls for a function that assigns categories
to tickets and never touches a sensitivity ceiling. The result is INFERRED, its basis
string says it was inferred from the verb, and a reviewer discards it.

## Test coverage

- Control anchors pinned (the RA-2 and LLM02 rows):
  `tests/test_crosswalk.py::test_canonical_control_anchors_present`.
- Heuristic probe (`redact_pii`, never fabricates and never asserts):
  `tests/test_crosswalk.py::test_map_action_never_fabricates_a_framework_id`.
- Declared-reason fixture: `examples/hardened_agent/agent.yaml`
  (`phi_data_classification_gate`), scanned end-to-end by the README-documented
  hardened-agent run (SOVEREIGN 93).
