# regulated_egress_blocked

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). A mapping is ASSERTED only when the source names this
reason verbatim; the verb heuristic below yields INFERRED at best.

## Definition

Regulated data is about to LEAVE the controlled boundary toward an out-of-scope endpoint --
an export, upload, transmission, or share whose destination is not approved for that data.
The block is about movement across the boundary, independent of whether the agent was
allowed to handle the data inside it.

## Included action types

- Capabilities that move data outward: exports to external warehouses, uploads to
  third-party services, outbound transmissions, telemetry, record sharing.
- Gates that enforce destination allowlists for regulated records.
- Heuristic verbs (Layer 2, INFERRED only): `export`, `egress`, `exfil`, `exfiltrate`,
  `upload`, `send`, `forward`, `transmit`, `share`, `leak`.

## Excluded action types (the boundary)

- HANDLING data above the agent's clearance is `classification_above_ceiling` -- the
  ceiling governs what may be touched at all; this reason governs where it may go. An
  agent cleared for the data can still be blocked from exporting it.
- Reaching a system outside the agent's authority is `out_of_scope_domain`.
- Purely internal sends (a notification to an internal channel, a write to an in-boundary
  queue) are not regulated egress; declaring them so dilutes the signal.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | AC-4 | Information Flow Enforcement | asserted |
| NIST SP 800-53r5 | SC-7 | Boundary Protection | asserted |
| EU AI Act | Art 10 | Data and data governance | asserted |
| OWASP LLM Top 10 (2025) | LLM02 | Sensitive Information Disclosure | asserted |
| MITRE ATT&CK | TA0010 | Exfiltration | advisory |

## Advisory MITRE mapping

Two advisory entries ride along: TA0010 (Exfiltration, the tactic -- confirm the specific
technique with an analyst) from the base table, plus T1048 (Exfiltration Over Alternative
Protocol) from the technique enrichment. Advisory mappings are informative and never
counted toward coverage or the badge.

## True positive

A healthcare agent declares `reason: regulated_egress_blocked` on
`export_phi_records` (export patient records to a research warehouse), resolving ASSERTED
to AC-4 / SC-7 / Art 10 / LLM02. This is exactly the `export_phi_records` capability in
`examples/hardened_agent/agent.yaml`. The undeclared form is just as instructive: the
real-world scan of open-interpreter surfaced `send_telemetry` as INFERRED onto AC-4/SC-7
from the bare verb (`docs/real-world-scan.md`).

## False positive

An ops agent exposes `send_notification(channel, text)` posting build results to an
internal chat channel. The verb `send` fires the egress heuristic and proposes
boundary-protection controls for traffic that never leaves the boundary. The result is
INFERRED, its basis string flags the inference, and a reviewer drops it.

## Test coverage

- Verb-named egress function is crosswalked, not dropped (`fn_send_telemetry`):
  `tests/test_action_crosswalk.py::test_verb_named_functions_are_crosswalked`.
- Control anchors pinned (the AC-4 and SC-7 rows):
  `tests/test_crosswalk.py::test_canonical_control_anchors_present`.
- Remediation recovers this reason for export actions:
  `tests/test_fde.py::test_fde_onboard_improves_tier_and_emits_artifacts`.
