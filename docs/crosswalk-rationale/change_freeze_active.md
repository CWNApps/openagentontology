# change_freeze_active

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). A mapping is ASSERTED only when the source names this
reason verbatim; the verb heuristic below yields INFERRED at best.

## Definition

A change freeze is in effect: a declared time window (release blackout, quarter close,
incident lockdown, regulatory hold) during which changes -- including otherwise-approved
ones -- must not be applied. The gate enforces WHEN change is allowed, on top of whatever
per-change approvals exist.

## Included action types

- Tasks that mutate production state during a freeze window: deployments, config pushes,
  schema migrations attempted inside a blackout.
- Destructive data operations held by a freeze or hold: purges, drops, wipes.
- Heuristic verbs (Layer 2, INFERRED only): `delete`, `drop`, `purge`, `wipe`, `destroy`,
  `truncate`, `erase`. Note the honest imprecision: the heuristic routes destructive verbs
  to this reason as the nearest canonical change-control semantics; the basis string flags
  the inference and a reviewer may re-declare such actions as `approval_required` or
  `high_blast_needs_named_approver` instead.

## Excluded action types (the boundary)

- A change blocked for lack of an approved change request is `approval_required` -- a
  PER-CHANGE gate, where freeze is a TIME-WINDOW gate. A deploy can clear approval and
  still be frozen.
- A change whose blast radius demands an accountable named human is
  `high_blast_needs_named_approver`.
- An adverse decision about a person is `human_review_required`.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | CM-3 | Configuration Change Control | asserted |
| NIST SP 800-53r5 | CM-5 | Access Restrictions for Change | asserted |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | asserted |

## Advisory MITRE mapping

MITRE ATT&CK T1485 (Data Destruction), advisory: a destructive change during a freeze maps
to data destruction. Advisory mappings are informative and never counted toward coverage or
the badge.

## True positive

A data-platform agent exposes `purge_audit_logs(retention_days)` behind a gate that
declares `reason: change_freeze_active` while a regulatory hold is in force. The gate
resolves ASSERTED to CM-3 / CM-5 / LLM06 -- the freeze declaration is exactly what an
auditor needs to see attached to a destructive capability.

## False positive

A build agent exposes `delete_temp_files()` that clears its own scratch directory between
runs. The verb `delete` fires the heuristic and proposes change-control controls for
janitorial cleanup of agent-local state. The result is INFERRED, labeled as a guess in its
basis string, and a reviewer drops it.

## Test coverage

- Control anchors pinned (the CM-3 and CM-5 rows):
  `tests/test_crosswalk.py::test_canonical_control_anchors_present`.
- Heuristic probe (`delete_dataset`, never fabricates and never asserts):
  `tests/test_crosswalk.py::test_map_action_never_fabricates_a_framework_id`.
- Membership in the canonical ten:
  `tests/test_crosswalk.py::test_all_canonical_reasons_present`.
