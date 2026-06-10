# high_blast_needs_named_approver

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). Layer-1 only: NO heuristic verb maps to this reason --
blast radius is a judgment about consequences, not a property of an action label, so it
must be declared by the source to appear at all.

## Definition

A change whose blast radius is wide or irreversible -- mass deletion, tenant-wide
reconfiguration, destruction of recovery paths -- requires an impact analysis AND a NAMED,
accountable human approver distinct from the actor. Not "an approval exists" but "a
specific person owns this outcome".

## Included action types

- Tasks that are irreversible or organization-wide in effect: deleting records under
  regulatory hold, dropping production datastores, disabling backups or recovery, rotating
  credentials fleet-wide, tenant-wide policy rewrites.
- Gates that require a named approver identity (not just an approval state) plus an impact
  analysis artifact before such a change.

## Excluded action types (the boundary)

- A routine production change with a normal sign-off path is `approval_required` --
  approval accepts any valid change request; high-blast demands a named accountable
  approver and an impact analysis. Declaring every config bump as high-blast dilutes the
  named-approver signal until it means nothing.
- A change blocked only by a blackout window is `change_freeze_active`.
- A financial transaction needing two authorizers is `dual_control_required` (transaction
  control, not change control).

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | CM-4 | Impact Analyses | asserted |
| NIST SP 800-53r5 | AC-5 | Separation of Duties | asserted |
| EU AI Act | Art 14 | Human oversight | asserted |

## Advisory MITRE mapping

MITRE ATT&CK T1490 (Inhibit System Recovery), advisory: a high blast-radius destructive
change maps to inhibit-system-recovery. Advisory mappings are informative and never counted
toward coverage or the badge.

## True positive

A healthcare data agent declares `reason: high_blast_needs_named_approver` on
`delete_records` (delete patient records under regulatory hold), resolving ASSERTED to
CM-4 / AC-5 / Art 14. This is exactly the `delete_records` capability in
`examples/hardened_agent/agent.yaml` -- an irreversible action whose receipt should carry a
named human owner.

## False positive

A platform team declares `reason: high_blast_needs_named_approver` on
`deploy_config` for a routine feature-flag flip because "production is always high stakes".
Layer 1 fires on the verbatim token and asserts impact-analysis controls for a change that
`approval_required` already covers. The mapping is sourced but over-classified; the GRC
review the CONFIRM_NOTE mandates should downgrade the declaration so the named-approver
signal stays meaningful.

## Test coverage

- Declared-reason fixture: `examples/hardened_agent/agent.yaml` (`delete_records`),
  scanned end-to-end by the README-documented hardened-agent run (SOVEREIGN 93). No
  dedicated unit test exercises this reason in isolation; its table row is pinned by the
  table-integrity tests below.
- Membership in the canonical ten:
  `tests/test_crosswalk.py::test_all_canonical_reasons_present`.
- Its mappings are fully sourced, ASCII, and asserted/advisory only:
  `tests/test_crosswalk.py::test_every_table_mapping_is_fully_sourced_and_ascii` and
  `tests/test_crosswalk.py::test_table_mappings_are_asserted_or_advisory_only`.
