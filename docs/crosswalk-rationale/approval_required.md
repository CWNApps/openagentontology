# approval_required

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). A mapping is ASSERTED only when the source names this
reason verbatim; the verb heuristic below yields INFERRED at best.

## Definition

The action -- canonically a production change -- requires an approved change request before
it may execute. APPROVAL is a NAMED gate that BLOCKS: the deploy does not happen until the
sign-off artifact exists. This is the core of change control applied to an autonomous
agent.

## Included action types

- Tasks that mutate production systems: deployments, releases, rollouts, reconfigurations,
  provisioning, migrations, publishes to live surfaces.
- Gates that check for an approved change ticket / change request before allowing the
  mutation.
- Heuristic verbs (Layer 2, INFERRED only): `deploy`, `release`, `ship`, `rollout`,
  `reconfigure`, `provision`, `migrate`, `publish`.

## Excluded action types (the boundary)

- `human_review_required` is the neighboring reason and the boundary matters: APPROVAL is a
  named gate that blocks an action until sign-off; REVIEW is asynchronous human inspection
  of an automated adverse outcome about a person. Deploying without a change request is
  approval; denying a claim without human eyes is review.
- A change blocked by a declared blackout window is `change_freeze_active` (when, not
  whether-signed-off).
- A change whose blast radius demands a NAMED accountable approver plus impact analysis is
  `high_blast_needs_named_approver` -- approval_required accepts any valid approval;
  high-blast requires a specific accountable human.
- A financial transaction needing a second authorizer is `dual_control_required`.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | CM-3 | Configuration Change Control | asserted |
| EU AI Act | Art 14 | Human oversight | asserted |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | asserted |

## Advisory MITRE mapping

MITRE ATT&CK T1543 (Create or Modify System Process), advisory: an unapproved production
change maps to system-process modification / persistence. Advisory mappings are informative
and never counted toward coverage or the badge.

## True positive

A billing-platform agent declares `reason: approval_required` on `deploy_config` (apply a
configuration change to the live billing service), resolving ASSERTED to CM-3 / Art 14 /
LLM06. This is exactly the `deploy_config` capability in
`examples/hardened_agent/agent.yaml`; the Rego deny-key form (`reasons contains
"approval_required"`) is the fixture in
`tests/test_ingest.py::test_skips_binary_and_vendored_dirs`.

## False positive

A content agent exposes `publish_blog_post(draft_id)` pushing marketing copy to a CMS. The
verb `publish` fires the heuristic and proposes production change-control for an editorial
workflow that the organization governs with a completely different process. The result is
INFERRED, flagged as a guess in its basis string, and re-declared (or dismissed) on review.

## Test coverage

- Source-named extraction from Rego (`approval_required` deny key in `real.rego`):
  `tests/test_ingest.py::test_skips_binary_and_vendored_dirs`.
- Control anchor pinned (the CM-3 row):
  `tests/test_crosswalk.py::test_canonical_control_anchors_present`.
- Remediation recovers this reason for deploy actions:
  `tests/test_fde.py::test_fde_onboard_improves_tier_and_emits_artifacts`.
