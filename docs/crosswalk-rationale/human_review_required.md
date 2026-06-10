# human_review_required

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). A mapping is ASSERTED only when the source names this
reason verbatim; the verb heuristic below yields INFERRED at best.

## Definition

An adverse automated decision affecting a person -- a denial, rejection, termination,
suspension -- requires human inspection before (or as a condition of) taking effect. The
agent may compute the outcome, but a human must review it. This is the oversight reason for
decision points, not for production changes.

## Included action types

- Decisions that issue adverse outcomes about people: deny a claim, reject an application,
  decline credit, suspend an account, terminate a service.
- Gates that route automated adverse outcomes to a human queue.
- Heuristic verbs (Layer 2, INFERRED only): `approve`, `deny`, `reject`, `decline`,
  `cancel`, `adverse`, `terminate`, `suspend`.

## Excluded action types (the boundary)

- `approval_required` is the neighboring reason and the boundary matters: APPROVAL is a
  NAMED gate that BLOCKS an action (canonically a production change) until sign-off exists;
  REVIEW is asynchronous human inspection of an automated outcome. Deploying without an
  approved change request is `approval_required`; denying an insurance claim with no human
  in the loop is `human_review_required`.
- A financial transaction missing a second authorizer is `dual_control_required`.
- A destructive change during a freeze window is `change_freeze_active`.
- A wide-blast change needing an accountable owner is `high_blast_needs_named_approver`.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| EU AI Act | Art 14 | Human oversight | asserted |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | asserted |
| NIST AI RMF | MEASURE | Measure function | advisory |

## Advisory MITRE mapping

MITRE ATT&CK T1059 (Command and Scripting Interpreter), advisory: autonomous execution
without oversight maps to command/scripting abuse. Advisory mappings are informative and
never counted toward coverage or the badge.

## True positive

A claims-processing agent exposes `deny_claim(claim_id)` and its agent definition declares
`reason: human_review_required` on the allow-or-escalate decision (the shape of
`examples/hardened_agent/agent.yaml`, decision `allow_or_escalate`). The decision resolves
ASSERTED to Art 14 / LLM06. Without the declaration, the bare verb `deny` still surfaces
the action as INFERRED so the gap is visible -- the PR gate even flags a NEW ungoverned
`deny_claim` as an Article 14 gap.

## False positive

A subscription agent exposes `cancel_subscription(user_id)` that runs only when the user
themselves asks to cancel. The verb `cancel` fires the heuristic and proposes oversight
controls for an action that is the user's own intent, not an adverse automated decision.
The result is INFERRED, labeled as a guess in its basis string, and a reviewer drops it.

## Test coverage

- Control anchor pinned (the Art 14 row):
  `tests/test_crosswalk.py::test_canonical_control_anchors_present`.
- Heuristic probe (`deny_claim`, never fabricates and never asserts):
  `tests/test_crosswalk.py::test_map_action_never_fabricates_a_framework_id`.
- Oversight-gap behavior in CI (a new ungoverned `deny_claim` fails the PR):
  `tests/test_ci_check.py::test_new_ungoverned_oversight_action_is_an_art14_gap`, and the
  no-false-gap counterpart `tests/test_ci_check.py::test_inferred_oversight_is_not_a_gap`.
