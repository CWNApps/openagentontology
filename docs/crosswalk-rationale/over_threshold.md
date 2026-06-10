# over_threshold

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). Layer-1 only: NO heuristic verb maps to this reason --
a value ceiling is a semantic fact about limits, not something recoverable from an action
label, so it must be declared by the source to appear at all.

## Definition

The transaction's VALUE exceeds the ceiling the agent is authorized to execute. The agent
may hold the capability (paying invoices is its job) but not for this amount; anything above
the limit must escalate instead of auto-executing. This is the deny key a gate emits when
`input.amount > data.limits.max_amount`.

## Included action types

- Capabilities and Decisions carrying a monetary or value-denominated limit: payment
  ceilings, refund caps, trade size limits, credit issuance bounds.
- Gates that compare a transaction amount against a configured maximum.

## Excluded action types (the boundary)

- A missing second authorizer is `dual_control_required` -- threshold limits HOW MUCH one
  grant covers; dual control limits WHO can complete it alone. The same payment gate
  frequently declares both, as `examples/sample_agent/payments.rego` does.
- Rate limits, request quotas, and token budgets are throughput controls, not transaction
  value authority -- do not declare them as `over_threshold`.
- A data-sensitivity ceiling is `classification_above_ceiling` (what may be handled), not a
  value threshold (how much may be transacted).
- A blast-radius limit on a CHANGE is `high_blast_needs_named_approver`.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | AC-3 | Access Enforcement | asserted |
| NIST SP 800-53r5 | AC-6 | Least Privilege | asserted |
| EU AI Act | Art 14 | Human oversight | asserted |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | asserted |

## Advisory MITRE mapping

MITRE ATT&CK T1078 (Valid Accounts), advisory: a transaction-value ceiling bounds
valid-account authority. Advisory mappings are informative and never counted toward
coverage or the badge.

## True positive

A treasury agent's Rego policy emits `reasons contains "over_threshold" if input.amount >
data.limits.max_amount`. The scan extracts the deny key verbatim and the gate resolves
ASSERTED to AC-3 / AC-6 / Art 14 / LLM06. This is exactly
`examples/sample_agent/payments.rego`.

## False positive

An API-client agent declares a guardrail named `over_threshold` for "more than 100 requests
per minute". The token matches the canonical reason exactly, so Layer 1 fires and asserts
transaction-authority controls (AC-3/AC-6) for what is actually a rate limit. The mapping is
sourced (the author literally declared the canonical reason) but semantically wrong -- the
CONFIRM_NOTE discipline ("confirm against the current published control text") exists for
precisely this review.

## Test coverage

- Source-named extraction: `tests/test_ingest.py::test_rego_deny_keys_become_source_named_reasons`
  over the fixture `examples/sample_agent/payments.rego`.
- Control anchors pinned (AC-3 and AC-6 rows):
  `tests/test_crosswalk.py::test_canonical_control_anchors_present`.
- Membership in the canonical ten:
  `tests/test_crosswalk.py::test_all_canonical_reasons_present`.
