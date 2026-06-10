# dual_control_required

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). A mapping is ASSERTED only when the source names this
reason verbatim; the verb heuristic below yields INFERRED at best.

## Definition

A sensitive transaction -- canonically the movement of funds -- must be completed by two
independent actors: the agent that initiates and a second authorizer that confirms. No
single actor (here, one agent) finishes the action alone. This is the deny key a payments
gate emits when the second authorization is missing.

## Included action types

- Capabilities and Tasks that move money or value: wire transfers, payments, refunds,
  disbursements, remittances, invoice payouts.
- Decisions that commit a financial transaction on behalf of the organization.
- Heuristic verbs (Layer 2, INFERRED only): `pay`, `payment`, `wire`, `transfer`, `remit`,
  `invoice`, `disburse`, `refund`.

## Excluded action types (the boundary)

- A transaction blocked because the AMOUNT exceeds a ceiling is `over_threshold`, not dual
  control -- the cure there is escalation above a limit, not a second signature. One action
  can legitimately declare both.
- A production change needing a sign-off is `approval_required` (change control), not dual
  control (transaction control).
- Paying an unverified counterparty is `beneficiary_unverified` -- WHO is paid, not HOW MANY
  authorize.
- An adverse automated decision about a person needing human eyes is
  `human_review_required`.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | AC-5 | Separation of Duties | asserted |
| EU AI Act | Art 14 | Human oversight | asserted |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | asserted |
| NIST AI RMF | MANAGE | Manage function | advisory |

## Advisory MITRE mapping

MITRE ATT&CK T1078 (Valid Accounts), advisory: separation of duties mitigates
valid-account / privilege abuse. Advisory mappings are informative and never counted
toward coverage or the badge.

## True positive

An autonomous finance-ops agent exposes `wire_transfer(amount, beneficiary)` behind an OPA
gate whose policy emits `reasons contains "dual_control_required" if not
input.dual_control`. The scan extracts the deny key verbatim and the action resolves
ASSERTED to AC-5 / Art 14 / LLM06. This is exactly
`examples/sample_agent/payments.rego`.

## False positive

A ticketing agent exposes `transfer_ownership(ticket_id, assignee)`. The verb `transfer`
fires the payments heuristic even though no funds move. The crosswalk handles this honestly
rather than perfectly: the result is INFERRED (never asserted), the basis string says
"inferred from action verb 'transfer'; confirm against published text", and a reviewer
discards the mapping. This is why heuristics can never assert.

## Test coverage

- Source-named extraction: `tests/test_ingest.py::test_rego_deny_keys_become_source_named_reasons`
  over the fixture `examples/sample_agent/payments.rego`.
- Asserted resolution is byte-identical to the table:
  `tests/test_crosswalk.py::test_source_named_reason_yields_asserted_extracted`.
- End-to-end (the AC-5 chip reaches the badge):
  `tests/test_pipeline.py::test_e2e_finds_the_source_named_asserted_controls`.
