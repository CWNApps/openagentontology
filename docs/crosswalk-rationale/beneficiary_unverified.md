# beneficiary_unverified

One of the ten canonical reasons in `ASSERTED_TABLE`
(`openagentontology/crosswalk.py`). Layer-1 only: NO heuristic verb maps to this reason --
counterparty verification status is invisible to a label heuristic, so it must be declared
by the source to appear at all.

## Definition

The agent is about to transact with a counterparty whose identity has not been verified.
The action itself may be in scope and under the value ceiling; the block is about WHO is on
the other end. This is the deny key a payments gate emits when
`input.beneficiary.verified` is false.

## Included action types

- Capabilities that send funds, goods, credentials, or entitlements to an external party:
  payments to a beneficiary account, vendor payouts, payee onboarding shortcuts.
- Gates that check a counterparty verification flag (KYC/KYB-style checks, verified-payee
  registries) before a transfer.

## Excluded action types (the boundary)

- A missing second sign-off on the same payment is `dual_control_required` -- how many
  authorize, not who receives.
- Reaching a system or domain the agent has no authority over is `out_of_scope_domain` --
  the agent's OWN authority, not the counterparty's identity.
- Sending regulated DATA to an unapproved destination is `regulated_egress_blocked` --
  information flow, not funds flow.
- Generic contact hygiene (an unverified email address on a newsletter list) is not a
  regulated counterparty check; do not declare it with this reason.

## Primary controls (from ASSERTED_TABLE)

| Framework | Control | Name | Confidence |
|---|---|---|---|
| NIST SP 800-53r5 | AC-3 | Access Enforcement | asserted |
| EU AI Act | Art 10 | Data and data governance | asserted |
| OWASP LLM Top 10 (2025) | LLM06 | Excessive Agency | asserted |

## Advisory MITRE mapping

MITRE ATT&CK T1078 (Valid Accounts), advisory: acting on behalf of an unverified party is
valid-account abuse. Advisory mappings are informative and never counted toward coverage or
the badge.

## True positive

A finance-ops agent's Rego policy emits `reasons contains "beneficiary_unverified" if not
input.beneficiary.verified`, blocking wires to accounts that have not cleared verification.
The scan extracts the deny key verbatim and the gate resolves ASSERTED to AC-3 / Art 10 /
LLM06. This is exactly `examples/sample_agent/payments.rego`; the declared-gate form
appears as `beneficiary_verification_gate` in `examples/hardened_agent/agent.yaml`.

## False positive

A support agent declares `reason: beneficiary_unverified` on a gate that merely checks
whether a customer's email bounced before sending a satisfaction survey. Layer 1 fires on
the verbatim token and asserts counterparty-transaction controls for a mailing-list
hygiene check. The mapping is sourced but over-scoped -- the GRC review the CONFIRM_NOTE
mandates should re-declare it (or leave the action heuristic-governed).

## Test coverage

- Source-named extraction: `tests/test_ingest.py::test_rego_deny_keys_become_source_named_reasons`
  over the fixture `examples/sample_agent/payments.rego`.
- Only canonical reasons are ever recorded by ingest:
  `tests/test_ingest.py::test_recorded_reasons_are_only_canonical`.
- Membership in the canonical ten:
  `tests/test_crosswalk.py::test_all_canonical_reasons_present`.
