package sample.agent_firewall.payments

import rego.v1

# FAIL-CLOSED firewall for the sample finance-ops agent's payment action.
# Default DENY: no input means no action. The wire / payment / refund action
# executes ONLY when every guardrail holds. openagentontology reads the
# `reasons contains "<key>"` deny keys below AS TEXT (never runs this policy)
# and treats each key as an EXTRACTED governance reason, which the crosswalk
# maps 1:1 to its asserted NIST 800-53 / EU AI Act / OWASP LLM controls.
default allow := false

allow if {
	valid_action
	input.dual_control == true
	input.amount <= data.limits.max_amount
	input.beneficiary.verified == true
}

valid_action if input.action in {"wire_transfer", "payment", "refund"}

decision := {
	"allow": allow,
	"policy": "sample.agent_firewall.payments/v1",
	"agent": input.agent_id,
	"action": input.action,
	"amount": input.amount,
	"reasons": reasons,
}

# These deny keys are the canonical reasons. Each maps to an asserted control
# in the openagentontology crosswalk ASSERTED_TABLE:
#   dual_control_required  -> NIST 800-53 AC-5  / EU AI Act Art 14 / OWASP LLM06
#   over_threshold         -> NIST 800-53 AC-3, AC-6 / EU AI Act Art 14
#   beneficiary_unverified -> NIST 800-53 AC-3  / EU AI Act Art 10 / OWASP LLM06
reasons contains "dual_control_required" if not input.dual_control
reasons contains "over_threshold" if input.amount > data.limits.max_amount
reasons contains "beneficiary_unverified" if not input.beneficiary.verified
