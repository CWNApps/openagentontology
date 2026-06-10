package fixtures.payment_agent

import rego.v1

# FAIL-CLOSED firewall for the payment fixture. Default DENY; the payment executes only
# when dual control holds. The deny key below is the canonical reason the governance
# manifest also declares -- openagentontology reads it AS TEXT (never runs this policy).
default allow := false

allow if {
	input.action == "initiate_payment"
	input.dual_control == true
}

reasons contains "dual_control_required" if not input.dual_control
