# AgentFDE governance firewall — fail closed.
#
# Every consequential FDE action is denied unless the named canonical condition holds. Each
# deny key is a canonical reason in the Agent Ontology crosswalk, so OpenAgentOntology maps it
# to ASSERTED controls (NIST 800-53 / EU AI Act / OWASP LLM Top 10). This file is read as TEXT
# by the scanner — never evaluated.
package cwn.agent_fde

default allow := false

allow if {
	not deny[_]
}

# No single FDE both authors and certifies a remediation (separation of duties).
deny contains "dual_control_required" if {
	input.action == "certify"
	input.actor == input.author
}

# A generated gate is a production change -> requires an approved change request.
deny contains "approval_required" if {
	input.action == "apply_remediation"
	not input.change_request_approved
}

# Honor the customer's change freeze.
deny contains "change_freeze_active" if {
	input.action == "apply_remediation"
	input.change_freeze
}

# Publishing a receipt to the ledger is regulated egress -> controlled endpoint only.
deny contains "regulated_egress_blocked" if {
	input.action == "register_receipt"
	not input.endpoint_in_allowlist
}

# Stay inside the signed engagement scope.
deny contains "out_of_scope_domain" if {
	not input.target in input.engagement_scope
}

# A high blast-radius rollout requires a named, accountable approver.
deny contains "high_blast_needs_named_approver" if {
	input.action == "rollout_org_policy"
	not input.named_approver
}

# Refuse to scan data above the FDE's clearance ceiling.
deny contains "classification_above_ceiling" if {
	input.data_classification > input.fde_clearance
}

# Changes above the blast threshold escalate to a human.
deny contains "over_threshold" if {
	input.blast_radius > input.threshold
}

# An adverse certification decision requires human review before it is issued.
deny contains "human_review_required" if {
	input.action == "certify"
	input.verdict == "fail"
}
