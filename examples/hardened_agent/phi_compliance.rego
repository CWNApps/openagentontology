# PHI Compliance Firewall — fail-closed OPA policy for healthcare agent.
#
# Every deny reason uses a CANONICAL name from the OpenAgentOntology ASSERTED_TABLE
# so the crosswalk produces ASSERTED (not INFERRED) mappings. This is why
# hardened_agent scores 75+ while sample_agent scores 41.
package healthcare.phi_compliance

import future.keywords.in
import future.keywords.contains

default allow := false

allow if {
    valid_action
    not any_deny
}

deny_reasons contains "dual_control_required" if {
    input.action == "process_claim"
    input.amount > 10000
    not input.dual_approver
}

deny_reasons contains "over_threshold" if {
    input.action in {"process_claim", "wire_transfer"}
    input.amount > input.threshold_limit
}

deny_reasons contains "beneficiary_unverified" if {
    input.action in {"process_claim", "wire_transfer"}
    not input.beneficiary.verified
}

deny_reasons contains "human_review_required" if {
    input.action in {"delete_records", "deploy"}
    not input.human_reviewer_id
}

deny_reasons contains "classification_above_ceiling" if {
    input.data_classification in {"PHI", "PII", "RESTRICTED"}
    input.destination_clearance < input.data_classification_level
}

deny_reasons contains "regulated_egress_blocked" if {
    input.action == "export_records"
    not input.destination in data.approved_destinations
}

deny_reasons contains "approval_required" if {
    input.action == "deploy"
    not input.change_ticket_approved
}

deny_reasons contains "high_blast_needs_named_approver" if {
    input.action == "delete_records"
    input.record_count > 1000
    not input.named_approver
}

any_deny if {
    count(deny_reasons) > 0
}

valid_action if {
    input.action in {"export_records", "process_claim", "deploy", "delete_records"}
}
