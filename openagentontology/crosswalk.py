"""crosswalk.py — the two-layer, fabrication-safe framework crosswalk.

LAYER 1 — ASSERTED_TABLE: the canonical reason-to-control map transcribed 1:1 (the value,
copied not reinvented). The 10 canonical OPA reasons, each with its full sourced control
list preserving fw + id + name + basis + confidence EXACTLY. When ingest detects an
EXPLICIT, source-named reason (a Rego deny key, a speckit guardrail, an eval expected
reason), map_action() returns these mappings at provenance=EXTRACTED with the confidence
words ('asserted'/'advisory') untouched.

LAYER 2 — HEURISTICS: when an action has NO source-named reason, map_action() runs the
action label through an ordered list of (regex, canonical_reason, downgrade). A strong
single-domain verb yields the matching reason's controls DOWNGRADED to confidence=inferred
/ provenance=INFERRED (basis rewritten to flag the inference). A weak / overloaded /
side-effecting verb with no clean domain yields confidence=ambiguous / provenance=AMBIGUOUS
— at most a single OWASP LLM06 'excessive agency' stub, never a specific 800-53 id.

HARD INVARIANTS (pol.must_do.143):
  1. map_action NEVER constructs a framework-id string. It only re-emits ids that already
     live in ASSERTED_TABLE. There is no code path that fabricates 'AC-99'.
  2. Every emitted Mapping carries fw + id + name + basis + confidence + provenance.
  3. ASSERTED ('asserted'/'advisory') is reserved for Layer-1 source-named matches.
     Everything auto-detected is 'inferred' or 'ambiguous'.
  4. A mapping whose fw is outside ALLOWED_FRAMEWORKS is rejected downstream by validate.py.
  5. CONFIRM_NOTE is the CWN's canonical control map string verbatim.

Pure data + map_action() + compact_refs(). Zero I/O, zero network. ASCII-only.
"""
from __future__ import annotations

import re

from .schema import ActionMap, Mapping

# Verbatim from the canonical confirm-note.
CONFIRM_NOTE = ("Proposed CWN mappings, confidence-tagged. Confirm against the current "
                "published control text before relying on them for audit. Enterprise "
                "control ids are mapped at onboarding by your GRC team, never auto-asserted.")

# Fabrication guard. A Mapping.fw outside this set fails validate.py closed.
ALLOWED_FRAMEWORKS = (
    "NIST SP 800-53r5",
    "EU AI Act",
    "OWASP LLM Top 10 (2025)",
    "NIST AI RMF",
    "MITRE ATT&CK",
    "OCSF",
    "NICE",
)

# Short labels for citable receipt refs (e.g. "NIST 800-53 AC-5"). From the canonical short-labels.
_SHORT = {
    "NIST SP 800-53r5": "NIST 800-53",
    "EU AI Act": "EU AI Act",
    "OWASP LLM Top 10 (2025)": "OWASP",
    "NIST AI RMF": "NIST AI RMF",
    "MITRE ATT&CK": "MITRE",
    "OCSF": "OCSF",
    "NICE": "NICE",
}


def _m(fw, cid, name, basis, confidence, provenance="EXTRACTED"):
    return Mapping(fw=fw, id=cid, name=name, basis=basis,
                   confidence=confidence, provenance=provenance)


# ── LAYER 1: ASSERTED_TABLE — the canonical reason-to-control map, 1:1 ────────
# Keyed by the exact canonical reason string. The basis text is copied verbatim:
# DO NOT paraphrase — it lands inside signed evidence.
ASSERTED_TABLE = {
    "dual_control_required": [
        _m("NIST SP 800-53r5", "AC-5", "Separation of Duties",
           "Dual control is the textbook separation-of-duties control: no single actor (here, one agent) completes a sensitive transaction alone.", "asserted"),
        _m("EU AI Act", "Art 14", "Human oversight",
           "A high-value financial action by an automated system requires effective human oversight before it takes effect.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
           "An agent moving money without a second authorizer is the canonical excessive-agency failure.", "asserted"),
        _m("NIST AI RMF", "MANAGE", "Manage function",
           "Risk treatment: enforce a control commensurate with transaction risk.", "advisory"),
    ],
    "over_threshold": [
        _m("NIST SP 800-53r5", "AC-3", "Access Enforcement",
           "A transaction-value ceiling is an access-enforcement rule on what the agent is permitted to execute.", "asserted"),
        _m("NIST SP 800-53r5", "AC-6", "Least Privilege",
           "The agent is granted only the transaction authority it needs; amounts above the limit exceed that grant.", "asserted"),
        _m("EU AI Act", "Art 14", "Human oversight",
           "Above-threshold value should escalate to a human rather than auto-execute.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
           "Unbounded transaction authority is excessive agency.", "asserted"),
    ],
    "beneficiary_unverified": [
        _m("NIST SP 800-53r5", "AC-3", "Access Enforcement",
           "Paying only verified beneficiaries enforces who the agent may transact with.", "asserted"),
        _m("EU AI Act", "Art 10", "Data and data governance",
           "Acting on unverified counterparty data is a data-governance failure.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
           "Sending funds to an unverified party is acting beyond safe authority.", "asserted"),
    ],
    "human_review_required": [
        _m("EU AI Act", "Art 14", "Human oversight",
           "An adverse automated decision affecting a person requires human oversight before it is issued.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
           "Issuing an adverse decision with no human in the loop is excessive agency.", "asserted"),
        _m("NIST AI RMF", "MEASURE", "Measure function",
           "Adverse outcomes are a measured risk requiring a treatment (human review).", "advisory"),
    ],
    "classification_above_ceiling": [
        _m("NIST SP 800-53r5", "RA-2", "Security Categorization",
           "Refusing to handle data above a classification ceiling enforces the categorization of the resource.", "asserted"),
        _m("NIST SP 800-53r5", "AC-4", "Information Flow Enforcement",
           "The ceiling governs the flow of classified information through the agent.", "asserted"),
        _m("EU AI Act", "Art 10", "Data and data governance",
           "Handling over-classified data is a data-governance violation.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM02", "Sensitive Information Disclosure",
           "Processing restricted data above ceiling risks sensitive-information disclosure.", "asserted"),
    ],
    "out_of_scope_domain": [
        _m("NIST SP 800-53r5", "AC-6", "Least Privilege",
           "Restricting the agent to in-scope resources is least privilege.", "asserted"),
        _m("NIST SP 800-53r5", "AC-3", "Access Enforcement",
           "Scope is enforced at access time.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
           "Reaching outside authorized scope is excessive agency.", "asserted"),
    ],
    "regulated_egress_blocked": [
        _m("NIST SP 800-53r5", "AC-4", "Information Flow Enforcement",
           "Blocking export to an out-of-scope endpoint is information-flow enforcement.", "asserted"),
        _m("NIST SP 800-53r5", "SC-7", "Boundary Protection",
           "Preventing data leaving the controlled boundary is boundary protection.", "asserted"),
        _m("EU AI Act", "Art 10", "Data and data governance",
           "Uncontrolled egress of regulated data is a data-governance failure.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM02", "Sensitive Information Disclosure",
           "Egress of regulated records is sensitive-information disclosure.", "asserted"),
        _m("MITRE ATT&CK", "TA0010", "Exfiltration",
           "Data leaving to an external domain maps to the Exfiltration tactic; confirm the specific technique with an analyst.", "advisory"),
    ],
    "change_freeze_active": [
        _m("NIST SP 800-53r5", "CM-3", "Configuration Change Control",
           "Honoring a change freeze is configuration change control.", "asserted"),
        _m("NIST SP 800-53r5", "CM-5", "Access Restrictions for Change",
           "A freeze restricts who/when changes may be applied.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
           "Deploying during a freeze is acting beyond authority.", "asserted"),
    ],
    "approval_required": [
        _m("NIST SP 800-53r5", "CM-3", "Configuration Change Control",
           "Requiring an approved change request is the core of change control.", "asserted"),
        _m("EU AI Act", "Art 14", "Human oversight",
           "An unapproved production change by an agent needs human sign-off.", "asserted"),
        _m("OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
           "Deploying without approval is excessive agency.", "asserted"),
    ],
    "high_blast_needs_named_approver": [
        _m("NIST SP 800-53r5", "CM-4", "Impact Analyses",
           "A high blast-radius change requires an impact analysis and an accountable approver.", "asserted"),
        _m("NIST SP 800-53r5", "AC-5", "Separation of Duties",
           "A named approver distinct from the actor is separation of duties.", "asserted"),
        _m("EU AI Act", "Art 14", "Human oversight",
           "High-impact automated changes require a named human owner.", "asserted"),
    ],
}

# ── MITRE ATT&CK technique enrichment (advisory) ─────────────────────────────
# Each canonical reason carries the adversary TECHNIQUE it mitigates -- the language every SOC
# already speaks -- sourced from CWN's NICE x MITRE control crosswalk (T1078/T1059/T1048/
# T1543 are graph-confirmed agent-relevant techniques). Advisory confidence: informative, never
# counted toward coverage/rigor/breadth, so the badge is never inflated (pol.must_do.143).
_MITRE_ATTACK = {
    "dual_control_required": _m("MITRE ATT&CK", "T1078", "Valid Accounts",
        "separation of duties mitigates valid-account / privilege abuse", "advisory"),
    "over_threshold": _m("MITRE ATT&CK", "T1078", "Valid Accounts",
        "a transaction-value ceiling bounds valid-account authority", "advisory"),
    "beneficiary_unverified": _m("MITRE ATT&CK", "T1078", "Valid Accounts",
        "acting on behalf of an unverified party is valid-account abuse", "advisory"),
    "human_review_required": _m("MITRE ATT&CK", "T1059", "Command and Scripting Interpreter",
        "autonomous execution without oversight maps to command/scripting abuse", "advisory"),
    "classification_above_ceiling": _m("MITRE ATT&CK", "T1530", "Data from Cloud Storage",
        "handling data above a classification ceiling maps to sensitive-data access", "advisory"),
    "out_of_scope_domain": _m("MITRE ATT&CK", "T1098", "Account Manipulation",
        "reaching outside authorized scope maps to account/privilege manipulation", "advisory"),
    "regulated_egress_blocked": _m("MITRE ATT&CK", "T1048", "Exfiltration Over Alternative Protocol",
        "uncontrolled egress of regulated data maps to exfiltration", "advisory"),
    "change_freeze_active": _m("MITRE ATT&CK", "T1485", "Data Destruction",
        "a destructive change during a freeze maps to data destruction", "advisory"),
    "approval_required": _m("MITRE ATT&CK", "T1543", "Create or Modify System Process",
        "an unapproved production change maps to system-process modification / persistence", "advisory"),
    "high_blast_needs_named_approver": _m("MITRE ATT&CK", "T1490", "Inhibit System Recovery",
        "a high blast-radius destructive change maps to inhibit-system-recovery", "advisory"),
}
for _r, _mit in _MITRE_ATTACK.items():
    ASSERTED_TABLE[_r] = ASSERTED_TABLE[_r] + [_mit]


# The single OWASP LLM06 stub a weak/overloaded side-effecting verb resolves to. The basis
# is explicit that it is a heuristic, so the buyer never mistakes it for an asserted control.
_AMBIGUOUS_STUB = _m(
    "OWASP LLM Top 10 (2025)", "LLM06", "Excessive Agency",
    "heuristic: side-effecting action with no second authorizer detected -- confirm against published text",
    "ambiguous", "AMBIGUOUS")


def _downgrade(reason: str, verb: str) -> tuple:
    """Take a Layer-1 reason's asserted controls and DOWNGRADE them to an inferred mapping
    for a strong heuristic verb hit. Re-emits only ids already in ASSERTED_TABLE (invariant
    1). The basis is rewritten to make the inference explicit (invariant 2 + honesty)."""
    out = []
    for m in ASSERTED_TABLE[reason]:
        if m.confidence == "asserted":
            out.append(Mapping(
                fw=m.fw, id=m.id, name=m.name,
                basis=f"inferred from action verb '{verb}'; confirm against published text "
                      f"(asserted basis: {m.basis})",
                confidence="inferred", provenance="INFERRED"))
        elif m.confidence == "advisory":
            out.append(m)  # advisory (e.g. MITRE ATT&CK technique) rides along, still advisory
    return tuple(out)


# ── LAYER 2: HEURISTICS — ordered (regex, canonical_reason, strength) ────────
# strength='strong' -> INFERRED downgrade of the reason's asserted controls.
# strength='weak'   -> AMBIGUOUS single LLM06 stub (overloaded / side-effecting verb).
# First match wins. ASCII regexes only.
#
# Boundary note: we deliberately do NOT use \b — '_' is a regex word char, so \b would
# miss the leading verb in snake_case labels like 'export_records' / 'wire_transfer' /
# 'deny_claim'. _v() wraps each alternation in a non-letter boundary so a verb matches
# whether it is space- or underscore- or camelCase-delimited.
def _v(alts: str):
    return re.compile(r"(?<![a-z])(?:" + alts + r")(?![a-z])", re.I)


HEURISTICS = [
    (_v(r"pay|payment|wire|transfer|remit|invoice|disburse|refund"),
     "dual_control_required", "strong"),
    (_v(r"export|egress|exfil|exfiltrate|upload|send|forward|transmit|share|leak"),
     "regulated_egress_blocked", "strong"),
    (_v(r"pii|ssn|secret|credential|password|classif|classify|confidential|restricted|redact"),
     "classification_above_ceiling", "strong"),
    (_v(r"delete|drop|purge|wipe|destroy|truncate|erase"),
     "change_freeze_active", "strong"),
    (_v(r"deploy|release|ship|rollout|reconfigure|provision|migrate|publish"),
     "approval_required", "strong"),
    (_v(r"approve|deny|reject|decline|cancel|adverse|terminate|suspend"),
     "human_review_required", "strong"),
    (_v(r"scope|domain|admin|privilege|elevate|escalate|impersonate|root|sudo"),
     "out_of_scope_domain", "strong"),
    # weak / overloaded / side-effecting verbs -> ambiguous stub only
    (_v(r"process|update|run|execute|modify|change|write|persist|store|act|submit|commit"),
     None, "weak"),
]


def map_action(label: str, source_reason: str | None = None) -> ActionMap:
    """Resolve one capability / decision / gate label to framework controls.

    1) source_reason in ASSERTED_TABLE -> the asserted mappings, provenance EXTRACTED,
       confidence as-is. matched_via='asserted_table'.
    2) else first HEURISTICS regex hit on label -> INFERRED (strong verb) or
       AMBIGUOUS (weak/overloaded verb). matched_via='heuristic'.
    3) else -> empty mapping, matched_via='none'.

    NEVER invents a framework id — only re-emits ids present in ASSERTED_TABLE.
    """
    sid = (label or "").strip()
    # Layer 1: an explicit, source-named reason.
    if source_reason and source_reason in ASSERTED_TABLE:
        return ActionMap(subject_id=sid, label=sid,
                         mappings=tuple(ASSERTED_TABLE[source_reason]),
                         matched_via="asserted_table")
    # Layer 2: heuristic over the action label.
    text = sid
    for pattern, reason, strength in HEURISTICS:
        mobj = pattern.search(text)
        if not mobj:
            continue
        verb = mobj.group(0).lower()
        if strength == "strong" and reason:
            return ActionMap(subject_id=sid, label=sid,
                             mappings=_downgrade(reason, verb),
                             matched_via="heuristic")
        # weak -> ambiguous stub
        return ActionMap(subject_id=sid, label=sid,
                         mappings=(_AMBIGUOUS_STUB,), matched_via="heuristic")
    # No match -> ungoverned action (validate.py emits a WARN).
    return ActionMap(subject_id=sid, label=sid, mappings=(), matched_via="none")


def compact_refs(action_map: ActionMap, asserted_only: bool = True, limit: int = 3) -> list:
    """Citable, ASCII, receipt-safe refs for one ActionMap, e.g. ['NIST 800-53 AC-5', ...].
    Mirrors the canonical compact-refs short-label logic. asserted_only keeps the
    badge honest by default (only well-established controls become chips)."""
    out = []
    for m in action_map.mappings:
        if asserted_only and m.confidence != "asserted":
            continue
        token = f"{_SHORT.get(m.fw, m.fw)} {m.id}"
        if token not in out:
            out.append(token)
        if len(out) >= limit:
            break
    return out
