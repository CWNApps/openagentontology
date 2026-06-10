"""risk_profile.py -- the v0.2 risk-side scoring split: four honest 0..100 sub-scores.

trust_profile.py answers "how much governance did the scan PROVE?" (tier + score; the badge).
This module answers the complementary buyer question: "how exposed is this agent, and how
much should I trust the scan itself?" The two are deliberately separate -- RiskProfile is
ADDITIVE and the existing TrustProfile axes, weights, and tier bands are untouched, so every
committed scan and badge stays valid.

THE FOUR SUB-SCORES (each an int 0..100, each with a one-line rationale):

  declaration_coverage   of the SIDE-EFFECTING actions (verb-classified as execution /
                         financial / egress / destruction / deployment / identity / mutation),
                         what fraction carry at least one ASSERTED control -- i.e. the source
                         literally declared a canonical reason. Heuristic guesses do not count.
  enforcement_evidence   of the HIGH-RISK actions (severity critical or high), what fraction
                         are wired to a blocking Gate/Policy node by a per-action edge
                         (action -GATED_BY/GOVERNED_BY-> gate, or gate -ENFORCES-> action).
                         Today's ingest adapters hang gates off the Agent root only, so a
                         normal scan honestly scores 0 with the rationale "enforcement linkage
                         not yet measured" -- the score is real the moment a producer emits
                         per-action gate edges. Never faked.
  extraction_confidence  how confident the EXTRACTOR is in its own inventory: a weighted mean
                         over how each action resolved (asserted_table 1.0 / heuristic-inferred
                         0.6 / heuristic-ambiguous 0.3 / none 0.0), with a flat penalty when a
                         dynamic-registration hint (register_tool / tool_install /
                         mcp_tool_register / ...) appears in the extracted labels -- a static
                         parse of such an agent is structurally incomplete.
  risk_exposure          100 minus a severity-weighted penalty for every verb-classified action
                         that lacks a declared (asserted) control: critical 5, high 3,
                         medium 2, low 1. Floor 0. An empty inventory scores 0, not 100 --
                         "we extracted nothing" is unknown exposure, never proof of safety.

HONESTY INVARIANTS (pol.must_do.143): reads ONLY what the crosswalk and ingest already
produced; never re-runs the crosswalk, never invents a control, never auto-asserts. Every
zero carries a rationale line saying WHY it is zero.

Pure function. Imports schema only. No I/O, no network, ASCII rationale.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# -- verb-class table: action label -> (risk_domain, severity) ----------------
# Small on purpose. First match wins; an unmatched label is "unclassified" with
# severity "none" (it accrues no exposure penalty and is not side-effecting).
# Boundary trick mirrors crosswalk._v: '_' is a regex word char, so \b would miss
# the leading verb in snake_case labels like 'exec_payload' / 'wire_transfer'.
def _v(alts: str):
    return re.compile(r"(?<![a-z])(?:" + alts + r")(?![a-z])", re.I)


VERB_CLASSES = (
    ("execution", "critical", _v(r"exec|execute|run|shell|spawn|eval")),
    ("financial", "high", _v(r"pay|payment|wire|transfer|refund|remit|disburse")),
    ("egress", "high", _v(r"send|post|export|upload|transmit|share|forward|email")),
    ("destruction", "high", _v(r"delete|drop|purge|destroy|wipe|erase|truncate")),
    ("deployment", "high", _v(r"deploy|release|rollout|provision|migrate|publish")),
    ("identity", "high", _v(r"impersonate|escalate|elevate|grant|revoke|sudo")),
    ("mutation", "medium", _v(r"write|update|modify|store|persist|commit|insert|create")),
    ("read", "low", _v(r"read|get|list|fetch|query|view")),
)

# Severity -> exposure penalty when the action lacks a declared (asserted) control.
SEVERITY_PENALTY = {"critical": 5, "high": 3, "medium": 2, "low": 1}

# Side-effecting = anything that can change the world; high-risk = the subset a gate
# must answer for first.
_SIDE_EFFECTING = ("critical", "high", "medium")
_HIGH_RISK = ("critical", "high")

# Extractor-resolution weights for extraction_confidence (how each ActionMap resolved).
_RESOLUTION_WEIGHTS = {"asserted": 1.0, "inferred": 0.6, "ambiguous": 0.3, "none": 0.0}

# Dynamic tool registration hints: if the extracted inventory itself names a way to add
# tools at runtime, the static parse is structurally incomplete -- penalize confidence.
_DYNAMIC_HINT = re.compile(
    r"(?:register|install|load|add)_?(?:tool|plugin|extension|skill|server|mcp)"
    r"|(?:tool|plugin|mcp|skill)s?_?(?:register|install)"
    r"|dynamic_?(?:registration|tool)", re.I)
_DYNAMIC_PENALTY = 25

# Edge rels that count as a blocking-gate wire when they land on a Gate/Policy node.
_GATE_RELS = ("GATED_BY", "GOVERNED_BY")
_GATE_NODE_TYPES = ("Gate", "Policy")


@dataclass(frozen=True)
class RiskProfile:
    """The four risk sub-scores (each 0..100) + ASCII rationale lines."""
    declaration_coverage: int
    enforcement_evidence: int
    extraction_confidence: int
    risk_exposure: int
    rationale: tuple = field(default=())

    def to_dict(self) -> dict:
        return {
            "declaration_coverage": self.declaration_coverage,
            "enforcement_evidence": self.enforcement_evidence,
            "extraction_confidence": self.extraction_confidence,
            "risk_exposure": self.risk_exposure,
            "rationale": list(self.rationale),
        }


def classify_action(label: str) -> tuple:
    """(risk_domain, severity) for one action label, from the verb-class table.
    Unmatched -> ('unclassified', 'none'). Deterministic; first class wins."""
    text = label or ""
    for domain, severity, pattern in VERB_CLASSES:
        if pattern.search(text):
            return domain, severity
    return "unclassified", "none"


def _bounded(x) -> int:
    return max(0, min(100, int(round(x))))


def _has_asserted(am) -> bool:
    return any(m.confidence == "asserted" for m in am.mappings)


def _resolution(am) -> str:
    """How one ActionMap resolved, for the extraction-confidence weights."""
    if am.matched_via == "asserted_table":
        return "asserted"
    if am.matched_via == "heuristic":
        if any(m.confidence == "inferred" for m in am.mappings):
            return "inferred"
        return "ambiguous"
    return "none"


def score_risk(doc) -> RiskProfile:
    """Score an OntologyDoc -> RiskProfile. Deterministic: identical docs always yield an
    identical profile (safe to carry inside signed receipt evidence)."""
    by_id = {n.id: n for n in doc.nodes}
    gate_ids = {n.id for n in doc.nodes if n.type in _GATE_NODE_TYPES}
    action_maps = sorted(doc.action_maps, key=lambda a: a.subject_id)
    rationale = []

    # severity per governed action (by subject_id), from the verb-class table.
    severity = {am.subject_id: classify_action(am.label)[1] for am in action_maps}
    side_effecting = [am for am in action_maps if severity[am.subject_id] in _SIDE_EFFECTING]
    high_risk = [am for am in action_maps if severity[am.subject_id] in _HIGH_RISK]

    # -- declaration_coverage --------------------------------------------------
    declared = [am for am in side_effecting if _has_asserted(am)]
    if side_effecting:
        declaration = _bounded(100 * len(declared) / len(side_effecting))
        rationale.append(
            f"declaration_coverage: {len(declared)}/{len(side_effecting)} side-effecting "
            "action(s) declare an asserted control.")
    else:
        declaration = 0
        rationale.append("declaration_coverage: no side-effecting actions detected -- "
                         "nothing declared means nothing proven.")

    # -- enforcement_evidence --------------------------------------------------
    def _gated(nid: str) -> bool:
        for e in doc.edges:
            if e.src == nid and e.rel in _GATE_RELS and e.dst in gate_ids:
                return True
            if e.dst == nid and e.rel == "ENFORCES" and e.src in gate_ids:
                return True
        return False

    def _is_action_node(nid: str) -> bool:
        n = by_id.get(nid)
        return n is not None and n.type not in ("Agent", "Actor") + _GATE_NODE_TYPES

    # linkage is "extractable" only if SOME per-action gate edge exists anywhere in the
    # doc (gates hanging off the Agent root do not count -- they gate nothing specific).
    linkage_present = any(
        (e.rel in _GATE_RELS and e.dst in gate_ids and _is_action_node(e.src))
        or (e.rel == "ENFORCES" and e.src in gate_ids and _is_action_node(e.dst))
        for e in doc.edges)

    if not high_risk:
        enforcement = 0
        rationale.append("enforcement_evidence: no high-risk actions detected.")
    elif not linkage_present:
        enforcement = 0
        rationale.append("enforcement_evidence: enforcement linkage not yet measured -- "
                         "no per-action gate edge in this ontology.")
    else:
        gated = [am for am in high_risk if _gated(am.subject_id)]
        enforcement = _bounded(100 * len(gated) / len(high_risk))
        rationale.append(
            f"enforcement_evidence: {len(gated)}/{len(high_risk)} high-risk action(s) "
            "carry a blocking gate edge.")

    # -- extraction_confidence -------------------------------------------------
    if action_maps:
        weights = [_RESOLUTION_WEIGHTS[_resolution(am)] for am in action_maps]
        confidence = 100 * sum(weights) / len(weights)
        hints = sorted({am.label for am in action_maps if _DYNAMIC_HINT.search(am.label or "")})
        if hints:
            confidence -= _DYNAMIC_PENALTY
            rationale.append(
                "extraction_confidence: dynamic tool-registration hint detected "
                f"({', '.join(hints[:3])}) -- static inventory may be incomplete, "
                f"penalty {_DYNAMIC_PENALTY}.")
        extraction = _bounded(confidence)
        rationale.append(
            f"extraction_confidence: weighted resolution over {len(action_maps)} "
            f"governed action(s) = {extraction}.")
    else:
        extraction = 0
        rationale.append("extraction_confidence: no governed actions extracted.")

    # -- risk_exposure ---------------------------------------------------------
    if action_maps:
        penalized = [am for am in action_maps
                     if severity[am.subject_id] in SEVERITY_PENALTY and not _has_asserted(am)]
        penalty = sum(SEVERITY_PENALTY[severity[am.subject_id]] for am in penalized)
        exposure = _bounded(100 - penalty)
        rationale.append(
            f"risk_exposure: {len(penalized)} action(s) missing a declared control; "
            f"severity-weighted penalty {penalty}.")
    else:
        exposure = 0
        rationale.append("risk_exposure: nothing extracted -- exposure is unknown, "
                         "scored 0 (never assumed safe).")

    return RiskProfile(
        declaration_coverage=declaration,
        enforcement_evidence=enforcement,
        extraction_confidence=extraction,
        risk_exposure=exposure,
        rationale=tuple(rationale),
    )
