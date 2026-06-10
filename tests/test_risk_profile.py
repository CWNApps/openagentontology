"""test_risk_profile.py -- the v0.2 risk-side scoring split.

score_risk(doc) must produce four honest, bounded, deterministic sub-scores that read ONLY
what the crosswalk and ingest already established: declared(asserted) coverage of the
side-effecting surface, per-action gate enforcement evidence (honestly 0 with a rationale
until producers emit per-action gate edges), extractor self-confidence with the
dynamic-registration penalty, and severity-weighted exposure. The existing TrustProfile
axes/weights/tier bands MUST NOT move -- committed scans and the paper depend on them.

Also pins the governed skill catalog (schema/skills-v0.2.0.yaml): it parses, and every
required_control is one of the 10 canonical reasons -- never an invented control.
"""
from __future__ import annotations

import json
import re

import pytest
import yaml

import openagentontology
from openagentontology import trust_profile
from openagentontology.crosswalk import ASSERTED_TABLE, map_action
from openagentontology.risk_profile import (
    RiskProfile,
    SEVERITY_PENALTY,
    classify_action,
    score_risk,
)
from openagentontology.schema import ActionMap, Edge, Node, OntologyDoc


# -- helpers: synthetic docs built from the real schema + real crosswalk -------
def _governed_doc(cap_specs, edges=()):
    """A small OntologyDoc: an Agent root + one Capability per (id, action, reason) spec,
    crosswalked with the REAL map_action (never hand-faked mappings)."""
    nodes = [Node(id="agent_t", type="Agent", name="t-agent")]
    action_maps = []
    for nid, action, reason in cap_specs:
        nodes.append(Node(id=nid, type="Capability", name=action, props={"action": action}))
        am = map_action(action, reason)
        action_maps.append(ActionMap(subject_id=nid, label=am.label,
                                     mappings=am.mappings, matched_via=am.matched_via))
    return OntologyDoc(source="synthetic", source_kind="test",
                       nodes=nodes, edges=list(edges), action_maps=action_maps)


@pytest.fixture(scope="module")
def sample_result(repo_root):
    return openagentontology.run_pipeline(
        str(repo_root / "examples" / "sample_agent"), make_receipt=False)


# -- bounds + wiring -----------------------------------------------------------
def test_sample_subscores_are_bounded_ints(sample_result):
    rp = sample_result.risk_profile
    assert isinstance(rp, RiskProfile)
    for k, v in rp.to_dict().items():
        if k == "rationale":
            continue
        assert isinstance(v, int), f"{k} is not an int"
        assert 0 <= v <= 100, f"{k}={v} out of 0..100"


def test_pipeline_result_carries_risk_profile_ascii(sample_result):
    d = sample_result.to_dict()
    assert "risk_profile" in d and d["risk_profile"], "risk_profile missing from to_dict"
    # everything stays receipt-safe ASCII
    json.dumps(d["risk_profile"], ensure_ascii=False).encode("ascii")
    assert d["risk_profile"]["rationale"], "every sub-score must explain itself"


def test_trust_profile_contract_unchanged(sample_result):
    # the committed scans + paper depend on these exact axes, weights, and tier floors.
    assert trust_profile._WEIGHTS == {
        "coverage": 0.45, "rigor": 0.25, "breadth": 0.15, "structure": 0.15}
    assert trust_profile._BANDS == (
        ("SOVEREIGN", 90), ("HARDENED", 75), ("DEVELOPING", 50), ("UNGOVERNED", 0))
    assert set(sample_result.profile.subscores) == {
        "coverage", "rigor", "breadth", "structure"}


# -- enforcement_evidence: honest zero today, real the moment edges exist ------
def test_sample_enforcement_is_honest_zero(sample_result):
    # today's adapters hang gates off the Agent root only -> no per-action linkage.
    rp = sample_result.risk_profile
    assert rp.enforcement_evidence == 0
    assert any("enforcement linkage not yet measured" in line for line in rp.rationale)


def test_enforcement_measured_when_per_action_gate_edge_exists():
    nodes = [
        Node(id="agent_t", type="Agent", name="t-agent"),
        Node(id="cap_wire", type="Capability", name="wire transfer",
             props={"action": "wire_transfer"}),
        Node(id="gate_dc", type="Gate", name="dual control",
             props={"action": "dual_control_required"}),
    ]
    am = map_action("wire_transfer", "dual_control_required")
    doc = OntologyDoc(
        source="synthetic", source_kind="test", nodes=nodes,
        edges=[Edge(src="agent_t", rel="HAS_CAPABILITY", dst="cap_wire"),
               Edge(src="cap_wire", rel="GATED_BY", dst="gate_dc")],
        action_maps=[ActionMap("cap_wire", am.label, am.mappings, am.matched_via)])
    rp = score_risk(doc)
    assert rp.enforcement_evidence == 100
    assert any("1/1 high-risk" in line for line in rp.rationale)


def test_agent_root_gate_edge_does_not_count_as_enforcement():
    # the synthesized Agent-root GATED_BY edge gates nothing specific.
    nodes = [
        Node(id="agent_t", type="Agent", name="t-agent"),
        Node(id="cap_wire", type="Capability", name="wire transfer",
             props={"action": "wire_transfer"}),
        Node(id="gate_dc", type="Gate", name="dual control",
             props={"action": "dual_control_required"}),
    ]
    am = map_action("wire_transfer", None)
    doc = OntologyDoc(
        source="synthetic", source_kind="test", nodes=nodes,
        edges=[Edge(src="agent_t", rel="GATED_BY", dst="gate_dc")],
        action_maps=[ActionMap("cap_wire", am.label, am.mappings, am.matched_via)])
    rp = score_risk(doc)
    assert rp.enforcement_evidence == 0
    assert any("not yet measured" in line for line in rp.rationale)


# -- declaration_coverage: asserted only, heuristics never count ---------------
def test_declaration_full_when_source_declares_canonical_reason():
    doc = _governed_doc([("cap_wire", "wire_transfer", "dual_control_required")])
    rp = score_risk(doc)
    assert rp.declaration_coverage == 100


def test_declaration_zero_when_heuristic_only():
    # the same side-effecting action with NO source-named reason: inferred != declared.
    doc = _governed_doc([("cap_wire", "wire_transfer", None)])
    rp = score_risk(doc)
    assert rp.declaration_coverage == 0


# -- extraction_confidence: dynamic-registration hint penalizes honestly -------
def test_dynamic_registration_hint_penalizes_extraction():
    base = _governed_doc([("cap_wire", "wire_transfer", "dual_control_required")])
    hinted = _governed_doc([
        ("cap_wire", "wire_transfer", "dual_control_required"),
        ("cap_reg", "mcp_tool_register", "approval_required"),
    ])
    clean, dirty = score_risk(base), score_risk(hinted)
    assert dirty.extraction_confidence < clean.extraction_confidence
    assert any("dynamic" in line for line in dirty.rationale)


# -- risk_exposure: severity-weighted, floored at 0, never assumed safe --------
def test_exposure_floors_at_zero_under_many_ungoverned_criticals():
    specs = [(f"cap_x{i:02d}", f"exec_payload_{i:02d}", None) for i in range(25)]
    rp = score_risk(_governed_doc(specs))
    # 25 ungoverned critical actions x penalty 5 = 125 -> floored
    assert rp.risk_exposure == 0
    assert rp.declaration_coverage == 0


def test_exposure_penalty_weights_match_severity_table():
    assert SEVERITY_PENALTY == {"critical": 5, "high": 3, "medium": 2, "low": 1}
    assert classify_action("exec_payload") == ("execution", "critical")
    assert classify_action("export_records") == ("egress", "high")
    assert classify_action("delete_dataset") == ("destruction", "high")
    assert classify_action("write_config") == ("mutation", "medium")
    assert classify_action("read_status") == ("read", "low")
    assert classify_action("dual_control_required") == ("unclassified", "none")


def test_empty_doc_scores_zero_everywhere():
    rp = score_risk(OntologyDoc(source="empty", source_kind="test"))
    d = rp.to_dict()
    assert d["declaration_coverage"] == 0
    assert d["enforcement_evidence"] == 0
    assert d["extraction_confidence"] == 0
    assert d["risk_exposure"] == 0, "nothing extracted must never read as safe"
    assert d["rationale"]


# -- determinism ---------------------------------------------------------------
def test_score_risk_is_deterministic(repo_root):
    p = str(repo_root / "examples" / "sample_agent")
    r1 = openagentontology.run_pipeline(p, make_receipt=False)
    r2 = openagentontology.run_pipeline(p, make_receipt=False)
    assert r1.risk_profile.to_dict() == r2.risk_profile.to_dict()
    assert score_risk(r1.ontology).to_dict() == score_risk(r1.ontology).to_dict()


# -- the governed skill catalog (schema/skills-v0.2.0.yaml) --------------------
@pytest.fixture(scope="module")
def skills_catalog(repo_root):
    fp = repo_root / "schema" / "skills-v0.2.0.yaml"
    assert fp.is_file(), f"missing skills catalog: {fp}"
    return yaml.safe_load(fp.read_text(encoding="ascii"))


def test_skills_catalog_parses_with_expected_shape(skills_catalog):
    assert skills_catalog["catalog"] == "openagentontology-governed-skills"
    assert skills_catalog["version"] == "0.2.0"
    skills = skills_catalog["skills"]
    assert len(skills) == 20
    ids = [s["skill_id"] for s in skills]
    assert len(ids) == len(set(ids)), "duplicate skill_id"
    for s in skills:
        assert re.fullmatch(r"oao\.skill\.[a-z_]+", s["skill_id"]), s["skill_id"]
        assert s["name"] and s["risk_domain"]
        assert s["default_severity"] in skills_catalog["severity_levels"]
        assert s["action_effect"]
        assert isinstance(s["required_evidence"], list) and s["required_evidence"]


def test_skills_catalog_controls_are_the_ten_canonical_reasons(skills_catalog):
    canonical = set(ASSERTED_TABLE)
    assert set(skills_catalog["canonical_reasons"]) == canonical
    assert len(canonical) == 10
    for s in skills_catalog["skills"]:
        assert s["required_controls"], f"{s['skill_id']} has no required controls"
        for c in s["required_controls"]:
            assert c in canonical, f"{s['skill_id']} names non-canonical control {c!r}"


def test_skills_catalog_mitre_is_advisory_and_well_formed(skills_catalog):
    for s in skills_catalog["skills"]:
        for t in s.get("advisory_mitre", []):
            assert re.fullmatch(r"T\d{4}", t), f"{s['skill_id']} bad technique id {t!r}"
