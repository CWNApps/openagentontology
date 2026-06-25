"""test_ci_check.py — the PR governance gate (ci/pr_check.py) decides correctly.

The GitHub Action's pass/fail logic lives in ci/pr_check.evaluate(). These tests pin its
contract against synthetic --json payloads (shaped exactly like the CLI emits) so the viral
PR check can't silently rot: a real regression must fail, a clean PR must pass, and the gate
never fabricates a 'gap' for an action that is merely inferred-governed.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

# load ci/pr_check.py (it lives outside the package, the way the Action invokes it).
_spec = importlib.util.spec_from_file_location("pr_check", _REPO / "ci" / "pr_check.py")
pr_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pr_check)


def _payload(tier="HARDENED", score=80, ok=True, action_maps=None, findings=None):
    return {
        "tier": tier, "score": score, "ok": ok,
        "findings": findings or [],
        "profile": {"subscores": {"coverage": 80, "rigor": 80, "breadth": 75, "structure": 100},
                    "rationale": ["synthetic"]},
        "confirm_note": "Proposed CWN mappings, confidence-tagged. Confirm ...",
        "ontology": {"nodes": [{"id": "n"}], "note": "note",
                     "action_maps": action_maps or []},
    }


def _am(subject_id, label, matched_via="asserted_table", mappings=None):
    return {"subject_id": subject_id, "label": label,
            "matched_via": matched_via, "mappings": mappings or []}


_ASSERTED_AC5 = [{"fw": "NIST SP 800-53r5", "id": "AC-5", "name": "Separation of Duties",
                  "basis": "x", "confidence": "asserted", "provenance": "EXTRACTED"}]
_INFERRED_ART14 = [{"fw": "EU AI Act", "id": "Art 14", "name": "Human oversight",
                    "basis": "inferred", "confidence": "inferred", "provenance": "INFERRED"}]


# ── clean PR passes ───────────────────────────────────────────────────────────
def test_clean_pr_passes():
    head = _payload(action_maps=[_am("cap_wire", "wire_transfer", "asserted_table", _ASSERTED_AC5)])
    v = pr_check.evaluate(head, base=None)
    assert v["passed"] is True
    assert not v["fail_reasons"]


# ── fail-closed validation on HEAD fails ──────────────────────────────────────
def test_failed_validation_fails():
    head = _payload(ok=False, findings=[{"level": "error", "code": "E_FRAMEWORK", "msg": "x"}])
    v = pr_check.evaluate(head, base=None)
    assert v["passed"] is False
    assert any("FAILED closed" in r for r in v["fail_reasons"])


# ── nested CLI payload shape (tier/score/ok under summary, not top level) ──────
def _payload_nested(tier="HARDENED", score=80, ok=True, action_maps=None):
    """The shape the live `python -m openagentontology --json` actually emits: tier/score/ok
    live under `summary` (and `profile`), NOT at the top level. The gate must read either."""
    return {
        "findings": [],
        "summary": {"tier": tier, "score": score, "ok": ok},
        "profile": {"tier": tier, "score": score,
                    "subscores": {"coverage": 80, "rigor": 80, "breadth": 75, "structure": 100}},
        "ontology": {"nodes": [{"id": "n"}], "action_maps": action_maps or []},
    }


def test_nested_payload_is_read_correctly():
    # a clean, valid nested payload must PASS -- this is the real CLI output shape.
    head = _payload_nested(action_maps=[_am("cap_wire", "wire_transfer", "asserted_table", _ASSERTED_AC5)])
    v = pr_check.evaluate(head, base=None)
    assert v["head_ok"] is True, "ok must be read from summary, not defaulted to False"
    assert v["head_tier"] == "HARDENED"
    assert v["head_score"] == 80
    assert v["passed"] is True
    assert not v["fail_reasons"]


def test_nested_failed_validation_still_fails():
    head = _payload_nested(ok=False)
    head["findings"] = [{"level": "error", "code": "E_FRAMEWORK", "msg": "x"}]
    v = pr_check.evaluate(head, base=None)
    assert v["passed"] is False
    assert any("FAILED closed" in r for r in v["fail_reasons"])


def test_nested_tier_drop_vs_nested_base_fails():
    base = _payload_nested(tier="HARDENED", score=80)
    head = _payload_nested(tier="DEVELOPING", score=60)
    v = pr_check.evaluate(head, base=base)
    assert v["tier_dropped"] is True and v["passed"] is False


# ── NEW ungoverned high-risk action fails; pre-existing one does not ──────────
def test_new_ungoverned_high_risk_fails():
    base = _payload(action_maps=[_am("cap_wire", "wire_transfer", "asserted_table", _ASSERTED_AC5)])
    # HEAD adds a brand-new, totally ungoverned export action
    head = _payload(action_maps=[
        _am("cap_wire", "wire_transfer", "asserted_table", _ASSERTED_AC5),
        _am("cap_export", "export_records", "none", []),
    ])
    v = pr_check.evaluate(head, base)
    assert v["passed"] is False
    assert "cap_export" in v["new_ungoverned"]
    assert any("NEW ungoverned high-risk" in r for r in v["fail_reasons"])


def test_preexisting_ungoverned_does_not_fail():
    # same ungoverned export on BOTH base and head -> not NEW -> does not fail the PR.
    am = _am("cap_export", "export_records", "none", [])
    base = _payload(action_maps=[am])
    head = _payload(action_maps=[am])
    v = pr_check.evaluate(head, base)
    assert v["passed"] is True
    assert v["new_ungoverned"] == {}


# ── tier drop fails ───────────────────────────────────────────────────────────
def test_tier_drop_fails():
    base = _payload(tier="HARDENED", score=80)
    head = _payload(tier="DEVELOPING", score=60)
    v = pr_check.evaluate(head, base)
    assert v["passed"] is False and v["tier_dropped"] is True
    assert any("DROPPED" in r for r in v["fail_reasons"])


def test_tier_improve_passes():
    base = _payload(tier="DEVELOPING", score=60)
    head = _payload(tier="HARDENED", score=80)
    v = pr_check.evaluate(head, base)
    assert v["passed"] is True and v["tier_dropped"] is False


# ── inferred-governed oversight action is NOT a fabricated Art 14 'gap' ───────
def test_inferred_oversight_is_not_a_gap():
    # a deploy action mapped to an INFERRED Art 14 control is governed, not a gap.
    head = _payload(action_maps=[_am("cap_deploy", "deploy_service", "heuristic", _INFERRED_ART14)])
    v = pr_check.evaluate(head, base=None)
    assert v["new_art14_gaps"] == {}, "inferred-governed action wrongly flagged as an Art 14 gap"


def test_new_ungoverned_oversight_action_is_an_art14_gap():
    base = _payload(action_maps=[])
    head = _payload(action_maps=[_am("cap_deny", "deny_claim", "none", [])])
    v = pr_check.evaluate(head, base)
    assert "cap_deny" in v["new_art14_gaps"]
    assert v["passed"] is False


# ── report renders + is well-formed markdown ──────────────────────────────────
def test_report_renders_markdown_with_note():
    head = _payload(action_maps=[_am("cap_deny", "deny_claim", "none", [])])
    v = pr_check.evaluate(head, base=_payload(action_maps=[]))
    md = pr_check.render_report(v, head)
    assert md.startswith("## OpenAgentOntology")
    assert "Result: FAIL" in md
    assert "Article 14" in md
    assert "Proposed CWN mappings" in md  # the confirm-note always rides along


def test_main_writes_report_and_returns_exit_code(tmp_path):
    import json
    head = _payload(tier="UNGOVERNED", action_maps=[_am("cap_x", "export_records", "none", [])])
    hp = tmp_path / "head.json"
    hp.write_text(json.dumps(head), encoding="utf-8")
    bp = tmp_path / "base.json"
    bp.write_text(json.dumps(_payload(action_maps=[])), encoding="utf-8")
    rep = tmp_path / "report.md"
    rc = pr_check.main(["--head", str(hp), "--base", str(bp), "--report", str(rep)])
    assert rc == 1  # a new ungoverned high-risk export -> fail
    assert rep.exists() and "OpenAgentOntology" in rep.read_text(encoding="utf-8")


def test_main_missing_head_is_usage_error(tmp_path):
    rc = pr_check.main(["--head", str(tmp_path / "nope.json")])
    assert rc == 2
