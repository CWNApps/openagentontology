"""test_pipeline.py — the real end-to-end run on the dogfood corpus.

run_pipeline(examples/sample_agent) must produce, for real: a validated OntologyDoc, a
deterministic TrustProfile, a standalone SVG badge, and a verifying Ed25519 receipt -- with
the honesty invariants intact (no fabricated controls, ASCII everywhere, the confirm-note
carried). Also exercises the lazy package facade, determinism, the fail-closed validator,
and the CLI exit-code contract the GitHub Action depends on.
"""
from __future__ import annotations

import json
import subprocess
import sys

import pytest

import openagentontology
from openagentontology import OntologyDoc, TrustProfile
from openagentontology.crosswalk import ALLOWED_FRAMEWORKS, CONFIRM_NOTE
from openagentontology.receipt import verify_receipt
from openagentontology.schema import NODE_TYPES, TIERS
from openagentontology.validate import validate


# ── lazy facade ───────────────────────────────────────────────────────────────
def test_package_lazy_exposes_pipeline():
    # __init__ must surface run_pipeline / PipelineResult via __getattr__ without eager import.
    assert callable(openagentontology.run_pipeline)
    assert isinstance(openagentontology.PipelineResult, type)
    assert openagentontology.VERSION == openagentontology.__version__


def test_unknown_attr_still_raises():
    with pytest.raises(AttributeError):
        _ = openagentontology.this_attr_does_not_exist


# ── end-to-end ────────────────────────────────────────────────────────────────
@pytest.fixture()
def result(sample_dir, receipt_key):
    return openagentontology.run_pipeline(sample_dir, make_receipt=True, key_path=receipt_key)


def test_e2e_produces_all_four_artifacts(result):
    # ontology
    assert isinstance(result.ontology, OntologyDoc)
    assert result.ontology.nodes, "no nodes produced"
    assert result.ontology.action_maps, "no governed actions produced"
    # profile
    assert isinstance(result.profile, TrustProfile)
    assert result.profile.tier in TIERS
    assert 0 <= result.profile.score <= 100
    # badge
    assert result.badge_svg.startswith("<svg") and result.badge_svg.rstrip().endswith("</svg>")
    assert result.profile.tier in result.badge_svg
    # receipt
    assert result.receipt and result.receipt.get("evidence_hash")


def test_e2e_ontology_validates_clean(result):
    ok, findings = validate(result.ontology)
    assert ok is result.ok
    errors = [f for f in findings if f.level == "error"]
    assert not errors, f"dogfood ontology must validate clean; got {[f.code for f in errors]}"


def test_e2e_nodes_are_typed_and_edges_resolve(result):
    node_ids = {n.id for n in result.ontology.nodes}
    for n in result.ontology.nodes:
        assert n.type in NODE_TYPES
    for e in result.ontology.edges:
        assert e.src in node_ids and e.dst in node_ids, "generate left a dangling edge"


def test_e2e_no_fabricated_framework_anywhere(result):
    for am in result.ontology.action_maps:
        for m in am.mappings:
            assert m.fw in ALLOWED_FRAMEWORKS, f"fabricated framework {m.fw!r} reached the ontology"


def test_e2e_everything_is_ascii(result):
    # the whole serialized result (the receipt's hashed input + display) must be ASCII so a
    # JS verifier reproduces the hash byte-for-byte.
    json.dumps(result.to_dict(), ensure_ascii=False).encode("ascii")
    result.badge_svg.encode("ascii")
    assert result.ontology.note == CONFIRM_NOTE


def test_e2e_receipt_verifies_from_cert_alone(result):
    v = verify_receipt(result.receipt)
    assert v["ok"] and v["hash_ok"]
    # cryptography is a declared dep, so the receipt should be genuinely signed here.
    assert v["signed"] and v["sig_ok"], v["reason"]


def test_e2e_badge_chips_are_asserted_refs(result):
    # the refs that became badge chips must all be asserted, citable tokens.
    for tok in result.refs:
        tok.encode("ascii")
    # at least the canonical dual-control control surfaces from the rego reasons
    assert any("AC-5" in t for t in result.refs), \
        f"expected an asserted control chip; got {result.refs}"


def test_e2e_finds_the_source_named_asserted_controls(result):
    # the rego named dual_control_required/over_threshold/beneficiary_unverified -> these
    # must come through as ASSERTED (the honest, source-grounded part of the score).
    asserted_ids = {
        (m.fw, m.id)
        for am in result.ontology.action_maps for m in am.mappings
        if m.confidence == "asserted"}
    assert ("NIST SP 800-53r5", "AC-5") in asserted_ids
    assert ("EU AI Act", "Art 14") in asserted_ids


# ── determinism (safe to put the score/hash in a signed receipt) ──────────────
def test_pipeline_is_deterministic(sample_dir, receipt_key):
    r1 = openagentontology.run_pipeline(sample_dir, make_receipt=True, key_path=receipt_key)
    r2 = openagentontology.run_pipeline(sample_dir, make_receipt=True, key_path=receipt_key)
    assert r1.ontology.to_dict() == r2.ontology.to_dict()
    assert r1.profile.to_dict() == r2.profile.to_dict()
    assert r1.badge_svg == r2.badge_svg
    # the evidence hash is a pure function of the ontology -> identical across runs
    assert r1.receipt["evidence_hash"] == r2.receipt["evidence_hash"]


def test_no_receipt_flag_is_hermetic(sample_dir):
    r = openagentontology.run_pipeline(sample_dir, make_receipt=False)
    assert r.receipt == {}
    # ontology + profile + badge still produced
    assert r.ontology.nodes and r.badge_svg.startswith("<svg")


# ── fail-closed validator path ────────────────────────────────────────────────
def test_validator_fails_closed_on_fabricated_framework():
    from openagentontology.schema import ActionMap, Mapping, Node
    bad = Mapping(fw="ISO 9001 (not allowed)", id="X-1", name="bogus",
                  basis="fabricated", confidence="asserted", provenance="EXTRACTED")
    doc = OntologyDoc(
        source="adversarial", source_kind="test",
        nodes=[Node("d1", "Decision", "do thing", {"action": "thing"})],
        action_maps=[ActionMap("d1", "thing", (bad,), "asserted_table")],
        frameworks=["ISO 9001 (not allowed)"], note=CONFIRM_NOTE)
    ok, findings = validate(doc)
    assert ok is False
    codes = {f.code for f in findings if f.level == "error"}
    assert "E_FRAMEWORK" in codes


def test_validator_fails_closed_on_empty_ontology():
    doc = OntologyDoc(source="empty", source_kind="test", note=CONFIRM_NOTE)
    ok, findings = validate(doc)
    assert ok is False
    assert "E_EMPTY" in {f.code for f in findings}


# ── CLI exit-code contract (the GitHub Action depends on this) ────────────────
def _run_cli(repo_root, *args):
    return subprocess.run(
        [sys.executable, "-m", "openagentontology", *args],
        cwd=str(repo_root),
        env={"PYTHONPATH": str(repo_root), **_clean_env()},
        capture_output=True, text=True)


def _clean_env():
    import os
    e = dict(os.environ)
    e["PYTHONPATH"] = str(e.get("PYTHONPATH", ""))
    return e


def test_cli_runs_and_exits_zero_on_pass(repo_root, sample_dir, tmp_path):
    out_dir = tmp_path / "artifacts"
    cp = _run_cli(repo_root, str(sample_dir), "--json", "--out", str(out_dir))
    assert cp.returncode == 0, cp.stderr
    payload = json.loads(cp.stdout)
    assert "summary" in payload
    assert payload["summary"]["tier"] in TIERS
    assert payload["summary"]["ok"] is True
    assert "counts" in payload["summary"]
    assert payload["summary"]["counts"]["nodes"] > 0
    assert "confirm_note" in payload and payload["confirm_note"] == CONFIRM_NOTE
    # artifacts were written to --out
    assert (out_dir / "ontology.json").exists()
    assert (out_dir / "badge.svg").exists()


def test_cli_missing_path_exits_two(repo_root, tmp_path):
    cp = _run_cli(repo_root, str(tmp_path / "nope"))
    assert cp.returncode == 2


def test_cli_version_flag(repo_root):
    cp = _run_cli(repo_root, "--version")
    assert cp.returncode == 0
    assert openagentontology.VERSION in (cp.stdout + cp.stderr)
