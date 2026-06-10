"""test_sarif.py -- SARIF 2.1.0 export of one governance scan.

to_sarif(result) must emit a structurally valid SARIF log (validated here against the
2.1.0 SHAPE -- never against a remote schema; no network in this suite): one run, driver
'openagentontology', one error/warning result per UNGOVERNED side-effecting action
(error when the verb class is critical), one note per AMBIGUOUS action, stable
OAO-UNGOVERNED-<DOMAIN> rule ids, honest locations (the scanned source path -- never a
fabricated line number), and byte-identical output across runs.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

import openagentontology
from openagentontology.crosswalk import map_action
from openagentontology.sarif import SARIF_SCHEMA_URI, SARIF_VERSION, to_sarif
from openagentontology.schema import VERSION, ActionMap, Node, OntologyDoc

_LEVELS = {"error", "warning", "note"}

# A tiny agent whose surface exercises all three SARIF result classes:
#   exec_payload   verb-named action fn, no heuristic match  -> UNGOVERNED critical -> error
#   email_blast    verb-named action fn, no heuristic match  -> UNGOVERNED high     -> warning
#   update_record  @tool capability, weak overloaded verb    -> AMBIGUOUS stub      -> note
_RISKY_AGENT_PY = '''\
@tool
def update_record(payload):
    """Persist an update to the record store."""
    return payload


def exec_payload(cmd):
    return cmd


def email_blast(recipients):
    return recipients
'''


@pytest.fixture(scope="module")
def sample_sarif(repo_root):
    res = openagentontology.run_pipeline(
        str(repo_root / "examples" / "sample_agent"), make_receipt=False)
    return to_sarif(res)


@pytest.fixture()
def risky_result(tmp_path):
    fp = tmp_path / "risky_agent.py"
    fp.write_text(_RISKY_AGENT_PY, encoding="ascii")
    return openagentontology.run_pipeline(str(fp), make_receipt=False)


def _assert_valid_shape(log):
    assert log["$schema"] == SARIF_SCHEMA_URI
    assert log["version"] == SARIF_VERSION == "2.1.0"
    assert len(log["runs"]) == 1
    run = log["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "openagentontology"
    assert driver["version"] == VERSION
    rule_ids = [r["id"] for r in driver["rules"]]
    assert rule_ids == sorted(set(rule_ids)), "rules must be sorted + unique"
    for res in run["results"]:
        assert res["level"] in _LEVELS
        assert res["message"]["text"]
        assert res["ruleId"] in rule_ids
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["locations"], "every result carries a location"
    # ASCII end to end (receipt discipline applies to every artifact we emit)
    json.dumps(log, ensure_ascii=False).encode("ascii")


# -- structure -----------------------------------------------------------------
def test_sample_agent_produces_valid_sarif(sample_sarif):
    _assert_valid_shape(sample_sarif)


def test_risky_agent_produces_valid_sarif(risky_result):
    _assert_valid_shape(to_sarif(risky_result))


# -- result classes ------------------------------------------------------------
def test_ungoverned_exec_yields_error_result(risky_result):
    results = to_sarif(risky_result)["runs"][0]["results"]
    errs = [r for r in results if r["level"] == "error"]
    assert errs, f"expected an error result; got {results}"
    assert any(r["ruleId"] == "OAO-UNGOVERNED-EXECUTION" for r in errs)
    assert any("exec_payload" in r["message"]["text"] for r in errs)


def test_ungoverned_high_severity_yields_warning(risky_result):
    results = to_sarif(risky_result)["runs"][0]["results"]
    warns = [r for r in results if r["level"] == "warning"]
    assert any(r["ruleId"] == "OAO-UNGOVERNED-EGRESS" for r in warns), warns


def test_ambiguous_action_yields_note(risky_result):
    results = to_sarif(risky_result)["runs"][0]["results"]
    notes = [r for r in results if r["level"] == "note"]
    assert any(r["ruleId"].startswith("OAO-AMBIGUOUS-") for r in notes), results
    assert any("update_record" in r["message"]["text"] for r in notes)


def test_inferred_and_asserted_actions_emit_no_result():
    # a strongly-inferred action (wire_transfer) and an asserted one are NOT findings.
    nodes = [Node(id="agent_t", type="Agent", name="t")]
    ams = []
    for nid, action, reason in (("cap_a", "wire_transfer", None),
                                ("cap_b", "export_records", "regulated_egress_blocked")):
        nodes.append(Node(id=nid, type="Capability", name=action, props={"action": action}))
        am = map_action(action, reason)
        ams.append(ActionMap(nid, am.label, am.mappings, am.matched_via))
    doc = OntologyDoc(source="synthetic", source_kind="test", nodes=nodes, action_maps=ams)
    assert to_sarif(doc)["runs"][0]["results"] == []


# -- locations: only what the ontology actually carries ------------------------
def test_locations_carry_the_scanned_source(risky_result):
    src = risky_result.ontology.source.replace("\\", "/")
    for res in to_sarif(risky_result)["runs"][0]["results"]:
        loc = res["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == src
        assert loc["logicalLocations"][0]["name"]  # the governed node id


# -- determinism ---------------------------------------------------------------
def test_sarif_is_deterministic(repo_root):
    p = str(repo_root / "examples" / "sample_agent")
    s1 = to_sarif(openagentontology.run_pipeline(p, make_receipt=False))
    s2 = to_sarif(openagentontology.run_pipeline(p, make_receipt=False))
    assert json.dumps(s1, sort_keys=True) == json.dumps(s2, sort_keys=True)


# -- CLI flag ------------------------------------------------------------------
def test_cli_sarif_flag_writes_valid_file(repo_root, tmp_path):
    sarif_fp = tmp_path / "scan.sarif"
    cp = subprocess.run(
        [sys.executable, "-m", "openagentontology",
         str(repo_root / "examples" / "sample_agent"),
         "--json", "--out", str(tmp_path / "artifacts"),
         "--sarif", str(sarif_fp), "--no-receipt"],
        cwd=str(repo_root), capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(repo_root)})
    assert cp.returncode == 0, cp.stderr
    payload = json.loads(cp.stdout)
    assert "risk_profile" in payload and payload["risk_profile"]
    assert set(payload["risk_profile"]) >= {
        "declaration_coverage", "enforcement_evidence",
        "extraction_confidence", "risk_exposure"}
    log = json.loads(sarif_fp.read_text(encoding="ascii"))
    _assert_valid_shape(log)
    assert payload["artifacts"]["sarif"] == str(sarif_fp.resolve())
