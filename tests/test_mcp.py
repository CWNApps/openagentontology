"""test_mcp.py -- the MCP tool functions are real, read-only, and need no `mcp` install.

build_server() imports FastMCP lazily, so the governance tool callables are testable on
their own. These pin the contract the MCP layer exposes to any calling agent.
"""
from __future__ import annotations

from openagentontology import run_pipeline
from openagentontology.mcp_server import (
    explain,
    map_action_controls,
    scan_agent,
    verify,
)


def test_scan_agent_summarizes_a_real_agent(sample_dir):
    out = scan_agent(str(sample_dir))
    assert "error" not in out
    assert out["tier"] in ("SOVEREIGN", "HARDENED", "DEVELOPING", "UNGOVERNED")
    assert 0 <= out["score"] <= 100
    # the action accounting closes: every governed + ungoverned action is counted once
    assert out["counts"]["actions"] == out["counts"]["governed"] + out["counts"]["ungoverned"]
    assert isinstance(out["asserted_controls"], list)
    assert out["note"]


def test_scan_agent_missing_path_is_a_clean_error():
    out = scan_agent("does/not/exist/anywhere")
    assert out["error"]


def test_scan_agent_caps_list_sizes(sample_dir):
    out = scan_agent(str(sample_dir), max_items=1)
    assert len(out["governed_actions"]) <= 1
    assert len(out["ungoverned_actions"]) <= 1


def test_map_action_returns_sourced_controls():
    out = map_action_controls("wire_transfer")
    assert out["matched_via"] in ("asserted_table", "heuristic", "none")
    for m in out["mappings"]:
        assert {"framework", "id", "name", "confidence", "basis"} <= set(m)
        # a heuristic match is never auto-asserted
        assert m["confidence"] in ("inferred", "advisory", "ambiguous")


def test_map_action_canonical_reason_is_asserted():
    out = map_action_controls("anything", source_reason="dual_control_required")
    assert out["matched_via"] == "asserted_table"
    assert any(m["confidence"] == "asserted" for m in out["mappings"])


def test_verify_roundtrips_a_real_receipt(sample_dir, receipt_key):
    res = run_pipeline(str(sample_dir), make_receipt=True, key_path=receipt_key)
    v = verify(res.receipt)
    assert v["ok"] and v["hash_ok"]


def test_verify_rejects_non_dict_input():
    assert verify("not a receipt")["ok"] is False


def test_explain_surfaces_weights_and_frameworks():
    e = explain()
    assert abs(sum(e["axis_weights"].values()) - 1.0) < 1e-9
    assert e["frameworks"]
    assert "SOVEREIGN" in e["tiers"]
    assert len(e["layers"]) == 3
