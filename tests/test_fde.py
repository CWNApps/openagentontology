"""test_fde.py — CWN AgentFDE: the autonomous onboarding loop must actually remediate.

Locks the headline behaviour: scanning an ungoverned agent, generating the governance, and
re-scanning the GENERATED manifest must prove a real tier jump (not a cosmetic one), with a
verifiable receipt and the four handoff artifacts on disk.
"""
from __future__ import annotations

import json

from openagentontology.fde import onboard
from openagentontology.pipeline import run_pipeline
from openagentontology.receipt import verify_receipt


def test_fde_onboard_improves_tier_and_emits_artifacts(sample_dir, tmp_path):
    out = tmp_path / "fde"
    r = onboard(str(sample_dir), out_dir=str(out), make_receipt=True)

    # the raw agent is ungoverned; the projection is materially better.
    assert r.before_tier == "UNGOVERNED"
    assert r.after_score > r.before_score
    assert r.after_tier in ("DEVELOPING", "HARDENED", "SOVEREIGN")

    # it recovered the money/deploy/export remediations from the verb crosswalk.
    reasons = {x.reason for x in r.remediations}
    assert "dual_control_required" in reasons   # wire_transfer
    assert "approval_required" in reasons        # deploy
    assert "regulated_egress_blocked" in reasons  # export

    # all four handoff artifacts exist.
    for f in ("governance.agent.yaml", "governance.rego", "ONBOARDING.md", "receipt.json"):
        assert (out / f).exists(), f"missing {f}"


def test_fde_generated_manifest_is_real_governance(sample_dir, tmp_path):
    out = tmp_path / "fde"
    onboard(str(sample_dir), out_dir=str(out), make_receipt=False)
    # the generated agentdef is not a stub: scanning it reads ASSERTED, not inferred/mcp.
    man = run_pipeline(str(out / "governance.agent.yaml"), make_receipt=False)
    assert man.profile.tier in ("HARDENED", "SOVEREIGN")
    assert man.ontology.action_maps
    assert all(a.matched_via == "asserted_table" for a in man.ontology.action_maps)


def test_fde_receipt_verifies_offline(sample_dir, tmp_path):
    out = tmp_path / "fde"
    onboard(str(sample_dir), out_dir=str(out), make_receipt=True)
    rec = json.load(open(out / "receipt.json"))
    v = verify_receipt(rec)
    assert v["ok"] and v["hash_ok"]
