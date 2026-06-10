"""test_golden_fixtures.py -- five tiny agents pin the pipeline's honest classifications.

Each fixture under tests/fixtures/ is a complete, scannable agent directory (a small Python
file, optionally a governance manifest + Rego policy) chosen to exercise ONE classification
path end-to-end through run_pipeline:

    shell_exec_agent     raw command execution, zero governance  -> UNGOVERNED, unmapped
    telemetry_agent      egress verb, no declared reason         -> heuristic INFERRED only
    payment_agent        source-declared dual_control_required   -> genuinely ASSERTED
    ambiguous_run_agent  weak overloaded verbs ('run')           -> AMBIGUOUS stub only
    fake_control_agent   manifest claims FAKE_NIST / AC-999      -> claims do NOT survive

Every expectation below was derived by RUNNING the pipeline on the fixture and checking the
output is the honest one (e.g. payment_agent asserts because its manifest NAMES the canonical
reason; the fake-control claims never become mappings because the crosswalk only re-emits ids
already in ASSERTED_TABLE). These are regression pins on honesty, not aspirations.

All runs use make_receipt=False so the golden scans stay hermetic (no key, no disk writes);
receipt tamper-evidence is exercised separately in test_mutation.py.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import openagentontology
from openagentontology.crosswalk import ALLOWED_FRAMEWORKS

_FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def scans():
    """One pipeline run per fixture, shared across the module (the runs are deterministic)."""
    out = {}
    for name in ("shell_exec_agent", "telemetry_agent", "payment_agent",
                 "ambiguous_run_agent", "fake_control_agent"):
        d = _FIXTURES / name
        assert d.is_dir(), f"missing golden fixture: {d}"
        out[name] = openagentontology.run_pipeline(d, make_receipt=False)
    return out


# -- shared accessors ----------------------------------------------------------
def _maps_by_id(result):
    return {am.subject_id: am for am in result.ontology.action_maps}


def _asserted_count(result):
    return sum(1 for am in result.ontology.action_maps
               if any(m.confidence == "asserted" for m in am.mappings))


def _ungoverned_count(result):
    return sum(1 for am in result.ontology.action_maps if am.matched_via == "none")


def _all_mappings(result):
    for am in result.ontology.action_maps:
        for m in am.mappings:
            yield m


# -- shell_exec_agent: raw exec, zero governance -> UNGOVERNED -----------------
def test_shell_exec_agent_is_ungoverned(scans):
    r = scans["shell_exec_agent"]
    assert r.profile.tier == "UNGOVERNED"
    assert len(r.ontology.action_maps) == 1
    assert _asserted_count(r) == 0
    assert _ungoverned_count(r) == 1


def test_shell_exec_agent_exec_stays_unmapped(scans):
    # 'exec' names no canonical reason and matches no verb heuristic -- the honest answer
    # is matched_via='none', surfaced as a W_UNGOVERNED finding, never a guessed control.
    r = scans["shell_exec_agent"]
    am = _maps_by_id(r)["cap_exec"]
    assert am.matched_via == "none"
    assert am.mappings == ()
    assert any(f.code == "W_UNGOVERNED" and "cap_exec" in f.msg for f in r.findings)
    assert r.refs == []                      # no asserted controls -> no badge chips


# -- telemetry_agent: egress verb, no declared reason -> INFERRED only ---------
def test_telemetry_agent_gets_inferred_egress_controls(scans):
    r = scans["telemetry_agent"]
    am = _maps_by_id(r)["cap_send_telemetry"]
    assert am.matched_via == "heuristic"
    inferred = {(m.fw, m.id) for m in am.mappings if m.confidence == "inferred"}
    # the regulated-egress controls, DOWNGRADED to inferred (verb 'send', no source reason)
    assert ("NIST SP 800-53r5", "AC-4") in inferred
    assert ("NIST SP 800-53r5", "SC-7") in inferred


def test_telemetry_agent_never_asserts_from_a_heuristic(scans):
    # heuristic output is inferred/advisory at most -- ASSERTED is reserved for a
    # source-declared canonical reason, which this agent does not have.
    r = scans["telemetry_agent"]
    confidences = {m.confidence for m in _all_mappings(r)}
    assert "asserted" not in confidences
    assert confidences <= {"inferred", "advisory"}
    assert _asserted_count(r) == 0
    assert r.profile.tier == "UNGOVERNED"    # inferred-only coverage earns no governed tier
    assert r.refs == []


# -- payment_agent: declared dual_control_required -> genuinely ASSERTED -------
def test_payment_agent_asserts_via_declared_reason(scans):
    # the governance manifest NAMES dual_control_required for initiate_payment, and the
    # rego carries the matching deny key -- so Layer-1 fires and AC-5 arrives asserted.
    r = scans["payment_agent"]
    am = _maps_by_id(r)["cap_initiate_payment"]
    assert am.matched_via == "asserted_table"
    asserted = {(m.fw, m.id) for m in am.mappings if m.confidence == "asserted"}
    assert ("NIST SP 800-53r5", "AC-5") in asserted
    assert ("EU AI Act", "Art 14") in asserted
    assert ("OWASP LLM Top 10 (2025)", "LLM06") in asserted


def test_payment_agent_counts_and_tier(scans):
    r = scans["payment_agent"]
    assert r.ok is True
    assert r.profile.tier == "HARDENED"
    assert len(r.ontology.action_maps) == 4   # capability + 2 dual-control gates + rego allow guard
    assert _asserted_count(r) == 3
    assert _ungoverned_count(r) == 1          # the rego 'allow' guard maps to nothing -- honest
    assert "NIST 800-53 AC-5" in r.refs


def test_payment_agent_rego_deny_key_is_asserted_too(scans):
    # the rego's literal deny key becomes its own asserted gate, independent of the manifest.
    r = scans["payment_agent"]
    am = _maps_by_id(r)["gate_dual_control_required"]
    assert am.matched_via == "asserted_table"
    assert any(m.confidence == "asserted" for m in am.mappings)


# -- ambiguous_run_agent: weak verbs -> AMBIGUOUS stub, never asserted ---------
def test_ambiguous_run_agent_gets_only_the_ambiguous_stub(scans):
    r = scans["ambiguous_run_agent"]
    for cap in ("cap_run_pipeline", "cap_run_report"):
        am = _maps_by_id(r)[cap]
        assert am.matched_via == "heuristic"
        assert len(am.mappings) == 1
        m = am.mappings[0]
        # at most the single OWASP LLM06 excessive-agency stub -- never a specific 800-53 id
        assert (m.fw, m.id) == ("OWASP LLM Top 10 (2025)", "LLM06")
        assert m.confidence == "ambiguous" and m.provenance == "AMBIGUOUS"


def test_ambiguous_run_agent_is_flagged_and_ungoverned_tier(scans):
    r = scans["ambiguous_run_agent"]
    assert {m.confidence for m in _all_mappings(r)} == {"ambiguous"}
    assert _asserted_count(r) == 0
    assert r.profile.tier == "UNGOVERNED"
    assert any(f.code == "W_AMBIGUOUS" for f in r.findings)
    assert r.refs == []


# -- fake_control_agent: fabricated claims must not survive --------------------
def test_fake_control_claims_never_become_mappings(scans):
    # the manifest claims framework 'FAKE_NIST' and control id 'AC-999'. The crosswalk only
    # re-emits ids already in ASSERTED_TABLE, so neither token may appear in any mapping.
    r = scans["fake_control_agent"]
    for m in _all_mappings(r):
        assert m.fw != "FAKE_NIST"
        assert m.id != "AC-999"
        assert m.fw in ALLOWED_FRAMEWORKS


def test_fake_control_agent_earns_no_assertion(scans):
    # 'NIST AC-999' is not a canonical reason, so nothing fires Layer-1: the payment
    # capability falls back to the honest verb heuristic (inferred), the fake gate maps to
    # nothing, and the scan validates clean BECAUSE the fabricated claims were dropped.
    r = scans["fake_control_agent"]
    assert _asserted_count(r) == 0
    maps = _maps_by_id(r)
    assert maps["cap_initiate_payment"].matched_via == "heuristic"
    assert all(m.confidence in ("inferred", "advisory")
               for m in maps["cap_initiate_payment"].mappings)
    assert maps["gate_fake_nist_compliance_gate"].matched_via == "none"
    assert r.ok is True
    assert r.profile.tier == "UNGOVERNED"
    assert r.refs == []
