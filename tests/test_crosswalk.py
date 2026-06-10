"""test_crosswalk.py — the fabrication-safe mapping-rigor gate (pol.must_do.143).

These tests are the heart of the honesty guarantee. They prove, mechanically, that:
  - No mapping ever names a framework outside crosswalk.ALLOWED_FRAMEWORKS.
  - Every Mapping is fully sourced: fw + id + name + basis + confidence + provenance, all ASCII.
  - 'asserted' confidence is RESERVED for the source-named ASSERTED_TABLE -- a heuristic match
    can only ever produce 'inferred' or 'ambiguous' (auto-detected != ASSERTED unless exact).
  - map_action NEVER fabricates a control id: every emitted id already lives in ASSERTED_TABLE.
  - The ASSERTED_TABLE is transcribed 1:1 from the canonical CWN's canonical control map.
  - CONFIRM_NOTE is present, ASCII, and carries the 'confidence-tagged / confirm' discipline.
"""
from __future__ import annotations

import re

import pytest

from openagentontology.crosswalk import (
    ALLOWED_FRAMEWORKS,
    ASSERTED_TABLE,
    CONFIRM_NOTE,
    compact_refs,
    map_action,
)
from openagentontology.schema import CONFIDENCE, PROVENANCE


def _all_table_mappings():
    for reason, mappings in ASSERTED_TABLE.items():
        for m in mappings:
            yield reason, m


# ── ALLOWED frameworks fence ──────────────────────────────────────────────────
def test_asserted_table_only_uses_allowed_frameworks():
    for reason, m in _all_table_mappings():
        assert m.fw in ALLOWED_FRAMEWORKS, f"{reason}: fw {m.fw!r} outside ALLOWED_FRAMEWORKS"


def test_no_heuristic_mapping_escapes_allowed_frameworks():
    # exercise a strong verb, a weak verb, and a no-match label
    for label in ("wire_transfer", "export_records", "deploy_service",
                  "process_thing", "frobnicate_the_widget", "lookup_balance"):
        am = map_action(label)
        for m in am.mappings:
            assert m.fw in ALLOWED_FRAMEWORKS, f"{label}: leaked fw {m.fw!r}"


# ── every mapping fully sourced + confidence/provenance tagged + ASCII ────────
def test_every_table_mapping_is_fully_sourced_and_ascii():
    for reason, m in _all_table_mappings():
        for fld in ("fw", "id", "name", "basis", "confidence", "provenance"):
            val = getattr(m, fld)
            assert isinstance(val, str) and val.strip(), f"{reason}: empty field {fld}"
            # ASCII discipline: these strings land inside the signed receipt evidence.
            val.encode("ascii")
        assert m.confidence in CONFIDENCE, f"{reason}: bad confidence {m.confidence!r}"
        assert m.provenance in PROVENANCE, f"{reason}: bad provenance {m.provenance!r}"


def test_table_mappings_are_asserted_or_advisory_only():
    # Layer 1 is the source-named table: it may only carry the two SOURCE confidences.
    for reason, m in _all_table_mappings():
        assert m.confidence in ("asserted", "advisory"), \
            f"{reason}: table mapping has non-source confidence {m.confidence!r}"
        assert m.provenance == "EXTRACTED", \
            f"{reason}: table mapping provenance must be EXTRACTED, got {m.provenance!r}"


# ── auto-detected != ASSERTED unless exact ────────────────────────────────────
def test_source_named_reason_yields_asserted_extracted():
    am = map_action("anything", source_reason="dual_control_required")
    assert am.matched_via == "asserted_table"
    assert any(m.confidence == "asserted" for m in am.mappings)
    # and it is byte-identical to the table (1:1, not a paraphrase)
    assert list(am.mappings) == list(ASSERTED_TABLE["dual_control_required"])


def test_strong_heuristic_is_inferred_never_asserted():
    am = map_action("wire_transfer")  # strong 'wire' verb, no source_reason
    assert am.matched_via == "heuristic"
    assert am.mappings, "a strong verb must still map to *something*"
    for m in am.mappings:
        assert m.confidence in ("inferred", "advisory"), f"strong heuristic leaked confidence {m.confidence!r}"
    # the downgraded asserted controls become inferred; advisory controls (NIST AI RMF, the
    # MITRE ATT&CK technique enrichment) ride along as advisory
    assert any(m.confidence == "inferred" and m.provenance == "INFERRED" for m in am.mappings)
    # crucially: a heuristic NEVER produces an asserted mapping
    assert not any(m.confidence == "asserted" for m in am.mappings)


def test_weak_heuristic_is_ambiguous_stub_only():
    am = map_action("process_the_batch")  # overloaded/side-effecting verb -> ambiguous stub
    assert am.matched_via == "heuristic"
    assert len(am.mappings) == 1
    m = am.mappings[0]
    assert m.confidence == "ambiguous" and m.provenance == "AMBIGUOUS"
    # the stub is an OWASP LLM06 excessive-agency flag, NEVER a specific 800-53 id
    assert m.fw == "OWASP LLM Top 10 (2025)" and m.id == "LLM06"


def test_no_match_is_empty_and_ungoverned():
    am = map_action("frobnicate_quux")  # no governed verb at all
    assert am.matched_via == "none"
    assert am.mappings == ()


def test_unknown_source_reason_falls_through_to_heuristic_not_fabrication():
    # a source_reason that is NOT in the table must not be trusted as asserted; it falls
    # through to the label heuristic (here the label has no verb -> none).
    am = map_action("frobnicate_quux", source_reason="totally_made_up_reason")
    assert am.matched_via in ("heuristic", "none")
    assert not any(m.confidence == "asserted" for m in am.mappings)


# ── the no-fabrication guard: every emitted id pre-exists in ASSERTED_TABLE ────
def test_map_action_never_fabricates_a_framework_id():
    legit_ids = {(m.fw, m.id) for _r, m in _all_table_mappings()}
    # plus the single ambiguous stub, which is a known, fixed OWASP id
    legit_ids.add(("OWASP LLM Top 10 (2025)", "LLM06"))

    probes = [
        "wire_transfer", "pay_invoice", "export_records", "egress_data", "redact_pii",
        "delete_dataset", "deploy_service", "approve_loan", "deny_claim", "escalate_privilege",
        "process", "update", "run", "AC-99", "fabricate", "id_42", "",
    ]
    for label in probes:
        for src in (None, "over_threshold", "not_a_real_reason"):
            am = map_action(label, source_reason=src)
            for m in am.mappings:
                assert (m.fw, m.id) in legit_ids, \
                    f"FABRICATED id ({m.fw} {m.id}) for label={label!r} src={src!r}"


def test_no_control_id_looks_invented():
    # defensive: no id like 'AC-99' / 'AC-00' that is not in the table sneaks through.
    table_ids = {(m.fw, m.id) for _r, m in _all_table_mappings()}
    fake = re.compile(r"^[A-Z]{2}-9\d$")
    for label in ("wire", "export", "deploy", "deny", "process"):
        for m in map_action(label).mappings:
            assert (m.fw, m.id) in table_ids or not fake.match(m.id)


# ── parity with the canonical CWN's canonical control map (transcribed 1:1) ─────────
# Spot-check the controls the build brief calls out by name. These are the exact
# (reason -> control) anchors from CWN's canonical control map; a drift here is a regression.
@pytest.mark.parametrize("reason,fw,cid", [
    ("dual_control_required", "NIST SP 800-53r5", "AC-5"),
    ("over_threshold", "NIST SP 800-53r5", "AC-3"),
    ("over_threshold", "NIST SP 800-53r5", "AC-6"),
    ("regulated_egress_blocked", "NIST SP 800-53r5", "AC-4"),
    ("regulated_egress_blocked", "NIST SP 800-53r5", "SC-7"),
    ("classification_above_ceiling", "NIST SP 800-53r5", "RA-2"),
    ("change_freeze_active", "NIST SP 800-53r5", "CM-3"),
    ("change_freeze_active", "NIST SP 800-53r5", "CM-5"),
    ("approval_required", "NIST SP 800-53r5", "CM-3"),
    ("human_review_required", "EU AI Act", "Art 14"),
    ("dual_control_required", "OWASP LLM Top 10 (2025)", "LLM06"),
    ("classification_above_ceiling", "OWASP LLM Top 10 (2025)", "LLM02"),
])
def test_canonical_control_anchors_present(reason, fw, cid):
    assert reason in ASSERTED_TABLE, f"missing canonical reason {reason}"
    pairs = {(m.fw, m.id) for m in ASSERTED_TABLE[reason]}
    assert (fw, cid) in pairs, f"{reason} lost its anchor control {fw} {cid}"


def test_all_canonical_reasons_present():
    # The ASSERTED_TABLE is transcribed 1:1 from the canonical reason-to-control map, which
    # defines exactly these 10 canonical OPA reasons. A drift in this set (added/dropped key)
    # means the crosswalk no longer mirrors the canonical source -> a regression.
    expected = {
        "dual_control_required", "over_threshold", "beneficiary_unverified",
        "human_review_required", "classification_above_ceiling", "out_of_scope_domain",
        "regulated_egress_blocked", "change_freeze_active", "approval_required",
        "high_blast_needs_named_approver",
    }
    assert set(ASSERTED_TABLE) == expected, \
        f"ASSERTED_TABLE drifted from the canonical FRAMEWORK_MAP reasons: {set(ASSERTED_TABLE) ^ expected}"


# ── CONFIRM_NOTE discipline ───────────────────────────────────────────────────
def test_confirm_note_is_present_ascii_and_disciplined():
    assert isinstance(CONFIRM_NOTE, str) and CONFIRM_NOTE.strip()
    CONFIRM_NOTE.encode("ascii")  # must be ASCII (it rides into the receipt evidence)
    low = CONFIRM_NOTE.lower()
    assert "confidence-tagged" in low
    assert "confirm" in low
    assert "never auto-asserted" in low


# ── compact_refs: honest, ASCII, asserted-only by default ─────────────────────
def test_compact_refs_are_asserted_only_ascii_tokens():
    am = map_action("anything", source_reason="dual_control_required")
    refs = compact_refs(am)  # asserted_only defaults True
    assert refs, "asserted mapping must yield citable refs"
    for tok in refs:
        tok.encode("ascii")
        assert re.match(r"^[A-Za-z0-9 .()/-]+ [A-Za-z0-9-]+$", tok), f"odd ref token {tok!r}"
    # 'NIST 800-53 AC-5' is the canonical short form
    assert "NIST 800-53 AC-5" in refs


def test_compact_refs_drops_non_asserted_when_asserted_only():
    am = map_action("wire_transfer")  # heuristic -> inferred only, never asserted
    assert compact_refs(am, asserted_only=True) == []
    # but with asserted_only=False the inferred controls are still ASCII tokens
    loose = compact_refs(am, asserted_only=False)
    for tok in loose:
        tok.encode("ascii")


def test_compact_refs_respects_limit():
    am = map_action("anything", source_reason="over_threshold")
    assert len(compact_refs(am, asserted_only=False, limit=2)) <= 2
