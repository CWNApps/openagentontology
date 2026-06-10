"""test_mutation.py -- programmatic tamper attempts; every one must be CAUGHT.

A receipt is only worth minting if a mutated artifact cannot pass for the original. Each
test below takes one REAL pipeline run on the dogfood corpus, applies a single surgical
mutation (a fabricated control id, a fake framework, a forged matched_via claim, edited
receipt evidence, a corrupted signature leg, a smuggled non-ASCII name), and asserts the
honest layer that catches it:

    ontology mutations  -> validate() fails closed (E_FAKE_ID / E_FRAMEWORK / E_MATCHED_VIA
                           / E_NONASCII)
    evidence edits      -> verify_receipt() hash_ok False (sha256 over canonical evidence)
    body (tier) edits   -> verify_receipt() signature legs fail (the tier rides in the
                           signed body, so the signature -- not the hash -- catches it)
    signature corruption-> the corrupted leg reports 'fail' and ok is False, even when
                           another leg still verifies (one good leg never masks a bad one)

The PQ-leg test is guarded on pqsign availability so the suite stays green on an
Ed25519-only host.
"""
from __future__ import annotations

import copy
import dataclasses

import pytest

import openagentontology
from openagentontology import pqsign
from openagentontology.receipt import verify_receipt
from openagentontology.validate import validate


@pytest.fixture()
def scan(sample_dir, receipt_key):
    """One real, signed pipeline run to mutate (fresh per test -- mutations never leak)."""
    return openagentontology.run_pipeline(sample_dir, make_receipt=True, key_path=receipt_key)


# -- helpers -------------------------------------------------------------------
def _error_codes(findings):
    return {f.code for f in findings if f.level == "error"}


def _with_mutated_mapping(doc, match, **changes):
    """Copy of doc with the FIRST mapping matching `match` rebuilt with `changes`."""
    hit = False
    new_maps = []
    for am in doc.action_maps:
        if not hit:
            ms = []
            for m in am.mappings:
                if not hit and match(m):
                    m = dataclasses.replace(m, **changes)
                    hit = True
                ms.append(m)
            am = dataclasses.replace(am, mappings=tuple(ms))
        new_maps.append(am)
    assert hit, "mutation target not found -- the dogfood corpus drifted"
    return dataclasses.replace(doc, action_maps=new_maps)


def _corrupt_b64(s):
    """Flip one character mid-signature so the bytes no longer verify."""
    assert s, "expected a non-empty signature to corrupt"
    i = len(s) // 2
    return s[:i] + ("A" if s[i] != "A" else "B") + s[i + 1:]


# -- ontology mutations: validate() must fail closed ----------------------------
def test_control_id_mutated_to_ac999_fails_validation(scan):
    # AC-5 is a real asserted control on the corpus; AC-999 exists in no framework.
    doc = _with_mutated_mapping(
        scan.ontology,
        lambda m: m.id == "AC-5" and m.confidence == "asserted",
        id="AC-999")
    ok, findings = validate(doc)
    assert ok is False
    assert "E_FAKE_ID" in _error_codes(findings)


def test_framework_mutated_to_fake_nist_fails_validation(scan):
    doc = _with_mutated_mapping(
        scan.ontology,
        lambda m: m.fw == "NIST SP 800-53r5" and m.confidence == "asserted",
        fw="FAKE_NIST")
    ok, findings = validate(doc)
    assert ok is False
    assert "E_FRAMEWORK" in _error_codes(findings)


def test_forged_matched_via_with_no_mappings_fails_validation(scan):
    # Take a genuinely UNGOVERNED action and forge its matched_via to claim the asserted
    # path fired. A claim with zero mappings behind it is evidence-free and must fail closed.
    forged, new_maps = False, []
    for am in scan.ontology.action_maps:
        if not forged and am.matched_via == "none":
            am = dataclasses.replace(am, matched_via="asserted_table")
            forged = True
        new_maps.append(am)
    assert forged, "expected at least one ungoverned action in the dogfood corpus"
    doc = dataclasses.replace(scan.ontology, action_maps=new_maps)
    ok, findings = validate(doc)
    assert ok is False
    assert "E_MATCHED_VIA" in _error_codes(findings)


def test_nonascii_smuggled_into_node_name_fails_validation(scan):
    # _canon() would escape the character (the hash stays reproducible either way), so the
    # layer that actually REJECTS a smuggled non-ASCII name is the fail-closed validator.
    nodes = list(scan.ontology.nodes)
    nodes[0] = dataclasses.replace(nodes[0], name=nodes[0].name + "\u00e9")
    doc = dataclasses.replace(scan.ontology, nodes=nodes)
    ok, findings = validate(doc)
    assert ok is False
    assert "E_NONASCII" in _error_codes(findings)


# -- receipt evidence edits: the hash catches them ------------------------------
def test_receipt_edited_coverage_count_breaks_hash(scan):
    # inflate the score-bearing summary count -- the evidence hash no longer reproduces.
    rcpt = copy.deepcopy(scan.receipt)
    rcpt["evidence"]["summary"]["asserted_covered"] += 1
    v = verify_receipt(rcpt)
    assert v["hash_ok"] is False
    assert v["ok"] is False


def test_receipt_deleted_action_breaks_hash(scan):
    # silently dropping a governed action from the evidence is tamper, not housekeeping.
    rcpt = copy.deepcopy(scan.receipt)
    assert rcpt["evidence"]["ontology"]["action_maps"], "corpus must have governed actions"
    rcpt["evidence"]["ontology"]["action_maps"].pop()
    v = verify_receipt(rcpt)
    assert v["hash_ok"] is False
    assert v["ok"] is False


def test_receipt_edited_tier_claim_breaks_signature(scan):
    # the tier rides in the signed body (decision='GOVERNED:<tier>'), not in evidence --
    # so upgrading it leaves the hash intact and the SIGNATURE is what cries foul.
    rcpt = copy.deepcopy(scan.receipt)
    assert rcpt["decision"] != "GOVERNED:SOVEREIGN"
    rcpt["decision"] = "GOVERNED:SOVEREIGN"
    v = verify_receipt(rcpt)
    assert v["hash_ok"] is True
    assert v["legs"]["ed25519"] == "fail"
    assert v["ok"] is False


# -- signature corruption: the broken leg reports fail, ok is False -------------
def test_corrupt_ed25519_leg_is_reported(scan):
    rcpt = copy.deepcopy(scan.receipt)
    rcpt["signature_b64"] = _corrupt_b64(rcpt["signature_b64"])
    v = verify_receipt(rcpt)
    assert v["hash_ok"] is True              # evidence untouched
    assert v["legs"]["ed25519"] == "fail"
    assert v["ok"] is False


@pytest.mark.skipif(not pqsign.ML_DSA_AVAILABLE, reason="no ML-DSA backend on this host")
def test_corrupt_ml_dsa_leg_is_reported_even_with_good_ed25519(scan):
    # hybrid honesty: a verifying Ed25519 leg must NOT mask a broken post-quantum leg.
    rcpt = copy.deepcopy(scan.receipt)
    assert rcpt.get("ml_dsa_signature_b64"), "PQ backend present but no ML-DSA leg minted"
    rcpt["ml_dsa_signature_b64"] = _corrupt_b64(rcpt["ml_dsa_signature_b64"])
    v = verify_receipt(rcpt)
    assert v["hash_ok"] is True
    assert v["legs"]["ed25519"] == "ok"      # the classical leg still verifies...
    assert v["legs"]["ml_dsa"] == "fail"     # ...but the tampered leg is named...
    assert v["ok"] is False                  # ...and the receipt as a whole is rejected.


# -- control: the unmutated artifacts still pass --------------------------------
def test_unmutated_scan_still_validates_and_verifies(scan):
    # guards against a mutation helper that "catches" everything because the baseline
    # itself is broken: the untouched doc validates and the untouched receipt verifies.
    ok, findings = validate(scan.ontology)
    assert ok is True
    v = verify_receipt(scan.receipt)
    assert v["ok"] is True and v["hash_ok"] is True and v["sig_ok"] is True
