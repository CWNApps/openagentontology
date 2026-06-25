"""test_sign_skill.py -- a signed OAO skill manifest is a tamper-evident, cert-only credential.

sign_skill mints a detached receipt over a skill manifest by reusing mint_receipt, so it
inherits the receipt invariants: the manifest is carried in evidence, the evidence_hash is
sha256 over the canonical manifest, and any post-signing edit breaks verification. These
tests prove the round trip, the fail-closed validator, and tamper detection -- without
re-testing the crypto itself (test_receipt.py already does that).
"""
from __future__ import annotations

import copy
import json

import pytest

from scripts.sign_skill import REQUIRED_FIELDS, sign_skill, verify_skill

VALID_MANIFEST = {
    "oao_version": "1.0",
    "skill_id": "oao-skill-test-0001",
    "name": "Test Skill",
    "description": "A signable manifest for the round-trip test.",
    "governance": {
        "requires_human_approval": False,
        "max_credentials": 1,
        "escalation_threshold": 0.75,
    },
    "trust_gate": {"attestation_required": True, "execution_count": 0},
}


def test_sign_skill_round_trips():
    receipt = sign_skill(copy.deepcopy(VALID_MANIFEST))
    res = verify_skill(receipt)
    assert res["hash_ok"] is True
    assert res["ok"] is True
    # the full manifest is carried under evidence.ontology, byte-recoverable
    assert receipt["evidence"]["ontology"]["skill_id"] == "oao-skill-test-0001"
    assert receipt["decision"] == "SKILL_REGISTRY_SIGNED"


def test_tampered_skill_is_detected():
    receipt = sign_skill(copy.deepcopy(VALID_MANIFEST))
    # an attacker loosens governance inside the signed evidence
    receipt["evidence"]["ontology"]["governance"]["requires_human_approval"] = True
    res = verify_skill(receipt)
    assert res["hash_ok"] is False
    assert res["ok"] is False
    assert "evidence_hash mismatch" in res["reason"]


def test_signature_tamper_is_detected_when_crypto_present():
    receipt = sign_skill(copy.deepcopy(VALID_MANIFEST))
    if not receipt.get("signed"):
        pytest.skip("cryptography unavailable; signature-leg tamper not exercised")
    # flip a body field that is signed but not part of the evidence hash
    receipt["decision"] = "TOTALLY_DIFFERENT"
    res = verify_skill(receipt)
    assert res["ok"] is False


@pytest.mark.parametrize("missing", list(REQUIRED_FIELDS))
def test_missing_required_field_fails_closed(missing):
    bad = copy.deepcopy(VALID_MANIFEST)
    bad.pop(missing)
    with pytest.raises(ValueError):
        sign_skill(bad)


def test_governance_without_threshold_rejected():
    bad = copy.deepcopy(VALID_MANIFEST)
    bad["governance"] = {"requires_human_approval": False}  # no escalation_threshold
    with pytest.raises(ValueError):
        sign_skill(bad)


def test_trust_gate_not_object_rejected():
    bad = copy.deepcopy(VALID_MANIFEST)
    bad["trust_gate"] = "attested"  # must be an object, not a string
    with pytest.raises(ValueError):
        sign_skill(bad)


def test_non_dict_rejected():
    with pytest.raises(ValueError):
        sign_skill(["not", "a", "manifest"])  # type: ignore[arg-type]
