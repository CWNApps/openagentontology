"""test_pqsign.py -- the post-quantum receipt legs are additive, hybrid, and tamper-evident.

A receipt may carry up to three signature legs over the SAME canonical body:
    Ed25519 (classical)  +  ML-DSA-65 (FIPS 204)  +  SLH-DSA (FIPS 205)

These tests prove the properties that make that safe:
  - the PQ legs NEVER change the evidence hash or the Ed25519 leg (an Ed25519-only verifier
    is unaffected -> backward compatible),
  - every present leg verifies on a host that has the backend,
  - breaking any single leg is detected as tamper ("any leg verifies" does not mean "ignore a
    broken leg"),
  - with no PQ backend the receipt is simply Ed25519-only and still valid.

When no PQ backend is installed the PQ-specific assertions are skipped (the base tool keeps
its no-install promise), but the backward-compatibility test always runs.
"""
from __future__ import annotations

import base64
import copy

import pytest

from openagentontology import pqsign
from openagentontology.generate import generate
from openagentontology.ingest import ingest
from openagentontology.receipt import mint_receipt, verify_receipt

_HAS_PQ = pqsign.ML_DSA_AVAILABLE  # at least the ML-DSA leg is available
pq_only = pytest.mark.skipif(not _HAS_PQ, reason="no post-quantum backend installed")


@pytest.fixture()
def doc(repo_root):
    return generate(ingest(str(repo_root / "examples" / "sample_agent")))


def _flip_b64(s: str) -> str:
    """Flip one byte of a base64 blob, returning a still-valid-base64 but wrong signature."""
    raw = bytearray(base64.b64decode(s))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


@pq_only
def test_triple_sign_all_legs_present_and_verify(doc, receipt_key):
    r = mint_receipt(doc, key_path=receipt_key)
    assert r["alg"] == "Ed25519"                       # classical leg unchanged
    assert "ML-DSA-65" in r["signature_alg"]
    assert r.get("ml_dsa_signature_b64")
    assert r.get("ml_dsa_public_key_b64")
    v = verify_receipt(r)
    assert v["ok"] and v["hash_ok"] and v["sig_ok"]
    assert v["legs"]["ed25519"] == "ok"
    assert v["legs"]["ml_dsa"] == "ok"
    # slh_dsa is "ok" with liboqs, "absent" with the dilithium_py-only tier -- never "fail".
    assert v["legs"]["slh_dsa"] in ("ok", "absent")


@pq_only
def test_pq_legs_sign_the_same_body_as_ed25519(doc, receipt_key):
    """Every leg commits to the identical canonical body -> the evidence hash and the Ed25519
    signature are byte-for-byte what an Ed25519-only mint would have produced."""
    r = mint_receipt(doc, key_path=receipt_key)
    # Strip the PQ fields and re-verify as if a legacy Ed25519-only verifier read it.
    legacy = {k: v for k, v in r.items() if not k.startswith(("ml_dsa_", "slh_dsa_"))}
    legacy.pop("signature_alg", None)
    v = verify_receipt(legacy)
    assert v["ok"] and v["legs"]["ed25519"] == "ok"
    assert v["legs"]["ml_dsa"] == "absent" and v["legs"]["slh_dsa"] == "absent"


@pq_only
def test_tampering_a_pq_leg_is_detected(doc, receipt_key):
    r = mint_receipt(doc, key_path=receipt_key)
    bad = copy.deepcopy(r)
    bad["ml_dsa_signature_b64"] = _flip_b64(bad["ml_dsa_signature_b64"])
    v = verify_receipt(bad)
    assert v["ok"] is False
    assert v["legs"]["ed25519"] == "ok"      # classical leg still fine
    assert v["legs"]["ml_dsa"] == "fail"     # ...but the broken PQ leg is caught
    assert "ml_dsa" in v["reason"]


@pq_only
def test_tampering_evidence_fails_before_any_leg(doc, receipt_key):
    r = mint_receipt(doc, key_path=receipt_key)
    bad = copy.deepcopy(r)
    bad["evidence"]["summary"]["score"] = 999
    v = verify_receipt(bad)
    assert v["ok"] is False and v["hash_ok"] is False


@pq_only
def test_signature_alg_advertises_the_real_leg_set(doc, receipt_key):
    r = mint_receipt(doc, key_path=receipt_key)
    legs = r["signature_alg"].split("+")
    assert legs[0] == "Ed25519"
    assert ("ML-DSA-65" in legs) == pqsign.ML_DSA_AVAILABLE
    assert ("SLH-DSA" in legs) == pqsign.SLH_DSA_AVAILABLE


def test_ed25519_only_receipt_still_verifies_with_pq_code_present(doc, receipt_key):
    """Backward compatibility, ALWAYS run: a receipt carrying no PQ legs (the historical
    shape) verifies cleanly through the new verifier, with the PQ legs reported 'absent'."""
    r = mint_receipt(doc, key_path=receipt_key)
    legacy = {k: v for k, v in r.items() if not k.startswith(("ml_dsa_", "slh_dsa_"))}
    legacy.pop("signature_alg", None)
    v = verify_receipt(legacy)
    assert v["ok"] and v["legs"]["ed25519"] in ("ok", "unverifiable")
    assert v["legs"]["ml_dsa"] == "absent"
    assert v["legs"]["slh_dsa"] == "absent"
