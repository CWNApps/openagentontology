"""test_receipt.py — the receipt is cross-language verifiable and tamper-evident.

The whole point of the cert-only receipt is that a browser JS verifier reproduces the Python
sha256 byte-for-byte. We PROVE that here without a browser: a pure-Python re-implementation
of what a correct JS verifier does --

    canon(x): recursively sort object keys, emit compact JSON (no spaces), ASCII-only --
              i.e. JSON.stringify over a key-sorted structure with no whitespace
    evidence_hash = sha256(canon(evidence))
    verify Ed25519 signature over canon(body)

If THIS independent canonicalizer reproduces the module's hash and the signature checks out,
a faithful JS implementation will too. Then: a genuine receipt verifies; any tamper (to
evidence, to the signed body, to the signature, to the key) fails.
"""
from __future__ import annotations

import base64
import hashlib
import json

import pytest

from openagentontology import OntologyDoc
from openagentontology.crosswalk import CONFIRM_NOTE
from openagentontology.generate import generate
from openagentontology.ingest import ingest
from openagentontology.receipt import mint_receipt, verify_receipt

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


# ── an independent canonicalizer == what a correct JS verifier does ───────────
def js_like_canon(obj) -> str:
    """Reproduce a faithful browser canon(): recursively sort keys, compact separators,
    ensure_ascii. This is deliberately a SEPARATE implementation from receipt._canon so the
    test proves cross-impl agreement, not that the module agrees with itself.

    A correct JS verifier does:
        function canon(x){
          if(Array.isArray(x)) return '['+x.map(canon).join(',')+']';
          if(x && typeof x==='object'){
            const k=Object.keys(x).sort();
            return '{'+k.map(j=>JSON.stringify(j)+':'+canon(x[j])).join(',')+'}';
          }
          return JSON.stringify(x);
        }
    The recursion below mirrors that exactly; Python's json.dumps with sort_keys + compact
    separators + ensure_ascii yields the identical byte string for JSON-safe data.
    """
    return json.dumps(_sort(obj), separators=(",", ":"), ensure_ascii=True)


def _sort(obj):
    if isinstance(obj, dict):
        return {k: _sort(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_sort(v) for v in obj]
    return obj


def _sha256_ascii(s: str) -> str:
    return hashlib.sha256(s.encode("ascii")).hexdigest()


@pytest.fixture()
def receipt(sample_dir, receipt_key):
    doc = generate(ingest(sample_dir))
    return mint_receipt(doc, decision="GOVERNED:TEST", key_path=receipt_key)


# ── cross-language hash agreement ─────────────────────────────────────────────
def test_independent_canon_reproduces_evidence_hash(receipt):
    recomputed = _sha256_ascii(js_like_canon(receipt["evidence"]))
    assert recomputed == receipt["evidence_hash"], \
        "a faithful JS canon() would NOT reproduce the Python evidence_hash"


def test_independent_canon_verifies_the_signed_body(receipt):
    if not _HAS_CRYPTO or not receipt.get("signed"):
        pytest.skip("cryptography not available / receipt unsigned")
    body = {k: receipt[k] for k in
            ("atom_id", "type", "decision", "evidence_hash", "signed_at")}
    pub = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.b64decode(receipt["verify_pubkey_b64"]))
    # sign was over canon(body); our independent canon must reproduce the exact signed bytes.
    pub.verify(base64.b64decode(receipt["signature_b64"]),
               js_like_canon(body).encode("ascii"))  # raises on mismatch


def test_evidence_is_pure_ascii(receipt):
    # ensure_ascii must hold for the whole receipt -> reproducible in any language.
    js_like_canon(receipt).encode("ascii")
    json.dumps(receipt, ensure_ascii=False).encode("ascii")


# ── genuine verifies ──────────────────────────────────────────────────────────
def test_genuine_receipt_verifies(receipt):
    v = verify_receipt(receipt)
    assert v["ok"] and v["hash_ok"]
    if receipt.get("signed"):
        assert v["sig_ok"], v["reason"]


# ── tamper detection ──────────────────────────────────────────────────────────
def test_tampered_evidence_fails(receipt):
    import copy
    bad = copy.deepcopy(receipt)
    # flip one node name deep inside the hashed evidence
    bad["evidence"]["ontology"]["nodes"][0]["name"] += "_TAMPERED"
    v = verify_receipt(bad)
    assert v["ok"] is False and v["hash_ok"] is False
    assert "altered" in v["reason"] or "mismatch" in v["reason"]


def test_tampered_summary_count_fails(receipt):
    import copy
    bad = copy.deepcopy(receipt)
    bad["evidence"]["summary"]["asserted_covered"] += 99  # inflate the headline number
    assert verify_receipt(bad)["hash_ok"] is False


def test_tampered_signed_body_fails(receipt):
    if not receipt.get("signed"):
        pytest.skip("unsigned receipt")
    import copy
    bad = copy.deepcopy(receipt)
    # change the decision string the body committed to, but leave evidence + hash intact.
    bad["decision"] = "GOVERNED:SOVEREIGN_FORGED"
    v = verify_receipt(bad)
    # hash still matches (evidence untouched) but the signature is over the OLD body.
    assert v["hash_ok"] is True
    assert v["sig_ok"] is False and v["ok"] is False


def test_tampered_signature_fails(receipt):
    if not receipt.get("signed"):
        pytest.skip("unsigned receipt")
    import copy
    bad = copy.deepcopy(receipt)
    raw = bytearray(base64.b64decode(bad["signature_b64"]))
    raw[0] ^= 0xFF  # corrupt one byte of the signature
    bad["signature_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    v = verify_receipt(bad)
    assert v["sig_ok"] is False and v["ok"] is False


def test_wrong_public_key_fails(receipt):
    if not _HAS_CRYPTO or not receipt.get("signed"):
        pytest.skip("cryptography not available / unsigned")
    import copy
    bad = copy.deepcopy(receipt)
    other_pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    bad["verify_pubkey_b64"] = base64.b64encode(other_pub).decode("ascii")
    v = verify_receipt(bad)
    assert v["sig_ok"] is False and v["ok"] is False


# ── soft-crypto degradation (still hash-verifiable, clearly flagged) ──────────
def test_unsigned_receipt_is_hash_valid_but_flagged():
    doc = OntologyDoc(source="x", source_kind="test",
                      nodes=[__import__("openagentontology").Node("n1", "Resource", "r")],
                      note=CONFIRM_NOTE)
    r = mint_receipt(doc)
    # simulate a crypto-less host by stripping the signature envelope
    r["alg"] = "none"
    r["signature_b64"] = ""
    r["signed"] = False
    v = verify_receipt(r)
    assert v["hash_ok"] is True
    assert v["signed"] is False
    assert v["ok"] is True  # hash is valid; absence of a signature is reported, not failed
    assert "UNSIGNED" in v["reason"].upper()


def test_non_dict_receipt_is_rejected():
    v = verify_receipt("not a receipt")
    assert v["ok"] is False
