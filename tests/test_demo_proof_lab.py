"""test_demo_proof_lab.py -- the Proof Lab demo verifies the SHIPPED scan artifacts.

demo/index.html fetches docs/scans/open-interpreter/{receipt.json, graph_resolutions.json}
at relative paths and verifies the receipt in the browser. These tests pin the contract the
page depends on: the shipped receipt's evidence_hash reproduces under the same canon() a
faithful JS verifier uses, the Ed25519 leg verifies, the PQ legs are present and decodable,
and the page itself carries every Proof Lab module with its honest labels intact.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCAN = ROOT / "docs" / "scans" / "open-interpreter"
DEMO = ROOT / "demo" / "index.html"

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover
    _HAS_CRYPTO = False


def _canon(obj) -> str:
    # same contract as tests/test_receipt.py js_like_canon: key-sorted, compact, ASCII.
    def _sort(o):
        if isinstance(o, dict):
            return {k: _sort(o[k]) for k in sorted(o.keys())}
        if isinstance(o, list):
            return [_sort(v) for v in o]
        return o
    return json.dumps(_sort(obj), separators=(",", ":"), ensure_ascii=True)


@pytest.fixture(scope="module")
def shipped_receipt():
    return json.loads((SCAN / "receipt.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def demo_html():
    return DEMO.read_text(encoding="utf-8")


# -- the shipped artifact the page verifies is itself genuine ------------------
def test_shipped_receipt_hash_reproduces(shipped_receipt):
    recomputed = hashlib.sha256(
        _canon(shipped_receipt["evidence"]).encode("ascii")).hexdigest()
    assert recomputed == shipped_receipt["evidence_hash"], \
        "the demo's fetch target would FAIL its own in-browser hash check"


def test_shipped_receipt_ed25519_verifies(shipped_receipt):
    if not _HAS_CRYPTO or not shipped_receipt.get("signed"):
        pytest.skip("cryptography not available / receipt unsigned")
    body = {k: shipped_receipt[k] for k in
            ("atom_id", "type", "decision", "evidence_hash", "signed_at")}
    pub = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.b64decode(shipped_receipt["verify_pubkey_b64"]))
    pub.verify(base64.b64decode(shipped_receipt["signature_b64"]),
               _canon(body).encode("ascii"))  # raises on mismatch


def test_shipped_pq_legs_present_and_decodable(shipped_receipt):
    assert shipped_receipt["signature_alg"] == "Ed25519+ML-DSA-65+SLH-DSA"
    for leg in ("ml_dsa_signature_b64", "ml_dsa_public_key_b64",
                "slh_dsa_signature_b64", "slh_dsa_public_key_b64"):
        raw = base64.b64decode(shipped_receipt[leg])
        assert len(raw) > 0, f"{leg} did not decode to bytes"


def test_shipped_graph_resolutions_shape():
    g = json.loads((SCAN / "graph_resolutions.json").read_text(encoding="utf-8"))
    assert g["graph_snapshot_hash"] and g["resolutions"], "demo table would render empty"
    assert g["receipt"]["signature_alg"] == "Ed25519+ML-DSA-65+SLH-DSA"
    for r in g["resolutions"]:
        # GRAPH_INFERRED only -- the demo banner promises nothing here is ASSERTED.
        assert r["mapping_confidence"].startswith("GRAPH_INFERRED"), r["action"]


# -- the page carries every Proof Lab module with honest labels ----------------
def test_demo_page_has_proof_lab_modules(demo_html):
    for marker in (
        'id="verify"', 'id="tamper"', 'id="gms"', 'id="projected"',
        '../docs/scans/open-interpreter/receipt.json',
        '../docs/scans/open-interpreter/graph_resolutions.json',
        "GRAPH_INFERRED by the hosted CWN Graph Model Service",
        "hash verified; signature requires a runtime with WebCrypto Ed25519",
        "post-quantum legs verify offline via the CLI (FIPS 204/205); browsers cannot yet",
        "PROJECTED",
        "evidence_hash mismatch",
    ):
        assert marker in demo_html, f"Proof Lab marker missing: {marker}"


def test_demo_page_proof_lab_script_is_ascii(demo_html):
    scripts = re.findall(r"<script>(.*?)</script>", demo_html, re.S)
    lab = [s for s in scripts if "OAO PROOF LAB" in s]
    assert len(lab) == 1
    lab[0].encode("ascii")  # raises if any non-ASCII slipped into the verifier code


def test_demo_page_no_internal_terms(demo_html):
    # public-repo discipline: the hosted layer is named ONLY
    # "CWN Graph Model Service (hosted)" and no internal vocabulary leaks.
    banned = ("_service.py", "Neo4j", "neo4j", "Aura")
    low = demo_html
    for term in banned:
        assert term not in low, f"banned term in public demo: {term}"
    # "quantum" only ever as "post-quantum"
    for m in re.finditer(r"(?i)quantum", demo_html):
        prefix = demo_html[max(0, m.start() - 5):m.start()].lower()
        assert prefix.endswith("post-"), "bare 'quantum' in public demo"
