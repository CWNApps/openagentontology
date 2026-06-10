"""verify_receipts.py -- re-verify every receipt committed to this repo, from the certs alone.

Run from the repo root:

    PYTHONPATH=. python scripts/verify_receipts.py

Checks, and exits nonzero if ANY fails:

  docs/scans/open-interpreter/receipt.json   full verify (hash recompute + signature legs)
  docs/scans/gpt-engineer/receipt.json       full verify (hash recompute + signature legs)
  docs/scans/open-interpreter/graph_resolutions.json
      the embedded CWN Graph Model Service (hosted) receipt: STRUCTURAL check only. Its
      evidence lives on the hosted side, so the hash cannot be recomputed from this repo;
      we confirm the receipt shape and that all three signature legs (Ed25519 + ML-DSA-65
      + SLH-DSA) are present, and we never pretend a structural check is a verification.

No network, no database, no trusting us -- the full verifies use receipt.verify_receipt,
which recomputes sha256 over canonical(evidence) and checks each signature leg it can.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from openagentontology.receipt import verify_receipt

ROOT = Path(__file__).resolve().parent.parent
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

FULL_VERIFY = [
    ROOT / "docs" / "scans" / "open-interpreter" / "receipt.json",
    ROOT / "docs" / "scans" / "gpt-engineer" / "receipt.json",
]
GMS_WRAPPER = ROOT / "docs" / "scans" / "open-interpreter" / "graph_resolutions.json"

# Every leg the hosted receipt must carry: (signature field, public key field).
_GMS_LEGS = [
    ("Ed25519", "signature_b64", "verify_pubkey_b64"),
    ("ML-DSA-65", "ml_dsa_signature_b64", "ml_dsa_public_key_b64"),
    ("SLH-DSA", "slh_dsa_signature_b64", "slh_dsa_public_key_b64"),
]
_GMS_REQUIRED = ["atom_id", "type", "evidence_hash", "signed_at", "signature_alg"]


def check_full(path: Path) -> bool:
    """Full offline verify of a committed receipt. True iff hash + signatures hold."""
    receipt = json.loads(path.read_text(encoding="ascii"))
    result = verify_receipt(receipt)
    ok = bool(result["ok"]) and bool(result["hash_ok"]) and bool(result["sig_ok"])
    legs = ",".join(f"{k}={v}" for k, v in result.get("legs", {}).items())
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {path.relative_to(ROOT)}  legs[{legs}]  {result['reason']}")
    return ok


def check_gms_structure(path: Path) -> bool:
    """Structural check of the hosted-receipt wrapper: shape + all three legs present.
    NOT a cryptographic verify -- the evidence is not in this repo (and we say so)."""
    problems = []
    wrapper = json.loads(path.read_text(encoding="ascii"))
    receipt = wrapper.get("receipt")
    if not isinstance(receipt, dict):
        problems.append("no 'receipt' object in wrapper")
        receipt = {}
    for key in _GMS_REQUIRED:
        if not receipt.get(key):
            problems.append(f"missing/empty field: {key}")
    eh = receipt.get("evidence_hash", "")
    if eh and not _HEX64.match(eh):
        problems.append("evidence_hash is not a 64-char lowercase sha256 hex digest")
    for name, sig_key, pub_key in _GMS_LEGS:
        if not (receipt.get(sig_key) and receipt.get(pub_key)):
            problems.append(f"signature leg absent: {name} ({sig_key}/{pub_key})")
    ok = not problems
    status = "PASS" if ok else "FAIL"
    detail = "structure + 3 legs present (hosted evidence; hash not recomputable here)" \
        if ok else "; ".join(problems)
    print(f"[{status}] {path.relative_to(ROOT)} (structural)  {detail}")
    return ok


def main() -> int:
    results = [check_full(p) for p in FULL_VERIFY]
    results.append(check_gms_structure(GMS_WRAPPER))
    if all(results):
        print(f"all {len(results)} receipt check(s) passed")
        return 0
    print("RECEIPT VERIFICATION FAILED", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
