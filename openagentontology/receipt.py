"""receipt.py — Ed25519 cert-only receipt over an OntologyDoc.

A receipt is a tamper-evident, locally-verifiable record of ONE governance scan: the
ontology's deterministic content is hashed, a small signed body commits to that hash, and
the signature verifies from the cert alone -- no database, no network, no trusting us. This
is the OSS open-core leaf: it mints a SELF-signed receipt. CWN's hosted notary/registry
(not in this repo) is what adds cross-org verification on top.

Canonicalization is copied 1:1 from escape_plan_service._canon so a browser JS verifier
reproduces the Python sha256 byte-for-byte:
    _canon(obj) = json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=True)
    evidence_hash = sha256(_canon(evidence)).hexdigest()
    signature     = Ed25519.sign(_canon(body))            # body commits to evidence_hash
Everything that flows into evidence is ASCII (OntologyDoc.to_dict() is deterministic +
ASCII by the schema's discipline; validate.py fails closed on any non-ASCII), so the hash
is reproducible in any language.

SOFT crypto: if `cryptography` is missing, mint_receipt still returns a fully-formed,
hashed receipt with signature_b64="" and alg="none" and a clear "unsigned" flag -- the tool
never crashes for lack of an optional dep. verify_receipt reports unsigned receipts as
hash_ok-but-not-signed rather than silently passing.

Public:
    mint_receipt(ontology, *, decision=None, key_path=None) -> dict
    verify_receipt(receipt) -> dict   # {ok, hash_ok, sig_ok, signed, reason}

Imports stdlib + (soft) cryptography only. No import of the rest of the package; the
ontology argument is duck-typed (anything with .to_dict()), so the receipt layer does not
couple to generate/validate.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    _HAS_CRYPTO = True
except Exception:  # pragma: no cover - exercised only on a crypto-less host
    _HAS_CRYPTO = False

# Default, reproducible key location. Env-overridable so CI / a host can pin a stable key.
# A fresh ephemeral key is generated (and persisted) on first run if none exists.
_DEFAULT_KEY = os.getenv(
    "OAO_RECEIPT_KEY",
    str(Path.home() / ".openagentontology" / "receipt_ed25519.pem"))


def _canon(obj) -> str:
    """Compact canonical JSON: sorted keys, no spaces, ASCII-only. MUST match a JS verifier's
    canon() exactly (this is byte-for-byte identical to escape_plan_service._canon)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("ascii")).hexdigest()


def _load_key(key_path: str | None):
    """Load (or first-run generate+persist) the Ed25519 signing key. Returns (sk, pub_b64).
    Returns (None, "") when cryptography is unavailable -> caller mints an unsigned receipt."""
    if not _HAS_CRYPTO:
        return None, ""
    path = Path(key_path or _DEFAULT_KEY)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        sk = serialization.load_pem_private_key(path.read_bytes(), password=None)
    else:
        sk = ed25519.Ed25519PrivateKey.generate()
        path.write_bytes(sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    pub_b64 = base64.b64encode(sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
    return sk, pub_b64


def _ontology_dict(ontology) -> dict:
    """Duck-type the ontology to its deterministic dict. Accepts an OntologyDoc (has
    .to_dict()) or a plain dict that is already the serialized form."""
    if hasattr(ontology, "to_dict"):
        return ontology.to_dict()
    if isinstance(ontology, dict):
        return ontology
    raise TypeError("mint_receipt: ontology must expose .to_dict() or be a dict")


def _summary(odoc: dict) -> dict:
    """A tiny, ASCII, deterministic header carried alongside the full ontology in evidence,
    so a human reading the receipt sees the shape without parsing the whole graph."""
    action_maps = odoc.get("action_maps", [])
    governed = len(action_maps)
    asserted = sum(
        1 for am in action_maps
        if any(m.get("confidence") == "asserted" for m in am.get("mappings", [])))
    ungoverned = sum(1 for am in action_maps if am.get("matched_via") == "none")
    return {
        "source": odoc.get("source", ""),
        "source_kind": odoc.get("source_kind", ""),
        "nodes": len(odoc.get("nodes", [])),
        "edges": len(odoc.get("edges", [])),
        "governed_actions": governed,
        "asserted_covered": asserted,
        "ungoverned_actions": ungoverned,
        "frameworks": list(odoc.get("frameworks", [])),
    }


def mint_receipt(ontology, *, decision: str | None = None,
                 key_path: str | None = None) -> dict:
    """Mint an Ed25519 cert-only receipt over an OntologyDoc (or its to_dict()).

    decision  optional verdict string carried in the body (defaults to "ONTOLOGY_DERIVED").
    key_path  optional override of the signing key location (defaults to OAO_RECEIPT_KEY).

    Returns a JSON-safe, ASCII-only dict:
      atom_id, type, decision, evidence_hash, signed_at, evidence,
      alg, signature_b64, verify_pubkey_b64, signed (bool), note_pq
    The signature is over _canon(body); evidence_hash is sha256(_canon(evidence)); both
    reproduce in a browser verifier. If cryptography is absent: alg="none", signature_b64="",
    signed=False -- still hash-verifiable, clearly flagged as unsigned.
    """
    odoc = _ontology_dict(ontology)
    when = datetime.now(timezone.utc).isoformat()

    # evidence = the full deterministic ontology + a compact summary header. Both ASCII.
    evidence = {"summary": _summary(odoc), "ontology": odoc}
    evidence_hash = _sha256(_canon(evidence))

    # short, stable atom id from the source + hash prefix (deterministic, ASCII).
    src_tag = "".join(c for c in str(odoc.get("source", "")).upper()
                      if c.isalnum())[:12] or "ONTOLOGY"
    atom_id = f"oao-{src_tag}-{evidence_hash[:10]}"

    body = {
        "atom_id": atom_id,
        "type": "AgentGovernanceReceipt",
        "decision": decision or "ONTOLOGY_DERIVED",
        "evidence_hash": evidence_hash,
        "signed_at": when,
    }

    sk, pub_b64 = _load_key(key_path)
    if sk is not None:
        sig = base64.b64encode(sk.sign(_canon(body).encode("ascii"))).decode("ascii")
        alg, signed = "Ed25519", True
    else:
        sig, alg, signed = "", "none", False

    return {
        **body,
        "evidence": evidence,
        "alg": alg,
        "signature_b64": sig,
        "verify_pubkey_b64": pub_b64,
        "signed": signed,
        "note_pq": "Hosted CWN notary receipts add ML-DSA-65 (NIST FIPS 204) over the same hash.",
    }


def verify_receipt(receipt: dict) -> dict:
    """Re-check a receipt from the cert alone. Returns:
      {ok, hash_ok, sig_ok, signed, reason}

    hash_ok  recomputed sha256(_canon(evidence)) == receipt.evidence_hash
    sig_ok   Ed25519 verify of receipt.signature_b64 over _canon(body) with verify_pubkey_b64
    signed   whether the receipt claims a real signature (alg == "Ed25519")
    ok       hash_ok AND (sig_ok if signed else True)  -- an unsigned receipt can still be
             hash-valid; ok stays True but `signed` flags that it carries no cryptographic proof.
    """
    out = {"ok": False, "hash_ok": False, "sig_ok": False,
           "signed": False, "reason": ""}
    if not isinstance(receipt, dict):
        out["reason"] = "receipt is not a dict"
        return out

    evidence = receipt.get("evidence")
    claimed = receipt.get("evidence_hash", "")
    if evidence is None or not claimed:
        out["reason"] = "missing evidence or evidence_hash"
        return out

    out["hash_ok"] = (_sha256(_canon(evidence)) == claimed)
    if not out["hash_ok"]:
        out["reason"] = "evidence_hash mismatch -- evidence was altered"
        return out

    alg = receipt.get("alg", "none")
    sig_b64 = receipt.get("signature_b64", "")
    pub_b64 = receipt.get("verify_pubkey_b64", "")
    out["signed"] = (alg == "Ed25519" and bool(sig_b64) and bool(pub_b64))

    if not out["signed"]:
        # hash is valid but there is no cryptographic proof of origin.
        out["ok"] = True
        out["reason"] = "hash valid; receipt is UNSIGNED (no Ed25519 signature present)"
        return out

    if not _HAS_CRYPTO:
        out["reason"] = "cannot verify signature: cryptography not installed on this host"
        return out

    # body = the receipt minus evidence + the non-signed envelope fields. MUST be the exact
    # dict that was signed in mint_receipt (atom_id/type/decision/evidence_hash/signed_at).
    body = {k: receipt[k] for k in
            ("atom_id", "type", "decision", "evidence_hash", "signed_at") if k in receipt}
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(sig_b64), _canon(body).encode("ascii"))
        out["sig_ok"] = True
        out["ok"] = True
        out["reason"] = "hash valid and Ed25519 signature verified from the cert alone"
    except Exception as exc:  # InvalidSignature or malformed key/sig
        out["sig_ok"] = False
        out["reason"] = f"signature verification FAILED: {type(exc).__name__}"
    return out
