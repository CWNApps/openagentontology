#!/usr/bin/env python3
"""Verify an OpenAgentOntology receipt. Offline. Without trusting us.

THE ONE COMMAND -- nothing to install, nothing to clone:

    curl -s https://raw.githubusercontent.com/CWNApps/openagentontology/main/verify_receipt.py | python - autogen

Already have the file?           python verify_receipt.py path/to/receipt.json
Prefer a pinned tool?            uvx --from openagentontology oao-verify autogen

One file. No install, no clone, no account, and no key of ours. Everything
needed to check a receipt is inside the receipt.

A NOTE ON "OFFLINE". Naming a scan (`autogen`) downloads that receipt from
GitHub so you do not have to find it first. The DOWNLOAD is a convenience; the
VERIFICATION is local and never contacts CWN. Point it at a local file and it
makes no network call at all. Either way, nothing you check is checked by us.

WHY THIS FILE EXISTS
--------------------
The standard objection to every "tamper-evident audit log" product is that the
vendor hosts the log, so the vendor's word is doing the work. A signed receipt
you can only verify by asking the vendor is that objection restated, not
answered.

So: this script imports nothing from OpenAgentOntology and nothing from CWN. It
reproduces the canonicalisation from the published spec, reads the public key
out of the receipt itself, and checks the signature locally. If we tampered with
a receipt after signing it, this prints FAIL. If our servers vanish tomorrow,
every receipt we ever issued still verifies.

WHAT IT CHECKS
--------------
1. evidence_hash  -- recomputed as sha256(canonical(evidence)) and compared.
                     Proves the evidence was not altered after signing.
2. Ed25519        -- over the canonical body, using the key embedded in the
                     receipt.
3. ML-DSA-65      -- NIST FIPS 204, lattice-based. Checked when present and a
                     backend is available.
4. SLH-DSA        -- NIST FIPS 205, hash-based. Survives a lattice break.

Every leg signs the SAME bytes, so any one leg verifying proves authenticity,
and any leg present-but-broken is reported as tamper rather than ignored.

EXIT CODES
    0  verified
    1  verification FAILED (tamper, or a bad signature)
    2  usage error / unreadable receipt

Requires `cryptography` for the Ed25519 leg (pip install cryptography). The PQ
legs additionally need `oqs` or `dilithium-py`; when a backend is missing the
leg is reported "unverifiable" -- never silently treated as passing.

Apache-2.0. Copyright Cyber Warrior Network.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import warnings
from typing import Any

# The PQ backend prints an import banner and a version warning on some hosts.
# This is a demo surface; noise reads as breakage.
warnings.filterwarnings("ignore")
os.environ.setdefault("OQS_DISABLE_FAULTHANDLER", "1")

# The five fields every signature leg covers. From the published spec:
# the body COMMITS to evidence_hash; the signature is over canonical(body),
# not over the hash string.
_BODY_FIELDS = ("atom_id", "type", "decision", "evidence_hash", "signed_at")

# The published OpenAgentOntology signing key. Every receipt in docs/scans is
# signed by it.
#
# WHY THIS IS PINNED HERE. Without a known key, verification proves only that a
# receipt is INTERNALLY CONSISTENT: anyone can generate a keypair, sign a
# fabricated receipt, embed their own public key, and pass. That is integrity,
# not provenance. Pinning the issuer key is what lets this tool distinguish
# "unaltered since CWN signed it" from "unaltered since SOMEBODY signed it".
#
# Cross-check it against the copy published at
# https://github.com/CWNApps/openagentontology (docs/scans/*/receipt.json) --
# and note that a verifier which took the key from the receipt alone could
# never tell you this.
_KNOWN_ISSUER_KEYS = {
    "ig6AWna3kodv7bngRvd6hJ+AbhXGznIh6dhFlA2pfPQ=": "OpenAgentOntology (CWN) scan signer",
}

_GREEN, _RED, _YELLOW, _DIM, _OFF = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _c(colour: str, text: str) -> str:
    return text if not sys.stdout.isatty() else f"{colour}{text}{_OFF}"


def _b64(value: str) -> bytes:
    """Strict base64. Permissive decoding silently DISCARDS garbage characters,
    which turns malformed signature material into a backend error (reported as
    a skip) instead of the tamper it actually is."""
    return base64.b64decode(value, validate=True)


def canonical(obj: Any) -> str:
    """Canonical JSON, byte-identical to the signer's.

    Published contract -- reproduce this in any language:
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def signed_bytes(receipt: dict) -> bytes:
    body = {k: receipt.get(k, "") for k in _BODY_FIELDS}
    return canonical(body).encode("ascii")


def check_hash(receipt: dict) -> tuple[bool, str]:
    evidence = receipt.get("evidence")
    claimed = receipt.get("evidence_hash", "")
    if evidence is None or not claimed:
        return False, "receipt carries no evidence or no evidence_hash"
    actual = hashlib.sha256(canonical(evidence).encode("ascii")).hexdigest()
    if actual != claimed:
        return False, f"evidence_hash MISMATCH - evidence was altered after signing\n" \
                      f"        claimed  {claimed}\n        computed {actual}"
    return True, "recomputed sha256 over canonical evidence matches"


def check_ed25519(receipt: dict, payload: bytes) -> tuple[str, str]:
    sig_b64 = receipt.get("signature_b64", "")
    pub_b64 = receipt.get("verify_pubkey_b64", "")
    if not sig_b64:
        return "absent", "no Ed25519 signature on this receipt"
    if not pub_b64:
        return "fail", "signature present but no embedded public key"
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError:
        return "unverifiable", "install `cryptography` to check the Ed25519 leg"
    try:
        Ed25519PublicKey.from_public_bytes(_b64(pub_b64)).verify(_b64(sig_b64), payload)
        return "ok", "signature valid over the canonical body"
    except InvalidSignature:
        return "fail", "SIGNATURE INVALID - this receipt does not match its own key"
    except Exception as exc:
        return "fail", f"malformed key or signature: {type(exc).__name__}"


def _check_pq(name: str, alg: str, sig_b64: str, pub_b64: str,
              payload: bytes) -> tuple[str, str]:
    if not sig_b64:
        return "absent", f"no {name} signature on this receipt"
    if not pub_b64:
        return "fail", f"{name} signature present but no public key"
    try:
        import oqs  # type: ignore
    except ImportError:
        return "unverifiable", f"install `oqs` (liboqs-python) to check the {name} leg"
    try:
        try:
            sig_raw, pub_raw = _b64(sig_b64), _b64(pub_b64)
        except Exception:
            # Malformed material is TAMPER, not a missing backend.
            return "fail", f"{name} signature or key is not valid base64"
        ok = oqs.Signature(alg).verify(payload, sig_raw, pub_raw)
        return ("ok", f"{name} signature valid") if ok else (
            "fail", f"{name} SIGNATURE INVALID")
    except Exception as exc:
        # Reached only with well-formed base64 and a backend present, so the
        # library rejected the material: treat as tamper. Only an ABSENT
        # backend (ImportError above) is "unverifiable". Reporting a corrupt
        # signature as a skip is how a tampered leg used to pass.
        return "fail", f"{name} verification failed ({type(exc).__name__})"


def verify(receipt: dict, *, require_known_issuer: bool = True) -> dict:
    payload = signed_bytes(receipt)
    hash_ok, hash_msg = check_hash(receipt)

    legs = {
        "Ed25519": check_ed25519(receipt, payload),
        "ML-DSA-65": _check_pq(
            "ML-DSA-65", "ML-DSA-65",
            receipt.get("ml_dsa_signature_b64", ""),
            receipt.get("ml_dsa_public_key_b64", ""), payload),
        "SLH-DSA": _check_pq(
            "SLH-DSA", "SPHINCS+-SHA2-128s-simple",
            receipt.get("slh_dsa_signature_b64", ""),
            receipt.get("slh_dsa_public_key_b64", ""), payload),
    }

    any_ok = any(status == "ok" for status, _ in legs.values())
    any_fail = any(status == "fail" for status, _ in legs.values())
    signed = any(status != "absent" for status, _ in legs.values())

    # WHO SIGNED IT. A receipt carries its own public key, so a passing
    # signature alone proves only that the receipt is unaltered since SOMEBODY
    # signed it. Anyone can generate a keypair and sign a fabrication. Matching
    # the key against a pinned issuer is what turns integrity into provenance.
    pub = receipt.get("verify_pubkey_b64", "")
    issuer = _KNOWN_ISSUER_KEYS.get(pub, "")

    # `ok` now REQUIRES a verified signature. It previously allowed
    # `not signed`, so a receipt with every signature stripped printed
    # VERIFIED on a hash match alone -- a false pass on the exact tool whose
    # job is to be un-foolable. An unsigned document is not a verified one.
    integrity_ok = hash_ok and not any_fail and any_ok

    # DEFAULT: an unknown signing key is NOT a pass.
    #
    # Integrity alone is a trap in a security tool. A forged receipt signed with
    # an attacker-generated key is perfectly self-consistent -- it passes every
    # hash and signature check -- so printing VERIFIED and exiting 0 would hand
    # a CI job a green light on a fabrication. Provenance is part of the verdict
    # unless the caller explicitly opts out with --any-issuer.
    ok = integrity_ok and (bool(issuer) or not require_known_issuer)
    return {"ok": ok, "integrity_ok": integrity_ok,
            "require_known_issuer": require_known_issuer,
            "hash_ok": hash_ok, "hash_msg": hash_msg,
            "legs": legs, "signed": signed, "any_ok": any_ok,
            "any_fail": any_fail, "issuer": issuer, "pubkey": pub}


def render(receipt: dict, result: dict, fetched: bool = False) -> None:
    atom = receipt.get("atom_id", "(no atom_id)")
    decision = receipt.get("decision", "")
    print(f"\n  receipt   {atom}")
    if decision:
        print(f"  decision  {decision}")
    print()

    mark = _c(_GREEN, "PASS") if result["hash_ok"] else _c(_RED, "FAIL")
    print(f"  [{mark}] evidence hash   {result['hash_msg']}")

    for leg, (status, msg) in result["legs"].items():
        label = {
            "ok": _c(_GREEN, "PASS"), "fail": _c(_RED, "FAIL"),
            "absent": _c(_DIM, "  -- "), "unverifiable": _c(_YELLOW, "SKIP"),
        }[status]
        print(f"  [{label}] {leg:<15} {msg}")

    print()
    # Who signed it -- stated on every run, pass or fail.
    if result["issuer"]:
        print(f"  [{_c(_GREEN, 'PASS')}] issuer          key matches {result['issuer']}")
    elif result["pubkey"]:
        print(f"  [{_c(_YELLOW, 'WARN')}] issuer          signed by an UNKNOWN key "
              f"({result['pubkey'][:16]}...) - integrity only, provenance NOT established")
    print()

    how = ("downloaded from GitHub, then verified locally"
           if fetched else "verified locally, no network call")

    if result["ok"] and result["issuer"]:
        print(_c(_GREEN, "  VERIFIED") + f" - {how}.")
        print("  Unaltered since it was signed by the published "
              "OpenAgentOntology key.")
        print("  Checked on your machine. No CWN server was contacted or trusted.")
    elif result["ok"]:
        # --any-issuer was passed: integrity holds, provenance was not required.
        print(_c(_YELLOW, "  INTEGRITY ONLY") + f" - {how}.")
        print("  Unaltered since signing, but the key is NOT a known issuer key.")
        print("  Anyone can sign their own receipt. This is not proof of origin.")
    elif result["integrity_ok"] and not result["issuer"]:
        print(_c(_RED, "  NOT VERIFIED") + " - signed by an UNKNOWN key.")
        print("  The receipt is internally consistent, but a self-signed "
              "document proves")
        print("  nothing about who produced it. Re-run with --any-issuer to "
              "check integrity alone.")
    elif not result["any_ok"] and not result["any_fail"]:
        print(_c(_RED, "  NOT VERIFIED") + " - this receipt carries NO signature. "
              "A hash alone")
        print("  proves nothing about who produced it. Treat it as untrusted.")
    else:
        print(_c(_RED, "  NOT VERIFIED") + " - this receipt does not check out. "
              "Treat it as untrusted.")
    print()


# Pinned so a copy-pasted command cannot be redirected somewhere else. The
# receipt is fetched from GitHub, never from a CWN server -- CWN is not in the
# trust path even when the file is downloaded.
_RAW_BASE = "https://raw.githubusercontent.com/CWNApps/openagentontology/main/docs/scans"


def _assert_pinned_host(url: str) -> None:
    """Exact-host check. A prefix match is NOT host pinning: both
    `https://raw.githubusercontent.com.evil.com/` and
    `https://raw.githubusercontent.com@evil.com/` satisfy startswith()."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com":
        raise ValueError(
            f"refusing to fetch from {parsed.hostname or url!r} -- "
            "only https://raw.githubusercontent.com is allowed"
        )


def _fetch(name: str) -> dict:
    """Resolve a scan name (or a raw.githubusercontent URL) to a receipt."""
    import urllib.request

    url = name if name.startswith("https://") else f"{_RAW_BASE}/{name}/receipt.json"
    _assert_pinned_host(url)

    # Redirects are re-validated. Checking only the initial URL is not host
    # pinning: urllib follows 3xx by default, so a redirect could land the
    # fetch on any host while the original string still looked correct.
    class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            _assert_pinned_host(newurl)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(_PinnedRedirect)
    with opener.open(url, timeout=20) as resp:  # noqa: S310 - host pinned above
        return json.loads(resp.read().decode("utf-8"))


def load(source: str) -> tuple[dict, bool]:
    """Returns (receipt, fetched_over_network)."""
    if source == "-":
        return json.load(sys.stdin), False
    # A bare name like `autogen` (no path separator, no .json) means "fetch the
    # published scan by that name" -- the lowest-friction path for someone who
    # just wants to check our claim without hunting for a file first.
    # A bare token is treated as a scan name ONLY if it looks like one. Without
    # the charset check, a typo'd or missing local filename silently turns into
    # a network request for a scan of that name -- the user asked for a file and
    # got a download.
    looks_like_a_name = (
        not os.path.exists(source)
        and not source.endswith(".json")
        and "/" not in source
        and "\\" not in source
        and "." not in source
        and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", source))
    )
    if source.startswith("https://") or looks_like_a_name:
        return _fetch(source), True
    with open(source, encoding="utf-8") as fh:
        return json.load(fh), False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="verify_receipt.py",
        description="Verify an OpenAgentOntology receipt offline, without trusting the issuer.",
        epilog="Exit 0 verified | 1 verification failed | 2 usage error",
    )
    ap.add_argument(
        "receipt",
        help="a scan name (e.g. autogen), a path to receipt.json, a "
             "raw.githubusercontent URL, or '-' for stdin",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--any-issuer", action="store_true",
        help="accept a receipt signed by an unknown key (integrity only, NOT "
             "proof of origin). Off by default so a forged receipt cannot exit 0.",
    )
    args = ap.parse_args(argv)

    try:
        receipt, fetched = load(args.receipt)
    except FileNotFoundError:
        print(f"error: no such file: {args.receipt}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: not valid JSON: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: could not read receipt ({type(exc).__name__}: {exc})", file=sys.stderr)
        print("hint: try a scan name such as `autogen`, or a path to receipt.json",
              file=sys.stderr)
        return 2
    if not isinstance(receipt, dict):
        print("error: receipt must be a JSON object", file=sys.stderr)
        return 2

    result = verify(receipt, require_known_issuer=not args.any_issuer)

    if args.json:
        print(json.dumps({
            "ok": result["ok"],
            "atom_id": receipt.get("atom_id", ""),
            "hash_ok": result["hash_ok"],
            "fetched_over_network": fetched,
            "issuer": result["issuer"] or None,
            "issuer_known": bool(result["issuer"]),
            "integrity_ok": result["integrity_ok"],
            "legs": {k: v[0] for k, v in result["legs"].items()},
        }, indent=2))
    else:
        render(receipt, result, fetched=fetched)

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
