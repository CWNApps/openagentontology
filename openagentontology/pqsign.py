"""pqsign.py -- optional post-quantum signing legs for OAO receipts.

A receipt's authenticity should outlive the cryptography that signed it. An Ed25519
signature is fast and small, but a sufficiently large quantum computer breaks it, and an
adversary can *harvest now, decrypt later*: store today's receipt, forge it the day the
curve falls. So this module adds two NIST post-quantum signature legs over the SAME bytes
the Ed25519 leg signs, giving the receipt a hybrid triple-signature:

    leg 1  Ed25519                  classical, ~3ms, always present (in receipt.py)
    leg 2  ML-DSA-65    FIPS 204    lattice, NIST Level 3 (~AES-192)
    leg 3  SLH-DSA-128s  FIPS 205   hash-based -- survives a lattice break (diversity leg)

Everything here is OPTIONAL and SOFT. The base tool keeps its "no install step" promise:
with neither backend installed the receipt is Ed25519-only, exactly as before. Install the
extra to turn the PQ legs on:

    pip install "openagentontology[pq]"     # dilithium_py  -> adds ML-DSA-65
    pip install liboqs-python               # liboqs        -> adds ML-DSA-65 + SLH-DSA

Three-tier degradation, resolved once at import:

    tier 1  liboqs        -> Ed25519 + ML-DSA-65 + SLH-DSA   (full triple-sign)
    tier 2  dilithium_py  -> Ed25519 + ML-DSA-65             (dual-sign, no hash-based leg)
    tier 3  neither       -> Ed25519                          (classical only)

The PQ legs are ADDITIVE: they sign the identical canonical body the Ed25519 leg signs, are
written to NEW receipt fields, and never alter the evidence hash or the Ed25519 body. An
older Ed25519-only receipt therefore still verifies unchanged, and a verifier that has no PQ
backend simply skips the PQ legs (it can still check Ed25519 and the hash). No target code is
executed and there is no network here -- this is local signing of bytes, nothing else.
"""
from __future__ import annotations

import base64
import contextlib
import io
import os
import threading
from pathlib import Path

# ----------------------------------------------------------------------------------------
# Backend detection: liboqs (tier 1) preferred, dilithium_py (tier 2) fallback, else none.
# Resolved exactly once at import so signing/verifying is a branch-free hot path.
# ----------------------------------------------------------------------------------------

_BACKEND = "none"
_ML_DSA_ALG = "ML-DSA-65"                 # FIPS 204 standardized name
_SLH_DSA_ALG = "SPHINCS+-SHA2-128s-simple"  # liboqs's name for SLH-DSA-SHA2-128s (FIPS 205)
ML_DSA_AVAILABLE = False
SLH_DSA_AVAILABLE = False

# Set OAO_SKIP_LIBOQS=1 to bypass the native lib (e.g. CI without the C toolchain) and let
# the pure-Python dilithium_py tier take over.
if os.environ.get("OAO_SKIP_LIBOQS") == "1":
    oqs = None  # type: ignore[assignment]
else:
    try:
        # liboqs prints a "faulthandler is disabled" banner to stdout on import; muffle it so
        # it can never pollute the CLI's JSON output. Diagnostic only, safe to drop.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            import oqs  # type: ignore[import-untyped]
        try:
            _enabled = set(oqs.get_enabled_sig_mechanisms())
        except Exception:
            _enabled = set()
        if "ML-DSA-65" in _enabled:
            _ML_DSA_ALG = "ML-DSA-65"
        elif "Dilithium3" in _enabled:      # older liboqs builds: round-3 alias
            _ML_DSA_ALG = "Dilithium3"
        else:
            _ML_DSA_ALG = ""
        if _ML_DSA_ALG:
            _BACKEND = "liboqs"
            ML_DSA_AVAILABLE = True
            SLH_DSA_AVAILABLE = _SLH_DSA_ALG in _enabled
        else:
            oqs = None  # type: ignore[assignment]
    except (ImportError, SystemExit, OSError, RuntimeError):
        oqs = None  # type: ignore[assignment]

if _BACKEND == "none":
    try:
        from dilithium_py.ml_dsa import ML_DSA_65 as _ML_DSA_65  # type: ignore[import-untyped]
        _BACKEND = "dilithium_py"
        ML_DSA_AVAILABLE = True
    except ImportError:
        _ML_DSA_65 = None  # type: ignore[assignment]

# dilithium_py is pure-Python and not re-entrant; serialize its calls. liboqs is thread-safe.
_ml_lock = threading.Lock() if _BACKEND == "dilithium_py" else None
_key_lock = threading.Lock()
_ml_keys: dict[str, tuple[bytes, bytes]] = {}
_slh_keys: dict[str, tuple[bytes, bytes]] = {}


def backend() -> str:
    """Active PQ backend name: 'liboqs', 'dilithium_py', or 'none'. For diagnostics."""
    return _BACKEND


def signature_alg() -> str:
    """The hybrid algorithm-set string this host can produce, e.g.
    'Ed25519+ML-DSA-65+SLH-DSA'. Ed25519 is assumed present (the receipt's primary leg)."""
    legs = ["Ed25519"]
    if ML_DSA_AVAILABLE:
        legs.append("ML-DSA-65")
    if SLH_DSA_AVAILABLE:
        legs.append("SLH-DSA")
    return "+".join(legs)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# ----------------------------------------------------------------------------------------
# ML-DSA-65 (FIPS 204)
# ----------------------------------------------------------------------------------------

def _load_ml_dsa(base: str) -> tuple[bytes, bytes]:
    """Load or first-run generate+persist an ML-DSA-65 keypair beside the Ed25519 key.
    Sidecars: {base}.mldsa.pk / {base}.mldsa.sk. Returns (pk, sk) or (b'', b'')."""
    if not ML_DSA_AVAILABLE:
        return b"", b""
    hit = _ml_keys.get(base)
    if hit is not None:
        return hit
    with _key_lock:
        hit = _ml_keys.get(base)
        if hit is not None:
            return hit
        pk_p, sk_p = base + ".mldsa.pk", base + ".mldsa.sk"
        Path(base).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(pk_p) and os.path.exists(sk_p):
            pk, sk = Path(pk_p).read_bytes(), Path(sk_p).read_bytes()
        else:
            if _BACKEND == "liboqs":
                signer = oqs.Signature(_ML_DSA_ALG)
                pk = signer.generate_keypair()
                sk = signer.export_secret_key()
            else:
                pk, sk = _ML_DSA_65.keygen()  # type: ignore[union-attr]
            Path(pk_p).write_bytes(pk)
            Path(sk_p).write_bytes(sk)
        _ml_keys[base] = (pk, sk)
        return pk, sk


def sign_ml_dsa(base: str, payload: bytes) -> tuple[str, str]:
    """Sign payload with ML-DSA-65. Returns (signature_b64, public_key_b64) or ('','')."""
    if not ML_DSA_AVAILABLE:
        return "", ""
    pk, sk = _load_ml_dsa(base)
    if not sk:
        return "", ""
    if _BACKEND == "liboqs":
        sig = oqs.Signature(_ML_DSA_ALG, secret_key=sk).sign(payload)
    else:
        with _ml_lock:  # type: ignore[union-attr]
            sig = _ML_DSA_65.sign(sk, payload)  # type: ignore[union-attr]
    return _b64(sig), _b64(pk)


def verify_ml_dsa(public_key_b64: str, payload: bytes, signature_b64: str) -> bool:
    """Verify an ML-DSA-65 signature. False if unavailable or malformed (never raises)."""
    if not (ML_DSA_AVAILABLE and public_key_b64 and signature_b64):
        return False
    try:
        pk = base64.b64decode(public_key_b64)
        sig = base64.b64decode(signature_b64)
    except Exception:
        return False
    try:
        if _BACKEND == "liboqs":
            return bool(oqs.Signature(_ML_DSA_ALG).verify(payload, sig, pk))
        with _ml_lock:  # type: ignore[union-attr]
            return bool(_ML_DSA_65.verify(pk, payload, sig))  # type: ignore[union-attr]
    except Exception:
        return False


# ----------------------------------------------------------------------------------------
# SLH-DSA-SHA2-128s (FIPS 205) -- liboqs only (the hash-based diversity leg)
# ----------------------------------------------------------------------------------------

def _load_slh_dsa(base: str) -> tuple[bytes, bytes]:
    if not SLH_DSA_AVAILABLE:
        return b"", b""
    hit = _slh_keys.get(base)
    if hit is not None:
        return hit
    with _key_lock:
        hit = _slh_keys.get(base)
        if hit is not None:
            return hit
        pk_p, sk_p = base + ".slhdsa.pk", base + ".slhdsa.sk"
        Path(base).parent.mkdir(parents=True, exist_ok=True)
        if os.path.exists(pk_p) and os.path.exists(sk_p):
            pk, sk = Path(pk_p).read_bytes(), Path(sk_p).read_bytes()
        else:
            signer = oqs.Signature(_SLH_DSA_ALG)
            pk = signer.generate_keypair()
            sk = signer.export_secret_key()
            Path(pk_p).write_bytes(pk)
            Path(sk_p).write_bytes(sk)
        _slh_keys[base] = (pk, sk)
        return pk, sk


def sign_slh_dsa(base: str, payload: bytes) -> tuple[str, str]:
    """Sign payload with SLH-DSA-SHA2-128s. Returns (signature_b64, public_key_b64) or ('','')."""
    if not SLH_DSA_AVAILABLE:
        return "", ""
    pk, sk = _load_slh_dsa(base)
    if not sk:
        return "", ""
    sig = oqs.Signature(_SLH_DSA_ALG, secret_key=sk).sign(payload)
    return _b64(sig), _b64(pk)


def verify_slh_dsa(public_key_b64: str, payload: bytes, signature_b64: str) -> bool:
    """Verify an SLH-DSA signature. False if unavailable or malformed (never raises)."""
    if not (SLH_DSA_AVAILABLE and public_key_b64 and signature_b64):
        return False
    try:
        pk = base64.b64decode(public_key_b64)
        sig = base64.b64decode(signature_b64)
    except Exception:
        return False
    try:
        return bool(oqs.Signature(_SLH_DSA_ALG).verify(payload, sig, pk))
    except Exception:
        return False


def clear_key_cache() -> None:
    """Drop cached keypairs (test fixtures use this between temp key dirs)."""
    with _key_lock:
        _ml_keys.clear()
        _slh_keys.clear()
