"""sign_skill.py -- sign an OAO skill manifest into a ver-from-cert receipt.

The supply-chain gap this closes: agent skill manifests (skill.md / skill.json) ship
unsigned, so a runtime loads them with no way to prove the manifest it executes is the one
the author published. This tool mints a detached Ed25519 receipt OVER a skill manifest, so
any loader can verify -- from the cert alone, no network, no database -- that the manifest
is intact and authored by the holder of the signing key.

It is a thin wrapper on the repo's own receipt primitive: a skill manifest is just a dict,
and `mint_receipt` already hashes a canonical, ASCII, deterministic body, signs it with
Ed25519, and adds the ML-DSA-65 / SLH-DSA post-quantum legs when a PQ backend is installed.
So a signed skill inherits every property a governance receipt has, including offline
verification and tamper detection. No new crypto, no new canon -- one source of truth.

Fail-closed: a manifest missing the OAO skill-required fields is rejected before signing,
never silently signed into a malformed credential.

Run from the repo root:

    PYTHONPATH=. python scripts/sign_skill.py sign   examples/skill/sample_skill.json
    PYTHONPATH=. python scripts/sign_skill.py verify examples/skill/sample_skill.receipt.json

Public API (importable):
    sign_skill(manifest: dict, *, key_path=None) -> dict   # the detached receipt
    verify_skill(receipt: dict) -> dict                    # {ok, hash_ok, sig_ok, ...}
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from openagentontology.receipt import mint_receipt, verify_receipt

# The OAO skill manifest fields a credential must carry to be signable. A manifest missing
# any of these is not a skill we will vouch for -- reject before signing (fail closed).
REQUIRED_FIELDS = ("oao_version", "skill_id", "name", "governance", "trust_gate")
SKILL_DECISION = "SKILL_REGISTRY_SIGNED"


def _require_skill_fields(manifest: dict) -> None:
    if not isinstance(manifest, dict):
        raise ValueError("skill manifest must be a JSON object")
    missing = [f for f in REQUIRED_FIELDS if f not in manifest]
    if missing:
        raise ValueError(
            "manifest is not a signable OAO skill: missing required field(s): "
            + ", ".join(missing))
    gov = manifest.get("governance")
    if not isinstance(gov, dict) or "escalation_threshold" not in gov:
        raise ValueError("manifest.governance must be an object with an escalation_threshold")
    if not isinstance(manifest.get("trust_gate"), dict):
        raise ValueError("manifest.trust_gate must be an object")


def sign_skill(manifest: dict, *, key_path: str | None = None) -> dict:
    """Mint a detached receipt over an OAO skill manifest.

    The manifest is carried, in full, as the receipt's evidence; the receipt's evidence_hash
    is sha256 over the canonical manifest, and the signature commits to that hash. Verifying
    the receipt re-derives the hash from the embedded manifest, so any post-signing edit to
    the skill (loosening governance, swapping a capability) breaks verification.
    """
    _require_skill_fields(manifest)
    return mint_receipt(manifest, decision=SKILL_DECISION, key_path=key_path)


def verify_skill(receipt: dict) -> dict:
    """Re-verify a signed-skill receipt from the cert alone (delegates to verify_receipt)."""
    return verify_receipt(receipt)


# --------------------------------------------------------------------------- CLI
def _cmd_sign(path: Path, key_path: str | None) -> int:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    try:
        receipt = sign_skill(manifest, key_path=key_path)
    except ValueError as e:
        print(f"REJECTED: {e}", file=sys.stderr)
        return 2
    out = path.with_suffix(".receipt.json")
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"signed: {manifest.get('skill_id')}")
    print(f"  atom_id:       {receipt['atom_id']}")
    print(f"  evidence_hash: {receipt['evidence_hash']}")
    print(f"  alg:           {receipt.get('signature_alg', receipt.get('alg'))}")
    print(f"  signed:        {receipt['signed']}")
    print(f"  receipt ->     {out.name}")
    return 0


def _cmd_verify(path: Path) -> int:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    res = verify_skill(receipt)
    skill_id = (receipt.get("evidence", {}).get("ontology", {}) or {}).get("skill_id", "?")
    print(f"verify: {skill_id}")
    print(f"  hash_ok: {res['hash_ok']}")
    print(f"  sig_ok:  {res['sig_ok']}  legs={res.get('legs', {})}")
    print(f"  result:  {'VALID' if res['ok'] else 'INVALID'} -- {res['reason']}")
    return 0 if res["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 2 or argv[0] not in ("sign", "verify"):
        print(__doc__.strip().splitlines()[0])
        print("usage: sign_skill.py sign|verify PATH [--key KEYFILE]")
        return 64
    cmd, path = argv[0], Path(argv[1])
    key_path = None
    if "--key" in argv:
        ki = argv.index("--key")
        if ki + 1 >= len(argv):
            print("--key requires a key file path", file=sys.stderr)
            return 64
        key_path = argv[ki + 1]
    if cmd == "sign":
        return _cmd_sign(path, key_path)
    return _cmd_verify(path)


if __name__ == "__main__":
    raise SystemExit(main())
