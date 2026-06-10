# Reproducibility

Every command on this page was executed against the repo before being written down. If a
command here does not produce the stated result on your machine, that is a bug -- file it.

Commands are POSIX-shell form (bash, zsh, Git Bash on Windows). On Windows PowerShell,
replace the `PYTHONPATH=.` prefix with `$env:PYTHONPATH="."` on its own statement, e.g.
`$env:PYTHONPATH="."; python -m pytest -q`.

---

## 1. Clone and install

No install step is required for the tool itself; it runs from the source tree.

```bash
git clone https://github.com/CWNApps/openagentontology
cd openagentontology
pip install pyyaml cryptography     # the two runtime deps
pip install pytest                  # test-time only
```

Optional, for the post-quantum receipt legs:

```bash
pip install "openagentontology[pq]"   # dilithium-py  -> adds the ML-DSA-65 (FIPS 204) leg
pip install liboqs-python             # liboqs        -> adds ML-DSA-65 + SLH-DSA (FIPS 205)
```

Without the PQ extra the tool is Ed25519-only and every check below still works; the PQ
legs of committed receipts then report `unverifiable` on your host instead of `ok`, which
is the honest answer (you lack the backend, the legs are not broken).

## 2. Run the test suite

```bash
PYTHONPATH=. python -m pytest -q
```

Expected: every test passes, zero failures (152 passed at the time of writing; the count
only grows). The suite needs no install step -- `tests/conftest.py` puts the repo root on
`sys.path`.

## 3. Scan the examples

```bash
PYTHONPATH=. python -m openagentontology examples/sample_agent --no-receipt --out /tmp/oao_sample
PYTHONPATH=. python -m openagentontology examples/hardened_agent --no-receipt --out /tmp/oao_hardened
```

Expected headlines (deterministic, identical on every run):

- `examples/sample_agent` -- **UNGOVERNED 41/100** (its Rego declares 3 canonical reasons;
  the rest of its surface is heuristic or ungoverned)
- `examples/hardened_agent` -- **SOVEREIGN 93/100** (every capability declares a canonical
  reason)

Drop `--no-receipt` to also mint a signed `receipt.json` into the `--out` directory. Add
`--json` for the machine-readable payload. Exit code 0 = validation passed, 1 = failed
closed, 2 = usage error.

## 4. Reproduce the two real-world scans from the pinned commits

The committed artifacts under `docs/scans/` were produced from these exact upstream
commits. The evidence hash is a pure function of the scanned content, so you reproduce it
bit-for-bit. One subtlety: scan the clone BY ITS FOLDER NAME from the directory that
contains it -- the source label (`open-interpreter`) is part of the hashed evidence.

```bash
# from a scratch directory OUTSIDE the openagentontology repo
git clone https://github.com/OpenInterpreter/open-interpreter.git
git -C open-interpreter checkout e00f08e
git clone https://github.com/gpt-engineer-org/gpt-engineer.git
git -C gpt-engineer checkout a90fcd5

OAO=/path/to/openagentontology    # your clone of this repo

PYTHONPATH="$OAO" python -m openagentontology open-interpreter --out oi_artifacts --json > oi.scan.json
PYTHONPATH="$OAO" python -m openagentontology gpt-engineer     --out ge_artifacts --json > ge.scan.json
```

Expected verdicts: **UNGOVERNED 15/100** for both. Now prove your scan and the committed
one are the same evidence:

```bash
python - <<EOF
import json, os
OAO = os.path.expanduser("$OAO")
for name, mine in (("open-interpreter", "oi_artifacts/receipt.json"),
                   ("gpt-engineer", "ge_artifacts/receipt.json")):
    a = json.load(open(mine))
    b = json.load(open(f"{OAO}/docs/scans/{name}/receipt.json"))
    print(name, "evidence_hash match:", a["evidence_hash"] == b["evidence_hash"],
          "| atom_id match:", a["atom_id"] == b["atom_id"])
EOF
```

Expected output (verified):

```
open-interpreter evidence_hash match: True | atom_id match: True
gpt-engineer evidence_hash match: True | atom_id match: True
```

The stable atom ids are `oao-OPENINTERPRE-433522f130` and `oao-GPTENGINEER-158929ff54`.
Your `signature_b64` and `signed_at` will differ -- you sign with your own key; the
committed receipts verify from their own embedded certificates (next section). The
findings are what reproduce, and that is the point: same tool + same pinned commit =
same evidence hash, regardless of who runs it.

## 5. Verify the committed receipts, including the post-quantum legs

From the repo root:

```bash
PYTHONPATH=. python -c "import json; from openagentontology.receipt import verify_receipt; print(verify_receipt(json.load(open('docs/scans/open-interpreter/receipt.json'))))"
PYTHONPATH=. python -c "import json; from openagentontology.receipt import verify_receipt; print(verify_receipt(json.load(open('docs/scans/gpt-engineer/receipt.json'))))"
```

Expected on a host with both PQ backends installed (verified):

```
ok=True, hash_ok=True, sig_ok=True, signed=True,
legs={'ed25519': 'ok', 'ml_dsa': 'ok', 'slh_dsa': 'ok'},
reason='hash valid; verified from the cert alone via: ed25519, ml_dsa, slh_dsa'
```

The committed receipts are hybrid triple-signed (`signature_alg:
Ed25519+ML-DSA-65+SLH-DSA`). Without a PQ backend the PQ legs report `unverifiable` and
the Ed25519 leg still proves authenticity (`ok=True`). A leg may be `absent` (not on the
receipt) or `unverifiable` (no backend on your host) without failing verification; only a
leg that is present, checkable, and WRONG reports tamper.

## 6. Run the tamper test

The signature and tamper behavior is pinned by the suite:

```bash
PYTHONPATH=. python -m pytest tests/test_receipt.py tests/test_pqsign.py -q
```

Expected: all pass (this covers genuine-verifies, evidence edit, body edit, single-leg
corruption, wrong key, signature stripping, and PQ-leg tampering -- the scenarios in
[THREAT_MODEL.md](./THREAT_MODEL.md)).

And reproduce the headline tamper by hand -- inflate the committed scan's asserted count
and watch verification fail (verified):

```bash
PYTHONPATH=. python -c "import json; from openagentontology.receipt import verify_receipt; r=json.load(open('docs/scans/open-interpreter/receipt.json')); r['evidence']['summary']['asserted_covered']=21; v=verify_receipt(r); print(v['ok'], v['hash_ok'], v['reason'])"
```

Expected output:

```
False False evidence_hash mismatch -- evidence was altered
```

One edited byte, and the receipt stops verifying. That is the difference between a log and
a receipt.

---

*OpenAgentOntology -- https://github.com/CWNApps/openagentontology --
https://agent-ontology.cyberwarriornetwork.com. Stop Hoping. Start Proving.*
