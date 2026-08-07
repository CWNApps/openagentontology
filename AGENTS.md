# AGENTS.md — openagentontology (OAO)

Local delivery SOP for this repo. **Read this before working here; update it after.**
This is the public, Apache-2.0, customer-facing repo. A prospect's security
architect is the intended reader of everything in it.

---

## What makes this area high-miss

The artifacts here are *evidence*. If a claim in this repo is wrong, the product's
central promise — "check it yourself, don't trust us" — inverts into proof that we
overclaim. Two failure modes have already happened in this codebase and both apply
directly here:

1. **Claiming more than was performed.** `/api/v1/demo/sign` advertised
   "cryptographically signed, quantum-resistant" while returning an unsigned hash.
2. **Reading a key the producer never emits.** Registry entries stored `tier=""`
   because `register()` read `evidence.summary["tier"]`, which the scanner does not
   emit — the tier lives in `receipt["decision"]`.

## Must-not-skip

### Any change to `verify_receipt.py`
This file is the answer to the loudest objection in the category. Treat a false PASS
as a P0.

- [ ] **It imports NOTHING from `openagentontology` and nothing from CWN.** The whole
      point is that a third party can check a receipt without our code. Importing our
      own verifier would only prove we can verify our own receipts.
- [ ] **Run it against the full corpus**, not one receipt:
      `for d in docs/scans/*/; do python verify_receipt.py "$d/receipt.json" || echo "FAIL $d"; done`
- [ ] **Prove it can FAIL.** Tamper with a receipt (change one number inside
      `evidence`) and confirm it prints `NOT VERIFIED` and exits 1. A verifier nobody
      has watched fail is indistinguishable from `return True`.
- [ ] **Exit codes:** 0 verified / 1 failed / 2 usage. Verify by running, not reading.
- [ ] **Output claims must match what actually happened.** Fetch mode makes a network
      call; it must not print "no network". This is the same overclaim class as the
      `demo/sign` defect.
- [ ] **ASCII only in output.** Windows consoles are cp1252; an em dash renders as `?`
      in a demo a prospect is watching.
- [ ] **A missing PQ backend reports "unverifiable", never "pass".**

### Any change to `pyproject.toml`
- [ ] `verify_receipt` is a **top-level module, deliberately outside the package**. It
      must stay in `py-modules`, or the `oao-verify` entry point installs and then
      fails on import. `packages = [...]` alone does not cover it.
- [ ] Verify the entry point against a real build/install, not just `import`.

### Any change to the scan corpus (`docs/scans/`)
- [ ] Every receipt must remain self-contained: `verify_pubkey_b64`, `signature_b64`,
      `evidence_hash`, `evidence`. "Offline" degrades to "ask CWN for the key" without this.
- [ ] `signature_alg` must not name an algorithm the receipt does not carry.
- [ ] After changing the corpus, re-run the registry loader in cwn-trust-gate:
      `python scripts/oao_register_scans.py --write` and confirm the reconciliation
      line reports no delta.

### Any README claim
- [ ] **Every command in the README must run exactly as written.** Copy it, paste it,
      run it. Docs that 401 or traceback are worse than no docs.
- [ ] No claim that is not demonstrable by a command in the same section.
- [ ] **A command that installs from PyPI/GitHub must be checked against the LIVE
      index, not the local tree.** `pyproject.toml` declaring an entry point proves
      nothing about what is downloadable today. This is how a broken
      `uvx --from openagentontology oao-verify` shipped in the README on 2026-08-06:
      the entry point existed locally, the published `0.2.0` wheel had neither it nor
      `verify_receipt.py`, and "the command runs" was inferred from the source rather
      than executed. Inspect the actual artifact:
      `python -c "import json,urllib.request; print(json.load(urllib.request.urlopen('https://pypi.org/pypi/<pkg>/json'))['info']['version'])"`
      then list the wheel's contents before believing any install line.
- [ ] **Pin what you tell a reader to execute.** `curl … /main/… | python` and
      `uvx --from <pkg>` (no `==`) both resolve to a moving target. On a page whose
      argument is "do not trust the vendor", an unpinned pipe-to-interpreter is the
      argument contradicting itself. Offer a sha256 or a commit/version pin.

## Known field-location gotchas (cost real time — do not re-derive)

| You want | It is NOT in | It IS in |
|---|---|---|
| tier | `evidence.summary["tier"]` | `receipt["decision"]` as `"GOVERNED:<TIER>"` |
| score | the receipt at all | sibling `trust_profile.json` |
| what the signature covers | `evidence_hash` | `canonical(body)` over the 5 body fields; the body *commits to* the hash |
| frameworks | reliably anywhere | only 3 of 49 receipts carry any (47 are UNGOVERNED — the empty list is correct) |

## Done-criteria (the completeness gate for this repo)

Work here is not done until **all** of these pass, each with evidence:

1. `verify_receipt.py` passes against all 49 receipts.
2. A tampered receipt FAILS with exit 1 (demonstrated this session, not assumed).
3. Every README command has been executed as written.
4. Nothing in the repo claims a capability it cannot demonstrate.
5. **The work is committed and pushed.** Uncommitted work is not delivered — this is
   the step most often missed, including on the change that created this file.
6. An independent reviewer (not the author) has checked 1–5.

## Still manual (candidates to automate)

- The full-corpus verify loop → should become a CI job on this repo. Currently a
  human must remember to run it.
- The tamper negative-control → same; it exists as a test in cwn-trust-gate
  (`test_oao_offline_verification.py`) but not in this repo's own CI.

## Log

- **2026-08-06** — Created. Added `verify_receipt.py` (standalone offline verifier),
  `oao-verify` entry point, README one-command section. Gotchas table seeded from
  defects found the hard way during the OAO registry work (tier, score, signed body).
