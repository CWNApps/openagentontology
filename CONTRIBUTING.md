# Contributing to OpenAgentOntology

Thanks for helping build the Agent Ontology standard. Two rules carry everything else.

## 1. No fabricated mappings — ever

A control mapping is only **asserted** when a source declares a canonical reason that exists in
the crosswalk. To add or change a mapping you must:

- Add it to the reference `ASSERTED_TABLE` in `openagentontology/crosswalk.py` **with a sourced
  `basis`** for every control — a one-line justification a GRC reviewer can check against the
  published control text.
- Never construct a framework id the tool can't source. The tests enforce this (`tests/` checks
  "no framework outside the allowed set" and "auto-detected mappings are never asserted").
- If you're proposing a new canonical reason, regenerate the published standard:
  `PYTHONPATH=. python schema/_gen_schema.py`.

Heuristic (verb-based) and ATT&CK enrichment mappings ship as **inferred** or **advisory** —
informative, never counted toward the badge.

## 2. The receipt must stay reproducible

The Ed25519 receipt hashes a deterministic, ASCII ontology so any language reproduces the hash
byte-for-byte. Don't introduce non-determinism (no timestamps in the hashed evidence, no
unsorted collections, no non-ASCII). `tests/test_pipeline.py` proves determinism and offline
verification — keep them green.

## Workflow

```bash
git clone <your-fork> && cd openagentontology
pip install pytest
pytest                 # all tests must pass before a PR
PYTHONPATH=. python -m openagentontology examples/sample_agent   # sanity-run
```

- Keep the core **stdlib-only** (runtime deps: `pyyaml`, `cryptography`). Semantic/model-backed
  enrichment belongs behind an optional extra or the hosted service, never in the offline core.
- Match the surrounding code's style and comment density.
- One logical change per PR; include or update a test that locks the behavior.

## Reporting

- **Bugs / mappings:** open an issue with the agent input and the scan output (`--json`).
- **Security:** see [SECURITY.md](./SECURITY.md) — do not open a public issue for a vulnerability.

By contributing you agree your contributions are licensed under [Apache-2.0](./LICENSE).

*No Receipt. No Trust.*
